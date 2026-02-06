//! GRE (Generic Routing Encapsulation) Transport - IP Protocol 47
//!
//! Implements tunneling over GRE (RFC 2784/2890), a widely used
//! encapsulation protocol for VPN trunks between routers.
//!
//! GRE is used extensively by:
//! - PPTP VPN (GRE carries PPP frames)
//! - Cisco SD-WAN, DMVPN, and IPsec tunnels
//! - Cloud providers (GCP uses GRE for load balancing)
//! - Enterprise WAN connectivity
//!
//! Why GRE works for censorship circumvention:
//! - Infrastructure protocol used by ISPs and enterprises
//! - Blocking GRE breaks corporate VPNs and ISP infrastructure
//! - Less scrutinized than TCP/UDP by consumer-level DPI
//! - Lower overhead than FakeTCP (only 4-8 byte header)
//! - Some Iranian ISPs still pass GRE for enterprise customers
//!
//! Differences from Protocol 115:
//! - More commonly seen in the wild (higher traffic volume to blend with)
//! - Has optional key field for session multiplexing
//! - Has optional sequence numbers for ordering
//! - Some ISPs may specifically filter GRE (unlike less-known Protocol 115)
//!
//! We use the enhanced GRE header (RFC 2890) with Key and Sequence fields
//! for session identification and ordering.

use super::packet::{IpHeader, Packet, PacketBuilder};
use super::raw_socket::RawSocket;
use super::{Transport, TransportStats};
use crate::config::TransportMode;
use crate::error::{PhantomError, Result};
use crate::utils::random_u32;

use async_trait::async_trait;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

/// GRE Protocol number
pub const GRE_PROTOCOL: u8 = 47;

/// EtherType for our tunnel payload (using "Transparent Ethernet Bridging")
/// This looks like standard GRE-over-IP to any DPI system
const ETHERTYPE_TRANS_BRIDGE: u16 = 0x6558;

/// EtherType for raw IP payload
const ETHERTYPE_IPV4: u16 = 0x0800;

/// GRE flags
const GRE_FLAG_CHECKSUM: u16 = 0x8000;
const GRE_FLAG_KEY: u16 = 0x2000;
const GRE_FLAG_SEQUENCE: u16 = 0x1000;

/// GRE Header
///
/// RFC 2784 basic format (4 bytes):
/// ```text
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |C| |K|S| Reserved0       | Ver |         Protocol Type         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |      Checksum (optional)      |       Reserved1 (optional)    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                         Key (optional)                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                     Sequence Number (optional)                |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone)]
pub struct GreHeader {
    /// Flags and version
    pub flags: u16,
    /// Protocol type (EtherType of encapsulated payload)
    pub protocol_type: u16,
    /// Optional checksum
    pub checksum: Option<u16>,
    /// Optional key (used as tunnel session ID)
    pub key: Option<u32>,
    /// Optional sequence number
    pub sequence: Option<u32>,
}

impl GreHeader {
    /// Create a minimal GRE header (no optional fields)
    pub fn new(protocol_type: u16) -> Self {
        Self {
            flags: 0,
            protocol_type,
            checksum: None,
            key: None,
            sequence: None,
        }
    }

    /// Create a GRE header with key (for session identification)
    pub fn with_key(protocol_type: u16, key: u32) -> Self {
        Self {
            flags: GRE_FLAG_KEY,
            protocol_type,
            key: Some(key),
            checksum: None,
            sequence: None,
        }
    }

    /// Create a GRE header with key and sequence number
    pub fn with_key_and_seq(protocol_type: u16, key: u32, sequence: u32) -> Self {
        Self {
            flags: GRE_FLAG_KEY | GRE_FLAG_SEQUENCE,
            protocol_type,
            key: Some(key),
            sequence: Some(sequence),
            checksum: None,
        }
    }

    /// Serialize the GRE header to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.size());

        // Flags and Version (2 bytes) + Protocol Type (2 bytes)
        buf.extend_from_slice(&self.flags.to_be_bytes());
        buf.extend_from_slice(&self.protocol_type.to_be_bytes());

        // Optional Checksum + Reserved1 (4 bytes if present)
        if self.flags & GRE_FLAG_CHECKSUM != 0 {
            buf.extend_from_slice(&self.checksum.unwrap_or(0).to_be_bytes());
            buf.extend_from_slice(&0u16.to_be_bytes()); // Reserved1
        }

        // Optional Key (4 bytes)
        if let Some(key) = self.key {
            buf.extend_from_slice(&key.to_be_bytes());
        }

        // Optional Sequence (4 bytes)
        if let Some(seq) = self.sequence {
            buf.extend_from_slice(&seq.to_be_bytes());
        }

        buf
    }

    /// Parse a GRE header from bytes
    pub fn from_bytes(data: &[u8]) -> Result<(Self, usize)> {
        if data.len() < 4 {
            return Err(PhantomError::PacketParse("GRE header too short".into()));
        }

        let flags = u16::from_be_bytes([data[0], data[1]]);
        let protocol_type = u16::from_be_bytes([data[2], data[3]]);

        let mut offset = 4;
        let mut header = Self {
            flags,
            protocol_type,
            checksum: None,
            key: None,
            sequence: None,
        };

        // Parse optional Checksum + Reserved1
        if flags & GRE_FLAG_CHECKSUM != 0 {
            if data.len() < offset + 4 {
                return Err(PhantomError::PacketParse(
                    "GRE checksum field truncated".into(),
                ));
            }
            header.checksum = Some(u16::from_be_bytes([data[offset], data[offset + 1]]));
            offset += 4; // checksum + reserved1
        }

        // Parse optional Key
        if flags & GRE_FLAG_KEY != 0 {
            if data.len() < offset + 4 {
                return Err(PhantomError::PacketParse("GRE key field truncated".into()));
            }
            header.key = Some(u32::from_be_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]));
            offset += 4;
        }

        // Parse optional Sequence
        if flags & GRE_FLAG_SEQUENCE != 0 {
            if data.len() < offset + 4 {
                return Err(PhantomError::PacketParse(
                    "GRE sequence field truncated".into(),
                ));
            }
            header.sequence = Some(u32::from_be_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]));
            offset += 4;
        }

        Ok((header, offset))
    }

    /// Get the size of this header in bytes
    pub fn size(&self) -> usize {
        let mut size = 4; // Base header
        if self.flags & GRE_FLAG_CHECKSUM != 0 {
            size += 4;
        }
        if self.key.is_some() {
            size += 4;
        }
        if self.sequence.is_some() {
            size += 4;
        }
        size
    }
}

/// GRE Transport implementation
pub struct GreTransport {
    socket: Arc<RawSocket>,
    local_ip: Ipv4Addr,
    /// GRE key used as session/tunnel identifier
    tunnel_key: u32,
    /// Sequence number counter
    sequence: AtomicU32,
    /// Whether to include sequence numbers
    use_sequence: bool,
    /// Stats tracking
    stats: Arc<TransportStatsInner>,
    /// Running flag
    running: Arc<AtomicBool>,
}

struct TransportStatsInner {
    packets_sent: AtomicU64,
    packets_recv: AtomicU64,
    bytes_sent: AtomicU64,
    bytes_recv: AtomicU64,
    packets_dropped: AtomicU64,
}

impl GreTransport {
    /// Create a new GRE transport
    pub async fn new(bind_addr: SocketAddr) -> Result<Self> {
        let socket = RawSocket::new(GRE_PROTOCOL, true)?;

        let local_ip = match bind_addr {
            SocketAddr::V4(v4) => *v4.ip(),
            SocketAddr::V6(_) => return Err(PhantomError::Config("IPv6 not supported".into())),
        };

        let tunnel_key = random_u32();

        Ok(Self {
            socket: Arc::new(socket),
            local_ip,
            tunnel_key,
            sequence: AtomicU32::new(0),
            use_sequence: true,
            stats: Arc::new(TransportStatsInner {
                packets_sent: AtomicU64::new(0),
                packets_recv: AtomicU64::new(0),
                bytes_sent: AtomicU64::new(0),
                bytes_recv: AtomicU64::new(0),
                packets_dropped: AtomicU64::new(0),
            }),
            running: Arc::new(AtomicBool::new(true)),
        })
    }

    /// Create with a specific tunnel key
    pub async fn with_key(bind_addr: SocketAddr, tunnel_key: u32) -> Result<Self> {
        let mut transport = Self::new(bind_addr).await?;
        transport.tunnel_key = tunnel_key;
        Ok(transport)
    }

    /// Get the tunnel key
    pub fn tunnel_key(&self) -> u32 {
        self.tunnel_key
    }

    /// Get next sequence number
    fn next_sequence(&self) -> u32 {
        self.sequence.fetch_add(1, Ordering::SeqCst)
    }

    /// Build a GRE packet wrapping tunnel data
    fn build_packet(&self, dst_ip: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
        // Build GRE header with key (and optional sequence)
        let gre_header = if self.use_sequence {
            GreHeader::with_key_and_seq(
                ETHERTYPE_TRANS_BRIDGE,
                self.tunnel_key,
                self.next_sequence(),
            )
        } else {
            GreHeader::with_key(ETHERTYPE_TRANS_BRIDGE, self.tunnel_key)
        };

        // Combine GRE header with payload
        let mut gre_payload = gre_header.to_bytes();
        gre_payload.extend_from_slice(payload);

        // Build IP packet with Protocol 47 (GRE)
        let mut packet = PacketBuilder::new(GRE_PROTOCOL, self.local_ip, dst_ip)
            .payload(&gre_payload)
            .build();

        packet.to_bytes()
    }

    /// Parse an incoming GRE packet
    fn parse_packet(&self, data: &[u8]) -> Result<(Ipv4Addr, Vec<u8>)> {
        let packet = Packet::from_bytes(data)?;

        if packet.ip.protocol != GRE_PROTOCOL {
            return Err(PhantomError::InvalidPacket(format!(
                "Expected protocol {}, got {}",
                GRE_PROTOCOL, packet.ip.protocol
            )));
        }

        // Parse GRE header from payload
        let (gre_header, header_size) = GreHeader::from_bytes(&packet.payload)?;

        // Verify tunnel key matches
        match gre_header.key {
            Some(key) if key == self.tunnel_key => {}
            Some(key) => {
                return Err(PhantomError::InvalidPacket(format!(
                    "GRE key mismatch: expected {}, got {}",
                    self.tunnel_key, key
                )));
            }
            None => {
                return Err(PhantomError::InvalidPacket("GRE packet missing key".into()));
            }
        }

        // Extract payload after GRE header
        if header_size >= packet.payload.len() {
            return Err(PhantomError::InvalidPacket("GRE payload empty".into()));
        }

        let payload = packet.payload[header_size..].to_vec();

        Ok((packet.ip.src_ip, payload))
    }
}

#[async_trait]
impl Transport for GreTransport {
    fn mode(&self) -> TransportMode {
        TransportMode::Gre
    }

    async fn send(&self, data: &[u8], dst: SocketAddr) -> Result<usize> {
        let dst_ip = match dst {
            SocketAddr::V4(v4) => *v4.ip(),
            _ => return Err(PhantomError::Config("IPv6 not supported".into())),
        };

        let packet = self.build_packet(dst_ip, data);
        let sent = self.socket.send_to(&packet, dst).await?;

        self.stats.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.stats
            .bytes_sent
            .fetch_add(packet.len() as u64, Ordering::Relaxed);

        Ok(data.len())
    }

    async fn recv(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        let mut raw_buf = [0u8; 65535];

        loop {
            let (n, _) = self.socket.recv_from(&mut raw_buf).await?;

            // Minimum: IP header (20) + GRE base header (4)
            if n < IpHeader::MIN_SIZE + 4 {
                continue;
            }

            match self.parse_packet(&raw_buf[..n]) {
                Ok((src_ip, payload)) => {
                    let len = payload.len().min(buf.len());
                    buf[..len].copy_from_slice(&payload[..len]);

                    self.stats.packets_recv.fetch_add(1, Ordering::Relaxed);
                    self.stats
                        .bytes_recv
                        .fetch_add(len as u64, Ordering::Relaxed);

                    return Ok((len, SocketAddr::V4(SocketAddrV4::new(src_ip, 0))));
                }
                Err(_) => {
                    self.stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            }
        }
    }

    async fn close(&self) -> Result<()> {
        self.running.store(false, Ordering::SeqCst);
        Ok(())
    }

    fn is_healthy(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    fn stats(&self) -> TransportStats {
        TransportStats {
            packets_sent: self.stats.packets_sent.load(Ordering::Relaxed),
            packets_recv: self.stats.packets_recv.load(Ordering::Relaxed),
            bytes_sent: self.stats.bytes_sent.load(Ordering::Relaxed),
            bytes_recv: self.stats.bytes_recv.load(Ordering::Relaxed),
            packets_dropped: self.stats.packets_dropped.load(Ordering::Relaxed),
            retransmissions: 0,
            avg_rtt_ms: 0.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gre_header_basic() {
        let header = GreHeader::new(ETHERTYPE_IPV4);
        let bytes = header.to_bytes();
        assert_eq!(bytes.len(), 4);
        assert_eq!(bytes[2..4], ETHERTYPE_IPV4.to_be_bytes());
    }

    #[test]
    fn test_gre_header_with_key() {
        let header = GreHeader::with_key(ETHERTYPE_TRANS_BRIDGE, 0xDEADBEEF);
        let bytes = header.to_bytes();
        assert_eq!(bytes.len(), 8); // 4 base + 4 key
        assert_eq!(header.size(), 8);

        let (parsed, size) = GreHeader::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.key, Some(0xDEADBEEF));
        assert_eq!(parsed.protocol_type, ETHERTYPE_TRANS_BRIDGE);
        assert_eq!(size, 8);
    }

    #[test]
    fn test_gre_header_with_key_and_seq() {
        let header = GreHeader::with_key_and_seq(ETHERTYPE_TRANS_BRIDGE, 0x12345678, 42);
        let bytes = header.to_bytes();
        assert_eq!(bytes.len(), 12); // 4 base + 4 key + 4 seq

        let (parsed, size) = GreHeader::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.key, Some(0x12345678));
        assert_eq!(parsed.sequence, Some(42));
        assert_eq!(size, 12);
    }

    #[test]
    fn test_gre_header_roundtrip() {
        let header = GreHeader::with_key_and_seq(ETHERTYPE_TRANS_BRIDGE, 0xCAFEBABE, 100);
        let bytes = header.to_bytes();
        let (parsed, _) = GreHeader::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.flags & GRE_FLAG_KEY, GRE_FLAG_KEY);
        assert_eq!(parsed.flags & GRE_FLAG_SEQUENCE, GRE_FLAG_SEQUENCE);
        assert_eq!(parsed.key, Some(0xCAFEBABE));
        assert_eq!(parsed.sequence, Some(100));
        assert_eq!(parsed.protocol_type, ETHERTYPE_TRANS_BRIDGE);
    }
}
