//! UDP/QUIC Masquerade Transport
//!
//! Tunnels data over UDP port 443, masquerading as QUIC traffic.
//! QUIC (HTTP/3) is increasingly common on the internet, making UDP:443
//! traffic expected and difficult to block without collateral damage.
//!
//! The transport crafts packets that mimic QUIC Initial packets:
//! - Correct QUIC header format with version field
//! - Random connection IDs matching typical browser patterns
//! - Packet padding to match QUIC Initial minimum size (1200 bytes)
//!
//! Why UDP/QUIC masquerade works:
//! - QUIC traffic is rapidly growing (Google, YouTube, Cloudflare all use it)
//! - Blocking UDP:443 would break HTTP/3 for all users
//! - DPI for QUIC is immature compared to TLS inspection
//! - QUIC's encryption makes deep inspection difficult
//!
//! Advantages over raw socket transports:
//! - No root/CAP_NET_RAW required (standard UDP socket)
//! - NAT-friendly (UDP hole punching possible)
//! - Blends with massive volume of real QUIC traffic

use super::{Transport, TransportStats};
use crate::config::TransportMode;
use crate::error::{PhantomError, Result};
use crate::utils::{random_bytes, random_u32};

use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::net::UdpSocket;

/// QUIC version constants
const QUIC_VERSION_1: u32 = 0x00000001; // RFC 9000
const QUIC_VERSION_2: u32 = 0x6b3343cf; // RFC 9369

/// QUIC header form bit
const QUIC_LONG_HEADER: u8 = 0x80; // Long header form
const QUIC_FIXED_BIT: u8 = 0x40; // Fixed bit (must be 1)

/// QUIC long header packet types
const QUIC_INITIAL: u8 = 0x00; // Initial packet type

/// Minimum QUIC Initial packet size (RFC 9000 Section 14.1)
const QUIC_INITIAL_MIN_SIZE: usize = 1200;

/// Connection ID for our tunnel (mimics browser DCID length)
const DCID_LENGTH: usize = 8;
const SCID_LENGTH: usize = 0; // Browsers often omit SCID in Initial

/// Magic bytes to identify our packets within the QUIC payload
const PHANTOM_QUIC_MAGIC: [u8; 4] = [0x50, 0x48, 0x4E, 0x54]; // "PHNT"

/// QUIC masquerade transport
pub struct QuicMasqTransport {
    /// UDP socket
    socket: Arc<UdpSocket>,
    /// Our connection ID (acts as session identifier)
    connection_id: [u8; DCID_LENGTH],
    /// QUIC version to use in headers
    quic_version: u32,
    /// Whether to pad packets to QUIC Initial minimum size
    pad_to_initial: bool,
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

impl QuicMasqTransport {
    /// Create a new QUIC masquerade transport
    pub async fn new(bind_addr: SocketAddr) -> Result<Self> {
        let socket = UdpSocket::bind(bind_addr)
            .await
            .map_err(|e| PhantomError::Socket(format!("UDP bind failed: {}", e)))?;

        let mut connection_id = [0u8; DCID_LENGTH];
        let random = random_bytes(DCID_LENGTH);
        connection_id.copy_from_slice(&random);

        Ok(Self {
            socket: Arc::new(socket),
            connection_id,
            quic_version: QUIC_VERSION_1,
            pad_to_initial: true,
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

    /// Create with a specific connection ID
    pub async fn with_connection_id(
        bind_addr: SocketAddr,
        connection_id: [u8; DCID_LENGTH],
    ) -> Result<Self> {
        let mut transport = Self::new(bind_addr).await?;
        transport.connection_id = connection_id;
        Ok(transport)
    }

    /// Disable padding (for non-Initial packets after "handshake")
    pub fn set_padding(&mut self, enabled: bool) {
        self.pad_to_initial = enabled;
    }

    /// Build a QUIC-like packet wrapping tunnel data
    ///
    /// Format mimics QUIC Initial packet:
    /// ```text
    /// [Header Form (1)] [Version (4)] [DCID Len (1)] [DCID (8)]
    /// [SCID Len (1)] [Token Len (var)] [Length (var)] [Payload...]
    /// ```
    fn build_packet(&self, data: &[u8]) -> Vec<u8> {
        // Header byte: Long header + Fixed bit + Initial type
        let header_byte = QUIC_LONG_HEADER | QUIC_FIXED_BIT | QUIC_INITIAL;

        let mut packet = Vec::with_capacity(QUIC_INITIAL_MIN_SIZE);

        // QUIC Long Header
        packet.push(header_byte);
        packet.extend_from_slice(&self.quic_version.to_be_bytes());

        // Destination Connection ID
        packet.push(DCID_LENGTH as u8);
        packet.extend_from_slice(&self.connection_id);

        // Source Connection ID (empty)
        packet.push(SCID_LENGTH as u8);

        // Token Length (variable-length integer, 0 for Initial from client)
        packet.push(0x00); // No token

        // Payload = magic + length prefix + actual data
        let payload_len = PHANTOM_QUIC_MAGIC.len() + 2 + data.len();

        // Length field (variable-length integer encoding)
        // Use 2-byte form (0x4000 | length) for lengths up to 16383
        let length_val = payload_len as u16;
        packet.push(0x40 | ((length_val >> 8) as u8));
        packet.push(length_val as u8);

        // Packet Number (4 bytes, looks like QUIC packet number)
        let pn = random_u32();
        packet.extend_from_slice(&pn.to_be_bytes());

        // Payload starts here (would be encrypted in real QUIC)
        packet.extend_from_slice(&PHANTOM_QUIC_MAGIC);
        packet.extend_from_slice(&(data.len() as u16).to_be_bytes());
        packet.extend_from_slice(data);

        // Pad to minimum QUIC Initial size if enabled
        if self.pad_to_initial && packet.len() < QUIC_INITIAL_MIN_SIZE {
            let padding_needed = QUIC_INITIAL_MIN_SIZE - packet.len();
            // Use random padding (real QUIC uses PADDING frames = 0x00,
            // but random looks more like encrypted data)
            packet.extend_from_slice(&random_bytes(padding_needed));
        }

        packet
    }

    /// Parse an incoming QUIC-like packet and extract tunnel data
    fn parse_packet(&self, packet: &[u8]) -> Result<Vec<u8>> {
        if packet.len() < 7 {
            return Err(PhantomError::PacketParse("QUIC packet too short".into()));
        }

        let header_byte = packet[0];

        // Verify it's a long header
        if header_byte & QUIC_LONG_HEADER == 0 {
            // Short header - try to parse as short header packet
            return self.parse_short_header(packet);
        }

        // Skip version (4 bytes)
        let mut offset = 5;

        // DCID
        if offset >= packet.len() {
            return Err(PhantomError::PacketParse(
                "QUIC packet truncated at DCID len".into(),
            ));
        }
        let dcid_len = packet[offset] as usize;
        offset += 1 + dcid_len;

        // SCID
        if offset >= packet.len() {
            return Err(PhantomError::PacketParse(
                "QUIC packet truncated at SCID len".into(),
            ));
        }
        let scid_len = packet[offset] as usize;
        offset += 1 + scid_len;

        // Token length (variable-length integer)
        if offset >= packet.len() {
            return Err(PhantomError::PacketParse(
                "QUIC packet truncated at token".into(),
            ));
        }
        let (token_len, token_len_size) = decode_varint(&packet[offset..])?;
        offset += token_len_size + token_len as usize;

        // Length (variable-length integer)
        if offset >= packet.len() {
            return Err(PhantomError::PacketParse(
                "QUIC packet truncated at length".into(),
            ));
        }
        let (_payload_len, len_size) = decode_varint(&packet[offset..])?;
        offset += len_size;

        // Skip packet number (4 bytes)
        offset += 4;

        // Check for our magic bytes
        if offset + PHANTOM_QUIC_MAGIC.len() + 2 > packet.len() {
            return Err(PhantomError::InvalidPacket(
                "Payload too short for magic".into(),
            ));
        }

        if packet[offset..offset + PHANTOM_QUIC_MAGIC.len()] != PHANTOM_QUIC_MAGIC {
            return Err(PhantomError::InvalidPacket("QUIC magic mismatch".into()));
        }
        offset += PHANTOM_QUIC_MAGIC.len();

        // Data length
        let data_len = u16::from_be_bytes([packet[offset], packet[offset + 1]]) as usize;
        offset += 2;

        if offset + data_len > packet.len() {
            return Err(PhantomError::PacketParse(
                "Data length exceeds packet".into(),
            ));
        }

        Ok(packet[offset..offset + data_len].to_vec())
    }

    /// Parse a QUIC short header packet (used after "handshake")
    fn parse_short_header(&self, packet: &[u8]) -> Result<Vec<u8>> {
        // Short header: [Header (1)] [DCID (dcid_len)] [Packet Number (1-4)] [Payload]
        if packet.len() < 1 + DCID_LENGTH + 1 + PHANTOM_QUIC_MAGIC.len() + 2 {
            return Err(PhantomError::PacketParse("Short header too small".into()));
        }

        let mut offset = 1 + DCID_LENGTH;

        // Skip packet number (assume 1 byte for short header)
        offset += 1;

        // Check magic
        if packet[offset..offset + PHANTOM_QUIC_MAGIC.len()] != PHANTOM_QUIC_MAGIC {
            return Err(PhantomError::InvalidPacket(
                "Short header magic mismatch".into(),
            ));
        }
        offset += PHANTOM_QUIC_MAGIC.len();

        let data_len = u16::from_be_bytes([packet[offset], packet[offset + 1]]) as usize;
        offset += 2;

        if offset + data_len > packet.len() {
            return Err(PhantomError::PacketParse(
                "Short header data exceeds packet".into(),
            ));
        }

        Ok(packet[offset..offset + data_len].to_vec())
    }

    /// Build a short header packet (after initial exchange, for lower overhead)
    pub fn build_short_packet(&self, data: &[u8]) -> Vec<u8> {
        let header_byte = QUIC_FIXED_BIT | 0x20; // Short header + key phase

        let mut packet =
            Vec::with_capacity(1 + DCID_LENGTH + 1 + PHANTOM_QUIC_MAGIC.len() + 2 + data.len());

        packet.push(header_byte);
        packet.extend_from_slice(&self.connection_id);
        packet.push(0x01); // Packet number (1 byte)

        packet.extend_from_slice(&PHANTOM_QUIC_MAGIC);
        packet.extend_from_slice(&(data.len() as u16).to_be_bytes());
        packet.extend_from_slice(data);

        packet
    }
}

#[async_trait]
impl Transport for QuicMasqTransport {
    fn mode(&self) -> TransportMode {
        TransportMode::QuicMasq
    }

    async fn send(&self, data: &[u8], dst: SocketAddr) -> Result<usize> {
        let packet = self.build_packet(data);

        self.socket
            .send_to(&packet, dst)
            .await
            .map_err(PhantomError::Io)?;

        self.stats.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.stats
            .bytes_sent
            .fetch_add(packet.len() as u64, Ordering::Relaxed);

        Ok(data.len())
    }

    async fn recv(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        let mut raw_buf = [0u8; 65535];

        loop {
            let (n, src) = self
                .socket
                .recv_from(&mut raw_buf)
                .await
                .map_err(PhantomError::Io)?;

            if n < 7 {
                self.stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
                continue;
            }

            match self.parse_packet(&raw_buf[..n]) {
                Ok(data) => {
                    let len = data.len().min(buf.len());
                    buf[..len].copy_from_slice(&data[..len]);

                    self.stats.packets_recv.fetch_add(1, Ordering::Relaxed);
                    self.stats
                        .bytes_recv
                        .fetch_add(len as u64, Ordering::Relaxed);

                    return Ok((len, src));
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

// ============================================================
// QUIC Variable-Length Integer Encoding (RFC 9000 Section 16)
// ============================================================

/// Decode a QUIC variable-length integer
/// Returns (value, bytes_consumed)
fn decode_varint(data: &[u8]) -> Result<(u64, usize)> {
    if data.is_empty() {
        return Err(PhantomError::PacketParse("Empty varint".into()));
    }

    let prefix = data[0] >> 6;

    match prefix {
        0 => {
            // 6-bit value
            Ok((data[0] as u64 & 0x3F, 1))
        }
        1 => {
            // 14-bit value
            if data.len() < 2 {
                return Err(PhantomError::PacketParse("Varint too short".into()));
            }
            let val = u16::from_be_bytes([data[0] & 0x3F, data[1]]) as u64;
            Ok((val, 2))
        }
        2 => {
            // 30-bit value
            if data.len() < 4 {
                return Err(PhantomError::PacketParse("Varint too short".into()));
            }
            let val = u32::from_be_bytes([data[0] & 0x3F, data[1], data[2], data[3]]) as u64;
            Ok((val, 4))
        }
        3 => {
            // 62-bit value
            if data.len() < 8 {
                return Err(PhantomError::PacketParse("Varint too short".into()));
            }
            let val = u64::from_be_bytes([
                data[0] & 0x3F,
                data[1],
                data[2],
                data[3],
                data[4],
                data[5],
                data[6],
                data[7],
            ]);
            Ok((val, 8))
        }
        _ => unreachable!(),
    }
}

/// Encode a value as QUIC variable-length integer
#[allow(dead_code)]
fn encode_varint(value: u64) -> Vec<u8> {
    if value < 64 {
        vec![value as u8]
    } else if value < 16384 {
        let val = value as u16 | 0x4000;
        val.to_be_bytes().to_vec()
    } else if value < 1_073_741_824 {
        let val = value as u32 | 0x80000000;
        val.to_be_bytes().to_vec()
    } else {
        let val = value | 0xC000000000000000;
        val.to_be_bytes().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varint_roundtrip() {
        // 6-bit
        let encoded = encode_varint(37);
        let (decoded, size) = decode_varint(&encoded).unwrap();
        assert_eq!(decoded, 37);
        assert_eq!(size, 1);

        // 14-bit
        let encoded = encode_varint(15293);
        let (decoded, size) = decode_varint(&encoded).unwrap();
        assert_eq!(decoded, 15293);
        assert_eq!(size, 2);
    }

    #[test]
    fn test_quic_magic() {
        assert_eq!(&PHANTOM_QUIC_MAGIC, b"PHNT");
    }

    #[tokio::test]
    async fn test_packet_roundtrip() {
        let transport = QuicMasqTransport::new("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();

        let data = b"Hello, tunnel!";
        let packet = transport.build_packet(data);

        // Verify minimum size
        assert!(packet.len() >= QUIC_INITIAL_MIN_SIZE);

        // Verify we can parse it back
        let decoded = transport.parse_packet(&packet).unwrap();
        assert_eq!(decoded, data);
    }

    #[tokio::test]
    async fn test_short_header_roundtrip() {
        let transport = QuicMasqTransport::new("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();

        let data = b"Short header data";
        let packet = transport.build_short_packet(data);
        let decoded = transport.parse_short_header(&packet).unwrap();
        assert_eq!(decoded, data);
    }
}
