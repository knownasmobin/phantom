//! Protocol 115 (L2TPv3) Transport
//!
//! Implements IP Protocol 115 tunneling, which bypasses TCP/UDP inspection
//! since most DPI systems focus on those protocols.
//!
//! This exploits the "infrastructure blind spot" - Protocol 115 is often
//! used for router-to-router communication and may be whitelisted or ignored.

use super::packet::{IpHeader, PacketBuilder, Packet, TransportHeader};
use super::raw_socket::RawSocket;
use super::{Transport, TransportStats};
use crate::config::TransportMode;
use crate::error::{PhantomError, Result};
use crate::utils::random_u32;

use async_trait::async_trait;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

/// L2TPv3 Session Header (simplified)
/// We use a minimal header to reduce overhead while maintaining protocol compliance
#[derive(Debug, Clone)]
pub struct L2tpv3Header {
    /// Session ID (4 bytes) - identifies the tunnel
    pub session_id: u32,
    /// Cookie (optional, 0/4/8 bytes) - for additional security
    pub cookie: Option<u64>,
}

impl L2tpv3Header {
    pub const MIN_SIZE: usize = 4;

    pub fn new(session_id: u32) -> Self {
        Self {
            session_id,
            cookie: None,
        }
    }

    pub fn with_cookie(session_id: u32, cookie: u64) -> Self {
        Self {
            session_id,
            cookie: Some(cookie),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(12);
        buf.extend_from_slice(&self.session_id.to_be_bytes());
        if let Some(cookie) = self.cookie {
            buf.extend_from_slice(&cookie.to_be_bytes());
        }
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<(Self, usize)> {
        if data.len() < 4 {
            return Err(PhantomError::PacketParse("L2TPv3 header too short".into()));
        }

        let session_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);

        // Check if cookie is present (we use 8-byte cookies)
        if data.len() >= 12 {
            let cookie = u64::from_be_bytes([
                data[4], data[5], data[6], data[7],
                data[8], data[9], data[10], data[11],
            ]);
            Ok((Self { session_id, cookie: Some(cookie) }, 12))
        } else {
            Ok((Self { session_id, cookie: None }, 4))
        }
    }

    pub fn size(&self) -> usize {
        if self.cookie.is_some() { 12 } else { 4 }
    }
}

/// Protocol 115 Transport implementation
pub struct Protocol115Transport {
    socket: Arc<RawSocket>,
    local_ip: Ipv4Addr,
    session_id: u32,
    cookie: Option<u64>,
    stats: Arc<TransportStatsInner>,
    running: Arc<AtomicBool>,
}

struct TransportStatsInner {
    packets_sent: AtomicU64,
    packets_recv: AtomicU64,
    bytes_sent: AtomicU64,
    bytes_recv: AtomicU64,
    packets_dropped: AtomicU64,
}

impl Protocol115Transport {
    /// Create a new Protocol 115 transport
    pub async fn new(bind_addr: SocketAddr) -> Result<Self> {
        let socket = RawSocket::protocol_115()?;

        let local_ip = match bind_addr {
            SocketAddr::V4(v4) => *v4.ip(),
            SocketAddr::V6(_) => return Err(PhantomError::Config("IPv6 not supported".into())),
        };

        // Generate random session ID
        let session_id = random_u32();

        Ok(Self {
            socket: Arc::new(socket),
            local_ip,
            session_id,
            cookie: None,
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

    /// Create with a specific session ID and optional cookie
    pub async fn with_session(
        bind_addr: SocketAddr,
        session_id: u32,
        cookie: Option<u64>,
    ) -> Result<Self> {
        let mut transport = Self::new(bind_addr).await?;
        transport.session_id = session_id;
        transport.cookie = cookie;
        Ok(transport)
    }

    /// Set the session cookie for additional authentication
    pub fn set_cookie(&mut self, cookie: u64) {
        self.cookie = Some(cookie);
    }

    /// Get the session ID
    pub fn session_id(&self) -> u32 {
        self.session_id
    }

    /// Build a Protocol 115 packet
    fn build_packet(&self, dst_ip: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
        // Build L2TPv3 header
        let l2tp_header = if let Some(cookie) = self.cookie {
            L2tpv3Header::with_cookie(self.session_id, cookie)
        } else {
            L2tpv3Header::new(self.session_id)
        };

        // Combine L2TPv3 header with payload
        let mut l2tp_payload = l2tp_header.to_bytes();
        l2tp_payload.extend_from_slice(payload);

        // Build IP packet with Protocol 115
        let mut packet = PacketBuilder::new(115, self.local_ip, dst_ip)
            .protocol_115()
            .payload(&l2tp_payload)
            .build();

        packet.to_bytes()
    }

    /// Parse an incoming Protocol 115 packet
    fn parse_packet(&self, data: &[u8]) -> Result<(Ipv4Addr, Vec<u8>)> {
        let packet = Packet::from_bytes(data)?;

        if packet.ip.protocol != 115 {
            return Err(PhantomError::InvalidPacket(
                format!("Expected protocol 115, got {}", packet.ip.protocol)
            ));
        }

        // Parse L2TPv3 header
        let (l2tp_header, header_size) = L2tpv3Header::from_bytes(&packet.payload)?;

        // Verify session ID
        if l2tp_header.session_id != self.session_id {
            return Err(PhantomError::InvalidPacket("Session ID mismatch".into()));
        }

        // Verify cookie if set
        if let Some(expected_cookie) = self.cookie {
            match l2tp_header.cookie {
                Some(cookie) if cookie == expected_cookie => {}
                _ => return Err(PhantomError::InvalidPacket("Cookie mismatch".into())),
            }
        }

        // Extract payload after L2TPv3 header
        let payload = packet.payload[header_size..].to_vec();

        Ok((packet.ip.src_ip, payload))
    }
}

#[async_trait]
impl Transport for Protocol115Transport {
    fn mode(&self) -> TransportMode {
        TransportMode::Protocol115
    }

    async fn send(&self, data: &[u8], dst: SocketAddr) -> Result<usize> {
        let dst_ip = match dst {
            SocketAddr::V4(v4) => *v4.ip(),
            _ => return Err(PhantomError::Config("IPv6 not supported".into())),
        };

        let packet = self.build_packet(dst_ip, data);
        let sent = self.socket.send_to(&packet, dst).await?;

        self.stats.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.stats.bytes_sent.fetch_add(packet.len() as u64, Ordering::Relaxed);

        Ok(data.len())
    }

    async fn recv(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        let mut raw_buf = [0u8; 65535];

        loop {
            let (n, _) = self.socket.recv_from(&mut raw_buf).await?;

            if n < IpHeader::MIN_SIZE + L2tpv3Header::MIN_SIZE {
                continue;
            }

            match self.parse_packet(&raw_buf[..n]) {
                Ok((src_ip, payload)) => {
                    let len = payload.len().min(buf.len());
                    buf[..len].copy_from_slice(&payload[..len]);

                    self.stats.packets_recv.fetch_add(1, Ordering::Relaxed);
                    self.stats.bytes_recv.fetch_add(len as u64, Ordering::Relaxed);

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
    fn test_l2tpv3_header_roundtrip() {
        let header = L2tpv3Header::with_cookie(0x12345678, 0xDEADBEEFCAFEBABE);
        let bytes = header.to_bytes();
        let (parsed, size) = L2tpv3Header::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.session_id, 0x12345678);
        assert_eq!(parsed.cookie, Some(0xDEADBEEFCAFEBABE));
        assert_eq!(size, 12);
    }

    #[test]
    fn test_l2tpv3_header_no_cookie() {
        let header = L2tpv3Header::new(0xABCDEF01);
        let bytes = header.to_bytes();
        assert_eq!(bytes.len(), 4);
    }
}
