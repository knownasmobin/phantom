//! ICMP Tunnel Transport
//!
//! Implements tunneling over ICMP Echo Request/Reply packets.
//! This exploits the "diagnostic necessity" - ICMP is rarely blocked completely
//! because it breaks network troubleshooting (ping, traceroute, PMTUD).
//!
//! Limitations:
//! - Lower bandwidth than TCP/UDP
//! - May be rate-limited by ISPs
//! - Best used as fallback/control channel

use super::packet::{IpHeader, IcmpHeader, PacketBuilder, Packet, TransportHeader};
use super::raw_socket::RawSocket;
use super::{Transport, TransportStats};
use crate::config::TransportMode;
use crate::error::{PhantomError, Result};
use crate::utils::random_u16;

use async_trait::async_trait;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use std::sync::Arc;
use parking_lot::RwLock;
use std::collections::HashMap;

/// ICMP tunnel session
pub struct IcmpSession {
    /// Identifier for ICMP echo (acts like a "port")
    pub identifier: u16,
    /// Sequence number counter
    pub sequence: AtomicU16,
    /// Remote peer IP
    pub remote_ip: Ipv4Addr,
}

impl IcmpSession {
    pub fn new(identifier: u16, remote_ip: Ipv4Addr) -> Self {
        Self {
            identifier,
            sequence: AtomicU16::new(0),
            remote_ip,
        }
    }

    pub fn next_sequence(&self) -> u16 {
        self.sequence.fetch_add(1, Ordering::SeqCst)
    }
}

/// ICMP Transport implementation
pub struct IcmpTransport {
    socket: Arc<RawSocket>,
    local_ip: Ipv4Addr,
    identifier: u16,
    sequence: AtomicU16,
    sessions: Arc<RwLock<HashMap<Ipv4Addr, Arc<IcmpSession>>>>,
    stats: Arc<TransportStatsInner>,
    running: Arc<AtomicBool>,
    is_client: bool,
}

struct TransportStatsInner {
    packets_sent: AtomicU64,
    packets_recv: AtomicU64,
    bytes_sent: AtomicU64,
    bytes_recv: AtomicU64,
    packets_dropped: AtomicU64,
}

impl IcmpTransport {
    /// Create a new ICMP transport
    pub async fn new(bind_addr: SocketAddr) -> Result<Self> {
        let socket = RawSocket::icmp()?;

        let local_ip = match bind_addr {
            SocketAddr::V4(v4) => *v4.ip(),
            SocketAddr::V6(_) => return Err(PhantomError::Config("IPv6 not supported".into())),
        };

        // Generate random identifier (acts like a port)
        let identifier = random_u16();

        Ok(Self {
            socket: Arc::new(socket),
            local_ip,
            identifier,
            sequence: AtomicU16::new(0),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(TransportStatsInner {
                packets_sent: AtomicU64::new(0),
                packets_recv: AtomicU64::new(0),
                bytes_sent: AtomicU64::new(0),
                bytes_recv: AtomicU64::new(0),
                packets_dropped: AtomicU64::new(0),
            }),
            running: Arc::new(AtomicBool::new(true)),
            is_client: true,
        })
    }

    /// Create with a specific identifier
    pub async fn with_identifier(bind_addr: SocketAddr, identifier: u16) -> Result<Self> {
        let mut transport = Self::new(bind_addr).await?;
        transport.identifier = identifier;
        Ok(transport)
    }

    /// Set as server mode (responds with Echo Reply)
    pub fn set_server_mode(&mut self) {
        self.is_client = false;
    }

    /// Get the identifier
    pub fn identifier(&self) -> u16 {
        self.identifier
    }

    /// Get next sequence number
    fn next_sequence(&self) -> u16 {
        self.sequence.fetch_add(1, Ordering::SeqCst)
    }

    /// Build an ICMP Echo Request packet
    fn build_echo_request(&self, dst_ip: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
        let seq = self.next_sequence();

        let mut packet = PacketBuilder::new(1, self.local_ip, dst_ip)
            .icmp_echo_request(self.identifier, seq)
            .payload(payload)
            .build();

        packet.to_bytes()
    }

    /// Build an ICMP Echo Reply packet
    fn build_echo_reply(&self, dst_ip: Ipv4Addr, identifier: u16, sequence: u16, payload: &[u8]) -> Vec<u8> {
        let mut packet = PacketBuilder::new(1, self.local_ip, dst_ip)
            .icmp_echo_reply(identifier, sequence)
            .payload(payload)
            .build();

        packet.to_bytes()
    }

    /// Parse an incoming ICMP packet
    fn parse_packet(&self, data: &[u8]) -> Result<(Ipv4Addr, u16, u16, Vec<u8>, bool)> {
        let packet = Packet::from_bytes(data)?;

        if packet.ip.protocol != 1 {
            return Err(PhantomError::InvalidPacket("Not an ICMP packet".into()));
        }

        if let TransportHeader::Icmp(icmp) = &packet.transport {
            let is_reply = icmp.icmp_type == IcmpHeader::ECHO_REPLY;
            let is_request = icmp.icmp_type == IcmpHeader::ECHO_REQUEST;

            if !is_reply && !is_request {
                return Err(PhantomError::InvalidPacket(
                    format!("Unsupported ICMP type: {}", icmp.icmp_type)
                ));
            }

            // In client mode, we expect replies with our identifier
            // In server mode, we accept any requests
            if self.is_client {
                if !is_reply || icmp.identifier != self.identifier {
                    return Err(PhantomError::InvalidPacket("Not our ICMP reply".into()));
                }
            }

            Ok((
                packet.ip.src_ip,
                icmp.identifier,
                icmp.sequence,
                packet.payload.clone(),
                is_request,
            ))
        } else {
            Err(PhantomError::InvalidPacket("Missing ICMP header".into()))
        }
    }

    /// Get or create a session for a remote IP
    fn get_or_create_session(&self, remote_ip: Ipv4Addr) -> Arc<IcmpSession> {
        let mut sessions = self.sessions.write();
        sessions.entry(remote_ip)
            .or_insert_with(|| Arc::new(IcmpSession::new(self.identifier, remote_ip)))
            .clone()
    }
}

#[async_trait]
impl Transport for IcmpTransport {
    fn mode(&self) -> TransportMode {
        TransportMode::Icmp
    }

    async fn send(&self, data: &[u8], dst: SocketAddr) -> Result<usize> {
        let dst_ip = match dst {
            SocketAddr::V4(v4) => *v4.ip(),
            _ => return Err(PhantomError::Config("IPv6 not supported".into())),
        };

        // Build and send ICMP Echo Request
        let packet = self.build_echo_request(dst_ip, data);
        self.socket.send_to(&packet, dst).await?;

        self.stats.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.stats.bytes_sent.fetch_add(packet.len() as u64, Ordering::Relaxed);

        Ok(data.len())
    }

    async fn recv(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        let mut raw_buf = [0u8; 65535];

        loop {
            let (n, _) = self.socket.recv_from(&mut raw_buf).await?;

            if n < IpHeader::MIN_SIZE + IcmpHeader::SIZE {
                continue;
            }

            match self.parse_packet(&raw_buf[..n]) {
                Ok((src_ip, identifier, sequence, payload, is_request)) => {
                    // If we're in server mode and got a request, send a reply
                    if !self.is_client && is_request {
                        // Echo back with reply (for now, just record the session)
                        let session = self.get_or_create_session(src_ip);

                        // The payload contains the actual tunnel data
                        // We don't auto-reply here; the tunnel layer handles responses
                    }

                    let len = payload.len().min(buf.len());
                    buf[..len].copy_from_slice(&payload[..len]);

                    self.stats.packets_recv.fetch_add(1, Ordering::Relaxed);
                    self.stats.bytes_recv.fetch_add(len as u64, Ordering::Relaxed);

                    return Ok((len, SocketAddr::V4(SocketAddrV4::new(src_ip, identifier))));
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

/// ICMP tunnel with rate limiting to avoid detection
pub struct RateLimitedIcmpTransport {
    inner: IcmpTransport,
    /// Minimum interval between packets (microseconds)
    min_interval_us: u64,
    /// Last send time
    last_send: std::sync::atomic::AtomicU64,
}

impl RateLimitedIcmpTransport {
    pub async fn new(bind_addr: SocketAddr, packets_per_second: u32) -> Result<Self> {
        let inner = IcmpTransport::new(bind_addr).await?;
        let min_interval_us = if packets_per_second > 0 {
            1_000_000 / packets_per_second as u64
        } else {
            0
        };

        Ok(Self {
            inner,
            min_interval_us,
            last_send: std::sync::atomic::AtomicU64::new(0),
        })
    }

    async fn wait_for_rate_limit(&self) {
        use crate::utils::timestamp_us;

        if self.min_interval_us == 0 {
            return;
        }

        loop {
            let last = self.last_send.load(Ordering::SeqCst);
            let now = timestamp_us();
            let elapsed = now.saturating_sub(last);

            if elapsed >= self.min_interval_us {
                if self.last_send.compare_exchange(
                    last,
                    now,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                ).is_ok() {
                    return;
                }
            } else {
                let wait_us = self.min_interval_us - elapsed;
                tokio::time::sleep(tokio::time::Duration::from_micros(wait_us)).await;
            }
        }
    }
}

#[async_trait]
impl Transport for RateLimitedIcmpTransport {
    fn mode(&self) -> TransportMode {
        TransportMode::Icmp
    }

    async fn send(&self, data: &[u8], dst: SocketAddr) -> Result<usize> {
        self.wait_for_rate_limit().await;
        self.inner.send(data, dst).await
    }

    async fn recv(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        self.inner.recv(buf).await
    }

    async fn close(&self) -> Result<()> {
        self.inner.close().await
    }

    fn is_healthy(&self) -> bool {
        self.inner.is_healthy()
    }

    fn stats(&self) -> TransportStats {
        self.inner.stats()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_icmp_session() {
        let session = IcmpSession::new(1234, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(session.next_sequence(), 0);
        assert_eq!(session.next_sequence(), 1);
        assert_eq!(session.next_sequence(), 2);
    }
}
