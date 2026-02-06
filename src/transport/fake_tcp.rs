//! FakeTCP Transport
//!
//! Implements TCP-like behavior using raw sockets, bypassing the kernel's TCP stack.
//! This allows for:
//! - Custom TCP flags and options
//! - Ignoring kernel RST packets
//! - Custom congestion control (or none)
//! - Geneva strategy integration

use super::packet::{IpHeader, TcpHeader, TcpFlags, Packet, TransportHeader, PacketBuilder};
use super::raw_socket::{RawSocket, IptablesGuard};
use super::{Transport, TransportStats};
use crate::config::TransportMode;
use crate::error::{PhantomError, Result};
use crate::utils::{random_u16, random_u32};

use async_trait::async_trait;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::{Duration, Instant};

/// FakeTCP connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

/// Connection tracking for a single FakeTCP session
pub struct FakeTcpConnection {
    pub state: TcpState,
    pub local_addr: SocketAddrV4,
    pub remote_addr: SocketAddrV4,
    pub local_seq: AtomicU32,
    pub local_ack: AtomicU32,
    pub remote_seq: u32,
    pub remote_ack: u32,
    pub window: u16,
    pub last_activity: Instant,
}

impl FakeTcpConnection {
    pub fn new(local_addr: SocketAddrV4, remote_addr: SocketAddrV4) -> Self {
        Self {
            state: TcpState::Closed,
            local_addr,
            remote_addr,
            local_seq: AtomicU32::new(random_u32()),
            local_ack: AtomicU32::new(0),
            remote_seq: 0,
            remote_ack: 0,
            window: 65535,
            last_activity: Instant::now(),
        }
    }

    pub fn next_seq(&self, len: u32) -> u32 {
        self.local_seq.fetch_add(len, Ordering::SeqCst)
    }

    pub fn current_seq(&self) -> u32 {
        self.local_seq.load(Ordering::SeqCst)
    }

    pub fn set_ack(&self, ack: u32) {
        self.local_ack.store(ack, Ordering::SeqCst);
    }

    pub fn current_ack(&self) -> u32 {
        self.local_ack.load(Ordering::SeqCst)
    }
}

/// FakeTCP Transport implementation
pub struct FakeTcpTransport {
    socket: Arc<RawSocket>,
    local_addr: SocketAddr,
    local_ip: Ipv4Addr,
    local_port: u16,
    connections: Arc<RwLock<HashMap<SocketAddrV4, Arc<RwLock<FakeTcpConnection>>>>>,
    stats: Arc<TransportStatsInner>,
    running: Arc<AtomicBool>,
    passthrough: bool, // If true, use standard TCP behavior
    _iptables_guard: Option<IptablesGuard>,
}

struct TransportStatsInner {
    packets_sent: AtomicU64,
    packets_recv: AtomicU64,
    bytes_sent: AtomicU64,
    bytes_recv: AtomicU64,
    packets_dropped: AtomicU64,
    retransmissions: AtomicU64,
}

impl FakeTcpTransport {
    /// Create a new FakeTCP transport
    pub async fn new(bind_addr: SocketAddr) -> Result<Self> {
        let socket = RawSocket::tcp()?;

        let local_ip = match bind_addr {
            SocketAddr::V4(v4) => *v4.ip(),
            SocketAddr::V6(_) => return Err(PhantomError::Config("IPv6 not supported".into())),
        };

        let local_port = if bind_addr.port() == 0 {
            random_u16() | 0x8000 // High port
        } else {
            bind_addr.port()
        };

        // Set up iptables to block kernel RST
        let iptables_guard = match IptablesGuard::new_server(local_port) {
            Ok(guard) => Some(guard),
            Err(e) => {
                tracing::warn!("Failed to set up iptables rules: {}. Continuing without RST suppression.", e);
                None
            }
        };

        Ok(Self {
            socket: Arc::new(socket),
            local_addr: bind_addr,
            local_ip,
            local_port,
            connections: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(TransportStatsInner {
                packets_sent: AtomicU64::new(0),
                packets_recv: AtomicU64::new(0),
                bytes_sent: AtomicU64::new(0),
                bytes_recv: AtomicU64::new(0),
                packets_dropped: AtomicU64::new(0),
                retransmissions: AtomicU64::new(0),
            }),
            running: Arc::new(AtomicBool::new(true)),
            passthrough: false,
            _iptables_guard: iptables_guard,
        })
    }

    /// Create a passthrough transport (standard TCP behavior)
    pub async fn new_passthrough(bind_addr: SocketAddr) -> Result<Self> {
        let mut transport = Self::new(bind_addr).await?;
        transport.passthrough = true;
        Ok(transport)
    }

    /// Perform a FakeTCP handshake with a remote peer
    pub async fn connect(&self, remote_addr: SocketAddr) -> Result<()> {
        let remote = match remote_addr {
            SocketAddr::V4(v4) => v4,
            _ => return Err(PhantomError::Config("IPv6 not supported".into())),
        };

        let local = SocketAddrV4::new(self.local_ip, self.local_port);
        let conn = Arc::new(RwLock::new(FakeTcpConnection::new(local, remote)));

        // Send SYN
        {
            let mut c = conn.write();
            c.state = TcpState::SynSent;
            let seq = c.next_seq(1); // SYN consumes 1 sequence number

            let mut packet = PacketBuilder::new(6, self.local_ip, *remote.ip())
                .tcp(self.local_port, remote.port())
                .tcp_flags(TcpFlags::syn())
                .tcp_seq(seq)
                .tcp_window(65535)
                .build();

            let data = packet.to_bytes();
            self.socket.send_to(&data, remote_addr).await?;
            self.stats.packets_sent.fetch_add(1, Ordering::Relaxed);
            self.stats.bytes_sent.fetch_add(data.len() as u64, Ordering::Relaxed);
        }

        // Wait for SYN-ACK
        let mut buf = [0u8; 65535];
        let timeout = Duration::from_secs(10);
        let start = Instant::now();

        loop {
            if start.elapsed() > timeout {
                return Err(PhantomError::Timeout);
            }

            tokio::select! {
                result = self.socket.recv_from(&mut buf) => {
                    let (n, src) = result?;
                    if n < 40 { continue; } // IP + TCP headers

                    let packet = Packet::from_bytes(&buf[..n])?;

                    // Check if this is from our target
                    if packet.ip.src_ip != *remote.ip() {
                        continue;
                    }

                    if let TransportHeader::Tcp(tcp) = &packet.transport {
                        if tcp.flags.syn && tcp.flags.ack {
                            // Got SYN-ACK
                            let mut c = conn.write();
                            c.remote_seq = tcp.seq_num;
                            c.set_ack(tcp.seq_num + 1);
                            c.state = TcpState::Established;

                            // Send ACK
                            let seq = c.current_seq();
                            let ack = c.current_ack();

                            let mut ack_packet = PacketBuilder::new(6, self.local_ip, *remote.ip())
                                .tcp(self.local_port, remote.port())
                                .tcp_flags(TcpFlags::ack())
                                .tcp_seq(seq)
                                .tcp_ack(ack)
                                .tcp_window(65535)
                                .build();

                            let data = ack_packet.to_bytes();
                            self.socket.send_to(&data, remote_addr).await?;
                            self.stats.packets_sent.fetch_add(1, Ordering::Relaxed);

                            // Store connection
                            self.connections.write().insert(remote, conn.clone());

                            return Ok(());
                        }
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(100)) => {
                    continue;
                }
            }
        }
    }

    /// Send data over an established connection
    pub async fn send_data(&self, data: &[u8], remote: SocketAddrV4) -> Result<usize> {
        let conn = self.connections.read()
            .get(&remote)
            .cloned()
            .ok_or_else(|| PhantomError::InvalidState("No connection".into()))?;

        let (seq, ack) = {
            let mut c = conn.write();
            if c.state != TcpState::Established {
                return Err(PhantomError::InvalidState("Connection not established".into()));
            }
            let seq = c.next_seq(data.len() as u32);
            let ack = c.current_ack();
            c.last_activity = Instant::now();
            (seq, ack)
        };

        let mut packet = PacketBuilder::new(6, self.local_ip, *remote.ip())
            .tcp(self.local_port, remote.port())
            .tcp_flags(TcpFlags::psh_ack())
            .tcp_seq(seq)
            .tcp_ack(ack)
            .tcp_window(65535)
            .payload(data)
            .build();

        let packet_data = packet.to_bytes();
        let sent = self.socket.send_to(&packet_data, SocketAddr::V4(remote)).await?;

        self.stats.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.stats.bytes_sent.fetch_add(packet_data.len() as u64, Ordering::Relaxed);

        Ok(data.len())
    }

    /// Build a raw TCP packet with custom parameters
    /// This is useful for Geneva strategies
    pub fn build_packet(
        &self,
        remote: SocketAddrV4,
        flags: TcpFlags,
        seq: u32,
        ack: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut packet = PacketBuilder::new(6, self.local_ip, *remote.ip())
            .tcp(self.local_port, remote.port())
            .tcp_flags(flags)
            .tcp_seq(seq)
            .tcp_ack(ack)
            .tcp_window(65535)
            .payload(payload)
            .build();

        packet.to_bytes()
    }

    /// Send a raw packet (for Geneva strategies)
    pub async fn send_raw(&self, packet: &[u8], dst: SocketAddr) -> Result<usize> {
        self.socket.send_to(packet, dst).await
    }

    /// Get or create a connection for a remote address
    pub fn get_or_create_connection(&self, remote: SocketAddrV4) -> Arc<RwLock<FakeTcpConnection>> {
        let mut connections = self.connections.write();
        connections.entry(remote).or_insert_with(|| {
            let local = SocketAddrV4::new(self.local_ip, self.local_port);
            Arc::new(RwLock::new(FakeTcpConnection::new(local, remote)))
        }).clone()
    }
}

#[async_trait]
impl Transport for FakeTcpTransport {
    fn mode(&self) -> TransportMode {
        if self.passthrough {
            TransportMode::Tcp
        } else {
            TransportMode::FakeTcp
        }
    }

    async fn send(&self, data: &[u8], dst: SocketAddr) -> Result<usize> {
        let remote = match dst {
            SocketAddr::V4(v4) => v4,
            _ => return Err(PhantomError::Config("IPv6 not supported".into())),
        };

        // Check if we have an established connection
        let has_conn = self.connections.read().contains_key(&remote);

        if !has_conn {
            // For server mode, create connection on first packet
            let conn = self.get_or_create_connection(remote);
            let mut c = conn.write();
            c.state = TcpState::Established;
            self.connections.write().insert(remote, conn.clone());
        }

        self.send_data(data, remote).await
    }

    async fn recv(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        let mut raw_buf = [0u8; 65535];

        loop {
            let (n, src) = self.socket.recv_from(&mut raw_buf).await?;

            if n < 40 {
                continue; // Too short for IP + TCP
            }

            let packet = match Packet::from_bytes(&raw_buf[..n]) {
                Ok(p) => p,
                Err(_) => continue,
            };

            // Only process TCP packets
            if packet.ip.protocol != 6 {
                continue;
            }

            if let TransportHeader::Tcp(tcp) = &packet.transport {
                // Skip RST packets (likely from kernel)
                if tcp.flags.rst {
                    continue;
                }

                // Skip SYN packets (handled by accept logic)
                if tcp.flags.syn && !tcp.flags.ack {
                    // This is a new connection attempt - handle in server mode
                    let remote = SocketAddrV4::new(packet.ip.src_ip, tcp.src_port);
                    let conn = self.get_or_create_connection(remote);
                    let mut c = conn.write();

                    if c.state == TcpState::Closed || c.state == TcpState::Listen {
                        c.state = TcpState::SynReceived;
                        c.remote_seq = tcp.seq_num;
                        c.set_ack(tcp.seq_num + 1);

                        // Send SYN-ACK
                        let seq = c.next_seq(1);
                        let ack = c.current_ack();

                        let mut syn_ack = PacketBuilder::new(6, self.local_ip, packet.ip.src_ip)
                            .tcp(self.local_port, tcp.src_port)
                            .tcp_flags(TcpFlags::syn_ack())
                            .tcp_seq(seq)
                            .tcp_ack(ack)
                            .tcp_window(65535)
                            .build();

                        let data = syn_ack.to_bytes();
                        let _ = self.socket.send_to(&data, SocketAddr::V4(remote)).await;
                    }
                    continue;
                }

                // Handle ACK for SYN-ACK (completes handshake)
                if tcp.flags.ack && !tcp.flags.syn {
                    let remote = SocketAddrV4::new(packet.ip.src_ip, tcp.src_port);

                    if let Some(conn) = self.connections.read().get(&remote).cloned() {
                        let mut c = conn.write();

                        if c.state == TcpState::SynReceived {
                            c.state = TcpState::Established;
                            c.last_activity = Instant::now();
                        }

                        // Update ACK tracking
                        c.remote_ack = tcp.ack_num;
                    }
                }

                // Return payload if present
                if !packet.payload.is_empty() {
                    let remote = SocketAddrV4::new(packet.ip.src_ip, tcp.src_port);

                    // Update connection state
                    if let Some(conn) = self.connections.read().get(&remote).cloned() {
                        let mut c = conn.write();
                        c.set_ack(tcp.seq_num + packet.payload.len() as u32);
                        c.last_activity = Instant::now();

                        // Send ACK
                        let seq = c.current_seq();
                        let ack = c.current_ack();

                        let mut ack_packet = PacketBuilder::new(6, self.local_ip, packet.ip.src_ip)
                            .tcp(self.local_port, tcp.src_port)
                            .tcp_flags(TcpFlags::ack())
                            .tcp_seq(seq)
                            .tcp_ack(ack)
                            .tcp_window(65535)
                            .build();

                        let data = ack_packet.to_bytes();
                        let _ = self.socket.send_to(&data, SocketAddr::V4(remote)).await;
                    }

                    let len = packet.payload.len().min(buf.len());
                    buf[..len].copy_from_slice(&packet.payload[..len]);

                    self.stats.packets_recv.fetch_add(1, Ordering::Relaxed);
                    self.stats.bytes_recv.fetch_add(len as u64, Ordering::Relaxed);

                    return Ok((len, SocketAddr::V4(remote)));
                }
            }
        }
    }

    async fn close(&self) -> Result<()> {
        self.running.store(false, Ordering::SeqCst);

        // Send FIN to all connections
        for (remote, conn) in self.connections.read().iter() {
            let c = conn.read();
            if c.state == TcpState::Established {
                let seq = c.current_seq();
                let ack = c.current_ack();

                let mut fin_packet = PacketBuilder::new(6, self.local_ip, *remote.ip())
                    .tcp(self.local_port, remote.port())
                    .tcp_flags(TcpFlags::fin_ack())
                    .tcp_seq(seq)
                    .tcp_ack(ack)
                    .tcp_window(65535)
                    .build();

                let data = fin_packet.to_bytes();
                let _ = self.socket.send_to(&data, SocketAddr::V4(*remote)).await;
            }
        }

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
            retransmissions: self.stats.retransmissions.load(Ordering::Relaxed),
            avg_rtt_ms: 0.0, // TODO: Implement RTT tracking
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_state_transitions() {
        let local = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), 12345);
        let remote = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 443);
        let mut conn = FakeTcpConnection::new(local, remote);

        assert_eq!(conn.state, TcpState::Closed);
        conn.state = TcpState::SynSent;
        assert_eq!(conn.state, TcpState::SynSent);
    }
}
