//! Transport layer for Phantom tunnel
//!
//! Provides multiple transport mechanisms:
//! - FakeTCP: Raw socket TCP with kernel bypass
//! - Protocol 115: L2TPv3-style raw IP packets
//! - ICMP: Echo request/reply tunneling

pub mod raw_socket;
pub mod fake_tcp;
pub mod protocol_115;
pub mod icmp;
pub mod packet;

use crate::config::TransportMode;
use crate::error::Result;
use async_trait::async_trait;
use std::net::SocketAddr;

pub use fake_tcp::FakeTcpTransport;
pub use protocol_115::Protocol115Transport;
pub use icmp::IcmpTransport;
pub use packet::{Packet, PacketBuilder};

/// Trait for all transport implementations
#[async_trait]
pub trait Transport: Send + Sync {
    /// Get the transport mode
    fn mode(&self) -> TransportMode;

    /// Send a packet
    async fn send(&self, data: &[u8], dst: SocketAddr) -> Result<usize>;

    /// Receive a packet
    async fn recv(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)>;

    /// Close the transport
    async fn close(&self) -> Result<()>;

    /// Check if transport is healthy
    fn is_healthy(&self) -> bool;

    /// Get current statistics
    fn stats(&self) -> TransportStats;
}

/// Statistics for transport monitoring
#[derive(Debug, Clone, Default)]
pub struct TransportStats {
    pub packets_sent: u64,
    pub packets_recv: u64,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub packets_dropped: u64,
    pub retransmissions: u64,
    pub avg_rtt_ms: f64,
}

/// Create a transport based on mode
pub async fn create_transport(
    mode: TransportMode,
    bind_addr: SocketAddr,
) -> Result<Box<dyn Transport>> {
    match mode {
        TransportMode::FakeTcp => {
            let transport = FakeTcpTransport::new(bind_addr).await?;
            Ok(Box::new(transport))
        }
        TransportMode::Protocol115 => {
            let transport = Protocol115Transport::new(bind_addr).await?;
            Ok(Box::new(transport))
        }
        TransportMode::Icmp => {
            let transport = IcmpTransport::new(bind_addr).await?;
            Ok(Box::new(transport))
        }
        TransportMode::Tcp => {
            // Standard TCP fallback - uses FakeTcp in passthrough mode
            let transport = FakeTcpTransport::new_passthrough(bind_addr).await?;
            Ok(Box::new(transport))
        }
    }
}
