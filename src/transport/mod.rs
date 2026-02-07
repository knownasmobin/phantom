//! Transport layer for Phantom tunnel
//!
//! Provides multiple transport mechanisms:
//!
//! **Standard transports (reimplementations of known techniques):**
//! - FakeTCP: Raw socket TCP with kernel bypass
//! - Protocol 115: L2TPv3-style raw IP packets
//! - ICMP: Echo request/reply tunneling
//! - DNS: DNS query/response tunneling (always whitelisted)
//! - QUIC Masquerade: UDP:443 mimicking QUIC Initial packets
//! - GRE: Generic Routing Encapsulation (IP Protocol 47)
//!
//! **Novel transports (Phantom inventions):**
//! - HTTP Smuggle: CL/TE desync exploiting DPI parsing bugs
//! - Video Parasite: Covert data in HLS/MPEG-TS packets (first implementation ever)
//! - Proto Morph: Session-unique wire format, no fingerprint possible

pub mod dns_tunnel;
pub mod fake_tcp;
pub mod gre;
pub mod http_smuggle;
pub mod icmp;
pub mod packet;
pub mod proto_morph;
pub mod protocol_115;
pub mod quic_masq;
pub mod raw_socket;
pub mod video_parasite;

use crate::config::TransportMode;
use crate::error::Result;
use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::Arc;

pub use dns_tunnel::DnsTunnelTransport;
pub use fake_tcp::FakeTcpTransport;
pub use gre::GreTransport;
pub use http_smuggle::HttpSmuggleTransport;
pub use icmp::IcmpTransport;
pub use packet::{Packet, PacketBuilder};
pub use proto_morph::ProtoMorphTransport;
pub use protocol_115::Protocol115Transport;
pub use quic_masq::QuicMasqTransport;
pub use video_parasite::VideoParasiteTransport;

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
///
/// When `is_server` is true, TCP-based transports bind a listener and accept connections.
/// When false (client mode), they connect outbound to the destination.
pub async fn create_transport(
    mode: TransportMode,
    bind_addr: SocketAddr,
    is_server: bool,
) -> Result<Arc<dyn Transport>> {
    match mode {
        TransportMode::FakeTcp => {
            let transport = FakeTcpTransport::new(bind_addr).await?;
            Ok(Arc::new(transport))
        }
        TransportMode::Protocol115 => {
            let transport = Protocol115Transport::new(bind_addr).await?;
            Ok(Arc::new(transport))
        }
        TransportMode::Icmp => {
            let transport = IcmpTransport::new(bind_addr).await?;
            Ok(Arc::new(transport))
        }
        TransportMode::Dns => {
            // DNS tunnel requires a tunnel domain - use default
            let transport = if is_server {
                DnsTunnelTransport::new_server(bind_addr, "t.phantom.local".into()).await?
            } else {
                DnsTunnelTransport::new(bind_addr, "t.phantom.local".into()).await?
            };
            Ok(Arc::new(transport))
        }
        TransportMode::QuicMasq => {
            let transport = QuicMasqTransport::new(bind_addr).await?;
            Ok(Arc::new(transport))
        }
        TransportMode::Gre => {
            let transport = GreTransport::new(bind_addr).await?;
            Ok(Arc::new(transport))
        }
        TransportMode::HttpSmuggle => {
            let transport = if is_server {
                HttpSmuggleTransport::new_server(bind_addr).await?
            } else {
                HttpSmuggleTransport::new(bind_addr).await?
            };
            Ok(Arc::new(transport))
        }
        TransportMode::VideoParasite => {
            let transport = if is_server {
                VideoParasiteTransport::new_server(bind_addr).await?
            } else {
                VideoParasiteTransport::new(bind_addr).await?
            };
            Ok(Arc::new(transport))
        }
        TransportMode::ProtoMorph => {
            // ProtoMorph requires a shared seed - use random for factory default
            let transport = if is_server {
                ProtoMorphTransport::new_random_server(bind_addr).await?
            } else {
                ProtoMorphTransport::new_random(bind_addr).await?
            };
            Ok(Arc::new(transport))
        }
        TransportMode::Tcp => {
            // Standard TCP fallback - uses FakeTcp in passthrough mode
            let transport = FakeTcpTransport::new_passthrough(bind_addr).await?;
            Ok(Arc::new(transport))
        }
    }
}

/// Create a DNS transport with a specific tunnel domain
pub async fn create_dns_transport(
    bind_addr: SocketAddr,
    tunnel_domain: String,
    is_server: bool,
) -> Result<Arc<dyn Transport>> {
    let transport = if is_server {
        DnsTunnelTransport::new_server(bind_addr, tunnel_domain).await?
    } else {
        DnsTunnelTransport::new(bind_addr, tunnel_domain).await?
    };
    Ok(Arc::new(transport))
}
