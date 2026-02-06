//! Phantom Tunnel - Core tunnel implementation
//!
//! Brings together all components:
//! - Transport layer (FakeTCP, Protocol 115, ICMP)
//! - Geneva engine (DPI evasion)
//! - Cryptography (Noise Protocol)
//! - FEC (packet loss recovery)
//! - Handshake mimicry (TLS fingerprinting)

use crate::config::{Config, TransportMode};
use crate::crypto::noise::SharedNoiseSession;
use crate::crypto::{KeyPair, NoiseSession, PublicKey};
use crate::error::{PhantomError, Result};
use crate::fec::{FecCodec, FecPacket, FecSender};
use crate::geneva::GenevaEngine;
use crate::handshake::generate_client_hello;
use crate::transport::{create_transport, Transport};

use parking_lot::RwLock;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::time::Instant;

/// Tunnel state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelState {
    /// Not connected
    Disconnected,
    /// Performing handshake
    Handshaking,
    /// Fully connected and operational
    Connected,
    /// Connection lost, attempting reconnect
    Reconnecting,
    /// Tunnel closed
    Closed,
}

/// Statistics for the tunnel
#[derive(Debug, Clone, Default)]
pub struct TunnelStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub handshake_time_ms: u64,
    pub current_transport: TransportMode,
    pub transport_switches: u64,
    pub fec_recoveries: u64,
}

/// The main Phantom tunnel
pub struct PhantomTunnel {
    config: Config,
    state: Arc<RwLock<TunnelState>>,
    transport: Arc<RwLock<Option<Arc<dyn Transport>>>>,
    noise_session: Arc<RwLock<Option<SharedNoiseSession>>>,
    geneva: Arc<GenevaEngine>,
    fec_codec: Option<Arc<FecCodec>>,
    local_keypair: KeyPair,
    remote_public: Option<PublicKey>,
    running: Arc<AtomicBool>,
    stats: Arc<RwLock<TunnelStats>>,
}

impl PhantomTunnel {
    /// Create a new tunnel with the given configuration
    pub fn new(config: Config, local_keypair: KeyPair) -> Result<Self> {
        let geneva = Arc::new(GenevaEngine::new(&config.geneva));

        let fec_codec = if config.fec.enabled {
            Some(Arc::new(FecCodec::new(&config.fec)?))
        } else {
            None
        };

        Ok(Self {
            config,
            state: Arc::new(RwLock::new(TunnelState::Disconnected)),
            transport: Arc::new(RwLock::new(None)),
            noise_session: Arc::new(RwLock::new(None)),
            geneva,
            fec_codec,
            local_keypair,
            remote_public: None,
            running: Arc::new(AtomicBool::new(false)),
            stats: Arc::new(RwLock::new(TunnelStats::default())),
        })
    }

    /// Set the remote peer's public key (required for client mode)
    pub fn set_remote_public_key(&mut self, key: PublicKey) {
        self.remote_public = Some(key);
    }

    /// Get current tunnel state
    pub fn state(&self) -> TunnelState {
        *self.state.read()
    }

    /// Get tunnel statistics
    pub fn stats(&self) -> TunnelStats {
        self.stats.read().clone()
    }

    /// Check if tunnel is running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Connect to a remote server (client mode)
    pub async fn connect(&self, remote_addr: SocketAddr) -> Result<()> {
        if self.remote_public.is_none() {
            return Err(PhantomError::Config("Remote public key not set".into()));
        }

        *self.state.write() = TunnelState::Handshaking;
        self.running.store(true, Ordering::SeqCst);

        let start = Instant::now();

        // Create transport
        let transport =
            create_transport(self.config.transport.primary, self.config.network.bind_addr).await?;

        // Generate fake TLS ClientHello for mimicry
        let client_hello = generate_client_hello(&self.config.handshake, None)?;

        // Create Noise session
        let mut noise = NoiseSession::new_initiator(
            self.local_keypair.clone(),
            self.remote_public.unwrap(),
            None, // TODO: Add PSK support
        )?;

        // Send handshake message (embedded in fake TLS ClientHello structure)
        let handshake_msg = noise.write_handshake(&client_hello)?;

        // Apply Geneva strategies to the handshake
        let packets = self.geneva.process_outbound(
            &handshake_msg,
            match self.config.network.bind_addr {
                SocketAddr::V4(v4) => *v4.ip(),
                _ => return Err(PhantomError::Config("IPv6 not supported".into())),
            },
            match remote_addr {
                SocketAddr::V4(v4) => *v4.ip(),
                _ => return Err(PhantomError::Config("IPv6 not supported".into())),
            },
            self.config.network.bind_addr.port(),
            remote_addr.port(),
        )?;

        // Send all Geneva-processed packets
        for packet in packets {
            transport.send(&packet, remote_addr).await?;
        }

        // Wait for response
        let mut buf = vec![0u8; 65535];
        let timeout = self.config.network.timeout;

        let response = tokio::time::timeout(timeout, async {
            loop {
                let (n, _) = transport.recv(&mut buf).await?;
                if n > 0 {
                    return Ok::<_, PhantomError>(buf[..n].to_vec());
                }
            }
        })
        .await
        .map_err(|_| PhantomError::Timeout)??;

        // Process response
        let _payload = noise.read_handshake(&response)?;

        // Handshake complete
        let handshake_time = start.elapsed().as_millis() as u64;

        *self.transport.write() = Some(transport);
        *self.noise_session.write() = Some(SharedNoiseSession::new(noise));
        *self.state.write() = TunnelState::Connected;

        {
            let mut stats = self.stats.write();
            stats.handshake_time_ms = handshake_time;
            stats.current_transport = self.config.transport.primary;
        }

        Ok(())
    }

    /// Start listening for connections (server mode)
    pub async fn listen(&self) -> Result<()> {
        *self.state.write() = TunnelState::Handshaking;
        self.running.store(true, Ordering::SeqCst);

        // Create transport
        let transport =
            create_transport(self.config.transport.primary, self.config.network.bind_addr).await?;

        *self.transport.write() = Some(transport);

        Ok(())
    }

    /// Accept a connection (server mode)
    pub async fn accept(&self) -> Result<(SocketAddr, SharedNoiseSession)> {
        let transport = self
            .transport
            .read()
            .as_ref()
            .ok_or_else(|| PhantomError::InvalidState("Not listening".into()))?
            .clone();

        // Wait for handshake
        let mut buf = vec![0u8; 65535];
        let (n, remote_addr) = transport.recv(&mut buf).await?;

        // Create Noise session for this connection
        let mut noise = NoiseSession::new_responder(
            self.local_keypair.clone(),
            None, // TODO: PSK
        )?;

        // Process handshake
        let _client_payload = noise.read_handshake(&buf[..n])?;

        // Send response
        let response = noise.write_handshake(&[])?;
        transport.send(&response, remote_addr).await?;

        let session = SharedNoiseSession::new(noise);
        *self.state.write() = TunnelState::Connected;

        Ok((remote_addr, session))
    }

    /// Send data through the tunnel
    pub async fn send(&self, data: &[u8], remote_addr: SocketAddr) -> Result<usize> {
        let transport = self
            .transport
            .read()
            .as_ref()
            .ok_or_else(|| PhantomError::InvalidState("Not connected".into()))?
            .clone();

        let session = self
            .noise_session
            .read()
            .as_ref()
            .ok_or_else(|| PhantomError::InvalidState("No session".into()))?
            .clone();

        // Encrypt
        let encrypted = session.encrypt(data)?;

        // Apply FEC if enabled
        let packets_to_send = if let Some(ref codec) = self.fec_codec {
            let mut sender = FecSender::new(codec.clone());
            let fec_packets = sender.encode(&encrypted)?;
            fec_packets.into_iter().map(|p| p.to_bytes()).collect()
        } else {
            vec![encrypted]
        };

        // Apply Geneva and send
        let mut total_sent = 0;
        for packet in packets_to_send {
            let processed = self.geneva.process_outbound(
                &packet,
                match self.config.network.bind_addr {
                    SocketAddr::V4(v4) => *v4.ip(),
                    _ => return Err(PhantomError::Config("IPv6 not supported".into())),
                },
                match remote_addr {
                    SocketAddr::V4(v4) => *v4.ip(),
                    _ => return Err(PhantomError::Config("IPv6 not supported".into())),
                },
                self.config.network.bind_addr.port(),
                remote_addr.port(),
            )?;

            for p in processed {
                transport.send(&p, remote_addr).await?;
                total_sent += p.len();
            }
        }

        // Update stats
        {
            let mut stats = self.stats.write();
            stats.bytes_sent += total_sent as u64;
            stats.packets_sent += 1;
        }

        Ok(data.len())
    }

    /// Receive data from the tunnel
    pub async fn recv(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        let transport = self
            .transport
            .read()
            .as_ref()
            .ok_or_else(|| PhantomError::InvalidState("Not connected".into()))?
            .clone();

        let session = self
            .noise_session
            .read()
            .as_ref()
            .ok_or_else(|| PhantomError::InvalidState("No session".into()))?
            .clone();

        let mut recv_buf = vec![0u8; 65535];
        let (n, remote) = transport.recv(&mut recv_buf).await?;

        // Decrypt
        let decrypted = if let Some(ref codec) = self.fec_codec {
            // Parse FEC packet and try to decode
            let fec_packet = FecPacket::from_bytes(&recv_buf[..n])?;
            // For simplicity, assume single-packet blocks for now
            // A full implementation would use FecReceiver to accumulate
            session.decrypt(&fec_packet.data)?
        } else {
            session.decrypt(&recv_buf[..n])?
        };

        let len = decrypted.len().min(buf.len());
        buf[..len].copy_from_slice(&decrypted[..len]);

        // Update stats
        {
            let mut stats = self.stats.write();
            stats.bytes_received += n as u64;
            stats.packets_received += 1;
        }

        Ok((len, remote))
    }

    /// Switch to a different transport (transport agility)
    pub async fn switch_transport(&self, mode: TransportMode) -> Result<()> {
        let new_transport = create_transport(mode, self.config.network.bind_addr).await?;

        *self.transport.write() = Some(new_transport);

        {
            let mut stats = self.stats.write();
            stats.current_transport = mode;
            stats.transport_switches += 1;
        }

        Ok(())
    }

    /// Close the tunnel
    pub async fn close(&self) -> Result<()> {
        self.running.store(false, Ordering::SeqCst);

        let transport = self.transport.write().take();
        if let Some(transport) = transport {
            transport.close().await?;
        }

        *self.state.write() = TunnelState::Closed;

        Ok(())
    }
}

/// Builder for PhantomTunnel
pub struct TunnelBuilder {
    config: Config,
    local_keypair: Option<KeyPair>,
    remote_public: Option<PublicKey>,
}

impl TunnelBuilder {
    pub fn new() -> Self {
        Self {
            config: Config::default(),
            local_keypair: None,
            remote_public: None,
        }
    }

    pub fn config(mut self, config: Config) -> Self {
        self.config = config;
        self
    }

    pub fn local_keypair(mut self, keypair: KeyPair) -> Self {
        self.local_keypair = Some(keypair);
        self
    }

    pub fn remote_public_key(mut self, key: PublicKey) -> Self {
        self.remote_public = Some(key);
        self
    }

    pub fn build(self) -> Result<PhantomTunnel> {
        let keypair = self.local_keypair.unwrap_or_else(KeyPair::generate);
        let mut tunnel = PhantomTunnel::new(self.config, keypair)?;

        if let Some(remote) = self.remote_public {
            tunnel.set_remote_public_key(remote);
        }

        Ok(tunnel)
    }
}

impl Default for TunnelBuilder {
    fn default() -> Self {
        Self::new()
    }
}
