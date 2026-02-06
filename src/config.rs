//! Configuration structures for Phantom tunnel

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

/// Main configuration for Phantom
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Operating mode
    pub mode: Mode,

    /// Network configuration
    pub network: NetworkConfig,

    /// Transport configuration
    pub transport: TransportConfig,

    /// Geneva engine configuration
    pub geneva: GenevaConfig,

    /// Handshake/mimicry configuration
    pub handshake: HandshakeConfig,

    /// Cryptography configuration
    pub crypto: CryptoConfig,

    /// FEC configuration
    pub fec: FecConfig,

    /// Logging level
    pub log_level: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mode: Mode::Client,
            network: NetworkConfig::default(),
            transport: TransportConfig::default(),
            geneva: GenevaConfig::default(),
            handshake: HandshakeConfig::default(),
            crypto: CryptoConfig::default(),
            fec: FecConfig::default(),
            log_level: "info".into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Mode {
    Client,
    Server,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Local bind address (for server) or local tunnel interface
    pub bind_addr: SocketAddr,

    /// Remote server address (for client)
    pub remote_addr: Option<SocketAddr>,

    /// Interface to use for raw sockets
    pub interface: Option<String>,

    /// Connection timeout
    #[serde(with = "humantime_serde")]
    pub timeout: Duration,

    /// Keepalive interval
    #[serde(with = "humantime_serde")]
    pub keepalive: Duration,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:443".parse().unwrap(),
            remote_addr: None,
            interface: None,
            timeout: Duration::from_secs(30),
            keepalive: Duration::from_secs(15),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportConfig {
    /// Primary transport mode
    pub primary: TransportMode,

    /// Fallback transport modes in order of preference
    pub fallback: Vec<TransportMode>,

    /// Enable automatic transport switching
    pub auto_switch: bool,

    /// Threshold for switching (packet loss percentage)
    pub switch_threshold: f32,

    /// Fixed sending rate (bytes/sec), 0 for adaptive
    pub send_rate: u64,

    /// Enable TCP congestion control bypass
    pub bypass_congestion: bool,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            primary: TransportMode::FakeTcp,
            fallback: vec![
                TransportMode::QuicMasq,
                TransportMode::Protocol115,
                TransportMode::Gre,
                TransportMode::Icmp,
                TransportMode::Dns,
            ],
            auto_switch: true,
            switch_threshold: 0.3, // 30% packet loss triggers switch
            send_rate: 0,          // Adaptive
            bypass_congestion: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum TransportMode {
    // --- Standard transports (reimplementations) ---
    /// Raw socket FakeTCP (like udp2raw/Paqet)
    #[default]
    FakeTcp,
    /// IP Protocol 115 (L2TPv3)
    Protocol115,
    /// ICMP Echo tunneling
    Icmp,
    /// DNS query/response tunneling (always whitelisted, low bandwidth)
    Dns,
    /// UDP:443 masquerading as QUIC Initial packets (no root required)
    QuicMasq,
    /// GRE (IP Protocol 47) - infrastructure tunnel protocol
    Gre,

    // --- Novel transports (Phantom inventions) ---
    /// HTTP CL/TE request smuggling (exploits DPI parsing ambiguity)
    HttpSmuggle,
    /// HLS video stream parasiting (covert data in MPEG-TS packets)
    VideoParasite,
    /// Protocol entropy morphing (session-unique wire format)
    ProtoMorph,

    /// Standard TCP (fallback)
    Tcp,
}

impl TransportMode {
    pub fn protocol_number(&self) -> u8 {
        match self {
            TransportMode::FakeTcp => 6, // TCP
            TransportMode::Protocol115 => 115,
            TransportMode::Icmp => 1,
            TransportMode::Dns => 17,      // UDP (DNS uses UDP)
            TransportMode::QuicMasq => 17, // UDP
            TransportMode::Gre => 47,
            TransportMode::HttpSmuggle => 6,   // TCP (HTTP)
            TransportMode::VideoParasite => 6, // TCP (HTTPS)
            TransportMode::ProtoMorph => 6,    // TCP
            TransportMode::Tcp => 6,
        }
    }

    /// Whether this transport requires raw socket (root) privileges
    pub fn requires_raw_socket(&self) -> bool {
        match self {
            TransportMode::FakeTcp => true,
            TransportMode::Protocol115 => true,
            TransportMode::Icmp => true,
            TransportMode::Gre => true,
            TransportMode::Dns => false,           // Standard UDP socket
            TransportMode::QuicMasq => false,      // Standard UDP socket
            TransportMode::HttpSmuggle => false,   // Standard TCP socket
            TransportMode::VideoParasite => false, // Standard TCP socket
            TransportMode::ProtoMorph => false,    // Standard TCP socket
            TransportMode::Tcp => false,
        }
    }

    /// Whether this is a novel Phantom-invented transport
    pub fn is_novel(&self) -> bool {
        matches!(
            self,
            TransportMode::HttpSmuggle | TransportMode::VideoParasite | TransportMode::ProtoMorph
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenevaConfig {
    /// Enable Geneva engine
    pub enabled: bool,

    /// Active strategies
    pub strategies: Vec<GenevaStrategy>,

    /// Probability of applying strategy (0.0-1.0)
    pub probability: f32,
}

impl Default for GenevaConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            strategies: vec![
                GenevaStrategy::TcpSegmentation,
                GenevaStrategy::ChecksumPoisoning,
                GenevaStrategy::TtlExpiry,
            ],
            probability: 0.8,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GenevaStrategy {
    /// Split TCP payload into segments
    TcpSegmentation,
    /// Send packets with bad checksums to confuse middleboxes
    ChecksumPoisoning,
    /// Use TTL to make packets expire after GFW but before server
    TtlExpiry,
    /// Send duplicate ACKs during handshake
    DuplicateAck,
    /// Send FIN packets before SYN
    FinBeforeSyn,
    /// Inject RST with short TTL
    RstWithShortTtl,
    /// Out of order segments
    OutOfOrder,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeConfig {
    /// SNI to spoof in TLS ClientHello
    pub spoof_sni: String,

    /// Target domestic service to mimic
    pub mimic_target: MimicTarget,

    /// Custom JA3 fingerprint (None = auto-generate based on target)
    pub ja3_fingerprint: Option<String>,

    /// Enable TLS fingerprint randomization
    pub randomize_fingerprint: bool,

    /// Padding bytes to add (statistical mimicry)
    pub initial_padding: usize,
}

impl Default for HandshakeConfig {
    fn default() -> Self {
        Self {
            spoof_sni: "messenger.rubika.ir".into(),
            mimic_target: MimicTarget::Rubika,
            ja3_fingerprint: None,
            randomize_fingerprint: false,
            initial_padding: 256,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MimicTarget {
    /// Rubika messenger (most popular in Iran)
    Rubika,
    /// Eitaa messenger
    Eitaa,
    /// Soroush messenger
    Soroush,
    /// Bale messenger
    Bale,
    /// Generic Chrome browser
    Chrome,
    /// Generic Firefox browser
    Firefox,
}

impl MimicTarget {
    pub fn default_sni(&self) -> &'static str {
        match self {
            MimicTarget::Rubika => "messenger.rubika.ir",
            MimicTarget::Eitaa => "eitaa.com",
            MimicTarget::Soroush => "soroush-app.ir",
            MimicTarget::Bale => "bale.ai",
            MimicTarget::Chrome => "www.google.com",
            MimicTarget::Firefox => "www.mozilla.org",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoConfig {
    /// Path to private key file
    pub private_key: Option<PathBuf>,

    /// Path to peer's public key (client only)
    pub peer_public_key: Option<PathBuf>,

    /// Pre-shared key for additional authentication
    pub psk: Option<String>,

    /// Enable replay protection
    pub replay_protection: bool,

    /// Replay window size (number of packets)
    pub replay_window: u32,

    /// Rekey interval
    #[serde(with = "humantime_serde")]
    pub rekey_interval: Duration,
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            private_key: None,
            peer_public_key: None,
            psk: None,
            replay_protection: true,
            replay_window: 1024,
            rekey_interval: Duration::from_secs(3600), // 1 hour
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FecConfig {
    /// Enable FEC
    pub enabled: bool,

    /// Data shards (original packets)
    pub data_shards: usize,

    /// Parity shards (redundancy)
    pub parity_shards: usize,

    /// Shard size
    pub shard_size: usize,
}

impl Default for FecConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            data_shards: 10,
            parity_shards: 3, // Can recover from 30% loss
            shard_size: 1300,
        }
    }
}

// Helper module for Duration serialization
mod humantime_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(duration.as_secs())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let secs = u64::deserialize(deserializer)?;
        Ok(Duration::from_secs(secs))
    }
}
