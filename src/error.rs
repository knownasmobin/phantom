//! Error types for Phantom tunnel

use thiserror::Error;

pub type Result<T> = std::result::Result<T, PhantomError>;

#[derive(Error, Debug)]
pub enum PhantomError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Socket error: {0}")]
    Socket(String),

    #[error("Raw socket requires root/CAP_NET_RAW privileges")]
    InsufficientPrivileges,

    #[error("Packet parsing error: {0}")]
    PacketParse(String),

    #[error("Packet too large: {size} > {max}")]
    PacketTooLarge { size: usize, max: usize },

    #[error("Invalid packet: {0}")]
    InvalidPacket(String),

    #[error("Checksum mismatch")]
    ChecksumMismatch,

    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Decryption error: {0}")]
    Decryption(String),

    #[error("Handshake failed: {0}")]
    HandshakeFailed(String),

    #[error("Connection timeout")]
    Timeout,

    #[error("Connection reset by peer")]
    ConnectionReset,

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Transport not available: {0}")]
    TransportUnavailable(String),

    #[error("Geneva strategy failed: {0}")]
    GenevaStrategy(String),

    #[error("FEC decode failed: insufficient shards")]
    FecDecodeFailed,

    #[error("Replay attack detected")]
    ReplayAttack,

    #[error("Invalid state: {0}")]
    InvalidState(String),

    #[error("Channel closed")]
    ChannelClosed,

    #[error("Noise protocol error: {0}")]
    Noise(String),
}

impl From<chacha20poly1305::Error> for PhantomError {
    fn from(_: chacha20poly1305::Error) -> Self {
        PhantomError::Decryption("ChaCha20-Poly1305 AEAD error".into())
    }
}

impl From<snow::Error> for PhantomError {
    fn from(e: snow::Error) -> Self {
        PhantomError::Noise(e.to_string())
    }
}
