//! Cryptography module for Phantom tunnel
//!
//! Provides:
//! - Noise Protocol Framework for key exchange (IK pattern for 0-RTT)
//! - XChaCha20-Poly1305 for symmetric encryption
//! - Replay protection

pub mod noise;
pub mod symmetric;
pub mod keys;

pub use noise::NoiseSession;
pub use symmetric::{Cipher, encrypt, decrypt};
pub use keys::{KeyPair, PublicKey, PrivateKey};

use crate::error::Result;

/// Maximum payload size for encrypted packets
pub const MAX_PAYLOAD_SIZE: usize = 65535 - 16 - 8; // Max - tag - nonce overhead

/// Nonce size for XChaCha20-Poly1305
pub const NONCE_SIZE: usize = 24;

/// Authentication tag size
pub const TAG_SIZE: usize = 16;
