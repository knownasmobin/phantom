//! Key management for Phantom tunnel

use crate::error::{PhantomError, Result};
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};
use std::fmt;
use std::path::Path;

/// A Curve25519 public key
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    pub const SIZE: usize = 32;

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(PhantomError::Config("Invalid public key length".into()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_base64(&self) -> String {
        base64::encode(&self.0)
    }

    pub fn from_base64(s: &str) -> Result<Self> {
        let bytes = base64::decode(s)
            .map_err(|e| PhantomError::Config(format!("Invalid base64: {}", e)))?;
        Self::from_bytes(&bytes)
    }

    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s)
            .map_err(|e| PhantomError::Config(format!("Invalid hex: {}", e)))?;
        Self::from_bytes(&bytes)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({}...)", &self.to_hex()[..8])
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_base64())
    }
}

/// A Curve25519 private key
pub struct PrivateKey(StaticSecret);

impl PrivateKey {
    pub const SIZE: usize = 32;

    /// Generate a new random private key
    pub fn generate() -> Self {
        Self(StaticSecret::random_from_rng(OsRng))
    }

    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(PhantomError::Config("Invalid private key length".into()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Self(StaticSecret::from(arr)))
    }

    /// Get the raw bytes
    pub fn as_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Derive the public key
    pub fn public_key(&self) -> PublicKey {
        let public = X25519Public::from(&self.0);
        PublicKey(*public.as_bytes())
    }

    /// Perform Diffie-Hellman key exchange
    pub fn diffie_hellman(&self, peer_public: &PublicKey) -> [u8; 32] {
        let peer = X25519Public::from(peer_public.0);
        let shared = self.0.diffie_hellman(&peer);
        *shared.as_bytes()
    }

    pub fn to_base64(&self) -> String {
        base64::encode(self.as_bytes())
    }

    pub fn from_base64(s: &str) -> Result<Self> {
        let bytes = base64::decode(s)
            .map_err(|e| PhantomError::Config(format!("Invalid base64: {}", e)))?;
        Self::from_bytes(&bytes)
    }
}

impl Clone for PrivateKey {
    fn clone(&self) -> Self {
        Self::from_bytes(&self.as_bytes()).unwrap()
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PrivateKey([REDACTED])")
    }
}

/// A key pair (private + public)
#[derive(Clone)]
pub struct KeyPair {
    pub private: PrivateKey,
    pub public: PublicKey,
}

impl KeyPair {
    /// Generate a new random key pair
    pub fn generate() -> Self {
        let private = PrivateKey::generate();
        let public = private.public_key();
        Self { private, public }
    }

    /// Create from a private key
    pub fn from_private(private: PrivateKey) -> Self {
        let public = private.public_key();
        Self { private, public }
    }

    /// Load from file
    pub fn load(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| PhantomError::Config(format!("Failed to read key file: {}", e)))?;

        let private = PrivateKey::from_base64(contents.trim())?;
        Ok(Self::from_private(private))
    }

    /// Save to file
    pub fn save(&self, path: &Path) -> Result<()> {
        std::fs::write(path, self.private.to_base64())
            .map_err(|e| PhantomError::Config(format!("Failed to write key file: {}", e)))
    }
}

impl fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyPair")
            .field("public", &self.public)
            .field("private", &"[REDACTED]")
            .finish()
    }
}

/// Pre-shared key for additional authentication
#[derive(Clone)]
pub struct PreSharedKey([u8; 32]);

impl PreSharedKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(PhantomError::Config("PSK must be 32 bytes".into()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }

    pub fn from_passphrase(passphrase: &str) -> Self {
        use blake2::{Blake2b512, Digest};
        let mut hasher = Blake2b512::new();
        hasher.update(b"phantom-psk-v1");
        hasher.update(passphrase.as_bytes());
        let result = hasher.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&result[..32]);
        Self(arr)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for PreSharedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PreSharedKey([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let keypair = KeyPair::generate();
        assert_eq!(keypair.public.as_bytes().len(), 32);
    }

    #[test]
    fn test_diffie_hellman() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();

        let shared_alice = alice.private.diffie_hellman(&bob.public);
        let shared_bob = bob.private.diffie_hellman(&alice.public);

        assert_eq!(shared_alice, shared_bob);
    }

    #[test]
    fn test_key_serialization() {
        let keypair = KeyPair::generate();
        let b64 = keypair.private.to_base64();
        let loaded = PrivateKey::from_base64(&b64).unwrap();
        assert_eq!(loaded.public_key().as_bytes(), keypair.public.as_bytes());
    }

    #[test]
    fn test_psk_from_passphrase() {
        let psk1 = PreSharedKey::from_passphrase("test password");
        let psk2 = PreSharedKey::from_passphrase("test password");
        let psk3 = PreSharedKey::from_passphrase("different password");

        assert_eq!(psk1.as_bytes(), psk2.as_bytes());
        assert_ne!(psk1.as_bytes(), psk3.as_bytes());
    }
}
