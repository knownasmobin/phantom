//! Noise Protocol implementation for Phantom tunnel
//!
//! Uses the IK pattern for 0-RTT key exchange:
//! - Initiator (client) knows responder's (server) static public key
//! - Provides forward secrecy and identity hiding for initiator
//!
//! Pattern: Noise_IK_25519_ChaChaPoly_BLAKE2b
//!
//! IK:
//!   <- s
//!   ...
//!   -> e, es, s, ss
//!   <- e, ee, se

use crate::error::{PhantomError, Result};
use crate::crypto::keys::{KeyPair, PublicKey, PreSharedKey};
use snow::{Builder, HandshakeState, TransportState};
use std::sync::Arc;
use parking_lot::Mutex;

/// Noise protocol pattern
const NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2b";

/// Maximum message size for Noise
const MAX_MESSAGE_SIZE: usize = 65535;

/// Handshake message overhead
const HANDSHAKE_OVERHEAD: usize = 64;

/// Transport message overhead (16 bytes for AEAD tag)
const TRANSPORT_OVERHEAD: usize = 16;

/// State of a Noise session
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoiseState {
    /// Handshake not started
    Initial,
    /// Handshake in progress (initiator sent first message)
    HandshakeSent,
    /// Handshake in progress (responder sent response)
    HandshakeReceived,
    /// Handshake complete, transport mode active
    Transport,
    /// Session failed
    Failed,
}

/// A Noise protocol session
pub struct NoiseSession {
    state: NoiseState,
    handshake: Option<HandshakeState>,
    transport: Option<TransportState>,
    local_keypair: KeyPair,
    remote_public: Option<PublicKey>,
    is_initiator: bool,
    psk: Option<PreSharedKey>,
}

impl NoiseSession {
    /// Create a new session as initiator (client)
    ///
    /// The client must know the server's public key in advance
    pub fn new_initiator(
        local_keypair: KeyPair,
        remote_public: PublicKey,
        psk: Option<PreSharedKey>,
    ) -> Result<Self> {
        let mut builder = Builder::new(NOISE_PATTERN.parse().unwrap())
            .local_private_key(&local_keypair.private.as_bytes())
            .remote_public_key(remote_public.as_bytes());

        if let Some(ref psk) = psk {
            builder = builder.psk(0, psk.as_bytes());
        }

        let handshake = builder
            .build_initiator()
            .map_err(|e| PhantomError::Noise(e.to_string()))?;

        Ok(Self {
            state: NoiseState::Initial,
            handshake: Some(handshake),
            transport: None,
            local_keypair,
            remote_public: Some(remote_public),
            is_initiator: true,
            psk,
        })
    }

    /// Create a new session as responder (server)
    pub fn new_responder(
        local_keypair: KeyPair,
        psk: Option<PreSharedKey>,
    ) -> Result<Self> {
        let mut builder = Builder::new(NOISE_PATTERN.parse().unwrap())
            .local_private_key(&local_keypair.private.as_bytes());

        if let Some(ref psk) = psk {
            builder = builder.psk(0, psk.as_bytes());
        }

        let handshake = builder
            .build_responder()
            .map_err(|e| PhantomError::Noise(e.to_string()))?;

        Ok(Self {
            state: NoiseState::Initial,
            handshake: Some(handshake),
            transport: None,
            local_keypair,
            remote_public: None,
            is_initiator: false,
            psk,
        })
    }

    /// Get current state
    pub fn state(&self) -> NoiseState {
        self.state
    }

    /// Check if handshake is complete
    pub fn is_transport_ready(&self) -> bool {
        self.state == NoiseState::Transport
    }

    /// Generate the first handshake message (initiator only)
    ///
    /// Can include an optional payload that will be encrypted
    pub fn write_handshake(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        let handshake = self.handshake.as_mut()
            .ok_or_else(|| PhantomError::InvalidState("No handshake state".into()))?;

        let mut message = vec![0u8; MAX_MESSAGE_SIZE];
        let len = handshake
            .write_message(payload, &mut message)
            .map_err(|e| PhantomError::Noise(e.to_string()))?;

        message.truncate(len);

        if self.is_initiator {
            self.state = NoiseState::HandshakeSent;
        } else {
            // Responder's write completes the handshake
            self.finalize_handshake()?;
        }

        Ok(message)
    }

    /// Process a received handshake message
    ///
    /// Returns the decrypted payload if present
    pub fn read_handshake(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        let handshake = self.handshake.as_mut()
            .ok_or_else(|| PhantomError::InvalidState("No handshake state".into()))?;

        let mut payload = vec![0u8; MAX_MESSAGE_SIZE];
        let len = handshake
            .read_message(message, &mut payload)
            .map_err(|e| PhantomError::Noise(e.to_string()))?;

        payload.truncate(len);

        if self.is_initiator {
            // Initiator reading response completes handshake
            self.state = NoiseState::HandshakeReceived;
            self.finalize_handshake()?;
        } else {
            self.state = NoiseState::HandshakeReceived;
        }

        Ok(payload)
    }

    /// Finalize the handshake and transition to transport mode
    fn finalize_handshake(&mut self) -> Result<()> {
        let handshake = self.handshake.take()
            .ok_or_else(|| PhantomError::InvalidState("No handshake state".into()))?;

        if !handshake.is_handshake_finished() {
            return Err(PhantomError::HandshakeFailed("Handshake not complete".into()));
        }

        // Get remote public key if we're responder
        if !self.is_initiator {
            if let Some(remote_static) = handshake.get_remote_static() {
                self.remote_public = Some(PublicKey::from_bytes(remote_static)?);
            }
        }

        let transport = handshake
            .into_transport_mode()
            .map_err(|e| PhantomError::Noise(e.to_string()))?;

        self.transport = Some(transport);
        self.state = NoiseState::Transport;

        Ok(())
    }

    /// Encrypt a message in transport mode
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let transport = self.transport.as_mut()
            .ok_or_else(|| PhantomError::InvalidState("Not in transport mode".into()))?;

        let mut ciphertext = vec![0u8; plaintext.len() + TRANSPORT_OVERHEAD];
        let len = transport
            .write_message(plaintext, &mut ciphertext)
            .map_err(|e| PhantomError::Encryption(e.to_string()))?;

        ciphertext.truncate(len);
        Ok(ciphertext)
    }

    /// Decrypt a message in transport mode
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let transport = self.transport.as_mut()
            .ok_or_else(|| PhantomError::InvalidState("Not in transport mode".into()))?;

        let mut plaintext = vec![0u8; ciphertext.len()];
        let len = transport
            .read_message(ciphertext, &mut plaintext)
            .map_err(|e| PhantomError::Decryption(e.to_string()))?;

        plaintext.truncate(len);
        Ok(plaintext)
    }

    /// Get the remote peer's public key (available after handshake)
    pub fn remote_public_key(&self) -> Option<&PublicKey> {
        self.remote_public.as_ref()
    }

    /// Get the local public key
    pub fn local_public_key(&self) -> &PublicKey {
        &self.local_keypair.public
    }

    /// Check if we are the initiator
    pub fn is_initiator(&self) -> bool {
        self.is_initiator
    }

    /// Rekey the session (for forward secrecy)
    pub fn rekey(&mut self) -> Result<()> {
        let transport = self.transport.as_mut()
            .ok_or_else(|| PhantomError::InvalidState("Not in transport mode".into()))?;

        transport.rekey_outgoing();
        transport.rekey_incoming();

        Ok(())
    }
}

/// Thread-safe wrapper for NoiseSession
pub struct SharedNoiseSession {
    inner: Arc<Mutex<NoiseSession>>,
}

impl SharedNoiseSession {
    pub fn new(session: NoiseSession) -> Self {
        Self {
            inner: Arc::new(Mutex::new(session)),
        }
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.inner.lock().encrypt(plaintext)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.inner.lock().decrypt(ciphertext)
    }

    pub fn state(&self) -> NoiseState {
        self.inner.lock().state()
    }

    pub fn is_transport_ready(&self) -> bool {
        self.inner.lock().is_transport_ready()
    }
}

impl Clone for SharedNoiseSession {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

/// Perform a complete handshake as initiator
pub async fn handshake_initiator<S, R>(
    session: &mut NoiseSession,
    send: S,
    recv: R,
    initial_payload: &[u8],
) -> Result<Vec<u8>>
where
    S: FnOnce(Vec<u8>) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send>>,
    R: FnOnce() -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>>> + Send>>,
{
    // Send first message
    let msg1 = session.write_handshake(initial_payload)?;
    send(msg1).await?;

    // Receive response
    let msg2 = recv().await?;
    let response_payload = session.read_handshake(&msg2)?;

    Ok(response_payload)
}

/// Perform a complete handshake as responder
pub async fn handshake_responder<S, R>(
    session: &mut NoiseSession,
    send: S,
    recv: R,
    response_payload: &[u8],
) -> Result<Vec<u8>>
where
    S: FnOnce(Vec<u8>) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send>>,
    R: FnOnce() -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>>> + Send>>,
{
    // Receive first message
    let msg1 = recv().await?;
    let initial_payload = session.read_handshake(&msg1)?;

    // Send response
    let msg2 = session.write_handshake(response_payload)?;
    send(msg2).await?;

    Ok(initial_payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_noise_handshake() {
        // Generate keys
        let server_keypair = KeyPair::generate();
        let client_keypair = KeyPair::generate();

        // Create sessions
        let mut client = NoiseSession::new_initiator(
            client_keypair,
            server_keypair.public,
            None,
        ).unwrap();

        let mut server = NoiseSession::new_responder(
            server_keypair,
            None,
        ).unwrap();

        // Client -> Server (first message)
        let msg1 = client.write_handshake(b"hello from client").unwrap();

        // Server processes first message
        let payload1 = server.read_handshake(&msg1).unwrap();
        assert_eq!(payload1, b"hello from client");

        // Server -> Client (response)
        let msg2 = server.write_handshake(b"hello from server").unwrap();

        // Client processes response
        let payload2 = client.read_handshake(&msg2).unwrap();
        assert_eq!(payload2, b"hello from server");

        // Both should be in transport mode
        assert!(client.is_transport_ready());
        assert!(server.is_transport_ready());

        // Test transport encryption
        let plaintext = b"secret message";
        let ciphertext = client.encrypt(plaintext).unwrap();
        let decrypted = server.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);

        // Test reverse direction
        let plaintext2 = b"reply message";
        let ciphertext2 = server.encrypt(plaintext2).unwrap();
        let decrypted2 = client.decrypt(&ciphertext2).unwrap();
        assert_eq!(decrypted2, plaintext2);
    }

    #[test]
    fn test_noise_with_psk() {
        let server_keypair = KeyPair::generate();
        let client_keypair = KeyPair::generate();
        let psk = PreSharedKey::from_passphrase("shared secret");

        let mut client = NoiseSession::new_initiator(
            client_keypair,
            server_keypair.public,
            Some(psk.clone()),
        ).unwrap();

        let mut server = NoiseSession::new_responder(
            server_keypair,
            Some(psk),
        ).unwrap();

        // Perform handshake
        let msg1 = client.write_handshake(&[]).unwrap();
        server.read_handshake(&msg1).unwrap();
        let msg2 = server.write_handshake(&[]).unwrap();
        client.read_handshake(&msg2).unwrap();

        assert!(client.is_transport_ready());
        assert!(server.is_transport_ready());
    }
}
