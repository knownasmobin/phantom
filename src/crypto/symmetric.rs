//! Symmetric encryption using XChaCha20-Poly1305
//!
//! XChaCha20-Poly1305 is chosen over AES-GCM because:
//! - No AES fingerprint (DPI may detect AES patterns)
//! - Larger nonce (192-bit) allows random nonces without collision risk
//! - Constant-time implementation, resistant to timing attacks
//! - High performance on systems without AES-NI

use crate::error::{PhantomError, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand::RngCore;

/// Nonce size for XChaCha20-Poly1305
pub const NONCE_SIZE: usize = 24;

/// Authentication tag size
pub const TAG_SIZE: usize = 16;

/// XChaCha20-Poly1305 cipher wrapper
pub struct Cipher {
    cipher: XChaCha20Poly1305,
}

impl Cipher {
    /// Create a new cipher from a 32-byte key
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: XChaCha20Poly1305::new(key.into()),
        }
    }

    /// Encrypt data with optional associated data
    ///
    /// Returns: nonce || ciphertext || tag
    pub fn encrypt(&self, plaintext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        // Generate random nonce
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);

        let payload = match aad {
            Some(ad) => Payload { msg: plaintext, aad: ad },
            None => Payload { msg: plaintext, aad: &[] },
        };

        let ciphertext = self.cipher.encrypt(nonce, payload)
            .map_err(|_| PhantomError::Encryption("Encryption failed".into()))?;

        // Prepend nonce to ciphertext
        let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend(ciphertext);

        Ok(result)
    }

    /// Encrypt with a specific nonce (for deterministic encryption)
    pub fn encrypt_with_nonce(
        &self,
        plaintext: &[u8],
        nonce: &[u8; NONCE_SIZE],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let nonce = XNonce::from_slice(nonce);

        let payload = match aad {
            Some(ad) => Payload { msg: plaintext, aad: ad },
            None => Payload { msg: plaintext, aad: &[] },
        };

        self.cipher.encrypt(nonce, payload)
            .map_err(|_| PhantomError::Encryption("Encryption failed".into()))
    }

    /// Decrypt data with optional associated data
    ///
    /// Input format: nonce || ciphertext || tag
    pub fn decrypt(&self, ciphertext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        if ciphertext.len() < NONCE_SIZE + TAG_SIZE {
            return Err(PhantomError::Decryption("Ciphertext too short".into()));
        }

        let (nonce_bytes, ct) = ciphertext.split_at(NONCE_SIZE);
        let nonce = XNonce::from_slice(nonce_bytes);

        let payload = match aad {
            Some(ad) => Payload { msg: ct, aad: ad },
            None => Payload { msg: ct, aad: &[] },
        };

        self.cipher.decrypt(nonce, payload)
            .map_err(|_| PhantomError::Decryption("Decryption failed".into()))
    }

    /// Decrypt with a known nonce (ciphertext doesn't include nonce)
    pub fn decrypt_with_nonce(
        &self,
        ciphertext: &[u8],
        nonce: &[u8; NONCE_SIZE],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let nonce = XNonce::from_slice(nonce);

        let payload = match aad {
            Some(ad) => Payload { msg: ciphertext, aad: ad },
            None => Payload { msg: ciphertext, aad: &[] },
        };

        self.cipher.decrypt(nonce, payload)
            .map_err(|_| PhantomError::Decryption("Decryption failed".into()))
    }
}

/// Convenience function for one-shot encryption
pub fn encrypt(key: &[u8; 32], plaintext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
    Cipher::new(key).encrypt(plaintext, aad)
}

/// Convenience function for one-shot decryption
pub fn decrypt(key: &[u8; 32], ciphertext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
    Cipher::new(key).decrypt(ciphertext, aad)
}

/// Derive multiple keys from a master key using HKDF-like construction
pub fn derive_keys(master: &[u8; 32], info: &[u8], num_keys: usize) -> Vec<[u8; 32]> {
    use blake2::{Blake2b512, Digest};

    let mut keys = Vec::with_capacity(num_keys);
    let mut counter = 0u8;

    while keys.len() < num_keys {
        let mut hasher = Blake2b512::new();
        hasher.update(master);
        hasher.update(info);
        hasher.update(&[counter]);
        let result = hasher.finalize();

        let mut key = [0u8; 32];
        key.copy_from_slice(&result[..32]);
        keys.push(key);

        counter += 1;
    }

    keys
}

/// Secure key derivation from password (for PSK)
pub fn derive_key_from_password(password: &[u8], salt: &[u8]) -> [u8; 32] {
    use blake2::{Blake2b512, Digest};

    // Simple PBKDF-like construction (for production, use Argon2)
    let mut result = [0u8; 32];
    let mut hasher = Blake2b512::new();

    // Multiple iterations for key stretching
    let mut current = password.to_vec();
    current.extend_from_slice(salt);

    for _ in 0..10000 {
        hasher.update(&current);
        let hash = hasher.finalize_reset();
        current = hash.to_vec();
    }

    result.copy_from_slice(&current[..32]);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = [0x42u8; 32];
        let plaintext = b"Hello, World!";

        let ciphertext = encrypt(&key, plaintext, None).unwrap();
        let decrypted = decrypt(&key, &ciphertext, None).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_with_aad() {
        let key = [0x42u8; 32];
        let plaintext = b"Hello, World!";
        let aad = b"additional authenticated data";

        let ciphertext = encrypt(&key, plaintext, Some(aad)).unwrap();

        // Decryption with correct AAD should succeed
        let decrypted = decrypt(&key, &ciphertext, Some(aad)).unwrap();
        assert_eq!(decrypted, plaintext);

        // Decryption with wrong AAD should fail
        let result = decrypt(&key, &ciphertext, Some(b"wrong aad"));
        assert!(result.is_err());
    }

    #[test]
    fn test_ciphertext_length() {
        let key = [0x42u8; 32];
        let plaintext = b"Hello, World!";

        let ciphertext = encrypt(&key, plaintext, None).unwrap();

        // Length should be: nonce + plaintext + tag
        assert_eq!(ciphertext.len(), NONCE_SIZE + plaintext.len() + TAG_SIZE);
    }

    #[test]
    fn test_derive_keys() {
        let master = [0x42u8; 32];
        let keys = derive_keys(&master, b"phantom-keys", 3);

        assert_eq!(keys.len(), 3);
        // All keys should be different
        assert_ne!(keys[0], keys[1]);
        assert_ne!(keys[1], keys[2]);
    }
}
