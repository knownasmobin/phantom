//! TLS Handshake Mimicry
//!
//! Provides fake TLS ClientHello generation that mimics legitimate
//! domestic apps (Rubika, Eitaa, etc.) to bypass SNI-based filtering.
//!
//! The key insight is that traffic to domestic "super apps" is whitelisted.
//! By mimicking their TLS fingerprint, we can get our connection whitelisted
//! even though it's going to a different server.

pub mod tls;
pub mod fingerprint;

pub use tls::{TlsClientHello, TlsClientHelloBuilder};
pub use fingerprint::{Fingerprint, FingerprintGenerator};

use crate::config::{HandshakeConfig, MimicTarget};
use crate::error::Result;

/// Generate a TLS ClientHello that mimics the specified target
pub fn generate_client_hello(config: &HandshakeConfig, server_name: Option<&str>) -> Result<Vec<u8>> {
    let sni = server_name.unwrap_or(&config.spoof_sni);

    let builder = TlsClientHelloBuilder::new()
        .server_name(sni)
        .mimic(config.mimic_target);

    if config.randomize_fingerprint {
        builder.randomize().build()
    } else {
        builder.build()
    }
}
