//! # Phantom - Adaptive State-Masquerade Tunnel (ASMT)
//!
//! A next-generation censorship circumvention tunnel designed to bypass
//! sophisticated DPI systems like Iran's GFW through:
//!
//! - **Raw Socket Control**: Kernel bypass for precise packet manipulation
//! - **Geneva Engine**: State machine desynchronization attacks
//! - **Domestic Mimicry**: TLS fingerprint spoofing (Rubika/Eitaa)
//! - **Transport Agility**: Dynamic switching between TCP/Protocol 115/ICMP
//! - **FEC**: Forward Error Correction to survive packet loss/throttling

#![allow(dead_code)]
#![allow(unused_variables)]

pub mod config;
pub mod crypto;
pub mod fec;
pub mod geneva;
pub mod handshake;
pub mod transport;
pub mod tunnel;
pub mod error;
pub mod utils;

pub use config::Config;
pub use error::{PhantomError, Result};

/// Protocol version for wire compatibility
pub const PROTOCOL_VERSION: u8 = 1;

/// Maximum transmission unit for tunnel packets
pub const TUNNEL_MTU: usize = 1400;

/// Default ports
pub const DEFAULT_PORT: u16 = 443;

/// IP Protocol numbers
pub mod protocol {
    pub const TCP: u8 = 6;
    pub const UDP: u8 = 17;
    pub const ICMP: u8 = 1;
    pub const L2TPV3: u8 = 115;
    pub const GRE: u8 = 47;
}
