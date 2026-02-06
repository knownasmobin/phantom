//! Geneva Engine - DPI Desynchronization Strategies
//!
//! Implements packet manipulation strategies to confuse Deep Packet Inspection
//! middleboxes. Based on research from the Geneva project (https://geneva.cs.umd.edu).
//!
//! Key strategies:
//! - TCP Segmentation: Split payload to bypass reassembly-limited DPI
//! - Checksum Poisoning: Send bad checksums to desync middlebox state
//! - TTL Manipulation: Expire packets at middlebox but not server
//! - Flag Manipulation: Confuse state tracking with unexpected flags

pub mod strategies;
pub mod engine;

pub use engine::GenevaEngine;
pub use strategies::*;

use crate::config::GenevaStrategy;
use crate::error::Result;
use crate::transport::packet::{Packet, TcpFlags};
use std::net::Ipv4Addr;

/// Action to take on a packet
#[derive(Debug, Clone)]
pub enum PacketAction {
    /// Send the packet as-is
    Send(Vec<u8>),
    /// Send multiple packets (e.g., segmentation)
    SendMultiple(Vec<Vec<u8>>),
    /// Drop the packet
    Drop,
    /// Modify and send
    Modify(Vec<u8>),
}

/// Context for packet manipulation
#[derive(Debug, Clone)]
pub struct PacketContext {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub direction: Direction,
    /// Estimated TTL to middlebox
    pub middlebox_ttl: u8,
    /// TTL to server
    pub server_ttl: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Outbound,
    Inbound,
}

/// Trait for packet manipulation strategies
pub trait Strategy: Send + Sync {
    /// Get the strategy type
    fn strategy_type(&self) -> GenevaStrategy;

    /// Apply the strategy to a packet
    fn apply(&self, packet: &[u8], ctx: &PacketContext) -> Result<PacketAction>;

    /// Check if this strategy applies to the given packet
    fn applies_to(&self, packet: &[u8], ctx: &PacketContext) -> bool;

    /// Get a description of the strategy
    fn description(&self) -> &'static str;
}
