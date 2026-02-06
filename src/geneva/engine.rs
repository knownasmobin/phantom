//! Geneva Engine - Orchestrates packet manipulation strategies

use super::strategies::*;
use super::{Direction, PacketAction, PacketContext, Strategy};
use crate::config::{GenevaConfig, GenevaStrategy as GenevaStrategyType};
use crate::error::Result;

use rand::Rng;
use std::net::Ipv4Addr;
use std::sync::Arc;

/// The Geneva Engine applies packet manipulation strategies
/// to outbound packets to evade DPI.
pub struct GenevaEngine {
    strategies: Vec<Arc<dyn Strategy>>,
    probability: f32,
    enabled: bool,
    /// Estimated TTL to middlebox (can be probed/configured)
    middlebox_ttl: u8,
    /// Estimated TTL to server
    server_ttl: u8,
}

impl GenevaEngine {
    /// Create a new Geneva engine with the specified configuration
    pub fn new(config: &GenevaConfig) -> Self {
        let mut strategies: Vec<Arc<dyn Strategy>> = Vec::new();

        for strategy_type in &config.strategies {
            let strategy: Arc<dyn Strategy> = match strategy_type {
                GenevaStrategyType::TcpSegmentation => Arc::new(TcpSegmentationStrategy::default()),
                GenevaStrategyType::ChecksumPoisoning => {
                    Arc::new(ChecksumPoisoningStrategy::default())
                }
                GenevaStrategyType::TtlExpiry => Arc::new(TtlExpiryStrategy::default()),
                GenevaStrategyType::DuplicateAck => Arc::new(DuplicateAckStrategy::default()),
                GenevaStrategyType::FinBeforeSyn => Arc::new(FinBeforeSynStrategy::default()),
                GenevaStrategyType::RstWithShortTtl => Arc::new(RstWithShortTtlStrategy::default()),
                GenevaStrategyType::OutOfOrder => Arc::new(OutOfOrderStrategy::default()),
            };
            strategies.push(strategy);
        }

        Self {
            strategies,
            probability: config.probability,
            enabled: config.enabled,
            middlebox_ttl: 8, // Conservative default
            server_ttl: 64,   // Default TTL
        }
    }

    /// Create a disabled engine (passthrough)
    pub fn disabled() -> Self {
        Self {
            strategies: Vec::new(),
            probability: 0.0,
            enabled: false,
            middlebox_ttl: 8,
            server_ttl: 64,
        }
    }

    /// Set the estimated TTL to middlebox
    pub fn set_middlebox_ttl(&mut self, ttl: u8) {
        self.middlebox_ttl = ttl;
    }

    /// Set the estimated TTL to server
    pub fn set_server_ttl(&mut self, ttl: u8) {
        self.server_ttl = ttl;
    }

    /// Process an outbound packet through the Geneva engine
    ///
    /// Returns a list of packets to send (may be more or fewer than input)
    pub fn process_outbound(
        &self,
        packet: &[u8],
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
    ) -> Result<Vec<Vec<u8>>> {
        if !self.enabled || self.strategies.is_empty() {
            return Ok(vec![packet.to_vec()]);
        }

        // Probabilistic application
        if rand::thread_rng().gen::<f32>() > self.probability {
            return Ok(vec![packet.to_vec()]);
        }

        let ctx = PacketContext {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            direction: Direction::Outbound,
            middlebox_ttl: self.middlebox_ttl,
            server_ttl: self.server_ttl,
        };

        // Apply all matching strategies in sequence
        let mut current_packets = vec![packet.to_vec()];

        for strategy in &self.strategies {
            let mut new_packets = Vec::new();

            for pkt in &current_packets {
                if strategy.applies_to(pkt, &ctx) {
                    match strategy.apply(pkt, &ctx)? {
                        PacketAction::Send(p) => new_packets.push(p),
                        PacketAction::SendMultiple(ps) => new_packets.extend(ps),
                        PacketAction::Drop => {} // Don't add to output
                        PacketAction::Modify(p) => new_packets.push(p),
                    }
                } else {
                    new_packets.push(pkt.clone());
                }
            }

            current_packets = new_packets;
        }

        Ok(current_packets)
    }

    /// Process an inbound packet (typically passthrough, but could filter)
    pub fn process_inbound(&self, packet: &[u8]) -> Result<Vec<Vec<u8>>> {
        // For now, inbound packets are passed through
        // In the future, we could filter injected RSTs, etc.
        Ok(vec![packet.to_vec()])
    }

    /// Get list of active strategies
    pub fn active_strategies(&self) -> Vec<&str> {
        self.strategies.iter().map(|s| s.description()).collect()
    }

    /// Check if a specific strategy is enabled
    pub fn has_strategy(&self, strategy_type: GenevaStrategyType) -> bool {
        self.strategies
            .iter()
            .any(|s| s.strategy_type() == strategy_type)
    }

    /// Add a custom strategy
    pub fn add_strategy(&mut self, strategy: Arc<dyn Strategy>) {
        self.strategies.push(strategy);
    }

    /// Remove all strategies
    pub fn clear_strategies(&mut self) {
        self.strategies.clear();
    }

    /// Enable/disable the engine
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Check if enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

/// Builder for Geneva Engine with fine-grained control
pub struct GenevaEngineBuilder {
    strategies: Vec<Arc<dyn Strategy>>,
    probability: f32,
    middlebox_ttl: u8,
    server_ttl: u8,
}

impl GenevaEngineBuilder {
    pub fn new() -> Self {
        Self {
            strategies: Vec::new(),
            probability: 1.0,
            middlebox_ttl: 8,
            server_ttl: 64,
        }
    }

    pub fn with_segmentation(mut self, first_segment_size: usize) -> Self {
        self.strategies.push(Arc::new(TcpSegmentationStrategy {
            first_segment_size,
            segment_delay_us: 0,
        }));
        self
    }

    pub fn with_checksum_poisoning(mut self) -> Self {
        self.strategies
            .push(Arc::new(ChecksumPoisoningStrategy::default()));
        self
    }

    pub fn with_ttl_expiry(mut self, decoy_ttl: u8, decoy_type: TtlDecoyType) -> Self {
        self.strategies.push(Arc::new(TtlExpiryStrategy {
            decoy_ttl,
            decoy_type,
        }));
        self
    }

    pub fn with_duplicate_acks(mut self, count: u8) -> Self {
        self.strategies.push(Arc::new(DuplicateAckStrategy {
            num_duplicates: count,
        }));
        self
    }

    pub fn with_fin_before_syn(mut self, count: u8) -> Self {
        self.strategies
            .push(Arc::new(FinBeforeSynStrategy { num_fins: count }));
        self
    }

    pub fn with_rst_short_ttl(mut self, ttl: u8) -> Self {
        self.strategies
            .push(Arc::new(RstWithShortTtlStrategy { ttl }));
        self
    }

    pub fn with_out_of_order(mut self) -> Self {
        self.strategies
            .push(Arc::new(OutOfOrderStrategy::default()));
        self
    }

    pub fn probability(mut self, prob: f32) -> Self {
        self.probability = prob.clamp(0.0, 1.0);
        self
    }

    pub fn middlebox_ttl(mut self, ttl: u8) -> Self {
        self.middlebox_ttl = ttl;
        self
    }

    pub fn server_ttl(mut self, ttl: u8) -> Self {
        self.server_ttl = ttl;
        self
    }

    pub fn build(self) -> GenevaEngine {
        GenevaEngine {
            strategies: self.strategies,
            probability: self.probability,
            enabled: true,
            middlebox_ttl: self.middlebox_ttl,
            server_ttl: self.server_ttl,
        }
    }
}

impl Default for GenevaEngineBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Probe the network to estimate middlebox TTL
///
/// This sends packets with increasing TTL and measures where
/// ICMP Time Exceeded messages come from.
pub async fn probe_middlebox_ttl(dst_ip: Ipv4Addr, dst_port: u16) -> Result<u8> {
    // This is a simplified implementation
    // A real implementation would send probes and analyze ICMP responses

    // For now, return a conservative estimate
    // In Iran, the GFW is typically within 5-10 hops
    Ok(8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::GenevaConfig;

    #[test]
    fn test_engine_creation() {
        let config = GenevaConfig::default();
        let engine = GenevaEngine::new(&config);

        assert!(engine.is_enabled());
        assert!(!engine.strategies.is_empty());
    }

    #[test]
    fn test_engine_builder() {
        let engine = GenevaEngineBuilder::new()
            .with_segmentation(10)
            .with_checksum_poisoning()
            .probability(0.8)
            .build();

        assert!(engine.is_enabled());
        assert_eq!(engine.strategies.len(), 2);
    }

    #[test]
    fn test_disabled_engine() {
        let engine = GenevaEngine::disabled();

        assert!(!engine.is_enabled());
        assert!(engine.strategies.is_empty());
    }
}
