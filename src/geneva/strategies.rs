//! Geneva strategy implementations

use super::{Direction, PacketAction, PacketContext, Strategy};
use crate::config::GenevaStrategy;
use crate::error::Result;
use crate::transport::packet::{IpHeader, Packet, TcpFlags, TcpHeader, TransportHeader};

/// TCP Segmentation Strategy
///
/// Splits TCP payload into multiple segments to bypass DPI that
/// doesn't properly reassemble TCP streams.
///
/// The GFW often only inspects the first packet of a flow.
/// By splitting the SNI or other sensitive data across packets,
/// we can evade detection.
pub struct TcpSegmentationStrategy {
    /// Number of bytes in first segment
    pub first_segment_size: usize,
    /// Delay between segments (microseconds)
    pub segment_delay_us: u64,
}

impl Default for TcpSegmentationStrategy {
    fn default() -> Self {
        Self {
            first_segment_size: 10, // Split after TLS header, before SNI
            segment_delay_us: 0,
        }
    }
}

impl Strategy for TcpSegmentationStrategy {
    fn strategy_type(&self) -> GenevaStrategy {
        GenevaStrategy::TcpSegmentation
    }

    fn apply(&self, packet: &[u8], ctx: &PacketContext) -> Result<PacketAction> {
        let pkt = Packet::from_bytes(packet)?;

        // Only apply to TCP packets with payload
        if pkt.ip.protocol != 6 || pkt.payload.is_empty() {
            return Ok(PacketAction::Send(packet.to_vec()));
        }

        // Don't segment if payload is too small
        if pkt.payload.len() <= self.first_segment_size {
            return Ok(PacketAction::Send(packet.to_vec()));
        }

        let tcp = match &pkt.transport {
            TransportHeader::Tcp(tcp) => tcp.clone(),
            _ => return Ok(PacketAction::Send(packet.to_vec())),
        };

        // Split payload
        let (first_payload, second_payload) = pkt.payload.split_at(self.first_segment_size);

        // Build first segment
        let mut pkt1 = pkt.clone();
        pkt1.payload = first_payload.to_vec();
        let data1 = pkt1.to_bytes();

        // Build second segment with adjusted sequence number
        let mut pkt2 = pkt.clone();
        pkt2.payload = second_payload.to_vec();
        if let TransportHeader::Tcp(ref mut tcp2) = pkt2.transport {
            tcp2.seq_num = tcp.seq_num.wrapping_add(self.first_segment_size as u32);
        }
        let data2 = pkt2.to_bytes();

        Ok(PacketAction::SendMultiple(vec![data1, data2]))
    }

    fn applies_to(&self, packet: &[u8], ctx: &PacketContext) -> bool {
        ctx.direction == Direction::Outbound && packet.len() > 60
    }

    fn description(&self) -> &'static str {
        "Split TCP payload into multiple segments to bypass reassembly-limited DPI"
    }
}

/// Checksum Poisoning Strategy
///
/// Sends a packet with an invalid checksum before the real packet.
/// The middlebox may process the bad packet and update its state,
/// while the server drops it. This desynchronizes the middlebox state.
pub struct ChecksumPoisoningStrategy {
    /// Whether to corrupt TCP or IP checksum
    pub corrupt_tcp: bool,
    pub corrupt_ip: bool,
}

impl Default for ChecksumPoisoningStrategy {
    fn default() -> Self {
        Self {
            corrupt_tcp: true,
            corrupt_ip: false, // IP checksum errors are more likely to be dropped early
        }
    }
}

impl Strategy for ChecksumPoisoningStrategy {
    fn strategy_type(&self) -> GenevaStrategy {
        GenevaStrategy::ChecksumPoisoning
    }

    fn apply(&self, packet: &[u8], ctx: &PacketContext) -> Result<PacketAction> {
        let pkt = Packet::from_bytes(packet)?;

        if pkt.ip.protocol != 6 {
            return Ok(PacketAction::Send(packet.to_vec()));
        }

        // Create a poisoned copy
        let mut poisoned = pkt.clone();

        if self.corrupt_tcp {
            if let TransportHeader::Tcp(ref mut tcp) = poisoned.transport {
                tcp.checksum = tcp.checksum.wrapping_add(1); // Invalidate checksum
            }
        }

        if self.corrupt_ip {
            poisoned.ip.checksum = poisoned.ip.checksum.wrapping_add(1);
        }

        // Rebuild the poisoned packet (don't recalculate checksums)
        let mut poisoned_data = Vec::new();
        poisoned_data.extend_from_slice(&poisoned.ip.to_bytes());
        if let TransportHeader::Tcp(tcp) = &poisoned.transport {
            poisoned_data.extend_from_slice(&tcp.to_bytes());
        }
        poisoned_data.extend_from_slice(&poisoned.payload);

        // Send poisoned packet first, then real packet
        Ok(PacketAction::SendMultiple(vec![
            poisoned_data,
            packet.to_vec(),
        ]))
    }

    fn applies_to(&self, packet: &[u8], ctx: &PacketContext) -> bool {
        ctx.direction == Direction::Outbound
    }

    fn description(&self) -> &'static str {
        "Send packet with bad checksum to desync middlebox state"
    }
}

/// TTL Expiry Strategy
///
/// Sends a packet (like RST) with a TTL that expires after the middlebox
/// but before the server. The middlebox processes it (e.g., closes connection
/// state) but the server never sees it.
pub struct TtlExpiryStrategy {
    /// TTL for the decoy packet (should be > middlebox hops, < server hops)
    pub decoy_ttl: u8,
    /// Type of decoy packet to send
    pub decoy_type: TtlDecoyType,
}

#[derive(Debug, Clone, Copy)]
pub enum TtlDecoyType {
    /// Send RST to make middlebox think connection is closed
    Rst,
    /// Send FIN to start close sequence
    Fin,
    /// Send SYN to confuse state machine
    Syn,
}

impl Default for TtlExpiryStrategy {
    fn default() -> Self {
        Self {
            decoy_ttl: 8, // Typical middlebox is within 8 hops
            decoy_type: TtlDecoyType::Rst,
        }
    }
}

impl Strategy for TtlExpiryStrategy {
    fn strategy_type(&self) -> GenevaStrategy {
        GenevaStrategy::TtlExpiry
    }

    fn apply(&self, packet: &[u8], ctx: &PacketContext) -> Result<PacketAction> {
        let pkt = Packet::from_bytes(packet)?;

        if pkt.ip.protocol != 6 {
            return Ok(PacketAction::Send(packet.to_vec()));
        }

        let tcp = match &pkt.transport {
            TransportHeader::Tcp(tcp) => tcp.clone(),
            _ => return Ok(PacketAction::Send(packet.to_vec())),
        };

        // Create decoy packet with short TTL
        let mut decoy_ip = pkt.ip.clone();
        decoy_ip.ttl = self.decoy_ttl;

        let mut decoy_tcp = tcp.clone();
        decoy_tcp.flags = match self.decoy_type {
            TtlDecoyType::Rst => TcpFlags::rst(),
            TtlDecoyType::Fin => TcpFlags::fin_ack(),
            TtlDecoyType::Syn => TcpFlags::syn(),
        };

        // Build decoy
        decoy_ip.total_length = (IpHeader::MIN_SIZE + TcpHeader::MIN_SIZE) as u16;
        decoy_ip.calculate_checksum();
        decoy_tcp.calculate_checksum(decoy_ip.src_ip, decoy_ip.dst_ip, &[]);

        let mut decoy_data = Vec::new();
        decoy_data.extend_from_slice(&decoy_ip.to_bytes());
        decoy_data.extend_from_slice(&decoy_tcp.to_bytes());

        // Send decoy first, then real packet
        Ok(PacketAction::SendMultiple(vec![
            decoy_data,
            packet.to_vec(),
        ]))
    }

    fn applies_to(&self, packet: &[u8], ctx: &PacketContext) -> bool {
        ctx.direction == Direction::Outbound
    }

    fn description(&self) -> &'static str {
        "Send decoy packet with short TTL to expire at middlebox"
    }
}

/// Duplicate ACK Strategy
///
/// Sends multiple duplicate ACK packets during handshake to confuse
/// the middlebox's TCP state machine.
pub struct DuplicateAckStrategy {
    pub num_duplicates: u8,
}

impl Default for DuplicateAckStrategy {
    fn default() -> Self {
        Self { num_duplicates: 9 }
    }
}

impl Strategy for DuplicateAckStrategy {
    fn strategy_type(&self) -> GenevaStrategy {
        GenevaStrategy::DuplicateAck
    }

    fn apply(&self, packet: &[u8], ctx: &PacketContext) -> Result<PacketAction> {
        let pkt = Packet::from_bytes(packet)?;

        if pkt.ip.protocol != 6 {
            return Ok(PacketAction::Send(packet.to_vec()));
        }

        let tcp = match &pkt.transport {
            TransportHeader::Tcp(tcp) => tcp,
            _ => return Ok(PacketAction::Send(packet.to_vec())),
        };

        // Only apply to ACK packets during handshake (no payload)
        if !tcp.flags.ack || tcp.flags.syn || !pkt.payload.is_empty() {
            return Ok(PacketAction::Send(packet.to_vec()));
        }

        // Create multiple copies of the ACK
        let mut packets = Vec::with_capacity(self.num_duplicates as usize + 1);
        for _ in 0..self.num_duplicates {
            packets.push(packet.to_vec());
        }
        packets.push(packet.to_vec()); // The "real" one

        Ok(PacketAction::SendMultiple(packets))
    }

    fn applies_to(&self, packet: &[u8], ctx: &PacketContext) -> bool {
        ctx.direction == Direction::Outbound
    }

    fn description(&self) -> &'static str {
        "Send multiple duplicate ACKs to confuse middlebox state"
    }
}

/// FIN Before SYN Strategy
///
/// Sends FIN packets before the SYN to pre-pollute middlebox state.
pub struct FinBeforeSynStrategy {
    pub num_fins: u8,
}

impl Default for FinBeforeSynStrategy {
    fn default() -> Self {
        Self { num_fins: 2 }
    }
}

impl Strategy for FinBeforeSynStrategy {
    fn strategy_type(&self) -> GenevaStrategy {
        GenevaStrategy::FinBeforeSyn
    }

    fn apply(&self, packet: &[u8], ctx: &PacketContext) -> Result<PacketAction> {
        let pkt = Packet::from_bytes(packet)?;

        if pkt.ip.protocol != 6 {
            return Ok(PacketAction::Send(packet.to_vec()));
        }

        let tcp = match &pkt.transport {
            TransportHeader::Tcp(tcp) => tcp.clone(),
            _ => return Ok(PacketAction::Send(packet.to_vec())),
        };

        // Only apply to SYN packets
        if !tcp.flags.syn || tcp.flags.ack {
            return Ok(PacketAction::Send(packet.to_vec()));
        }

        // Create FIN packets
        let mut fin_tcp = tcp.clone();
        fin_tcp.flags = TcpFlags::fin_ack();

        let mut fin_ip = pkt.ip.clone();
        fin_ip.total_length = (IpHeader::MIN_SIZE + TcpHeader::MIN_SIZE) as u16;
        fin_ip.calculate_checksum();
        fin_tcp.calculate_checksum(fin_ip.src_ip, fin_ip.dst_ip, &[]);

        let mut fin_data = Vec::new();
        fin_data.extend_from_slice(&fin_ip.to_bytes());
        fin_data.extend_from_slice(&fin_tcp.to_bytes());

        let mut packets = Vec::with_capacity(self.num_fins as usize + 1);
        for _ in 0..self.num_fins {
            packets.push(fin_data.clone());
        }
        packets.push(packet.to_vec()); // The real SYN

        Ok(PacketAction::SendMultiple(packets))
    }

    fn applies_to(&self, packet: &[u8], ctx: &PacketContext) -> bool {
        ctx.direction == Direction::Outbound
    }

    fn description(&self) -> &'static str {
        "Send FIN packets before SYN to pollute middlebox state"
    }
}

/// RST with Short TTL Strategy
///
/// Inject RST packets with TTL that expires before the server but
/// after the middlebox, making the middlebox think the connection is closed.
pub struct RstWithShortTtlStrategy {
    pub ttl: u8,
}

impl Default for RstWithShortTtlStrategy {
    fn default() -> Self {
        Self { ttl: 8 }
    }
}

impl Strategy for RstWithShortTtlStrategy {
    fn strategy_type(&self) -> GenevaStrategy {
        GenevaStrategy::RstWithShortTtl
    }

    fn apply(&self, packet: &[u8], ctx: &PacketContext) -> Result<PacketAction> {
        // Use the TTL Expiry strategy with RST
        let ttl_strategy = TtlExpiryStrategy {
            decoy_ttl: self.ttl,
            decoy_type: TtlDecoyType::Rst,
        };
        ttl_strategy.apply(packet, ctx)
    }

    fn applies_to(&self, packet: &[u8], ctx: &PacketContext) -> bool {
        ctx.direction == Direction::Outbound
    }

    fn description(&self) -> &'static str {
        "Inject RST with short TTL to close middlebox state"
    }
}

/// Out of Order Strategy
///
/// Sends TCP segments out of order to confuse middleboxes that
/// expect sequential delivery.
pub struct OutOfOrderStrategy {
    /// Whether to reverse segment order
    pub reverse: bool,
}

impl Default for OutOfOrderStrategy {
    fn default() -> Self {
        Self { reverse: true }
    }
}

impl Strategy for OutOfOrderStrategy {
    fn strategy_type(&self) -> GenevaStrategy {
        GenevaStrategy::OutOfOrder
    }

    fn apply(&self, packet: &[u8], ctx: &PacketContext) -> Result<PacketAction> {
        // First, segment the packet
        let segmentation = TcpSegmentationStrategy::default();
        let action = segmentation.apply(packet, ctx)?;

        // Then reverse the order if needed
        match action {
            PacketAction::SendMultiple(mut packets) if self.reverse => {
                packets.reverse();
                Ok(PacketAction::SendMultiple(packets))
            }
            other => Ok(other),
        }
    }

    fn applies_to(&self, packet: &[u8], ctx: &PacketContext) -> bool {
        ctx.direction == Direction::Outbound && packet.len() > 60
    }

    fn description(&self) -> &'static str {
        "Send TCP segments out of order to confuse middlebox"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::packet::PacketBuilder;
    use std::net::Ipv4Addr;

    fn make_test_packet() -> Vec<u8> {
        let mut packet =
            PacketBuilder::new(6, Ipv4Addr::new(192, 168, 1, 1), Ipv4Addr::new(10, 0, 0, 1))
                .tcp(12345, 443)
                .tcp_flags(TcpFlags::psh_ack())
                .tcp_seq(1000)
                .tcp_ack(2000)
                .payload(b"Hello, World! This is test data for segmentation.")
                .build();
        packet.to_bytes()
    }

    fn make_test_context() -> PacketContext {
        PacketContext {
            src_ip: Ipv4Addr::new(192, 168, 1, 1),
            dst_ip: Ipv4Addr::new(10, 0, 0, 1),
            src_port: 12345,
            dst_port: 443,
            direction: Direction::Outbound,
            middlebox_ttl: 8,
            server_ttl: 20,
        }
    }

    #[test]
    fn test_tcp_segmentation() {
        let strategy = TcpSegmentationStrategy::default();
        let packet = make_test_packet();
        let ctx = make_test_context();

        let action = strategy.apply(&packet, &ctx).unwrap();
        if let PacketAction::SendMultiple(packets) = action {
            assert_eq!(packets.len(), 2);
            assert!(packets[0].len() < packet.len());
        } else {
            panic!("Expected SendMultiple");
        }
    }

    #[test]
    fn test_checksum_poisoning() {
        let strategy = ChecksumPoisoningStrategy::default();
        let packet = make_test_packet();
        let ctx = make_test_context();

        let action = strategy.apply(&packet, &ctx).unwrap();
        if let PacketAction::SendMultiple(packets) = action {
            assert_eq!(packets.len(), 2);
            // First packet should have corrupted checksum
            assert_ne!(packets[0], packets[1]);
        } else {
            panic!("Expected SendMultiple");
        }
    }
}
