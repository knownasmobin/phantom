//! Forward Error Correction using Reed-Solomon
//!
//! FEC allows recovery from packet loss without retransmission.
//! This is critical for bypassing throttling - instead of slowing down
//! when packets are dropped, we can recover them from redundant data.
//!
//! Configuration:
//! - data_shards: Number of original data packets
//! - parity_shards: Number of redundancy packets
//! - With 10 data + 3 parity, we can recover from 30% loss

use crate::error::{PhantomError, Result};
use crate::config::FecConfig;
use reed_solomon_erasure::galois_8::ReedSolomon;
use std::sync::Arc;

/// FEC encoder/decoder
pub struct FecCodec {
    rs: ReedSolomon,
    data_shards: usize,
    parity_shards: usize,
    shard_size: usize,
}

impl FecCodec {
    /// Create a new FEC codec
    pub fn new(config: &FecConfig) -> Result<Self> {
        let rs = ReedSolomon::new(config.data_shards, config.parity_shards)
            .map_err(|e| PhantomError::Config(format!("FEC config error: {:?}", e)))?;

        Ok(Self {
            rs,
            data_shards: config.data_shards,
            parity_shards: config.parity_shards,
            shard_size: config.shard_size,
        })
    }

    /// Create with explicit parameters
    pub fn with_params(data_shards: usize, parity_shards: usize, shard_size: usize) -> Result<Self> {
        let rs = ReedSolomon::new(data_shards, parity_shards)
            .map_err(|e| PhantomError::Config(format!("FEC config error: {:?}", e)))?;

        Ok(Self {
            rs,
            data_shards,
            parity_shards,
            shard_size,
        })
    }

    /// Get the total number of shards (data + parity)
    pub fn total_shards(&self) -> usize {
        self.data_shards + self.parity_shards
    }

    /// Get the data shard count
    pub fn data_shards(&self) -> usize {
        self.data_shards
    }

    /// Get the parity shard count
    pub fn parity_shards(&self) -> usize {
        self.parity_shards
    }

    /// Get the shard size
    pub fn shard_size(&self) -> usize {
        self.shard_size
    }

    /// Encode data into shards with parity
    ///
    /// Input: raw data
    /// Output: Vec of shards (data shards + parity shards)
    pub fn encode(&self, data: &[u8]) -> Result<Vec<Vec<u8>>> {
        // Calculate how many bytes we need per data shard
        let total_data_size = self.data_shards * self.shard_size;

        // Pad data if necessary
        let mut padded_data = data.to_vec();
        if padded_data.len() < total_data_size {
            padded_data.resize(total_data_size, 0);
        } else if padded_data.len() > total_data_size {
            return Err(PhantomError::PacketTooLarge {
                size: padded_data.len(),
                max: total_data_size,
            });
        }

        // Create shards
        let mut shards: Vec<Vec<u8>> = Vec::with_capacity(self.total_shards());

        // Data shards
        for i in 0..self.data_shards {
            let start = i * self.shard_size;
            let end = start + self.shard_size;
            shards.push(padded_data[start..end].to_vec());
        }

        // Parity shards (initially zero)
        for _ in 0..self.parity_shards {
            shards.push(vec![0u8; self.shard_size]);
        }

        // Generate parity
        self.rs.encode(&mut shards)
            .map_err(|e| PhantomError::Protocol(format!("FEC encode error: {:?}", e)))?;

        Ok(shards)
    }

    /// Decode shards back to original data
    ///
    /// Input: Vec of Option<shard> - None for missing shards
    /// Output: Original data (if recoverable)
    pub fn decode(&self, shards: &mut Vec<Option<Vec<u8>>>) -> Result<Vec<u8>> {
        if shards.len() != self.total_shards() {
            return Err(PhantomError::Protocol(format!(
                "Expected {} shards, got {}",
                self.total_shards(),
                shards.len()
            )));
        }

        // Count available shards
        let available = shards.iter().filter(|s| s.is_some()).count();
        if available < self.data_shards {
            return Err(PhantomError::FecDecodeFailed);
        }

        // Reconstruct missing shards
        self.rs.reconstruct(shards)
            .map_err(|_| PhantomError::FecDecodeFailed)?;

        // Extract data from data shards
        let mut data = Vec::with_capacity(self.data_shards * self.shard_size);
        for shard in shards.iter().take(self.data_shards) {
            if let Some(s) = shard {
                data.extend_from_slice(s);
            } else {
                return Err(PhantomError::FecDecodeFailed);
            }
        }

        Ok(data)
    }

    /// Verify that shards are consistent
    pub fn verify(&self, shards: &[Vec<u8>]) -> bool {
        if shards.len() != self.total_shards() {
            return false;
        }

        // Convert to the format expected by the library
        let shard_refs: Vec<&[u8]> = shards.iter().map(|s| s.as_slice()).collect();
        self.rs.verify(&shard_refs).unwrap_or(false)
    }
}

/// FEC packet wrapper with metadata
#[derive(Debug, Clone)]
pub struct FecPacket {
    /// Block ID (groups shards together)
    pub block_id: u32,
    /// Shard index within block
    pub shard_index: u8,
    /// Total shards in block
    pub total_shards: u8,
    /// Data shards in block
    pub data_shards: u8,
    /// Original data length (before padding)
    pub original_len: u16,
    /// Shard data
    pub data: Vec<u8>,
}

impl FecPacket {
    pub const HEADER_SIZE: usize = 10; // 4 + 1 + 1 + 1 + 1 + 2

    pub fn new(
        block_id: u32,
        shard_index: u8,
        total_shards: u8,
        data_shards: u8,
        original_len: u16,
        data: Vec<u8>,
    ) -> Self {
        Self {
            block_id,
            shard_index,
            total_shards,
            data_shards,
            original_len,
            data,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::HEADER_SIZE + self.data.len());
        buf.extend_from_slice(&self.block_id.to_be_bytes());
        buf.push(self.shard_index);
        buf.push(self.total_shards);
        buf.push(self.data_shards);
        buf.push(0); // Reserved
        buf.extend_from_slice(&self.original_len.to_be_bytes());
        buf.extend_from_slice(&self.data);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < Self::HEADER_SIZE {
            return Err(PhantomError::PacketParse("FEC packet too short".into()));
        }

        let block_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let shard_index = data[4];
        let total_shards = data[5];
        let data_shards = data[6];
        // data[7] is reserved
        let original_len = u16::from_be_bytes([data[8], data[9]]);
        let shard_data = data[Self::HEADER_SIZE..].to_vec();

        Ok(Self {
            block_id,
            shard_index,
            total_shards,
            data_shards,
            original_len,
            data: shard_data,
        })
    }

    pub fn is_parity(&self) -> bool {
        self.shard_index >= self.data_shards
    }
}

/// FEC block assembler for receiving
pub struct FecBlockAssembler {
    block_id: u32,
    total_shards: usize,
    data_shards: usize,
    original_len: usize,
    shards: Vec<Option<Vec<u8>>>,
    received_count: usize,
}

impl FecBlockAssembler {
    pub fn new(block_id: u32, total_shards: usize, data_shards: usize, original_len: usize) -> Self {
        Self {
            block_id,
            total_shards,
            data_shards,
            original_len,
            shards: vec![None; total_shards],
            received_count: 0,
        }
    }

    pub fn add_shard(&mut self, index: usize, data: Vec<u8>) -> bool {
        if index >= self.total_shards {
            return false;
        }

        if self.shards[index].is_none() {
            self.shards[index] = Some(data);
            self.received_count += 1;
            true
        } else {
            false // Duplicate
        }
    }

    pub fn can_decode(&self) -> bool {
        self.received_count >= self.data_shards
    }

    pub fn is_complete(&self) -> bool {
        self.received_count == self.total_shards
    }

    pub fn decode(&mut self, codec: &FecCodec) -> Result<Vec<u8>> {
        let mut data = codec.decode(&mut self.shards)?;
        data.truncate(self.original_len);
        Ok(data)
    }

    pub fn block_id(&self) -> u32 {
        self.block_id
    }

    pub fn received_count(&self) -> usize {
        self.received_count
    }
}

/// FEC sender that encodes data into shards
pub struct FecSender {
    codec: Arc<FecCodec>,
    block_counter: u32,
}

impl FecSender {
    pub fn new(codec: Arc<FecCodec>) -> Self {
        Self {
            codec,
            block_counter: 0,
        }
    }

    /// Encode data into FEC packets
    pub fn encode(&mut self, data: &[u8]) -> Result<Vec<FecPacket>> {
        let block_id = self.block_counter;
        self.block_counter = self.block_counter.wrapping_add(1);

        let original_len = data.len();
        let shards = self.codec.encode(data)?;

        let packets: Vec<FecPacket> = shards
            .into_iter()
            .enumerate()
            .map(|(i, shard)| {
                FecPacket::new(
                    block_id,
                    i as u8,
                    self.codec.total_shards() as u8,
                    self.codec.data_shards() as u8,
                    original_len as u16,
                    shard,
                )
            })
            .collect();

        Ok(packets)
    }
}

/// FEC receiver that reassembles blocks
pub struct FecReceiver {
    codec: Arc<FecCodec>,
    blocks: std::collections::HashMap<u32, FecBlockAssembler>,
    max_blocks: usize,
}

impl FecReceiver {
    pub fn new(codec: Arc<FecCodec>, max_blocks: usize) -> Self {
        Self {
            codec,
            blocks: std::collections::HashMap::new(),
            max_blocks,
        }
    }

    /// Process a received FEC packet
    ///
    /// Returns the decoded data if the block is now complete
    pub fn receive(&mut self, packet: FecPacket) -> Result<Option<Vec<u8>>> {
        let block_id = packet.block_id;

        // Get or create block assembler
        let assembler = self.blocks.entry(block_id).or_insert_with(|| {
            FecBlockAssembler::new(
                block_id,
                packet.total_shards as usize,
                packet.data_shards as usize,
                packet.original_len as usize,
            )
        });

        // Add shard
        assembler.add_shard(packet.shard_index as usize, packet.data);

        // Try to decode if we have enough shards
        if assembler.can_decode() {
            let data = assembler.decode(&self.codec)?;
            self.blocks.remove(&block_id);

            // Cleanup old blocks
            if self.blocks.len() > self.max_blocks {
                // Remove oldest block
                if let Some(&oldest) = self.blocks.keys().min() {
                    self.blocks.remove(&oldest);
                }
            }

            return Ok(Some(data));
        }

        Ok(None)
    }

    /// Get statistics
    pub fn stats(&self) -> FecStats {
        FecStats {
            pending_blocks: self.blocks.len(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct FecStats {
    pub pending_blocks: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fec_encode_decode() {
        let codec = FecCodec::with_params(4, 2, 256).unwrap();
        let data = b"Hello, World! This is a test of FEC encoding and decoding.";

        // Encode
        let shards = codec.encode(data).unwrap();
        assert_eq!(shards.len(), 6); // 4 data + 2 parity

        // Decode with all shards
        let mut all_shards: Vec<Option<Vec<u8>>> = shards.iter().map(|s| Some(s.clone())).collect();
        let decoded = codec.decode(&mut all_shards).unwrap();
        assert!(decoded.starts_with(data));
    }

    #[test]
    fn test_fec_recovery() {
        let codec = FecCodec::with_params(4, 2, 256).unwrap();
        let data = b"Test data for recovery";

        // Encode
        let shards = codec.encode(data).unwrap();

        // Simulate packet loss (lose 2 shards)
        let mut partial_shards: Vec<Option<Vec<u8>>> = shards.iter().map(|s| Some(s.clone())).collect();
        partial_shards[1] = None; // Lose shard 1
        partial_shards[3] = None; // Lose shard 3

        // Should still be able to decode
        let decoded = codec.decode(&mut partial_shards).unwrap();
        assert!(decoded.starts_with(data));
    }

    #[test]
    fn test_fec_too_much_loss() {
        let codec = FecCodec::with_params(4, 2, 256).unwrap();
        let data = b"Test data";

        // Encode
        let shards = codec.encode(data).unwrap();

        // Lose too many shards (3 out of 6, only 3 left but need 4)
        let mut partial_shards: Vec<Option<Vec<u8>>> = shards.iter().map(|s| Some(s.clone())).collect();
        partial_shards[0] = None;
        partial_shards[2] = None;
        partial_shards[4] = None;

        // Should fail
        assert!(codec.decode(&mut partial_shards).is_err());
    }

    #[test]
    fn test_fec_packet_roundtrip() {
        let packet = FecPacket::new(42, 3, 6, 4, 100, vec![1, 2, 3, 4, 5]);
        let bytes = packet.to_bytes();
        let parsed = FecPacket::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.block_id, 42);
        assert_eq!(parsed.shard_index, 3);
        assert_eq!(parsed.total_shards, 6);
        assert_eq!(parsed.data_shards, 4);
        assert_eq!(parsed.original_len, 100);
        assert_eq!(parsed.data, vec![1, 2, 3, 4, 5]);
    }
}
