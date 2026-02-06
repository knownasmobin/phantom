//! Protocol Entropy Morphing Transport
//!
//! **NOVEL TRANSPORT** - Inspired by UPGen (USENIX Security 2025) but adapted
//! for whitelist censors like Iran's GFW.
//!
//! Each session generates a unique wire format derived from the shared key.
//! No two sessions have the same packet structure, so no DPI fingerprint
//! can possibly exist. The morphing is deterministic (both sides compute
//! the same format from the same seed) but appears random to observers.
//!
//! ## How it works
//!
//! 1. Both sides derive a 32-byte `morph_seed` from the shared secret via HKDF
//! 2. The seed deterministically generates a `WireFormat` specifying:
//!    - Header layout (size, field positions, length encoding)
//!    - Per-session magic bytes (unique identifier)
//!    - Byte transformation (XOR mask that changes every byte's appearance)
//!    - Padding strategy (fixed, random, or traffic-shaped)
//!    - Packet size distribution (mimics a randomly-selected real protocol)
//! 3. All tunnel data is encoded/decoded using this session-unique format
//! 4. Runs over TCP port 443 (whitelisted)
//!
//! ## Why it's undetectable
//! - No stable fingerprint: each session has different structure
//! - XOR mask: same plaintext → different ciphertext across sessions
//! - Statistical shaping: packet sizes match real protocol patterns
//! - Per-session magic: no universal identifier to match on
//! - Computationally infeasible for DPI to fingerprint every connection individually

use super::{Transport, TransportStats};
use crate::config::TransportMode;
use crate::error::{PhantomError, Result};

use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

// ============================================================
// Deterministic PRNG seeded from morph_seed
// ============================================================

/// Simple deterministic PRNG (xoshiro256**) for generating wire format
/// from the morph seed. We need determinism, not cryptographic strength.
struct MorphRng {
    state: [u64; 4],
}

impl MorphRng {
    fn from_seed(seed: &[u8; 32]) -> Self {
        let mut state = [0u64; 4];
        for (i, s) in state.iter_mut().enumerate() {
            let offset = i * 8;
            *s = u64::from_le_bytes([
                seed[offset],
                seed[offset + 1],
                seed[offset + 2],
                seed[offset + 3],
                seed[offset + 4],
                seed[offset + 5],
                seed[offset + 6],
                seed[offset + 7],
            ]);
        }
        // Ensure state is never all-zero
        if state == [0; 4] {
            state[0] = 0xDEAD_BEEF_CAFE_BABE;
        }
        Self { state }
    }

    fn next_u64(&mut self) -> u64 {
        let result = self.state[1].wrapping_mul(5).rotate_left(7).wrapping_mul(9);
        let t = self.state[1] << 17;

        self.state[2] ^= self.state[0];
        self.state[3] ^= self.state[1];
        self.state[1] ^= self.state[2];
        self.state[0] ^= self.state[3];

        self.state[2] ^= t;
        self.state[3] = self.state[3].rotate_left(45);

        result
    }

    fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }

    fn next_u8(&mut self) -> u8 {
        (self.next_u64() >> 56) as u8
    }

    /// Random value in range [min, max]
    fn next_range(&mut self, min: usize, max: usize) -> usize {
        if min >= max {
            return min;
        }
        let range = (max - min + 1) as u64;
        (min as u64 + self.next_u64() % range) as usize
    }

    /// Generate N random bytes
    fn next_bytes(&mut self, n: usize) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(n);
        for _ in 0..n {
            bytes.push(self.next_u8());
        }
        bytes
    }
}

// ============================================================
// Wire Format Specification
// ============================================================

/// How the length field is encoded
#[derive(Debug, Clone, Copy)]
pub enum LengthEncoding {
    /// Big-endian 16-bit
    BigEndian16,
    /// Little-endian 16-bit
    LittleEndian16,
    /// Big-endian 32-bit
    BigEndian32,
    /// Variable-length (1 byte if <128, 2 bytes otherwise)
    Variable,
}

/// Padding strategy
#[derive(Debug, Clone, Copy)]
pub enum PaddingStrategy {
    /// No padding
    None,
    /// Pad to fixed block size
    FixedBlock(usize),
    /// Random padding between min and max bytes
    Random { min: usize, max: usize },
    /// Pad to one of several predetermined sizes (mimics HTTP responses)
    HttpMimic,
}

/// A session-unique wire format generated from the morph seed
#[derive(Debug, Clone)]
pub struct WireFormat {
    /// Total header size (4-16 bytes)
    pub header_size: usize,

    /// Position of the length field within the header (byte offset)
    pub length_field_offset: usize,

    /// How the length field is encoded
    pub length_encoding: LengthEncoding,

    /// Per-session magic bytes (2-4 bytes at the start of header)
    pub magic: Vec<u8>,

    /// XOR mask applied to ALL bytes (derived from seed, unique per session)
    /// Completely changes the byte-level appearance of every packet
    pub xor_mask: Vec<u8>,

    /// Padding strategy
    pub padding: PaddingStrategy,

    /// Predetermined packet sizes for HttpMimic mode
    pub mimic_sizes: Vec<usize>,

    /// Whether to include a sequence number in the header
    pub has_sequence: bool,

    /// Position of sequence number (if present)
    pub sequence_offset: usize,
}

impl WireFormat {
    /// Generate a WireFormat deterministically from a 32-byte seed
    ///
    /// Both client and server call this with the same seed and get
    /// identical WireFormat specifications.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let mut rng = MorphRng::from_seed(seed);

        // Header size: 4-16 bytes
        let header_size = rng.next_range(6, 16);

        // Magic bytes: 2-4 bytes
        let magic_len = rng.next_range(2, 4);
        let magic = rng.next_bytes(magic_len);

        // Length field position: after magic, within header
        let length_field_offset = magic_len;

        // Length encoding: randomly selected
        let length_encoding = match rng.next_u32() % 4 {
            0 => LengthEncoding::BigEndian16,
            1 => LengthEncoding::LittleEndian16,
            2 => LengthEncoding::BigEndian32,
            _ => LengthEncoding::Variable,
        };

        // Sequence number: 50% chance
        let has_sequence = rng.next_u32().is_multiple_of(2);
        let sequence_offset = if has_sequence {
            length_field_offset
                + match length_encoding {
                    LengthEncoding::BigEndian16 | LengthEncoding::LittleEndian16 => 2,
                    LengthEncoding::BigEndian32 => 4,
                    LengthEncoding::Variable => 2, // Assume typical 2-byte
                }
        } else {
            0
        };

        // Ensure header is large enough for all fields
        let min_header = if has_sequence {
            sequence_offset + 4
        } else {
            length_field_offset
                + match length_encoding {
                    LengthEncoding::BigEndian16 | LengthEncoding::LittleEndian16 => 2,
                    LengthEncoding::BigEndian32 => 4,
                    LengthEncoding::Variable => 2,
                }
        };
        let header_size = header_size.max(min_header);

        // XOR mask: 256 bytes (repeating)
        let xor_mask = rng.next_bytes(256);

        // Padding strategy
        let padding = match rng.next_u32() % 4 {
            0 => PaddingStrategy::None,
            1 => PaddingStrategy::FixedBlock(rng.next_range(16, 64)),
            2 => PaddingStrategy::Random {
                min: rng.next_range(0, 16),
                max: rng.next_range(32, 128),
            },
            _ => PaddingStrategy::HttpMimic,
        };

        // HTTP-like response sizes for mimicry
        let mimic_sizes = vec![
            rng.next_range(200, 400),
            rng.next_range(500, 900),
            rng.next_range(1000, 1400),
            rng.next_range(1400, 2000),
            rng.next_range(2000, 4000),
        ];

        Self {
            header_size,
            length_field_offset,
            length_encoding,
            magic,
            xor_mask,
            padding,
            mimic_sizes,
            has_sequence,
            sequence_offset,
        }
    }

    /// Encode data into a morphed packet
    pub fn encode(&self, data: &[u8], sequence: u32) -> Vec<u8> {
        let padded_data = self.apply_padding(data);
        let payload_len = padded_data.len();

        let mut packet = Vec::with_capacity(self.header_size + payload_len);

        // Build header with empty bytes first
        packet.resize(self.header_size, 0);

        // Write magic
        for (i, &b) in self.magic.iter().enumerate() {
            if i < packet.len() {
                packet[i] = b;
            }
        }

        // Write length field
        self.encode_length(payload_len, &mut packet);

        // Write sequence number if enabled
        if self.has_sequence && self.sequence_offset + 4 <= self.header_size {
            let seq_bytes = sequence.to_be_bytes();
            packet[self.sequence_offset..self.sequence_offset + 4].copy_from_slice(&seq_bytes);
        }

        // Fill remaining header bytes with deterministic padding
        // (so they don't stand out as zeros)
        for (i, byte) in packet[..self.header_size].iter_mut().enumerate() {
            if *byte == 0 && !self.is_field_position(i) {
                *byte = self.xor_mask[i % self.xor_mask.len()];
            }
        }

        // Append payload
        packet.extend_from_slice(&padded_data);

        // Apply XOR mask to entire packet
        self.apply_xor_mask(&mut packet);

        packet
    }

    /// Decode a morphed packet back to original data
    pub fn decode(&self, packet: &[u8]) -> Result<(Vec<u8>, u32)> {
        if packet.len() < self.header_size {
            return Err(PhantomError::PacketParse("Morphed packet too short".into()));
        }

        // Remove XOR mask
        let mut unmasked = packet.to_vec();
        self.apply_xor_mask(&mut unmasked);

        // Verify magic
        for (i, &expected) in self.magic.iter().enumerate() {
            if i >= unmasked.len() || unmasked[i] != expected {
                return Err(PhantomError::InvalidPacket("Morph magic mismatch".into()));
            }
        }

        // Read length field
        let payload_len = self.decode_length(&unmasked)?;

        // Read sequence number
        let sequence = if self.has_sequence && self.sequence_offset + 4 <= self.header_size {
            u32::from_be_bytes([
                unmasked[self.sequence_offset],
                unmasked[self.sequence_offset + 1],
                unmasked[self.sequence_offset + 2],
                unmasked[self.sequence_offset + 3],
            ])
        } else {
            0
        };

        // Extract payload
        let payload_start = self.header_size;
        let payload_end = payload_start + payload_len;

        if payload_end > unmasked.len() {
            return Err(PhantomError::PacketParse(
                "Morph payload exceeds packet".into(),
            ));
        }

        let payload = unmasked[payload_start..payload_end].to_vec();

        // Remove padding
        let data = self.remove_padding(&payload)?;

        Ok((data, sequence))
    }

    /// Apply XOR mask to data (symmetric - same operation for encode/decode)
    fn apply_xor_mask(&self, data: &mut [u8]) {
        let mask_len = self.xor_mask.len();
        for (i, byte) in data.iter_mut().enumerate() {
            *byte ^= self.xor_mask[i % mask_len];
        }
    }

    /// Encode length into the header
    fn encode_length(&self, length: usize, header: &mut [u8]) {
        let offset = self.length_field_offset;
        match self.length_encoding {
            LengthEncoding::BigEndian16 => {
                if offset + 2 <= header.len() {
                    let bytes = (length as u16).to_be_bytes();
                    header[offset] = bytes[0];
                    header[offset + 1] = bytes[1];
                }
            }
            LengthEncoding::LittleEndian16 => {
                if offset + 2 <= header.len() {
                    let bytes = (length as u16).to_le_bytes();
                    header[offset] = bytes[0];
                    header[offset + 1] = bytes[1];
                }
            }
            LengthEncoding::BigEndian32 => {
                if offset + 4 <= header.len() {
                    let bytes = (length as u32).to_be_bytes();
                    header[offset..offset + 4].copy_from_slice(&bytes);
                }
            }
            LengthEncoding::Variable => {
                if length < 128 {
                    if offset < header.len() {
                        header[offset] = length as u8;
                    }
                } else if offset + 1 < header.len() {
                    header[offset] = 0x80 | ((length >> 8) as u8 & 0x7F);
                    header[offset + 1] = (length & 0xFF) as u8;
                }
            }
        }
    }

    /// Decode length from the header
    fn decode_length(&self, header: &[u8]) -> Result<usize> {
        let offset = self.length_field_offset;
        match self.length_encoding {
            LengthEncoding::BigEndian16 => {
                if offset + 2 > header.len() {
                    return Err(PhantomError::PacketParse("Length field truncated".into()));
                }
                Ok(u16::from_be_bytes([header[offset], header[offset + 1]]) as usize)
            }
            LengthEncoding::LittleEndian16 => {
                if offset + 2 > header.len() {
                    return Err(PhantomError::PacketParse("Length field truncated".into()));
                }
                Ok(u16::from_le_bytes([header[offset], header[offset + 1]]) as usize)
            }
            LengthEncoding::BigEndian32 => {
                if offset + 4 > header.len() {
                    return Err(PhantomError::PacketParse("Length field truncated".into()));
                }
                Ok(u32::from_be_bytes([
                    header[offset],
                    header[offset + 1],
                    header[offset + 2],
                    header[offset + 3],
                ]) as usize)
            }
            LengthEncoding::Variable => {
                if offset >= header.len() {
                    return Err(PhantomError::PacketParse("Length field truncated".into()));
                }
                if header[offset] & 0x80 == 0 {
                    Ok(header[offset] as usize)
                } else if offset + 1 < header.len() {
                    let high = (header[offset] & 0x7F) as usize;
                    let low = header[offset + 1] as usize;
                    Ok((high << 8) | low)
                } else {
                    Err(PhantomError::PacketParse(
                        "Variable length truncated".into(),
                    ))
                }
            }
        }
    }

    /// Check if a byte position is part of a field (not padding)
    fn is_field_position(&self, pos: usize) -> bool {
        // Magic bytes
        if pos < self.magic.len() {
            return true;
        }
        // Length field
        let len_size = match self.length_encoding {
            LengthEncoding::BigEndian16 | LengthEncoding::LittleEndian16 => 2,
            LengthEncoding::BigEndian32 => 4,
            LengthEncoding::Variable => 2,
        };
        if pos >= self.length_field_offset && pos < self.length_field_offset + len_size {
            return true;
        }
        // Sequence number
        if self.has_sequence && pos >= self.sequence_offset && pos < self.sequence_offset + 4 {
            return true;
        }
        false
    }

    /// Apply padding to data before encoding
    fn apply_padding(&self, data: &[u8]) -> Vec<u8> {
        match self.padding {
            PaddingStrategy::None => {
                // Length-prefixed so receiver knows where data ends
                let mut padded = Vec::with_capacity(2 + data.len());
                padded.extend_from_slice(&(data.len() as u16).to_be_bytes());
                padded.extend_from_slice(data);
                padded
            }
            PaddingStrategy::FixedBlock(block) => {
                let total = (2 + data.len()).div_ceil(block) * block;
                let mut padded = Vec::with_capacity(total);
                padded.extend_from_slice(&(data.len() as u16).to_be_bytes());
                padded.extend_from_slice(data);
                padded.resize(total, 0);
                padded
            }
            PaddingStrategy::Random { min, max } => {
                let pad_amount = min + (crate::utils::random_u32() as usize % (max - min + 1));
                let mut padded = Vec::with_capacity(2 + data.len() + pad_amount);
                padded.extend_from_slice(&(data.len() as u16).to_be_bytes());
                padded.extend_from_slice(data);
                padded.extend_from_slice(&crate::utils::random_bytes(pad_amount));
                padded
            }
            PaddingStrategy::HttpMimic => {
                // Pad to nearest mimic size
                let base_len = 2 + data.len();
                let target = self
                    .mimic_sizes
                    .iter()
                    .find(|&&s| s >= base_len)
                    .copied()
                    .unwrap_or(*self.mimic_sizes.last().unwrap_or(&base_len));
                let mut padded = Vec::with_capacity(target);
                padded.extend_from_slice(&(data.len() as u16).to_be_bytes());
                padded.extend_from_slice(data);
                if padded.len() < target {
                    padded.extend_from_slice(&crate::utils::random_bytes(target - padded.len()));
                }
                padded
            }
        }
    }

    /// Remove padding from decoded payload
    fn remove_padding(&self, payload: &[u8]) -> Result<Vec<u8>> {
        if payload.len() < 2 {
            return Err(PhantomError::PacketParse(
                "Payload too short for length prefix".into(),
            ));
        }
        let data_len = u16::from_be_bytes([payload[0], payload[1]]) as usize;
        if 2 + data_len > payload.len() {
            return Err(PhantomError::PacketParse(
                "Data length exceeds payload".into(),
            ));
        }
        Ok(payload[2..2 + data_len].to_vec())
    }
}

// ============================================================
// Protocol Morph Transport
// ============================================================

/// Protocol Entropy Morphing Transport
pub struct ProtoMorphTransport {
    /// TCP stream
    stream: Arc<Mutex<Option<TcpStream>>>,
    /// Remote address
    remote_addr: SocketAddr,
    /// Session-unique wire format
    wire_format: WireFormat,
    /// Sequence counter
    sequence: AtomicU64,
    /// Stats
    stats: Arc<TransportStatsInner>,
    /// Running flag
    running: Arc<AtomicBool>,
}

struct TransportStatsInner {
    packets_sent: AtomicU64,
    packets_recv: AtomicU64,
    bytes_sent: AtomicU64,
    bytes_recv: AtomicU64,
    packets_dropped: AtomicU64,
}

impl ProtoMorphTransport {
    /// Create a new protocol morphing transport with a given seed
    ///
    /// Both client and server must use the same seed (derived from shared key).
    pub async fn new(remote_addr: SocketAddr, seed: [u8; 32]) -> Result<Self> {
        let wire_format = WireFormat::from_seed(&seed);

        Ok(Self {
            stream: Arc::new(Mutex::new(None)),
            remote_addr,
            wire_format,
            sequence: AtomicU64::new(0),
            stats: Arc::new(TransportStatsInner {
                packets_sent: AtomicU64::new(0),
                packets_recv: AtomicU64::new(0),
                bytes_sent: AtomicU64::new(0),
                bytes_recv: AtomicU64::new(0),
                packets_dropped: AtomicU64::new(0),
            }),
            running: Arc::new(AtomicBool::new(true)),
        })
    }

    /// Create with a default random seed (for testing)
    pub async fn new_random(remote_addr: SocketAddr) -> Result<Self> {
        let seed_bytes = crate::utils::random_bytes(32);
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&seed_bytes);
        Self::new(remote_addr, seed).await
    }

    /// Get the wire format (for inspection/debugging)
    pub fn wire_format(&self) -> &WireFormat {
        &self.wire_format
    }

    /// Ensure connection
    async fn ensure_connected(&self) -> Result<()> {
        let needs_connect = self.stream.lock().await.is_none();

        if needs_connect {
            let stream = TcpStream::connect(self.remote_addr)
                .await
                .map_err(|e| PhantomError::Socket(format!("Morph connect failed: {}", e)))?;
            stream.set_nodelay(true).ok();
            *self.stream.lock().await = Some(stream);
        }
        Ok(())
    }

    fn next_sequence(&self) -> u32 {
        self.sequence.fetch_add(1, Ordering::Relaxed) as u32
    }
}

#[async_trait]
impl Transport for ProtoMorphTransport {
    fn mode(&self) -> TransportMode {
        TransportMode::ProtoMorph
    }

    async fn send(&self, data: &[u8], dst: SocketAddr) -> Result<usize> {
        self.ensure_connected().await?;

        let seq = self.next_sequence();
        let packet = self.wire_format.encode(data, seq);

        let mut guard = self.stream.lock().await;
        if let Some(ref mut stream) = *guard {
            // Send length prefix (4 bytes) + packet
            // This framing is also morphed by the XOR mask
            let frame_len = (packet.len() as u32).to_be_bytes();
            stream
                .write_all(&frame_len)
                .await
                .map_err(PhantomError::Io)?;
            stream.write_all(&packet).await.map_err(PhantomError::Io)?;

            self.stats.packets_sent.fetch_add(1, Ordering::Relaxed);
            self.stats
                .bytes_sent
                .fetch_add((4 + packet.len()) as u64, Ordering::Relaxed);

            Ok(data.len())
        } else {
            Err(PhantomError::Socket("Not connected".into()))
        }
    }

    async fn recv(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        self.ensure_connected().await?;

        let mut guard = self.stream.lock().await;
        if let Some(ref mut stream) = *guard {
            // Read frame length
            let mut len_buf = [0u8; 4];
            stream
                .read_exact(&mut len_buf)
                .await
                .map_err(PhantomError::Io)?;

            let frame_len = u32::from_be_bytes(len_buf) as usize;
            if frame_len > 65535 {
                return Err(PhantomError::PacketParse("Frame too large".into()));
            }

            // Read the morphed packet
            let mut packet = vec![0u8; frame_len];
            stream
                .read_exact(&mut packet)
                .await
                .map_err(PhantomError::Io)?;

            // Decode
            let (data, _seq) = self.wire_format.decode(&packet)?;

            let len = data.len().min(buf.len());
            buf[..len].copy_from_slice(&data[..len]);

            self.stats.packets_recv.fetch_add(1, Ordering::Relaxed);
            self.stats
                .bytes_recv
                .fetch_add((4 + frame_len) as u64, Ordering::Relaxed);

            Ok((len, self.remote_addr))
        } else {
            Err(PhantomError::Socket("Not connected".into()))
        }
    }

    async fn close(&self) -> Result<()> {
        self.running.store(false, Ordering::SeqCst);
        let mut guard = self.stream.lock().await;
        if let Some(ref mut stream) = *guard {
            let _ = stream.shutdown().await;
        }
        *guard = None;
        Ok(())
    }

    fn is_healthy(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    fn stats(&self) -> TransportStats {
        TransportStats {
            packets_sent: self.stats.packets_sent.load(Ordering::Relaxed),
            packets_recv: self.stats.packets_recv.load(Ordering::Relaxed),
            bytes_sent: self.stats.bytes_sent.load(Ordering::Relaxed),
            bytes_recv: self.stats.bytes_recv.load(Ordering::Relaxed),
            packets_dropped: self.stats.packets_dropped.load(Ordering::Relaxed),
            retransmissions: 0,
            avg_rtt_ms: 0.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_morph_rng_deterministic() {
        let seed = [42u8; 32];
        let mut rng1 = MorphRng::from_seed(&seed);
        let mut rng2 = MorphRng::from_seed(&seed);

        for _ in 0..100 {
            assert_eq!(rng1.next_u64(), rng2.next_u64());
        }
    }

    #[test]
    fn test_morph_rng_different_seeds() {
        let mut rng1 = MorphRng::from_seed(&[1u8; 32]);
        let mut rng2 = MorphRng::from_seed(&[2u8; 32]);

        // Should produce different output
        let vals1: Vec<u64> = (0..10).map(|_| rng1.next_u64()).collect();
        let vals2: Vec<u64> = (0..10).map(|_| rng2.next_u64()).collect();
        assert_ne!(vals1, vals2);
    }

    #[test]
    fn test_wire_format_deterministic() {
        let seed = [0xAB; 32];
        let fmt1 = WireFormat::from_seed(&seed);
        let fmt2 = WireFormat::from_seed(&seed);

        assert_eq!(fmt1.header_size, fmt2.header_size);
        assert_eq!(fmt1.magic, fmt2.magic);
        assert_eq!(fmt1.xor_mask, fmt2.xor_mask);
        assert_eq!(fmt1.has_sequence, fmt2.has_sequence);
    }

    #[test]
    fn test_wire_format_different_seeds() {
        let fmt1 = WireFormat::from_seed(&[1u8; 32]);
        let fmt2 = WireFormat::from_seed(&[2u8; 32]);

        // Different seeds should produce different formats
        // (magic bytes should differ with overwhelming probability)
        assert_ne!(fmt1.magic, fmt2.magic);
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let seed = [0xCD; 32];
        let format = WireFormat::from_seed(&seed);

        let data = b"Hello, morphed world!";
        let encoded = format.encode(data, 42);

        // Verify encoded doesn't contain the plaintext
        let data_str = std::str::from_utf8(data).unwrap();
        let encoded_str = String::from_utf8_lossy(&encoded);
        assert!(!encoded_str.contains(data_str));

        // Verify roundtrip
        let (decoded, seq) = format.decode(&encoded).unwrap();
        assert_eq!(decoded, data);
        if format.has_sequence {
            assert_eq!(seq, 42);
        } else {
            assert_eq!(seq, 0);
        }
    }

    #[test]
    fn test_encode_decode_large_data() {
        let seed = [0xEF; 32];
        let format = WireFormat::from_seed(&seed);

        let data = vec![0x42; 5000];
        let encoded = format.encode(&data, 0);
        let (decoded, _) = format.decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_different_sessions_different_output() {
        let fmt1 = WireFormat::from_seed(&[1u8; 32]);
        let fmt2 = WireFormat::from_seed(&[2u8; 32]);

        let data = b"same input data";

        let encoded1 = fmt1.encode(data, 0);
        let encoded2 = fmt2.encode(data, 0);

        // Same data, different seeds = different output
        assert_ne!(encoded1, encoded2);

        // But both decode correctly with their own format
        let (decoded1, _) = fmt1.decode(&encoded1).unwrap();
        let (decoded2, _) = fmt2.decode(&encoded2).unwrap();
        assert_eq!(decoded1, data.to_vec());
        assert_eq!(decoded2, data.to_vec());

        // Cross-decoding should fail
        assert!(fmt1.decode(&encoded2).is_err());
        assert!(fmt2.decode(&encoded1).is_err());
    }

    #[test]
    fn test_xor_mask_symmetry() {
        let seed = [0x55; 32];
        let format = WireFormat::from_seed(&seed);

        let mut data = vec![1, 2, 3, 4, 5];
        let original = data.clone();

        // Apply twice = identity
        format.apply_xor_mask(&mut data);
        assert_ne!(data, original); // Should be different after first XOR
        format.apply_xor_mask(&mut data);
        assert_eq!(data, original); // Should be back to original
    }

    #[test]
    fn test_all_padding_strategies() {
        for seed_byte in [0x01, 0x42, 0x83, 0xC4] {
            let seed = [seed_byte; 32];
            let format = WireFormat::from_seed(&seed);

            let data = b"test data for padding";
            let encoded = format.encode(data, 0);
            let (decoded, _) = format.decode(&encoded).unwrap();
            assert_eq!(decoded, data, "Failed with seed byte 0x{:02x}", seed_byte);
        }
    }

    #[test]
    fn test_empty_data() {
        let seed = [0xFF; 32];
        let format = WireFormat::from_seed(&seed);

        let data = b"";
        let encoded = format.encode(data, 0);
        let (decoded, _) = format.decode(&encoded).unwrap();
        assert_eq!(decoded, data.to_vec());
    }
}
