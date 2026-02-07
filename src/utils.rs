//! Utility functions for Phantom tunnel

use std::net::Ipv4Addr;

/// Calculate Internet checksum (RFC 1071)
/// Used for IP, TCP, UDP, ICMP headers
pub fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;

    // Sum 16-bit words
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }

    // Add odd byte if present
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }

    // Fold 32-bit sum to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
}

/// Calculate TCP/UDP checksum with pseudo-header
pub fn tcp_checksum(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, protocol: u8, tcp_segment: &[u8]) -> u16 {
    let mut pseudo_header = Vec::with_capacity(12 + tcp_segment.len());

    // Pseudo-header
    pseudo_header.extend_from_slice(&src_ip.octets());
    pseudo_header.extend_from_slice(&dst_ip.octets());
    pseudo_header.push(0); // Reserved
    pseudo_header.push(protocol);
    pseudo_header.extend_from_slice(&(tcp_segment.len() as u16).to_be_bytes());

    // TCP segment
    pseudo_header.extend_from_slice(tcp_segment);

    internet_checksum(&pseudo_header)
}

/// Calculate ICMP checksum
pub fn icmp_checksum(icmp_packet: &[u8]) -> u16 {
    internet_checksum(icmp_packet)
}

/// Generate a random u32 for sequence numbers, etc.
pub fn random_u32() -> u32 {
    use rand::Rng;
    rand::thread_rng().gen()
}

/// Generate a random u16 for ports, IDs, etc.
pub fn random_u16() -> u16 {
    use rand::Rng;
    rand::thread_rng().gen()
}

/// Generate random bytes
pub fn random_bytes(len: usize) -> Vec<u8> {
    use rand::Rng;
    let mut bytes = vec![0u8; len];
    rand::thread_rng().fill(&mut bytes[..]);
    bytes
}

/// Get current timestamp in milliseconds
pub fn timestamp_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_millis() as u64
}

/// Get current timestamp in microseconds
pub fn timestamp_us() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_micros() as u64
}

/// Monotonic counter for replay protection
pub struct MonotonicCounter {
    counter: std::sync::atomic::AtomicU64,
}

impl MonotonicCounter {
    pub fn new() -> Self {
        Self {
            counter: std::sync::atomic::AtomicU64::new(timestamp_us()),
        }
    }

    pub fn next(&self) -> u64 {
        self.counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    }

    pub fn current(&self) -> u64 {
        self.counter.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl Default for MonotonicCounter {
    fn default() -> Self {
        Self::new()
    }
}

/// Sliding window for replay protection
pub struct ReplayWindow {
    window: std::collections::HashSet<u64>,
    window_size: usize,
    last_seq: u64,
}

impl ReplayWindow {
    pub fn new(size: usize) -> Self {
        Self {
            window: std::collections::HashSet::with_capacity(size),
            window_size: size,
            last_seq: 0,
        }
    }

    /// Check if a sequence number is valid (not replayed)
    /// Returns true if valid, false if replayed
    pub fn check_and_update(&mut self, seq: u64) -> bool {
        // If sequence is too old, reject
        if seq + self.window_size as u64 <= self.last_seq {
            return false;
        }

        // If sequence is in window, check if seen (O(1) with HashSet)
        if self.window.contains(&seq) {
            return false;
        }

        // Valid - update window
        self.window.insert(seq);
        if seq > self.last_seq {
            self.last_seq = seq;
        }

        // Trim window
        if self.window.len() > self.window_size {
            let cutoff = self.last_seq.saturating_sub(self.window_size as u64);
            self.window.retain(|&s| s > cutoff);
        }

        true
    }
}

/// XOR two byte slices
pub fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

/// Pad data to a multiple of block_size
pub fn pad_to_block(data: &[u8], block_size: usize) -> Vec<u8> {
    let padding_needed = (block_size - (data.len() % block_size)) % block_size;
    let mut padded = data.to_vec();
    padded.extend(std::iter::repeat_n(0u8, padding_needed));
    padded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_internet_checksum() {
        // Test vector from RFC 1071
        let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        let sum = internet_checksum(&data);
        assert_eq!(sum, 0x220d);
    }

    #[test]
    fn test_replay_window() {
        let mut window = ReplayWindow::new(10);

        assert!(window.check_and_update(1));
        assert!(window.check_and_update(2));
        assert!(!window.check_and_update(1)); // Replay
        assert!(window.check_and_update(5));
        assert!(window.check_and_update(3)); // Out of order OK
        assert!(!window.check_and_update(3)); // Replay
    }
}
