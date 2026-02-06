//! DNS Tunnel Transport
//!
//! Implements tunneling over DNS queries and responses.
//! DNS (port 53) is never blocked because it's required for all internet access.
//! Data is encoded into DNS query names and TXT record responses.
//!
//! Encoding: Each label in a DNS name can carry up to 63 bytes.
//! We use base32 encoding in query names (A/CNAME queries) and
//! base64 in TXT record responses for higher throughput downstream.
//!
//! Advantages over raw IP transports:
//! - DNS is ALWAYS whitelisted (blocking it = no internet)
//! - Works even on captive portals and heavily restricted networks
//! - Can traverse NAT without raw socket privileges (UDP mode)
//!
//! Limitations:
//! - Low throughput (~50-100 KB/s typical)
//! - High latency (DNS caching, round-trip per query)
//! - Query name length limited to 253 bytes total
//! - Best used as fallback/control channel

use super::{Transport, TransportStats};
use crate::config::TransportMode;
use crate::error::{PhantomError, Result};
use crate::utils::random_u16;

use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::net::UdpSocket;

/// DNS header constants
const DNS_FLAG_QUERY: u16 = 0x0100; // Standard query, recursion desired
const DNS_FLAG_RESPONSE: u16 = 0x8180; // Standard response, recursion available
const DNS_TYPE_TXT: u16 = 16;
const DNS_TYPE_CNAME: u16 = 5;
const DNS_TYPE_NULL: u16 = 10; // NULL record - allows arbitrary data
const DNS_CLASS_IN: u16 = 1;

/// Maximum data per DNS query name (after base32 encoding, split across labels)
/// Each label max 63 chars, total name max 253 chars
/// With base32: ~150 bytes of raw data per query name
const MAX_QUERY_DATA: usize = 150;

/// Maximum data per TXT record response
/// TXT records can carry up to ~65000 bytes, but we stay conservative
const MAX_RESPONSE_DATA: usize = 200;

/// Base32 encoding table (lowercase for DNS compatibility)
const BASE32_ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// DNS tunnel transport
pub struct DnsTunnelTransport {
    /// UDP socket for DNS communication
    socket: Arc<UdpSocket>,
    /// Tunnel domain suffix (e.g., "t.example.com")
    tunnel_domain: String,
    /// Transaction ID counter
    tx_id: AtomicU16,
    /// Whether we're operating as upstream (server) resolver
    is_server: bool,
    /// Stats tracking
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

impl DnsTunnelTransport {
    /// Create a new DNS tunnel transport (client mode)
    ///
    /// # Arguments
    /// * `bind_addr` - Local address to bind UDP socket
    /// * `tunnel_domain` - Domain suffix for tunnel queries (e.g., "t.example.com")
    pub async fn new(bind_addr: SocketAddr, tunnel_domain: String) -> Result<Self> {
        let socket = UdpSocket::bind(bind_addr)
            .await
            .map_err(|e| PhantomError::Socket(format!("DNS bind failed: {}", e)))?;

        Ok(Self {
            socket: Arc::new(socket),
            tunnel_domain,
            tx_id: AtomicU16::new(random_u16()),
            is_server: false,
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

    /// Create in server mode (authoritative resolver for tunnel domain)
    pub async fn new_server(bind_addr: SocketAddr, tunnel_domain: String) -> Result<Self> {
        let mut transport = Self::new(bind_addr, tunnel_domain).await?;
        transport.is_server = true;
        Ok(transport)
    }

    /// Get next transaction ID
    fn next_tx_id(&self) -> u16 {
        self.tx_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Encode data into a DNS query packet
    ///
    /// Format: <base32_label1>.<base32_label2>...<tunnel_domain>
    /// Query type: NULL (allows arbitrary data) or TXT
    fn encode_query(&self, data: &[u8]) -> Vec<u8> {
        let tx_id = self.next_tx_id();
        let encoded_name = self.encode_query_name(data);

        let mut packet = Vec::with_capacity(512);

        // DNS Header (12 bytes)
        packet.extend_from_slice(&tx_id.to_be_bytes()); // Transaction ID
        packet.extend_from_slice(&DNS_FLAG_QUERY.to_be_bytes()); // Flags
        packet.extend_from_slice(&1u16.to_be_bytes()); // Questions: 1
        packet.extend_from_slice(&0u16.to_be_bytes()); // Answers: 0
        packet.extend_from_slice(&0u16.to_be_bytes()); // Authority: 0
        packet.extend_from_slice(&0u16.to_be_bytes()); // Additional: 0

        // Question section
        packet.extend_from_slice(&encoded_name); // QNAME
        packet.extend_from_slice(&DNS_TYPE_NULL.to_be_bytes()); // QTYPE: NULL
        packet.extend_from_slice(&DNS_CLASS_IN.to_be_bytes()); // QCLASS: IN

        packet
    }

    /// Encode data into DNS query name labels
    ///
    /// Base32-encodes the data and splits into labels of max 63 chars each
    fn encode_query_name(&self, data: &[u8]) -> Vec<u8> {
        let encoded = base32_encode(data);

        let mut name = Vec::new();

        // Split encoded data into labels of max 63 chars
        for chunk in encoded.as_bytes().chunks(63) {
            name.push(chunk.len() as u8);
            name.extend_from_slice(chunk);
        }

        // Append tunnel domain labels
        for label in self.tunnel_domain.split('.') {
            if !label.is_empty() {
                name.push(label.len() as u8);
                name.extend_from_slice(label.as_bytes());
            }
        }

        // Null terminator
        name.push(0);

        name
    }

    /// Decode data from a DNS query name
    ///
    /// Strips the tunnel domain suffix and base32-decodes the remaining labels
    fn decode_query_name(&self, name_data: &[u8]) -> Result<Vec<u8>> {
        let labels = parse_dns_labels(name_data)?;

        // Count how many labels belong to the tunnel domain
        let domain_labels: Vec<&str> = self
            .tunnel_domain
            .split('.')
            .filter(|s| !s.is_empty())
            .collect();
        let domain_label_count = domain_labels.len();

        if labels.len() <= domain_label_count {
            return Err(PhantomError::InvalidPacket("Query name too short".into()));
        }

        // Data labels are everything before the tunnel domain suffix
        let data_label_count = labels.len() - domain_label_count;
        let data_labels = &labels[..data_label_count];

        // Concatenate data labels and base32-decode
        let encoded: String = data_labels.join("");
        base32_decode(&encoded)
            .ok_or_else(|| PhantomError::InvalidPacket("Invalid base32 in query".into()))
    }

    /// Encode data into a DNS response packet (TXT record)
    fn encode_response(&self, tx_id: u16, query_name: &[u8], data: &[u8]) -> Vec<u8> {
        let mut packet = Vec::with_capacity(512);

        // DNS Header
        packet.extend_from_slice(&tx_id.to_be_bytes());
        packet.extend_from_slice(&DNS_FLAG_RESPONSE.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes()); // Questions: 1
        packet.extend_from_slice(&1u16.to_be_bytes()); // Answers: 1
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());

        // Question section (echo back)
        packet.extend_from_slice(query_name);
        packet.extend_from_slice(&DNS_TYPE_NULL.to_be_bytes());
        packet.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());

        // Answer section (TXT record with tunnel data)
        packet.extend_from_slice(&[0xC0, 0x0C]); // Name pointer to question
        packet.extend_from_slice(&DNS_TYPE_TXT.to_be_bytes());
        packet.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        packet.extend_from_slice(&0u32.to_be_bytes()); // TTL = 0 (no caching)

        // TXT RDATA: length-prefixed strings
        // Each TXT string can be up to 255 bytes
        let mut rdata = Vec::new();
        for chunk in data.chunks(255) {
            rdata.push(chunk.len() as u8);
            rdata.extend_from_slice(chunk);
        }

        packet.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        packet.extend_from_slice(&rdata);

        packet
    }

    /// Parse a DNS response and extract TXT record data
    fn decode_response(&self, packet: &[u8]) -> Result<(u16, Vec<u8>)> {
        if packet.len() < 12 {
            return Err(PhantomError::PacketParse("DNS packet too short".into()));
        }

        let tx_id = u16::from_be_bytes([packet[0], packet[1]]);
        let flags = u16::from_be_bytes([packet[2], packet[3]]);
        let answer_count = u16::from_be_bytes([packet[6], packet[7]]);

        // Verify it's a response
        if flags & 0x8000 == 0 {
            return Err(PhantomError::InvalidPacket("Not a DNS response".into()));
        }

        if answer_count == 0 {
            return Err(PhantomError::InvalidPacket(
                "No answers in DNS response".into(),
            ));
        }

        // Skip question section
        let mut offset = 12;
        offset = skip_dns_name(packet, offset)?;
        offset += 4; // QTYPE + QCLASS

        // Parse answer section
        offset = skip_dns_name(packet, offset)?;

        if offset + 10 > packet.len() {
            return Err(PhantomError::PacketParse("Answer section too short".into()));
        }

        let rtype = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        offset += 2; // TYPE
        offset += 2; // CLASS
        offset += 4; // TTL

        let rdlength = u16::from_be_bytes([packet[offset], packet[offset + 1]]) as usize;
        offset += 2;

        if offset + rdlength > packet.len() {
            return Err(PhantomError::PacketParse("RDATA exceeds packet".into()));
        }

        // Extract TXT record data (concatenate all TXT strings)
        let mut data = Vec::new();
        let rdata_end = offset + rdlength;

        if rtype == DNS_TYPE_TXT {
            let mut pos = offset;
            while pos < rdata_end {
                let txt_len = packet[pos] as usize;
                pos += 1;
                if pos + txt_len > rdata_end {
                    break;
                }
                data.extend_from_slice(&packet[pos..pos + txt_len]);
                pos += txt_len;
            }
        } else {
            // For NULL or other record types, take raw RDATA
            data.extend_from_slice(&packet[offset..rdata_end]);
        }

        Ok((tx_id, data))
    }

    /// Parse an incoming DNS query and extract the encoded data
    fn decode_query(&self, packet: &[u8]) -> Result<(u16, Vec<u8>, Vec<u8>)> {
        if packet.len() < 12 {
            return Err(PhantomError::PacketParse("DNS packet too short".into()));
        }

        let tx_id = u16::from_be_bytes([packet[0], packet[1]]);
        let flags = u16::from_be_bytes([packet[2], packet[3]]);

        // Verify it's a query
        if flags & 0x8000 != 0 {
            return Err(PhantomError::InvalidPacket("Not a DNS query".into()));
        }

        // Extract query name
        let name_start = 12;
        let name_end = skip_dns_name(packet, name_start)?;
        let query_name = packet[name_start..name_end].to_vec();

        // Decode data from the query name
        let data = self.decode_query_name(&packet[name_start..])?;

        Ok((tx_id, query_name, data))
    }
}

#[async_trait]
impl Transport for DnsTunnelTransport {
    fn mode(&self) -> TransportMode {
        TransportMode::Dns
    }

    async fn send(&self, data: &[u8], dst: SocketAddr) -> Result<usize> {
        let packet = if self.is_server {
            // Server sends responses - we need a tx_id and query_name
            // In practice, the tunnel layer manages request/response pairing
            // For raw send, we encode as a query (bidirectional queries)
            self.encode_query(data)
        } else {
            // Client encodes data as DNS query
            self.encode_query(data)
        };

        self.socket
            .send_to(&packet, dst)
            .await
            .map_err(PhantomError::Io)?;

        self.stats.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.stats
            .bytes_sent
            .fetch_add(packet.len() as u64, Ordering::Relaxed);

        Ok(data.len())
    }

    async fn recv(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        let mut raw_buf = [0u8; 4096];

        loop {
            let (n, src) = self
                .socket
                .recv_from(&mut raw_buf)
                .await
                .map_err(PhantomError::Io)?;

            if n < 12 {
                self.stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
                continue;
            }

            let result = if self.is_server {
                // Server receives queries - extract data from query names
                match self.decode_query(&raw_buf[..n]) {
                    Ok((_tx_id, _query_name, data)) => Ok(data),
                    Err(e) => Err(e),
                }
            } else {
                // Client receives responses - extract data from TXT records
                match self.decode_response(&raw_buf[..n]) {
                    Ok((_tx_id, data)) => Ok(data),
                    Err(e) => Err(e),
                }
            };

            match result {
                Ok(data) => {
                    let len = data.len().min(buf.len());
                    buf[..len].copy_from_slice(&data[..len]);

                    self.stats.packets_recv.fetch_add(1, Ordering::Relaxed);
                    self.stats
                        .bytes_recv
                        .fetch_add(len as u64, Ordering::Relaxed);

                    return Ok((len, src));
                }
                Err(_) => {
                    self.stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            }
        }
    }

    async fn close(&self) -> Result<()> {
        self.running.store(false, Ordering::SeqCst);
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

// ============================================================
// DNS Helper Functions
// ============================================================

/// Base32 encode (RFC 4648, lowercase)
fn base32_encode(data: &[u8]) -> String {
    let mut result = String::new();
    let mut buffer: u64 = 0;
    let mut bits_left = 0;

    for &byte in data {
        buffer = (buffer << 8) | byte as u64;
        bits_left += 8;

        while bits_left >= 5 {
            bits_left -= 5;
            let index = ((buffer >> bits_left) & 0x1F) as usize;
            result.push(BASE32_ALPHABET[index] as char);
        }
    }

    if bits_left > 0 {
        let index = ((buffer << (5 - bits_left)) & 0x1F) as usize;
        result.push(BASE32_ALPHABET[index] as char);
    }

    result
}

/// Base32 decode (RFC 4648, lowercase)
fn base32_decode(input: &str) -> Option<Vec<u8>> {
    let mut result = Vec::new();
    let mut buffer: u64 = 0;
    let mut bits_left = 0;

    for c in input.chars() {
        let val = match c {
            'a'..='z' => (c as u8 - b'a') as u64,
            '2'..='7' => (c as u8 - b'2' + 26) as u64,
            'A'..='Z' => (c as u8 - b'A') as u64, // case-insensitive
            '=' => continue,                      // padding
            _ => return None,
        };

        buffer = (buffer << 5) | val;
        bits_left += 5;

        if bits_left >= 8 {
            bits_left -= 8;
            result.push((buffer >> bits_left) as u8);
        }
    }

    Some(result)
}

/// Parse DNS name labels into a vector of strings
fn parse_dns_labels(data: &[u8]) -> Result<Vec<String>> {
    let mut labels = Vec::new();
    let mut offset = 0;

    loop {
        if offset >= data.len() {
            break;
        }

        let len = data[offset] as usize;
        if len == 0 {
            break;
        }

        // Check for compression pointer
        if len & 0xC0 == 0xC0 {
            break; // Stop at compression pointer
        }

        offset += 1;

        if offset + len > data.len() {
            return Err(PhantomError::PacketParse("DNS label exceeds packet".into()));
        }

        let label = String::from_utf8_lossy(&data[offset..offset + len]).to_string();
        labels.push(label);
        offset += len;
    }

    Ok(labels)
}

/// Skip a DNS name in a packet, returning offset after the name
fn skip_dns_name(packet: &[u8], mut offset: usize) -> Result<usize> {
    loop {
        if offset >= packet.len() {
            return Err(PhantomError::PacketParse("DNS name exceeds packet".into()));
        }

        let len = packet[offset] as usize;

        if len == 0 {
            return Ok(offset + 1);
        }

        // Compression pointer
        if len & 0xC0 == 0xC0 {
            return Ok(offset + 2);
        }

        offset += 1 + len;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base32_roundtrip() {
        let data = b"Hello, World!";
        let encoded = base32_encode(data);
        let decoded = base32_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_base32_encode() {
        let encoded = base32_encode(b"test");
        assert_eq!(encoded, "orsxg5a");
    }

    #[test]
    fn test_base32_empty() {
        let encoded = base32_encode(b"");
        assert_eq!(encoded, "");
        let decoded = base32_decode("").unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_dns_labels() {
        // Build a DNS name: "test.example.com\0"
        let mut name = Vec::new();
        name.push(4);
        name.extend_from_slice(b"test");
        name.push(7);
        name.extend_from_slice(b"example");
        name.push(3);
        name.extend_from_slice(b"com");
        name.push(0);

        let labels = parse_dns_labels(&name).unwrap();
        assert_eq!(labels, vec!["test", "example", "com"]);
    }
}
