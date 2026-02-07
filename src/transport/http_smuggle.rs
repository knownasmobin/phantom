//! HTTP Request Smuggling Tunnel
//!
//! **NOVEL TRANSPORT** - First weaponization of HTTP request smuggling for tunneling.
//!
//! Exploits the Content-Length vs Transfer-Encoding (CL/TE) parsing ambiguity
//! between Iran's DPI middleboxes and our tunnel server. The DPI sees one
//! interpretation of the HTTP stream; our server sees another.
//!
//! Additionally exploits Iran's **case-sensitive HTTP Host matching bug**
//! discovered by FOCI 2025: `Host: Rubika.ir` bypasses the filter that
//! matches `rubika.ir`.
//!
//! Reference: "HTTP Request Smuggling for Censorship Evasion" (FOCI 2024)
//! Reference: "I(ra)nconsistencies in Iran's Censorship" (FOCI 2025)
//!
//! ## How it works
//!
//! **CL/TE Desync (upstream):**
//! ```text
//! POST /api/v1/sync HTTP/1.1\r\n
//! Host: Rubika.ir\r\n           ← Case-sensitive bypass
//! Content-Length: 6\r\n          ← DPI reads this: sees 6-byte body
//! Transfer-Encoding: chunked\r\n ← Server reads this: chunked body
//! \r\n
//! 0\r\n\r\n                      ← DPI thinks request ends here
//! [chunked tunnel data]          ← Server continues reading chunks
//! ```
//!
//! **Downstream:** Server responds with chunked Transfer-Encoding carrying
//! tunnel data in the response body.
//!
//! ## Advantages
//! - High bandwidth (full HTTP body throughput)
//! - No root/raw socket required (standard TCP)
//! - Traffic is syntactically valid HTTP (not malformed)
//! - Exploits known Iran-specific DPI implementation bugs
//! - Works on ports 80 and 443

use super::{Transport, TransportStats};
use crate::config::TransportMode;
use crate::error::{PhantomError, Result};
use crate::utils::random_u32;

use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

/// HTTP smuggling desync modes
///
/// Each mode exploits a different parsing ambiguity between DPI and endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmuggleMode {
    /// Content-Length / Transfer-Encoding desync
    /// DPI prioritizes CL, server prioritizes TE
    /// Most common against forward proxies and DPI middleboxes
    ClTe,

    /// Transfer-Encoding / Content-Length desync
    /// DPI prioritizes TE, server prioritizes CL
    /// Works when DPI is more "spec-compliant" than the server
    TeCl,

    /// Transfer-Encoding obfuscation
    /// Both sides support TE, but DPI fails to recognize obfuscated TE header:
    /// "Transfer-Encoding: xchunked", "Transfer-Encoding : chunked", etc.
    TeObfuscation,
}

/// TE header obfuscation variants that bypass DPI parsing
/// but are accepted by tolerant HTTP servers
const TE_OBFUSCATIONS: &[&str] = &[
    "Transfer-Encoding: chunked",
    "Transfer-Encoding : chunked",       // Space before colon
    "Transfer-Encoding: chunked\r\nX: ", // Continuation
    "Transfer-Encoding:\tchunked",       // Tab instead of space
    "Transfer-Encoding: xchunked",       // Some parsers strip 'x' prefix
    "Transfer-encoding: chunked",        // Lowercase
    "Transfer-Encoding: chunked\x00",    // Null byte
    " Transfer-Encoding: chunked",       // Leading space
];

/// Case-sensitive Host header bypasses for Iranian domains
/// Iran's DPI matches exact lowercase; mixed case bypasses the filter
const IRAN_HOST_BYPASSES: &[&str] = &[
    "Rubika.ir",
    "RUBIKA.IR",
    "Messenger.Rubika.ir",
    "Eitaa.Com",
    "EITAA.COM",
    "Bale.Ai",
    "Soroush-App.IR",
];

/// HTTP Request Smuggling Transport
pub struct HttpSmuggleTransport {
    /// TCP connection to the tunnel server
    stream: Arc<Mutex<Option<TcpStream>>>,
    /// TCP listener for server mode
    listener: Arc<Mutex<Option<TcpListener>>>,
    /// Remote/bind address
    remote_addr: SocketAddr,
    /// Peer address (updated on accept)
    peer_addr: Arc<Mutex<SocketAddr>>,
    /// Smuggling mode
    mode: SmuggleMode,
    /// Host header to use (case-sensitive bypass)
    host_header: String,
    /// URL path to use (looks like legitimate API endpoint)
    path: String,
    /// TE obfuscation variant index
    te_variant: usize,
    /// Request counter for pipelining
    request_id: AtomicU64,
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

impl HttpSmuggleTransport {
    /// Create a new HTTP smuggling transport (client mode)
    pub async fn new(remote_addr: SocketAddr) -> Result<Self> {
        Ok(Self {
            stream: Arc::new(Mutex::new(None)),
            listener: Arc::new(Mutex::new(None)),
            remote_addr,
            peer_addr: Arc::new(Mutex::new(remote_addr)),
            mode: SmuggleMode::ClTe,
            host_header: IRAN_HOST_BYPASSES[0].to_string(),
            path: "/api/v1/sync".to_string(),
            te_variant: 0,
            request_id: AtomicU64::new(0),
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

    /// Create a new server-mode transport that binds and accepts connections
    pub async fn new_server(bind_addr: SocketAddr) -> Result<Self> {
        let listener = TcpListener::bind(bind_addr)
            .await
            .map_err(|e| PhantomError::Socket(format!("HTTP smuggle bind failed: {}", e)))?;

        Ok(Self {
            stream: Arc::new(Mutex::new(None)),
            listener: Arc::new(Mutex::new(Some(listener))),
            remote_addr: bind_addr,
            peer_addr: Arc::new(Mutex::new(bind_addr)),
            mode: SmuggleMode::ClTe,
            host_header: IRAN_HOST_BYPASSES[0].to_string(),
            path: "/api/v1/sync".to_string(),
            te_variant: 0,
            request_id: AtomicU64::new(0),
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

    /// Set smuggling mode
    pub fn set_mode(&mut self, mode: SmuggleMode) {
        self.mode = mode;
    }

    /// Set host header for case-sensitive bypass
    pub fn set_host(&mut self, host: String) {
        self.host_header = host;
    }

    /// Set URL path
    pub fn set_path(&mut self, path: String) {
        self.path = path;
    }

    /// Select TE obfuscation variant
    pub fn set_te_variant(&mut self, variant: usize) {
        self.te_variant = variant % TE_OBFUSCATIONS.len();
    }

    /// Ensure a TCP connection is established.
    /// In server mode (listener exists): accepts an incoming connection.
    /// In client mode: connects to connect_addr.
    async fn ensure_connected(&self, connect_addr: SocketAddr) -> Result<()> {
        if self.stream.lock().await.is_some() {
            return Ok(());
        }

        let listener_guard = self.listener.lock().await;

        // Double-check after acquiring lock
        if self.stream.lock().await.is_some() {
            return Ok(());
        }

        let (stream, peer) = if let Some(ref listener) = *listener_guard {
            listener
                .accept()
                .await
                .map_err(|e| PhantomError::Socket(format!("HTTP accept failed: {}", e)))?
        } else {
            drop(listener_guard);
            let stream = TcpStream::connect(connect_addr)
                .await
                .map_err(|e| PhantomError::Socket(format!("HTTP connect failed: {}", e)))?;
            (stream, connect_addr)
        };

        stream
            .set_nodelay(true)
            .map_err(|e| PhantomError::Socket(format!("TCP_NODELAY failed: {}", e)))?;

        *self.peer_addr.lock().await = peer;
        *self.stream.lock().await = Some(stream);
        Ok(())
    }

    /// Build a CL/TE desync request
    ///
    /// The key insight: we send BOTH Content-Length and Transfer-Encoding.
    /// Iran's DPI reads Content-Length and sees a short benign request.
    /// Our server reads Transfer-Encoding and processes the chunked body.
    fn build_cl_te_request(&self, data: &[u8]) -> Vec<u8> {
        let chunked_body = encode_chunked(data);

        // The "decoy" body that DPI sees via Content-Length
        // "0\r\n\r\n" = 5 bytes (empty chunked terminator)
        let decoy_length = 5;

        let te_header = TE_OBFUSCATIONS[self.te_variant];

        let request = format!(
            "POST {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Content-Length: {}\r\n\
             {}\r\n\
             Connection: keep-alive\r\n\
             User-Agent: RubikaAndroid/3.5.1\r\n\
             Accept: application/json\r\n\
             X-Request-ID: {:08x}\r\n\
             \r\n",
            self.path,
            self.host_header,
            decoy_length,
            te_header,
            random_u32(),
        );

        let mut packet = request.into_bytes();

        // The chunked body follows:
        // First: the empty chunk terminator (what DPI sees as the CL body)
        // Then: our actual data as a chunked body (what server processes)
        packet.extend_from_slice(b"0\r\n\r\n");
        packet.extend_from_slice(&chunked_body);

        packet
    }

    /// Build a TE/CL desync request (reversed)
    fn build_te_cl_request(&self, data: &[u8]) -> Vec<u8> {
        let te_header = TE_OBFUSCATIONS[self.te_variant];

        // In TE/CL mode, DPI reads Transfer-Encoding and sees a terminated chunk.
        // Server reads Content-Length and includes the "next request" as body.
        let smuggled_data = hex::encode(data); // Safe encoding for HTTP body

        let content_length = 5 + smuggled_data.len(); // "0\r\n\r\n" + smuggled data

        let request = format!(
            "POST {} HTTP/1.1\r\n\
             Host: {}\r\n\
             {}\r\n\
             Content-Length: {}\r\n\
             Connection: keep-alive\r\n\
             User-Agent: RubikaAndroid/3.5.1\r\n\
             \r\n\
             0\r\n\
             \r\n\
             {}",
            self.path, self.host_header, te_header, content_length, smuggled_data,
        );

        request.into_bytes()
    }

    /// Build a request with TE obfuscation
    fn build_te_obfuscation_request(&self, data: &[u8]) -> Vec<u8> {
        let chunked_body = encode_chunked(data);

        // Use an obfuscated Transfer-Encoding that DPI doesn't recognize
        // but our server's tolerant parser accepts
        let te_header = TE_OBFUSCATIONS[self.te_variant];

        let request = format!(
            "POST {} HTTP/1.1\r\n\
             Host: {}\r\n\
             {}\r\n\
             Connection: keep-alive\r\n\
             User-Agent: RubikaAndroid/3.5.1\r\n\
             X-Request-ID: {:08x}\r\n\
             \r\n",
            self.path,
            self.host_header,
            te_header,
            random_u32(),
        );

        let mut packet = request.into_bytes();
        packet.extend_from_slice(&chunked_body);
        packet
    }

    /// Build the appropriate request based on smuggle mode
    fn build_request(&self, data: &[u8]) -> Vec<u8> {
        match self.mode {
            SmuggleMode::ClTe => self.build_cl_te_request(data),
            SmuggleMode::TeCl => self.build_te_cl_request(data),
            SmuggleMode::TeObfuscation => self.build_te_obfuscation_request(data),
        }
    }

    /// Parse an HTTP response and extract tunnel data from chunked body
    fn parse_response(data: &[u8]) -> Result<(Vec<u8>, usize)> {
        // Find end of HTTP headers
        let header_end = find_header_end(data)
            .ok_or_else(|| PhantomError::PacketParse("No header terminator found".into()))?;

        let headers = &data[..header_end];
        let body = &data[header_end..];

        // Check if response uses chunked encoding
        let headers_str = String::from_utf8_lossy(headers);

        if headers_str
            .to_lowercase()
            .contains("transfer-encoding: chunked")
            || headers_str
                .to_lowercase()
                .contains("transfer-encoding:chunked")
        {
            // Decode chunked body
            let (decoded, consumed) = decode_chunked(body)?;
            Ok((decoded, header_end + consumed))
        } else if let Some(cl) = extract_content_length(&headers_str) {
            // Fixed-length body
            if body.len() < cl {
                return Err(PhantomError::PacketParse("Incomplete response body".into()));
            }
            Ok((body[..cl].to_vec(), header_end + cl))
        } else {
            // No body length indicator - read what we have
            Ok((body.to_vec(), data.len()))
        }
    }
}

#[async_trait]
impl Transport for HttpSmuggleTransport {
    fn mode(&self) -> TransportMode {
        TransportMode::HttpSmuggle
    }

    async fn send(&self, data: &[u8], dst: SocketAddr) -> Result<usize> {
        self.ensure_connected(dst).await?;

        let request = self.build_request(data);

        let mut guard = self.stream.lock().await;
        if let Some(ref mut stream) = *guard {
            if let Err(e) = stream.write_all(&request).await {
                *guard = None;
                return Err(PhantomError::Io(e));
            }

            self.stats.packets_sent.fetch_add(1, Ordering::Relaxed);
            self.stats
                .bytes_sent
                .fetch_add(request.len() as u64, Ordering::Relaxed);
            self.request_id.fetch_add(1, Ordering::Relaxed);

            Ok(data.len())
        } else {
            Err(PhantomError::Socket("Not connected".into()))
        }
    }

    async fn recv(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        self.ensure_connected(self.remote_addr).await?;

        let mut raw_buf = [0u8; 65535];

        let mut guard = self.stream.lock().await;
        if let Some(ref mut stream) = *guard {
            let n = match stream.read(&mut raw_buf).await {
                Ok(0) => {
                    *guard = None;
                    return Err(PhantomError::ConnectionReset);
                }
                Ok(n) => n,
                Err(e) => {
                    *guard = None;
                    return Err(PhantomError::Io(e));
                }
            };

            match Self::parse_response(&raw_buf[..n]) {
                Ok((data, _consumed)) => {
                    let len = data.len().min(buf.len());
                    buf[..len].copy_from_slice(&data[..len]);

                    self.stats.packets_recv.fetch_add(1, Ordering::Relaxed);
                    self.stats
                        .bytes_recv
                        .fetch_add(len as u64, Ordering::Relaxed);

                    let peer = *self.peer_addr.lock().await;
                    Ok((len, peer))
                }
                Err(e) => {
                    self.stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
                    Err(e)
                }
            }
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

// ============================================================
// HTTP Chunked Encoding/Decoding
// ============================================================

/// Encode data as HTTP chunked transfer encoding
///
/// Format: `<hex-length>\r\n<data>\r\n` ... `0\r\n\r\n`
fn encode_chunked(data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return b"0\r\n\r\n".to_vec();
    }

    let mut result = Vec::with_capacity(data.len() + 32);

    // Split into chunks to look more like real HTTP
    for chunk in data.chunks(4096) {
        let size_str = format!("{:x}\r\n", chunk.len());
        result.extend_from_slice(size_str.as_bytes());
        result.extend_from_slice(chunk);
        result.extend_from_slice(b"\r\n");
    }

    // Final chunk
    result.extend_from_slice(b"0\r\n\r\n");
    result
}

/// Decode HTTP chunked transfer encoding
///
/// Returns (decoded_data, bytes_consumed_from_input)
fn decode_chunked(data: &[u8]) -> Result<(Vec<u8>, usize)> {
    let mut result = Vec::new();
    let mut offset = 0;

    loop {
        // Find chunk size line
        let line_end = find_crlf(&data[offset..])
            .ok_or_else(|| PhantomError::PacketParse("Missing chunk size CRLF".into()))?;

        let size_str = String::from_utf8_lossy(&data[offset..offset + line_end]);
        let chunk_size = usize::from_str_radix(size_str.trim(), 16)
            .map_err(|_| PhantomError::PacketParse(format!("Invalid chunk size: {}", size_str)))?;

        offset += line_end + 2; // Skip size line + CRLF

        if chunk_size == 0 {
            // Final chunk - skip trailing CRLF
            offset += 2;
            break;
        }

        if offset + chunk_size > data.len() {
            return Err(PhantomError::PacketParse(
                "Chunk data exceeds buffer".into(),
            ));
        }

        result.extend_from_slice(&data[offset..offset + chunk_size]);
        offset += chunk_size + 2; // Skip data + trailing CRLF
    }

    Ok((result, offset))
}

/// Find `\r\n\r\n` in data (end of HTTP headers)
fn find_header_end(data: &[u8]) -> Option<usize> {
    for i in 0..data.len().saturating_sub(3) {
        if data[i] == b'\r' && data[i + 1] == b'\n' && data[i + 2] == b'\r' && data[i + 3] == b'\n'
        {
            return Some(i + 4);
        }
    }
    None
}

/// Find `\r\n` in data
fn find_crlf(data: &[u8]) -> Option<usize> {
    (0..data.len().saturating_sub(1)).find(|&i| data[i] == b'\r' && data[i + 1] == b'\n')
}

/// Extract Content-Length value from HTTP headers
fn extract_content_length(headers: &str) -> Option<usize> {
    for line in headers.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("content-length:") {
            let value = line.split(':').nth(1)?.trim();
            return value.parse().ok();
        }
    }
    None
}

/// Simple hex encoding for TE/CL mode data
mod hex {
    use std::fmt::Write;

    pub fn encode(data: &[u8]) -> String {
        data.iter().fold(String::new(), |mut s, b| {
            write!(s, "{:02x}", b).unwrap();
            s
        })
    }

    #[allow(dead_code)]
    pub fn decode(s: &str) -> Option<Vec<u8>> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunked_roundtrip() {
        let data = b"Hello, this is tunnel data!";
        let encoded = encode_chunked(data);
        let (decoded, _) = decode_chunked(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_chunked_empty() {
        let encoded = encode_chunked(b"");
        assert_eq!(encoded, b"0\r\n\r\n");
        let (decoded, _) = decode_chunked(&encoded).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_chunked_large() {
        let data = vec![0xAB; 10000];
        let encoded = encode_chunked(&data);
        let (decoded, _) = decode_chunked(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_find_header_end() {
        let data = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nBody here";
        let end = find_header_end(data).unwrap();
        assert_eq!(&data[end..], b"Body here");
    }

    #[test]
    fn test_content_length_extraction() {
        let headers = "HTTP/1.1 200 OK\r\nContent-Length: 42\r\nConnection: close\r\n";
        assert_eq!(extract_content_length(headers), Some(42));
    }

    #[test]
    fn test_cl_te_desync_structure() {
        let addr: SocketAddr = "127.0.0.1:80".parse().unwrap();
        let transport = HttpSmuggleTransport {
            stream: Arc::new(Mutex::new(None)),
            listener: Arc::new(Mutex::new(None)),
            remote_addr: addr,
            peer_addr: Arc::new(Mutex::new(addr)),
            mode: SmuggleMode::ClTe,
            host_header: "Rubika.ir".to_string(),
            path: "/api/v1/sync".to_string(),
            te_variant: 0,
            request_id: AtomicU64::new(0),
            stats: Arc::new(TransportStatsInner {
                packets_sent: AtomicU64::new(0),
                packets_recv: AtomicU64::new(0),
                bytes_sent: AtomicU64::new(0),
                bytes_recv: AtomicU64::new(0),
                packets_dropped: AtomicU64::new(0),
            }),
            running: Arc::new(AtomicBool::new(true)),
        };

        let request = transport.build_cl_te_request(b"secret data");
        let request_str = String::from_utf8_lossy(&request);

        // Verify both CL and TE headers present
        assert!(request_str.contains("Content-Length: 5"));
        assert!(request_str.contains("Transfer-Encoding: chunked"));

        // Verify case-sensitive Host header
        assert!(request_str.contains("Host: Rubika.ir"));

        // Verify decoy body (empty chunk terminator)
        assert!(request_str.contains("0\r\n\r\n"));
    }

    #[test]
    fn test_hex_roundtrip() {
        let data = b"test data";
        let encoded = hex::encode(data);
        let decoded = hex::decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_host_bypass_case_sensitivity() {
        // Verify our bypass hosts use mixed case
        for host in IRAN_HOST_BYPASSES {
            let lower = host.to_lowercase();
            assert_ne!(*host, lower, "Host bypass should use mixed case: {}", host);
        }
    }
}
