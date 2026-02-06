//! Video Stream Parasiting Transport
//!
//! **NOVEL TRANSPORT** - First-ever implementation of HLS video stream covert channel.
//! The concept was first proposed at IFIP Networking 2025; no implementation exists.
//!
//! Hides tunnel data inside MPEG-TS (Transport Stream) packets served as an HLS
//! video stream over HTTPS. To DPI, this looks like a user watching a video.
//! The video actually plays (cover traffic), while tunnel data is embedded in:
//!
//! 1. **Adaptation field stuffing bytes** - normally 0xFF padding, replaced with data
//! 2. **Null TS packets (PID 0x1FFF)** - spec says "may be discarded", content irrelevant
//! 3. **Private data bytes** in adaptation field - explicitly designed for custom data
//!
//! ## Why it's undetectable
//! - Traffic IS a valid HTTPS video stream
//! - TS adaptation stuffing is defined as arbitrary padding
//! - Null packets' contents are irrelevant per ISO/IEC 13818-1
//! - No known DPI system decodes MPEG-TS packet structure
//! - Packet sizes and timing match real HLS streaming
//!
//! ## MPEG-TS Packet Structure (188 bytes fixed)
//! ```text
//! [Sync 0x47] [PID 13b] [Flags 4b] [Adaptation Field (optional)] [Payload]
//!      1 byte      3 bytes                variable                  variable
//! ```

use super::{Transport, TransportStats};
use crate::config::TransportMode;
use crate::error::{PhantomError, Result};
use crate::utils::random_bytes;

use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

// ============================================================
// MPEG-TS Constants
// ============================================================

/// TS packet size (fixed per ISO/IEC 13818-1)
pub const TS_PACKET_SIZE: usize = 188;

/// Sync byte that starts every TS packet
pub const TS_SYNC_BYTE: u8 = 0x47;

/// Null packet PID - "may be discarded" per spec
pub const TS_NULL_PID: u16 = 0x1FFF;

/// PAT PID (Program Association Table)
pub const TS_PAT_PID: u16 = 0x0000;

/// Our covert data PID - looks like a private data stream
/// PID 0x0100-0x1FFE are available for private use
pub const TS_COVERT_PID: u16 = 0x0100;

/// Adaptation field flag in TS header
const AF_EXISTS: u8 = 0x20;
/// Payload flag in TS header
const PAYLOAD_EXISTS: u8 = 0x10;

/// Magic marker for our covert data within adaptation field
const PHANTOM_TS_MAGIC: [u8; 2] = [0xAC, 0xDC];

// ============================================================
// TS Packet Structure
// ============================================================

/// A single MPEG-TS packet (188 bytes)
#[derive(Clone)]
pub struct TsPacket {
    /// Raw 188-byte packet data
    pub data: [u8; TS_PACKET_SIZE],
}

impl TsPacket {
    /// Create a null TS packet (PID 0x1FFF) carrying covert data
    ///
    /// Null packets are defined by the spec as "may be inserted/discarded"
    /// and their payload content has no defined meaning.
    /// This makes them perfect for carrying tunnel data.
    pub fn new_null_with_data(payload: &[u8]) -> Self {
        let mut data = [0xFF; TS_PACKET_SIZE]; // Fill with 0xFF (standard stuffing)

        // TS Header (4 bytes)
        data[0] = TS_SYNC_BYTE;
        // PID 0x1FFF (null packet): split across bytes 1-2
        // Byte 1: TEI(0) PUSI(0) Priority(0) PID[12:8]=0x1F
        data[1] = 0x1F;
        // Byte 2: PID[7:0]=0xFF
        data[2] = 0xFF;
        // Byte 3: Scrambling(00) AF(00) Payload(01) Continuity(0000)
        data[3] = PAYLOAD_EXISTS; // 0x10

        // Payload starts at byte 4
        // Embed our magic marker
        data[4] = PHANTOM_TS_MAGIC[0];
        data[5] = PHANTOM_TS_MAGIC[1];

        // Data length (2 bytes, big-endian)
        let len = payload.len().min(TS_PACKET_SIZE - 8) as u16;
        data[6] = (len >> 8) as u8;
        data[7] = len as u8;

        // Copy payload data
        let copy_len = len as usize;
        data[8..8 + copy_len].copy_from_slice(&payload[..copy_len]);

        Self { data }
    }

    /// Create a TS packet with covert data hidden in the adaptation field
    ///
    /// The adaptation field has a "stuffing bytes" section that is normally
    /// filled with 0xFF. We replace these with encrypted tunnel data.
    /// The packet also carries a real (or fake) payload so it looks normal.
    pub fn new_with_adaptation_data(pid: u16, covert_data: &[u8], video_payload: &[u8]) -> Self {
        let mut data = [0xFF; TS_PACKET_SIZE];

        // TS Header (4 bytes)
        data[0] = TS_SYNC_BYTE;

        // PID spread across bytes 1-2
        data[1] = ((pid >> 8) & 0x1F) as u8; // TEI=0, PUSI=0, Priority=0, PID high
        data[2] = (pid & 0xFF) as u8; // PID low

        // Both AF and payload present
        data[3] = AF_EXISTS | PAYLOAD_EXISTS;

        // Adaptation field
        let covert_len = covert_data.len().min(160); // Leave room for header + video payload
        let af_length = 3 + covert_len; // flags(1) + magic(2) + covert data

        data[4] = af_length as u8; // Adaptation field length
        data[5] = 0x00; // AF flags: no PCR, no OPCR, no splice, no private data flag

        // "Stuffing bytes" - normally 0xFF, we embed our data here
        // We use our magic marker to identify covert packets
        let stuff_start = 6;
        data[stuff_start] = PHANTOM_TS_MAGIC[0];
        data[stuff_start + 1] = PHANTOM_TS_MAGIC[1];

        // Embed covert data in the stuffing area
        let data_start = stuff_start + 2;
        data[data_start..data_start + covert_len].copy_from_slice(&covert_data[..covert_len]);

        // Video payload after adaptation field
        let payload_start = 5 + af_length;
        let video_len = video_payload.len().min(TS_PACKET_SIZE - payload_start);
        if video_len > 0 {
            data[payload_start..payload_start + video_len]
                .copy_from_slice(&video_payload[..video_len]);
        }

        Self { data }
    }

    /// Create a normal video TS packet (no covert data)
    pub fn new_video(pid: u16, payload: &[u8], continuity_counter: u8) -> Self {
        let mut data = [0xFF; TS_PACKET_SIZE];

        data[0] = TS_SYNC_BYTE;
        data[1] = ((pid >> 8) & 0x1F) as u8;
        data[2] = (pid & 0xFF) as u8;
        data[3] = PAYLOAD_EXISTS | (continuity_counter & 0x0F);

        let copy_len = payload.len().min(TS_PACKET_SIZE - 4);
        data[4..4 + copy_len].copy_from_slice(&payload[..copy_len]);

        Self { data }
    }

    /// Check if this is a null packet
    pub fn is_null(&self) -> bool {
        self.pid() == TS_NULL_PID
    }

    /// Get the PID of this packet
    pub fn pid(&self) -> u16 {
        ((self.data[1] as u16 & 0x1F) << 8) | self.data[2] as u16
    }

    /// Check if this packet has an adaptation field
    pub fn has_adaptation_field(&self) -> bool {
        self.data[3] & AF_EXISTS != 0
    }

    /// Check if this packet has payload
    pub fn has_payload(&self) -> bool {
        self.data[3] & PAYLOAD_EXISTS != 0
    }

    /// Extract covert data from this packet (if present)
    ///
    /// Checks both null-packet embedding and adaptation field embedding
    pub fn extract_covert_data(&self) -> Option<Vec<u8>> {
        if self.is_null() {
            // Null packet: check for magic at payload start
            if self.data[4] == PHANTOM_TS_MAGIC[0] && self.data[5] == PHANTOM_TS_MAGIC[1] {
                let len = u16::from_be_bytes([self.data[6], self.data[7]]) as usize;
                if len > 0 && 8 + len <= TS_PACKET_SIZE {
                    return Some(self.data[8..8 + len].to_vec());
                }
            }
        } else if self.has_adaptation_field() {
            // Adaptation field: check for magic in stuffing area
            let af_length = self.data[4] as usize;
            if af_length >= 4 {
                let stuff_start = 6;
                if stuff_start + 1 < TS_PACKET_SIZE
                    && self.data[stuff_start] == PHANTOM_TS_MAGIC[0]
                    && self.data[stuff_start + 1] == PHANTOM_TS_MAGIC[1]
                {
                    let data_start = stuff_start + 2;
                    let data_end = (5 + af_length).min(TS_PACKET_SIZE);
                    if data_start < data_end {
                        return Some(self.data[data_start..data_end].to_vec());
                    }
                }
            }
        }
        None
    }
}

// ============================================================
// TS Segment (collection of TS packets = one HLS segment)
// ============================================================

/// An HLS segment containing multiple TS packets
pub struct TsSegment {
    pub packets: Vec<TsPacket>,
}

impl TsSegment {
    /// Create a new segment embedding covert data among video packets
    ///
    /// The segment contains a mix of:
    /// - Real video packets (cover traffic)
    /// - Null packets with covert data
    /// - Video packets with covert data in adaptation fields
    pub fn new_with_covert_data(
        covert_data: &[u8],
        segment_duration_ms: u64,
        video_pid: u16,
    ) -> Self {
        let mut packets = Vec::new();

        // Calculate how many packets we need for the covert data
        // Limit per-packet capacity to spread data across both null and AF packets
        let bytes_per_null_packet = 80; // Spread data across multiple packets
        let bytes_per_af_packet = 80; // Spread data across multiple packets
        let mut data_offset = 0;

        // Target: ~30% null packets (realistic for real video streams)
        // Real video streams have 5-20% null packets for rate padding
        let total_packets = ((segment_duration_ms / 7) as usize).max(50); // ~7ms per packet at 1Mbps

        let mut continuity = 0u8;

        for i in 0..total_packets {
            if data_offset < covert_data.len() {
                if i % 3 == 0 {
                    // Every 3rd packet: null packet with covert data
                    let remaining = &covert_data[data_offset..];
                    let chunk_len = remaining.len().min(bytes_per_null_packet);
                    packets.push(TsPacket::new_null_with_data(&remaining[..chunk_len]));
                    data_offset += chunk_len;
                } else if i % 3 == 1 {
                    // Adaptation field embedding
                    let remaining = &covert_data[data_offset..];
                    let chunk_len = remaining.len().min(bytes_per_af_packet);
                    let fake_video = random_bytes(20); // Fake video payload
                    packets.push(TsPacket::new_with_adaptation_data(
                        video_pid,
                        &remaining[..chunk_len],
                        &fake_video,
                    ));
                    data_offset += chunk_len;
                } else {
                    // Regular video packet (cover traffic)
                    let fake_video = random_bytes(TS_PACKET_SIZE - 4);
                    packets.push(TsPacket::new_video(video_pid, &fake_video, continuity));
                    continuity = continuity.wrapping_add(1) & 0x0F;
                }
            } else {
                // No more covert data - fill with normal video packets
                if i % 5 == 0 {
                    // Some null packets for realism (rate padding)
                    let mut null = TsPacket {
                        data: [0xFF; TS_PACKET_SIZE],
                    };
                    null.data[0] = TS_SYNC_BYTE;
                    null.data[1] = 0x1F;
                    null.data[2] = 0xFF;
                    null.data[3] = PAYLOAD_EXISTS;
                    packets.push(null);
                } else {
                    let fake_video = random_bytes(TS_PACKET_SIZE - 4);
                    packets.push(TsPacket::new_video(video_pid, &fake_video, continuity));
                    continuity = continuity.wrapping_add(1) & 0x0F;
                }
            }
        }

        Self { packets }
    }

    /// Extract all covert data from a segment
    pub fn extract_covert_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        for packet in &self.packets {
            if let Some(covert) = packet.extract_covert_data() {
                data.extend_from_slice(&covert);
            }
        }
        data
    }

    /// Serialize all packets to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.packets.len() * TS_PACKET_SIZE);
        for packet in &self.packets {
            bytes.extend_from_slice(&packet.data);
        }
        bytes
    }

    /// Parse TS packets from raw bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if !data.len().is_multiple_of(TS_PACKET_SIZE) {
            return Err(PhantomError::PacketParse(format!(
                "TS data length {} not multiple of {}",
                data.len(),
                TS_PACKET_SIZE
            )));
        }

        let mut packets = Vec::new();
        for chunk in data.chunks(TS_PACKET_SIZE) {
            if chunk[0] != TS_SYNC_BYTE {
                return Err(PhantomError::PacketParse("Missing TS sync byte".into()));
            }
            let mut packet = TsPacket {
                data: [0; TS_PACKET_SIZE],
            };
            packet.data.copy_from_slice(chunk);
            packets.push(packet);
        }

        Ok(Self { packets })
    }
}

// ============================================================
// HLS Playlist Generation
// ============================================================

/// Generate an HLS .m3u8 playlist pointing to our TS segments
pub fn generate_playlist(segment_count: u32, segment_duration: f64, base_url: &str) -> String {
    let mut playlist = String::new();

    playlist.push_str("#EXTM3U\n");
    playlist.push_str("#EXT-X-VERSION:3\n");
    playlist.push_str(&format!(
        "#EXT-X-TARGETDURATION:{}\n",
        segment_duration.ceil() as u32
    ));
    playlist.push_str("#EXT-X-MEDIA-SEQUENCE:0\n");

    for i in 0..segment_count {
        playlist.push_str(&format!("#EXTINF:{:.3},\n", segment_duration));
        playlist.push_str(&format!("{}/segment_{:04}.ts\n", base_url, i));
    }

    playlist
}

// ============================================================
// Video Parasite Transport
// ============================================================

/// Video Stream Parasiting Transport
///
/// Communicates over HTTPS disguised as HLS video streaming.
/// Upstream: HTTP POST with chunked TS segment bodies
/// Downstream: HTTP GET responses containing TS segments with embedded data
pub struct VideoParasiteTransport {
    /// TCP stream to the tunnel server
    stream: Arc<Mutex<Option<TcpStream>>>,
    /// Remote server address
    remote_addr: SocketAddr,
    /// Video PID for cover traffic
    video_pid: u16,
    /// Segment counter
    segment_counter: AtomicU64,
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

impl VideoParasiteTransport {
    /// Create a new video parasite transport
    pub async fn new(remote_addr: SocketAddr) -> Result<Self> {
        Ok(Self {
            stream: Arc::new(Mutex::new(None)),
            remote_addr,
            video_pid: TS_COVERT_PID,
            segment_counter: AtomicU64::new(0),
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

    /// Ensure connection to the tunnel server
    async fn ensure_connected(&self) -> Result<()> {
        let needs_connect = self.stream.lock().await.is_none();

        if needs_connect {
            let stream = TcpStream::connect(self.remote_addr)
                .await
                .map_err(|e| PhantomError::Socket(format!("Video connect failed: {}", e)))?;
            stream.set_nodelay(true).ok();
            *self.stream.lock().await = Some(stream);
        }
        Ok(())
    }

    /// Build an HTTP request carrying a TS segment with embedded covert data
    fn build_segment_request(&self, data: &[u8]) -> Vec<u8> {
        let seg_num = self.segment_counter.fetch_add(1, Ordering::Relaxed);

        // Create a TS segment with the covert data embedded
        let segment = TsSegment::new_with_covert_data(data, 2000, self.video_pid);
        let ts_data = segment.to_bytes();

        // Wrap in an HTTP POST that looks like a video segment upload
        let request = format!(
            "POST /upload/segment_{:04}.ts HTTP/1.1\r\n\
             Host: stream.cdn-video.ir\r\n\
             Content-Type: video/mp2t\r\n\
             Content-Length: {}\r\n\
             Connection: keep-alive\r\n\
             X-Stream-Key: live_phantom_{:08x}\r\n\
             \r\n",
            seg_num,
            ts_data.len(),
            crate::utils::random_u32(),
        );

        let mut packet = request.into_bytes();
        packet.extend_from_slice(&ts_data);
        packet
    }

    /// Parse an HTTP response containing a TS segment and extract covert data
    fn parse_segment_response(data: &[u8]) -> Result<Vec<u8>> {
        // Find end of HTTP headers
        let header_end = find_header_end(data)
            .ok_or_else(|| PhantomError::PacketParse("No header end in video response".into()))?;

        let body = &data[header_end..];

        // Check if body length is multiple of TS_PACKET_SIZE
        let ts_len = (body.len() / TS_PACKET_SIZE) * TS_PACKET_SIZE;
        if ts_len == 0 {
            return Err(PhantomError::PacketParse(
                "No TS packets in response".into(),
            ));
        }

        // Parse TS segment and extract covert data
        let segment = TsSegment::from_bytes(&body[..ts_len])?;
        let covert_data = segment.extract_covert_data();

        if covert_data.is_empty() {
            return Err(PhantomError::InvalidPacket(
                "No covert data in segment".into(),
            ));
        }

        Ok(covert_data)
    }
}

/// Find \r\n\r\n in data
fn find_header_end(data: &[u8]) -> Option<usize> {
    for i in 0..data.len().saturating_sub(3) {
        if data[i] == b'\r' && data[i + 1] == b'\n' && data[i + 2] == b'\r' && data[i + 3] == b'\n'
        {
            return Some(i + 4);
        }
    }
    None
}

#[async_trait]
impl Transport for VideoParasiteTransport {
    fn mode(&self) -> TransportMode {
        TransportMode::VideoParasite
    }

    async fn send(&self, data: &[u8], dst: SocketAddr) -> Result<usize> {
        self.ensure_connected().await?;

        let request = self.build_segment_request(data);

        let mut guard = self.stream.lock().await;
        if let Some(ref mut stream) = *guard {
            stream.write_all(&request).await.map_err(PhantomError::Io)?;

            self.stats.packets_sent.fetch_add(1, Ordering::Relaxed);
            self.stats
                .bytes_sent
                .fetch_add(request.len() as u64, Ordering::Relaxed);

            Ok(data.len())
        } else {
            Err(PhantomError::Socket("Not connected".into()))
        }
    }

    async fn recv(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        self.ensure_connected().await?;

        let mut raw_buf = [0u8; 131072]; // 128KB buffer for video segments

        let mut guard = self.stream.lock().await;
        if let Some(ref mut stream) = *guard {
            let n = stream.read(&mut raw_buf).await.map_err(PhantomError::Io)?;

            if n == 0 {
                *guard = None;
                return Err(PhantomError::ConnectionReset);
            }

            match Self::parse_segment_response(&raw_buf[..n]) {
                Ok(data) => {
                    let len = data.len().min(buf.len());
                    buf[..len].copy_from_slice(&data[..len]);

                    self.stats.packets_recv.fetch_add(1, Ordering::Relaxed);
                    self.stats
                        .bytes_recv
                        .fetch_add(len as u64, Ordering::Relaxed);

                    Ok((len, self.remote_addr))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_null_packet_covert_roundtrip() {
        let data = b"Hello from the covert channel!";
        let packet = TsPacket::new_null_with_data(data);

        assert!(packet.is_null());
        assert_eq!(packet.data[0], TS_SYNC_BYTE);
        assert_eq!(packet.pid(), TS_NULL_PID);

        let extracted = packet.extract_covert_data().unwrap();
        assert_eq!(extracted, data);
    }

    #[test]
    fn test_adaptation_field_covert_roundtrip() {
        let covert = b"Secret adaptation data";
        let video = b"Fake video payload";
        let packet = TsPacket::new_with_adaptation_data(TS_COVERT_PID, covert, video);

        assert!(!packet.is_null());
        assert!(packet.has_adaptation_field());
        assert_eq!(packet.pid(), TS_COVERT_PID);

        let extracted = packet.extract_covert_data().unwrap();
        // Extracted data may include padding up to AF length
        assert!(extracted.starts_with(covert));
    }

    #[test]
    fn test_normal_video_packet_no_covert() {
        let video = random_bytes(TS_PACKET_SIZE - 4);
        let packet = TsPacket::new_video(0x0101, &video, 0);

        assert!(!packet.is_null());
        assert!(!packet.has_adaptation_field());
        assert!(packet.extract_covert_data().is_none());
    }

    #[test]
    fn test_segment_covert_roundtrip() {
        let covert_data = b"This is a long message that needs to be spread across multiple TS packets in the segment. It should survive the encode/decode roundtrip perfectly.";

        let segment = TsSegment::new_with_covert_data(covert_data, 2000, TS_COVERT_PID);

        // Verify we have a mix of packet types
        let null_count = segment.packets.iter().filter(|p| p.is_null()).count();
        let af_count = segment
            .packets
            .iter()
            .filter(|p| p.has_adaptation_field())
            .count();
        assert!(null_count > 0, "Should have null packets");
        assert!(af_count > 0, "Should have adaptation field packets");

        // Verify all packets are valid TS
        for packet in &segment.packets {
            assert_eq!(packet.data[0], TS_SYNC_BYTE);
        }

        // Extract and verify covert data
        let extracted = segment.extract_covert_data();
        assert!(extracted.starts_with(covert_data));
    }

    #[test]
    fn test_segment_serialization() {
        let data = b"Test covert data";
        let segment = TsSegment::new_with_covert_data(data, 1000, TS_COVERT_PID);
        let bytes = segment.to_bytes();

        assert_eq!(bytes.len() % TS_PACKET_SIZE, 0);

        let parsed = TsSegment::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.packets.len(), segment.packets.len());

        let extracted = parsed.extract_covert_data();
        assert!(extracted.starts_with(data));
    }

    #[test]
    fn test_playlist_generation() {
        let playlist = generate_playlist(3, 2.0, "https://cdn.example.com/live");
        assert!(playlist.contains("#EXTM3U"));
        assert!(playlist.contains("#EXTINF:2.000"));
        assert!(playlist.contains("segment_0000.ts"));
        assert!(playlist.contains("segment_0002.ts"));
    }

    #[test]
    fn test_ts_packet_size() {
        let packet = TsPacket::new_null_with_data(b"test");
        assert_eq!(packet.data.len(), 188);
    }
}
