# Phantom - Adaptive State-Masquerade Tunnel (ASMT)

A censorship circumvention tool designed to bypass Deep Packet Inspection (DPI) systems, specifically targeting Iran's GFW (Great Firewall). Phantom uses multiple evasion techniques including protocol masquerading, TLS fingerprint mimicry, and stateful DPI exploitation.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Design Decisions](#design-decisions)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Transport Modes](#transport-modes)
- [Geneva Strategies](#geneva-strategies)
- [Security](#security)
- [Technical Details](#technical-details)
- [Troubleshooting](#troubleshooting)
- [License](#license)

## Overview

Phantom implements the ASMT (Adaptive State-Masquerade Tunnel) architecture, which combines multiple bypass techniques:

1. **Protocol Masquerading**: Tunnels data through protocols that are whitelisted by DPI systems
2. **TLS Fingerprint Mimicry**: Generates ClientHello messages that match legitimate Iranian apps (Rubika, Eitaa)
3. **Geneva Engine**: Exploits stateful DPI middlebox vulnerabilities through packet manipulation
4. **Transport Agility**: Dynamically switches between transport modes when one is blocked
5. **Forward Error Correction**: Recovers from packet loss without retransmission

### Why It Works

Iran's GFW operates on a "default-deny" model for unknown protocols but has several blind spots:

| Bypass Method | Reason |
|---------------|--------|
| FakeTCP | Kernel bypass prevents RST injection from affecting connections |
| Protocol 115 | L2TPv3 infrastructure protocol not inspected |
| ICMP | Diagnostic necessity - blocking would break network troubleshooting |
| DNS Tunnel | DNS is required for all internet access - never blocked |
| QUIC Masquerade | UDP:443 traffic mimics HTTP/3 - blocking breaks YouTube/Google |
| GRE | Infrastructure protocol for enterprise VPN trunks |
| Domestic App Fronting | SNI matching whitelisted Iranian services bypasses TLS inspection |

## Features

- **Multiple Transport Modes (9 modes, 3 novel inventions)**
  - FakeTCP: Raw socket TCP-like protocol with kernel bypass
  - Protocol 115: L2TPv3-style tunneling through unmonitored IP protocol
  - ICMP: Echo request/reply tunneling
  - DNS Tunnel: Data encoded in DNS queries/TXT responses (always whitelisted)
  - QUIC Masquerade: UDP:443 with QUIC Initial packet mimicry (no root needed)
  - GRE: Generic Routing Encapsulation (IP Protocol 47, enterprise blind spot)
  - **HTTP Smuggle** (novel): CL/TE desync exploiting DPI parsing bugs + Iran's case-sensitive Host matching
  - **Video Parasite** (novel): Covert data in HLS/MPEG-TS packets - first implementation ever
  - **Proto Morph** (novel): Session-unique wire format derived from shared key - no fingerprint possible

- **DPI Evasion (Geneva Engine)**
  - TCP Segmentation: Splits packets to evade signature matching
  - Checksum Poisoning: Sends packets with bad checksums (dropped by DPI, accepted by endpoint)
  - TTL Expiry: Packets expire at DPI but reach destination
  - Duplicate ACKs: Confuses DPI state tracking
  - FIN-before-SYN: Breaks DPI connection state machines
  - RST with Short TTL: Fake connection teardown
  - Out-of-Order Delivery: Reorders packets to evade sequential matching

- **Cryptography**
  - Noise Protocol IK pattern for authenticated key exchange
  - X25519 for key agreement
  - XChaCha20-Poly1305 for symmetric encryption (avoids AES fingerprinting)
  - Blake2 for hashing

- **TLS Mimicry**
  - Generates ClientHello matching Rubika/Eitaa Android apps
  - JA3/JA4 fingerprint validation
  - SNI spoofing to whitelisted domains

- **Reliability**
  - Reed-Solomon Forward Error Correction
  - Automatic transport failover
  - Connection state recovery

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Application                              │
│                      (SOCKS5 Proxy)                              │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                       Phantom Tunnel                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
│  │   Noise     │  │    FEC      │  │   Geneva Engine         │  │
│  │  Protocol   │  │  Encoder    │  │  (DPI Evasion)          │  │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                Transport Layer (9 modes, 3 novel)                │
│  ┌───────────┐  ┌───────────────┐  ┌─────────────────────────┐  │
│  │  FakeTCP  │  │  Protocol 115 │  │        ICMP             │  │
│  │ (Raw Sock)│  │  (L2TPv3-like)│  │   (Echo Tunnel)         │  │
│  └───────────┘  └───────────────┘  └─────────────────────────┘  │
│  ┌───────────┐  ┌───────────────┐  ┌─────────────────────────┐  │
│  │    DNS    │  │ QUIC Masq     │  │        GRE              │  │
│  │ (UDP:53)  │  │  (UDP:443)    │  │   (IP Proto 47)         │  │
│  └───────────┘  └───────────────┘  └─────────────────────────┘  │
│  ╔═══════════╗  ╔═══════════════╗  ╔═════════════════════════╗  │
│  ║  HTTP     ║  ║ Video         ║  ║    Protocol Entropy     ║  │
│  ║ Smuggle*  ║  ║ Parasite*     ║  ║    Morphing*            ║  │
│  ╚═══════════╝  ╚═══════════════╝  ╚═════════════════════════╝  │
│  * = Novel Phantom inventions                                    │
└─────────────────────────────────────────────────────────────────┘
                              │
                    ┌─────────┴─────────┐
                    ▼                   ▼
┌──────────────────────────┐ ┌────────────────────────────────────┐
│     Raw IP Sockets       │ │        Standard UDP Sockets        │
│ (FakeTCP, Proto115,      │ │  (DNS, QUIC Masq - no root)       │
│  ICMP, GRE - root req.)  │ │                                    │
└──────────────────────────┘ └────────────────────────────────────┘
```

## Design Decisions

This section explains why specific technologies and approaches were chosen over alternatives.

### Why Rust?

| Consideration | Rust | Go | C/C++ | Python |
|---------------|------|-----|-------|--------|
| **Memory safety** | Compile-time guarantees | GC-managed | Manual (error-prone) | GC-managed |
| **Performance** | Near-C speed | Good, but GC pauses | Best possible | Too slow |
| **Binary size** | ~2-5MB static | ~10MB+ | Smallest | Requires runtime |
| **Async I/O** | Tokio (zero-cost) | Goroutines (good) | Manual/libuv | asyncio (overhead) |
| **Raw sockets** | socket2 crate | Possible but awkward | Native | Requires root + slow |
| **Cross-compile** | Excellent | Excellent | Complex | N/A |

**Decision**: Rust provides the best combination of:
- **Zero-cost abstractions** for packet manipulation without runtime overhead
- **Memory safety** critical for security-sensitive code handling untrusted network input
- **No garbage collector** means predictable latency (important for real-time tunnel)
- **Strong type system** catches protocol errors at compile time
- **Excellent async ecosystem** (Tokio) for handling thousands of concurrent connections

Go was considered but rejected due to GC pauses affecting latency and less precise control over memory layout for packet crafting. C was rejected due to memory safety concerns in security-critical code.

### Why XChaCha20-Poly1305 over AES-GCM?

| Cipher | Reason for/against |
|--------|-------------------|
| **AES-GCM** | ❌ Hardware AES-NI instructions create detectable timing patterns |
| **AES-GCM** | ❌ Most common cipher - easier to fingerprint as "encrypted tunnel" |
| **AES-GCM** | ❌ 96-bit nonce requires careful state management to avoid reuse |
| **ChaCha20-Poly1305** | ✅ Constant-time in software, no timing side-channels |
| **ChaCha20-Poly1305** | ✅ Less common, harder to fingerprint |
| **XChaCha20-Poly1305** | ✅ 192-bit nonce allows random nonce generation safely |
| **XChaCha20-Poly1305** | ✅ Extended nonce eliminates nonce-reuse catastrophe risk |

**Decision**: XChaCha20-Poly1305 provides:
- **No AES fingerprinting**: DPI systems often flag AES-GCM traffic patterns
- **Safe random nonces**: 192-bit nonce space makes collision probability negligible
- **Constant-time operations**: No timing attacks possible
- **Same security level**: 256-bit key, AEAD with 128-bit authentication tag

### Why Noise Protocol over TLS or Custom Crypto?

| Protocol | Consideration |
|----------|--------------|
| **TLS 1.3** | ❌ Complex state machine, many round-trips |
| **TLS 1.3** | ❌ Recognizable handshake pattern (even with ESNI) |
| **TLS 1.3** | ❌ Certificate management overhead |
| **Custom protocol** | ❌ Likely to have security vulnerabilities |
| **Custom protocol** | ❌ No formal security analysis |
| **Noise Protocol** | ✅ Formally verified security properties |
| **Noise Protocol** | ✅ Minimal round-trips (IK pattern = 0-RTT data) |
| **Noise Protocol** | ✅ Simple state machine, hard to get wrong |
| **Noise Protocol** | ✅ Built-in identity hiding and forward secrecy |

**Decision**: Noise Protocol IK pattern because:
- **0-RTT connection**: Client can send data immediately (critical for latency)
- **Mutual authentication**: Both parties verify each other's identity
- **Forward secrecy**: Ephemeral keys protect past sessions if long-term key compromised
- **No certificates**: Simple public key distribution, no PKI complexity
- **Proven security**: Formal verification by cryptographers, used by WireGuard, Signal, Lightning

### Why X25519 over RSA or P-256?

| Algorithm | Key Size | Performance | Security Concerns |
|-----------|----------|-------------|-------------------|
| **RSA-2048** | 2048 bits | Slow | Quantum-vulnerable, large keys |
| **RSA-4096** | 4096 bits | Very slow | Still quantum-vulnerable |
| **P-256 (NIST)** | 256 bits | Moderate | NSA involvement concerns, complex implementation |
| **X25519** | 256 bits | **Fastest** | Clean design, constant-time, no NSA involvement |

**Decision**: X25519 (Curve25519) provides:
- **Highest performance**: Fastest ECDH, critical for handshake speed
- **Constant-time by design**: Immune to timing attacks without special care
- **Simple implementation**: Hard to implement incorrectly
- **Strong security margin**: 128-bit security level, equivalent to RSA-3072
- **Trusted design**: Created by djb, no government involvement in curve selection

### Why Blake2 over SHA-256?

| Hash | Speed | Security | Usage |
|------|-------|----------|-------|
| **SHA-256** | Baseline | 128-bit | Most common, more recognizable |
| **SHA-3** | Slower | 128-bit | Overkill, slower in software |
| **Blake2s** | **1.5x faster** | 128-bit | Optimized for 32-bit |
| **Blake2b** | **1.3x faster** | 256-bit | Optimized for 64-bit |

**Decision**: Blake2 because:
- **Faster than SHA-256**: Important for high-throughput tunnel
- **Same security**: No known weaknesses
- **Less fingerprinting**: SHA-256 patterns are well-known to DPI
- **Used by Noise**: Native integration with Noise Protocol

### Why Reed-Solomon FEC over Other Codes?

| FEC Code | Overhead | Recovery | Complexity | Latency |
|----------|----------|----------|------------|---------|
| **Simple XOR** | 100% | 1 packet | Trivial | None |
| **Reed-Solomon** | **Configurable (10-50%)** | **Any k of n** | Moderate | Buffering |
| **LDPC** | Lower | Probabilistic | High | High |
| **Raptor/Fountain** | Rateless | Probabilistic | Very high | Variable |

**Decision**: Reed-Solomon because:
- **Optimal recovery**: Can recover from ANY k packet losses with k parity packets
- **Configurable overhead**: Tune data:parity ratio for network conditions
- **Deterministic**: No probabilistic decoding failures
- **Low latency**: Small block sizes (10-15 packets) minimize buffering delay
- **Well-understood**: Decades of production use, mature implementations

Fountain codes were considered for high-loss scenarios but rejected due to complexity and variable latency.

### Why Raw Sockets over TUN/TAP?

| Approach | Kernel Integration | Performance | Flexibility |
|----------|-------------------|-------------|-------------|
| **TUN device** | Full IP stack | Slower (context switches) | Limited to IP |
| **TAP device** | Ethernet layer | Slower | Requires ARP handling |
| **Raw sockets** | **Bypass kernel TCP** | **Fastest** | **Full packet control** |
| **DPDK/XDP** | Kernel bypass | Fastest possible | Complex setup |

**Decision**: Raw sockets (SOCK_RAW + IP_HDRINCL) because:
- **Kernel bypass for TCP**: Kernel doesn't see our FakeTCP, can't send RSTs
- **Full packet control**: Craft any headers for Geneva strategies
- **No virtual interface**: Simpler deployment, no tun/tap module needed
- **Good enough performance**: Millions of PPS possible without DPDK complexity

TUN/TAP was rejected because the kernel TCP stack would interfere with our FakeTCP. DPDK/XDP was considered overkill for the throughput requirements.

### Why SOCKS5 over HTTP Proxy?

| Proxy Type | Protocol Support | Connection Overhead | Complexity |
|------------|-----------------|---------------------|------------|
| **HTTP CONNECT** | TCP only | High (HTTP parsing) | Headers leak info |
| **HTTP Proxy** | HTTP only | High | No TCP tunneling |
| **SOCKS4** | TCP only | Low | No UDP, no auth |
| **SOCKS5** | **TCP + UDP** | **Low (binary)** | Simple binary protocol |
| **Transparent** | All | None | Requires iptables |

**Decision**: SOCKS5 because:
- **Universal support**: All browsers, curl, most applications support it
- **Binary protocol**: Less overhead than HTTP text parsing
- **UDP support**: Future extensibility for DNS, QUIC
- **Simple implementation**: Well-defined state machine
- **No information leakage**: Minimal headers compared to HTTP proxy

### Why These Specific Transport Modes?

#### FakeTCP vs Real TCP

| Aspect | Real TCP (kernel) | FakeTCP (raw socket) |
|--------|-------------------|---------------------|
| RST injection | ❌ Kernel responds to injected RSTs | ✅ Ignored (kernel doesn't see it) |
| Sequence tracking | ❌ DPI can track state | ✅ We control all sequence numbers |
| Fingerprinting | ❌ OS TCP stack fingerprint | ✅ Custom stack, configurable |

**Decision**: FakeTCP with raw sockets because Iran's GFW injects TCP RST packets to kill connections. Real TCP would honor these RSTs; FakeTCP ignores them.

#### Protocol 115 (L2TPv3)

| Factor | Reasoning |
|--------|-----------|
| **Why 115?** | L2TPv3 uses IP protocol 115, designed for ISP infrastructure |
| **Why not UDP/TCP?** | Heavily inspected, need to escape to unmonitored protocols |
| **Why not OSPF (89)?** | Would trigger routing anomalies |

**Decision**: Protocol 115 exploits an "infrastructure blind spot" - it's used by carriers for L2 VPNs, so blocking it risks breaking enterprise services.

#### GRE (Protocol 47)

| Factor | Reasoning |
|--------|-----------|
| **Why GRE?** | Used by PPTP VPN, Cisco DMVPN, GCP load balancing |
| **Why alongside Protocol 115?** | Higher real-world traffic volume, more to blend with |
| **Why not GRE only?** | Some Iranian ISPs already filter GRE; 115 is less known |
| **Key field** | Provides built-in session multiplexing (RFC 2890) |
| **vs Protocol 115** | Complementary - GRE is the "known" option, 115 is the "obscure" one |

**Decision**: GRE provides a well-known infrastructure alternative to Protocol 115. If one is blocked, the other likely isn't - they exploit different administrative blind spots.

#### ICMP Tunneling

| Factor | Reasoning |
|--------|-----------|
| **Why ICMP?** | Blocking ICMP breaks ping, traceroute, path MTU discovery |
| **Why Echo specifically?** | Most commonly allowed ICMP type |
| **Limitation** | Rate-limited on most networks, low bandwidth |

**Decision**: ICMP provides a reliable fallback when TCP/UDP and protocol 115 are blocked, exploiting the "diagnostic necessity" loophole.

#### DNS Tunneling

| Factor | Reasoning |
|--------|-----------|
| **Why DNS?** | DNS is the one protocol that can NEVER be blocked |
| **Why not iodine/dnscat2?** | External tools, different protocol, not integrated |
| **Encoding** | Base32 in query names (DNS-safe), raw bytes in TXT responses |
| **Why NULL records?** | NULL type allows arbitrary binary data in responses |
| **Why not A/AAAA?** | Only 4/16 bytes per record - too low throughput |

**Decision**: DNS tunnel is the ultimate fallback. Even during Iran's total internet shutdowns, internal DNS continues functioning. Low throughput (~50-100 KB/s) but virtually unblockable.

#### UDP/QUIC Masquerade

| Factor | Reasoning |
|--------|-----------|
| **Why QUIC?** | HTTP/3 adoption is massive (Google, YouTube, Cloudflare) |
| **Why not real QUIC?** | Real QUIC handshake requires valid certificates |
| **Why UDP:443?** | Established port for QUIC, expected by network equipment |
| **Why mimic Initial?** | 1200-byte padding matches real QUIC, passes size heuristics |
| **No root needed** | Standard UDP socket - works without CAP_NET_RAW |
| **vs obfs4/shadowsocks** | Those are detectable; QUIC Initial is indistinguishable at L4 |

**Decision**: QUIC masquerade fills a critical gap - a high-throughput transport that requires no special privileges. As QUIC traffic grows, blocking UDP:443 becomes increasingly costly for censors.

### Why Mimic Rubika/Eitaa?

| App | Reason for Mimicking |
|-----|---------------------|
| **Rubika** | ✅ Iranian government-approved messenger, never blocked |
| **Eitaa** | ✅ Iranian government-approved Telegram alternative |
| **Telegram** | ❌ Actively blocked, fingerprint is flagged |
| **WhatsApp** | ❌ Foreign app, may be blocked during protests |
| **Chrome/Firefox** | ⚠️ Generic browser, less targeted but also less whitelisted |

**Decision**: Mimic Rubika and Eitaa because:
- **Whitelisted by policy**: Government-approved apps cannot be blocked without political issues
- **High traffic volume**: Large user base means our traffic blends in
- **Known fingerprints**: We captured real JA3 fingerprints from these apps
- **Domestic fronting**: SNI shows `messenger.rubika.ir`, appears as legitimate Iranian traffic

### Why These Geneva Strategies?

Each strategy exploits specific DPI implementation weaknesses:

| Strategy | DPI Weakness Exploited | Why It Works on Iranian GFW |
|----------|----------------------|----------------------------|
| **TCP Segmentation** | Signature matching assumes contiguous data | GFW reassembly has size limits |
| **Checksum Poisoning** | DPI accepts bad checksums; endpoint drops | Middlebox doesn't validate checksums |
| **TTL Expiry** | DPI sees packet; but it expires before destination | GFW is topologically "in the middle" |
| **Duplicate ACKs** | Confuses TCP state tracking in DPI | State machine can't handle duplicates |
| **FIN-before-SYN** | DPI expects SYN first | State machine resets incorrectly |

**Decision**: Selected strategies that research shows work against Iranian DPI specifically, based on Geneva project findings and independent testing.

## Requirements

- **Operating System**: Linux (kernel 3.10+)
- **Privileges**: Root access (required for raw sockets)
- **Rust**: 1.70+ (for building)
- **Dependencies**: libpcap-dev (optional, for packet capture debugging)

### System Configuration

The tunnel automatically configures iptables to drop kernel RST packets:

```bash
# This is done automatically, but for reference:
iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
```

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/your-org/phantom.git
cd phantom

# Build release binaries
cargo build --release

# Binaries will be in target/release/
ls target/release/phantom-client target/release/phantom-server
```

### Quick Install

```bash
cargo install --path .
```

## Usage

### Server Setup

1. **Generate server keys and start listening:**

```bash
# First run generates keys and prints public key
sudo ./phantom-server --listen 0.0.0.0:443 --transport faketcp

# Output:
# ========================================
# SERVER PUBLIC KEY (share with clients):
# base64_encoded_public_key_here
# ========================================
```

2. **With configuration file:**

```bash
sudo ./phantom-server --config server.json --listen 0.0.0.0:443
```

3. **Print key only (for sharing with clients):**

```bash
./phantom-server --print-key --key-file phantom-server.key
```

### Client Setup

1. **Connect to server:**

```bash
sudo ./phantom-client \
  --remote SERVER_IP:443 \
  --server-key "base64_public_key_from_server" \
  --listen 1080 \
  --transport faketcp \
  --sni messenger.rubika.ir
```

2. **Configure applications to use SOCKS5:**

```bash
# Example with curl
curl --socks5 127.0.0.1:1080 https://check.torproject.org

# Example with Firefox
# Settings -> Network Settings -> Manual proxy -> SOCKS Host: 127.0.0.1:1080
```

### Command Line Options

#### phantom-server

| Option | Description | Default |
|--------|-------------|---------|
| `-c, --config` | Path to configuration file | None |
| `-l, --listen` | Listen address (ip:port) | 0.0.0.0:443 |
| `-t, --transport` | Transport mode (faketcp, protocol115, icmp, dns, quicmasq, gre) | faketcp |
| `-v, --verbose` | Enable debug logging | false |
| `-k, --key-file` | Path to server private key | phantom-server.key |
| `--print-key` | Print public key and exit | false |

#### phantom-client

| Option | Description | Default |
|--------|-------------|---------|
| `-c, --config` | Path to configuration file | None |
| `-r, --remote` | Remote server address (ip:port) | Required |
| `-k, --server-key` | Server's public key (base64) | Required |
| `-l, --listen` | Local SOCKS5 proxy port | 1080 |
| `-t, --transport` | Transport mode | faketcp |
| `-v, --verbose` | Enable debug logging | false |
| `--sni` | SNI to spoof | messenger.rubika.ir |
| `--key-file` | Path to save/load client key | None (ephemeral) |

## Configuration

### Configuration File Format

```json
{
  "mode": "client",
  "transport": {
    "primary": "faketcp",
    "fallback": ["quicmasq", "protocol115", "gre", "icmp", "dns"],
    "auto_switch": true,
    "switch_threshold_ms": 5000
  },
  "network": {
    "bind_addr": "0.0.0.0:0",
    "remote_addr": "1.2.3.4:443",
    "mtu": 1400,
    "timeout_secs": 30
  },
  "handshake": {
    "mimic_target": "rubika",
    "spoof_sni": "messenger.rubika.ir",
    "include_grease": true,
    "randomize_extensions": false
  },
  "geneva": {
    "enabled": true,
    "strategies": ["tcp_segmentation", "checksum_poisoning"],
    "probability": 0.3
  },
  "fec": {
    "enabled": true,
    "data_shards": 10,
    "parity_shards": 3
  },
  "crypto": {
    "psk": null,
    "rekey_interval_secs": 3600
  }
}
```

### Configuration Options

#### Transport Configuration

| Field | Type | Description |
|-------|------|-------------|
| `primary` | string | Primary transport mode |
| `fallback` | array | Ordered list of fallback transports |
| `auto_switch` | bool | Enable automatic transport switching |
| `switch_threshold_ms` | u64 | Time before switching to fallback |

#### Geneva Configuration

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | bool | Enable Geneva DPI evasion |
| `strategies` | array | List of strategies to use |
| `probability` | f64 | Probability of applying strategy (0.0-1.0) |

#### FEC Configuration

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | bool | Enable Forward Error Correction |
| `data_shards` | usize | Number of data shards |
| `parity_shards` | usize | Number of parity shards |

## Transport Modes

### Comparison Matrix

| Transport | Protocol | Root | Throughput | GFW Blind Spot | Novel? |
|-----------|----------|:---:|:---:|---|:---:|
| **FakeTCP** | TCP (raw) | Yes | High | RST injection immunity | |
| **QUIC Masq** | UDP:443 | **No** | High | HTTP/3 traffic volume | |
| **Protocol 115** | IP:115 | Yes | High | ISP infrastructure | |
| **GRE** | IP:47 | Yes | High | Enterprise VPN trunks | |
| **ICMP** | ICMP | Yes | Low | Diagnostic necessity | |
| **DNS** | UDP:53 | **No** | Very Low | Required for internet | |
| **HTTP Smuggle** | TCP:80/443 | **No** | High | CL/TE parsing ambiguity + Iran case-bug | **YES** |
| **Video Parasite** | TCP:443 | **No** | Moderate | MPEG-TS spec allows arbitrary stuffing | **YES** |
| **Proto Morph** | TCP:443 | **No** | High | No fingerprint exists (session-unique) | **YES** |

### FakeTCP (Default)

Uses raw sockets to implement TCP-like behavior without the kernel's TCP stack. This prevents the kernel from interfering with RST packets injected by the GFW.

**Pros:**
- Most reliable for TCP-based filtering bypass
- Kernel bypass prevents RST injection attacks
- Supports full TCP handshake mimicry

**Cons:**
- Requires raw socket privileges (root)
- May be detected by advanced DPI analyzing TCP timestamps

### Protocol 115

Tunnels data using IP protocol 115 (L2TPv3), which is typically used for carrier infrastructure and not inspected by consumer-level DPI.

**Pros:**
- Invisible to most DPI systems
- Lower overhead than FakeTCP
- Works even when TCP/UDP are heavily filtered

**Cons:**
- May be blocked at network edge by protocol whitelisting
- Less common, could be flagged by anomaly detection

### ICMP

Tunnels data within ICMP Echo Request/Reply packets.

**Pros:**
- ICMP rarely blocked (breaks network diagnostics)
- Simple protocol, low overhead
- Works on many restricted networks

**Cons:**
- Limited bandwidth (typically rate-limited)
- Payload size restrictions
- May be deprioritized by network equipment

### DNS Tunnel

Encodes tunnel data inside DNS queries (base32 in query names) and responses (TXT records). DNS traffic on port 53 is never blocked because it's required for all internet functionality.

**Pros:**
- DNS is ALWAYS whitelisted - blocking it means no internet for anyone
- Works on captive portals and extremely restricted networks
- No root/raw socket required (standard UDP socket)
- Can traverse any NAT

**Cons:**
- Low throughput (~50-100 KB/s) due to query name length limits
- High latency (each exchange is a DNS round-trip)
- Requires an authoritative DNS server for the tunnel domain
- Heavy use may trigger DNS anomaly detection

**Best for:** Last-resort fallback, control channel, environments where all other transports are blocked.

### QUIC Masquerade

Sends tunnel data over UDP port 443, wrapped in packets that mimic QUIC (HTTP/3) Initial handshake format. Real QUIC version numbers, connection IDs, and padding are used to pass cursory DPI inspection.

**Pros:**
- No root/raw socket required (standard UDP socket)
- Blends with massive volume of real QUIC traffic (YouTube, Google, Cloudflare)
- Blocking UDP:443 would break HTTP/3 for all users
- QUIC DPI is immature compared to TLS/TCP inspection
- NAT-friendly (UDP hole punching possible)

**Cons:**
- Deep QUIC inspection could detect missing real crypto handshake
- Padding to 1200-byte minimum increases overhead
- UDP may be rate-limited on some networks

**Best for:** Primary transport when raw sockets aren't available, or when TCP-based transports are being filtered.

### GRE (Protocol 47)

Tunnels data using Generic Routing Encapsulation (IP Protocol 47), widely used by enterprise VPNs (PPTP), Cisco DMVPN, and cloud providers (GCP).

**Pros:**
- Infrastructure protocol - blocking breaks enterprise VPNs
- Lower overhead than FakeTCP (4-12 byte GRE header)
- Key field provides session multiplexing
- Sequence numbers for packet ordering
- Higher traffic volume than Protocol 115 (more to blend with)

**Cons:**
- Requires raw socket privileges (root)
- Some Iranian ISPs have been observed filtering GRE
- More widely known than Protocol 115, so more likely to be targeted

**Best for:** Enterprise-like environments, networks where PPTP VPNs are expected, as alternative to Protocol 115.

---

### Novel Transports (Phantom Inventions)

The following transports are **original inventions** - no production implementation exists for any of them.

### HTTP Request Smuggling Tunnel

Exploits the Content-Length vs Transfer-Encoding parsing ambiguity between Iran's DPI and our server. The DPI sees one interpretation of the HTTP stream; the tunnel server sees another. Additionally exploits Iran's **case-sensitive Host header matching bug** (discovered by FOCI 2025).

**How the desync works:**
```
POST /api/v1/sync HTTP/1.1
Host: Rubika.ir              ← Mixed case bypasses Iran's lowercase filter
Content-Length: 5             ← DPI reads this: sees 5-byte body ("0\r\n\r\n")
Transfer-Encoding: chunked   ← Server reads this: processes chunked body

0\r\n\r\n                     ← DPI thinks request ends here
[chunked tunnel data]         ← Server continues reading tunnel data
```

**Three desync modes:**
- **CL/TE**: DPI prioritizes Content-Length, server reads Transfer-Encoding
- **TE/CL**: Reversed - for DPI systems that prioritize TE
- **TE Obfuscation**: Obfuscated TE header (`Transfer-Encoding : chunked`, tab/space variants) that DPI fails to recognize

**Pros:**
- High bandwidth (full HTTP body throughput, ~Mbps)
- No root required (standard TCP socket)
- Traffic is syntactically valid HTTP
- Exploits known, documented Iran-specific DPI implementation bugs
- Pipelined requests maintain persistent bidirectional channel

**Cons:**
- Relies on specific DPI parsing behavior (may be patched)
- Server must implement custom HTTP parser
- HTTP/2 changes the smuggling surface

**Research:** FOCI 2024 "HTTP Request Smuggling for Censorship Evasion", FOCI 2025 "I(ra)nconsistencies in Iran's Censorship"

### Video Stream Parasiting

**First-ever implementation** of covert data embedding in HLS video Transport Stream packets. The concept was first proposed at IFIP Networking 2025 - no implementation exists anywhere.

Tunnel data is hidden inside MPEG-TS packets (188 bytes fixed size) served as an HLS video stream over HTTPS. A real video plays as cover traffic.

**Three embedding locations in each TS packet:**

| Location | Spec Definition | Capacity per Packet |
|----------|----------------|-------------------|
| Adaptation field stuffing | "may be any value" (arbitrary padding) | ~160 bytes |
| Null packets (PID 0x1FFF) | "may be inserted or discarded" | ~180 bytes |
| Private data bytes | Explicitly for custom data | ~150 bytes |

**Pros:**
- Traffic IS a valid HTTPS video stream - the video actually plays
- No DPI system decodes MPEG-TS packet internals
- Adaptation stuffing bytes are defined as arbitrary by ISO/IEC 13818-1
- Null packet contents are meaningless per spec
- Packet sizes and timing match real HLS streaming patterns

**Cons:**
- Moderate bandwidth (~100 Kbps covert in a 1 Mbps stream)
- Requires tunnel server to generate valid HLS segments
- Higher latency than direct tunneling (segment-based)
- Bandwidth overhead from cover video traffic

**Research:** IFIP Networking 2025 "HLS Covert Channel" (first paper, no prior implementation)

### Protocol Entropy Morphing

Each session generates a **unique wire format** derived from the shared key. No two sessions have the same packet structure, field layout, or byte patterns. A DPI fingerprint **cannot exist** because there is nothing stable to fingerprint.

Inspired by UPGen (USENIX Security 2025) but adapted for whitelist censors - runs over port 443 TCP and shapes traffic to match real protocol statistics.

**What the morph seed generates (all deterministic, both sides compute identically):**

| Component | Variation Range |
|-----------|----------------|
| Header size | 6-16 bytes |
| Magic bytes | 2-4 unique bytes per session |
| Length encoding | BE16 / LE16 / BE32 / Variable-length |
| XOR mask | 256-byte session-unique mask applied to ALL bytes |
| Padding | None / Fixed block / Random / HTTP-mimic sizes |
| Sequence numbers | Present or absent |

**Pros:**
- No fingerprint possible - every session has different structure
- XOR mask changes every byte's appearance across sessions
- Same plaintext produces completely different ciphertext per session
- DPI would need to fingerprint every individual connection (computationally infeasible)
- Even if one session is detected, the rule won't match any other session
- No root required

**Cons:**
- Requires shared seed (from key exchange)
- Outer TCP framing is still visible (port 443, packet sizes)
- Statistical analysis of connection behavior (not content) may still work

**Research:** UPGen (USENIX Security 2025) - automatic protocol generation for censorship evasion

## Geneva Strategies

The Geneva Engine implements DPI evasion through packet manipulation:

| Strategy | Description | Effectiveness |
|----------|-------------|---------------|
| `tcp_segmentation` | Splits TCP packets into smaller segments | High |
| `checksum_poisoning` | Sends packets with bad checksums | Medium |
| `ttl_expiry` | Sets TTL so packets expire at DPI | Medium |
| `duplicate_ack` | Sends duplicate ACKs to confuse state | Low |
| `fin_before_syn` | Sends FIN before connection established | Medium |
| `rst_short_ttl` | Fake RST with short TTL | Medium |
| `out_of_order` | Reorders packet delivery | Low |

### Recommended Strategy Combinations

**For Iranian GFW:**
```json
{
  "strategies": ["tcp_segmentation", "ttl_expiry"],
  "probability": 0.5
}
```

**For aggressive DPI:**
```json
{
  "strategies": ["tcp_segmentation", "checksum_poisoning", "out_of_order"],
  "probability": 0.7
}
```

## Security

### Cryptographic Details

- **Key Exchange**: Noise Protocol IK pattern
  - Provides mutual authentication
  - 0-RTT connection establishment
  - Forward secrecy through ephemeral keys

- **Symmetric Encryption**: XChaCha20-Poly1305
  - 256-bit key, 192-bit nonce
  - AEAD (Authenticated Encryption with Associated Data)
  - Chosen to avoid AES fingerprinting

- **Key Derivation**: X25519 ECDH + Blake2

### Threat Model

**Protected Against:**
- Passive traffic analysis
- Active probing (via TLS fingerprint mimicry)
- RST injection attacks
- TCP sequence number prediction
- Replay attacks (via nonce tracking)

**Not Protected Against:**
- Endpoint compromise
- Traffic correlation attacks (timing analysis)
- Complete protocol blocking (IP/port blacklisting)
- Active MITM with compromised keys

### Key Management

```bash
# Generate new server key
./phantom-server --key-file new-server.key --print-key

# Server key is stored in:
# - Private key: phantom-server.key (keep secret!)
# - Public key: printed to stdout (share with clients)

# Client can use ephemeral keys (default) or persistent:
./phantom-client --key-file client.key ...
```

## Technical Details

### Packet Format

```
┌─────────────────────────────────────────────────────────────┐
│                    IP Header (20 bytes)                      │
├─────────────────────────────────────────────────────────────┤
│              Transport Header (varies by mode)               │
│  - FakeTCP: TCP Header (20+ bytes)                          │
│  - Protocol 115: L2TP Header (12 bytes)                     │
│  - ICMP: ICMP Header (8 bytes)                              │
├─────────────────────────────────────────────────────────────┤
│                   FEC Header (4 bytes)                       │
│  - Block ID (2 bytes)                                        │
│  - Shard Index (1 byte)                                      │
│  - Total Shards (1 byte)                                     │
├─────────────────────────────────────────────────────────────┤
│                 Encrypted Payload (variable)                 │
│  - Noise-encrypted application data                          │
│  - XChaCha20-Poly1305 ciphertext                            │
│  - 16-byte authentication tag                                │
└─────────────────────────────────────────────────────────────┘
```

### Connection State Machine

```
Client                                              Server
  │                                                    │
  │  ──────── ClientHello (Noise handshake) ────────►  │
  │           [Mimics Rubika TLS fingerprint]          │
  │                                                    │
  │  ◄─────── ServerResponse (Noise handshake) ──────  │
  │                                                    │
  │  ════════════ Encrypted Tunnel Active ═══════════  │
  │                                                    │
  │  ──────── CONNECT host:port ─────────────────────► │
  │                                                    │
  │  ◄──────────── [proxied data] ──────────────────── │
  │  ───────────── [proxied data] ────────────────────►│
```

### Performance Tuning

```bash
# Increase socket buffers
sysctl -w net.core.rmem_max=26214400
sysctl -w net.core.wmem_max=26214400

# Disable TCP timestamps (optional, for stealth)
sysctl -w net.ipv4.tcp_timestamps=0

# Increase connection tracking limits
sysctl -w net.netfilter.nf_conntrack_max=1048576
```

## Troubleshooting

### Common Issues

**"Permission denied" when starting:**
```bash
# Run with sudo
sudo ./phantom-server ...

# Or set capabilities (preferred)
sudo setcap cap_net_raw,cap_net_admin=eip ./phantom-server
sudo setcap cap_net_raw,cap_net_admin=eip ./phantom-client
```

**"Address already in use":**
```bash
# Check what's using the port
ss -tlnp | grep 443

# Kill existing process or use different port
./phantom-server --listen 0.0.0.0:8443
```

**Connection timeouts:**
1. Verify server is reachable: `ping SERVER_IP`
2. Try different transport mode: `--transport protocol115`
3. Check firewall rules on server
4. Enable verbose logging: `-v`

**"Invalid server key" error:**
- Ensure public key is copied exactly (no extra whitespace)
- Verify base64 encoding is complete

### Debug Mode

```bash
# Enable full debug logging
RUST_LOG=debug ./phantom-client -v ...

# Log to file
RUST_LOG=debug ./phantom-client -v ... 2>&1 | tee phantom.log
```

### Checking Connection Status

```bash
# View active raw sockets
ss -w

# Monitor packet flow
tcpdump -i eth0 'ip proto 115' -n

# Check iptables rules
iptables -L OUTPUT -n | grep RST
```

## Project Structure

```
phantom/
├── Cargo.toml                 # Project configuration
├── README.md                  # This file
├── src/
│   ├── lib.rs                 # Library root
│   ├── error.rs               # Error types
│   ├── config.rs              # Configuration structures
│   ├── utils.rs               # Utility functions
│   ├── bin/
│   │   ├── client.rs          # Client binary
│   │   └── server.rs          # Server binary
│   ├── transport/
│   │   ├── mod.rs             # Transport trait + factory
│   │   ├── packet.rs          # IP/TCP/ICMP headers
│   │   ├── raw_socket.rs      # Raw socket wrapper
│   │   ├── fake_tcp.rs        # FakeTCP implementation
│   │   ├── protocol_115.rs    # L2TPv3-style transport
│   │   ├── icmp.rs            # ICMP tunnel
│   │   ├── dns_tunnel.rs      # DNS query/response tunnel
│   │   ├── quic_masq.rs       # UDP/QUIC masquerade transport
│   │   ├── gre.rs             # GRE (Protocol 47) transport
│   │   ├── http_smuggle.rs    # [NOVEL] HTTP CL/TE request smuggling
│   │   ├── video_parasite.rs  # [NOVEL] HLS/MPEG-TS covert channel
│   │   └── proto_morph.rs     # [NOVEL] Session-unique wire format
│   ├── geneva/
│   │   ├── mod.rs             # Strategy trait
│   │   ├── strategies.rs      # DPI evasion strategies
│   │   └── engine.rs          # Strategy orchestration
│   ├── crypto/
│   │   ├── mod.rs             # Crypto module
│   │   ├── keys.rs            # Key types
│   │   ├── symmetric.rs       # XChaCha20-Poly1305
│   │   └── noise.rs           # Noise Protocol
│   ├── fec/
│   │   └── mod.rs             # Reed-Solomon FEC
│   ├── handshake/
│   │   ├── mod.rs             # Handshake module
│   │   ├── tls.rs             # TLS ClientHello builder
│   │   └── fingerprint.rs     # JA3 fingerprinting
│   └── tunnel/
│       └── mod.rs             # Main tunnel implementation
```

## Contributing

Contributions are welcome! Please ensure:

1. Code follows Rust idioms and best practices
2. All tests pass: `cargo test`
3. No clippy warnings: `cargo clippy`
4. Format code: `cargo fmt`

## Disclaimer

This software is provided for educational and research purposes. Users are responsible for ensuring compliance with applicable laws and regulations. The authors do not condone the use of this software for illegal activities.

## License

MIT License - See [LICENSE](LICENSE) for details.

---

**Phantom** - *Invisible tunnels for a free internet*
