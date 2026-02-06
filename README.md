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
| Domestic App Fronting | SNI matching whitelisted Iranian services bypasses TLS inspection |

## Features

- **Multiple Transport Modes**
  - FakeTCP: Raw socket TCP-like protocol with kernel bypass
  - Protocol 115: L2TPv3-style tunneling through unmonitored IP protocol
  - ICMP: Echo request/reply tunneling

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
│                     Transport Layer                              │
│  ┌───────────┐  ┌───────────────┐  ┌─────────────────────────┐  │
│  │  FakeTCP  │  │  Protocol 115 │  │        ICMP             │  │
│  │ (Raw Sock)│  │  (L2TPv3-like)│  │   (Echo Tunnel)         │  │
│  └───────────┘  └───────────────┘  └─────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Raw IP Sockets                               │
│                  (Kernel Bypass)                                 │
└─────────────────────────────────────────────────────────────────┘
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
| **Why not GRE (47)?** | Already blocked by some Iranian ISPs |
| **Why not OSPF (89)?** | Would trigger routing anomalies |

**Decision**: Protocol 115 exploits an "infrastructure blind spot" - it's used by carriers for L2 VPNs, so blocking it risks breaking enterprise services.

#### ICMP Tunneling

| Factor | Reasoning |
|--------|-----------|
| **Why ICMP?** | Blocking ICMP breaks ping, traceroute, path MTU discovery |
| **Why Echo specifically?** | Most commonly allowed ICMP type |
| **Limitation** | Rate-limited on most networks, low bandwidth |

**Decision**: ICMP provides a reliable fallback when TCP/UDP and protocol 115 are blocked, exploiting the "diagnostic necessity" loophole.

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
| `-t, --transport` | Transport mode (faketcp, protocol115, icmp) | faketcp |
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
    "fallback": ["protocol115", "icmp"],
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
│   │   ├── mod.rs             # Transport trait
│   │   ├── packet.rs          # IP/TCP/ICMP headers
│   │   ├── raw_socket.rs      # Raw socket wrapper
│   │   ├── fake_tcp.rs        # FakeTCP implementation
│   │   ├── protocol_115.rs    # L2TPv3-style transport
│   │   └── icmp.rs            # ICMP tunnel
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
