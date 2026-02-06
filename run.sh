#!/usr/bin/env bash
set -euo pipefail

# ============================================================
#  Phantom Tunnel - Setup & Run
# ============================================================
#
#  Quick start:
#    On your SERVER (VPS outside Iran):   ./run.sh setup server
#    On your CLIENT (inside Iran):        ./run.sh setup client
#    Test if tunnel works:                ./run.sh check
#
# ============================================================

GITHUB_REPO="knownasmobin/phantom"
VERSION="${PHANTOM_VERSION:-latest}"

PHANTOM_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="${PHANTOM_DIR}/bin"
DATA_DIR="${PHANTOM_DIR}/data"
SERVER_KEY="${DATA_DIR}/server.key"
CLIENT_KEY="${DATA_DIR}/client.key"
SERVER_CONFIG="${DATA_DIR}/server.json"
CLIENT_CONFIG="${DATA_DIR}/client.json"
INFO_FILE="${DATA_DIR}/connection-info.txt"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ---- Helpers ----

log_info()  { echo -e "${CYAN}[*]${NC} $*"; }
log_ok()    { echo -e "${GREEN}[+]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
log_err()   { echo -e "${RED}[-]${NC} $*"; }

ask() {
    local prompt="$1" default="$2" var="$3"
    local input
    echo -en "${BOLD}${prompt}${NC} [${default}]: "
    read -r input
    eval "$var=\"${input:-$default}\""
}

ask_choice() {
    local prompt="$1" var="$2"
    shift 2
    local options=("$@")

    echo -e "\n${BOLD}${prompt}${NC}"
    local i=1
    for opt in "${options[@]}"; do
        echo "  ${i}) ${opt}"
        ((i++))
    done
    echo -n "Choose [1]: "
    read -r choice
    choice="${choice:-1}"

    if [[ "$choice" -ge 1 && "$choice" -le "${#options[@]}" ]]; then
        eval "$var=\"${options[$((choice-1))]}\""
    else
        eval "$var=\"${options[0]}\""
    fi
}

banner() {
    echo -e "${CYAN}"
    echo "  ____  _                 _"
    echo " |  _ \\| |__   __ _ _ __ | |_ ___  _ __ ___"
    echo " | |_) | '_ \\ / _\` | '_ \\| __/ _ \\| '_ \` _ \\"
    echo " |  __/| | | | (_| | | | | || (_) | | | | | |"
    echo " |_|   |_| |_|\\__,_|_| |_|\\__\\___/|_| |_| |_|"
    echo -e "${NC}"
    echo "  Adaptive State-Masquerade Tunnel"
    echo ""
}

ensure_dirs() {
    mkdir -p "$DATA_DIR"
    mkdir -p "$BIN_DIR"
}

# ---- Binary Management ----

detect_platform() {
    local arch os

    arch=$(uname -m)
    os=$(uname -s | tr '[:upper:]' '[:lower:]')

    if [ "$os" != "linux" ]; then
        log_err "Pre-built binaries are only available for Linux."
        echo "    Use './run.sh build' to compile from source on this platform."
        exit 1
    fi

    case "$arch" in
        x86_64|amd64)   echo "linux-amd64" ;;
        aarch64|arm64)   echo "linux-arm64" ;;
        armv7l|armhf)    echo "linux-armv7" ;;
        *)
            log_err "Unsupported architecture: ${arch}"
            echo "    Use './run.sh build' to compile from source."
            exit 1
            ;;
    esac
}

resolve_version() {
    if [ "$VERSION" = "latest" ]; then
        log_info "Checking latest release..."
        VERSION=$(curl -fsSL --max-time 10 \
            "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" \
            2>/dev/null | grep '"tag_name"' | head -1 | cut -d'"' -f4 || echo "")

        if [ -z "$VERSION" ]; then
            log_err "Could not determine latest version from GitHub."
            echo "    Set a specific version: PHANTOM_VERSION=v0.1.0 ./run.sh setup server"
            echo "    Or build from source:   ./run.sh build"
            exit 1
        fi
        log_ok "Latest version: ${VERSION}"
    fi
}

download_binaries() {
    local platform="$1"
    local artifact="phantom-${platform}"
    local url="https://github.com/${GITHUB_REPO}/releases/download/${VERSION}/${artifact}.tar.gz"
    local checksum_url="https://github.com/${GITHUB_REPO}/releases/download/${VERSION}/SHA256SUMS.txt"
    local tmp_dir

    tmp_dir=$(mktemp -d)
    trap "rm -rf ${tmp_dir}" EXIT

    log_info "Downloading Phantom ${VERSION} for ${platform}..."
    echo "    ${url}"

    if ! curl -fSL --max-time 120 --progress-bar -o "${tmp_dir}/${artifact}.tar.gz" "$url"; then
        log_err "Download failed."
        echo ""
        echo "    Possible causes:"
        echo "      - Version ${VERSION} does not exist"
        echo "      - No release for platform '${platform}'"
        echo "      - Network issue (GitHub blocked?)"
        echo ""
        echo "    Alternatives:"
        echo "      - Check releases: https://github.com/${GITHUB_REPO}/releases"
        echo "      - Build from source: ./run.sh build"
        rm -rf "$tmp_dir"
        exit 1
    fi

    # Verify checksum if available
    if curl -fsSL --max-time 10 -o "${tmp_dir}/SHA256SUMS.txt" "$checksum_url" 2>/dev/null; then
        log_info "Verifying checksum..."
        local expected
        expected=$(grep "${artifact}.tar.gz" "${tmp_dir}/SHA256SUMS.txt" | awk '{print $1}')
        if [ -n "$expected" ]; then
            local actual
            actual=$(sha256sum "${tmp_dir}/${artifact}.tar.gz" | awk '{print $1}')
            if [ "$expected" = "$actual" ]; then
                log_ok "Checksum verified"
            else
                log_err "Checksum mismatch! Download may be corrupted."
                echo "    Expected: ${expected}"
                echo "    Got:      ${actual}"
                rm -rf "$tmp_dir"
                exit 1
            fi
        fi
    else
        log_warn "Could not fetch checksums, skipping verification"
    fi

    # Extract
    log_info "Extracting..."
    tar xzf "${tmp_dir}/${artifact}.tar.gz" -C "$BIN_DIR"
    chmod +x "${BIN_DIR}/phantom-client" "${BIN_DIR}/phantom-server"

    # Save version marker
    echo "$VERSION" > "${BIN_DIR}/.version"

    rm -rf "$tmp_dir"
    trap - EXIT

    log_ok "Installed phantom-client and phantom-server to ${BIN_DIR}/"
}

# Ensure binaries exist: download from release, or use local build
ensure_binaries() {
    # Check bin/ directory first (downloaded release)
    if [ -f "${BIN_DIR}/phantom-server" ] && [ -f "${BIN_DIR}/phantom-client" ]; then
        local installed_ver=""
        [ -f "${BIN_DIR}/.version" ] && installed_ver=$(cat "${BIN_DIR}/.version")
        log_ok "Binaries found (${installed_ver:-local})"
        return 0
    fi

    # Check if built from source
    if [ -f "${PHANTOM_DIR}/target/release/phantom-server" ] && \
       [ -f "${PHANTOM_DIR}/target/release/phantom-client" ]; then
        log_ok "Using locally built binaries"
        # Symlink into bin/ for consistent paths
        ln -sf "${PHANTOM_DIR}/target/release/phantom-server" "${BIN_DIR}/phantom-server"
        ln -sf "${PHANTOM_DIR}/target/release/phantom-client" "${BIN_DIR}/phantom-client"
        return 0
    fi

    # Nothing found — download
    log_info "No binaries found. Downloading from GitHub releases..."
    echo ""
    local platform
    platform=$(detect_platform)
    resolve_version
    download_binaries "$platform"
}

# ---- Transport Helpers ----

transport_to_enum() {
    case "$1" in
        "FakeTCP (recommended)")  echo "FakeTcp"       ;;
        "HTTP Smuggling")         echo "HttpSmuggle"    ;;
        "Protocol Morphing")      echo "ProtoMorph"     ;;
        "Video Parasiting")       echo "VideoParasite"  ;;
        "QUIC Masquerade")        echo "QuicMasq"       ;;
        "DNS Tunnel")             echo "Dns"            ;;
        *)                        echo "FakeTcp"        ;;
    esac
}

transport_to_cli() {
    case "$1" in
        "FakeTcp")       echo "faketcp"       ;;
        "HttpSmuggle")   echo "httpsmuggle"   ;;
        "ProtoMorph")    echo "protomorph"    ;;
        "VideoParasite") echo "videoparasite" ;;
        "QuicMasq")      echo "quicmasq"      ;;
        "Dns")           echo "dns"           ;;
        *)               echo "faketcp"       ;;
    esac
}

needs_root() {
    case "$1" in
        FakeTcp|Protocol115|Icmp|Gre) return 0 ;;
        *) return 1 ;;
    esac
}

# ---- Config Generation ----

write_config() {
    local mode="$1" transport_enum="$2" sni="$3" psk="$4"
    local listen_addr="$5" remote_addr="$6" log_level="$7"
    local config_file key_file mimic

    if [ "$mode" = "Server" ]; then
        config_file="$SERVER_CONFIG"
        key_file="$SERVER_KEY"
    else
        config_file="$CLIENT_CONFIG"
        key_file="$CLIENT_KEY"
    fi

    case "$sni" in
        *rubika*)  mimic="Rubika"  ;;
        *eitaa*)   mimic="Eitaa"   ;;
        *soroush*) mimic="Soroush" ;;
        *bale*)    mimic="Bale"    ;;
        *)         mimic="Chrome"  ;;
    esac

    cat > "$config_file" <<EOF
{
  "mode": "${mode}",
  "network": {
    "bind_addr": "${listen_addr}",
    "remote_addr": ${remote_addr},
    "interface": null,
    "timeout": 30,
    "keepalive": 15
  },
  "transport": {
    "primary": "${transport_enum}",
    "fallback": ["HttpSmuggle", "ProtoMorph", "QuicMasq", "Dns"],
    "auto_switch": true,
    "switch_threshold": 0.25,
    "send_rate": 0,
    "bypass_congestion": true
  },
  "geneva": {
    "enabled": true,
    "strategies": ["TcpSegmentation", "ChecksumPoisoning", "TtlExpiry"],
    "probability": 0.85
  },
  "handshake": {
    "spoof_sni": "${sni}",
    "mimic_target": "${mimic}",
    "ja3_fingerprint": null,
    "randomize_fingerprint": true,
    "initial_padding": 384
  },
  "crypto": {
    "private_key": "${key_file}",
    "peer_public_key": null,
    "psk": "${psk}",
    "replay_protection": true,
    "replay_window": 2048,
    "rekey_interval": 1800
  },
  "fec": {
    "enabled": true,
    "data_shards": 10,
    "parity_shards": 4,
    "shard_size": 1300
  },
  "log_level": "${log_level}"
}
EOF
}

# ---- Setup Commands ----

setup_server() {
    banner
    echo -e "${BOLD}=== Server Setup ===${NC}"
    echo "Run this on your VPS (the machine OUTSIDE Iran)."
    echo ""

    ensure_dirs

    # Port
    ask "Which port should the server listen on?" "443" PORT

    # Transport
    ask_choice "Which transport mode?" TRANSPORT_NAME \
        "FakeTCP (recommended)" \
        "HTTP Smuggling" \
        "Protocol Morphing" \
        "Video Parasiting" \
        "QUIC Masquerade" \
        "DNS Tunnel"
    local transport_enum
    transport_enum=$(transport_to_enum "$TRANSPORT_NAME")

    if needs_root "$transport_enum"; then
        log_warn "Transport '${TRANSPORT_NAME}' requires root/sudo to run."
    fi

    # SNI
    ask_choice "Which Iranian service to mimic? (DPI evasion)" SNI_CHOICE \
        "messenger.rubika.ir (Rubika - most popular)" \
        "eitaa.com (Eitaa)" \
        "web.bale.ai (Bale)" \
        "soroush-app.ir (Soroush)"
    local sni="${SNI_CHOICE%% *}"

    # PSK
    local default_psk
    default_psk="phantom-$(head -c 16 /dev/urandom | base64 | tr -d '/+=' | head -c 16)"
    ask "Pre-shared key (both sides must match)" "$default_psk" PSK

    # Logging
    ask_choice "Log level?" LOG_LEVEL "info" "debug"

    echo ""
    ensure_binaries

    # Generate server key
    local server_pub_key
    log_info "Generating server keypair..."
    "${BIN_DIR}/phantom-server" \
        --key-file "$SERVER_KEY" --print-key --listen "0.0.0.0:${PORT}" 2>/dev/null \
        | grep -v '=' | head -1 > /dev/null 2>&1 || true

    server_pub_key=$("${BIN_DIR}/phantom-server" \
        --key-file "$SERVER_KEY" --print-key --listen "0.0.0.0:${PORT}" 2>/dev/null \
        | grep -v '^$' | grep -v '=' | grep -v 'SERVER' | grep -v 'info' | head -1 || echo "CHECK_KEY_FILE")

    # Write config
    write_config "Server" "$transport_enum" "$sni" "$PSK" \
        "0.0.0.0:${PORT}" "null" "$LOG_LEVEL"

    # Detect public IP
    local server_ip
    server_ip=$(curl -s --max-time 5 ifconfig.me 2>/dev/null \
        || hostname -I 2>/dev/null | awk '{print $1}' \
        || echo "YOUR_SERVER_IP")

    # Save connection info for easy sharing
    cat > "$INFO_FILE" <<EOF
# -------------------------------------------------
# Phantom Connection Info
# Give this to the person running the client.
# -------------------------------------------------
SERVER_IP=${server_ip}
SERVER_PORT=${PORT}
SERVER_KEY=${server_pub_key}
PSK=${PSK}
TRANSPORT=$(transport_to_cli "$transport_enum")
# -------------------------------------------------
EOF

    echo ""
    echo -e "${GREEN}============================================${NC}"
    echo -e "${GREEN}  Server setup complete!${NC}"
    echo -e "${GREEN}============================================${NC}"
    echo ""
    echo -e "  Config saved to:  ${BOLD}${SERVER_CONFIG}${NC}"
    echo -e "  Server key:       ${BOLD}${SERVER_KEY}${NC}"
    echo ""
    echo -e "${YELLOW}--- Send this to the client user: ---${NC}"
    echo ""
    echo -e "  Server IP:        ${BOLD}${server_ip}${NC}"
    echo -e "  Server Port:      ${BOLD}${PORT}${NC}"
    echo -e "  Server Key:       ${BOLD}${server_pub_key}${NC}"
    echo -e "  PSK:              ${BOLD}${PSK}${NC}"
    echo -e "  Transport:        ${BOLD}$(transport_to_cli "$transport_enum")${NC}"
    echo ""
    echo -e "  (Also saved to ${BOLD}${INFO_FILE}${NC})"
    echo ""
    echo -e "${YELLOW}--- To start the server: ---${NC}"
    echo ""
    if needs_root "$transport_enum"; then
        echo -e "  sudo ./run.sh start server"
    else
        echo -e "  ./run.sh start server"
    fi
    echo ""
}

setup_client() {
    banner
    echo -e "${BOLD}=== Client Setup ===${NC}"
    echo "Run this on the machine INSIDE Iran."
    echo "You need the connection info from whoever set up the server."
    echo ""

    ensure_dirs

    # Gather info from user
    ask "Server IP address" "" SERVER_IP
    if [ -z "$SERVER_IP" ]; then
        log_err "Server IP is required."
        exit 1
    fi

    ask "Server port" "443" SERVER_PORT
    ask "Server public key (from server setup)" "" SERVER_PUB_KEY
    if [ -z "$SERVER_PUB_KEY" ]; then
        log_err "Server public key is required."
        exit 1
    fi

    ask "Pre-shared key (must match server)" "" PSK
    if [ -z "$PSK" ]; then
        log_err "PSK is required (get it from the server admin)."
        exit 1
    fi

    # Transport
    ask_choice "Transport mode (must match server)" TRANSPORT_NAME \
        "FakeTCP (recommended)" \
        "HTTP Smuggling" \
        "Protocol Morphing" \
        "Video Parasiting" \
        "QUIC Masquerade" \
        "DNS Tunnel"
    local transport_enum
    transport_enum=$(transport_to_enum "$TRANSPORT_NAME")

    # Local SOCKS port
    ask "Local SOCKS5 proxy port (apps connect here)" "1080" SOCKS_PORT

    # SNI
    ask_choice "Which service to mimic? (must match server)" SNI_CHOICE \
        "messenger.rubika.ir (Rubika - most popular)" \
        "eitaa.com (Eitaa)" \
        "web.bale.ai (Bale)" \
        "soroush-app.ir (Soroush)"
    local sni="${SNI_CHOICE%% *}"

    # Log level
    ask_choice "Log level?" LOG_LEVEL "info" "debug"

    echo ""
    ensure_binaries

    # Write config
    write_config "Client" "$transport_enum" "$sni" "$PSK" \
        "127.0.0.1:${SOCKS_PORT}" "\"${SERVER_IP}:${SERVER_PORT}\"" "$LOG_LEVEL"

    # Save connection state for start/check commands
    echo "$SERVER_PUB_KEY" > "${DATA_DIR}/server-public.key"
    echo "$SERVER_IP"      > "${DATA_DIR}/server-addr.txt"
    echo "$SERVER_PORT"    > "${DATA_DIR}/server-port.txt"
    echo "$SOCKS_PORT"     > "${DATA_DIR}/socks-port.txt"
    echo "$(transport_to_cli "$transport_enum")" > "${DATA_DIR}/transport.txt"
    echo "$sni"            > "${DATA_DIR}/sni.txt"

    echo ""
    echo -e "${GREEN}============================================${NC}"
    echo -e "${GREEN}  Client setup complete!${NC}"
    echo -e "${GREEN}============================================${NC}"
    echo ""
    echo -e "  Config saved to: ${BOLD}${CLIENT_CONFIG}${NC}"
    echo ""
    echo -e "${YELLOW}--- To connect: ---${NC}"
    echo ""
    if needs_root "$transport_enum"; then
        echo -e "  sudo ./run.sh start client"
    else
        echo -e "  ./run.sh start client"
    fi
    echo ""
    echo -e "${YELLOW}--- After connecting, test it: ---${NC}"
    echo ""
    echo -e "  ./run.sh check"
    echo ""
    echo -e "${YELLOW}--- Then configure your apps: ---${NC}"
    echo ""
    echo "  SOCKS5 proxy: 127.0.0.1:${SOCKS_PORT}"
    echo "  (Firefox: Settings > Network > Manual Proxy > SOCKS Host)"
    echo ""
}

# ---- Start Commands ----

start_server() {
    if [ ! -f "$SERVER_CONFIG" ]; then
        log_err "Server not set up yet. Run: ./run.sh setup server"
        exit 1
    fi

    ensure_dirs
    ensure_binaries

    local port transport
    port=$(grep -o '"bind_addr": "[^"]*"' "$SERVER_CONFIG" | grep -o ':[0-9]*"' | tr -d ':"')
    transport=$(grep -o '"primary": "[^"]*"' "$SERVER_CONFIG" | cut -d'"' -f4)

    echo ""
    echo -e "${GREEN}Starting Phantom server...${NC}"
    echo -e "  Listening on port ${BOLD}${port}${NC}"
    echo -e "  Transport: ${BOLD}${transport}${NC}"
    echo -e "  Press Ctrl+C to stop"
    echo ""

    local extra_args=()
    if [ -f "$SERVER_KEY" ]; then
        extra_args+=(--key-file "$SERVER_KEY")
    fi

    exec "${BIN_DIR}/phantom-server" \
        --config "$SERVER_CONFIG" \
        --listen "0.0.0.0:${port}" \
        --transport "$(transport_to_cli "$transport")" \
        "${extra_args[@]}"
}

start_client() {
    if [ ! -f "$CLIENT_CONFIG" ]; then
        log_err "Client not set up yet. Run: ./run.sh setup client"
        exit 1
    fi

    ensure_dirs
    ensure_binaries

    local server_key server_ip server_port socks_port transport sni
    server_key=$(cat "${DATA_DIR}/server-public.key" 2>/dev/null || echo "")
    server_ip=$(cat "${DATA_DIR}/server-addr.txt" 2>/dev/null || echo "")
    server_port=$(cat "${DATA_DIR}/server-port.txt" 2>/dev/null || echo "443")
    socks_port=$(cat "${DATA_DIR}/socks-port.txt" 2>/dev/null || echo "1080")
    transport=$(cat "${DATA_DIR}/transport.txt" 2>/dev/null || echo "faketcp")
    sni=$(cat "${DATA_DIR}/sni.txt" 2>/dev/null || echo "messenger.rubika.ir")

    if [ -z "$server_key" ] || [ -z "$server_ip" ]; then
        log_err "Missing connection info. Run: ./run.sh setup client"
        exit 1
    fi

    echo ""
    echo -e "${GREEN}Connecting to Phantom server...${NC}"
    echo -e "  Server:    ${BOLD}${server_ip}:${server_port}${NC}"
    echo -e "  SOCKS5:    ${BOLD}127.0.0.1:${socks_port}${NC}"
    echo -e "  Transport: ${BOLD}${transport}${NC}"
    echo -e "  SNI:       ${BOLD}${sni}${NC}"
    echo -e "  Press Ctrl+C to disconnect"
    echo ""

    exec "${BIN_DIR}/phantom-client" \
        --config "$CLIENT_CONFIG" \
        --remote "${server_ip}:${server_port}" \
        --server-key "$server_key" \
        --listen "$socks_port" \
        --transport "$transport" \
        --sni "$sni" \
        --key-file "$CLIENT_KEY"
}

# ---- Check/Test ----

cmd_check() {
    banner
    echo -e "${BOLD}=== Connection Check ===${NC}"
    echo ""

    local socks_port
    socks_port=$(cat "${DATA_DIR}/socks-port.txt" 2>/dev/null || echo "1080")

    # 1. Check if client is running
    log_info "Checking if SOCKS5 proxy is reachable on port ${socks_port}..."
    if command -v ss &>/dev/null; then
        if ss -tlnp 2>/dev/null | grep -q ":${socks_port}"; then
            log_ok "SOCKS5 port ${socks_port} is listening"
        else
            log_err "Nothing listening on port ${socks_port}"
            echo "    Make sure the client is running: ./run.sh start client"
            exit 1
        fi
    elif command -v netstat &>/dev/null; then
        if netstat -tln 2>/dev/null | grep -q ":${socks_port}"; then
            log_ok "SOCKS5 port ${socks_port} is listening"
        else
            log_err "Nothing listening on port ${socks_port}"
            echo "    Make sure the client is running: ./run.sh start client"
            exit 1
        fi
    else
        log_warn "Cannot check port (no ss/netstat), skipping..."
    fi

    # 2. Test SOCKS5 connection
    log_info "Testing tunnel with an HTTP request through SOCKS5..."
    echo ""

    if command -v curl &>/dev/null; then
        local start_time end_time elapsed
        start_time=$(date +%s%N 2>/dev/null || date +%s)

        local response
        response=$(curl -s --max-time 15 \
            --socks5-hostname "127.0.0.1:${socks_port}" \
            "http://ifconfig.me/ip" 2>&1) || true

        end_time=$(date +%s%N 2>/dev/null || date +%s)

        if [ -n "$response" ] && echo "$response" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
            if [[ "$start_time" =~ ^[0-9]{10,}$ ]]; then
                elapsed=$(( (end_time - start_time) / 1000000 ))
                log_ok "Tunnel is working! (${elapsed}ms)"
            else
                log_ok "Tunnel is working!"
            fi
            echo ""
            echo -e "  Your exit IP:  ${BOLD}${response}${NC}"
            echo ""

            # Compare with direct IP
            local direct_ip
            direct_ip=$(curl -s --max-time 5 "http://ifconfig.me/ip" 2>/dev/null || echo "")
            if [ -n "$direct_ip" ] && [ "$direct_ip" != "$response" ]; then
                log_ok "IPs are different - tunnel is routing traffic correctly"
                echo -e "  Direct IP:     ${direct_ip}"
                echo -e "  Tunnel IP:     ${response}"
            elif [ -n "$direct_ip" ]; then
                log_warn "Exit IP matches your direct IP - traffic may not be tunneled"
            fi

        elif echo "$response" | grep -qi "refused\|denied\|reset\|timeout"; then
            log_err "Connection failed: ${response}"
            echo ""
            echo "  Possible causes:"
            echo "    - Server is not running"
            echo "    - Firewall blocking the connection"
            echo "    - Wrong server IP/port"
            echo "    - Transport mode mismatch between client and server"
            exit 1
        else
            log_err "Got unexpected response: ${response}"
            echo "    The tunnel may be partially working but something is wrong."
            exit 1
        fi
    else
        log_warn "curl not found, trying basic TCP check..."
        if (echo > /dev/tcp/127.0.0.1/"${socks_port}") 2>/dev/null; then
            log_ok "SOCKS5 proxy is accepting connections"
            echo "    Install curl to do a full tunnel test"
        else
            log_err "Cannot connect to SOCKS5 proxy"
            exit 1
        fi
    fi

    echo ""
    echo -e "${GREEN}============================================${NC}"
    echo -e "  All checks passed! Your tunnel is ready."
    echo -e ""
    echo -e "  Configure your apps to use:"
    echo -e "    SOCKS5 proxy: ${BOLD}127.0.0.1:${socks_port}${NC}"
    echo -e "${GREEN}============================================${NC}"
    echo ""
}

# ---- Build from source ----

cmd_build() {
    local missing=()
    for cmd in cargo rustc; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done
    if [ ${#missing[@]} -gt 0 ]; then
        log_err "Missing build dependencies: ${missing[*]}"
        echo "  Install Rust: https://rustup.rs"
        echo "  Or download pre-built: ./run.sh download"
        exit 1
    fi

    log_info "Building Phantom from source..."
    cargo build --release --manifest-path "${PHANTOM_DIR}/Cargo.toml"

    # Copy into bin/ so start commands find them
    ensure_dirs
    cp "${PHANTOM_DIR}/target/release/phantom-client" "${BIN_DIR}/"
    cp "${PHANTOM_DIR}/target/release/phantom-server" "${BIN_DIR}/"
    echo "source" > "${BIN_DIR}/.version"

    log_ok "Build complete"
    echo "  Binaries installed to: ${BIN_DIR}/"
}

# ---- Download release ----

cmd_download() {
    ensure_dirs
    local platform
    platform=$(detect_platform)
    resolve_version
    download_binaries "$platform"
}

# ---- Update ----

cmd_update() {
    ensure_dirs
    log_info "Checking for updates..."

    local current=""
    [ -f "${BIN_DIR}/.version" ] && current=$(cat "${BIN_DIR}/.version")

    VERSION="latest"
    resolve_version

    if [ "$current" = "$VERSION" ]; then
        log_ok "Already up to date (${VERSION})"
        return 0
    fi

    if [ -n "$current" ]; then
        log_info "Updating ${current} -> ${VERSION}"
    fi

    local platform
    platform=$(detect_platform)
    download_binaries "$platform"
    log_ok "Updated to ${VERSION}"
}

# ---- Status ----

cmd_status() {
    banner

    echo -e "${BOLD}Setup status:${NC}"

    # Binaries
    if [ -f "${BIN_DIR}/phantom-server" ] && [ -f "${BIN_DIR}/phantom-client" ]; then
        local ver=""
        [ -f "${BIN_DIR}/.version" ] && ver=$(cat "${BIN_DIR}/.version")
        log_ok "Binaries installed (${ver:-unknown})"
    else
        echo -e "  ${RED}x${NC} No binaries  (run: ./run.sh download)"
    fi

    # Configs
    if [ -f "$SERVER_CONFIG" ]; then
        log_ok "Server configured"
    else
        echo -e "  ${RED}x${NC} Server not configured  (run: ./run.sh setup server)"
    fi
    if [ -f "$CLIENT_CONFIG" ]; then
        log_ok "Client configured"
    else
        echo -e "  ${RED}x${NC} Client not configured  (run: ./run.sh setup client)"
    fi

    # Connection info
    if [ -f "$INFO_FILE" ]; then
        echo ""
        echo -e "${BOLD}Connection info:${NC}"
        grep -v '^#' "$INFO_FILE" | grep -v '^$' | while IFS='=' read -r key val; do
            printf "  %-16s %s\n" "$key" "$val"
        done
    fi

    echo ""
}

# ---- Uninstall ----

cmd_uninstall() {
    log_warn "This will remove all Phantom binaries, configs, and keys."
    echo -n "Are you sure? [y/N]: "
    read -r confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        rm -rf "$BIN_DIR" "$DATA_DIR"
        log_ok "Removed ${BIN_DIR} and ${DATA_DIR}"
    else
        log_info "Cancelled"
    fi
}

# ---- Help ----

print_help() {
    banner
    echo -e "${BOLD}Usage:${NC}  ./run.sh <command>"
    echo ""
    echo -e "${BOLD}First-time setup:${NC}"
    echo "  setup server     Interactive server setup (run on VPS)"
    echo "  setup client     Interactive client setup (run inside Iran)"
    echo ""
    echo -e "${BOLD}Running:${NC}"
    echo "  start server     Start the tunnel server"
    echo "  start client     Connect to the tunnel server"
    echo ""
    echo -e "${BOLD}Testing:${NC}"
    echo "  check            Test if the tunnel is working"
    echo "  status           Show setup & version info"
    echo ""
    echo -e "${BOLD}Installation:${NC}"
    echo "  download         Download pre-built binaries from GitHub"
    echo "  build            Build from source (requires Rust)"
    echo "  update           Download the latest release"
    echo "  uninstall        Remove all binaries, configs, and keys"
    echo ""
    echo -e "${BOLD}Options:${NC}"
    echo "  PHANTOM_VERSION=v0.1.0 ./run.sh download   Pin a specific version"
    echo ""
    echo -e "${BOLD}Typical workflow:${NC}"
    echo "  1. On server VPS:   ./run.sh setup server"
    echo "  2. Share the connection info with the client"
    echo "  3. On client:       ./run.sh setup client"
    echo "  4. On server:       ./run.sh start server"
    echo "  5. On client:       ./run.sh start client"
    echo "  6. On client:       ./run.sh check"
    echo "  7. Set SOCKS5 proxy in your browser to 127.0.0.1:1080"
    echo ""
}

# ---- Main ----

case "${1:-}" in
    setup)
        case "${2:-}" in
            server) setup_server ;;
            client) setup_client ;;
            *)
                log_err "Usage: ./run.sh setup [server|client]"
                exit 1
                ;;
        esac
        ;;
    start)
        case "${2:-}" in
            server) start_server ;;
            client) start_client ;;
            *)
                log_err "Usage: ./run.sh start [server|client]"
                exit 1
                ;;
        esac
        ;;
    check)     cmd_check ;;
    status)    cmd_status ;;
    build)     cmd_build ;;
    download)  cmd_download ;;
    update)    cmd_update ;;
    uninstall) cmd_uninstall ;;
    help|-h|--help)
        print_help ;;
    *)
        print_help
        exit 1
        ;;
esac
