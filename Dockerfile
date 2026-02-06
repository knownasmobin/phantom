# ---- Builder Stage ----
FROM rust:1.83-bookworm AS builder

WORKDIR /build

# Cache dependencies: copy manifests first, create dummy src, build deps
COPY Cargo.toml Cargo.lock* ./
RUN mkdir -p src/bin && \
    echo "fn main() {}" > src/bin/client.rs && \
    echo "fn main() {}" > src/bin/server.rs && \
    echo "" > src/lib.rs && \
    cargo build --release 2>/dev/null || true && \
    rm -rf src

# Copy actual source and build
COPY src/ src/
RUN cargo build --release --bin phantom-client --bin phantom-server

# ---- Runtime Stage ----
FROM debian:bookworm-slim AS runtime

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        iptables \
        iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user (raw sockets still need NET_ADMIN capability)
RUN groupadd -r phantom && useradd -r -g phantom phantom

COPY --from=builder /build/target/release/phantom-client /usr/local/bin/
COPY --from=builder /build/target/release/phantom-server /usr/local/bin/

# Default config directory
RUN mkdir -p /etc/phantom && chown phantom:phantom /etc/phantom
VOLUME ["/etc/phantom"]

# Expose common ports
# 443: TLS/QUIC masquerade, 80: HTTP smuggle, 53: DNS tunnel
EXPOSE 443/tcp 443/udp 80/tcp 53/udp

# Raw socket transports require NET_ADMIN and NET_RAW capabilities
# Run with: docker run --cap-add=NET_ADMIN --cap-add=NET_RAW
USER phantom

ENTRYPOINT ["phantom-server"]
CMD ["--config", "/etc/phantom/server.json"]
