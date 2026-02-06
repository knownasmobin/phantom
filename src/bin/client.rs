//! Phantom Client - ASMT Tunnel Client
//!
//! Usage:
//!   phantom-client --config <path> --remote <ip:port>
//!   phantom-client --remote <ip:port> --server-key <base64>

use phantom::{Config, PhantomError, Result};
use phantom::config::{Mode, TransportMode};
use phantom::crypto::{KeyPair, PublicKey};
use phantom::tunnel::{PhantomTunnel, TunnelBuilder, TunnelState};

use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{info, error, debug, warn};

#[derive(Parser, Debug)]
#[command(name = "phantom-client")]
#[command(about = "Phantom ASMT Tunnel Client")]
#[command(version)]
struct Args {
    /// Path to configuration file
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Remote server address (ip:port)
    #[arg(short, long)]
    remote: SocketAddr,

    /// Server's public key (base64)
    #[arg(short = 'k', long)]
    server_key: String,

    /// Local SOCKS5 proxy port
    #[arg(short, long, default_value = "1080")]
    listen: u16,

    /// Transport mode (faketcp, protocol115, icmp)
    #[arg(short, long, default_value = "faketcp")]
    transport: String,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// SNI to spoof
    #[arg(long, default_value = "messenger.rubika.ir")]
    sni: String,

    /// Path to save/load client key
    #[arg(long)]
    key_file: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    let log_level = if args.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(log_level)
        .init();

    info!("Phantom Client starting...");
    info!("Remote server: {}", args.remote);

    // Load or generate client keypair
    let local_keypair = if let Some(ref key_file) = args.key_file {
        if key_file.exists() {
            info!("Loading client key from {:?}", key_file);
            KeyPair::load(key_file)?
        } else {
            info!("Generating new client key, saving to {:?}", key_file);
            let kp = KeyPair::generate();
            kp.save(key_file)?;
            kp
        }
    } else {
        info!("Generating ephemeral client key");
        KeyPair::generate()
    };

    info!("Client public key: {}", local_keypair.public);

    // Parse server public key
    let server_public = PublicKey::from_base64(&args.server_key)?;
    info!("Server public key: {}", server_public);

    // Parse transport mode
    let transport_mode = match args.transport.to_lowercase().as_str() {
        "faketcp" | "fake-tcp" | "tcp" => TransportMode::FakeTcp,
        "protocol115" | "115" | "l2tp" => TransportMode::Protocol115,
        "icmp" => TransportMode::Icmp,
        _ => {
            error!("Unknown transport mode: {}", args.transport);
            return Err(PhantomError::Config(format!("Unknown transport: {}", args.transport)));
        }
    };

    // Build configuration
    let mut config = if let Some(config_path) = args.config {
        let content = std::fs::read_to_string(&config_path)
            .map_err(|e| PhantomError::Config(format!("Failed to read config: {}", e)))?;
        serde_json::from_str(&content)
            .map_err(|e| PhantomError::Config(format!("Failed to parse config: {}", e)))?
    } else {
        Config::default()
    };

    config.mode = Mode::Client;
    config.transport.primary = transport_mode;
    config.handshake.spoof_sni = args.sni;
    config.network.remote_addr = Some(args.remote);

    // Build tunnel
    let tunnel = TunnelBuilder::new()
        .config(config)
        .local_keypair(local_keypair)
        .remote_public_key(server_public)
        .build()?;

    let tunnel = std::sync::Arc::new(tunnel);

    // Connect to server
    info!("Connecting to server...");
    tunnel.connect(args.remote).await?;

    let stats = tunnel.stats();
    info!("Connected! Handshake completed in {}ms", stats.handshake_time_ms);
    info!("Using transport: {:?}", stats.current_transport);

    // Start local SOCKS5 proxy
    let listen_addr: SocketAddr = format!("127.0.0.1:{}", args.listen).parse().unwrap();
    let listener = TcpListener::bind(listen_addr).await
        .map_err(|e| PhantomError::Io(e))?;

    info!("SOCKS5 proxy listening on {}", listen_addr);
    info!("Configure your applications to use SOCKS5 proxy at 127.0.0.1:{}", args.listen);

    // Handle incoming connections
    loop {
        let (socket, client_addr) = listener.accept().await
            .map_err(|e| PhantomError::Io(e))?;

        debug!("New connection from {}", client_addr);

        let tunnel = tunnel.clone();
        let remote = args.remote;

        tokio::spawn(async move {
            if let Err(e) = handle_socks5_connection(socket, tunnel, remote).await {
                warn!("Connection error: {}", e);
            }
        });
    }
}

/// Handle a SOCKS5 connection
async fn handle_socks5_connection(
    mut socket: tokio::net::TcpStream,
    tunnel: std::sync::Arc<PhantomTunnel>,
    remote: SocketAddr,
) -> Result<()> {
    let mut buf = [0u8; 1024];

    // SOCKS5 handshake
    let n = socket.read(&mut buf).await.map_err(|e| PhantomError::Io(e))?;
    if n < 2 || buf[0] != 0x05 {
        return Err(PhantomError::Protocol("Invalid SOCKS5 handshake".into()));
    }

    // Send response (no auth required)
    socket.write_all(&[0x05, 0x00]).await.map_err(|e| PhantomError::Io(e))?;

    // Read connection request
    let n = socket.read(&mut buf).await.map_err(|e| PhantomError::Io(e))?;
    if n < 4 || buf[0] != 0x05 || buf[1] != 0x01 {
        return Err(PhantomError::Protocol("Invalid SOCKS5 request".into()));
    }

    // Parse destination
    let (dest_addr, dest_port) = match buf[3] {
        0x01 => {
            // IPv4
            if n < 10 {
                return Err(PhantomError::Protocol("Invalid IPv4 address".into()));
            }
            let addr = format!("{}.{}.{}.{}", buf[4], buf[5], buf[6], buf[7]);
            let port = u16::from_be_bytes([buf[8], buf[9]]);
            (addr, port)
        }
        0x03 => {
            // Domain name
            let len = buf[4] as usize;
            if n < 5 + len + 2 {
                return Err(PhantomError::Protocol("Invalid domain name".into()));
            }
            let domain = String::from_utf8_lossy(&buf[5..5 + len]).to_string();
            let port = u16::from_be_bytes([buf[5 + len], buf[6 + len]]);
            (domain, port)
        }
        0x04 => {
            // IPv6
            return Err(PhantomError::Protocol("IPv6 not supported".into()));
        }
        _ => {
            return Err(PhantomError::Protocol("Unknown address type".into()));
        }
    };

    debug!("SOCKS5 connect to {}:{}", dest_addr, dest_port);

    // Send success response
    socket.write_all(&[0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        .await.map_err(|e| PhantomError::Io(e))?;

    // Create connection header for the tunnel
    let connect_request = format!("CONNECT {}:{}\r\n", dest_addr, dest_port);
    tunnel.send(connect_request.as_bytes(), remote).await?;

    // Bidirectional data transfer
    let (mut read_half, mut write_half) = socket.into_split();

    // Local -> Tunnel
    let tunnel_send = tunnel.clone();
    let send_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 16384];
        loop {
            match read_half.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if tunnel_send.send(&buf[..n], remote).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // Tunnel -> Local
    let tunnel_recv = tunnel.clone();
    let recv_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 16384];
        loop {
            match tunnel_recv.recv(&mut buf).await {
                Ok((n, _)) => {
                    if write_half.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    tokio::select! {
        _ = send_task => {}
        _ = recv_task => {}
    }

    Ok(())
}
