//! Phantom Server - ASMT Tunnel Server
//!
//! Usage:
//!   phantom-server --config <path>
//!   phantom-server --listen <ip:port>

use phantom::{Config, PhantomError, Result};
use phantom::config::{Mode, TransportMode};
use phantom::crypto::{KeyPair, PublicKey, SharedNoiseSession};
use phantom::tunnel::{PhantomTunnel, TunnelBuilder, TunnelState};

use clap::Parser;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tracing::{info, error, debug, warn};

#[derive(Parser, Debug)]
#[command(name = "phantom-server")]
#[command(about = "Phantom ASMT Tunnel Server")]
#[command(version)]
struct Args {
    /// Path to configuration file
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Listen address (ip:port)
    #[arg(short, long, default_value = "0.0.0.0:443")]
    listen: SocketAddr,

    /// Transport mode (faketcp, protocol115, icmp)
    #[arg(short, long, default_value = "faketcp")]
    transport: String,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Path to server private key (will be created if not exists)
    #[arg(short, long, default_value = "phantom-server.key")]
    key_file: PathBuf,

    /// Print public key and exit
    #[arg(long)]
    print_key: bool,
}

/// Active client session
struct ClientSession {
    session: SharedNoiseSession,
    last_activity: std::time::Instant,
    remote_addr: SocketAddr,
}

type SessionMap = Arc<RwLock<HashMap<SocketAddr, ClientSession>>>;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    let log_level = if args.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(log_level)
        .init();

    // Load or generate server keypair
    let server_keypair = if args.key_file.exists() {
        info!("Loading server key from {:?}", args.key_file);
        KeyPair::load(&args.key_file)?
    } else {
        info!("Generating new server key, saving to {:?}", args.key_file);
        let kp = KeyPair::generate();
        kp.save(&args.key_file)?;
        kp
    };

    // Print public key for client configuration
    info!("Server public key: {}", server_keypair.public);
    println!("\n========================================");
    println!("SERVER PUBLIC KEY (share with clients):");
    println!("{}", server_keypair.public);
    println!("========================================\n");

    if args.print_key {
        return Ok(());
    }

    info!("Phantom Server starting...");
    info!("Listening on: {}", args.listen);

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

    config.mode = Mode::Server;
    config.transport.primary = transport_mode;
    config.network.bind_addr = args.listen;

    // Build tunnel
    let tunnel = TunnelBuilder::new()
        .config(config)
        .local_keypair(server_keypair)
        .build()?;

    let tunnel = Arc::new(tunnel);

    // Start listening
    tunnel.listen().await?;
    info!("Server listening on {:?}", tunnel.state());

    // Session tracking
    let sessions: SessionMap = Arc::new(RwLock::new(HashMap::new()));

    // Session cleanup task
    let sessions_cleanup = sessions.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;

            let mut sessions = sessions_cleanup.write().await;
            let now = std::time::Instant::now();
            sessions.retain(|addr, session| {
                let age = now.duration_since(session.last_activity);
                if age.as_secs() > 300 {
                    info!("Cleaning up stale session from {}", addr);
                    false
                } else {
                    true
                }
            });
        }
    });

    // Accept connections
    loop {
        match tunnel.accept().await {
            Ok((client_addr, session)) => {
                info!("New client connected: {}", client_addr);

                let tunnel = tunnel.clone();
                let sessions = sessions.clone();

                // Store session
                sessions.write().await.insert(client_addr, ClientSession {
                    session: session.clone(),
                    last_activity: std::time::Instant::now(),
                    remote_addr: client_addr,
                });

                // Handle client
                tokio::spawn(async move {
                    if let Err(e) = handle_client(tunnel, session, client_addr).await {
                        warn!("Client {} error: {}", client_addr, e);
                    }
                    info!("Client {} disconnected", client_addr);
                });
            }
            Err(e) => {
                error!("Accept error: {}", e);
            }
        }
    }
}

/// Handle a connected client
async fn handle_client(
    tunnel: Arc<PhantomTunnel>,
    session: SharedNoiseSession,
    client_addr: SocketAddr,
) -> Result<()> {
    let mut buf = vec![0u8; 65535];

    loop {
        // Receive data from client
        let (n, _) = tunnel.recv(&mut buf).await?;
        if n == 0 {
            break;
        }

        // Parse request (simple CONNECT protocol)
        let request = String::from_utf8_lossy(&buf[..n]);
        debug!("Request from {}: {}", client_addr, request.trim());

        if request.starts_with("CONNECT ") {
            // Parse destination
            let parts: Vec<&str> = request.split_whitespace().collect();
            if parts.len() >= 2 {
                let dest = parts[1].trim();
                debug!("Client {} wants to connect to {}", client_addr, dest);

                // Connect to destination
                match TcpStream::connect(dest).await {
                    Ok(mut dest_stream) => {
                        info!("Connected to {} for client {}", dest, client_addr);

                        // Bidirectional proxy
                        let (mut dest_read, mut dest_write) = dest_stream.split();

                        // Tunnel -> Destination
                        let tunnel_recv = tunnel.clone();
                        let forward_task = tokio::spawn(async move {
                            let mut buf = vec![0u8; 16384];
                            loop {
                                match tunnel_recv.recv(&mut buf).await {
                                    Ok((n, _)) if n > 0 => {
                                        if dest_write.write_all(&buf[..n]).await.is_err() {
                                            break;
                                        }
                                    }
                                    _ => break,
                                }
                            }
                        });

                        // Destination -> Tunnel
                        let tunnel_send = tunnel.clone();
                        let backward_task = tokio::spawn(async move {
                            let mut buf = vec![0u8; 16384];
                            loop {
                                match dest_read.read(&mut buf).await {
                                    Ok(n) if n > 0 => {
                                        if tunnel_send.send(&buf[..n], client_addr).await.is_err() {
                                            break;
                                        }
                                    }
                                    _ => break,
                                }
                            }
                        });

                        tokio::select! {
                            _ = forward_task => {}
                            _ = backward_task => {}
                        }
                    }
                    Err(e) => {
                        warn!("Failed to connect to {}: {}", dest, e);
                        // Send error back to client
                        let error_msg = format!("ERROR: {}\n", e);
                        let _ = tunnel.send(error_msg.as_bytes(), client_addr).await;
                    }
                }
            }
        }
    }

    Ok(())
}
