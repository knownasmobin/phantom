//! Raw socket implementation for Linux
//!
//! Provides SOCK_RAW access for crafting custom packets.
//! Requires CAP_NET_RAW or root privileges.

use crate::error::{PhantomError, Result};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::unix::io::{AsRawFd, RawFd};
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;

/// Raw socket wrapper with async support
pub struct RawSocket {
    inner: AsyncFd<Socket>,
    protocol: u8,
    include_ip_header: bool,
}

impl RawSocket {
    /// Create a new raw socket for the specified IP protocol
    ///
    /// # Arguments
    /// * `protocol` - IP protocol number (6=TCP, 1=ICMP, 115=L2TPv3, etc.)
    /// * `include_ip_header` - If true, IP_HDRINCL is set and we craft IP headers
    pub fn new(protocol: u8, include_ip_header: bool) -> Result<Self> {
        // Create raw socket
        let socket = Socket::new(
            Domain::IPV4,
            Type::RAW,
            Some(Protocol::from(protocol as i32)),
        ).map_err(|e| {
            if e.raw_os_error() == Some(1) {
                // EPERM
                PhantomError::InsufficientPrivileges
            } else {
                PhantomError::Socket(e.to_string())
            }
        })?;

        // Set IP_HDRINCL to craft our own IP headers
        if include_ip_header {
            socket.set_header_included(true)
                .map_err(|e| PhantomError::Socket(format!("Failed to set IP_HDRINCL: {}", e)))?;
        }

        // Set non-blocking for async
        socket.set_nonblocking(true)
            .map_err(|e| PhantomError::Socket(format!("Failed to set non-blocking: {}", e)))?;

        // Enable address reuse
        socket.set_reuse_address(true)
            .map_err(|e| PhantomError::Socket(format!("Failed to set SO_REUSEADDR: {}", e)))?;

        let async_fd = AsyncFd::new(socket)
            .map_err(|e| PhantomError::Socket(format!("Failed to create AsyncFd: {}", e)))?;

        Ok(Self {
            inner: async_fd,
            protocol,
            include_ip_header,
        })
    }

    /// Create a raw TCP socket (protocol 6)
    pub fn tcp() -> Result<Self> {
        Self::new(6, true)
    }

    /// Create a raw ICMP socket (protocol 1)
    pub fn icmp() -> Result<Self> {
        // ICMP doesn't need IP_HDRINCL typically, but we want full control
        Self::new(1, true)
    }

    /// Create a raw socket for IP protocol 115 (L2TPv3)
    pub fn protocol_115() -> Result<Self> {
        Self::new(115, true)
    }

    /// Bind the socket to a local address
    pub fn bind(&self, addr: SocketAddr) -> Result<()> {
        let socket_addr: socket2::SockAddr = addr.into();
        self.inner.get_ref().bind(&socket_addr)
            .map_err(|e| PhantomError::Socket(format!("Bind failed: {}", e)))
    }

    /// Send a raw packet
    ///
    /// If IP_HDRINCL is set, `data` should be a complete IP packet including headers.
    /// Otherwise, it should be just the payload.
    pub async fn send_to(&self, data: &[u8], dst: SocketAddr) -> Result<usize> {
        loop {
            let mut guard = self.inner.ready(Interest::WRITABLE).await
                .map_err(|e| PhantomError::Socket(format!("Async ready failed: {}", e)))?;

            match guard.try_io(|inner| {
                let socket_addr: socket2::SockAddr = dst.into();
                inner.get_ref().send_to(data, &socket_addr)
            }) {
                Ok(result) => {
                    return result.map_err(|e| PhantomError::Io(e));
                }
                Err(_would_block) => continue,
            }
        }
    }

    /// Receive a raw packet
    ///
    /// Returns the packet data and source address.
    /// If IP_HDRINCL is set, the returned data includes the IP header.
    pub async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        loop {
            let mut guard = self.inner.ready(Interest::READABLE).await
                .map_err(|e| PhantomError::Socket(format!("Async ready failed: {}", e)))?;

            match guard.try_io(|inner| {
                let mut storage = std::mem::MaybeUninit::<socket2::SockAddr>::uninit();
                inner.get_ref().recv_from(unsafe {
                    std::slice::from_raw_parts_mut(buf.as_mut_ptr(), buf.len())
                })
            }) {
                Ok(result) => {
                    let (n, addr) = result.map_err(|e| PhantomError::Io(e))?;
                    // Extract source address from the received packet if needed
                    // For raw sockets, we parse the IP header
                    if self.include_ip_header && n >= 20 {
                        let src_ip = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
                        return Ok((n, SocketAddr::V4(SocketAddrV4::new(src_ip, 0))));
                    }
                    return Ok((n, SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))));
                }
                Err(_would_block) => continue,
            }
        }
    }

    /// Get the raw file descriptor
    pub fn as_raw_fd(&self) -> RawFd {
        self.inner.get_ref().as_raw_fd()
    }

    /// Get the protocol number
    pub fn protocol(&self) -> u8 {
        self.protocol
    }
}

/// Helper to set up iptables rules for FakeTCP
/// This prevents the kernel from sending RST packets for our raw connections
pub struct IptablesGuard {
    rules: Vec<String>,
}

impl IptablesGuard {
    /// Create iptables rules to suppress kernel RST packets
    ///
    /// # Arguments
    /// * `local_port` - Local port we're using for FakeTCP
    /// * `remote_ip` - Remote IP we're connecting to
    pub fn new(local_port: u16, remote_ip: Ipv4Addr) -> Result<Self> {
        let rules = vec![
            // Block outgoing RST packets from kernel
            format!(
                "-A OUTPUT -p tcp --sport {} -d {} --tcp-flags RST RST -j DROP",
                local_port, remote_ip
            ),
            // Block incoming RST packets (optional, for protection)
            format!(
                "-A INPUT -p tcp --dport {} -s {} --tcp-flags RST RST -j DROP",
                local_port, remote_ip
            ),
        ];

        // Apply rules
        for rule in &rules {
            let output = std::process::Command::new("iptables")
                .args(rule.split_whitespace())
                .output()
                .map_err(|e| PhantomError::Socket(format!("Failed to run iptables: {}", e)))?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                // Ignore if rule already exists
                if !stderr.contains("already exists") {
                    tracing::warn!("iptables rule may have failed: {}", stderr);
                }
            }
        }

        Ok(Self { rules })
    }

    /// Create rules for server mode
    pub fn new_server(listen_port: u16) -> Result<Self> {
        let rules = vec![
            // Block outgoing RST packets from kernel for all connections on this port
            format!(
                "-A OUTPUT -p tcp --sport {} --tcp-flags RST RST -j DROP",
                listen_port
            ),
        ];

        for rule in &rules {
            let _ = std::process::Command::new("iptables")
                .args(rule.split_whitespace())
                .output();
        }

        Ok(Self { rules })
    }
}

impl Drop for IptablesGuard {
    fn drop(&mut self) {
        // Remove rules on cleanup
        for rule in &self.rules {
            // Replace -A with -D to delete
            let delete_rule = rule.replace("-A ", "-D ");
            let _ = std::process::Command::new("iptables")
                .args(delete_rule.split_whitespace())
                .output();
        }
    }
}

/// Check if we have raw socket capabilities
pub fn check_capabilities() -> Result<()> {
    // Try to create a raw socket to check permissions
    match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(6))) {
        Ok(_) => Ok(()),
        Err(e) => {
            if e.raw_os_error() == Some(1) {
                Err(PhantomError::InsufficientPrivileges)
            } else {
                Err(PhantomError::Socket(e.to_string()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore] // Requires root
    fn test_raw_socket_creation() {
        let socket = RawSocket::tcp().unwrap();
        assert_eq!(socket.protocol(), 6);
    }
}
