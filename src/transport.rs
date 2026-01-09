//! Network transport layer for VMess protocol
//!
//! Provides async TCP transport with timeout support.

use crate::command::Address;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),
    #[error("Connection timeout")]
    Timeout,
    #[error("DNS resolution failed: {0}")]
    DnsError(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Send failed: {0}")]
    SendFailed(String),
    #[error("Receive failed: {0}")]
    ReceiveFailed(String),
}

/// TCP transport for VMess protocol
pub struct TcpTransport {
    stream: TcpStream,
}

impl TcpTransport {
    /// Connect to server with timeout
    pub async fn connect(
        addr: &Address,
        port: u16,
        connect_timeout: Duration,
    ) -> Result<Self, TransportError> {
        let socket_addr = Self::resolve_address(addr, port).await?;

        let stream = timeout(connect_timeout, TcpStream::connect(socket_addr))
            .await
            .map_err(|_| TransportError::Timeout)?
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        // Disable Nagle's algorithm for lower latency
        stream.set_nodelay(true)?;

        Ok(Self { stream })
    }

    /// Resolve address to SocketAddr
    async fn resolve_address(addr: &Address, port: u16) -> Result<SocketAddr, TransportError> {
        match addr {
            Address::IPv4(ip) => {
                let ip_addr = Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]);
                Ok(SocketAddr::new(IpAddr::V4(ip_addr), port))
            }
            Address::IPv6(ip) => {
                let segments: [u16; 8] = [
                    u16::from_be_bytes([ip[0], ip[1]]),
                    u16::from_be_bytes([ip[2], ip[3]]),
                    u16::from_be_bytes([ip[4], ip[5]]),
                    u16::from_be_bytes([ip[6], ip[7]]),
                    u16::from_be_bytes([ip[8], ip[9]]),
                    u16::from_be_bytes([ip[10], ip[11]]),
                    u16::from_be_bytes([ip[12], ip[13]]),
                    u16::from_be_bytes([ip[14], ip[15]]),
                ];
                let ip_addr = Ipv6Addr::new(
                    segments[0],
                    segments[1],
                    segments[2],
                    segments[3],
                    segments[4],
                    segments[5],
                    segments[6],
                    segments[7],
                );
                Ok(SocketAddr::new(IpAddr::V6(ip_addr), port))
            }
            Address::Domain(domain) => {
                // Use tokio's DNS resolution
                let addr_str = format!("{}:{}", domain, port);
                let addrs: Vec<SocketAddr> = tokio::net::lookup_host(&addr_str)
                    .await
                    .map_err(|e| TransportError::DnsError(e.to_string()))?
                    .collect();

                addrs.into_iter().next().ok_or_else(|| {
                    TransportError::DnsError(format!("No addresses found for {}", domain))
                })
            }
        }
    }

    /// Send data
    pub async fn send(&mut self, data: &[u8]) -> Result<(), TransportError> {
        self.stream
            .write_all(data)
            .await
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;
        self.stream
            .flush()
            .await
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;
        Ok(())
    }

    /// Send data with timeout
    pub async fn send_timeout(
        &mut self,
        data: &[u8],
        send_timeout: Duration,
    ) -> Result<(), TransportError> {
        timeout(send_timeout, self.send(data))
            .await
            .map_err(|_| TransportError::Timeout)?
    }

    /// Receive data into buffer
    /// Returns the number of bytes read
    pub async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, TransportError> {
        let n = self
            .stream
            .read(buf)
            .await
            .map_err(|e| TransportError::ReceiveFailed(e.to_string()))?;
        Ok(n)
    }

    /// Receive data with timeout
    pub async fn recv_timeout(
        &mut self,
        buf: &mut [u8],
        recv_timeout: Duration,
    ) -> Result<usize, TransportError> {
        timeout(recv_timeout, self.recv(buf))
            .await
            .map_err(|_| TransportError::Timeout)?
    }

    /// Receive exact number of bytes
    pub async fn recv_exact(&mut self, buf: &mut [u8]) -> Result<(), TransportError> {
        self.stream
            .read_exact(buf)
            .await
            .map_err(|e| TransportError::ReceiveFailed(e.to_string()))?;
        Ok(())
    }

    /// Close connection
    pub async fn close(mut self) -> Result<(), TransportError> {
        self.stream
            .shutdown()
            .await
            .map_err(TransportError::IoError)?;
        Ok(())
    }

    /// Get the local address
    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        self.stream.local_addr().map_err(TransportError::IoError)
    }

    /// Get the peer address
    pub fn peer_addr(&self) -> Result<SocketAddr, TransportError> {
        self.stream.peer_addr().map_err(TransportError::IoError)
    }

    /// Split into read and write halves
    pub fn split(
        self,
    ) -> (
        tokio::net::tcp::OwnedReadHalf,
        tokio::net::tcp::OwnedWriteHalf,
    ) {
        self.stream.into_split()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_to_socket_addr_ipv4() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let addr = Address::IPv4([127, 0, 0, 1]);
            let socket_addr = TcpTransport::resolve_address(&addr, 8080).await.unwrap();
            assert_eq!(socket_addr.to_string(), "127.0.0.1:8080");
        });
    }

    #[test]
    fn test_address_to_socket_addr_ipv6() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let addr = Address::IPv6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
            let socket_addr = TcpTransport::resolve_address(&addr, 8080).await.unwrap();
            assert_eq!(socket_addr.to_string(), "[::1]:8080");
        });
    }

    #[test]
    fn test_transport_error_display() {
        let err = TransportError::Timeout;
        assert_eq!(err.to_string(), "Connection timeout");

        let err = TransportError::ConnectionFailed("refused".to_string());
        assert!(err.to_string().contains("refused"));
    }
}
