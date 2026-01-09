//! VMess server implementation
//!
//! Provides a high-level server interface for VMess protocol.

use crate::command::Address;
use crate::config::VmessConfig;
use crate::data::{Chunk, DataProcessor};
use crate::error::VmessError;
use crate::message::{RequestBuilder, ResponseParser};
use crate::transport::TcpTransport;
use crate::user_id::UserId;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// VMess server errors
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("Bind failed: {0}")]
    BindFailed(String),
    #[error("Accept failed: {0}")]
    AcceptFailed(String),
    #[error("Parse request failed: {0}")]
    ParseFailed(String),
    #[error("Connection to target failed: {0}")]
    TargetConnectionFailed(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("VMess error: {0}")]
    VmessError(#[from] VmessError),
    #[error("Transport error: {0}")]
    TransportError(#[from] crate::transport::TransportError),
}

/// VMess server configuration
pub struct ServerConfig {
    /// User ID for authentication
    pub user_id: UserId,
    /// Bind address
    pub bind_address: String,
    /// Bind port
    pub bind_port: u16,
    /// Connection timeout
    pub timeout: Duration,
    /// Authentication time window
    pub auth_time_window: Duration,
}

impl ServerConfig {
    /// Create server config from VmessConfig
    pub fn from_vmess_config(config: &VmessConfig) -> Result<Self, VmessError> {
        let user_id = config.user_id()?;
        Ok(Self {
            user_id,
            bind_address: config.server_address.clone(),
            bind_port: config.server_port,
            timeout: Duration::from_secs(config.options.timeout_seconds),
            auth_time_window: Duration::from_secs(config.options.auth_time_window_seconds),
        })
    }
}

/// VMess server
pub struct VmessServer {
    config: Arc<ServerConfig>,
    listener: TcpListener,
}

impl VmessServer {
    /// Create and bind a new VMess server
    pub async fn bind(config: ServerConfig) -> Result<Self, ServerError> {
        let bind_addr = format!("{}:{}", config.bind_address, config.bind_port);
        let listener = TcpListener::bind(&bind_addr)
            .await
            .map_err(|e| ServerError::BindFailed(format!("{}: {}", bind_addr, e)))?;

        println!("VMess server listening on {}", bind_addr);

        Ok(Self {
            config: Arc::new(config),
            listener,
        })
    }

    /// Run the server, accepting connections
    pub async fn run(&self) -> Result<(), ServerError> {
        loop {
            match self.listener.accept().await {
                Ok((stream, addr)) => {
                    let config = Arc::clone(&self.config);
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, addr, config).await {
                            eprintln!("[{}] Connection error: {}", addr, e);
                        }
                    });
                }
                Err(e) => {
                    eprintln!("Accept error: {}", e);
                }
            }
        }
    }

    /// Get the local address the server is bound to
    pub fn local_addr(&self) -> Result<SocketAddr, ServerError> {
        self.listener.local_addr().map_err(ServerError::IoError)
    }
}

/// Handle a single client connection
async fn handle_connection(
    mut stream: TcpStream,
    addr: SocketAddr,
    config: Arc<ServerConfig>,
) -> Result<(), ServerError> {
    println!("[{}] New connection", addr);

    // Set TCP options
    stream.set_nodelay(true)?;

    // Read initial data (auth + command + initial data)
    let mut buf = vec![0u8; 65536];
    let n = stream.read(&mut buf).await?;
    if n < 16 {
        return Err(ServerError::ParseFailed("Request too short".to_string()));
    }
    buf.truncate(n);

    // Parse VMess request
    let request_builder =
        RequestBuilder::with_time_window(config.user_id.clone(), config.auth_time_window);

    let request = request_builder
        .parse(&buf)
        .map_err(|e| ServerError::ParseFailed(e.to_string()))?;

    let target_addr = &request.command.address;
    let target_port = request.command.port;

    println!(
        "[{}] Proxying to {}:{}",
        addr,
        format_address(target_addr),
        target_port
    );

    // Connect to target
    let target_transport = TcpTransport::connect(target_addr, target_port, config.timeout).await?;

    let (mut target_read, mut target_write) = target_transport.split();

    // Send initial data to target (if any)
    if !request.data.is_empty() {
        target_write.write_all(&request.data).await?;
    }

    // Create response parser for building responses
    let response_parser = ResponseParser::from_command(&request.command);

    // Split client stream
    let (mut client_read, mut client_write) = stream.into_split();

    // Store encryption parameters for relay
    let encryption_method = request.command.encryption_method;
    let data_key = request.command.data_key;
    let data_iv = request.command.data_iv;

    // Bidirectional relay
    let client_to_target = async {
        let data_processor = DataProcessor::new(encryption_method, data_key, data_iv);
        let mut buf = vec![0u8; 65536];
        let mut chunk_index = 1u16; // Start from 1 since 0 was used for initial data

        loop {
            match client_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    // Parse chunks from client
                    let mut pos = 0;
                    while pos < n {
                        match Chunk::from_bytes(&buf[pos..n]) {
                            Ok((chunk, consumed)) => {
                                if data_processor.is_eot(&chunk) {
                                    return Ok::<_, std::io::Error>(());
                                }
                                // Decrypt chunk and forward to target
                                match data_processor.decode_chunk(&chunk, chunk_index) {
                                    Ok(decrypted) => {
                                        target_write.write_all(&decrypted).await?;
                                    }
                                    Err(_) => break,
                                }
                                chunk_index = chunk_index.wrapping_add(1);
                                pos += consumed;
                            }
                            Err(_) => break,
                        }
                    }
                }
                Err(_) => break,
            }
        }
        Ok(())
    };

    let target_to_client = async {
        // Send response header first
        let header_response = response_parser
            .build(&[])
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        client_write.write_all(&header_response).await?;

        let data_processor = DataProcessor::new(encryption_method, data_key, data_iv);
        let mut buf = vec![0u8; 65536];
        let mut chunk_index = 0u16;

        loop {
            match target_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    // Encrypt data and send to client as chunks
                    match data_processor.encode_chunk(&buf[..n], chunk_index) {
                        Ok(chunk) => {
                            client_write.write_all(&chunk.to_bytes()).await?;
                        }
                        Err(_) => break,
                    }
                    chunk_index = chunk_index.wrapping_add(1);
                }
                Err(_) => break,
            }
        }

        // Send EOT chunk
        let eot = data_processor.create_eot_chunk();
        client_write.write_all(&eot.to_bytes()).await?;

        Ok::<_, std::io::Error>(())
    };

    // Run both directions concurrently
    tokio::select! {
        result = client_to_target => {
            if let Err(e) = result {
                eprintln!("[{}] Client to target error: {}", addr, e);
            }
        }
        result = target_to_client => {
            if let Err(e) = result {
                eprintln!("[{}] Target to client error: {}", addr, e);
            }
        }
    }

    println!("[{}] Connection closed", addr);
    Ok(())
}

/// Format address for display
fn format_address(addr: &Address) -> String {
    match addr {
        Address::IPv4(ip) => format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]),
        Address::IPv6(ip) => {
            let segments: Vec<String> = (0..8)
                .map(|i| format!("{:x}", u16::from_be_bytes([ip[i * 2], ip[i * 2 + 1]])))
                .collect();
            format!("[{}]", segments.join(":"))
        }
        Address::Domain(domain) => domain.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_address_ipv4() {
        let addr = Address::IPv4([192, 168, 1, 1]);
        assert_eq!(format_address(&addr), "192.168.1.1");
    }

    #[test]
    fn test_format_address_domain() {
        let addr = Address::Domain("example.com".to_string());
        assert_eq!(format_address(&addr), "example.com");
    }
}
