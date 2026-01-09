//! VMess client implementation
//!
//! Provides a high-level client interface for VMess protocol.

use crate::command::{Address, EncryptionMethod};
use crate::config::VmessConfig;
use crate::error::VmessError;
use crate::message::{RequestBuilder, ResponseParser};
use crate::transport::TcpTransport;
use crate::user_id::UserId;
use std::time::Duration;

/// VMess client state
enum ClientState {
    Disconnected,
    Connected {
        transport: TcpTransport,
        response_parser: ResponseParser,
    },
}

/// VMess client
pub struct VmessClient {
    config: VmessConfig,
    user_id: UserId,
    request_builder: RequestBuilder,
    state: ClientState,
}

impl VmessClient {
    /// Create a new VMess client from configuration
    pub fn new(config: VmessConfig) -> Result<Self, VmessError> {
        config.validate()?;
        let user_id = config.user_id()?;
        let request_builder = RequestBuilder::with_time_window(
            user_id.clone(),
            Duration::from_secs(config.options.auth_time_window_seconds),
        );

        Ok(Self {
            config,
            user_id,
            request_builder,
            state: ClientState::Disconnected,
        })
    }

    /// Connect to the VMess server
    pub async fn connect(&mut self) -> Result<(), VmessError> {
        let address = self.parse_server_address()?;
        let timeout = Duration::from_secs(self.config.options.timeout_seconds);

        let transport = TcpTransport::connect(&address, self.config.server_port, timeout).await?;

        self.state = ClientState::Connected {
            transport,
            response_parser: ResponseParser::new([0; 16], [0; 16], 0, EncryptionMethod::None),
        };

        Ok(())
    }

    /// Send a request to the target address through the VMess server
    pub async fn request(
        &mut self,
        target: Address,
        port: u16,
        data: &[u8],
    ) -> Result<Vec<u8>, VmessError> {
        let encryption = self.config.encryption_method()?;

        // Build request
        let (request_bytes, command) =
            self.request_builder.build(target, port, data, encryption)?;

        // Get transport
        let (transport, _) = match &mut self.state {
            ClientState::Connected {
                transport,
                response_parser,
            } => (transport, response_parser),
            ClientState::Disconnected => {
                return Err(VmessError::Transport(
                    crate::transport::TransportError::ConnectionFailed("Not connected".to_string()),
                ));
            }
        };

        // Send request
        let timeout = Duration::from_secs(self.config.options.timeout_seconds);
        transport.send_timeout(&request_bytes, timeout).await?;

        // Receive response
        let mut response_buf = vec![0u8; 65536];
        let n = transport.recv_timeout(&mut response_buf, timeout).await?;
        response_buf.truncate(n);

        // Parse response
        let response_parser = ResponseParser::from_command(&command);
        let response = response_parser.parse(&response_buf)?;

        Ok(response.data)
    }

    /// Send raw data (after initial handshake)
    pub async fn send(&mut self, data: &[u8]) -> Result<(), VmessError> {
        let transport = match &mut self.state {
            ClientState::Connected { transport, .. } => transport,
            ClientState::Disconnected => {
                return Err(VmessError::Transport(
                    crate::transport::TransportError::ConnectionFailed("Not connected".to_string()),
                ));
            }
        };

        let timeout = Duration::from_secs(self.config.options.timeout_seconds);
        transport.send_timeout(data, timeout).await?;
        Ok(())
    }

    /// Receive raw data
    pub async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, VmessError> {
        let transport = match &mut self.state {
            ClientState::Connected { transport, .. } => transport,
            ClientState::Disconnected => {
                return Err(VmessError::Transport(
                    crate::transport::TransportError::ConnectionFailed("Not connected".to_string()),
                ));
            }
        };

        let timeout = Duration::from_secs(self.config.options.timeout_seconds);
        let n = transport.recv_timeout(buf, timeout).await?;
        Ok(n)
    }

    /// Close the connection
    pub async fn close(self) -> Result<(), VmessError> {
        if let ClientState::Connected { transport, .. } = self.state {
            transport.close().await?;
        }
        Ok(())
    }

    /// Check if connected
    pub fn is_connected(&self) -> bool {
        matches!(self.state, ClientState::Connected { .. })
    }

    /// Get the configuration
    pub fn config(&self) -> &VmessConfig {
        &self.config
    }

    /// Get the user ID
    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    /// Parse server address from config
    fn parse_server_address(&self) -> Result<Address, VmessError> {
        let addr = &self.config.server_address;

        // Try parsing as IPv4
        if let Ok(parts) = addr
            .split('.')
            .map(|s| s.parse::<u8>())
            .collect::<Result<Vec<_>, _>>()
        {
            if parts.len() == 4 {
                return Ok(Address::IPv4([parts[0], parts[1], parts[2], parts[3]]));
            }
        }

        // Try parsing as IPv6
        if addr.contains(':') && !addr.contains('.') {
            // Simple IPv6 parsing (full format only)
            let parts: Result<Vec<u16>, _> = addr
                .split(':')
                .map(|s| u16::from_str_radix(s, 16))
                .collect();

            if let Ok(parts) = parts {
                if parts.len() == 8 {
                    let mut bytes = [0u8; 16];
                    for (i, &part) in parts.iter().enumerate() {
                        bytes[i * 2] = (part >> 8) as u8;
                        bytes[i * 2 + 1] = part as u8;
                    }
                    return Ok(Address::IPv6(bytes));
                }
            }
        }

        // Treat as domain name
        Ok(Address::Domain(addr.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> VmessConfig {
        VmessConfig::new(
            "de305d54-75b4-431b-adb2-eb6b9e546014".to_string(),
            "127.0.0.1".to_string(),
            10086,
            "aes-128-gcm".to_string(),
        )
    }

    #[test]
    fn test_client_new() {
        let config = test_config();
        let client = VmessClient::new(config).unwrap();
        assert!(!client.is_connected());
    }

    #[test]
    fn test_client_invalid_config() {
        let config = VmessConfig::new(
            "invalid-uuid".to_string(),
            "127.0.0.1".to_string(),
            10086,
            "aes-128-gcm".to_string(),
        );
        let result = VmessClient::new(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_ipv4_address() {
        let config = VmessConfig::new(
            "de305d54-75b4-431b-adb2-eb6b9e546014".to_string(),
            "192.168.1.1".to_string(),
            443,
            "none".to_string(),
        );
        let client = VmessClient::new(config).unwrap();
        let addr = client.parse_server_address().unwrap();
        assert!(matches!(addr, Address::IPv4([192, 168, 1, 1])));
    }

    #[test]
    fn test_parse_domain_address() {
        let config = VmessConfig::new(
            "de305d54-75b4-431b-adb2-eb6b9e546014".to_string(),
            "example.com".to_string(),
            443,
            "none".to_string(),
        );
        let client = VmessClient::new(config).unwrap();
        let addr = client.parse_server_address().unwrap();
        if let Address::Domain(domain) = addr {
            assert_eq!(domain, "example.com");
        } else {
            panic!("Expected domain address");
        }
    }

    #[test]
    fn test_client_config_getter() {
        let config = test_config();
        let client = VmessClient::new(config.clone()).unwrap();
        assert_eq!(client.config().server_port, config.server_port);
    }

    #[test]
    fn test_client_user_id_getter() {
        let config = test_config();
        let client = VmessClient::new(config).unwrap();
        assert_eq!(
            client.user_id().to_string(),
            "de305d54-75b4-431b-adb2-eb6b9e546014"
        );
    }
}
