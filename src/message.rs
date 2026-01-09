//! Request and Response handling for VMess protocol
//!
//! Handles building and parsing complete VMess messages including
//! authentication, command section, and data section.

use crate::auth::{AuthError, Authenticator};
use crate::command::{Address, Command, CommandCodec, CommandError, CommandOptions, CommandType, EncryptionMethod};
use crate::crypto::{md5, Aes128Cfb};
use crate::data::{Chunk, DataError, DataProcessor};
use crate::user_id::UserId;
use rand::{thread_rng, Rng};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RequestError {
    #[error("Authentication error: {0}")]
    Auth(#[from] AuthError),
    #[error("Command error: {0}")]
    Command(#[from] CommandError),
    #[error("Data error: {0}")]
    Data(#[from] DataError),
    #[error("Buffer too short")]
    BufferTooShort,
}

#[derive(Debug, Error)]
pub enum ResponseError {
    #[error("Response authentication mismatch")]
    AuthMismatch,
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("Invalid response format")]
    InvalidFormat,
    #[error("Buffer too short")]
    BufferTooShort,
}

/// VMess client request
#[derive(Clone, Debug, PartialEq)]
pub struct Request {
    pub auth_info: [u8; 16],
    pub command: Command,
    pub data: Vec<u8>,
}

/// VMess server response
#[derive(Clone, Debug, PartialEq)]
pub struct Response {
    pub response_auth: u8,
    pub options: u8,
    pub command: u8,
    pub command_content: Option<Vec<u8>>,
    pub data: Vec<u8>,
}

/// Request builder for VMess client
pub struct RequestBuilder {
    user_id: UserId,
    authenticator: Authenticator,
    command_codec: CommandCodec,
}

impl RequestBuilder {
    /// Create a new request builder
    pub fn new(user_id: UserId) -> Self {
        let authenticator = Authenticator::with_default_window(user_id.clone());
        let command_codec = CommandCodec::new(user_id.clone());
        Self {
            user_id,
            authenticator,
            command_codec,
        }
    }

    /// Create with custom time window
    pub fn with_time_window(user_id: UserId, time_window: Duration) -> Self {
        let authenticator = Authenticator::new(user_id.clone(), time_window);
        let command_codec = CommandCodec::new(user_id.clone());
        Self {
            user_id,
            authenticator,
            command_codec,
        }
    }

    /// Build a complete VMess request
    ///
    /// Returns the serialized request bytes and the command (for response parsing)
    pub fn build(
        &self,
        target: Address,
        port: u16,
        data: &[u8],
        encryption: EncryptionMethod,
    ) -> Result<(Vec<u8>, Command), RequestError> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        self.build_with_timestamp(target, port, data, encryption, timestamp)
    }

    /// Build request with specific timestamp (for testing)
    pub fn build_with_timestamp(
        &self,
        target: Address,
        port: u16,
        data: &[u8],
        encryption: EncryptionMethod,
        timestamp: u64,
    ) -> Result<(Vec<u8>, Command), RequestError> {
        // Generate random IV and key for data encryption
        let mut rng = thread_rng();
        let mut data_iv = [0u8; 16];
        let mut data_key = [0u8; 16];
        rng.fill(&mut data_iv);
        rng.fill(&mut data_key);

        // Create command
        let command = Command {
            version: 1,
            data_iv,
            data_key,
            response_auth: rng.gen(),
            options: CommandOptions {
                standard_format: true,
                reuse_connection: false,
                metadata: false,
            },
            encryption_method: encryption,
            command_type: CommandType::Tcp,
            port,
            address: target,
        };

        // Build request bytes
        let request_bytes = self.build_from_command(&command, data, timestamp)?;

        Ok((request_bytes, command))
    }

    /// Build request from existing command
    pub fn build_from_command(
        &self,
        command: &Command,
        data: &[u8],
        timestamp: u64,
    ) -> Result<Vec<u8>, RequestError> {
        let mut result = Vec::new();

        // 1. Authentication info (16 bytes)
        let auth_info = self.authenticator.generate_for_timestamp(timestamp);
        result.extend_from_slice(&auth_info);

        // 2. Encrypted command section
        let encrypted_command = self.command_codec.encode(command, timestamp)?;
        result.extend_from_slice(&encrypted_command);

        // 3. Data section (chunked)
        let data_processor = DataProcessor::new(
            command.encryption_method,
            command.data_key,
            command.data_iv,
        );
        let chunks = data_processor.encode(data)?;
        for chunk in chunks {
            result.extend_from_slice(&chunk.to_bytes());
        }

        Ok(result)
    }

    /// Parse a VMess request
    pub fn parse(&self, data: &[u8]) -> Result<Request, RequestError> {
        self.parse_at_time(data, None)
    }

    /// Parse request with specific reference time
    pub fn parse_at_time(&self, data: &[u8], reference_time: Option<u64>) -> Result<Request, RequestError> {
        if data.len() < 16 {
            return Err(RequestError::BufferTooShort);
        }

        // 1. Extract and verify authentication info
        let mut auth_info = [0u8; 16];
        auth_info.copy_from_slice(&data[..16]);

        let timestamp = if let Some(ref_time) = reference_time {
            self.authenticator.verify_at_time(&auth_info, ref_time)?
        } else {
            self.authenticator.verify(&auth_info)?
        };

        // 2. Decode command section with length
        let command_start = 16;
        let remaining = &data[command_start..];
        
        let (command, command_len) = self.command_codec.decode_with_length(remaining, timestamp)?;
        let data_start = command_start + command_len;

        // 3. Parse data section
        let data_processor = DataProcessor::new(
            command.encryption_method,
            command.data_key,
            command.data_iv,
        );

        let mut chunks = Vec::new();
        let mut pos = data_start;
        while pos < data.len() {
            match Chunk::from_bytes(&data[pos..]) {
                Ok((chunk, consumed)) => {
                    let is_eot = data_processor.is_eot(&chunk);
                    chunks.push(chunk);
                    pos += consumed;
                    if is_eot {
                        break;
                    }
                }
                Err(_) => break,
            }
        }

        let payload = data_processor.decode(&chunks)?;

        Ok(Request {
            auth_info,
            command,
            data: payload,
        })
    }

    /// Get the user ID
    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }
}

/// Response parser for VMess client
pub struct ResponseParser {
    data_key: [u8; 16],
    data_iv: [u8; 16],
    expected_auth: u8,
    encryption_method: EncryptionMethod,
}

impl ResponseParser {
    /// Create a new response parser
    pub fn new(
        data_key: [u8; 16],
        data_iv: [u8; 16],
        expected_auth: u8,
        encryption_method: EncryptionMethod,
    ) -> Self {
        Self {
            data_key,
            data_iv,
            expected_auth,
            encryption_method,
        }
    }

    /// Create from a command (convenience method)
    pub fn from_command(command: &Command) -> Self {
        Self::new(
            command.data_key,
            command.data_iv,
            command.response_auth,
            command.encryption_method,
        )
    }

    /// Parse a VMess response
    pub fn parse(&self, data: &[u8]) -> Result<Response, ResponseError> {
        if data.len() < 4 {
            return Err(ResponseError::BufferTooShort);
        }

        // Derive header decryption key and IV
        let header_key = md5(&self.data_key);
        let header_iv = md5(&self.data_iv);

        // Decrypt header (first 4 bytes minimum)
        let cipher = Aes128Cfb::new(header_key, header_iv);
        let decrypted_header = cipher.decrypt(&data[..4]);

        // Parse header
        let response_auth = decrypted_header[0];
        let options = decrypted_header[1];
        let command = decrypted_header[2];
        let command_length = decrypted_header[3] as usize;

        // Verify response authentication
        if response_auth != self.expected_auth {
            return Err(ResponseError::AuthMismatch);
        }

        // Parse command content if present
        let (command_content, data_start) = if command_length > 0 {
            if data.len() < 4 + command_length {
                return Err(ResponseError::BufferTooShort);
            }
            let full_header = cipher.decrypt(&data[..4 + command_length]);
            let content = full_header[4..4 + command_length].to_vec();
            (Some(content), 4 + command_length)
        } else {
            (None, 4)
        };

        // Parse data section
        let data_processor = DataProcessor::new(
            self.encryption_method,
            self.data_key,
            self.data_iv,
        );

        let mut chunks = Vec::new();
        let mut pos = data_start;
        while pos < data.len() {
            match Chunk::from_bytes(&data[pos..]) {
                Ok((chunk, consumed)) => {
                    let is_eot = data_processor.is_eot(&chunk);
                    chunks.push(chunk);
                    pos += consumed;
                    if is_eot {
                        break;
                    }
                }
                Err(_) => break,
            }
        }

        let payload = data_processor.decode(&chunks).map_err(|e| {
            ResponseError::DecryptionFailed(e.to_string())
        })?;

        Ok(Response {
            response_auth,
            options,
            command,
            command_content,
            data: payload,
        })
    }

    /// Build a VMess response (for server implementation)
    pub fn build(&self, response_data: &[u8]) -> Result<Vec<u8>, ResponseError> {
        let mut result = Vec::new();

        // Build header
        let header = vec![
            self.expected_auth,
            0, // options
            0, // command
            0, // command length
        ];

        // Encrypt header
        let header_key = md5(&self.data_key);
        let header_iv = md5(&self.data_iv);
        let cipher = Aes128Cfb::new(header_key, header_iv);
        let encrypted_header = cipher.encrypt(&header);
        result.extend_from_slice(&encrypted_header);

        // Encode data section
        let data_processor = DataProcessor::new(
            self.encryption_method,
            self.data_key,
            self.data_iv,
        );
        let chunks = data_processor.encode(response_data).map_err(|e| {
            ResponseError::DecryptionFailed(e.to_string())
        })?;
        for chunk in chunks {
            result.extend_from_slice(&chunk.to_bytes());
        }

        Ok(result)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    fn test_user_id() -> UserId {
        UserId::from_str("de305d54-75b4-431b-adb2-eb6b9e546014").unwrap()
    }

    #[test]
    fn test_request_builder_build() {
        let builder = RequestBuilder::new(test_user_id());
        let (bytes, command) = builder
            .build(
                Address::IPv4([127, 0, 0, 1]),
                443,
                b"Hello, VMess!",
                EncryptionMethod::Aes128Gcm,
            )
            .unwrap();

        assert!(!bytes.is_empty());
        assert_eq!(command.port, 443);
        assert_eq!(command.encryption_method, EncryptionMethod::Aes128Gcm);
    }

    #[test]
    fn test_request_roundtrip() {
        let builder = RequestBuilder::new(test_user_id());
        let timestamp = 1234567890u64;
        let data = b"Test request data";

        let (bytes, _command) = builder
            .build_with_timestamp(
                Address::IPv4([192, 168, 1, 1]),
                8080,
                data,
                EncryptionMethod::Aes128Gcm,
                timestamp,
            )
            .unwrap();

        let parsed = builder.parse_at_time(&bytes, Some(timestamp)).unwrap();

        assert_eq!(parsed.data, data);
        assert_eq!(parsed.command.port, 8080);
    }

    #[test]
    fn test_request_with_domain() {
        let builder = RequestBuilder::new(test_user_id());
        let timestamp = 1234567890u64;
        let data = b"Domain test";

        let (bytes, _command) = builder
            .build_with_timestamp(
                Address::Domain("www.example.com".to_string()),
                443,
                data,
                EncryptionMethod::ChaCha20Poly1305,
                timestamp,
            )
            .unwrap();

        let parsed = builder.parse_at_time(&bytes, Some(timestamp)).unwrap();

        assert_eq!(parsed.data, data);
        if let Address::Domain(domain) = &parsed.command.address {
            assert_eq!(domain, "www.example.com");
        } else {
            panic!("Expected domain address");
        }
    }

    #[test]
    fn test_request_with_ipv6() {
        let builder = RequestBuilder::new(test_user_id());
        let timestamp = 1234567890u64;
        let data = b"IPv6 test";

        let (bytes, _command) = builder
            .build_with_timestamp(
                Address::IPv6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
                80,
                data,
                EncryptionMethod::Aes128Cfb,
                timestamp,
            )
            .unwrap();

        let parsed = builder.parse_at_time(&bytes, Some(timestamp)).unwrap();

        assert_eq!(parsed.data, data);
    }

    #[test]
    fn test_request_empty_data() {
        let builder = RequestBuilder::new(test_user_id());
        let timestamp = 1234567890u64;

        let (bytes, _command) = builder
            .build_with_timestamp(
                Address::IPv4([127, 0, 0, 1]),
                443,
                b"",
                EncryptionMethod::None,
                timestamp,
            )
            .unwrap();

        let parsed = builder.parse_at_time(&bytes, Some(timestamp)).unwrap();

        assert!(parsed.data.is_empty());
    }

    #[test]
    fn test_request_large_data() {
        let builder = RequestBuilder::new(test_user_id());
        let timestamp = 1234567890u64;
        let data: Vec<u8> = (0..50000).map(|i| (i % 256) as u8).collect();

        let (bytes, _command) = builder
            .build_with_timestamp(
                Address::IPv4([127, 0, 0, 1]),
                443,
                &data,
                EncryptionMethod::Aes128Gcm,
                timestamp,
            )
            .unwrap();

        let parsed = builder.parse_at_time(&bytes, Some(timestamp)).unwrap();

        assert_eq!(parsed.data, data);
    }

    #[test]
    fn test_request_wrong_user_id_fails() {
        let builder1 = RequestBuilder::new(test_user_id());
        let builder2 = RequestBuilder::new(
            UserId::from_str("de305d54-75b4-431b-adb2-eb6b9e546015").unwrap()
        );
        let timestamp = 1234567890u64;

        let (bytes, _command) = builder1
            .build_with_timestamp(
                Address::IPv4([127, 0, 0, 1]),
                443,
                b"Test",
                EncryptionMethod::Aes128Gcm,
                timestamp,
            )
            .unwrap();

        let result = builder2.parse_at_time(&bytes, Some(timestamp));
        assert!(result.is_err());
    }

    #[test]
    fn test_response_parser_roundtrip() {
        let command = Command {
            version: 1,
            data_iv: [1u8; 16],
            data_key: [2u8; 16],
            response_auth: 0x42,
            options: CommandOptions::default(),
            encryption_method: EncryptionMethod::Aes128Gcm,
            command_type: CommandType::Tcp,
            port: 443,
            address: Address::IPv4([127, 0, 0, 1]),
        };

        let parser = ResponseParser::from_command(&command);
        let response_data = b"Response from server";

        let bytes = parser.build(response_data).unwrap();
        let parsed = parser.parse(&bytes).unwrap();

        assert_eq!(parsed.response_auth, command.response_auth);
        assert_eq!(parsed.data, response_data);
    }

    #[test]
    fn test_response_wrong_auth_fails() {
        let command = Command {
            version: 1,
            data_iv: [1u8; 16],
            data_key: [2u8; 16],
            response_auth: 0x42,
            options: CommandOptions::default(),
            encryption_method: EncryptionMethod::Aes128Gcm,
            command_type: CommandType::Tcp,
            port: 443,
            address: Address::IPv4([127, 0, 0, 1]),
        };

        let builder = ResponseParser::from_command(&command);
        let bytes = builder.build(b"Test").unwrap();

        // Create parser with wrong expected auth
        let wrong_parser = ResponseParser::new(
            command.data_key,
            command.data_iv,
            0x99, // Wrong auth
            command.encryption_method,
        );

        let result = wrong_parser.parse(&bytes);
        assert!(matches!(result, Err(ResponseError::AuthMismatch)));
    }

    #[test]
    fn test_response_empty_data() {
        let command = Command {
            version: 1,
            data_iv: [3u8; 16],
            data_key: [4u8; 16],
            response_auth: 0x55,
            options: CommandOptions::default(),
            encryption_method: EncryptionMethod::None,
            command_type: CommandType::Tcp,
            port: 80,
            address: Address::IPv4([127, 0, 0, 1]),
        };

        let parser = ResponseParser::from_command(&command);
        let bytes = parser.build(b"").unwrap();
        let parsed = parser.parse(&bytes).unwrap();

        assert!(parsed.data.is_empty());
    }

    #[test]
    fn test_all_encryption_methods() {
        let methods = [
            EncryptionMethod::None,
            EncryptionMethod::Aes128Cfb,
            EncryptionMethod::Aes128Gcm,
            EncryptionMethod::ChaCha20Poly1305,
        ];

        for method in methods {
            let builder = RequestBuilder::new(test_user_id());
            let timestamp = 1234567890u64;
            let data = b"Testing encryption method";

            let (bytes, _command) = builder
                .build_with_timestamp(
                    Address::IPv4([127, 0, 0, 1]),
                    443,
                    data,
                    method,
                    timestamp,
                )
                .unwrap();

            let parsed = builder.parse_at_time(&bytes, Some(timestamp)).unwrap();
            assert_eq!(parsed.data, data, "Failed for {:?}", method);
        }
    }
}
