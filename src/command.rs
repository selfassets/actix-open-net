//! Command section encoding/decoding for VMess protocol
//!
//! The command section contains encryption parameters, target address,
//! and other metadata needed for the VMess connection.

use crate::crypto::{fnv1a_32, md5, Aes128Cfb};
use crate::user_id::UserId;
use rand::{thread_rng, Rng};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CommandError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("Invalid checksum")]
    InvalidChecksum,
    #[error("Invalid address type: {0}")]
    InvalidAddressType(u8),
    #[error("Buffer too short")]
    BufferTooShort,
    #[error("Invalid encryption method: {0}")]
    InvalidEncryptionMethod(u8),
    #[error("Invalid command type: {0}")]
    InvalidCommandType(u8),
    #[error("Domain name too long: {0} bytes")]
    DomainTooLong(usize),
}

/// Encryption method for data section
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EncryptionMethod {
    None = 0x00,
    Aes128Cfb = 0x01,
    Aes128Gcm = 0x03,
    ChaCha20Poly1305 = 0x04,
}

impl EncryptionMethod {
    pub fn from_u8(value: u8) -> Result<Self, CommandError> {
        match value {
            0x00 => Ok(Self::None),
            0x01 => Ok(Self::Aes128Cfb),
            0x03 => Ok(Self::Aes128Gcm),
            0x04 => Ok(Self::ChaCha20Poly1305),
            _ => Err(CommandError::InvalidEncryptionMethod(value)),
        }
    }
}

/// Command type (TCP or UDP)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CommandType {
    Tcp = 0x01,
    Udp = 0x02,
}

impl CommandType {
    pub fn from_u8(value: u8) -> Result<Self, CommandError> {
        match value {
            0x01 => Ok(Self::Tcp),
            0x02 => Ok(Self::Udp),
            _ => Err(CommandError::InvalidCommandType(value)),
        }
    }
}

/// Address type constants
const ADDR_TYPE_IPV4: u8 = 0x01;
const ADDR_TYPE_DOMAIN: u8 = 0x02;
const ADDR_TYPE_IPV6: u8 = 0x03;

/// Target address
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Address {
    IPv4([u8; 4]),
    Domain(String),
    IPv6([u8; 16]),
}

impl Address {
    /// Get the address type byte
    pub fn type_byte(&self) -> u8 {
        match self {
            Address::IPv4(_) => ADDR_TYPE_IPV4,
            Address::Domain(_) => ADDR_TYPE_DOMAIN,
            Address::IPv6(_) => ADDR_TYPE_IPV6,
        }
    }

    /// Get the encoded length of the address
    pub fn encoded_len(&self) -> usize {
        match self {
            Address::IPv4(_) => 4,
            Address::Domain(s) => 1 + s.len(), // 1 byte length + domain
            Address::IPv6(_) => 16,
        }
    }
}

/// Command options (Opt byte)
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct CommandOptions {
    pub standard_format: bool,  // Opt(S) - bit 0
    pub reuse_connection: bool, // Opt(R) - bit 1
    pub metadata: bool,         // Opt(M) - bit 2
}

impl CommandOptions {
    pub fn to_byte(&self) -> u8 {
        let mut opt = 0u8;
        if self.standard_format {
            opt |= 0x01;
        }
        if self.reuse_connection {
            opt |= 0x02;
        }
        if self.metadata {
            opt |= 0x04;
        }
        opt
    }

    pub fn from_byte(byte: u8) -> Self {
        Self {
            standard_format: (byte & 0x01) != 0,
            reuse_connection: (byte & 0x02) != 0,
            metadata: (byte & 0x04) != 0,
        }
    }
}

/// VMess command section
#[derive(Clone, Debug, PartialEq)]
pub struct Command {
    pub version: u8,
    pub data_iv: [u8; 16],
    pub data_key: [u8; 16],
    pub response_auth: u8,
    pub options: CommandOptions,
    pub encryption_method: EncryptionMethod,
    pub command_type: CommandType,
    pub port: u16,
    pub address: Address,
}

impl Command {
    /// Create a new command with random IV and key
    pub fn new(
        address: Address,
        port: u16,
        encryption_method: EncryptionMethod,
        command_type: CommandType,
    ) -> Self {
        let mut rng = thread_rng();
        let mut data_iv = [0u8; 16];
        let mut data_key = [0u8; 16];
        rng.fill(&mut data_iv);
        rng.fill(&mut data_key);

        Self {
            version: 1,
            data_iv,
            data_key,
            response_auth: rng.gen(),
            options: CommandOptions {
                standard_format: true,
                reuse_connection: false,
                metadata: false,
            },
            encryption_method,
            command_type,
            port,
            address,
        }
    }
}

/// Command encoder/decoder
pub struct CommandCodec {
    user_id: UserId,
}

impl CommandCodec {
    pub fn new(user_id: UserId) -> Self {
        Self { user_id }
    }

    /// Encode command section with AES-128-CFB encryption
    ///
    /// The command is encrypted using:
    /// - Key: MD5(User_ID)
    /// - IV: MD5(timestamp bytes)
    pub fn encode(&self, cmd: &Command, timestamp: u64) -> Result<Vec<u8>, CommandError> {
        // Build plaintext command
        let plaintext = self.build_plaintext(cmd)?;

        // Derive encryption key and IV
        let key = md5(self.user_id.as_bytes());
        let iv = md5(&timestamp.to_be_bytes());

        // Encrypt
        let cipher = Aes128Cfb::new(key, iv);
        Ok(cipher.encrypt(&plaintext))
    }

    /// Decode command section
    /// Returns the command and the number of bytes consumed
    pub fn decode(&self, data: &[u8], timestamp: u64) -> Result<Command, CommandError> {
        // Derive decryption key and IV
        let key = md5(self.user_id.as_bytes());
        let iv = md5(&timestamp.to_be_bytes());

        // Decrypt
        let cipher = Aes128Cfb::new(key, iv);
        let plaintext = cipher.decrypt(data);

        // Parse plaintext
        self.parse_plaintext(&plaintext)
    }

    /// Decode command section and return bytes consumed
    pub fn decode_with_length(
        &self,
        data: &[u8],
        timestamp: u64,
    ) -> Result<(Command, usize), CommandError> {
        // Derive decryption key and IV
        let key = md5(self.user_id.as_bytes());
        let iv = md5(&timestamp.to_be_bytes());

        // Decrypt
        let cipher = Aes128Cfb::new(key, iv);
        let plaintext = cipher.decrypt(data);

        // Parse plaintext and get length
        let (cmd, len) = self.parse_plaintext_with_length(&plaintext)?;
        Ok((cmd, len))
    }

    /// Build plaintext command bytes
    fn build_plaintext(&self, cmd: &Command) -> Result<Vec<u8>, CommandError> {
        let mut buf = Vec::with_capacity(128);

        // Version (1 byte)
        buf.push(cmd.version);

        // Data encryption IV (16 bytes)
        buf.extend_from_slice(&cmd.data_iv);

        // Data encryption key (16 bytes)
        buf.extend_from_slice(&cmd.data_key);

        // Response authentication (1 byte)
        buf.push(cmd.response_auth);

        // Options (1 byte)
        buf.push(cmd.options.to_byte());

        // Padding length (4 bits) + Encryption method (4 bits)
        let padding_len = thread_rng().gen_range(0..16u8);
        let sec_byte = (padding_len << 4) | (cmd.encryption_method as u8);
        buf.push(sec_byte);

        // Reserved (1 byte)
        buf.push(0);

        // Command type (1 byte)
        buf.push(cmd.command_type as u8);

        // Port (2 bytes, big-endian)
        buf.extend_from_slice(&cmd.port.to_be_bytes());

        // Address type (1 byte)
        buf.push(cmd.address.type_byte());

        // Address
        match &cmd.address {
            Address::IPv4(ip) => buf.extend_from_slice(ip),
            Address::Domain(domain) => {
                if domain.len() > 255 {
                    return Err(CommandError::DomainTooLong(domain.len()));
                }
                buf.push(domain.len() as u8);
                buf.extend_from_slice(domain.as_bytes());
            }
            Address::IPv6(ip) => buf.extend_from_slice(ip),
        }

        // Random padding
        let padding: Vec<u8> = (0..padding_len).map(|_| thread_rng().gen()).collect();
        buf.extend_from_slice(&padding);

        // Checksum (FNV1a of all previous bytes)
        let checksum = fnv1a_32(&buf);
        buf.extend_from_slice(&checksum.to_be_bytes());

        Ok(buf)
    }

    /// Parse plaintext command bytes
    fn parse_plaintext(&self, data: &[u8]) -> Result<Command, CommandError> {
        let (cmd, _) = self.parse_plaintext_with_length(data)?;
        Ok(cmd)
    }

    /// Parse plaintext command bytes and return consumed length
    fn parse_plaintext_with_length(&self, data: &[u8]) -> Result<(Command, usize), CommandError> {
        if data.len() < 41 {
            // Minimum: 1 + 16 + 16 + 1 + 1 + 1 + 1 + 1 + 2 + 1 + 0 (no addr) = 41
            return Err(CommandError::BufferTooShort);
        }

        let mut pos = 0;

        // Version
        let version = data[pos];
        pos += 1;

        // Data IV
        let mut data_iv = [0u8; 16];
        data_iv.copy_from_slice(&data[pos..pos + 16]);
        pos += 16;

        // Data Key
        let mut data_key = [0u8; 16];
        data_key.copy_from_slice(&data[pos..pos + 16]);
        pos += 16;

        // Response auth
        let response_auth = data[pos];
        pos += 1;

        // Options
        let options = CommandOptions::from_byte(data[pos]);
        pos += 1;

        // Padding length + Encryption method
        let sec_byte = data[pos];
        let padding_len = (sec_byte >> 4) as usize;
        let encryption_method = EncryptionMethod::from_u8(sec_byte & 0x0F)?;
        pos += 1;

        // Reserved
        pos += 1;

        // Command type
        let command_type = CommandType::from_u8(data[pos])?;
        pos += 1;

        // Port
        if pos + 2 > data.len() {
            return Err(CommandError::BufferTooShort);
        }
        let port = u16::from_be_bytes([data[pos], data[pos + 1]]);
        pos += 2;

        // Address type
        if pos >= data.len() {
            return Err(CommandError::BufferTooShort);
        }
        let addr_type = data[pos];
        pos += 1;

        // Address
        let address = match addr_type {
            ADDR_TYPE_IPV4 => {
                if pos + 4 > data.len() {
                    return Err(CommandError::BufferTooShort);
                }
                let mut ip = [0u8; 4];
                ip.copy_from_slice(&data[pos..pos + 4]);
                pos += 4;
                Address::IPv4(ip)
            }
            ADDR_TYPE_DOMAIN => {
                if pos >= data.len() {
                    return Err(CommandError::BufferTooShort);
                }
                let domain_len = data[pos] as usize;
                pos += 1;
                if pos + domain_len > data.len() {
                    return Err(CommandError::BufferTooShort);
                }
                let domain = String::from_utf8_lossy(&data[pos..pos + domain_len]).to_string();
                pos += domain_len;
                Address::Domain(domain)
            }
            ADDR_TYPE_IPV6 => {
                if pos + 16 > data.len() {
                    return Err(CommandError::BufferTooShort);
                }
                let mut ip = [0u8; 16];
                ip.copy_from_slice(&data[pos..pos + 16]);
                pos += 16;
                Address::IPv6(ip)
            }
            _ => return Err(CommandError::InvalidAddressType(addr_type)),
        };

        // Skip padding
        pos += padding_len;

        // Verify checksum
        if pos + 4 > data.len() {
            return Err(CommandError::BufferTooShort);
        }
        let expected_checksum = fnv1a_32(&data[..pos]);
        let actual_checksum =
            u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);

        if expected_checksum != actual_checksum {
            return Err(CommandError::InvalidChecksum);
        }

        // Total consumed length includes checksum
        let total_len = pos + 4;

        Ok((
            Command {
                version,
                data_iv,
                data_key,
                response_auth,
                options,
                encryption_method,
                command_type,
                port,
                address,
            },
            total_len,
        ))
    }

    /// Format command as human-readable string
    pub fn pretty_print(cmd: &Command) -> String {
        let addr_str = match &cmd.address {
            Address::IPv4(ip) => format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]),
            Address::Domain(d) => d.clone(),
            Address::IPv6(ip) => {
                let parts: Vec<String> = ip
                    .chunks(2)
                    .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
                    .collect();
                parts.join(":")
            }
        };

        let enc_str = match cmd.encryption_method {
            EncryptionMethod::None => "none",
            EncryptionMethod::Aes128Cfb => "aes-128-cfb",
            EncryptionMethod::Aes128Gcm => "aes-128-gcm",
            EncryptionMethod::ChaCha20Poly1305 => "chacha20-poly1305",
        };

        let cmd_str = match cmd.command_type {
            CommandType::Tcp => "TCP",
            CommandType::Udp => "UDP",
        };

        format!(
            "VMess Command v{}\n\
             Target: {}:{} ({})\n\
             Encryption: {}\n\
             Options: S={} R={} M={}",
            cmd.version,
            addr_str,
            cmd.port,
            cmd_str,
            enc_str,
            cmd.options.standard_format,
            cmd.options.reuse_connection,
            cmd.options.metadata
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn test_user_id() -> UserId {
        UserId::from_str("de305d54-75b4-431b-adb2-eb6b9e546014").unwrap()
    }

    #[test]
    fn test_command_options_roundtrip() {
        let opts = CommandOptions {
            standard_format: true,
            reuse_connection: false,
            metadata: true,
        };
        let byte = opts.to_byte();
        let parsed = CommandOptions::from_byte(byte);
        assert_eq!(opts, parsed);
    }

    #[test]
    fn test_encryption_method_from_u8() {
        assert_eq!(
            EncryptionMethod::from_u8(0x00).unwrap(),
            EncryptionMethod::None
        );
        assert_eq!(
            EncryptionMethod::from_u8(0x01).unwrap(),
            EncryptionMethod::Aes128Cfb
        );
        assert_eq!(
            EncryptionMethod::from_u8(0x03).unwrap(),
            EncryptionMethod::Aes128Gcm
        );
        assert_eq!(
            EncryptionMethod::from_u8(0x04).unwrap(),
            EncryptionMethod::ChaCha20Poly1305
        );
        assert!(EncryptionMethod::from_u8(0x02).is_err());
    }

    #[test]
    fn test_command_type_from_u8() {
        assert_eq!(CommandType::from_u8(0x01).unwrap(), CommandType::Tcp);
        assert_eq!(CommandType::from_u8(0x02).unwrap(), CommandType::Udp);
        assert!(CommandType::from_u8(0x03).is_err());
    }

    #[test]
    fn test_address_type_byte() {
        assert_eq!(Address::IPv4([127, 0, 0, 1]).type_byte(), ADDR_TYPE_IPV4);
        assert_eq!(
            Address::Domain("example.com".to_string()).type_byte(),
            ADDR_TYPE_DOMAIN
        );
        assert_eq!(Address::IPv6([0u8; 16]).type_byte(), ADDR_TYPE_IPV6);
    }

    #[test]
    fn test_encode_decode_ipv4() {
        let codec = CommandCodec::new(test_user_id());
        let cmd = Command {
            version: 1,
            data_iv: [1u8; 16],
            data_key: [2u8; 16],
            response_auth: 0x42,
            options: CommandOptions {
                standard_format: true,
                reuse_connection: false,
                metadata: false,
            },
            encryption_method: EncryptionMethod::Aes128Gcm,
            command_type: CommandType::Tcp,
            port: 443,
            address: Address::IPv4([192, 168, 1, 1]),
        };

        let timestamp = 1234567890u64;
        let encoded = codec.encode(&cmd, timestamp).unwrap();
        let decoded = codec.decode(&encoded, timestamp).unwrap();

        assert_eq!(decoded.version, cmd.version);
        assert_eq!(decoded.data_iv, cmd.data_iv);
        assert_eq!(decoded.data_key, cmd.data_key);
        assert_eq!(decoded.response_auth, cmd.response_auth);
        assert_eq!(decoded.options, cmd.options);
        assert_eq!(decoded.encryption_method, cmd.encryption_method);
        assert_eq!(decoded.command_type, cmd.command_type);
        assert_eq!(decoded.port, cmd.port);
        assert_eq!(decoded.address, cmd.address);
    }

    #[test]
    fn test_encode_decode_domain() {
        let codec = CommandCodec::new(test_user_id());
        let cmd = Command {
            version: 1,
            data_iv: [3u8; 16],
            data_key: [4u8; 16],
            response_auth: 0x55,
            options: CommandOptions::default(),
            encryption_method: EncryptionMethod::ChaCha20Poly1305,
            command_type: CommandType::Tcp,
            port: 80,
            address: Address::Domain("www.example.com".to_string()),
        };

        let timestamp = 9876543210u64;
        let encoded = codec.encode(&cmd, timestamp).unwrap();
        let decoded = codec.decode(&encoded, timestamp).unwrap();

        assert_eq!(decoded.address, cmd.address);
        assert_eq!(decoded.port, cmd.port);
    }

    #[test]
    fn test_encode_decode_ipv6() {
        let codec = CommandCodec::new(test_user_id());
        let cmd = Command {
            version: 1,
            data_iv: [5u8; 16],
            data_key: [6u8; 16],
            response_auth: 0xAA,
            options: CommandOptions {
                standard_format: true,
                reuse_connection: true,
                metadata: true,
            },
            encryption_method: EncryptionMethod::None,
            command_type: CommandType::Udp,
            port: 8080,
            address: Address::IPv6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
        };

        let timestamp = 1111111111u64;
        let encoded = codec.encode(&cmd, timestamp).unwrap();
        let decoded = codec.decode(&encoded, timestamp).unwrap();

        assert_eq!(decoded.address, cmd.address);
        assert_eq!(decoded.command_type, cmd.command_type);
    }

    #[test]
    fn test_wrong_timestamp_fails() {
        let codec = CommandCodec::new(test_user_id());
        let cmd = Command::new(
            Address::IPv4([127, 0, 0, 1]),
            443,
            EncryptionMethod::Aes128Gcm,
            CommandType::Tcp,
        );

        let encoded = codec.encode(&cmd, 1000).unwrap();
        // Decode with different timestamp - checksum will fail
        let result = codec.decode(&encoded, 2000);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_user_id_fails() {
        let user_id1 = UserId::from_str("de305d54-75b4-431b-adb2-eb6b9e546014").unwrap();
        let user_id2 = UserId::from_str("de305d54-75b4-431b-adb2-eb6b9e546015").unwrap();

        let codec1 = CommandCodec::new(user_id1);
        let codec2 = CommandCodec::new(user_id2);

        let cmd = Command::new(
            Address::IPv4([127, 0, 0, 1]),
            443,
            EncryptionMethod::Aes128Gcm,
            CommandType::Tcp,
        );

        let timestamp = 1234567890u64;
        let encoded = codec1.encode(&cmd, timestamp).unwrap();
        // Decode with different user ID - will produce garbage
        let result = codec2.decode(&encoded, timestamp);
        assert!(result.is_err());
    }

    #[test]
    fn test_pretty_print_ipv4() {
        let cmd = Command {
            version: 1,
            data_iv: [0u8; 16],
            data_key: [0u8; 16],
            response_auth: 0,
            options: CommandOptions {
                standard_format: true,
                reuse_connection: false,
                metadata: false,
            },
            encryption_method: EncryptionMethod::Aes128Gcm,
            command_type: CommandType::Tcp,
            port: 443,
            address: Address::IPv4([192, 168, 1, 1]),
        };

        let output = CommandCodec::pretty_print(&cmd);
        assert!(output.contains("192.168.1.1:443"));
        assert!(output.contains("TCP"));
        assert!(output.contains("aes-128-gcm"));
    }

    #[test]
    fn test_pretty_print_domain() {
        let cmd = Command {
            version: 1,
            data_iv: [0u8; 16],
            data_key: [0u8; 16],
            response_auth: 0,
            options: CommandOptions::default(),
            encryption_method: EncryptionMethod::ChaCha20Poly1305,
            command_type: CommandType::Udp,
            port: 53,
            address: Address::Domain("dns.google".to_string()),
        };

        let output = CommandCodec::pretty_print(&cmd);
        assert!(output.contains("dns.google:53"));
        assert!(output.contains("UDP"));
        assert!(output.contains("chacha20-poly1305"));
    }

    #[test]
    fn test_truncated_data_fails() {
        let codec = CommandCodec::new(test_user_id());
        let cmd = Command::new(
            Address::IPv4([127, 0, 0, 1]),
            443,
            EncryptionMethod::Aes128Gcm,
            CommandType::Tcp,
        );

        let timestamp = 1234567890u64;
        let encoded = codec.encode(&cmd, timestamp).unwrap();

        // Truncate the data
        let truncated = &encoded[..encoded.len() - 10];
        let result = codec.decode(truncated, timestamp);
        assert!(result.is_err());
    }

    #[test]
    fn test_command_new_generates_random_values() {
        let cmd1 = Command::new(
            Address::IPv4([127, 0, 0, 1]),
            443,
            EncryptionMethod::Aes128Gcm,
            CommandType::Tcp,
        );
        let cmd2 = Command::new(
            Address::IPv4([127, 0, 0, 1]),
            443,
            EncryptionMethod::Aes128Gcm,
            CommandType::Tcp,
        );

        // Random values should be different
        assert_ne!(cmd1.data_iv, cmd2.data_iv);
        assert_ne!(cmd1.data_key, cmd2.data_key);
    }
}
