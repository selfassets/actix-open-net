//! VMess subscription link generation and parsing
//!
//! Generates and parses VMess subscription links in V2Ray standard format.
//! Format: vmess://base64(json)

use crate::config::VmessConfig;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Error type for link operations
#[derive(Debug, Error)]
pub enum LinkError {
    #[error("Invalid link format: missing vmess:// prefix")]
    InvalidPrefix,
    #[error("Base64 decode error: {0}")]
    Base64Error(String),
    #[error("JSON parse error: {0}")]
    JsonError(String),
}

/// V2Ray standard VMess link JSON format (version 2)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct VmessLinkJson {
    /// Version, always "2"
    pub v: String,
    /// Remarks/name
    pub ps: String,
    /// Server address
    pub add: String,
    /// Server port (as string)
    pub port: String,
    /// User UUID
    pub id: String,
    /// Alter ID, always "0"
    pub aid: String,
    /// Security/encryption method
    pub scy: String,
    /// Network type, always "tcp"
    pub net: String,
    /// Header type, always "none"
    #[serde(rename = "type")]
    pub header_type: String,
    /// Host (empty for tcp)
    pub host: String,
    /// Path (empty for tcp)
    pub path: String,
    /// TLS setting (empty for no TLS)
    pub tls: String,
}

impl VmessLinkJson {
    /// Create from VmessConfig
    pub fn from_config(config: &VmessConfig) -> Self {
        let ps = config
            .name
            .clone()
            .unwrap_or_else(|| format!("{}:{}", config.server_address, config.server_port));

        Self {
            v: "2".to_string(),
            ps,
            add: config.server_address.clone(),
            port: config.server_port.to_string(),
            id: config.user_id.clone(),
            aid: "0".to_string(),
            scy: config.encryption.clone(),
            net: "tcp".to_string(),
            header_type: "none".to_string(),
            host: String::new(),
            path: String::new(),
            tls: String::new(),
        }
    }
}

/// Generate VMess subscription link from config
///
/// Returns a string in format: vmess://base64(json)
pub fn generate_link(config: &VmessConfig) -> String {
    let link_json = VmessLinkJson::from_config(config);
    let json_str = serde_json::to_string(&link_json).expect("Failed to serialize link JSON");
    let encoded = STANDARD.encode(json_str.as_bytes());
    format!("vmess://{}", encoded)
}

/// Parse VMess subscription link back to VmessLinkJson
///
/// Expects format: vmess://base64(json)
pub fn parse_link(link: &str) -> Result<VmessLinkJson, LinkError> {
    // Check prefix
    let base64_part = link
        .strip_prefix("vmess://")
        .ok_or(LinkError::InvalidPrefix)?;

    // Decode base64
    let decoded_bytes = STANDARD
        .decode(base64_part)
        .map_err(|e| LinkError::Base64Error(e.to_string()))?;

    // Parse JSON
    let json_str =
        String::from_utf8(decoded_bytes).map_err(|e| LinkError::Base64Error(e.to_string()))?;

    serde_json::from_str(&json_str).map_err(|e| LinkError::JsonError(e.to_string()))
}

/// Check if a string is valid standard Base64
pub fn is_valid_base64(s: &str) -> bool {
    // Standard Base64 characters: A-Z, a-z, 0-9, +, /, and = for padding
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_link_basic() {
        let config = VmessConfig::new(
            "de305d54-75b4-431b-adb2-eb6b9e546014".to_string(),
            "127.0.0.1".to_string(),
            10086,
            "aes-128-gcm".to_string(),
        );

        let link = generate_link(&config);
        assert!(link.starts_with("vmess://"));
    }

    #[test]
    fn test_generate_link_with_name() {
        let config = VmessConfig::with_name(
            "de305d54-75b4-431b-adb2-eb6b9e546014".to_string(),
            "example.com".to_string(),
            443,
            "chacha20-poly1305".to_string(),
            "My Server".to_string(),
        );

        let link = generate_link(&config);
        let parsed = parse_link(&link).unwrap();
        assert_eq!(parsed.ps, "My Server");
    }

    #[test]
    fn test_generate_link_default_name() {
        let config = VmessConfig::new(
            "de305d54-75b4-431b-adb2-eb6b9e546014".to_string(),
            "example.com".to_string(),
            443,
            "aes-128-gcm".to_string(),
        );

        let link = generate_link(&config);
        let parsed = parse_link(&link).unwrap();
        assert_eq!(parsed.ps, "example.com:443");
    }

    #[test]
    fn test_parse_link_roundtrip() {
        let config = VmessConfig::with_name(
            "de305d54-75b4-431b-adb2-eb6b9e546014".to_string(),
            "test.example.com".to_string(),
            8080,
            "aes-128-cfb".to_string(),
            "Test Server".to_string(),
        );

        let link = generate_link(&config);
        let parsed = parse_link(&link).unwrap();

        assert_eq!(parsed.v, "2");
        assert_eq!(parsed.ps, "Test Server");
        assert_eq!(parsed.add, "test.example.com");
        assert_eq!(parsed.port, "8080");
        assert_eq!(parsed.id, "de305d54-75b4-431b-adb2-eb6b9e546014");
        assert_eq!(parsed.aid, "0");
        assert_eq!(parsed.scy, "aes-128-cfb");
        assert_eq!(parsed.net, "tcp");
        assert_eq!(parsed.header_type, "none");
    }

    #[test]
    fn test_parse_link_invalid_prefix() {
        let result = parse_link("http://invalid");
        assert!(matches!(result, Err(LinkError::InvalidPrefix)));
    }

    #[test]
    fn test_parse_link_invalid_base64() {
        let result = parse_link("vmess://!!!invalid!!!");
        assert!(matches!(result, Err(LinkError::Base64Error(_))));
    }

    #[test]
    fn test_link_uses_standard_base64() {
        let config = VmessConfig::new(
            "de305d54-75b4-431b-adb2-eb6b9e546014".to_string(),
            "127.0.0.1".to_string(),
            10086,
            "aes-128-gcm".to_string(),
        );

        let link = generate_link(&config);
        let base64_part = link.strip_prefix("vmess://").unwrap();
        assert!(is_valid_base64(base64_part));
    }

    #[test]
    fn test_all_encryption_methods() {
        let methods = ["none", "aes-128-cfb", "aes-128-gcm", "chacha20-poly1305"];

        for method in methods {
            let config = VmessConfig::new(
                "de305d54-75b4-431b-adb2-eb6b9e546014".to_string(),
                "127.0.0.1".to_string(),
                443,
                method.to_string(),
            );

            let link = generate_link(&config);
            let parsed = parse_link(&link).unwrap();
            assert_eq!(parsed.scy, method);
        }
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    // Strategy for generating valid UUIDs
    fn uuid_strategy() -> impl Strategy<Value = String> {
        "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    }

    // Strategy for generating server addresses
    fn address_strategy() -> impl Strategy<Value = String> {
        prop_oneof![
            // IPv4
            (1u8..255, 0u8..255, 0u8..255, 1u8..255)
                .prop_map(|(a, b, c, d)| format!("{}.{}.{}.{}", a, b, c, d)),
            // Domain
            "[a-z]{3,10}\\.[a-z]{2,5}",
        ]
    }

    // Strategy for encryption methods
    fn encryption_strategy() -> impl Strategy<Value = String> {
        prop_oneof![
            Just("none".to_string()),
            Just("aes-128-cfb".to_string()),
            Just("aes-128-gcm".to_string()),
            Just("chacha20-poly1305".to_string()),
        ]
    }

    // Strategy for optional name
    fn name_strategy() -> impl Strategy<Value = Option<String>> {
        prop_oneof![Just(None), "[a-zA-Z0-9 ]{1,20}".prop_map(Some),]
    }

    // Strategy for generating valid VmessConfig
    fn config_strategy() -> impl Strategy<Value = VmessConfig> {
        (
            uuid_strategy(),
            address_strategy(),
            1u16..65535,
            encryption_strategy(),
            name_strategy(),
        )
            .prop_map(|(user_id, server_address, server_port, encryption, name)| {
                let mut config = VmessConfig::new(user_id, server_address, server_port, encryption);
                config.name = name;
                config
            })
    }

    proptest! {
        /// Feature: vmess-subscription-link, Property 1: Link Format Validity
        /// For any valid VmessConfig, the generated subscription link SHALL start with
        /// "vmess://" and the remainder SHALL be valid standard Base64.
        /// **Validates: Requirements 1.1, 1.3, 2.2**
        #[test]
        fn prop_link_format_validity(config in config_strategy()) {
            let link = generate_link(&config);

            // Must start with vmess://
            prop_assert!(link.starts_with("vmess://"), "Link must start with vmess://");

            // Remainder must be valid Base64
            let base64_part = link.strip_prefix("vmess://").unwrap();
            prop_assert!(is_valid_base64(base64_part), "Base64 part must be valid standard Base64");

            // Must be decodable
            prop_assert!(parse_link(&link).is_ok(), "Link must be parseable");
        }

        /// Feature: vmess-subscription-link, Property 2: Round-Trip Encoding
        /// For any valid VmessConfig, encoding to a subscription link and then decoding
        /// the Base64 SHALL produce valid JSON containing all required fields.
        /// **Validates: Requirements 1.2, 1.4, 2.1**
        #[test]
        fn prop_roundtrip_encoding(config in config_strategy()) {
            let link = generate_link(&config);
            let parsed = parse_link(&link).expect("Should parse successfully");

            // Check all required fields exist and have correct types
            prop_assert_eq!(parsed.v, "2", "Version must be '2'");
            prop_assert!(!parsed.ps.is_empty(), "ps (remarks) must not be empty");
            prop_assert!(!parsed.add.is_empty(), "add (address) must not be empty");
            prop_assert!(!parsed.port.is_empty(), "port must not be empty");
            prop_assert!(!parsed.id.is_empty(), "id (user_id) must not be empty");
            prop_assert_eq!(parsed.aid, "0", "aid must be '0'");
            prop_assert!(!parsed.scy.is_empty(), "scy (encryption) must not be empty");
            prop_assert_eq!(parsed.net, "tcp", "net must be 'tcp'");
            prop_assert_eq!(parsed.header_type, "none", "type must be 'none'");
        }

        /// Feature: vmess-subscription-link, Property 3: Remarks Field Correctness
        /// For any VmessConfig:
        /// - If name is Some(value), the ps field SHALL equal value
        /// - If name is None, the ps field SHALL equal {server_address}:{server_port}
        /// **Validates: Requirements 3.1, 3.2, 3.3**
        #[test]
        fn prop_remarks_field_correctness(config in config_strategy()) {
            let link = generate_link(&config);
            let parsed = parse_link(&link).expect("Should parse successfully");

            match &config.name {
                Some(name) => {
                    prop_assert_eq!(&parsed.ps, name, "ps should equal config.name when provided");
                }
                None => {
                    let expected = format!("{}:{}", config.server_address, config.server_port);
                    prop_assert_eq!(parsed.ps, expected, "ps should be address:port when name is None");
                }
            }
        }

        /// Feature: vmess-subscription-link, Property 4: Field Value Preservation
        /// For any VmessConfig, the generated link's decoded JSON SHALL have:
        /// - add equal to config.server_address
        /// - port equal to config.server_port.to_string()
        /// - id equal to config.user_id
        /// - scy equal to config.encryption
        /// **Validates: Requirements 1.4, 2.1**
        #[test]
        fn prop_field_value_preservation(config in config_strategy()) {
            let link = generate_link(&config);
            let parsed = parse_link(&link).expect("Should parse successfully");

            prop_assert_eq!(parsed.add, config.server_address, "add must equal server_address");
            prop_assert_eq!(parsed.port, config.server_port.to_string(), "port must equal server_port");
            prop_assert_eq!(parsed.id, config.user_id, "id must equal user_id");
            prop_assert_eq!(parsed.scy, config.encryption, "scy must equal encryption");
        }
    }
}
