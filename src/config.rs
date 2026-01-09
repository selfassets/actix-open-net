//! Configuration management for VMess protocol
//!
//! Handles parsing, validation, and serialization of VMess configuration.

use crate::command::EncryptionMethod;
use crate::user_id::{UserId, UserIdError};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("JSON parse error: {0}")]
    ParseError(String),
    #[error("Invalid user ID: {0}")]
    InvalidUserId(String),
    #[error("Invalid server address: {0}")]
    InvalidServerAddress(String),
    #[error("Invalid encryption method: {0}")]
    InvalidEncryption(String),
    #[error("Invalid port: {0}")]
    InvalidPort(u16),
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

impl From<UserIdError> for ConfigError {
    fn from(e: UserIdError) -> Self {
        ConfigError::InvalidUserId(e.to_string())
    }
}

fn default_timeout() -> u64 {
    30
}
fn default_time_window() -> u64 {
    120
}

/// Configuration options
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConfigOptions {
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
    #[serde(default = "default_time_window")]
    pub auth_time_window_seconds: u64,
    /// Enable TLS on the server
    #[serde(default)]
    pub tls_enabled: bool,
    /// Path to TLS certificate file (PEM format)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_cert_path: Option<String>,
    /// Path to TLS private key file (PEM format)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_key_path: Option<String>,
    /// Mark TLS in subscription link (for external TLS termination like platform proxy)
    /// If not set, defaults to tls_enabled value
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_tls: Option<bool>,
}

impl Default for ConfigOptions {
    fn default() -> Self {
        Self {
            timeout_seconds: default_timeout(),
            auth_time_window_seconds: default_time_window(),
            tls_enabled: false,
            tls_cert_path: None,
            tls_key_path: None,
            link_tls: None,
        }
    }
}

/// VMess configuration
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VmessConfig {
    pub user_id: String,
    pub server_address: String,
    pub server_port: u16,
    pub encryption: String,
    #[serde(default)]
    pub options: ConfigOptions,
    /// Optional server name/remarks for subscription link
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Public address for subscription link (domain or public IP)
    /// If not set, server_address is used instead
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_address: Option<String>,
}

impl VmessConfig {
    /// Create a new configuration
    pub fn new(
        user_id: String,
        server_address: String,
        server_port: u16,
        encryption: String,
    ) -> Self {
        Self {
            user_id,
            server_address,
            server_port,
            encryption,
            options: ConfigOptions::default(),
            name: None,
            public_address: None,
        }
    }

    /// Create a new configuration with name
    pub fn with_name(
        user_id: String,
        server_address: String,
        server_port: u16,
        encryption: String,
        name: String,
    ) -> Self {
        Self {
            user_id,
            server_address,
            server_port,
            encryption,
            options: ConfigOptions::default(),
            name: Some(name),
            public_address: None,
        }
    }

    /// Parse from JSON string
    pub fn from_json(json: &str) -> Result<Self, ConfigError> {
        serde_json::from_str(json).map_err(|e| ConfigError::ParseError(e.to_string()))
    }

    /// Serialize to JSON string
    pub fn to_json(&self) -> Result<String, ConfigError> {
        serde_json::to_string_pretty(self)
            .map_err(|e| ConfigError::SerializationError(e.to_string()))
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Validate user ID
        UserId::from_str(&self.user_id)?;

        // Validate server address (basic check)
        if self.server_address.is_empty() {
            return Err(ConfigError::InvalidServerAddress(
                "Server address cannot be empty".to_string(),
            ));
        }

        // Validate port
        if self.server_port == 0 {
            return Err(ConfigError::InvalidPort(self.server_port));
        }

        // Validate encryption method
        self.encryption_method()?;

        Ok(())
    }

    /// Get the encryption method enum
    pub fn encryption_method(&self) -> Result<EncryptionMethod, ConfigError> {
        match self.encryption.to_lowercase().as_str() {
            "none" => Ok(EncryptionMethod::None),
            "aes-128-cfb" => Ok(EncryptionMethod::Aes128Cfb),
            "aes-128-gcm" => Ok(EncryptionMethod::Aes128Gcm),
            "chacha20-poly1305" => Ok(EncryptionMethod::ChaCha20Poly1305),
            _ => Err(ConfigError::InvalidEncryption(self.encryption.clone())),
        }
    }

    /// Get the user ID
    pub fn user_id(&self) -> Result<UserId, ConfigError> {
        UserId::from_str(&self.user_id).map_err(|e| e.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_from_json() {
        let json = r#"{
            "user_id": "de305d54-75b4-431b-adb2-eb6b9e546014",
            "server_address": "127.0.0.1",
            "server_port": 10086,
            "encryption": "aes-128-gcm"
        }"#;

        let config = VmessConfig::from_json(json).unwrap();
        assert_eq!(config.user_id, "de305d54-75b4-431b-adb2-eb6b9e546014");
        assert_eq!(config.server_address, "127.0.0.1");
        assert_eq!(config.server_port, 10086);
        assert_eq!(config.encryption, "aes-128-gcm");
    }

    #[test]
    fn test_config_to_json() {
        let config = VmessConfig::new(
            "de305d54-75b4-431b-adb2-eb6b9e546014".to_string(),
            "example.com".to_string(),
            443,
            "chacha20-poly1305".to_string(),
        );

        let json = config.to_json().unwrap();
        assert!(json.contains("de305d54-75b4-431b-adb2-eb6b9e546014"));
        assert!(json.contains("example.com"));
        assert!(json.contains("443"));
    }

    #[test]
    fn test_config_roundtrip() {
        let original = VmessConfig::new(
            "de305d54-75b4-431b-adb2-eb6b9e546014".to_string(),
            "test.example.com".to_string(),
            8080,
            "aes-128-cfb".to_string(),
        );

        let json = original.to_json().unwrap();
        let parsed = VmessConfig::from_json(&json).unwrap();

        assert_eq!(original, parsed);
    }

    #[test]
    fn test_config_validate_valid() {
        let config = VmessConfig::new(
            "de305d54-75b4-431b-adb2-eb6b9e546014".to_string(),
            "127.0.0.1".to_string(),
            443,
            "aes-128-gcm".to_string(),
        );

        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_validate_invalid_user_id() {
        let config = VmessConfig::new(
            "invalid-uuid".to_string(),
            "127.0.0.1".to_string(),
            443,
            "aes-128-gcm".to_string(),
        );

        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validate_empty_address() {
        let config = VmessConfig::new(
            "de305d54-75b4-431b-adb2-eb6b9e546014".to_string(),
            "".to_string(),
            443,
            "aes-128-gcm".to_string(),
        );

        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validate_zero_port() {
        let config = VmessConfig::new(
            "de305d54-75b4-431b-adb2-eb6b9e546014".to_string(),
            "127.0.0.1".to_string(),
            0,
            "aes-128-gcm".to_string(),
        );

        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validate_invalid_encryption() {
        let config = VmessConfig::new(
            "de305d54-75b4-431b-adb2-eb6b9e546014".to_string(),
            "127.0.0.1".to_string(),
            443,
            "invalid-encryption".to_string(),
        );

        assert!(config.validate().is_err());
    }

    #[test]
    fn test_encryption_method() {
        let config = VmessConfig::new(
            "de305d54-75b4-431b-adb2-eb6b9e546014".to_string(),
            "127.0.0.1".to_string(),
            443,
            "aes-128-gcm".to_string(),
        );

        assert_eq!(
            config.encryption_method().unwrap(),
            EncryptionMethod::Aes128Gcm
        );
    }

    #[test]
    fn test_all_encryption_methods() {
        let methods = [
            ("none", EncryptionMethod::None),
            ("aes-128-cfb", EncryptionMethod::Aes128Cfb),
            ("aes-128-gcm", EncryptionMethod::Aes128Gcm),
            ("chacha20-poly1305", EncryptionMethod::ChaCha20Poly1305),
        ];

        for (name, expected) in methods {
            let config = VmessConfig::new(
                "de305d54-75b4-431b-adb2-eb6b9e546014".to_string(),
                "127.0.0.1".to_string(),
                443,
                name.to_string(),
            );
            assert_eq!(config.encryption_method().unwrap(), expected);
        }
    }

    #[test]
    fn test_default_options() {
        let json = r#"{
            "user_id": "de305d54-75b4-431b-adb2-eb6b9e546014",
            "server_address": "127.0.0.1",
            "server_port": 443,
            "encryption": "none"
        }"#;

        let config = VmessConfig::from_json(json).unwrap();
        assert_eq!(config.options.timeout_seconds, 30);
        assert_eq!(config.options.auth_time_window_seconds, 120);
    }

    #[test]
    fn test_custom_options() {
        let json = r#"{
            "user_id": "de305d54-75b4-431b-adb2-eb6b9e546014",
            "server_address": "127.0.0.1",
            "server_port": 443,
            "encryption": "none",
            "options": {
                "timeout_seconds": 60,
                "auth_time_window_seconds": 300
            }
        }"#;

        let config = VmessConfig::from_json(json).unwrap();
        assert_eq!(config.options.timeout_seconds, 60);
        assert_eq!(config.options.auth_time_window_seconds, 300);
    }

    #[test]
    fn test_get_user_id() {
        let config = VmessConfig::new(
            "de305d54-75b4-431b-adb2-eb6b9e546014".to_string(),
            "127.0.0.1".to_string(),
            443,
            "none".to_string(),
        );

        let user_id = config.user_id().unwrap();
        assert_eq!(user_id.to_string(), "de305d54-75b4-431b-adb2-eb6b9e546014");
    }

    #[test]
    fn test_config_with_name() {
        let json = r#"{
            "user_id": "de305d54-75b4-431b-adb2-eb6b9e546014",
            "server_address": "127.0.0.1",
            "server_port": 443,
            "encryption": "aes-128-gcm",
            "name": "My Server"
        }"#;

        let config = VmessConfig::from_json(json).unwrap();
        assert_eq!(config.name, Some("My Server".to_string()));
    }

    #[test]
    fn test_config_without_name() {
        let json = r#"{
            "user_id": "de305d54-75b4-431b-adb2-eb6b9e546014",
            "server_address": "127.0.0.1",
            "server_port": 443,
            "encryption": "aes-128-gcm"
        }"#;

        let config = VmessConfig::from_json(json).unwrap();
        assert_eq!(config.name, None);
    }

    #[test]
    fn test_config_new_has_no_name() {
        let config = VmessConfig::new(
            "de305d54-75b4-431b-adb2-eb6b9e546014".to_string(),
            "127.0.0.1".to_string(),
            443,
            "aes-128-gcm".to_string(),
        );
        assert_eq!(config.name, None);
    }

    #[test]
    fn test_config_with_name_constructor() {
        let config = VmessConfig::with_name(
            "de305d54-75b4-431b-adb2-eb6b9e546014".to_string(),
            "127.0.0.1".to_string(),
            443,
            "aes-128-gcm".to_string(),
            "Test Server".to_string(),
        );
        assert_eq!(config.name, Some("Test Server".to_string()));
    }

    #[test]
    fn test_config_name_roundtrip() {
        let original = VmessConfig::with_name(
            "de305d54-75b4-431b-adb2-eb6b9e546014".to_string(),
            "example.com".to_string(),
            443,
            "aes-128-gcm".to_string(),
            "My VMess Server".to_string(),
        );

        let json = original.to_json().unwrap();
        let parsed = VmessConfig::from_json(&json).unwrap();

        assert_eq!(original, parsed);
        assert_eq!(parsed.name, Some("My VMess Server".to_string()));
    }
}
