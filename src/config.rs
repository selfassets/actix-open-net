//! Configuration management for VMess protocol
//!
//! Handles parsing, validation, and serialization of VMess configuration.

use crate::command::EncryptionMethod;
use crate::user_id::{UserId, UserIdError};
use serde::{Deserialize, Serialize};
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

fn default_timeout() -> u64 { 30 }
fn default_time_window() -> u64 { 120 }

/// Configuration options
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConfigOptions {
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
    #[serde(default = "default_time_window")]
    pub auth_time_window_seconds: u64,
}

impl Default for ConfigOptions {
    fn default() -> Self {
        Self {
            timeout_seconds: default_timeout(),
            auth_time_window_seconds: default_time_window(),
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
        }
    }

    /// Parse from JSON string
    pub fn from_json(json: &str) -> Result<Self, ConfigError> {
        serde_json::from_str(json)
            .map_err(|e| ConfigError::ParseError(e.to_string()))
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
                "Server address cannot be empty".to_string()
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

        assert_eq!(config.encryption_method().unwrap(), EncryptionMethod::Aes128Gcm);
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
}
