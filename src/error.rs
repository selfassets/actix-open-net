//! Error types for VMess protocol
//!
//! Provides a unified error type hierarchy for all VMess operations.
//! Errors are designed to be descriptive while not exposing sensitive
//! cryptographic material.

use crate::auth::AuthError;
use crate::command::CommandError;
use crate::config::ConfigError;
use crate::crypto::CryptoError;
use crate::data::DataError;
use crate::message::{RequestError, ResponseError};
use crate::transport::TransportError;
use crate::user_id::UserIdError;
use thiserror::Error;

/// Top-level VMess error type
///
/// This enum encompasses all possible errors that can occur during
/// VMess protocol operations. Each variant wraps a more specific
/// error type from the corresponding module.
#[derive(Debug, Error)]
pub enum VmessError {
    /// Error related to User ID parsing or generation
    #[error("User ID error: {0}")]
    UserId(#[from] UserIdError),

    /// Error during authentication (HMAC verification, timestamp)
    #[error("Authentication error: {0}")]
    Auth(#[from] AuthError),

    /// Error encoding/decoding command section
    #[error("Command error: {0}")]
    Command(#[from] CommandError),

    /// Error processing data chunks
    #[error("Data processing error: {0}")]
    Data(#[from] DataError),

    /// Error building/parsing requests
    #[error("Request error: {0}")]
    Request(#[from] RequestError),

    /// Error building/parsing responses
    #[error("Response error: {0}")]
    Response(#[from] ResponseError),

    /// Cryptographic operation error
    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),

    /// Network transport error
    #[error("Transport error: {0}")]
    Transport(#[from] TransportError),

    /// Configuration error
    #[error("Config error: {0}")]
    Config(#[from] ConfigError),
}

impl VmessError {
    /// Check if this is an authentication-related error
    pub fn is_auth_error(&self) -> bool {
        matches!(self, VmessError::Auth(_))
    }

    /// Check if this is a network-related error
    pub fn is_network_error(&self) -> bool {
        matches!(self, VmessError::Transport(_))
    }

    /// Check if this is a configuration error
    pub fn is_config_error(&self) -> bool {
        matches!(self, VmessError::Config(_))
    }

    /// Check if this is a cryptographic error
    pub fn is_crypto_error(&self) -> bool {
        matches!(self, VmessError::Crypto(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_id_error_conversion() {
        let err = UserIdError::InvalidFormat("test".to_string());
        let vmess_err: VmessError = err.into();
        assert!(matches!(vmess_err, VmessError::UserId(_)));
    }

    #[test]
    fn test_auth_error_conversion() {
        let err = AuthError::HmacMismatch;
        let vmess_err: VmessError = err.into();
        assert!(vmess_err.is_auth_error());
    }

    #[test]
    fn test_crypto_error_conversion() {
        let err = CryptoError::DecryptionFailed;
        let vmess_err: VmessError = err.into();
        assert!(vmess_err.is_crypto_error());
    }

    #[test]
    fn test_error_display() {
        let err = VmessError::Auth(AuthError::TimestampOutOfRange);
        let msg = err.to_string();
        assert!(msg.contains("Authentication"));
        assert!(msg.contains("timestamp"));
    }

    #[test]
    fn test_error_does_not_contain_keys() {
        // Verify that error messages don't contain raw key bytes
        let err = VmessError::Crypto(CryptoError::DecryptionFailed);
        let msg = err.to_string();

        // Should not contain hex patterns that look like keys
        assert!(!msg.contains("0x"));
        assert!(!msg.contains("[0,"));
    }

    #[test]
    fn test_is_auth_error() {
        let auth_err = VmessError::Auth(AuthError::HmacMismatch);
        let crypto_err = VmessError::Crypto(CryptoError::EncryptionFailed);

        assert!(auth_err.is_auth_error());
        assert!(!crypto_err.is_auth_error());
    }

    #[test]
    fn test_is_network_error() {
        let transport_err = VmessError::Transport(TransportError::Timeout);
        let config_err = VmessError::Config(ConfigError::InvalidPort(0));

        assert!(transport_err.is_network_error());
        assert!(!config_err.is_network_error());
    }

    #[test]
    fn test_is_config_error() {
        let config_err = VmessError::Config(ConfigError::InvalidPort(0));
        let auth_err = VmessError::Auth(AuthError::HmacMismatch);

        assert!(config_err.is_config_error());
        assert!(!auth_err.is_config_error());
    }
}
