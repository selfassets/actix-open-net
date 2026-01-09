//! Authentication module for VMess protocol
//!
//! Generates and verifies 16-byte authentication information
//! using HMAC-MD5 with User ID and UTC timestamp.

use crate::crypto::hmac_md5;
use crate::user_id::UserId;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Authentication failed: timestamp outside allowed window")]
    TimestampOutOfRange,
    #[error("Authentication failed: HMAC mismatch")]
    HmacMismatch,
}

/// Authentication information generator and verifier
///
/// VMess uses a time-based authentication scheme where the client
/// generates a 16-byte authentication value using HMAC-MD5 of the
/// User ID and current UTC timestamp.
pub struct Authenticator {
    user_id: UserId,
    time_window: Duration,
}

impl Authenticator {
    /// Create a new Authenticator with the given User ID and time window
    ///
    /// The time window specifies how much clock skew is allowed between
    /// client and server. Default is ±120 seconds.
    pub fn new(user_id: UserId, time_window: Duration) -> Self {
        Self {
            user_id,
            time_window,
        }
    }

    /// Create a new Authenticator with default time window (120 seconds)
    pub fn with_default_window(user_id: UserId) -> Self {
        Self::new(user_id, Duration::from_secs(120))
    }

    /// Generate 16-byte authentication info using current timestamp
    pub fn generate(&self) -> [u8; 16] {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
        self.generate_for_timestamp(timestamp)
    }

    /// Generate authentication info for a specific timestamp
    ///
    /// The authentication value is computed as:
    /// HMAC-MD5(User_ID, timestamp_bytes)
    ///
    /// Where timestamp_bytes is the 8-byte big-endian representation
    /// of the Unix timestamp.
    pub fn generate_for_timestamp(&self, timestamp: u64) -> [u8; 16] {
        let timestamp_bytes = timestamp.to_be_bytes();
        hmac_md5(self.user_id.as_bytes(), &timestamp_bytes)
    }

    /// Verify authentication info within time window
    ///
    /// Tries timestamps within the configured time window and returns
    /// the matching timestamp if found.
    pub fn verify(&self, auth_info: &[u8; 16]) -> Result<u64, AuthError> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        self.verify_at_time(auth_info, current_time)
    }

    /// Verify authentication info at a specific reference time
    ///
    /// This is useful for testing and for servers that need to
    /// verify against a specific time.
    pub fn verify_at_time(
        &self,
        auth_info: &[u8; 16],
        reference_time: u64,
    ) -> Result<u64, AuthError> {
        let window_secs = self.time_window.as_secs();

        // Calculate the range of timestamps to check
        let start_time = reference_time.saturating_sub(window_secs);
        let end_time = reference_time.saturating_add(window_secs);

        // Try each timestamp in the window
        for timestamp in start_time..=end_time {
            let expected = self.generate_for_timestamp(timestamp);
            if constant_time_eq(&expected, auth_info) {
                return Ok(timestamp);
            }
        }

        Err(AuthError::HmacMismatch)
    }

    /// Get the configured time window
    pub fn time_window(&self) -> Duration {
        self.time_window
    }

    /// Get a reference to the User ID
    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }
}

/// Constant-time comparison to prevent timing attacks
fn constant_time_eq(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn test_user_id() -> UserId {
        UserId::from_str("de305d54-75b4-431b-adb2-eb6b9e546014").unwrap()
    }

    #[test]
    fn test_generate_produces_16_bytes() {
        let auth = Authenticator::with_default_window(test_user_id());
        let result = auth.generate();
        assert_eq!(result.len(), 16);
    }

    #[test]
    fn test_generate_for_timestamp_deterministic() {
        let auth = Authenticator::with_default_window(test_user_id());
        let timestamp = 1234567890u64;

        let result1 = auth.generate_for_timestamp(timestamp);
        let result2 = auth.generate_for_timestamp(timestamp);

        assert_eq!(result1, result2);
    }

    #[test]
    fn test_different_timestamps_produce_different_auth() {
        let auth = Authenticator::with_default_window(test_user_id());

        let result1 = auth.generate_for_timestamp(1000);
        let result2 = auth.generate_for_timestamp(1001);

        assert_ne!(result1, result2);
    }

    #[test]
    fn test_different_user_ids_produce_different_auth() {
        let user_id1 = UserId::from_str("de305d54-75b4-431b-adb2-eb6b9e546014").unwrap();
        let user_id2 = UserId::from_str("de305d54-75b4-431b-adb2-eb6b9e546015").unwrap();

        let auth1 = Authenticator::with_default_window(user_id1);
        let auth2 = Authenticator::with_default_window(user_id2);

        let timestamp = 1234567890u64;
        let result1 = auth1.generate_for_timestamp(timestamp);
        let result2 = auth2.generate_for_timestamp(timestamp);

        assert_ne!(result1, result2);
    }

    #[test]
    fn test_verify_valid_auth_within_window() {
        let auth = Authenticator::with_default_window(test_user_id());
        let reference_time = 1000000u64;

        // Generate auth for a time within the window
        let auth_info = auth.generate_for_timestamp(reference_time);

        // Verify at the same reference time
        let result = auth.verify_at_time(&auth_info, reference_time);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), reference_time);
    }

    #[test]
    fn test_verify_valid_auth_at_window_edge() {
        let auth = Authenticator::new(test_user_id(), Duration::from_secs(60));
        let reference_time = 1000000u64;

        // Generate auth for a time at the edge of the window
        let auth_info = auth.generate_for_timestamp(reference_time - 60);

        // Verify at reference time
        let result = auth.verify_at_time(&auth_info, reference_time);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_invalid_auth_outside_window() {
        let auth = Authenticator::new(test_user_id(), Duration::from_secs(60));
        let reference_time = 1000000u64;

        // Generate auth for a time outside the window
        let auth_info = auth.generate_for_timestamp(reference_time - 61);

        // Verify at reference time - should fail
        let result = auth.verify_at_time(&auth_info, reference_time);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_tampered_auth_fails() {
        let auth = Authenticator::with_default_window(test_user_id());
        let reference_time = 1000000u64;

        let mut auth_info = auth.generate_for_timestamp(reference_time);
        // Tamper with the auth info
        auth_info[0] ^= 0xFF;

        let result = auth.verify_at_time(&auth_info, reference_time);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_wrong_user_id_fails() {
        let user_id1 = UserId::from_str("de305d54-75b4-431b-adb2-eb6b9e546014").unwrap();
        let user_id2 = UserId::from_str("de305d54-75b4-431b-adb2-eb6b9e546015").unwrap();

        let auth1 = Authenticator::with_default_window(user_id1);
        let auth2 = Authenticator::with_default_window(user_id2);

        let reference_time = 1000000u64;
        let auth_info = auth1.generate_for_timestamp(reference_time);

        // Try to verify with different user ID
        let result = auth2.verify_at_time(&auth_info, reference_time);
        assert!(result.is_err());
    }

    #[test]
    fn test_constant_time_eq() {
        let a = [1u8; 16];
        let b = [1u8; 16];
        let c = [2u8; 16];

        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
    }

    #[test]
    fn test_time_window_getter() {
        let window = Duration::from_secs(300);
        let auth = Authenticator::new(test_user_id(), window);
        assert_eq!(auth.time_window(), window);
    }

    #[test]
    fn test_user_id_getter() {
        let user_id = test_user_id();
        let auth = Authenticator::with_default_window(user_id.clone());
        assert_eq!(auth.user_id(), &user_id);
    }
}
