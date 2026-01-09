//! User ID (UUID) management for VMess protocol
//!
//! User ID is a 16-byte UUID that serves as the identity token
//! for VMess authentication.

use std::str::FromStr;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum UserIdError {
    #[error("Invalid UUID format: {0}")]
    InvalidFormat(String),
}

/// 16-byte User ID for VMess authentication
///
/// User ID is equivalent to a UUID v4 and is used as a token
/// for client authentication in the VMess protocol.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct UserId([u8; 16]);

impl UserId {
    /// Generate a new random User ID (UUID v4)
    pub fn generate() -> Self {
        let uuid = Uuid::new_v4();
        Self(*uuid.as_bytes())
    }

    /// Create a UserId from raw bytes
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Check if this is a valid UUID v4 (random UUID)
    pub fn is_valid_v4(&self) -> bool {
        let uuid = Uuid::from_bytes(self.0);
        uuid.get_version() == Some(uuid::Version::Random)
    }
}

impl FromStr for UserId {
    type Err = UserIdError;

    /// Parse from UUID string format
    ///
    /// Accepts format: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let uuid = Uuid::parse_str(s).map_err(|e| UserIdError::InvalidFormat(e.to_string()))?;
        Ok(Self(*uuid.as_bytes()))
    }
}

impl std::fmt::Display for UserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let uuid = Uuid::from_bytes(self.0);
        write!(f, "{}", uuid)
    }
}

impl TryFrom<&str> for UserId {
    type Error = UserIdError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::from_str(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_produces_16_bytes() {
        let user_id = UserId::generate();
        assert_eq!(user_id.as_bytes().len(), 16);
    }

    #[test]
    fn test_generate_produces_valid_v4() {
        let user_id = UserId::generate();
        assert!(user_id.is_valid_v4());
    }

    #[test]
    fn test_parse_valid_uuid() {
        let uuid_str = "de305d54-75b4-431b-adb2-eb6b9e546014";
        let user_id = UserId::from_str(uuid_str).unwrap();
        assert_eq!(user_id.to_string(), uuid_str);
    }

    #[test]
    fn test_parse_uppercase_uuid() {
        let uuid_str = "DE305D54-75B4-431B-ADB2-EB6B9E546014";
        let user_id = UserId::from_str(uuid_str).unwrap();
        // Output should be lowercase
        assert_eq!(user_id.to_string(), uuid_str.to_lowercase());
    }

    #[test]
    fn test_parse_invalid_uuid_wrong_length() {
        let result = UserId::from_str("de305d54-75b4-431b-adb2");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_uuid_bad_chars() {
        let result = UserId::from_str("de305d54-75b4-431b-adb2-eb6b9e54601g");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_uuid_no_dashes() {
        // UUID without dashes should still work
        let result = UserId::from_str("de305d5475b4431badb2eb6b9e546014");
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_empty_string() {
        let result = UserId::from_str("");
        assert!(result.is_err());
    }

    #[test]
    fn test_roundtrip() {
        let original = UserId::generate();
        let string = original.to_string();
        let parsed = UserId::from_str(&string).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_from_bytes() {
        let bytes = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let user_id = UserId::from_bytes(bytes);
        assert_eq!(user_id.as_bytes(), &bytes);
    }

    #[test]
    fn test_display() {
        let uuid_str = "de305d54-75b4-431b-adb2-eb6b9e546014";
        let user_id = UserId::from_str(uuid_str).unwrap();
        assert_eq!(format!("{}", user_id), uuid_str);
    }

    #[test]
    fn test_try_from() {
        let uuid_str = "de305d54-75b4-431b-adb2-eb6b9e546014";
        let user_id: UserId = uuid_str.try_into().unwrap();
        assert_eq!(user_id.to_string(), uuid_str);
    }

    #[test]
    fn test_equality() {
        let uuid_str = "de305d54-75b4-431b-adb2-eb6b9e546014";
        let user_id1 = UserId::from_str(uuid_str).unwrap();
        let user_id2 = UserId::from_str(uuid_str).unwrap();
        assert_eq!(user_id1, user_id2);
    }

    #[test]
    fn test_clone() {
        let original = UserId::generate();
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }
}
