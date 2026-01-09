//! Hash functions for VMess protocol
//! - MD5: Key derivation
//! - FNV1a: Checksum calculation
//! - HMAC-MD5: Authentication info generation

use hmac::{Hmac, Mac};
use md5::{Digest, Md5};

/// Compute MD5 hash of input data
/// Returns a 16-byte hash value
pub fn md5(data: &[u8]) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute HMAC-MD5 of data using the given key
/// Returns a 16-byte authentication code
pub fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    type HmacMd5 = Hmac<Md5>;
    
    let mut mac = HmacMd5::new_from_slice(key)
        .expect("HMAC can take key of any size");
    mac.update(data);
    let result = mac.finalize();
    result.into_bytes().into()
}

/// Compute FNV-1a 32-bit hash of input data
/// Used for checksum calculation in VMess command section
pub fn fnv1a_32(data: &[u8]) -> u32 {
    const FNV_OFFSET_BASIS: u32 = 2166136261;
    const FNV_PRIME: u32 = 16777619;
    
    let mut hash = FNV_OFFSET_BASIS;
    for byte in data {
        hash ^= *byte as u32;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_md5_empty() {
        let result = md5(b"");
        // MD5("") = d41d8cd98f00b204e9800998ecf8427e
        assert_eq!(
            result,
            [0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04,
             0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e]
        );
    }

    #[test]
    fn test_md5_hello() {
        let result = md5(b"hello");
        // MD5("hello") = 5d41402abc4b2a76b9719d911017c592
        assert_eq!(
            result,
            [0x5d, 0x41, 0x40, 0x2a, 0xbc, 0x4b, 0x2a, 0x76,
             0xb9, 0x71, 0x9d, 0x91, 0x10, 0x17, 0xc5, 0x92]
        );
    }

    #[test]
    fn test_fnv1a_empty() {
        let result = fnv1a_32(b"");
        assert_eq!(result, 2166136261); // FNV offset basis
    }

    #[test]
    fn test_fnv1a_hello() {
        let result = fnv1a_32(b"hello");
        // Known FNV-1a hash for "hello"
        assert_eq!(result, 0x4f9f2cab);
    }

    #[test]
    fn test_hmac_md5() {
        let key = b"key";
        let data = b"The quick brown fox jumps over the lazy dog";
        let result = hmac_md5(key, data);
        // Known HMAC-MD5 value
        assert_eq!(
            result,
            [0x80, 0x07, 0x07, 0x13, 0x46, 0x3e, 0x77, 0x49,
             0xb9, 0x0c, 0x2d, 0xc2, 0x49, 0x11, 0xe2, 0x75]
        );
    }

    #[test]
    fn test_md5_output_length() {
        let result = md5(b"any data");
        assert_eq!(result.len(), 16);
    }

    #[test]
    fn test_fnv1a_deterministic() {
        let data = b"test data";
        let result1 = fnv1a_32(data);
        let result2 = fnv1a_32(data);
        assert_eq!(result1, result2);
    }

    #[test]
    fn test_hmac_md5_output_length() {
        let result = hmac_md5(b"key", b"data");
        assert_eq!(result.len(), 16);
    }
}
