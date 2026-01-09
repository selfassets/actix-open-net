//! AES-128-CFB encryption/decryption
//!
//! CFB (Cipher Feedback) mode is a stream cipher mode that uses AES
//! as the underlying block cipher. It's used in VMess for encrypting
//! the command section.

use aes::Aes128;
use cfb_mode::cipher::{AsyncStreamCipher, KeyIvInit};
use cfb_mode::Decryptor as CfbDecryptor;
use cfb_mode::Encryptor as CfbEncryptor;

type Aes128CfbEnc = CfbEncryptor<Aes128>;
type Aes128CfbDec = CfbDecryptor<Aes128>;

/// AES-128-CFB cipher for VMess protocol
#[derive(Clone)]
pub struct Aes128Cfb {
    key: [u8; 16],
    iv: [u8; 16],
}

impl Aes128Cfb {
    /// Create a new AES-128-CFB cipher with the given key and IV
    pub fn new(key: [u8; 16], iv: [u8; 16]) -> Self {
        Self { key, iv }
    }

    /// Encrypt plaintext using AES-128-CFB
    /// Returns the ciphertext (same length as plaintext)
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let mut buffer = plaintext.to_vec();
        let cipher = Aes128CfbEnc::new(&self.key.into(), &self.iv.into());
        cipher.encrypt(&mut buffer);
        buffer
    }

    /// Decrypt ciphertext using AES-128-CFB
    /// Returns the plaintext (same length as ciphertext)
    pub fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8> {
        let mut buffer = ciphertext.to_vec();
        let cipher = Aes128CfbDec::new(&self.key.into(), &self.iv.into());
        cipher.decrypt(&mut buffer);
        buffer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0u8; 16];
        let iv = [0u8; 16];
        let cipher = Aes128Cfb::new(key, iv);

        let plaintext = b"Hello, VMess!";
        let ciphertext = cipher.encrypt(plaintext);
        let decrypted = cipher.decrypt(&ciphertext);

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_changes_data() {
        let key = [1u8; 16];
        let iv = [2u8; 16];
        let cipher = Aes128Cfb::new(key, iv);

        let plaintext = b"Secret message";
        let ciphertext = cipher.encrypt(plaintext);

        assert_ne!(ciphertext.as_slice(), plaintext);
    }

    #[test]
    fn test_same_length() {
        let key = [3u8; 16];
        let iv = [4u8; 16];
        let cipher = Aes128Cfb::new(key, iv);

        let plaintext = b"Test data of various length";
        let ciphertext = cipher.encrypt(plaintext);

        assert_eq!(ciphertext.len(), plaintext.len());
    }

    #[test]
    fn test_different_keys_produce_different_ciphertext() {
        let iv = [0u8; 16];
        let cipher1 = Aes128Cfb::new([1u8; 16], iv);
        let cipher2 = Aes128Cfb::new([2u8; 16], iv);

        let plaintext = b"Same plaintext";
        let ciphertext1 = cipher1.encrypt(plaintext);
        let ciphertext2 = cipher2.encrypt(plaintext);

        assert_ne!(ciphertext1, ciphertext2);
    }

    #[test]
    fn test_different_ivs_produce_different_ciphertext() {
        let key = [0u8; 16];
        let cipher1 = Aes128Cfb::new(key, [1u8; 16]);
        let cipher2 = Aes128Cfb::new(key, [2u8; 16]);

        let plaintext = b"Same plaintext";
        let ciphertext1 = cipher1.encrypt(plaintext);
        let ciphertext2 = cipher2.encrypt(plaintext);

        assert_ne!(ciphertext1, ciphertext2);
    }

    #[test]
    fn test_empty_data() {
        let key = [5u8; 16];
        let iv = [6u8; 16];
        let cipher = Aes128Cfb::new(key, iv);

        let plaintext = b"";
        let ciphertext = cipher.encrypt(plaintext);
        let decrypted = cipher.decrypt(&ciphertext);

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_large_data() {
        let key = [7u8; 16];
        let iv = [8u8; 16];
        let cipher = Aes128Cfb::new(key, iv);

        let plaintext: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();
        let ciphertext = cipher.encrypt(&plaintext);
        let decrypted = cipher.decrypt(&ciphertext);

        assert_eq!(decrypted, plaintext);
    }
}
