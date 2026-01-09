//! ChaCha20-Poly1305 AEAD encryption/decryption
//!
//! ChaCha20-Poly1305 is an AEAD cipher that provides both
//! confidentiality and authenticity. It's an alternative to
//! AES-GCM in VMess for data chunk encryption.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};

use super::CryptoError;

/// ChaCha20-Poly1305 AEAD cipher for VMess protocol
pub struct ChaCha20Poly1305Cipher {
    cipher: ChaCha20Poly1305,
}

impl ChaCha20Poly1305Cipher {
    /// Create a new ChaCha20-Poly1305 cipher with the given 32-byte key
    pub fn new(key: [u8; 32]) -> Self {
        let cipher = ChaCha20Poly1305::new(&key.into());
        Self { cipher }
    }

    /// Encrypt plaintext with authentication
    /// Returns ciphertext with appended 16-byte authentication tag
    pub fn encrypt(
        &self,
        nonce: &[u8; 12],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let nonce = Nonce::from_slice(nonce);

        self.cipher
            .encrypt(
                nonce,
                chacha20poly1305::aead::Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::EncryptionFailed)
    }

    /// Decrypt ciphertext and verify authentication tag
    /// Input should include the 16-byte authentication tag at the end
    pub fn decrypt(
        &self,
        nonce: &[u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let nonce = Nonce::from_slice(nonce);

        self.cipher
            .decrypt(
                nonce,
                chacha20poly1305::aead::Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::DecryptionFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let cipher = ChaCha20Poly1305Cipher::new(key);

        let plaintext = b"Hello, VMess!";
        let aad = b"additional data";

        let ciphertext = cipher.encrypt(&nonce, plaintext, aad).unwrap();
        let decrypted = cipher.decrypt(&nonce, &ciphertext, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_ciphertext_includes_tag() {
        let key = [1u8; 32];
        let nonce = [1u8; 12];
        let cipher = ChaCha20Poly1305Cipher::new(key);

        let plaintext = b"Test message";
        let ciphertext = cipher.encrypt(&nonce, plaintext, b"").unwrap();

        // Ciphertext should be plaintext length + 16 bytes tag
        assert_eq!(ciphertext.len(), plaintext.len() + 16);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = [2u8; 32];
        let nonce = [2u8; 12];
        let cipher = ChaCha20Poly1305Cipher::new(key);

        let plaintext = b"Secret data";
        let mut ciphertext = cipher.encrypt(&nonce, plaintext, b"").unwrap();

        // Tamper with the ciphertext
        ciphertext[0] ^= 0xFF;

        let result = cipher.decrypt(&nonce, &ciphertext, b"");
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_aad_fails() {
        let key = [3u8; 32];
        let nonce = [3u8; 12];
        let cipher = ChaCha20Poly1305Cipher::new(key);

        let plaintext = b"Protected data";
        let ciphertext = cipher.encrypt(&nonce, plaintext, b"correct aad").unwrap();

        let result = cipher.decrypt(&nonce, &ciphertext, b"wrong aad");
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_nonce_fails() {
        let key = [4u8; 32];
        let cipher = ChaCha20Poly1305Cipher::new(key);

        let plaintext = b"Nonce test";
        let ciphertext = cipher.encrypt(&[1u8; 12], plaintext, b"").unwrap();

        let result = cipher.decrypt(&[2u8; 12], &ciphertext, b"");
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_plaintext() {
        let key = [5u8; 32];
        let nonce = [5u8; 12];
        let cipher = ChaCha20Poly1305Cipher::new(key);

        let plaintext = b"";
        let ciphertext = cipher.encrypt(&nonce, plaintext, b"").unwrap();
        let decrypted = cipher.decrypt(&nonce, &ciphertext, b"").unwrap();

        assert_eq!(decrypted, plaintext);
        // Even empty plaintext has a 16-byte tag
        assert_eq!(ciphertext.len(), 16);
    }

    #[test]
    fn test_large_data() {
        let key = [6u8; 32];
        let nonce = [6u8; 12];
        let cipher = ChaCha20Poly1305Cipher::new(key);

        let plaintext: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();
        let ciphertext = cipher.encrypt(&nonce, &plaintext, b"").unwrap();
        let decrypted = cipher.decrypt(&nonce, &ciphertext, b"").unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_different_keys_produce_different_ciphertext() {
        let nonce = [0u8; 12];
        let cipher1 = ChaCha20Poly1305Cipher::new([1u8; 32]);
        let cipher2 = ChaCha20Poly1305Cipher::new([2u8; 32]);

        let plaintext = b"Same plaintext";
        let ciphertext1 = cipher1.encrypt(&nonce, plaintext, b"").unwrap();
        let ciphertext2 = cipher2.encrypt(&nonce, plaintext, b"").unwrap();

        assert_ne!(ciphertext1, ciphertext2);
    }
}
