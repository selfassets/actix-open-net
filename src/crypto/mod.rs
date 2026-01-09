//! Cryptographic primitives for VMess protocol

pub mod hash;
pub mod aes_cfb;
pub mod aes_gcm;
pub mod chacha;

pub use hash::{md5, hmac_md5, fnv1a_32};
pub use aes_cfb::Aes128Cfb;
pub use aes_gcm::Aes128Gcm;
pub use chacha::ChaCha20Poly1305Cipher;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed: authentication tag mismatch")]
    DecryptionFailed,
    #[error("Invalid key length")]
    InvalidKeyLength,
    #[error("Invalid nonce length")]
    InvalidNonceLength,
}
