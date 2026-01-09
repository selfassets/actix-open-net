//! Cryptographic primitives for VMess protocol

pub mod aes_cfb;
pub mod aes_gcm;
pub mod chacha;
pub mod hash;

pub use aes_cfb::Aes128Cfb;
pub use aes_gcm::Aes128Gcm;
pub use chacha::ChaCha20Poly1305Cipher;
pub use hash::{fnv1a_32, hmac_md5, md5};

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
