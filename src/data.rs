//! Data section processing for VMess protocol
//!
//! Handles chunked data transfer with various encryption methods.
//! Each chunk has a 2-byte length prefix followed by encrypted data.

use crate::command::EncryptionMethod;
use crate::crypto::{md5, Aes128Cfb, Aes128Gcm, ChaCha20Poly1305Cipher};
use thiserror::Error;

/// Maximum chunk size (16KB)
const MAX_CHUNK_SIZE: usize = 16384;

/// Authentication tag size for AEAD ciphers
const AEAD_TAG_SIZE: usize = 16;

#[derive(Debug, Error)]
pub enum DataError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("Authentication failed for chunk {0}")]
    ChunkAuthFailed(u16),
    #[error("Invalid chunk length")]
    InvalidChunkLength,
    #[error("Data too large for single chunk")]
    DataTooLarge,
}

/// A single data chunk
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Chunk {
    /// Length of the data (excluding length field itself)
    pub length: u16,
    /// Encrypted data (may include auth tag for AEAD)
    pub data: Vec<u8>,
}

impl Chunk {
    /// Create a new chunk
    pub fn new(length: u16, data: Vec<u8>) -> Self {
        Self { length, data }
    }

    /// Serialize chunk to bytes (length prefix + data)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(2 + self.data.len());
        buf.extend_from_slice(&self.length.to_be_bytes());
        buf.extend_from_slice(&self.data);
        buf
    }

    /// Parse chunk from bytes
    pub fn from_bytes(data: &[u8]) -> Result<(Self, usize), DataError> {
        if data.len() < 2 {
            return Err(DataError::InvalidChunkLength);
        }

        let length = u16::from_be_bytes([data[0], data[1]]);
        let total_len = 2 + length as usize;

        if data.len() < total_len {
            return Err(DataError::InvalidChunkLength);
        }

        let chunk_data = data[2..total_len].to_vec();
        Ok((Self::new(length, chunk_data), total_len))
    }
}

/// Chunk-based data processor for VMess data section
pub struct DataProcessor {
    encryption_method: EncryptionMethod,
    key: [u8; 16],
    iv: [u8; 16],
}

impl DataProcessor {
    /// Create a new data processor
    pub fn new(method: EncryptionMethod, key: [u8; 16], iv: [u8; 16]) -> Self {
        Self {
            encryption_method: method,
            key,
            iv,
        }
    }

    /// Encode data into chunks
    pub fn encode(&self, data: &[u8]) -> Result<Vec<Chunk>, DataError> {
        if data.is_empty() {
            return Ok(vec![self.create_eot_chunk()]);
        }

        let mut chunks = Vec::new();
        let mut offset = 0;
        let mut chunk_index = 0u16;

        // Calculate max payload size per chunk
        let max_payload = match self.encryption_method {
            EncryptionMethod::None | EncryptionMethod::Aes128Cfb => MAX_CHUNK_SIZE,
            EncryptionMethod::Aes128Gcm | EncryptionMethod::ChaCha20Poly1305 => {
                MAX_CHUNK_SIZE - AEAD_TAG_SIZE
            }
        };

        while offset < data.len() {
            let end = std::cmp::min(offset + max_payload, data.len());
            let chunk_data = &data[offset..end];
            let chunk = self.encode_chunk(chunk_data, chunk_index)?;
            chunks.push(chunk);
            offset = end;
            chunk_index += 1;
        }

        // Add EOT chunk
        chunks.push(self.create_eot_chunk());

        Ok(chunks)
    }

    /// Encode a single chunk
    pub fn encode_chunk(&self, data: &[u8], chunk_index: u16) -> Result<Chunk, DataError> {
        let encrypted = match self.encryption_method {
            EncryptionMethod::None => data.to_vec(),
            EncryptionMethod::Aes128Cfb => {
                let (key, iv) = self.derive_chunk_key_iv(chunk_index);
                let cipher = Aes128Cfb::new(key, iv);
                cipher.encrypt(data)
            }
            EncryptionMethod::Aes128Gcm => {
                let (key, nonce) = self.derive_aead_key_nonce(chunk_index);
                let cipher = Aes128Gcm::new(key);
                cipher
                    .encrypt(&nonce, data, &[])
                    .map_err(|e| DataError::EncryptionFailed(format!("{:?}", e)))?
            }
            EncryptionMethod::ChaCha20Poly1305 => {
                let (key, nonce) = self.derive_chacha_key_nonce(chunk_index);
                let cipher = ChaCha20Poly1305Cipher::new(key);
                cipher
                    .encrypt(&nonce, data, &[])
                    .map_err(|e| DataError::EncryptionFailed(format!("{:?}", e)))?
            }
        };

        Ok(Chunk::new(encrypted.len() as u16, encrypted))
    }

    /// Decode chunks back to original data
    pub fn decode(&self, chunks: &[Chunk]) -> Result<Vec<u8>, DataError> {
        let mut result = Vec::new();

        for (index, chunk) in chunks.iter().enumerate() {
            if self.is_eot(chunk) {
                break;
            }
            let decrypted = self.decode_chunk(chunk, index as u16)?;
            result.extend_from_slice(&decrypted);
        }

        Ok(result)
    }

    /// Decode a single chunk
    pub fn decode_chunk(&self, chunk: &Chunk, chunk_index: u16) -> Result<Vec<u8>, DataError> {
        match self.encryption_method {
            EncryptionMethod::None => Ok(chunk.data.clone()),
            EncryptionMethod::Aes128Cfb => {
                let (key, iv) = self.derive_chunk_key_iv(chunk_index);
                let cipher = Aes128Cfb::new(key, iv);
                Ok(cipher.decrypt(&chunk.data))
            }
            EncryptionMethod::Aes128Gcm => {
                let (key, nonce) = self.derive_aead_key_nonce(chunk_index);
                let cipher = Aes128Gcm::new(key);
                cipher
                    .decrypt(&nonce, &chunk.data, &[])
                    .map_err(|_| DataError::ChunkAuthFailed(chunk_index))
            }
            EncryptionMethod::ChaCha20Poly1305 => {
                let (key, nonce) = self.derive_chacha_key_nonce(chunk_index);
                let cipher = ChaCha20Poly1305Cipher::new(key);
                cipher
                    .decrypt(&nonce, &chunk.data, &[])
                    .map_err(|_| DataError::ChunkAuthFailed(chunk_index))
            }
        }
    }

    /// Create end-of-transmission chunk
    pub fn create_eot_chunk(&self) -> Chunk {
        match self.encryption_method {
            EncryptionMethod::None | EncryptionMethod::Aes128Cfb => Chunk::new(0, vec![]),
            EncryptionMethod::Aes128Gcm | EncryptionMethod::ChaCha20Poly1305 => {
                // For AEAD, EOT is signaled by auth tag length only
                Chunk::new(AEAD_TAG_SIZE as u16, vec![0u8; AEAD_TAG_SIZE])
            }
        }
    }

    /// Check if chunk is end-of-transmission
    pub fn is_eot(&self, chunk: &Chunk) -> bool {
        match self.encryption_method {
            EncryptionMethod::None | EncryptionMethod::Aes128Cfb => chunk.length == 0,
            EncryptionMethod::Aes128Gcm | EncryptionMethod::ChaCha20Poly1305 => {
                chunk.length == AEAD_TAG_SIZE as u16 && chunk.data.iter().all(|&b| b == 0)
            }
        }
    }

    /// Derive key and IV for CFB mode chunk
    fn derive_chunk_key_iv(&self, chunk_index: u16) -> ([u8; 16], [u8; 16]) {
        let mut key_input = self.key.to_vec();
        key_input.extend_from_slice(&chunk_index.to_be_bytes());
        let key = md5(&key_input);

        let mut iv_input = self.iv.to_vec();
        iv_input.extend_from_slice(&chunk_index.to_be_bytes());
        let iv = md5(&iv_input);

        (key, iv)
    }

    /// Derive key and nonce for AES-GCM
    fn derive_aead_key_nonce(&self, chunk_index: u16) -> ([u8; 16], [u8; 12]) {
        let mut key_input = self.key.to_vec();
        key_input.extend_from_slice(&chunk_index.to_be_bytes());
        let key = md5(&key_input);

        let mut nonce = [0u8; 12];
        let iv_hash = md5(&[&self.iv[..], &chunk_index.to_be_bytes()[..]].concat());
        nonce.copy_from_slice(&iv_hash[..12]);

        (key, nonce)
    }

    /// Derive key and nonce for ChaCha20-Poly1305
    fn derive_chacha_key_nonce(&self, chunk_index: u16) -> ([u8; 32], [u8; 12]) {
        // Derive 32-byte key by hashing key twice with different suffixes
        let key1 = md5(&[&self.key[..], &chunk_index.to_be_bytes()[..], &[0u8][..]].concat());
        let key2 = md5(&[&self.key[..], &chunk_index.to_be_bytes()[..], &[1u8][..]].concat());
        let mut key = [0u8; 32];
        key[..16].copy_from_slice(&key1);
        key[16..].copy_from_slice(&key2);

        let mut nonce = [0u8; 12];
        let iv_hash = md5(&[&self.iv[..], &chunk_index.to_be_bytes()[..]].concat());
        nonce.copy_from_slice(&iv_hash[..12]);

        (key, nonce)
    }

    /// Get the encryption method
    pub fn encryption_method(&self) -> EncryptionMethod {
        self.encryption_method
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunk_to_bytes() {
        let chunk = Chunk::new(5, vec![1, 2, 3, 4, 5]);
        let bytes = chunk.to_bytes();
        assert_eq!(bytes, vec![0, 5, 1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_chunk_from_bytes() {
        let data = vec![0, 5, 1, 2, 3, 4, 5, 0, 0];
        let (chunk, consumed) = Chunk::from_bytes(&data).unwrap();
        assert_eq!(chunk.length, 5);
        assert_eq!(chunk.data, vec![1, 2, 3, 4, 5]);
        assert_eq!(consumed, 7);
    }

    #[test]
    fn test_chunk_from_bytes_too_short() {
        let data = vec![0, 5, 1, 2];
        let result = Chunk::from_bytes(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_encode_decode_no_encryption() {
        let processor = DataProcessor::new(EncryptionMethod::None, [0u8; 16], [0u8; 16]);
        let data = b"Hello, VMess!";

        let chunks = processor.encode(data).unwrap();
        let decoded = processor.decode(&chunks).unwrap();

        assert_eq!(decoded, data);
    }

    #[test]
    fn test_encode_decode_aes_cfb() {
        let processor = DataProcessor::new(EncryptionMethod::Aes128Cfb, [1u8; 16], [2u8; 16]);
        let data = b"Secret message with AES-CFB encryption";

        let chunks = processor.encode(data).unwrap();
        let decoded = processor.decode(&chunks).unwrap();

        assert_eq!(decoded, data);
    }

    #[test]
    fn test_encode_decode_aes_gcm() {
        let processor = DataProcessor::new(EncryptionMethod::Aes128Gcm, [3u8; 16], [4u8; 16]);
        let data = b"Authenticated message with AES-GCM";

        let chunks = processor.encode(data).unwrap();
        let decoded = processor.decode(&chunks).unwrap();

        assert_eq!(decoded, data);
    }

    #[test]
    fn test_encode_decode_chacha20() {
        let processor = DataProcessor::new(EncryptionMethod::ChaCha20Poly1305, [5u8; 16], [6u8; 16]);
        let data = b"ChaCha20-Poly1305 encrypted data";

        let chunks = processor.encode(data).unwrap();
        let decoded = processor.decode(&chunks).unwrap();

        assert_eq!(decoded, data);
    }

    #[test]
    fn test_encode_empty_data() {
        let processor = DataProcessor::new(EncryptionMethod::None, [0u8; 16], [0u8; 16]);
        let data = b"";

        let chunks = processor.encode(data).unwrap();
        assert_eq!(chunks.len(), 1);
        assert!(processor.is_eot(&chunks[0]));
    }

    #[test]
    fn test_encode_large_data() {
        let processor = DataProcessor::new(EncryptionMethod::Aes128Gcm, [7u8; 16], [8u8; 16]);
        let data: Vec<u8> = (0..50000).map(|i| (i % 256) as u8).collect();

        let chunks = processor.encode(&data).unwrap();
        // Should have multiple chunks plus EOT
        assert!(chunks.len() > 2);

        let decoded = processor.decode(&chunks).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_eot_chunk_no_encryption() {
        let processor = DataProcessor::new(EncryptionMethod::None, [0u8; 16], [0u8; 16]);
        let eot = processor.create_eot_chunk();
        assert!(processor.is_eot(&eot));
        assert_eq!(eot.length, 0);
    }

    #[test]
    fn test_eot_chunk_aead() {
        let processor = DataProcessor::new(EncryptionMethod::Aes128Gcm, [0u8; 16], [0u8; 16]);
        let eot = processor.create_eot_chunk();
        assert!(processor.is_eot(&eot));
        assert_eq!(eot.length, AEAD_TAG_SIZE as u16);
    }

    #[test]
    fn test_tampered_chunk_fails_aead() {
        let processor = DataProcessor::new(EncryptionMethod::Aes128Gcm, [9u8; 16], [10u8; 16]);
        let data = b"Tamper test";

        let mut chunks = processor.encode(data).unwrap();
        // Tamper with the first chunk's data
        if !chunks.is_empty() && !chunks[0].data.is_empty() {
            chunks[0].data[0] ^= 0xFF;
        }

        let result = processor.decode(&chunks);
        assert!(result.is_err());
    }

    #[test]
    fn test_different_keys_produce_different_ciphertext() {
        let processor1 = DataProcessor::new(EncryptionMethod::Aes128Gcm, [1u8; 16], [0u8; 16]);
        let processor2 = DataProcessor::new(EncryptionMethod::Aes128Gcm, [2u8; 16], [0u8; 16]);
        let data = b"Same data";

        let chunks1 = processor1.encode(data).unwrap();
        let chunks2 = processor2.encode(data).unwrap();

        // Encrypted data should be different
        assert_ne!(chunks1[0].data, chunks2[0].data);
    }

    #[test]
    fn test_chunk_index_affects_encryption() {
        let processor = DataProcessor::new(EncryptionMethod::Aes128Cfb, [11u8; 16], [12u8; 16]);
        let data = b"Same data";

        let chunk0 = processor.encode_chunk(data, 0).unwrap();
        let chunk1 = processor.encode_chunk(data, 1).unwrap();

        // Same data encrypted with different chunk indices should differ
        assert_ne!(chunk0.data, chunk1.data);
    }

    #[test]
    fn test_decode_single_chunk() {
        let processor = DataProcessor::new(EncryptionMethod::Aes128Gcm, [13u8; 16], [14u8; 16]);
        let data = b"Single chunk test";

        let chunk = processor.encode_chunk(data, 0).unwrap();
        let decoded = processor.decode_chunk(&chunk, 0).unwrap();

        assert_eq!(decoded, data);
    }
}
