//! Cryptographic utilities and helpers

use ring::{
    aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey},
    rand::{SecureRandom, SystemRandom},
};

use crate::{ProtocolError, Result};

/// AES-256-GCM encryption context
pub struct AesGcmEncryption {
    key: LessSafeKey,
    rng: SystemRandom,
}

impl AesGcmEncryption {
    /// Create a new encryption context with a random key
    pub fn new() -> Result<Self> {
        let rng = SystemRandom::new();
        let mut key_bytes = [0u8; 32];
        rng.fill(&mut key_bytes)
            .map_err(|e| ProtocolError::Crypto(format!("Failed to generate key: {}", e)))?;

        let unbound_key = UnboundKey::new(&AES_256_GCM, &key_bytes)
            .map_err(|e| ProtocolError::Crypto(format!("Failed to create key: {}", e)))?;

        let key = LessSafeKey::new(unbound_key);

        Ok(Self { key, rng })
    }

    /// Create encryption context from existing key bytes
    pub fn from_key(key_bytes: &[u8; 32]) -> Result<Self> {
        let unbound_key = UnboundKey::new(&AES_256_GCM, key_bytes)
            .map_err(|e| ProtocolError::Crypto(format!("Failed to create key: {}", e)))?;

        let key = LessSafeKey::new(unbound_key);
        let rng = SystemRandom::new();

        Ok(Self { key, rng })
    }

    /// Encrypt plaintext and return (nonce, ciphertext)
    #[allow(clippy::type_complexity)]
    pub fn encrypt(&self, plaintext: &[u8], associated_data: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut nonce_bytes = [0u8; 12];
        self.rng
            .fill(&mut nonce_bytes)
            .map_err(|e| ProtocolError::Crypto(format!("Failed to generate nonce: {}", e)))?;

        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let aad = Aad::from(associated_data);

        let mut in_out = plaintext.to_vec();
        self.key
            .seal_in_place_append_tag(nonce, aad, &mut in_out)
            .map_err(|e| ProtocolError::Crypto(format!("Encryption failed: {}", e)))?;

        Ok((nonce_bytes.to_vec(), in_out))
    }

    /// Decrypt ciphertext using provided nonce
    pub fn decrypt(
        &self,
        nonce: &[u8],
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>> {
        if nonce.len() != 12 {
            return Err(ProtocolError::Crypto("Invalid nonce length".to_string()));
        }

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(nonce);
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let aad = Aad::from(associated_data);

        let mut in_out = ciphertext.to_vec();
        let plaintext_len = self
            .key
            .open_in_place(nonce, aad, &mut in_out)
            .map_err(|e| ProtocolError::Crypto(format!("Decryption failed: {}", e)))?
            .len();

        // Truncate to only the plaintext (removing the auth tag)
        in_out.truncate(plaintext_len);
        Ok(in_out)
    }
}

/// Generate a cryptographically secure random byte array
pub fn generate_random_bytes<const N: usize>() -> Result<[u8; N]> {
    let rng = SystemRandom::new();
    let mut bytes = [0u8; N];
    rng.fill(&mut bytes)
        .map_err(|e| ProtocolError::Crypto(format!("Failed to generate random bytes: {}", e)))?;
    Ok(bytes)
}

/// Hash function using SHA-256
pub fn hash_sha256(data: &[u8]) -> [u8; 32] {
    use ring::digest::{SHA256, digest};
    let digest = digest(&SHA256, data);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(digest.as_ref());
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_gcm_encryption() {
        let encryption = AesGcmEncryption::new().unwrap();
        let plaintext = b"Hello, NORC!";
        let associated_data = b"test_data";

        let (nonce, ciphertext) = encryption.encrypt(plaintext, associated_data).unwrap();
        let decrypted = encryption
            .decrypt(&nonce, &ciphertext, associated_data)
            .unwrap();

        // The decrypted output should match the original plaintext exactly
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_random_bytes_generation() {
        let bytes1: [u8; 32] = generate_random_bytes().unwrap();
        let bytes2: [u8; 32] = generate_random_bytes().unwrap();

        // Very unlikely to be equal if truly random
        assert_ne!(bytes1, bytes2);
    }

    #[test]
    fn test_sha256_hash() {
        let data = b"test data";
        let hash1 = hash_sha256(data);
        let hash2 = hash_sha256(data);

        // Same input should produce same hash
        assert_eq!(hash1, hash2);

        // Different input should produce different hash
        let hash3 = hash_sha256(b"different data");
        assert_ne!(hash1, hash3);
    }
}
