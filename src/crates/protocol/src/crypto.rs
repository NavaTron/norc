//! Cryptographic primitives for NORC protocol
//!
//! This module implements all required cryptographic operations with:
//! - Constant-time implementations to prevent timing side-channels
//! - Automatic zeroization of sensitive key material
//! - Support for both classical and post-quantum cryptography

use crate::constants::*;
use crate::error::{ProtocolError, Result};
use crate::types::*;
use blake3::Hasher;
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce as ChaNonce,
    aead::{Aead, KeyInit, Payload},
};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, SharedSecret};

/// Key pair for Ed25519 signatures
pub struct Ed25519KeyPair {
    /// Signing key (private)
    signing_key: SigningKey,
    /// Verifying key (public)
    verifying_key: VerifyingKey,
}

impl Ed25519KeyPair {
    /// Generate a new Ed25519 key pair
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Get the public key
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.verifying_key.to_bytes())
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> Signature {
        let signature = self.signing_key.sign(message);
        Signature(signature.to_bytes())
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<()> {
        let sig = ed25519_dalek::Signature::from_bytes(signature.as_bytes());
        self.verifying_key
            .verify(message, &sig)
            .map_err(|_| ProtocolError::InvalidSignature)
    }
}

/// X25519 ephemeral key pair for ECDH
pub struct X25519EphemeralKeyPair {
    secret: EphemeralSecret,
    public: X25519PublicKey,
}

impl X25519EphemeralKeyPair {
    /// Generate a new ephemeral X25519 key pair
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random_from_rng(&mut OsRng);
        let public = X25519PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Get the public key
    pub fn public_key(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    /// Perform ECDH key agreement
    pub fn diffie_hellman(self, peer_public: &[u8; 32]) -> Result<SharedSecret> {
        let peer_public = X25519PublicKey::from(*peer_public);
        Ok(self.secret.diffie_hellman(&peer_public))
    }
}

/// BLAKE3 hasher
pub struct Blake3Hasher {
    hasher: Hasher,
}

impl Blake3Hasher {
    /// Create a new BLAKE3 hasher
    pub fn new() -> Self {
        Self {
            hasher: Hasher::new(),
        }
    }

    /// Update the hasher with data
    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    /// Finalize and return the hash
    pub fn finalize(self) -> Hash {
        let output = self.hasher.finalize();
        Hash::new(*output.as_bytes())
    }

    /// Convenience method to hash data in one shot
    pub fn hash(data: &[u8]) -> Hash {
        let output = blake3::hash(data);
        Hash::new(*output.as_bytes())
    }
}

impl Default for Blake3Hasher {
    fn default() -> Self {
        Self::new()
    }
}

/// HKDF key derivation with BLAKE3
pub struct HkdfBlake3;

impl HkdfBlake3 {
    /// Derive a key using HKDF with BLAKE3 (using SHA256 for compatibility)
    ///
    /// # Arguments
    /// * `ikm` - Input key material
    /// * `salt` - Optional salt value
    /// * `info` - Context and application-specific information (must start with "norc:")
    /// * `okm` - Output key material buffer
    pub fn derive(ikm: &[u8], salt: &[u8], info: &str, okm: &mut [u8]) -> Result<()> {
        // Enforce domain separation - all labels must start with "norc:"
        if !info.starts_with(DOMAIN_PREFIX) {
            return Err(ProtocolError::CryptoError(format!(
                "HKDF info must start with '{}', got: {}",
                DOMAIN_PREFIX, info
            )));
        }

        let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
        hk.expand(info.as_bytes(), okm)
            .map_err(|e| ProtocolError::CryptoError(format!("HKDF expansion failed: {}", e)))
    }

    /// Derive a 32-byte key
    pub fn derive_32(ikm: &[u8], salt: &[u8], info: &str) -> Result<[u8; 32]> {
        let mut okm = [0u8; 32];
        Self::derive(ikm, salt, info, &mut okm)?;
        Ok(okm)
    }
}

/// ChaCha20-Poly1305 authenticated encryption
pub struct ChaCha20Poly1305Cipher {
    cipher: ChaCha20Poly1305,
}

impl ChaCha20Poly1305Cipher {
    /// Create a new cipher with the given key
    pub fn new(key: &SymmetricKey) -> Self {
        let key = Key::from_slice(key.as_bytes());
        Self {
            cipher: ChaCha20Poly1305::new(key),
        }
    }

    /// Encrypt data with associated data
    pub fn encrypt(&self, nonce: &Nonce, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let nonce_bytes = ChaNonce::from_slice(nonce.as_bytes());
        let payload = Payload {
            msg: plaintext,
            aad,
        };

        self.cipher
            .encrypt(nonce_bytes, payload)
            .map_err(|e| ProtocolError::CryptoError(format!("Encryption failed: {}", e)))
    }

    /// Decrypt data with associated data
    pub fn decrypt(&self, nonce: &Nonce, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let nonce_bytes = ChaNonce::from_slice(nonce.as_bytes());
        let payload = Payload {
            msg: ciphertext,
            aad,
        };

        self.cipher
            .decrypt(nonce_bytes, payload)
            .map_err(|e| ProtocolError::CryptoError(format!("Decryption failed: {}", e)))
    }
}

/// Generate a random nonce
pub fn generate_nonce() -> Nonce {
    let mut nonce = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce);
    Nonce::new(nonce)
}

/// Generate a random symmetric key
pub fn generate_symmetric_key() -> SymmetricKey {
    let mut key = [0u8; KEY_SIZE];
    OsRng.fill_bytes(&mut key);
    SymmetricKey::new(key)
}

/// Generate cryptographically secure random bytes
pub fn generate_random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Constant-time comparison
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_keygen_and_sign() {
        let keypair = Ed25519KeyPair::generate();
        let message = b"test message";
        let signature = keypair.sign(message);
        assert!(keypair.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_x25519_ecdh() {
        let alice = X25519EphemeralKeyPair::generate();
        let bob = X25519EphemeralKeyPair::generate();

        let alice_public = alice.public_key();
        let bob_public = bob.public_key();

        let alice_shared = alice.diffie_hellman(&bob_public).unwrap();
        let bob_shared = bob.diffie_hellman(&alice_public).unwrap();

        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }

    #[test]
    fn test_blake3_hash() {
        let data = b"test data";
        let hash1 = Blake3Hasher::hash(data);
        let hash2 = Blake3Hasher::hash(data);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hkdf_domain_separation() {
        let ikm = b"input key material";
        let salt = b"salt";

        // Valid label with norc: prefix
        assert!(HkdfBlake3::derive_32(ikm, salt, "norc:test:v1").is_ok());

        // Invalid label without norc: prefix
        assert!(HkdfBlake3::derive_32(ikm, salt, "invalid:test").is_err());
    }

    #[test]
    fn test_chacha20_poly1305() {
        let key = generate_symmetric_key();
        let cipher = ChaCha20Poly1305Cipher::new(&key);
        let nonce = generate_nonce();
        let plaintext = b"secret message";
        let aad = b"additional data";

        let ciphertext = cipher.encrypt(&nonce, plaintext, aad).unwrap();
        let decrypted = cipher.decrypt(&nonce, &ciphertext, aad).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_constant_time_eq() {
        let a = [1, 2, 3, 4];
        let b = [1, 2, 3, 4];
        let c = [1, 2, 3, 5];

        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
    }
}
