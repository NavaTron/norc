//!use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer};Identity and key management

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use ring::rand::SystemRandom;
use serde::{Deserialize, Serialize};

use crate::{ProtocolError, Result};

/// Public key type for NORC protocol
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct PublicKey {
    /// Ed25519 public key bytes
    pub key: [u8; 32],
}

/// Identity key pair for cryptographic operations
#[derive(Debug, Clone)]
pub struct IdentityKeyPair {
    /// Ed25519 signing key
    signing_key: SigningKey,
    /// Ed25519 verifying key (public key)
    verifying_key: VerifyingKey,
}

/// User identity with cryptographic keys
#[derive(Debug, Clone)]
pub struct Identity {
    /// User identifier
    pub user_id: String,
    /// Display name
    pub display_name: String,
    /// Public key for verification
    pub public_key: PublicKey,
    /// Optional key pair for signing (only available for local identity)
    pub key_pair: Option<IdentityKeyPair>,
}

impl PublicKey {
    /// Create a new public key from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { key: bytes }
    }

    /// Get the key bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }

    /// Verify a signature against this public key
    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> Result<()> {
        let verifying_key = VerifyingKey::from_bytes(&self.key)
            .map_err(|e| ProtocolError::Crypto(format!("Invalid public key: {}", e)))?;

        let signature = Signature::from_bytes(signature);

        verifying_key
            .verify(message, &signature)
            .map_err(|e| ProtocolError::Crypto(format!("Signature verification failed: {}", e)))?;

        Ok(())
    }
}

impl IdentityKeyPair {
    /// Generate a new key pair
    pub fn generate() -> Result<Self> {
        let rng = SystemRandom::new();
        let mut seed = [0u8; 32];

        // Generate random seed using ring's SystemRandom
        ring::rand::SecureRandom::fill(&rng, &mut seed)
            .map_err(|e| ProtocolError::Crypto(format!("Failed to generate random seed: {}", e)))?;

        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();

        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    /// Get the public key
    pub fn public_key(&self) -> PublicKey {
        PublicKey::from_bytes(self.verifying_key.to_bytes())
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing_key.sign(message).to_bytes()
    }

    /// Verify a signature (using own public key)
    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> Result<()> {
        self.public_key().verify(message, signature)
    }
}

impl Identity {
    /// Create a new identity with generated keys
    pub fn new(user_id: String, display_name: String) -> Result<Self> {
        let key_pair = IdentityKeyPair::generate()?;
        let public_key = key_pair.public_key();

        Ok(Self {
            user_id,
            display_name,
            public_key,
            key_pair: Some(key_pair),
        })
    }

    /// Create an identity from a public key only (for remote users)
    pub fn from_public_key(user_id: String, display_name: String, public_key: PublicKey) -> Self {
        Self {
            user_id,
            display_name,
            public_key,
            key_pair: None,
        }
    }

    /// Check if this identity can sign messages
    pub fn can_sign(&self) -> bool {
        self.key_pair.is_some()
    }

    /// Sign a message with this identity's private key
    pub fn sign(&self, message: &[u8]) -> Result<[u8; 64]> {
        match &self.key_pair {
            Some(key_pair) => Ok(key_pair.sign(message)),
            None => Err(ProtocolError::Crypto(
                "No private key available for signing".to_string(),
            )),
        }
    }

    /// Verify a signature against this identity's public key
    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> Result<()> {
        self.public_key.verify(message, signature)
    }
}
