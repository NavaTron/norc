//! Core types for the NORC protocol

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Device identifier (BLAKE3 hash of device public key)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeviceId([u8; 32]);

impl DeviceId {
    /// Create a new device ID from a hash
    pub fn new(hash: [u8; 32]) -> Self {
        Self(hash)
    }

    /// Get the hash as bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for DeviceId {
    fn from(hash: [u8; 32]) -> Self {
        Self(hash)
    }
}

/// User identifier (organization-local)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UserId(String);

impl UserId {
    /// Create a new user ID
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Get the ID as a string
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Organization identifier (DNS-based)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OrgId(String);

impl OrgId {
    /// Create a new organization ID
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Get the ID as a string
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Conversation identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConvId([u8; 32]);

impl ConvId {
    /// Create a new conversation ID from a hash
    pub fn new(hash: [u8; 32]) -> Self {
        Self(hash)
    }

    /// Get the hash as bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Message identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MessageId([u8; 32]);

impl MessageId {
    /// Create a new message ID from a hash
    pub fn new(hash: [u8; 32]) -> Self {
        Self(hash)
    }

    /// Get the hash as bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Ed25519 public key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKey(pub [u8; 32]);

impl PublicKey {
    /// Get the key as bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Ed25519 private key (zeroized on drop)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PrivateKey(pub [u8; 32]);

impl PrivateKey {
    /// Get the key as bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Ed25519 signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature(#[serde(with = "BigArray")] pub [u8; 64]);

impl Signature {
    /// Get the signature as bytes
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

/// BLAKE3 hash
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Hash([u8; 32]);

impl Hash {
    /// Create a new hash
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get the hash as bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Symmetric encryption key (zeroized on drop)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SymmetricKey(pub [u8; 32]);

impl SymmetricKey {
    /// Create a new symmetric key
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get the key as bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Nonce for ChaCha20-Poly1305
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Nonce(pub [u8; 12]);

impl Nonce {
    /// Create a new nonce
    pub fn new(bytes: [u8; 12]) -> Self {
        Self(bytes)
    }

    /// Get the nonce as bytes
    pub fn as_bytes(&self) -> &[u8; 12] {
        &self.0
    }
}

/// MAC tag for Poly1305
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacTag(pub [u8; 16]);

impl MacTag {
    /// Get the tag as bytes
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}
