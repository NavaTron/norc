//! Error types for the NORC protocol

use thiserror::Error;

/// Protocol errors
#[derive(Debug, Error)]
pub enum ProtocolError {
    /// Invalid protocol version
    #[error("Invalid protocol version: {0}")]
    InvalidVersion(String),

    /// Unsupported feature
    #[error("Unsupported feature: {0}")]
    UnsupportedFeature(String),

    /// Cryptographic operation failed
    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    /// Invalid message format
    #[error("Invalid message format: {0}")]
    InvalidMessage(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Deserialization error
    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    /// Handshake failed
    #[error("Handshake failed: {0}")]
    HandshakeError(String),

    /// Trust verification failed
    #[error("Trust verification failed: {0}")]
    TrustError(String),

    /// Invalid signature
    #[error("Invalid signature")]
    InvalidSignature,

    /// Invalid public key
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    /// Invalid private key
    #[error("Invalid private key: {0}")]
    InvalidPrivateKey(String),

    /// Message too large
    #[error("Message too large: {0} bytes (max: {1})")]
    MessageTooLarge(usize, usize),

    /// Timeout
    #[error("Operation timed out: {0}")]
    Timeout(String),

    /// I/O error
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// Other error
    #[error("{0}")]
    Other(String),
}

/// Result type for protocol operations
pub type Result<T> = std::result::Result<T, ProtocolError>;

impl From<bincode::Error> for ProtocolError {
    fn from(err: bincode::Error) -> Self {
        ProtocolError::SerializationError(err.to_string())
    }
}

impl From<serde_json::Error> for ProtocolError {
    fn from(err: serde_json::Error) -> Self {
        ProtocolError::SerializationError(err.to_string())
    }
}
