//! Protocol error types

use thiserror::Error;

/// Result type alias for protocol operations
pub type Result<T> = std::result::Result<T, ProtocolError>;

/// Protocol-specific error types
#[derive(Error, Debug)]
pub enum ProtocolError {
    /// Serialization or deserialization errors
    #[error("Serialization error: {0}")]
    Serialization(#[from] postcard::Error),

    /// JSON processing errors
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Cryptographic operation errors
    #[error("Cryptographic error: {0}")]
    Crypto(String),

    /// Message validation errors
    #[error("Invalid message: {0}")]
    InvalidMessage(String),

    /// Protocol version mismatch
    #[error("Protocol version mismatch: expected {expected}, got {actual}")]
    VersionMismatch { expected: String, actual: String },

    /// Message size exceeds limits
    #[error("Message too large: {size} bytes (max: {max})")]
    MessageTooLarge { size: usize, max: usize },

    /// Authentication or authorization errors
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    /// Generic I/O errors
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
