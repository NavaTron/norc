//! Transport layer errors

use thiserror::Error;

/// Transport errors
#[derive(Debug, Error)]
pub enum TransportError {
    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// TLS error
    #[error("TLS error: {0}")]
    Tls(String),

    /// WebSocket error
    #[error("WebSocket error: {0}")]
    WebSocket(String),

    /// Connection error
    #[error("Connection error: {0}")]
    Connection(String),

    /// Timeout error
    #[error("Timeout: {0}")]
    Timeout(String),

    /// Protocol error
    #[error("Protocol error: {0}")]
    Protocol(String),

    /// Message too large
    #[error("Message too large: {0} bytes")]
    MessageTooLarge(usize),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Configuration(String),

    /// Other error
    #[error("{0}")]
    Other(String),
}

/// Result type for transport operations
pub type Result<T> = std::result::Result<T, TransportError>;
