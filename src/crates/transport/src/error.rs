//! Transport error types

use thiserror::Error;

/// Result type alias for transport operations
pub type Result<T> = std::result::Result<T, TransportError>;

/// Transport-specific error types
#[derive(Error, Debug)]
pub enum TransportError {
    /// Network I/O errors
    #[error("Network I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Protocol errors
    #[error("Protocol error: {0}")]
    Protocol(#[from] norc_protocol::ProtocolError),

    /// Connection errors
    #[error("Connection error: {0}")]
    Connection(String),

    /// TLS errors
    #[error("TLS error: {0}")]
    Tls(String),
}
