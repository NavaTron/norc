//! Transport layer errors

use thiserror::Error;

/// Result type for transport operations
pub type Result<T> = std::result::Result<T, TransportError>;

/// Transport layer errors
#[derive(Error, Debug)]
pub enum TransportError {
    /// Connection errors
    #[error("Connection error: {message}")]
    Connection { message: String },

    /// TLS errors
    #[error("TLS error: {message}")]
    Tls { message: String },

    /// WebSocket errors
    #[error("WebSocket error: {message}")]
    WebSocket { message: String },

    /// Timeout errors
    #[error("Timeout: {message}")]
    Timeout { message: String },

    /// IO errors
    #[error("IO error: {source}")]
    Io { source: std::io::Error },
}

impl TransportError {
    /// Create a connection error
    pub fn connection(message: impl Into<String>) -> Self {
        Self::Connection {
            message: message.into(),
        }
    }

    /// Create a TLS error
    pub fn tls(message: impl Into<String>) -> Self {
        Self::Tls {
            message: message.into(),
        }
    }

    /// Create a WebSocket error
    pub fn websocket(message: impl Into<String>) -> Self {
        Self::WebSocket {
            message: message.into(),
        }
    }

    /// Create a timeout error
    pub fn timeout(message: impl Into<String>) -> Self {
        Self::Timeout {
            message: message.into(),
        }
    }
}