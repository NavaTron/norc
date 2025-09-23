//! Server error types

use thiserror::Error;

/// Result type alias for server operations
pub type Result<T> = std::result::Result<T, ServerError>;

/// Server-specific error types
#[derive(Error, Debug)]
pub enum ServerError {
    /// Configuration errors
    #[error("Configuration error: {0}")]
    Config(#[from] norc_config::ConfigError),

    /// Protocol errors
    #[error("Protocol error: {0}")]
    Protocol(#[from] norc_protocol::ProtocolError),

    /// Network I/O errors
    #[error("Network I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// TLS/encryption errors
    #[error("TLS error: {0}")]
    Tls(String),

    /// Server startup/shutdown errors
    #[error("Server lifecycle error: {0}")]
    Lifecycle(String),

    /// Connection management errors
    #[error("Connection error: {0}")]
    Connection(String),

    /// Authentication/authorization errors
    #[error("Authentication error: {0}")]
    Auth(String),

    /// Resource exhaustion errors
    #[error("Resource limit exceeded: {0}")]
    ResourceLimit(String),

    /// Generic server errors
    #[error("Server error: {0}")]
    Generic(String),
}