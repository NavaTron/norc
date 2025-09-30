//! Server error types

use thiserror::Error;

/// Server errors
#[derive(Debug, Error)]
pub enum ServerError {
    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(#[from] norc_config::ConfigError),

    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Signal handling error
    #[error("Signal handling error: {0}")]
    Signal(String),

    /// Daemon error
    #[error("Daemon error: {0}")]
    Daemon(String),

    /// Server startup failed
    #[error("Server startup failed: {0}")]
    Startup(String),

    /// Server shutdown failed
    #[error("Server shutdown failed: {0}")]
    Shutdown(String),

    /// Protocol error
    #[error("Protocol error: {0}")]
    Protocol(String),

    /// Transport error
    #[error("Transport error: {0}")]
    Transport(String),

    /// Network error
    #[error("Network error: {0}")]
    Network(String),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),

    /// Security error
    #[error("Security error: {0}")]
    Security(String),

    /// Routing error
    #[error("Routing error: {0}")]
    Routing(String),

    /// Prometheus error
    #[error("Prometheus error: {0}")]
    Prometheus(#[from] prometheus::Error),
}
