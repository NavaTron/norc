//! Transport layer errors

use std::io;
use thiserror::Error;

/// Transport layer result type
pub type Result<T> = std::result::Result<T, TransportError>;

/// Transport layer errors
#[derive(Debug, Error, Clone)]
pub enum TransportError {
    /// IO error
    #[error("IO error: {message}")]
    Io {
        /// Error message
        message: String,
    },

    /// TLS error
    #[error("TLS error: {message}")]
    Tls {
        /// Error message  
        message: String,
    },

    /// Connection error
    #[error("Connection error: {message}")]
    Connection {
        /// Error message
        message: String,
    },

    /// Protocol error from the lower layer
    #[error("Protocol error: {0}")]
    Protocol(#[from] navatron_protocol::NorcError),

    /// WebSocket error
    #[error("WebSocket error: {message}")]
    WebSocket {
        /// Error message
        message: String,
    },

    /// Timeout error
    #[error("Operation timed out after {duration_ms}ms")]
    Timeout {
        /// Timeout duration in milliseconds
        duration_ms: u64,
    },

    /// Invalid configuration
    #[error("Invalid configuration: {message}")]
    Config {
        /// Error message
        message: String,
    },

    /// ALPN negotiation failed
    #[error("ALPN negotiation failed: expected {expected:?}, got {actual:?}")]
    AlpnMismatch {
        /// Expected ALPN protocol
        expected: Vec<String>,
        /// Actual ALPN protocol
        actual: Option<String>,
    },

    /// Certificate validation error
    #[error("Certificate validation failed: {message}")]
    Certificate {
        /// Error message
        message: String,
    },

    /// Connection closed unexpectedly
    #[error("Connection closed unexpectedly")]
    ConnectionClosed,

    /// Authentication failed
    #[error("Authentication failed: {message}")]
    Authentication {
        /// Error message
        message: String,
    },

    /// Rate limit exceeded
    #[error("Rate limit exceeded: {message}")]
    RateLimit {
        /// Error message
        message: String,
    },

    /// Protocol version not supported
    #[error("Protocol version not supported: {version}")]
    UnsupportedVersion {
        /// Unsupported version
        version: String,
    },
}

impl TransportError {
    /// Create a connection error
    pub fn connection(message: impl Into<String>) -> Self {
        Self::Connection {
            message: message.into(),
        }
    }

    /// Create a configuration error
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config {
            message: message.into(),
        }
    }

    /// Create a certificate error
    pub fn certificate(message: impl Into<String>) -> Self {
        Self::Certificate {
            message: message.into(),
        }
    }

    /// Create an authentication error
    pub fn authentication(message: impl Into<String>) -> Self {
        Self::Authentication {
            message: message.into(),
        }
    }

    /// Create a rate limit error
    pub fn rate_limit(message: impl Into<String>) -> Self {
        Self::RateLimit {
            message: message.into(),
        }
    }

    /// Create an unsupported version error
    pub fn unsupported_version(version: impl Into<String>) -> Self {
        Self::UnsupportedVersion {
            version: version.into(),
        }
    }

    /// Check if the error is recoverable
    pub fn is_recoverable(&self) -> bool {
        match self {
            TransportError::Io { message } => {
                // Simple string-based heuristics for common recoverable IO errors
                message.contains("Connection refused") ||
                message.contains("Connection aborted") ||
                message.contains("Connection reset") ||
                message.contains("Timed out") ||
                message.contains("Interrupted")
            },
            TransportError::Timeout { .. } => true,
            TransportError::RateLimit { .. } => true,
            TransportError::ConnectionClosed => true,
            _ => false,
        }
    }

    /// Check if the error is retryable
    pub fn is_retryable(&self) -> bool {
        match self {
            TransportError::Io { message } => {
                // Simple string-based heuristics for retryable IO errors  
                message.contains("Connection refused") ||
                message.contains("Timed out") ||
                message.contains("Interrupted")
            },
            TransportError::Timeout { .. } => true,
            TransportError::RateLimit { .. } => true,
            _ => false,
        }
    }
}

// Manual From implementations to make error cloneable
impl From<io::Error> for TransportError {
    fn from(err: io::Error) -> Self {
        TransportError::Io {
            message: err.to_string(),
        }
    }
}

impl From<rustls::Error> for TransportError {
    fn from(err: rustls::Error) -> Self {
        TransportError::Tls {
            message: err.to_string(),
        }
    }
}

impl From<tokio_tungstenite::tungstenite::Error> for TransportError {
    fn from(err: tokio_tungstenite::tungstenite::Error) -> Self {
        TransportError::WebSocket {
            message: err.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_creation() {
        let err = TransportError::connection("test connection error");
        assert!(matches!(err, TransportError::Connection { .. }));

        let err = TransportError::config("test config error");
        assert!(matches!(err, TransportError::Config { .. }));

        let err = TransportError::certificate("test cert error");
        assert!(matches!(err, TransportError::Certificate { .. }));

        let err = TransportError::authentication("test auth error");
        assert!(matches!(err, TransportError::Authentication { .. }));

        let err = TransportError::rate_limit("test rate limit error");
        assert!(matches!(err, TransportError::RateLimit { .. }));

        let err = TransportError::unsupported_version("1.0");
        assert!(matches!(err, TransportError::UnsupportedVersion { .. }));
    }

    #[test]
    fn test_error_categorization() {
        let timeout_err = TransportError::Timeout { duration_ms: 5000 };
        assert!(timeout_err.is_recoverable());
        assert!(timeout_err.is_retryable());

        let rate_limit_err = TransportError::rate_limit("too many requests");
        assert!(rate_limit_err.is_recoverable());
        assert!(rate_limit_err.is_retryable());

        let config_err = TransportError::config("invalid setting");
        assert!(!config_err.is_recoverable());
        assert!(!config_err.is_retryable());

        let conn_closed = TransportError::ConnectionClosed;
        assert!(conn_closed.is_recoverable());
        assert!(!conn_closed.is_retryable());
    }

    #[test]
    fn test_io_error_categorization() {
        let refused = TransportError::from(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "connection refused",
        ));
        assert!(refused.is_recoverable());
        assert!(refused.is_retryable());

        let permission = TransportError::from(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "permission denied",
        ));
        assert!(!permission.is_recoverable());
        assert!(!permission.is_retryable());
    }
}