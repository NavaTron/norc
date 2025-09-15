//! Error types for the NORC protocol

use thiserror::Error;

/// Result type for NORC protocol operations
pub type Result<T> = std::result::Result<T, NorcError>;

/// Comprehensive error types for NORC protocol operations
#[derive(Error, Debug, Clone)]
pub enum NorcError {
    /// Protocol version mismatch or invalid version
    #[error("Protocol version error: {message}")]
    Version { message: String },

    /// Message encoding/decoding errors
    #[error("Codec error: {message}")]
    Codec { message: String },

    /// Cryptographic operation errors
    #[error("Cryptographic error: {message}")]
    Crypto { message: String },

    /// Authentication and authorization errors
    #[error("Authentication error: {message}")]
    Auth { message: String },

    /// Message validation errors
    #[error("Validation error: {message}")]
    Validation { message: String },

    /// Protocol state machine errors
    #[error("Protocol state error: expected {expected}, got {actual}")]
    InvalidState { expected: String, actual: String },

    /// Network and transport errors
    #[error("Transport error: {message}")]
    Transport { message: String },

    /// Federation-specific errors
    #[error("Federation error: {message}")]
    Federation { message: String },

    /// Trust establishment errors
    #[error("Trust error: {message}")]
    Trust { message: String },

    /// Rate limiting errors
    #[error("Rate limit exceeded: {message}, retry after {retry_after_secs}s")]
    RateLimit {
        message: String,
        retry_after_secs: u64,
    },

    /// Message replay detection
    #[error("Replay detected: {message}")]
    Replay { message: String },

    /// Message ordering violations
    #[error("Ordering violation: {message}")]
    Ordering { message: String },

    /// Configuration errors
    #[error("Configuration error: {message}")]
    Config { message: String },

    /// Internal server errors
    #[error("Internal error: {message}")]
    Internal { message: String },
}

impl NorcError {
    /// Create a version error
    pub fn version(message: impl Into<String>) -> Self {
        Self::Version {
            message: message.into(),
        }
    }

    /// Create a codec error
    pub fn codec(message: impl Into<String>) -> Self {
        Self::Codec {
            message: message.into(),
        }
    }

    /// Create a crypto error
    pub fn crypto(message: impl Into<String>) -> Self {
        Self::Crypto {
            message: message.into(),
        }
    }

    /// Create an auth error
    pub fn auth(message: impl Into<String>) -> Self {
        Self::Auth {
            message: message.into(),
        }
    }

    /// Create a validation error
    pub fn validation(message: impl Into<String>) -> Self {
        Self::Validation {
            message: message.into(),
        }
    }

    /// Create a state error
    pub fn invalid_state(expected: impl Into<String>, actual: impl Into<String>) -> Self {
        Self::InvalidState {
            expected: expected.into(),
            actual: actual.into(),
        }
    }

    /// Create a transport error
    pub fn transport(message: impl Into<String>) -> Self {
        Self::Transport {
            message: message.into(),
        }
    }

    /// Create a federation error
    pub fn federation(message: impl Into<String>) -> Self {
        Self::Federation {
            message: message.into(),
        }
    }

    /// Create a trust error
    pub fn trust(message: impl Into<String>) -> Self {
        Self::Trust {
            message: message.into(),
        }
    }

    /// Create a rate limit error
    pub fn rate_limit(message: impl Into<String>, retry_after_secs: u64) -> Self {
        Self::RateLimit {
            message: message.into(),
            retry_after_secs,
        }
    }

    /// Create a replay error
    pub fn replay(message: impl Into<String>) -> Self {
        Self::Replay {
            message: message.into(),
        }
    }

    /// Create an ordering error
    pub fn ordering(message: impl Into<String>) -> Self {
        Self::Ordering {
            message: message.into(),
        }
    }

    /// Create a config error
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config {
            message: message.into(),
        }
    }

    /// Create an internal error
    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal {
            message: message.into(),
        }
    }

    /// Check if this error is retryable
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Transport { .. } | Self::RateLimit { .. } | Self::Internal { .. }
        )
    }

    /// Get the retry delay for retryable errors
    pub fn retry_after(&self) -> Option<std::time::Duration> {
        match self {
            Self::RateLimit {
                retry_after_secs, ..
            } => Some(std::time::Duration::from_secs(*retry_after_secs)),
            Self::Transport { .. } => Some(std::time::Duration::from_millis(1000)), // Default backoff
            _ => None,
        }
    }

    /// Convert to an error code for wire protocol
    pub fn error_code(&self) -> u16 {
        match self {
            Self::Version { .. } => 1000,
            Self::Codec { .. } => 1001,
            Self::Crypto { .. } => 1002,
            Self::Auth { .. } => 2000,
            Self::Validation { .. } => 3000,
            Self::InvalidState { .. } => 3001,
            Self::Transport { .. } => 4000,
            Self::Federation { .. } => 5000,
            Self::Trust { .. } => 5001,
            Self::RateLimit { .. } => 6000,
            Self::Replay { .. } => 7000,
            Self::Ordering { .. } => 7001,
            Self::Config { .. } => 8000,
            Self::Internal { .. } => 9000,
        }
    }

    /// Create error from error code and message
    pub fn from_code(code: u16, message: String) -> Self {
        match code {
            1000 => Self::version(message),
            1001 => Self::codec(message),
            1002 => Self::crypto(message),
            2000 => Self::auth(message),
            3000 => Self::validation(message),
            3001 => Self::invalid_state("unknown", message),
            4000 => Self::transport(message),
            5000 => Self::federation(message),
            5001 => Self::trust(message),
            6000 => Self::rate_limit(message, 60), // Default retry after 1 minute
            7000 => Self::replay(message),
            7001 => Self::ordering(message),
            8000 => Self::config(message),
            _ => Self::internal(message),
        }
    }
}

/// Convert various error types to NorcError
impl From<serde_json::Error> for NorcError {
    fn from(err: serde_json::Error) -> Self {
        Self::codec(format!("JSON error: {err}"))
    }
}

impl From<bincode::Error> for NorcError {
    fn from(err: bincode::Error) -> Self {
        Self::codec(format!("Bincode error: {err}"))
    }
}

impl From<base64::DecodeError> for NorcError {
    fn from(err: base64::DecodeError) -> Self {
        Self::codec(format!("Base64 decode error: {err}"))
    }
}

impl From<ed25519_dalek::SignatureError> for NorcError {
    fn from(err: ed25519_dalek::SignatureError) -> Self {
        Self::crypto(format!("Ed25519 signature error: {err}"))
    }
}

impl From<chacha20poly1305::Error> for NorcError {
    fn from(err: chacha20poly1305::Error) -> Self {
        Self::crypto(format!("ChaCha20Poly1305 error: {err}"))
    }
}

impl From<uuid::Error> for NorcError {
    fn from(err: uuid::Error) -> Self {
        Self::validation(format!("UUID error: {err}"))
    }
}

impl From<std::io::Error> for NorcError {
    fn from(err: std::io::Error) -> Self {
        Self::Transport {
            message: format!("IO error: {err}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_codes() {
        let error = NorcError::version("test");
        assert_eq!(error.error_code(), 1000);

        let error = NorcError::auth("test");
        assert_eq!(error.error_code(), 2000);

        let error = NorcError::rate_limit("test", 30);
        assert_eq!(error.error_code(), 6000);
        assert_eq!(error.retry_after(), Some(std::time::Duration::from_secs(30)));
    }

    #[test]
    fn test_error_retryable() {
        assert!(NorcError::transport("test").is_retryable());
        assert!(NorcError::rate_limit("test", 30).is_retryable());
        assert!(!NorcError::validation("test").is_retryable());
        assert!(!NorcError::crypto("test").is_retryable());
    }

    #[test]
    fn test_error_from_code() {
        let error = NorcError::from_code(1000, "version error".to_string());
        assert!(matches!(error, NorcError::Version { .. }));

        let error = NorcError::from_code(9999, "unknown error".to_string());
        assert!(matches!(error, NorcError::Internal { .. }));
    }
}