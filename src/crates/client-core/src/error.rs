//! Client errors

use thiserror::Error;

/// Result type
pub type Result<T> = std::result::Result<T, ClientError>;

/// Client errors
#[derive(Error, Debug)]
pub enum ClientError {
    /// Generic error
    #[error("Client error: {message}")]
    Generic { message: String },
}

impl ClientError {
    /// Create a generic error
    pub fn generic(message: impl Into<String>) -> Self {
        Self::Generic {
            message: message.into(),
        }
    }
}