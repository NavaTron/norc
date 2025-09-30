//! Persistence layer errors

use thiserror::Error;

/// Result type for persistence operations
pub type Result<T> = std::result::Result<T, PersistenceError>;

/// Persistence layer errors
#[derive(Debug, Error)]
pub enum PersistenceError {
    /// Database error
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    /// Migration error
    #[error("Migration error: {0}")]
    Migration(String),

    /// Not found error
    #[error("Entity not found: {0}")]
    NotFound(String),

    /// Duplicate key error
    #[error("Duplicate key: {0}")]
    DuplicateKey(String),

    /// Validation error
    #[error("Validation error: {0}")]
    Validation(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Configuration(String),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<serde_json::Error> for PersistenceError {
    fn from(err: serde_json::Error) -> Self {
        PersistenceError::Serialization(err.to_string())
    }
}

impl From<bincode::Error> for PersistenceError {
    fn from(err: bincode::Error) -> Self {
        PersistenceError::Serialization(err.to_string())
    }
}
