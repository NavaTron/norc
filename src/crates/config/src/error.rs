//! Configuration error types

use thiserror::Error;

/// Result type alias for configuration operations
pub type Result<T> = std::result::Result<T, ConfigError>;

/// Configuration-specific error types
#[derive(Error, Debug)]
pub enum ConfigError {
    /// File I/O errors
    #[error("File I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// TOML parsing errors
    #[error("TOML parsing error: {0}")]
    Toml(#[from] toml::de::Error),

    /// Configuration validation errors
    #[error("Configuration validation error: {0}")]
    Validation(String),

    /// Missing required configuration
    #[error("Missing required configuration: {0}")]
    MissingRequired(String),

    /// Invalid configuration value
    #[error("Invalid configuration value for '{field}': {message}")]
    InvalidValue { field: String, message: String },

    /// Environment variable errors
    #[error("Environment variable error: {0}")]
    Environment(String),
}