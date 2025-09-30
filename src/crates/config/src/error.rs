//! Configuration error types

use thiserror::Error;

/// Configuration errors
#[derive(Debug, Error)]
pub enum ConfigError {
    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// TOML parsing error
    #[error("TOML error: {0}")]
    Toml(#[from] toml::de::Error),

    /// TOML serialization error
    #[error("TOML serialization error: {0}")]
    TomlSer(#[from] toml::ser::Error),

    /// Validation error
    #[error("Validation error: {0}")]
    Validation(String),

    /// Missing configuration
    #[error("Missing configuration: {0}")]
    Missing(String),

    /// Invalid value
    #[error("Invalid value for {0}: {1}")]
    InvalidValue(String, String),
}

