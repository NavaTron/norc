//! NORC Configuration Management
//!
//! Provides configuration loading, parsing, and validation for NORC server components.

pub mod error;
pub mod server;
pub mod loader;

pub use error::{ConfigError, Result};
pub use server::ServerConfiguration;
pub use loader::ConfigLoader;