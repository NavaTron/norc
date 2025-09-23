//! NORC Configuration Management
//!
//! Provides configuration loading, parsing, and validation for NORC server components.

pub mod error;
pub mod loader;
pub mod server;

pub use error::{ConfigError, Result};
pub use loader::ConfigLoader;
pub use server::ServerConfiguration;
