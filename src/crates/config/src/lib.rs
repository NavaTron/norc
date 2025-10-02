//! NORC Configuration Management
//!
//! Provides configuration loading, parsing, and validation for NORC server components.

pub mod cli;
pub mod error;
pub mod loader;
pub mod security;
pub mod server;

pub use cli::*;
pub use error::ConfigError;
pub use server::{
    CertificatePinningConfig, FederationConfig, NetworkConfig, ObservabilityConfig,
    OcspStaplingConfig, ResourceLimits, RevocationCheckConfig, SecurityConfig, ServerConfig,
    TlsSecurityConfig,
};
