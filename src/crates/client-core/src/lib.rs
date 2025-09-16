//! NavaTron NORC Client Core
//!
//! Headless client library for the NORC protocol. Provides connection management,
//! preliminary authentication scaffolding, and message handling placeholders.
//! Actual cryptographic session establishment & replay protection are pending (see
//! `SECURITY.md`).
//!
//! # Example (Connecting)
//!
//! ```rust,no_run
//! use navatron_client_core::{Client, ClientConfig};
//! use std::time::Duration;
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let config = ClientConfig {
//!     server_host: "example.com".to_string(),
//!     server_port: 8443,
//!     use_tls: true,
//!     connect_timeout: Duration::from_secs(10),
//!     ..Default::default()
//! };
//!
//! let client = Client::with_config(config);
//! client.connect().await?;
//! client.authenticate().await?;
//! # Ok(())
//! # }
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

/// Client error types
pub mod error;

/// Client implementation and configuration
pub mod client;

// Re-exports for convenience
pub use error::{ClientError, Result};
pub use client::{Client, ClientConfig, ClientState, ClientEvent};