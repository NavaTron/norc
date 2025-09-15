//! NavaTron NORC Server Core
//!
//! Server-side implementation providing client session management, message routing,
//! and federation capabilities for the NORC protocol.
//!
//! # Features
//! 
//! - **Session Management**: Handle multiple client connections with authentication
//! - **Message Routing**: Route messages between clients, including cross-device delivery
//! - **Federation**: Communicate with other NORC servers for distributed messaging
//! - **Storage**: Persistent message and user data storage (optional)
//! - **Security**: End-to-end encryption, message authentication, replay protection
//!
//! # Example
//!
//! ```rust,no_run
//! use navatron_server_core::{Server, ServerConfig};
//! use std::time::Duration;
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let config = ServerConfig {
//!     bind_host: "0.0.0.0".to_string(),
//!     bind_port: 8443,
//!     use_tls: true,
//!     max_connections: 1000,
//!     session_timeout: Duration::from_secs(3600),
//!     ..Default::default()
//! };
//!
//! let server = Server::with_config(config);
//! server.start().await?;
//! # Ok(())
//! # }
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

/// Error types for server operations
pub mod error;

/// Server configuration and main implementation
pub mod server;

/// Client session management
pub mod session;

/// Message routing and delivery
pub mod router;

/// Federation with other servers
pub mod federation;

// Re-exports for convenience
pub use error::{ServerError, Result};
pub use server::{Server, ServerConfig};
pub use session::{ClientSession, SessionManager};
pub use router::{MessageRouter, RoutingTable};