//! NavaTron NORC Transport Layer
//!
//! This crate provides the transport layer for NORC protocol communication,
//! including TLS, WebSocket connections, and connection management.
//!
//! ## Features
//!
//! - **TLS Support**: Production-ready TLS 1.3 with ALPN and optional mTLS
//! - **WebSocket Transport**: Standards-compliant WebSocket transport for web integration
//! - **Connection Management**: Advanced connection lifecycle management with health monitoring
//! - **Error Handling**: Comprehensive error types with recovery and retry guidance
//! - **Observability**: Structured logging and connection metrics
//!
//! ## Examples
//!
//! ### TLS Client Connection
//!
//! ```rust,no_run
//! use navatron_transport::tls::{TlsClientConfig, NorcTlsConnector};
//! use rustls::pki_types::ServerName;
//! use std::net::SocketAddr;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = TlsClientConfig::new();
//! let connector = NorcTlsConnector::new(config)?;
//! 
//! let addr: SocketAddr = "127.0.0.1:8443".parse()?;
//! let server_name = ServerName::try_from("localhost")?;
//! 
//! let connection = connector.connect(addr, server_name).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ### WebSocket Server
//!
//! ```rust,no_run
//! use navatron_transport::websocket::{WebSocketServer, WebSocketConfig};
//! use std::net::SocketAddr;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let addr: SocketAddr = "127.0.0.1:8080".parse()?;
//! let config = WebSocketConfig::new();
//! let server = WebSocketServer::bind(addr, config).await?;
//!
//! loop {
//!     let transport = server.accept().await?;
//!     // Handle connection...
//! }
//! # }
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs)]
#![warn(missing_debug_implementations, rust_2018_idioms)]

/// Transport layer errors
pub mod error;

/// TLS connection handling
pub mod tls;

/// WebSocket transport
pub mod websocket;

/// Connection management
pub mod connection;

/// Rate limiting primitives (token bucket, burst control)
pub mod rate_limit;

// Re-export commonly used types
pub use error::{Result, TransportError};
pub use connection::{
    ConnectionHandle, ConnectionManager, ConnectionMetadata, ConnectionState, 
    ConnectionEvent, ConnectionId, create_connection
};
pub use tls::{
    TlsClientConfig, TlsServerConfig, NorcTlsConnector, NorcTlsAcceptor, 
    TlsConnection, ClientCertVerification, NORC_ALPN
};
pub use websocket::{
    WebSocketConfig, WebSocketTransport, WebSocketServer, WebSocketAdapter
};

/// Placeholder for transport functionality
pub fn placeholder() {
    // TODO: Implement transport layer
}