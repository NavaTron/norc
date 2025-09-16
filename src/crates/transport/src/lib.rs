//! NavaTron NORC Transport Layer
//!
//! Provides concrete network transports (TLS, WebSocket) and connection lifecycle
//! management for the NORC protocol. Security‑critical pieces (TLS policy, ALPN, rate
//! limiting) are evolving; consult `SECURITY.md` for current guarantees vs. roadmap.
//!
//! ## Features (Scaffold Status)
//!
//! - **TLS Support**: API surface present; certificate validation & mTLS policy enforcement TBD
//! - **WebSocket Transport**: Structural stubs; masking/backpressure hooks planned
//! - **Connection Management**: Basic handles + metadata types
//! - **Rate Limiting**: Token bucket primitives (integration pending)
//! - **Observability**: Tracing spans available; metrics exporter pending
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