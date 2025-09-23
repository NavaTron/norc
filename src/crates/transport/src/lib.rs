//! NORC Transport Layer
//!
//! This crate provides transport layer implementations for the NORC protocol,
//! including TLS connections, connection management, rate limiting, and framing.
//!
//! # Features
//!
//! - **TLS Security**: Mandatory TLS 1.3 with strong cipher suites
//! - **Connection Management**: Async connection pooling and lifecycle management  
//! - **Rate Limiting**: Configurable rate limiting and backpressure
//! - **Message Framing**: Length-prefixed message framing over streams
//! - **Connection Multiplexing**: Multiple logical streams over a single connection
//!
//! # Example Usage
//!
//! ```rust,no_run
//! use norc_transport::{TlsListener, TlsConnector, ConnectionConfig};
//! use std::net::SocketAddr;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create a TLS listener
//! let config = ConnectionConfig::default();
//! let listener = TlsListener::bind("127.0.0.1:8443".parse::<SocketAddr>()?, config).await?;
//!
//! // Accept connections
//! while let Ok((conn, addr)) = listener.accept().await {
//!     tokio::spawn(async move {
//!         // Handle connection
//!     });
//! }
//! # Ok(())
//! # }
//! ```
