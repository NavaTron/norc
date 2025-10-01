//! NORC Transport Layer
//!
//! Implements transport protocols for NORC:
//! - TLS 1.3 over TCP (primary)
//! - WebSocket over TLS
//! - QUIC (optional)

pub mod error;
pub mod listener;
pub mod revocation;
pub mod tcp;
pub mod tls;
pub mod tls_config;
pub mod websocket;

#[cfg(feature = "quic")]
pub mod quic_transport;

pub use error::{Result, TransportError};
pub use listener::{ListenerConfig, NetworkListener};
pub use revocation::{RevocationChecker, RevocationConfig, RevocationStatus, RevocationError};
pub use tcp::TcpListener;
pub use tls::{TlsClientTransport, TlsServerTransport};
pub use tls_config::{create_client_config, create_server_config, TlsConfigError};
pub use websocket::WebSocketTransport;

use async_trait::async_trait;
use bytes::Bytes;

/// Transport trait for sending and receiving messages
#[async_trait]
pub trait Transport: Send + Sync {
    /// Send data over the transport
    async fn send(&mut self, data: &[u8]) -> Result<()>;

    /// Receive data from the transport
    async fn receive(&mut self) -> Result<Bytes>;

    /// Close the transport
    async fn close(&mut self) -> Result<()>;

    /// Check if the transport is connected
    fn is_connected(&self) -> bool;
}

/// Transport configuration
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// Maximum message size
    pub max_message_size: usize,
    /// Connection timeout in seconds
    pub connect_timeout_secs: u64,
    /// Read timeout in seconds
    pub read_timeout_secs: u64,
    /// Enable TLS
    pub enable_tls: bool,
    /// Enable WebSocket
    pub enable_websocket: bool,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            max_message_size: 16 * 1024 * 1024, // 16 MB
            connect_timeout_secs: 30,
            read_timeout_secs: 60,
            enable_tls: true,
            enable_websocket: false,
        }
    }
}
