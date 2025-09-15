//! Common utilities for integration tests

use std::time::Duration;
use navatron_transport::websocket::WebSocketConfig;
use navatron_client_core::client::ClientConfig;
use navatron_server_core::server::ServerConfig;

/// Default test timeout duration
pub const TEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Create a test client configuration
pub fn test_client_config(port: u16) -> ClientConfig {
    ClientConfig {
        server_host: "127.0.0.1".to_string(),
        server_port: port,
        use_tls: false,
        tls_config: None,
        websocket_config: WebSocketConfig::default(),
        connect_timeout: Duration::from_secs(5),
        heartbeat_interval: Duration::from_secs(10),
        max_reconnect_attempts: 1,
        reconnect_delay: Duration::from_secs(1),
    }
}

/// Create a test server configuration
pub fn test_server_config(port: u16) -> ServerConfig {
    ServerConfig {
        bind_host: "127.0.0.1".to_string(),
        bind_port: port,
        use_tls: false,
        tls_config: None,
        websocket_config: WebSocketConfig::default(),
        max_connections: 100,
        session_timeout: Duration::from_secs(300),
        federation_config: Default::default(),
        server_id: "test-server".to_string(),
        message_queue_size: 1000,
        cleanup_interval: Duration::from_secs(60),
    }
}

/// Initialize test logging
pub fn init_test_logging() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .try_init();
}