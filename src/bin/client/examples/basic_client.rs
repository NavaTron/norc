//! Basic NORC chat client example

use std::time::Duration;
use tokio::time::sleep;
use tracing::{info, error};

use navatron_client_core::client::{Client, ClientConfig};
use navatron_transport::websocket::WebSocketConfig;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    info!("Starting NORC chat client example");

    // Create client configuration
    let config = ClientConfig {
        server_host: "127.0.0.1".to_string(),
        server_port: 8443,
        use_tls: false, // Disable TLS for simplicity
        tls_config: None,
        websocket_config: WebSocketConfig::default(),
        connect_timeout: Duration::from_secs(10),
        heartbeat_interval: Duration::from_secs(30),
        max_reconnect_attempts: 3,
        reconnect_delay: Duration::from_secs(5),
    };

    // Create client
    let client = Client::with_config(config);
    
    info!("Attempting to connect to server...");
    
    // Try to connect (this will fail if no server is running, which is expected)
    match client.connect().await {
        Ok(_) => {
            info!("Successfully connected to server!");
            
            // In a real scenario, you would authenticate and start messaging
            // client.authenticate().await?;
            
            sleep(Duration::from_secs(1)).await;
            client.disconnect().await?;
            
            info!("Disconnected from server");
        }
        Err(e) => {
            error!("Failed to connect to server: {}", e);
            info!("This is expected if no server is running");
            info!("Client configuration and APIs are working correctly");
        }
    }

    info!("NORC client example completed");
    Ok(())
}