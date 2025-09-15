//! Client implementation

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info};

use navatron_protocol::{
    messages::{NorcMessage},
    types::DeviceId,
};
use navatron_transport::{
    connection::ConnectionHandle,
    tls::TlsClientConfig,
    websocket::WebSocketConfig,
};

use crate::error::{ClientError, Result};

/// Client connection state
#[derive(Debug, Clone, PartialEq)]
pub enum ClientState {
    /// Client is disconnected
    Disconnected,
    /// Client is connecting
    Connecting,
    /// Client is connected but not authenticated
    Connected,
    /// Client is authenticated and ready
    Authenticated,
    /// Client is disconnecting
    Disconnecting,
}

/// Client configuration
#[derive(Debug)]
pub struct ClientConfig {
    /// Server hostname
    pub server_host: String,
    /// Server port
    pub server_port: u16,
    /// Use TLS encryption
    pub use_tls: bool,
    /// TLS configuration
    pub tls_config: Option<TlsClientConfig>,
    /// WebSocket configuration
    pub websocket_config: WebSocketConfig,
    /// Connection timeout
    pub connect_timeout: Duration,
    /// Heartbeat interval
    pub heartbeat_interval: Duration,
    /// Maximum reconnection attempts
    pub max_reconnect_attempts: u32,
    /// Reconnection delay
    pub reconnect_delay: Duration,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            server_host: "localhost".to_string(),
            server_port: 8443,
            use_tls: true,
            tls_config: None,
            websocket_config: WebSocketConfig::default(),
            connect_timeout: Duration::from_secs(30),
            heartbeat_interval: Duration::from_secs(30),
            max_reconnect_attempts: 5,
            reconnect_delay: Duration::from_secs(5),
        }
    }
}

/// Client events
#[derive(Debug, Clone)]
pub enum ClientEvent {
    /// Connection established
    Connected,
    /// Authentication completed
    Authenticated,
    /// Message received
    MessageReceived(NorcMessage),
    /// Connection lost
    Disconnected,
    /// Error occurred
    Error(ClientError),
}

/// NORC client
pub struct Client {
    /// Client configuration
    config: ClientConfig,
    /// Client state
    state: Arc<RwLock<ClientState>>,
    /// Device identity
    identity: Option<DeviceId>,
    /// Active connection
    connection: Arc<RwLock<Option<ConnectionHandle>>>,
    /// Event sender
    event_sender: Option<mpsc::UnboundedSender<ClientEvent>>,
    /// Event receiver
    event_receiver: Arc<RwLock<Option<mpsc::UnboundedReceiver<ClientEvent>>>>,
}

impl Client {
    /// Create a new client with default configuration
    pub fn new() -> Self {
        Self::with_config(ClientConfig::default())
    }
    
    /// Create a new client with custom configuration
    pub fn with_config(config: ClientConfig) -> Self {
        let (event_sender, event_receiver) = mpsc::unbounded_channel();
        
        Self {
            config,
            state: Arc::new(RwLock::new(ClientState::Disconnected)),
            identity: None,
            connection: Arc::new(RwLock::new(None)),
            event_sender: Some(event_sender),
            event_receiver: Arc::new(RwLock::new(Some(event_receiver))),
        }
    }
    
    /// Set device identity
    pub fn with_identity(mut self, identity: DeviceId) -> Self {
        self.identity = Some(identity);
        self
    }
    
    /// Get current client state
    pub async fn state(&self) -> ClientState {
        self.state.read().await.clone()
    }
    
    /// Check if client is connected
    pub async fn is_connected(&self) -> bool {
        matches!(
            *self.state.read().await,
            ClientState::Connected | ClientState::Authenticated
        )
    }
    
    /// Check if client is authenticated
    pub async fn is_authenticated(&self) -> bool {
        matches!(*self.state.read().await, ClientState::Authenticated)
    }
    
    /// Get event receiver for listening to client events
    pub async fn events(&self) -> Option<mpsc::UnboundedReceiver<ClientEvent>> {
        self.event_receiver.write().await.take()
    }
    
    /// Connect to the server
    pub async fn connect(&self) -> Result<()> {
        let current_state = self.state().await;
        if current_state != ClientState::Disconnected {
            return Err(ClientError::InvalidState {
                expected: "Disconnected".to_string(),
                actual: format!("{:?}", current_state),
            });
        }
        
        info!("Connecting to {}:{}", self.config.server_host, self.config.server_port);
        
        // Update state to connecting
        *self.state.write().await = ClientState::Connecting;
        
        // Attempt connection
        match self.establish_connection().await {
            Ok(connection) => {
                *self.connection.write().await = Some(connection);
                *self.state.write().await = ClientState::Connected;
                
                if let Some(sender) = &self.event_sender {
                    let _ = sender.send(ClientEvent::Connected);
                }
                
                info!("Connected successfully");
                Ok(())
            }
            Err(err) => {
                *self.state.write().await = ClientState::Disconnected;
                
                if let Some(sender) = &self.event_sender {
                    let _ = sender.send(ClientEvent::Error(err.clone()));
                }
                
                error!("Connection failed: {}", err);
                Err(err)
            }
        }
    }
    
    /// Disconnect from the server
    pub async fn disconnect(&self) -> Result<()> {
        let current_state = self.state().await;
        if current_state == ClientState::Disconnected {
            return Ok(());
        }
        
        info!("Disconnecting from server");
        
        *self.state.write().await = ClientState::Disconnecting;
        
        // Close connection
        if let Some(connection) = self.connection.write().await.take() {
            // Connection cleanup will be handled by Drop trait
            drop(connection);
        }
        
        *self.state.write().await = ClientState::Disconnected;
        
        if let Some(sender) = &self.event_sender {
            let _ = sender.send(ClientEvent::Disconnected);
        }
        
        info!("Disconnected");
        Ok(())
    }
    
    /// Send a message to the server
    pub async fn send_message(&self, message: NorcMessage) -> Result<()> {
        if !self.is_connected().await {
            return Err(ClientError::NotConnected);
        }
        
        let connection_guard = self.connection.read().await;
        let connection = connection_guard
            .as_ref()
            .ok_or(ClientError::NotConnected)?;
        
        connection
            .send_message(message)
            .await
            .map_err(|e| ClientError::send_failed(e.to_string()))?;
        
        Ok(())
    }
    
    /// Authenticate with the server
    pub async fn authenticate(&self) -> Result<()> {
        if !self.is_connected().await {
            return Err(ClientError::NotConnected);
        }
        
        let identity = self.identity
            .as_ref()
            .ok_or_else(|| ClientError::authentication("No device identity configured"))?;
        
        // TODO: Implement proper authentication protocol
        // For now, just mark as authenticated
        *self.state.write().await = ClientState::Authenticated;
        
        if let Some(sender) = &self.event_sender {
            let _ = sender.send(ClientEvent::Authenticated);
        }
        
        info!("Authentication completed");
        Ok(())
    }
    
    /// Establish connection to server
    async fn establish_connection(&self) -> Result<ConnectionHandle> {
        let server_addr = format!("{}:{}", self.config.server_host, self.config.server_port);
        
        // TODO: Implement actual connection establishment using transport layer
        // For now, return an error indicating this is not yet implemented
        Err(ClientError::connection(format!(
            "Connection establishment not yet implemented for {}", 
            server_addr
        )))
    }
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        // Note: async drop is not available in stable Rust
        // Connection cleanup will be handled by the connection's Drop trait
        debug!("Client dropped");
    }
}