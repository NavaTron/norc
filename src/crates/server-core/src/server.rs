//! Main server implementation

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, RwLock};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use navatron_protocol::{
    messages::NorcMessage,
    types::{DeviceId, SessionId, UserId, ServerId},
};
use navatron_transport::{
    connection::ConnectionHandle,
    tls::TlsServerConfig,
    websocket::WebSocketConfig,
};

use crate::error::{ServerError, Result};
use crate::session::{ClientSession, SessionManager};
use crate::router::MessageRouter;
use crate::federation::{FederationManager, FederationConfig};

/// Server configuration
#[derive(Debug)]
pub struct ServerConfig {
    /// Server bind address
    pub bind_host: String,
    /// Server bind port
    pub bind_port: u16,
    /// Use TLS encryption
    pub use_tls: bool,
    /// TLS configuration
    pub tls_config: Option<TlsServerConfig>,
    /// WebSocket configuration
    pub websocket_config: WebSocketConfig,
    /// Maximum concurrent connections
    pub max_connections: usize,
    /// Session timeout
    pub session_timeout: Duration,
    /// Federation configuration
    pub federation_config: FederationConfig,
    /// Server identification
    pub server_id: ServerId,
    /// Message queue size
    pub message_queue_size: usize,
    /// Cleanup interval for expired sessions
    pub cleanup_interval: Duration,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_host: "0.0.0.0".to_string(),
            bind_port: 8443,
            use_tls: true,
            tls_config: None,
            websocket_config: WebSocketConfig::default(),
            max_connections: 1000,
            session_timeout: Duration::from_secs(3600),
            federation_config: FederationConfig::default(),
            server_id: "localhost".to_string(),
            message_queue_size: 1000,
            cleanup_interval: Duration::from_secs(300), // 5 minutes
        }
    }
}

/// Server state
#[derive(Debug, Clone, PartialEq)]
pub enum ServerState {
    /// Server is stopped
    Stopped,
    /// Server is starting up
    Starting,
    /// Server is running and accepting connections
    Running,
    /// Server is shutting down
    Shutting,
}

/// Server events
#[derive(Debug, Clone)]
pub enum ServerEvent {
    /// Server started successfully
    Started,
    /// New client connected
    ClientConnected { session_id: SessionId, remote_addr: SocketAddr },
    /// Client disconnected
    ClientDisconnected { session_id: SessionId },
    /// Client authenticated
    ClientAuthenticated { session_id: SessionId, user_id: UserId, device_id: DeviceId },
    /// Message received from client
    MessageReceived { session_id: SessionId, message: NorcMessage },
    /// Server is shutting down
    Shutdown,
    /// Error occurred
    Error(ServerError),
}

/// Main NORC server implementation
pub struct Server {
    /// Server configuration
    config: ServerConfig,
    /// Current server state
    state: Arc<RwLock<ServerState>>,
    /// Session manager
    session_manager: Arc<SessionManager>,
    /// Message router
    message_router: Arc<MessageRouter>,
    /// Federation manager
    federation_manager: Arc<FederationManager>,
    /// TCP listener
    listener: Option<TcpListener>,
    /// Server task handles
    tasks: Vec<JoinHandle<()>>,
    /// Event sender
    event_sender: Option<mpsc::UnboundedSender<ServerEvent>>,
    /// Event receiver
    event_receiver: Arc<RwLock<Option<mpsc::UnboundedReceiver<ServerEvent>>>>,
}

impl Server {
    /// Create a new server with default configuration
    pub fn new() -> Self {
        Self::with_config(ServerConfig::default())
    }
    
    /// Create a new server with custom configuration
    pub fn with_config(config: ServerConfig) -> Self {
        let session_manager = Arc::new(SessionManager::new(
            config.max_connections,
            config.session_timeout,
        ));
        
        let message_router = Arc::new(MessageRouter::new(session_manager.clone()));
        
        let federation_manager = Arc::new(FederationManager::new(
            config.server_id.clone(),
            config.federation_config.clone(),
        ));
        
        let (event_sender, event_receiver) = mpsc::unbounded_channel();
        
        Self {
            config,
            state: Arc::new(RwLock::new(ServerState::Stopped)),
            session_manager,
            message_router,
            federation_manager,
            listener: None,
            tasks: Vec::new(),
            event_sender: Some(event_sender),
            event_receiver: Arc::new(RwLock::new(Some(event_receiver))),
        }
    }
    
    /// Get current server state
    pub async fn state(&self) -> ServerState {
        self.state.read().await.clone()
    }
    
    /// Check if server is running
    pub async fn is_running(&self) -> bool {
        matches!(*self.state.read().await, ServerState::Running)
    }
    
    /// Get event receiver for listening to server events
    pub async fn events(&self) -> Option<mpsc::UnboundedReceiver<ServerEvent>> {
        self.event_receiver.write().await.take()
    }
    
    /// Start the server
    pub async fn start(&mut self) -> Result<()> {
        let current_state = self.state().await;
        if current_state != ServerState::Stopped {
            return Err(ServerError::startup(format!(
                "Cannot start server in state {:?}",
                current_state
            )));
        }
        
        info!(
            bind_address = %format!("{}:{}", self.config.bind_host, self.config.bind_port),
            max_connections = self.config.max_connections,
            "Starting NORC server"
        );
        
        *self.state.write().await = ServerState::Starting;
        
        // Bind TCP listener
        let bind_addr = format!("{}:{}", self.config.bind_host, self.config.bind_port);
        let listener = TcpListener::bind(&bind_addr)
            .await
            .map_err(|e| ServerError::startup(format!("Failed to bind to {}: {}", bind_addr, e)))?;
        
        info!(bind_address = %bind_addr, "Server listening");
        
        self.listener = Some(listener);
        *self.state.write().await = ServerState::Running;
        
        // Start background tasks
        self.start_background_tasks().await?;
        
        if let Some(sender) = &self.event_sender {
            let _ = sender.send(ServerEvent::Started);
        }
        
        info!("NORC server started successfully");
        Ok(())
    }
    
    /// Stop the server
    pub async fn stop(&mut self) -> Result<()> {
        info!("Stopping NORC server");
        
        *self.state.write().await = ServerState::Shutting;
        
        if let Some(sender) = &self.event_sender {
            let _ = sender.send(ServerEvent::Shutdown);
        }
        
        // Cancel all background tasks
        for task in self.tasks.drain(..) {
            task.abort();
        }
        
        // Close listener
        self.listener = None;
        
        *self.state.write().await = ServerState::Stopped;
        
        info!("NORC server stopped");
        Ok(())
    }
    
    /// Run the server (blocks until shutdown)
    pub async fn run(&mut self) -> Result<()> {
        self.start().await?;
        
        // Accept connections until shutdown
        if let Some(listener) = &self.listener {
            loop {
                match self.state().await {
                    ServerState::Running => {
                        // Accept new connection
                        match listener.accept().await {
                            Ok((stream, remote_addr)) => {
                                if let Err(e) = self.handle_new_connection(stream, remote_addr).await {
                                    error!(error = %e, "Failed to handle new connection");
                                }
                            }
                            Err(e) => {
                                error!(error = %e, "Failed to accept connection");
                                // Continue running unless it's a critical error
                            }
                        }
                    }
                    ServerState::Shutting => {
                        info!("Server shutting down, stopping connection acceptance");
                        break;
                    }
                    _ => {
                        warn!("Server not in running state, stopping");
                        break;
                    }
                }
            }
        }
        
        self.stop().await?;
        Ok(())
    }
    
    /// Handle a new client connection
    async fn handle_new_connection(
        &self,
        _stream: tokio::net::TcpStream,
        remote_addr: SocketAddr,
    ) -> Result<()> {
        // Check connection limit
        if self.session_manager.session_count().await >= self.config.max_connections {
            return Err(ServerError::resource_limit(
                "connections",
                self.config.max_connections as u64,
            ));
        }
        
        let session_id = uuid::Uuid::new_v4();
        
        info!(
            session_id = %session_id,
            remote_addr = %remote_addr,
            "New client connection"
        );
        
        // TODO: Implement actual connection setup with transport layer
        // For now, create a placeholder session
        
        // Create message channel for this session
        let (message_tx, _message_rx) = mpsc::unbounded_channel::<String>();
        
        // Create placeholder connection handle
        // In real implementation, this would be created from the stream
        return Err(ServerError::connection("Connection handling not yet implemented"));
        
        // This code would be used once transport layer integration is complete:
        /*
        let connection = create_connection_from_stream(stream).await?;
        
        let session = ClientSession::new(
            session_id,
            remote_addr,
            connection,
            message_tx,
        );
        
        self.session_manager.add_session(session).await?;
        
        if let Some(sender) = &self.event_sender {
            let _ = sender.send(ServerEvent::ClientConnected {
                session_id,
                remote_addr,
            });
        }
        
        Ok(())
        */
    }
    
    /// Start background tasks
    async fn start_background_tasks(&mut self) -> Result<()> {
        // Session cleanup task
        let session_manager = self.session_manager.clone();
        let cleanup_interval = self.config.cleanup_interval;
        let cleanup_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(cleanup_interval);
            loop {
                interval.tick().await;
                if let Err(e) = session_manager.cleanup_expired_sessions().await {
                    warn!(error = %e, "Session cleanup failed");
                }
            }
        });
        self.tasks.push(cleanup_task);
        
        // Message delivery retry task
        let message_router = self.message_router.clone();
        let retry_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                if let Err(e) = message_router.retry_pending_deliveries().await {
                    warn!(error = %e, "Message retry failed");
                }
            }
        });
        self.tasks.push(retry_task);
        
        info!("Background tasks started");
        Ok(())
    }
    
    /// Get server statistics
    pub async fn get_stats(&self) -> ServerStats {
        let total_sessions = self.session_manager.session_count().await;
        let authenticated_sessions = self.session_manager.authenticated_session_count().await;
        let federation_stats = self.federation_manager.get_stats().await;
        
        ServerStats {
            state: self.state().await,
            total_sessions,
            authenticated_sessions,
            uptime: std::time::Instant::now().elapsed(), // This should track actual start time
            federation_stats,
        }
    }
    
    /// Get session manager reference
    pub fn session_manager(&self) -> &Arc<SessionManager> {
        &self.session_manager
    }
    
    /// Get message router reference
    pub fn message_router(&self) -> &Arc<MessageRouter> {
        &self.message_router
    }
    
    /// Get federation manager reference
    pub fn federation_manager(&self) -> &Arc<FederationManager> {
        &self.federation_manager
    }
}

impl Default for Server {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        // Abort all background tasks
        for task in self.tasks.drain(..) {
            task.abort();
        }
        debug!("Server dropped");
    }
}

/// Server statistics
#[derive(Debug, Clone)]
pub struct ServerStats {
    /// Current server state
    pub state: ServerState,
    /// Total active sessions
    pub total_sessions: usize,
    /// Authenticated sessions
    pub authenticated_sessions: usize,
    /// Server uptime
    pub uptime: Duration,
    /// Federation statistics
    pub federation_stats: crate::federation::FederationStats,
}