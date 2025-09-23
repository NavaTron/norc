//! Core server implementation

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::{broadcast, RwLock};
use tracing::{info, warn, error, debug};

use crate::{ServerError, Result, Connection, ConnectionManager};

/// Server configuration
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Server bind address
    pub bind_address: SocketAddr,
    /// Maximum number of concurrent connections
    pub max_connections: usize,
    /// Connection timeout in seconds
    pub connection_timeout: u64,
    /// Enable TLS
    pub enable_tls: bool,
    /// TLS certificate file path
    pub tls_cert_path: Option<String>,
    /// TLS private key file path
    pub tls_key_path: Option<String>,
    /// Server name for TLS
    pub server_name: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_address: "0.0.0.0:4242".parse().unwrap(),
            max_connections: 1000,
            connection_timeout: 300, // 5 minutes
            enable_tls: false,
            tls_cert_path: None,
            tls_key_path: None,
            server_name: "norc-server".to_string(),
        }
    }
}

/// Core NORC server
#[derive(Clone)]
pub struct Server {
    config: ServerConfig,
    connection_manager: Arc<ConnectionManager>,
    shutdown_tx: Arc<RwLock<Option<broadcast::Sender<()>>>>,
}

impl Server {
    /// Create a new server instance
    pub async fn new(config: ServerConfig) -> Result<Self> {
        debug!("Creating new server with config: {:?}", config);
        
        let connection_manager = Arc::new(ConnectionManager::new(config.max_connections));
        
        Ok(Self {
            config,
            connection_manager,
            shutdown_tx: Arc::new(RwLock::new(None)),
        })
    }

    /// Start the server and begin accepting connections
    pub async fn start(&self) -> Result<()> {
        info!("Starting NORC server on {}", self.config.bind_address);

        // Setup shutdown channel
        let (shutdown_tx, _) = broadcast::channel(1);
        {
            let mut tx_guard = self.shutdown_tx.write().await;
            *tx_guard = Some(shutdown_tx);
        }

        // Bind to the configured address
        let listener = TcpListener::bind(&self.config.bind_address).await
            .map_err(|e| ServerError::Lifecycle(format!("Failed to bind to {}: {}", self.config.bind_address, e)))?;

        info!("Server listening on {}", self.config.bind_address);

        // Accept connections loop
        loop {
            // Check for shutdown signal
            if let Some(ref shutdown_tx) = *self.shutdown_tx.read().await {
                let mut shutdown_rx = shutdown_tx.subscribe();
                
                tokio::select! {
                    // Accept new connection
                    result = listener.accept() => {
                        match result {
                            Ok((stream, addr)) => {
                                debug!("Accepted connection from {}", addr);
                                
                                // Check connection limits
                                if self.connection_manager.connection_count().await >= self.config.max_connections {
                                    warn!("Connection limit reached, rejecting connection from {}", addr);
                                    drop(stream);
                                    continue;
                                }

                                // Handle connection
                                let connection_manager = self.connection_manager.clone();
                                let config = self.config.clone();
                                
                                tokio::spawn(async move {
                                    if let Err(e) = Self::handle_connection(stream, addr, connection_manager, config).await {
                                        error!("Connection handling error for {}: {}", addr, e);
                                    }
                                });
                            }
                            Err(e) => {
                                error!("Failed to accept connection: {}", e);
                                // Continue accepting other connections
                            }
                        }
                    }
                    
                    // Shutdown signal received
                    _ = shutdown_rx.recv() => {
                        info!("Server shutdown signal received");
                        break;
                    }
                }
            } else {
                break;
            }
        }

        info!("Server stopped accepting connections");
        Ok(())
    }

    /// Handle a single client connection
    async fn handle_connection(
        stream: tokio::net::TcpStream,
        addr: SocketAddr,
        connection_manager: Arc<ConnectionManager>,
        _config: ServerConfig,
    ) -> Result<()> {
        debug!("Handling connection from {}", addr);

        // Create connection wrapper
        let connection = Connection::new(stream, addr).await?;
        
        // Register connection
        let connection_id = connection_manager.add_connection(connection.clone()).await?;
        
        // Handle connection lifecycle
        let result = connection.handle().await;
        
        // Cleanup connection
        connection_manager.remove_connection(connection_id).await;
        
        match result {
            Ok(_) => {
                debug!("Connection from {} closed normally", addr);
            }
            Err(e) => {
                warn!("Connection from {} closed with error: {}", addr, e);
            }
        }

        Ok(())
    }

    /// Shutdown the server gracefully
    pub async fn shutdown(&self) -> Result<()> {
        info!("Shutting down server...");

        // Send shutdown signal
        if let Some(ref shutdown_tx) = *self.shutdown_tx.read().await {
            let _ = shutdown_tx.send(());
        }

        // Close all connections
        self.connection_manager.shutdown_all().await;

        info!("Server shutdown complete");
        Ok(())
    }

    /// Get server statistics
    pub async fn stats(&self) -> ServerStats {
        ServerStats {
            active_connections: self.connection_manager.connection_count().await,
            total_connections: self.connection_manager.total_connections().await,
            uptime_seconds: 0, // TODO: Track uptime
        }
    }

    /// Get server configuration
    pub fn config(&self) -> &ServerConfig {
        &self.config
    }
}

/// Server statistics
#[derive(Debug, Clone)]
pub struct ServerStats {
    /// Current number of active connections
    pub active_connections: usize,
    /// Total connections handled since start
    pub total_connections: u64,
    /// Server uptime in seconds
    pub uptime_seconds: u64,
}