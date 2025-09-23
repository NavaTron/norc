//! Connection management and handling

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, error, info, warn};

use norc_protocol::{Message, MessageType, MessagePayload, ProtocolError};
use crate::{ServerError, Result};

/// Unique connection identifier
pub type ConnectionId = u64;

/// Individual client connection
#[derive(Clone)]
pub struct Connection {
    id: ConnectionId,
    addr: SocketAddr,
    stream: Arc<Mutex<TcpStream>>,
}

impl Connection {
    /// Create a new connection
    pub async fn new(stream: TcpStream, addr: SocketAddr) -> Result<Self> {
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        
        Ok(Self {
            id,
            addr,
            stream: Arc::new(Mutex::new(stream)),
        })
    }

    /// Get connection ID
    pub fn id(&self) -> ConnectionId {
        self.id
    }

    /// Get connection address
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Handle the connection lifecycle
    pub async fn handle(&self) -> Result<()> {
        debug!("Starting connection handler for {}", self.addr);

        let mut buffer = vec![0u8; 8192];
        
        loop {
            // Read from connection
            let bytes_read = {
                let mut stream = self.stream.lock().await;
                match stream.read(&mut buffer).await {
                    Ok(0) => {
                        debug!("Connection {} closed by client", self.addr);
                        break;
                    }
                    Ok(n) => n,
                    Err(e) => {
                        error!("Read error on connection {}: {}", self.addr, e);
                        return Err(ServerError::Connection(format!("Read error: {}", e)));
                    }
                }
            };

            // Process the received data
            match self.process_data(&buffer[..bytes_read]).await {
                Ok(response) => {
                    if let Some(response_data) = response {
                        if let Err(e) = self.send_response(response_data).await {
                            error!("Failed to send response to {}: {}", self.addr, e);
                            break;
                        }
                    }
                }
                Err(e) => {
                    error!("Error processing data from {}: {}", self.addr, e);
                    // Send error response and close connection
                    break;
                }
            }
        }

        debug!("Connection handler for {} finished", self.addr);
        Ok(())
    }

    /// Process received data and return optional response
    async fn process_data(&self, data: &[u8]) -> Result<Option<Vec<u8>>> {
        // Try to parse as a NORC protocol message
        match Message::from_bytes(data) {
            Ok(message) => {
                debug!("Received message from {}: {:?}", self.addr, message.header.message_type);
                self.handle_message(message).await
            }
            Err(ProtocolError::Serialization(_)) => {
                // Not a valid protocol message, might be partial data
                debug!("Received partial or invalid data from {}", self.addr);
                Ok(None)
            }
            Err(e) => {
                warn!("Protocol error from {}: {}", self.addr, e);
                Err(ServerError::Protocol(e))
            }
        }
    }

    /// Handle a parsed protocol message
    async fn handle_message(&self, message: Message) -> Result<Option<Vec<u8>>> {
        match message.payload {
            MessagePayload::Ping { timestamp } => {
                debug!("Handling ping from {}", self.addr);
                
                // Create pong response
                let sender_key = message.header.sender.clone(); // Clone to avoid move
                let pong_message = Message::new(
                    MessageType::Pong,
                    MessagePayload::Pong {
                        original_timestamp: timestamp,
                        response_timestamp: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis() as u64,
                    },
                    message.header.recipient.unwrap_or(sender_key.clone()), // Use sender's key as response sender
                    Some(sender_key), // Send back to original sender
                );
                
                Ok(Some(pong_message.to_bytes()?))
            }
            
            MessagePayload::Handshake { client_version, capabilities } => {
                info!("Handshake from {}: version={}, capabilities={:?}", 
                      self.addr, client_version, capabilities);
                
                // TODO: Implement proper handshake logic
                // For now, just acknowledge
                Ok(None)
            }
            
            MessagePayload::Text { content, channel } => {
                info!("Text message from {}: channel={:?}, content='{}'", 
                      self.addr, channel, content);
                
                // TODO: Implement message routing and storage
                Ok(None)
            }
            
            _ => {
                debug!("Unhandled message type from {}: {:?}", self.addr, message.header.message_type);
                Ok(None)
            }
        }
    }

    /// Send response data to the client
    async fn send_response(&self, data: Vec<u8>) -> Result<()> {
        let mut stream = self.stream.lock().await;
        stream.write_all(&data).await
            .map_err(|e| ServerError::Connection(format!("Write error: {}", e)))?;
        stream.flush().await
            .map_err(|e| ServerError::Connection(format!("Flush error: {}", e)))?;
        Ok(())
    }

    /// Close the connection
    pub async fn close(&self) -> Result<()> {
        debug!("Closing connection {}", self.addr);
        let mut stream = self.stream.lock().await;
        stream.shutdown().await
            .map_err(|e| ServerError::Connection(format!("Shutdown error: {}", e)))?;
        Ok(())
    }
}

/// Connection manager for tracking active connections
pub struct ConnectionManager {
    connections: Arc<RwLock<HashMap<ConnectionId, Connection>>>,
    max_connections: usize,
    total_connections: AtomicU64,
}

impl ConnectionManager {
    /// Create a new connection manager
    pub fn new(max_connections: usize) -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            max_connections,
            total_connections: AtomicU64::new(0),
        }
    }

    /// Add a new connection
    pub async fn add_connection(&self, connection: Connection) -> Result<ConnectionId> {
        let connection_id = connection.id();
        
        {
            let mut connections = self.connections.write().await;
            
            if connections.len() >= self.max_connections {
                return Err(ServerError::ResourceLimit(
                    format!("Maximum connections ({}) reached", self.max_connections)
                ));
            }
            
            connections.insert(connection_id, connection);
        }
        
        self.total_connections.fetch_add(1, Ordering::Relaxed);
        debug!("Added connection {}", connection_id);
        
        Ok(connection_id)
    }

    /// Remove a connection
    pub async fn remove_connection(&self, connection_id: ConnectionId) {
        let mut connections = self.connections.write().await;
        if connections.remove(&connection_id).is_some() {
            debug!("Removed connection {}", connection_id);
        }
    }

    /// Get current connection count
    pub async fn connection_count(&self) -> usize {
        self.connections.read().await.len()
    }

    /// Get total connections handled
    pub async fn total_connections(&self) -> u64 {
        self.total_connections.load(Ordering::Relaxed)
    }

    /// Get a connection by ID
    pub async fn get_connection(&self, connection_id: ConnectionId) -> Option<Connection> {
        self.connections.read().await.get(&connection_id).cloned()
    }

    /// Shutdown all connections
    pub async fn shutdown_all(&self) {
        info!("Shutting down all connections...");
        
        let connections = {
            let mut connections_guard = self.connections.write().await;
            let connections = connections_guard.clone();
            connections_guard.clear();
            connections
        };

        for (id, connection) in connections {
            if let Err(e) = connection.close().await {
                warn!("Error closing connection {}: {}", id, e);
            }
        }
        
        info!("All connections closed");
    }

    /// Get all active connections
    pub async fn get_all_connections(&self) -> Vec<Connection> {
        self.connections.read().await.values().cloned().collect()
    }
}