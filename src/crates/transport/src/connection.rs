//! Connection management for NORC protocol

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, RwLock};
use tokio::task::JoinHandle;
use tokio::time::{interval, Instant as TokioInstant};
use tracing::{debug, info, warn};
use uuid::Uuid;

use navatron_protocol::{
    NorcMessage, Version, WireFormat,
};

use crate::error::{Result, TransportError};

/// Connection identifier
pub type ConnectionId = Uuid;

/// Default connection timeout
pub const DEFAULT_CONNECTION_TIMEOUT: Duration = Duration::from_secs(300); // 5 minutes

/// Default ping interval
pub const DEFAULT_PING_INTERVAL: Duration = Duration::from_secs(30);

/// Connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Connection is being established
    Connecting,
    /// Connection is active and healthy
    Active,
    /// Connection is established and ready
    Established,
    /// Connection is being closed gracefully
    Closing,
    /// Connection is closed
    Closed,
}

/// Connection statistics
#[derive(Debug, Clone, Default)]
pub struct ConnectionStats {
    /// Number of messages sent
    pub messages_sent: u64,
    /// Number of messages received
    pub messages_received: u64,
    /// Total bytes sent
    pub bytes_sent: u64,
    /// Total bytes received
    pub bytes_received: u64,
    /// Connection establishment time
    pub connected_at: Option<Instant>,
    /// Last activity timestamp
    pub last_activity: Option<Instant>,
    /// Number of pings sent
    pub pings_sent: u64,
    /// Number of pongs received
    pub pongs_received: u64,
    /// Average round-trip time
    pub avg_rtt: Option<Duration>,
}

/// Connection metadata
#[derive(Debug, Clone)]
pub struct ConnectionMetadata {
    /// Unique connection identifier
    pub id: ConnectionId,
    /// Remote socket address
    pub remote_addr: SocketAddr,
    /// Local socket address (if available)
    pub local_addr: Option<SocketAddr>,
    /// Protocol version
    pub protocol_version: Version,
    /// Connection state
    pub state: ConnectionState,
    /// Connection statistics
    pub stats: ConnectionStats,
    /// Additional properties
    pub properties: HashMap<String, String>,
}

impl ConnectionMetadata {
    /// Create new connection metadata
    pub fn new(
        remote_addr: SocketAddr,
        local_addr: Option<SocketAddr>,
        protocol_version: Version,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            remote_addr,
            local_addr,
            protocol_version,
            state: ConnectionState::Connecting,
            stats: ConnectionStats::default(),
            properties: HashMap::new(),
        }
    }

    /// Set a property
    pub fn set_property(&mut self, key: String, value: String) {
        self.properties.insert(key, value);
    }

    /// Get a property
    pub fn get_property(&self, key: &str) -> Option<&str> {
        self.properties.get(key).map(|s| s.as_str())
    }

    /// Set connection state
    pub fn set_state(&mut self, state: ConnectionState) {
        self.state = state;
        self.stats.last_activity = Some(Instant::now());
    }

    /// Record sent message
    pub fn record_sent(&mut self, bytes: usize) {
        self.stats.messages_sent += 1;
        self.stats.bytes_sent += bytes as u64;
        self.stats.last_activity = Some(Instant::now());
    }

    /// Record received message
    pub fn record_received(&mut self, bytes: usize) {
        self.stats.messages_received += 1;
        self.stats.bytes_received += bytes as u64;
        self.stats.last_activity = Some(Instant::now());
    }

    /// Check if connection is inactive for given duration
    pub fn is_inactive(&self, timeout: Duration) -> bool {
        let now = Instant::now();
        
        // Check last activity first
        if let Some(last_activity) = self.stats.last_activity {
            return now.duration_since(last_activity) > timeout;
        }
        
        // Fall back to connection time
        if let Some(connected_at) = self.stats.connected_at {
            return now.duration_since(connected_at) > timeout;
        }
        
        // No activity recorded, consider inactive
        true
    }
}

/// Connection events
#[derive(Debug, Clone)]
pub enum ConnectionEvent {
    /// Connection established
    Connected {
        /// Connection ID
        id: ConnectionId,
    },
    /// Connection closed
    Disconnected {
        /// Connection ID
        id: ConnectionId,
    },
    /// Message received
    MessageReceived {
        /// Connection ID
        id: ConnectionId,
        /// Received message
        message: NorcMessage,
    },
    /// Connection error
    Error {
        /// Connection ID
        id: ConnectionId,
        /// Error details
        error: TransportError,
    },
    /// Ping sent
    PingSent {
        /// Connection ID
        id: ConnectionId,
        /// Ping timestamp
        timestamp: Instant,
    },
    /// Pong received
    PongReceived {
        /// Connection ID
        id: ConnectionId,
        /// Pong timestamp
        timestamp: Instant,
        /// Round-trip time
        rtt: Duration,
    },
}

/// Connection handle for managing an individual connection
pub struct ConnectionHandle {
    /// Connection metadata
    metadata: Arc<RwLock<ConnectionMetadata>>,
    /// Message sender
    message_tx: mpsc::UnboundedSender<NorcMessage>,
    /// Event receiver
    event_rx: mpsc::UnboundedReceiver<ConnectionEvent>,
    /// Connection task handle
    task_handle: JoinHandle<Result<()>>,
}

impl ConnectionHandle {
    /// Get connection ID
    pub async fn id(&self) -> ConnectionId {
        self.metadata.read().await.id
    }

    /// Get connection metadata
    pub async fn metadata(&self) -> ConnectionMetadata {
        self.metadata.read().await.clone()
    }

    /// Send a message
    pub async fn send_message(&self, message: NorcMessage) -> Result<()> {
        self.message_tx.send(message).map_err(|_| {
            TransportError::connection("Connection closed while sending message")
        })?;
        Ok(())
    }

    /// Receive next event
    pub async fn next_event(&mut self) -> Option<ConnectionEvent> {
        self.event_rx.recv().await
    }

    /// Close the connection gracefully
    pub async fn close(self) -> Result<()> {
        // Set state to closing
        self.metadata.write().await.set_state(ConnectionState::Closing);
        
        // Cancel the connection task
        self.task_handle.abort();
        
        // Wait for task completion (with timeout)
        match tokio::time::timeout(Duration::from_secs(5), self.task_handle).await {
            Ok(result) => result.map_err(|e| TransportError::connection(format!("Task join error: {}", e)))?,
            Err(_) => {
                warn!("Connection close timed out");
                return Err(TransportError::Timeout { duration_ms: 5000 });
            }
        }

        Ok(())
    }

    /// Check if connection is active
    pub async fn is_active(&self) -> bool {
        matches!(self.metadata.read().await.state, ConnectionState::Active)
    }

    /// Create a new connection handle
    pub fn new(
        id: ConnectionId,
        message_tx: mpsc::UnboundedSender<NorcMessage>,
        event_rx: mpsc::UnboundedReceiver<ConnectionEvent>,
        task_handle: JoinHandle<Result<()>>,
        metadata: Arc<RwLock<ConnectionMetadata>>,
    ) -> Self {
        Self {
            metadata,
            message_tx,
            event_rx,
            task_handle,
        }
    }
}

/// Connection manager for handling multiple connections
#[derive(Debug)]
pub struct ConnectionManager {
    /// Active connections
    connections: Arc<RwLock<HashMap<ConnectionId, Arc<RwLock<ConnectionMetadata>>>>>,
    /// Event sender for broadcasting connection events
    event_tx: mpsc::UnboundedSender<ConnectionEvent>,
    /// Connection timeout
    connection_timeout: Duration,
    /// Cleanup task handle
    cleanup_task: Option<JoinHandle<()>>,
}

impl ConnectionManager {
    /// Create a new connection manager
    pub fn new(event_tx: mpsc::UnboundedSender<ConnectionEvent>) -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            event_tx,
            connection_timeout: DEFAULT_CONNECTION_TIMEOUT,
            cleanup_task: None,
        }
    }

    /// Set connection timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.connection_timeout = timeout;
        self
    }

    /// Start the connection manager
    pub async fn start(&mut self) {
        let connections = Arc::clone(&self.connections);
        let timeout = self.connection_timeout;
        
        // Start cleanup task
        self.cleanup_task = Some(tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(60)); // Check every minute
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            
            loop {
                interval.tick().await;
                
                let mut to_remove = Vec::new();
                {
                    let connections_read = connections.read().await;
                    for (id, metadata) in connections_read.iter() {
                        if metadata.read().await.is_inactive(timeout) {
                            to_remove.push(*id);
                        }
                    }
                }
                
                // Remove inactive connections
                if !to_remove.is_empty() {
                    let mut connections_write = connections.write().await;
                    for id in to_remove {
                        connections_write.remove(&id);
                        info!("Removed inactive connection: {}", id);
                    }
                }
            }
        }));
    }

    /// Register a new connection
    pub async fn register_connection(&self, metadata: ConnectionMetadata) -> ConnectionId {
        let id = metadata.id;
        let metadata = Arc::new(RwLock::new(metadata));
        
        self.connections.write().await.insert(id, Arc::clone(&metadata));
        
        let _ = self.event_tx.send(ConnectionEvent::Connected { id });
        
        info!("Registered connection: {}", id);
        id
    }

    /// Unregister a connection
    pub async fn unregister_connection(&self, id: ConnectionId) {
        if self.connections.write().await.remove(&id).is_some() {
            let _ = self.event_tx.send(ConnectionEvent::Disconnected { id });
            info!("Unregistered connection: {}", id);
        }
    }

    /// Get connection metadata
    pub async fn get_connection(&self, id: ConnectionId) -> Option<ConnectionMetadata> {
        // Simplified: read lock, clone Arc, then read inner lock once.
        let map_guard = self.connections.read().await;
        let arc_meta = map_guard.get(&id)?.clone();
        let meta = arc_meta.read().await.clone();
        Some(meta)
    }

    /// Get connection count
    pub async fn connection_count(&self) -> usize {
        self.connections.read().await.len()
    }

    /// Shutdown the connection manager
    pub async fn shutdown(&mut self) {
        if let Some(cleanup_task) = self.cleanup_task.take() {
            cleanup_task.abort();
        }
        
        // Close all connections
        let connections = self.connections.read().await;
        for id in connections.keys() {
            let _ = self.event_tx.send(ConnectionEvent::Disconnected { id: *id });
        }
        
        info!("Connection manager shut down");
    }
}

/// Create a connection handle from a stream (simplified version)
pub async fn create_connection<S>(
    _stream: S,
    metadata: ConnectionMetadata,
    event_tx: mpsc::UnboundedSender<ConnectionEvent>,
) -> Result<ConnectionHandle>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let metadata = Arc::new(RwLock::new(metadata));
    let (message_tx, _message_rx) = mpsc::unbounded_channel();
    let (event_sender, event_rx) = mpsc::unbounded_channel();

    // For now, create a simple placeholder connection task
    let metadata_clone = Arc::clone(&metadata);
    let event_tx_clone = event_tx.clone();

    // Spawn connection task (simplified version without protocol handling)
    let task_handle = tokio::spawn(async move {
        info!("Connection task started for {:?}", metadata_clone.read().await.id);
        
        // Simple connection maintenance loop
        let mut ping_interval = interval(DEFAULT_PING_INTERVAL);
        ping_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = ping_interval.tick() => {
                    // Send ping if needed
                    let id = metadata_clone.read().await.id;
                    debug!("Ping interval for connection {}", id);
                }
                _ = tokio::time::sleep(Duration::from_secs(1)) => {
                    // Basic keepalive
                    continue;
                }
            }
        }
    });

    let id = metadata.read().await.id;
    
    let connection = ConnectionHandle::new(
        id,
        message_tx,
        event_rx,
        task_handle,
        Arc::clone(&metadata),
    );

    // Mark connection as established
    metadata.write().await.state = ConnectionState::Established;
    let _ = event_tx.send(ConnectionEvent::Connected { id });

    Ok(connection)
}