//! Connection Pool Manager
//!
//! Manages concurrent client connections with resource limits and
//! efficient connection handling using the async runtime.
//!
//! Complies with F-01.04 Resource Management requirements.

use crate::error::ServerError;
use crate::runtime::{AsyncRuntime, WorkloadType};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Duration, Instant};

/// Unique connection identifier
pub type ConnectionId = u64;

/// Connection state information
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    /// Connection ID
    pub id: ConnectionId,
    
    /// Remote socket address
    pub remote_addr: SocketAddr,
    
    /// Connection establishment time
    pub established_at: Instant,
    
    /// Last activity timestamp
    pub last_activity: Instant,
    
    /// Number of messages sent
    pub messages_sent: u64,
    
    /// Number of messages received
    pub messages_received: u64,
    
    /// Total bytes sent
    pub bytes_sent: u64,
    
    /// Total bytes received
    pub bytes_received: u64,
}

/// Connection pool for managing concurrent client connections
pub struct ConnectionPool {
    /// Active connections
    connections: Arc<RwLock<HashMap<ConnectionId, ConnectionInfo>>>,
    
    /// Next connection ID
    next_id: Arc<RwLock<ConnectionId>>,
    
    /// Maximum concurrent connections
    max_connections: usize,
    
    /// Maximum idle time before disconnect (seconds)
    max_idle_time: Duration,
    
    /// Async runtime reference
    runtime: Arc<AsyncRuntime>,
}

impl ConnectionPool {
    /// Create a new connection pool
    pub fn new(
        max_connections: usize,
        max_idle_time_secs: u64,
        runtime: Arc<AsyncRuntime>,
    ) -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            next_id: Arc::new(RwLock::new(1)),
            max_connections,
            max_idle_time: Duration::from_secs(max_idle_time_secs),
            runtime,
        }
    }
    
    /// Register a new connection
    pub async fn register(&self, remote_addr: SocketAddr) -> Result<ConnectionId, ServerError> {
        // Check if we've reached the connection limit
        let current_count = self.connections.read().await.len();
        if current_count >= self.max_connections {
            return Err(ServerError::Internal(format!(
                "Connection limit reached: {} / {}",
                current_count, self.max_connections
            )));
        }
        
        // Generate new connection ID
        let mut next_id = self.next_id.write().await;
        let id = *next_id;
        *next_id += 1;
        drop(next_id);
        
        // Create connection info
        let now = Instant::now();
        let info = ConnectionInfo {
            id,
            remote_addr,
            established_at: now,
            last_activity: now,
            messages_sent: 0,
            messages_received: 0,
            bytes_sent: 0,
            bytes_received: 0,
        };
        
        // Store connection
        self.connections.write().await.insert(id, info);
        
        eprintln!(
            "Connection registered: {} from {} ({} / {} active)",
            id,
            remote_addr,
            current_count + 1,
            self.max_connections
        );
        
        Ok(id)
    }
    
    /// Unregister a connection
    pub async fn unregister(&self, id: ConnectionId) {
        if let Some(info) = self.connections.write().await.remove(&id) {
            let duration = info.last_activity.duration_since(info.established_at);
            eprintln!(
                "Connection unregistered: {} from {} (duration: {:?}, {} msgs sent, {} msgs received)",
                id,
                info.remote_addr,
                duration,
                info.messages_sent,
                info.messages_received
            );
        }
    }
    
    /// Update connection activity
    pub async fn update_activity(&self, id: ConnectionId) {
        if let Some(info) = self.connections.write().await.get_mut(&id) {
            info.last_activity = Instant::now();
        }
    }
    
    /// Record message sent
    pub async fn record_sent(&self, id: ConnectionId, bytes: u64) {
        if let Some(info) = self.connections.write().await.get_mut(&id) {
            info.messages_sent += 1;
            info.bytes_sent += bytes;
            info.last_activity = Instant::now();
        }
    }
    
    /// Record message received
    pub async fn record_received(&self, id: ConnectionId, bytes: u64) {
        if let Some(info) = self.connections.write().await.get_mut(&id) {
            info.messages_received += 1;
            info.bytes_received += bytes;
            info.last_activity = Instant::now();
        }
    }
    
    /// Get connection info
    pub async fn get_info(&self, id: ConnectionId) -> Option<ConnectionInfo> {
        self.connections.read().await.get(&id).cloned()
    }
    
    /// Get all connection IDs
    pub async fn get_all_ids(&self) -> Vec<ConnectionId> {
        self.connections.read().await.keys().copied().collect()
    }
    
    /// Get active connection count
    pub async fn count(&self) -> usize {
        self.connections.read().await.len()
    }
    
    /// Get connection pool statistics
    pub async fn get_stats(&self) -> ConnectionPoolStats {
        let connections = self.connections.read().await;
        
        let total_connections = connections.len();
        let mut total_messages_sent = 0u64;
        let mut total_messages_received = 0u64;
        let mut total_bytes_sent = 0u64;
        let mut total_bytes_received = 0u64;
        
        for info in connections.values() {
            total_messages_sent += info.messages_sent;
            total_messages_received += info.messages_received;
            total_bytes_sent += info.bytes_sent;
            total_bytes_received += info.bytes_received;
        }
        
        ConnectionPoolStats {
            active_connections: total_connections,
            max_connections: self.max_connections,
            total_messages_sent,
            total_messages_received,
            total_bytes_sent,
            total_bytes_received,
        }
    }
    
    /// Start background cleanup task for idle connections
    pub fn start_cleanup_task(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        let pool = self.clone();
        
        self.runtime.spawn(WorkloadType::Background, async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            
            loop {
                interval.tick().await;
                
                // Find and remove idle connections
                let now = Instant::now();
                let mut to_remove = Vec::new();
                
                {
                    let connections = pool.connections.read().await;
                    for (id, info) in connections.iter() {
                        if now.duration_since(info.last_activity) > pool.max_idle_time {
                            to_remove.push(*id);
                        }
                    }
                }
                
                // Remove idle connections
                for id in to_remove {
                    pool.unregister(id).await;
                    eprintln!("Removed idle connection: {}", id);
                }
            }
        })
    }
}

/// Connection pool statistics
#[derive(Debug, Clone)]
pub struct ConnectionPoolStats {
    pub active_connections: usize,
    pub max_connections: usize,
    pub total_messages_sent: u64,
    pub total_messages_received: u64,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use norc_config::ResourceLimits;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_connection_registration() {
        let limits = ResourceLimits {
            max_connections: 10,
            max_message_size: 1024,
            rate_limit_per_connection: 100,
            max_memory_per_connection: 1024,
            worker_threads: 2,
        };
        
        let runtime = Arc::new(AsyncRuntime::new(&limits).unwrap());
        let pool = ConnectionPool::new(10, 300, runtime.clone());
        
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let id = pool.register(addr).await.unwrap();
        
        assert_eq!(id, 1);
        assert_eq!(pool.count().await, 1);
        
        // Use mem::forget to prevent runtime drop in async context
        std::mem::forget(pool);
        std::mem::forget(runtime);
    }
    
    #[tokio::test]
    async fn test_connection_limit() {
        let limits = ResourceLimits {
            max_connections: 2,
            max_message_size: 1024,
            rate_limit_per_connection: 100,
            max_memory_per_connection: 1024,
            worker_threads: 2,
        };
        
        let runtime = Arc::new(AsyncRuntime::new(&limits).unwrap());
        let pool = ConnectionPool::new(2, 300, runtime.clone());
        
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        
        pool.register(addr).await.unwrap();
        pool.register(addr).await.unwrap();
        
        // Third connection should fail
        let result = pool.register(addr).await;
        assert!(result.is_err());
        
        // Use mem::forget to prevent runtime drop in async context
        std::mem::forget(pool);
        std::mem::forget(runtime);
    }
    
    #[tokio::test]
    async fn test_connection_stats() {
        let limits = ResourceLimits {
            max_connections: 10,
            max_message_size: 1024,
            rate_limit_per_connection: 100,
            max_memory_per_connection: 1024,
            worker_threads: 2,
        };
        
        let runtime = Arc::new(AsyncRuntime::new(&limits).unwrap());
        let pool = ConnectionPool::new(10, 300, runtime.clone());
        
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let id = pool.register(addr).await.unwrap();
        
        pool.record_sent(id, 100).await;
        pool.record_received(id, 200).await;
        
        let stats = pool.get_stats().await;
        assert_eq!(stats.active_connections, 1);
        assert_eq!(stats.total_messages_sent, 1);
        assert_eq!(stats.total_messages_received, 1);
        assert_eq!(stats.total_bytes_sent, 100);
        assert_eq!(stats.total_bytes_received, 200);
        
        // Use mem::forget to prevent runtime drop in async context
        std::mem::forget(pool);
        std::mem::forget(runtime);
    }
}
