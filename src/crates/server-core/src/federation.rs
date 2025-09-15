//! Federation with other NORC servers

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use navatron_protocol::{
    messages::{NorcMessage, Message, FederationHelloMessage},
    types::{ServerId, UserId},
};
use navatron_transport::connection::ConnectionHandle;

use crate::error::{ServerError, Result};

/// Federation connection state
#[derive(Debug, Clone, PartialEq)]
pub enum FederationState {
    /// Disconnected from federated server
    Disconnected,
    /// Connecting to federated server
    Connecting,
    /// Connected but not yet authenticated
    Connected,
    /// Fully authenticated and operational
    Authenticated,
    /// Connection is failing
    Failed,
}

/// Information about a federated server
pub struct FederatedServer {
    /// Server identifier (domain name)
    server_id: ServerId,
    /// Server hostname for connection
    hostname: String,
    /// Server port for connection
    port: u16,
    /// Federation state
    state: FederationState,
    /// Connection handle (if connected)
    connection: Option<ConnectionHandle>,
    /// Last successful connection time
    last_connected: Option<chrono::DateTime<chrono::Utc>>,
    /// Users hosted on this server
    hosted_users: Vec<UserId>,
    /// Server capabilities
    capabilities: HashMap<String, String>,
}

impl FederatedServer {
    /// Create a new federated server entry
    pub fn new(server_id: ServerId, hostname: String, port: u16) -> Self {
        Self {
            server_id,
            hostname,
            port,
            state: FederationState::Disconnected,
            connection: None,
            last_connected: None,
            hosted_users: Vec::new(),
            capabilities: HashMap::new(),
        }
    }
    
    /// Get server ID
    pub fn server_id(&self) -> &ServerId {
        &self.server_id
    }
    
    /// Get connection address
    pub fn address(&self) -> String {
        format!("{}:{}", self.hostname, self.port)
    }
    
    /// Get federation state
    pub fn state(&self) -> &FederationState {
        &self.state
    }
    
    /// Check if server is connected
    pub fn is_connected(&self) -> bool {
        matches!(
            self.state,
            FederationState::Connected | FederationState::Authenticated
        )
    }
    
    /// Update federation state
    pub fn set_state(&mut self, state: FederationState) {
        debug!(
            server_id = %self.server_id,
            old_state = ?self.state,
            new_state = ?state,
            "Federation state transition"
        );
        self.state = state;
    }
    
    /// Set connection handle
    pub fn set_connection(&mut self, connection: Option<ConnectionHandle>) {
        let is_connected = connection.is_some();
        self.connection = connection;
        if is_connected {
            self.last_connected = Some(chrono::Utc::now());
        }
    }
    
    /// Add hosted user
    pub fn add_hosted_user(&mut self, user_id: UserId) {
        if !self.hosted_users.contains(&user_id) {
            self.hosted_users.push(user_id);
        }
    }
    
    /// Remove hosted user
    pub fn remove_hosted_user(&mut self, user_id: &UserId) {
        self.hosted_users.retain(|u| u != user_id);
    }
    
    /// Get hosted users
    pub fn hosted_users(&self) -> &[UserId] {
        &self.hosted_users
    }
    
    /// Check if user is hosted on this server
    pub fn hosts_user(&self, user_id: &UserId) -> bool {
        self.hosted_users.contains(user_id)
    }
    
    /// Set server capability
    pub fn set_capability(&mut self, key: String, value: String) {
        self.capabilities.insert(key, value);
    }
    
    /// Get server capability
    pub fn get_capability(&self, key: &str) -> Option<&String> {
        self.capabilities.get(key)
    }
}

/// Federation manager handles connections to other NORC servers
pub struct FederationManager {
    /// Our server ID
    server_id: ServerId,
    /// Known federated servers
    servers: Arc<RwLock<HashMap<ServerId, FederatedServer>>>,
    /// User to server mapping for routing
    user_servers: Arc<RwLock<HashMap<UserId, ServerId>>>,
    /// Federation configuration
    config: FederationConfig,
}

/// Federation configuration
#[derive(Debug, Clone)]
pub struct FederationConfig {
    /// Enable federation
    pub enabled: bool,
    /// Our server domain
    pub server_domain: String,
    /// Federation listen port
    pub federation_port: u16,
    /// Connection timeout
    pub connect_timeout: Duration,
    /// Heartbeat interval
    pub heartbeat_interval: Duration,
    /// Reconnection attempts
    pub max_reconnect_attempts: u32,
    /// Allowed federated servers (empty = allow all)
    pub allowed_servers: Vec<ServerId>,
}

impl Default for FederationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            server_domain: "localhost".to_string(),
            federation_port: 8444,
            connect_timeout: Duration::from_secs(30),
            heartbeat_interval: Duration::from_secs(60),
            max_reconnect_attempts: 5,
            allowed_servers: Vec::new(),
        }
    }
}

impl FederationManager {
    /// Create a new federation manager
    pub fn new(server_id: ServerId, config: FederationConfig) -> Self {
        Self {
            server_id,
            servers: Arc::new(RwLock::new(HashMap::new())),
            user_servers: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }
    
    /// Check if federation is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }
    
    /// Get our server ID
    pub fn server_id(&self) -> &ServerId {
        &self.server_id
    }
    
    /// Add a known federated server
    pub async fn add_server(&self, server: FederatedServer) -> Result<()> {
        let server_id = server.server_id().clone();
        
        // Check if server is allowed
        if !self.config.allowed_servers.is_empty()
            && !self.config.allowed_servers.contains(&server_id)
        {
            return Err(ServerError::federation(format!(
                "Server {} not in allowed list",
                server_id
            )));
        }
        
        self.servers.write().await.insert(server_id.clone(), server);
        
        info!(server_id = %server_id, "Added federated server");
        Ok(())
    }
    
    /// Remove a federated server
    pub async fn remove_server(&self, server_id: &ServerId) -> Result<()> {
        let mut servers = self.servers.write().await;
        
        if let Some(server) = servers.remove(server_id) {
            // Update user mappings
            let mut user_servers = self.user_servers.write().await;
            for user_id in server.hosted_users() {
                user_servers.remove(user_id);
            }
            
            info!(server_id = %server_id, "Removed federated server");
        }
        
        Ok(())
    }
    
    /// Get a federated server
    pub async fn get_server(&self, server_id: &ServerId) -> Option<ServerId> {
        if self.servers.read().await.contains_key(server_id) {
            Some(server_id.clone())
        } else {
            None
        }
    }
    
    /// Connect to a federated server
    pub async fn connect_to_server(&self, server_id: &ServerId) -> Result<()> {
        let mut servers = self.servers.write().await;
        let server = servers
            .get_mut(server_id)
            .ok_or_else(|| ServerError::federation("Server not found"))?;
        
        if server.is_connected() {
            return Ok(());
        }
        
        server.set_state(FederationState::Connecting);
        
        // TODO: Implement actual connection establishment
        // For now, simulate connection
        info!(
            server_id = %server_id,
            address = %server.address(),
            "Connecting to federated server"
        );
        
        // Simulate connection failure for now
        server.set_state(FederationState::Failed);
        Err(ServerError::federation("Federation connection not yet implemented"))
    }
    
    /// Handle incoming federation message
    pub async fn handle_federation_message(&self, message: NorcMessage) -> Result<()> {
        match &message.payload {
            Message::FederationHello(hello) => {
                self.handle_federation_hello(hello).await
            }
            // Handle other federation message types
            _ => {
                debug!("Ignoring non-federation message");
                Ok(())
            }
        }
    }
    
    /// Handle federation hello message
    async fn handle_federation_hello(&self, hello: &FederationHelloMessage) -> Result<()> {
        info!(
            from_server = %hello.server_id,
            "Received federation hello"
        );
        
        // Check if server is allowed
        if !self.config.allowed_servers.is_empty()
            && !self.config.allowed_servers.contains(&hello.server_id)
        {
            return Err(ServerError::federation(format!(
                "Server {} not allowed for federation",
                hello.server_id
            )));
        }
        
        // Update or add server
        let mut servers = self.servers.write().await;
        if let Some(server) = servers.get_mut(&hello.server_id) {
            server.set_state(FederationState::Authenticated);
            
            // Note: The current FederationHelloMessage doesn't have hosted_users
            // In a real implementation, this would be part of the protocol
        } else {
            // Create new server entry - we don't have host/port from the hello message
            // In a real implementation, this would be part of the protocol
            let mut server = FederatedServer::new(
                hello.server_id.clone(),
                "unknown".to_string(), // Placeholder
                8444, // Default port
            );
            server.set_state(FederationState::Authenticated);
            
            servers.insert(hello.server_id.clone(), server);
        }
        
        Ok(())
    }
    
    /// Route a message to a federated server
    pub async fn route_to_server(
        &self,
        server_id: &ServerId,
        message: NorcMessage,
    ) -> Result<()> {
        let servers = self.servers.read().await;
        let server = servers
            .get(server_id)
            .ok_or_else(|| ServerError::federation("Target server not found"))?;
        
        if !server.is_connected() {
            return Err(ServerError::federation("Target server not connected"));
        }
        
        // TODO: Send message through federation connection
        debug!(
            server_id = %server_id,
            "Routing message to federated server"
        );
        
        Ok(())
    }
    
    /// Find which server hosts a user
    pub async fn find_user_server(&self, user_id: &UserId) -> Option<ServerId> {
        self.user_servers.read().await.get(user_id).cloned()
    }
    
    /// Route a message to the appropriate federated server for a user
    pub async fn route_to_user_server(
        &self,
        user_id: &UserId,
        message: NorcMessage,
    ) -> Result<()> {
        let server_id = self
            .find_user_server(user_id)
            .await
            .ok_or_else(|| ServerError::federation("User server not found"))?;
        
        self.route_to_server(&server_id, message).await
    }
    
    /// Get all connected federated servers
    pub async fn connected_servers(&self) -> Vec<ServerId> {
        self.servers
            .read()
            .await
            .values()
            .filter(|server| server.is_connected())
            .map(|server| server.server_id().clone())
            .collect()
    }
    
    /// Get federation statistics
    pub async fn get_stats(&self) -> FederationStats {
        let servers = self.servers.read().await;
        let total_servers = servers.len();
        let connected_servers = servers
            .values()
            .filter(|server| server.is_connected())
            .count();
        let federated_users = self.user_servers.read().await.len();
        
        FederationStats {
            total_servers,
            connected_servers,
            federated_users,
        }
    }
}

/// Federation statistics
#[derive(Debug, Clone)]
pub struct FederationStats {
    /// Total known federated servers
    pub total_servers: usize,
    /// Currently connected servers
    pub connected_servers: usize,
    /// Total federated users
    pub federated_users: usize,
}