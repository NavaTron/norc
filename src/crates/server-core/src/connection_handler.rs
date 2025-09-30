//! Connection handler for processing client connections
//! Implements SERVER_REQUIREMENTS F-03.02 and F-03.04

use crate::{ConnectionId, ConnectionPool, MessageRouter, ServerError};
use norc_protocol::messages::EncryptedMessage;
use norc_protocol::DeviceId;
use norc_transport::{TlsServerTransport, Transport};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Connection handler processes messages from a single client
pub struct ConnectionHandler {
    connection_id: ConnectionId,
    device_id: Option<DeviceId>,
    peer_addr: SocketAddr,
    transport: TlsServerTransport,
    router: Arc<MessageRouter>,
    pool: Arc<ConnectionPool>,
}

impl ConnectionHandler {
    /// Create a new connection handler
    pub fn new(
        connection_id: ConnectionId,
        peer_addr: SocketAddr,
        transport: TlsServerTransport,
        router: Arc<MessageRouter>,
        pool: Arc<ConnectionPool>,
    ) -> Self {
        Self {
            connection_id,
            device_id: None,
            peer_addr,
            transport,
            router,
            pool,
        }
    }

    /// Handle the connection lifecycle
    pub async fn handle(mut self) -> Result<(), ServerError> {
        info!("Handling connection {} from {}", self.connection_id, self.peer_addr);

        // Connection loop
        loop {
            match self.process_message().await {
                Ok(should_continue) => {
                    if !should_continue {
                        info!("Connection {} closed normally", self.connection_id);
                        break;
                    }
                }
                Err(e) => {
                    error!("Error processing message on connection {}: {}", self.connection_id, e);
                    break;
                }
            }
        }

        // Cleanup
        self.cleanup().await;
        
        Ok(())
    }

    /// Process a single message from the transport
    async fn process_message(&mut self) -> Result<bool, ServerError> {
        // Receive encrypted message
        let data = match self.transport.receive().await {
            Ok(data) => data,
            Err(e) => {
                warn!("Failed to receive data: {}", e);
                return Ok(false); // Connection closed
            }
        };

        debug!("Received {} bytes from {}", data.len(), self.peer_addr);

        // Deserialize encrypted message
        let encrypted_msg: EncryptedMessage = match bincode::deserialize(&data) {
            Ok(msg) => msg,
            Err(e) => {
                error!("Failed to deserialize message: {}", e);
                return Err(ServerError::Protocol(format!("Invalid message format: {}", e)));
            }
        };

        // Extract device ID from message if not yet set
        if self.device_id.is_none() {
            self.device_id = Some(encrypted_msg.sender);
            info!("Connection {} authenticated as device {:?}", 
                  self.connection_id, encrypted_msg.sender);
        }

        // Route the message
        if let Err(e) = self.router.route_message(encrypted_msg).await {
            error!("Failed to route message: {}", e);
            return Err(ServerError::Routing(e));
        }

        Ok(true)
    }

    /// Cleanup when connection closes
    async fn cleanup(&mut self) {
        // Unregister device from router if authenticated
        if let Some(device_id) = &self.device_id {
            self.router.unregister_device(device_id).await;
        }

        // Unregister from connection pool
        self.pool.unregister(self.connection_id).await;

        // Close transport
        if let Err(e) = self.transport.close().await {
            warn!("Error closing transport: {}", e);
        }

        info!("Connection {} cleaned up", self.connection_id);
    }
}

/// Start handling a new connection
pub async fn handle_connection(
    connection_id: ConnectionId,
    transport: TlsServerTransport,
    peer_addr: SocketAddr,
    router: Arc<MessageRouter>,
    pool: Arc<ConnectionPool>,
) {
    let handler = ConnectionHandler::new(
        connection_id,
        peer_addr,
        transport,
        router,
        pool,
    );

    if let Err(e) = handler.handle().await {
        error!("Connection handler error: {}", e);
    }
}
