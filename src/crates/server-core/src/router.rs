//! Message router per SERVER_REQUIREMENTS F-03.04

use norc_protocol::messages::{EncryptedMessage, MessageHeader};
use norc_protocol::{DeviceId, MessageId};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, warn};

/// Message routing table entry
#[derive(Debug, Clone)]
pub struct RoutingEntry {
    /// Device ID
    pub device_id: DeviceId,
    /// Organization ID
    pub org_id: String,
    /// Local or federated
    pub is_local: bool,
}

/// Message router handles encrypted message routing
pub struct MessageRouter {
    /// Routing table: device_id -> routing entry
    routing_table: Arc<RwLock<HashMap<DeviceId, RoutingEntry>>>,
    /// Message queue
    outbound_tx: mpsc::Sender<(DeviceId, EncryptedMessage)>,
    outbound_rx: Arc<RwLock<mpsc::Receiver<(DeviceId, EncryptedMessage)>>>,
}

impl MessageRouter {
    /// Create a new message router
    pub fn new() -> Self {
        let (outbound_tx, outbound_rx) = mpsc::channel(1000);

        Self {
            routing_table: Arc::new(RwLock::new(HashMap::new())),
            outbound_tx,
            outbound_rx: Arc::new(RwLock::new(outbound_rx)),
        }
    }

    /// Register a device route
    pub async fn register_device(&self, device_id: DeviceId, org_id: String, is_local: bool) {
        let mut table = self.routing_table.write().await;
        
        let entry = RoutingEntry {
            device_id,
            org_id: org_id.clone(),
            is_local,
        };

        table.insert(device_id, entry);
        info!("Registered device route: {:?} -> {} (local: {})", device_id, org_id, is_local);
    }

    /// Unregister a device route
    pub async fn unregister_device(&self, device_id: &DeviceId) {
        let mut table = self.routing_table.write().await;
        if table.remove(device_id).is_some() {
            info!("Unregistered device route: {:?}", device_id);
        }
    }

    /// Route an encrypted message
    pub async fn route_message(&self, message: EncryptedMessage) -> Result<(), String> {
        let table = self.routing_table.read().await;

        // Look up recipient routing
        let routing_entry = table.get(&message.recipient)
            .ok_or_else(|| format!("No route to device: {:?}", message.recipient))?;

        debug!("Routing message {:?} to {:?}", message.header.message_id, message.recipient);

        // Queue message for delivery
        self.outbound_tx
            .send((message.recipient, message))
            .await
            .map_err(|e| format!("Failed to queue message: {}", e))?;

        Ok(())
    }

    /// Process outbound messages (to be called in a loop)
    pub async fn process_outbound_messages<F>(&self, mut handler: F)
    where
        F: FnMut(DeviceId, EncryptedMessage) -> Result<(), String>,
    {
        let mut rx = self.outbound_rx.write().await;

        while let Some((device_id, message)) = rx.recv().await {
            if let Err(e) = handler(device_id, message) {
                warn!("Failed to deliver message: {}", e);
            }
        }
    }

    /// Get routing information for a device
    pub async fn get_route(&self, device_id: &DeviceId) -> Option<RoutingEntry> {
        let table = self.routing_table.read().await;
        table.get(device_id).cloned()
    }

    /// Get routing table statistics
    pub async fn get_stats(&self) -> RouterStats {
        let table = self.routing_table.read().await;
        
        let total_routes = table.len();
        let local_routes = table.values().filter(|e| e.is_local).count();
        let federated_routes = table.values().filter(|e| !e.is_local).count();

        RouterStats {
            total_routes,
            local_routes,
            federated_routes,
        }
    }
}

impl Default for MessageRouter {
    fn default() -> Self {
        Self::new()
    }
}

/// Router statistics
#[derive(Debug, Clone)]
pub struct RouterStats {
    /// Total number of routes
    pub total_routes: usize,
    /// Number of local routes
    pub local_routes: usize,
    /// Number of federated routes
    pub federated_routes: usize,
}
