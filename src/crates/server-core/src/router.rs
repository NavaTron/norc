//! Message routing and delivery

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use navatron_protocol::{
    messages::{NorcMessage, Message, MessageSendMessage, MessageAckMessage},
    types::{DeviceId, UserId, MessageId, ConversationId},
};

use crate::error::{ServerError, Result};
use crate::session::SessionManager;

/// Message delivery status
#[derive(Debug, Clone, PartialEq)]
pub enum DeliveryStatus {
    /// Message pending delivery
    Pending,
    /// Message delivered to device
    Delivered,
    /// Delivery failed
    Failed,
    /// Message acknowledged by recipient
    Acknowledged,
}

/// Message delivery record
#[derive(Debug, Clone)]
pub struct DeliveryRecord {
    /// Message ID
    message_id: MessageId,
    /// Sender device ID
    sender_device: DeviceId,
    /// Target device ID
    target_device: DeviceId,
    /// Delivery status
    status: DeliveryStatus,
    /// Delivery attempts
    attempts: u32,
    /// Timestamp of last attempt
    last_attempt: chrono::DateTime<chrono::Utc>,
}

/// Routing table for message delivery
pub struct RoutingTable {
    /// User to devices mapping
    user_devices: Arc<RwLock<HashMap<UserId, Vec<DeviceId>>>>,
    /// Device to user mapping
    device_users: Arc<RwLock<HashMap<DeviceId, UserId>>>,
    /// Conversation participants
    conversation_participants: Arc<RwLock<HashMap<ConversationId, Vec<UserId>>>>,
    /// Pending message deliveries
    pending_deliveries: Arc<RwLock<HashMap<MessageId, Vec<DeliveryRecord>>>>,
}

impl RoutingTable {
    /// Create a new routing table
    pub fn new() -> Self {
        Self {
            user_devices: Arc::new(RwLock::new(HashMap::new())),
            device_users: Arc::new(RwLock::new(HashMap::new())),
            conversation_participants: Arc::new(RwLock::new(HashMap::new())),
            pending_deliveries: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Register a device for a user
    pub async fn register_device(&self, user_id: UserId, device_id: DeviceId) {
        // Add device to user's device list
        let mut user_devices = self.user_devices.write().await;
        user_devices
            .entry(user_id.clone())
            .or_insert_with(Vec::new)
            .push(device_id);
        
        // Map device to user
        self.device_users.write().await.insert(device_id, user_id.clone());
        
        info!(
            user_id = %user_id,
            device_id = %device_id,
            "Device registered for user"
        );
    }
    
    /// Unregister a device
    pub async fn unregister_device(&self, device_id: DeviceId) {
        let mut device_users = self.device_users.write().await;
        
        if let Some(user_id) = device_users.remove(&device_id) {
            // Remove device from user's device list
            let mut user_devices = self.user_devices.write().await;
            if let Some(devices) = user_devices.get_mut(&user_id) {
                devices.retain(|&id| id != device_id);
                if devices.is_empty() {
                    user_devices.remove(&user_id);
                }
            }
            
            info!(
                user_id = %user_id,
                device_id = %device_id,
                "Device unregistered"
            );
        }
    }
    
    /// Get all devices for a user
    pub async fn get_user_devices(&self, user_id: &UserId) -> Vec<DeviceId> {
        self.user_devices
            .read()
            .await
            .get(user_id)
            .cloned()
            .unwrap_or_default()
    }
    
    /// Get user for a device
    pub async fn get_device_user(&self, device_id: DeviceId) -> Option<UserId> {
        self.device_users.read().await.get(&device_id).cloned()
    }
    
    /// Add participants to a conversation
    pub async fn add_conversation_participants(
        &self,
        conversation_id: ConversationId,
        participants: Vec<UserId>,
    ) {
        self.conversation_participants
            .write()
            .await
            .insert(conversation_id, participants);
    }
    
    /// Get conversation participants
    pub async fn get_conversation_participants(
        &self,
        conversation_id: ConversationId,
    ) -> Vec<UserId> {
        self.conversation_participants
            .read()
            .await
            .get(&conversation_id)
            .cloned()
            .unwrap_or_default()
    }
    
    /// Add pending delivery
    pub async fn add_pending_delivery(&self, delivery: DeliveryRecord) {
        let message_id = delivery.message_id;
        self.pending_deliveries
            .write()
            .await
            .entry(message_id)
            .or_insert_with(Vec::new)
            .push(delivery);
    }
    
    /// Mark delivery as completed
    pub async fn complete_delivery(&self, message_id: MessageId, target_device: DeviceId) {
        let mut pending = self.pending_deliveries.write().await;
        if let Some(deliveries) = pending.get_mut(&message_id) {
            for delivery in deliveries.iter_mut() {
                if delivery.target_device == target_device {
                    delivery.status = DeliveryStatus::Delivered;
                    break;
                }
            }
            
            // Remove if all deliveries are complete
            if deliveries.iter().all(|d| d.status != DeliveryStatus::Pending) {
                pending.remove(&message_id);
            }
        }
    }
    
    /// Get pending deliveries for retry
    pub async fn get_pending_deliveries(&self) -> Vec<DeliveryRecord> {
        self.pending_deliveries
            .read()
            .await
            .values()
            .flatten()
            .filter(|d| d.status == DeliveryStatus::Pending)
            .cloned()
            .collect()
    }
}

/// Message router handles message delivery between clients
pub struct MessageRouter {
    /// Session manager reference
    session_manager: Arc<SessionManager>,
    /// Routing table
    routing_table: RoutingTable,
    /// Maximum delivery attempts
    max_delivery_attempts: u32,
}

impl MessageRouter {
    /// Create a new message router
    pub fn new(session_manager: Arc<SessionManager>) -> Self {
        Self {
            session_manager,
            routing_table: RoutingTable::new(),
            max_delivery_attempts: 3,
        }
    }
    
    /// Route a message to its recipients
    pub async fn route_message(&self, message: NorcMessage) -> Result<()> {
        match &message.payload {
            Message::MessageSend(msg) => {
                self.handle_message_send(&message, msg).await
            }
            Message::MessageAck(ack) => {
                self.handle_message_ack(ack).await
            }
            // Handle other message types as needed
            _ => {
                debug!("Ignoring non-routable message type");
                Ok(())
            }
        }
    }
    
    /// Handle message send routing
    async fn handle_message_send(
        &self,
        message: &NorcMessage,
        msg: &MessageSendMessage,
    ) -> Result<()> {
        debug!(
            message_id = %message.message_id,
            conversation_id = %msg.conversation_id,
            "Routing message send"
        );
        
        // Get conversation participants - use the recipients from the message
        let participants = msg.recipients.clone();
        
        if participants.is_empty() {
            return Err(ServerError::routing("No recipients found in message"));
        }
        
        let mut delivery_count = 0;
        let mut pending_deliveries = Vec::new();
        
        // Route to all participant devices
        for participant in participants {
            let devices = self.routing_table.get_user_devices(&participant).await;
            
            for device_id in devices {
                // Try immediate delivery
                match self.session_manager.send_to_device(device_id, message.clone()).await {
                    Ok(true) => {
                        delivery_count += 1;
                        debug!(
                            device_id = %device_id,
                            message_id = %message.message_id,
                            "Message delivered immediately"
                        );
                    }
                    Ok(false) => {
                        // Device offline, add to pending
                        let delivery = DeliveryRecord {
                            message_id: message.message_id,
                            sender_device: device_id, // Use device_id as placeholder
                            target_device: device_id,
                            status: DeliveryStatus::Pending,
                            attempts: 0,
                            last_attempt: chrono::Utc::now(),
                        };
                        pending_deliveries.push(delivery);
                        
                        debug!(
                            device_id = %device_id,
                            message_id = %message.message_id,
                            "Device offline, queued for delivery"
                        );
                    }
                    Err(e) => {
                        warn!(
                            device_id = %device_id,
                            message_id = %message.message_id,
                            error = %e,
                            "Failed to deliver message"
                        );
                    }
                }
            }
        }
        
        // Store pending deliveries
        for delivery in pending_deliveries {
            self.routing_table.add_pending_delivery(delivery).await;
        }
        
        info!(
            message_id = %message.message_id,
            delivered = delivery_count,
            "Message routing completed"
        );
        
        Ok(())
    }
    
    /// Handle message acknowledgment
    async fn handle_message_ack(&self, ack: &MessageAckMessage) -> Result<()> {
        debug!(
            message_id = %ack.message_id,
            ack_type = ?ack.ack_type,
            "Processing message acknowledgment"
        );
        
        // For now, we don't have device_id in the ack message,
        // so we'll need to track this differently in a real implementation
        // Mark delivery as acknowledged - this is a simplified implementation
        
        Ok(())
    }
    
    /// Register a device for message routing
    pub async fn register_device(&self, user_id: UserId, device_id: DeviceId) {
        self.routing_table.register_device(user_id, device_id).await;
    }
    
    /// Unregister a device
    pub async fn unregister_device(&self, device_id: DeviceId) {
        self.routing_table.unregister_device(device_id).await;
    }
    
    /// Add participants to a conversation
    pub async fn setup_conversation(
        &self,
        conversation_id: ConversationId,
        participants: Vec<UserId>,
    ) {
        self.routing_table
            .add_conversation_participants(conversation_id, participants)
            .await;
    }
    
    /// Retry pending message deliveries
    pub async fn retry_pending_deliveries(&self) -> Result<usize> {
        let pending = self.routing_table.get_pending_deliveries().await;
        let mut retry_count = 0;
        
        for mut delivery in pending {
            if delivery.attempts >= self.max_delivery_attempts {
                continue;
            }
            
            // Create a mock message for retry (in real implementation, store the full message)
            // For now, skip actual retry logic
            delivery.attempts += 1;
            delivery.last_attempt = chrono::Utc::now();
            
            retry_count += 1;
        }
        
        if retry_count > 0 {
            info!(retry_count, "Retried pending message deliveries");
        }
        
        Ok(retry_count)
    }
    
    /// Get routing table reference
    pub fn routing_table(&self) -> &RoutingTable {
        &self.routing_table
    }
}