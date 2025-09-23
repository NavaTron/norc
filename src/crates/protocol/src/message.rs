//! Protocol message types and structures

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::identity::PublicKey;

/// Core message structure for all NORC protocol communications
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// Message header with metadata
    pub header: MessageHeader,
    /// Message payload
    pub payload: MessagePayload,
}

/// Message header containing metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageHeader {
    /// Unique message identifier
    pub id: Uuid,
    /// Message type
    pub message_type: MessageType,
    /// Protocol version
    pub version: ProtocolVersion,
    /// Timestamp when message was created
    #[serde(with = "time::serde::rfc3339")]
    pub timestamp: OffsetDateTime,
    /// Sender's public key (for authentication)
    pub sender: PublicKey,
    /// Optional recipient public key (for direct messages)
    pub recipient: Option<PublicKey>,
}

/// Protocol version information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl Default for ProtocolVersion {
    fn default() -> Self {
        Self {
            major: crate::PROTOCOL_VERSION_MAJOR,
            minor: crate::PROTOCOL_VERSION_MINOR,
            patch: crate::PROTOCOL_VERSION_PATCH,
        }
    }
}

/// Message type enumeration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageType {
    /// Handshake and authentication
    Handshake,
    /// Text message
    Text,
    /// File transfer
    File,
    /// Status update
    Status,
    /// Server administration
    Admin,
    /// Federation protocol messages
    Federation,
    /// Keep-alive/ping
    Ping,
    /// Pong response
    Pong,
}

/// Message payload containing the actual data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessagePayload {
    /// Handshake data
    Handshake {
        client_version: String,
        capabilities: Vec<String>,
    },
    /// Text message content
    Text {
        content: String,
        channel: Option<String>,
    },
    /// File transfer data
    File {
        filename: String,
        content_type: String,
        size: u64,
        data: Vec<u8>,
    },
    /// Status update
    Status {
        status: UserStatus,
        message: Option<String>,
    },
    /// Administrative command
    Admin {
        command: String,
        parameters: serde_json::Value,
    },
    /// Federation protocol data
    Federation {
        action: FederationAction,
        data: serde_json::Value,
    },
    /// Ping message
    Ping {
        timestamp: u64,
    },
    /// Pong response
    Pong {
        original_timestamp: u64,
        response_timestamp: u64,
    },
}

/// User status enumeration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UserStatus {
    Online,
    Away,
    Busy,
    Offline,
}

/// Federation action types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FederationAction {
    /// Establish federation connection
    Connect,
    /// Disconnect from federation
    Disconnect,
    /// Synchronize data
    Sync,
    /// Forward message to federated server
    Forward,
}

impl Message {
    /// Create a new message with the given type and payload
    pub fn new(
        message_type: MessageType,
        payload: MessagePayload,
        sender: PublicKey,
        recipient: Option<PublicKey>,
    ) -> Self {
        Self {
            header: MessageHeader {
                id: Uuid::new_v4(),
                message_type,
                version: ProtocolVersion::default(),
                timestamp: OffsetDateTime::now_utc(),
                sender,
                recipient,
            },
            payload,
        }
    }

    /// Serialize message to binary format
    pub fn to_bytes(&self) -> crate::Result<Vec<u8>> {
        postcard::to_allocvec(self).map_err(Into::into)
    }

    /// Deserialize message from binary format
    pub fn from_bytes(data: &[u8]) -> crate::Result<Self> {
        postcard::from_bytes(data).map_err(Into::into)
    }

    /// Validate message size
    pub fn validate_size(&self) -> crate::Result<()> {
        let size = self.to_bytes()?.len();
        if size > crate::MAX_MESSAGE_SIZE {
            return Err(crate::ProtocolError::MessageTooLarge {
                size,
                max: crate::MAX_MESSAGE_SIZE,
            });
        }
        Ok(())
    }
}