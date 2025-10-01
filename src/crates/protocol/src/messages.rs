//! Protocol messages per PROTOCOL_SPECIFICATION.md Section 4

use crate::types::*;
use crate::version::ProtocolVersion;
use serde::{Deserialize, Serialize};

/// Protocol layers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ProtocolLayer {
    /// Client layer (NORC-C)
    Client = 1,
    /// Federation layer (NORC-F)
    Federation = 2,
    /// Trust layer (NORC-T)
    Trust = 3,
}

/// Message flags
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct MessageFlags(pub u8);

impl MessageFlags {
    /// Create new message flags
    pub const fn new() -> Self {
        Self(0)
    }

    /// Set encrypted flag
    pub const fn encrypted(mut self) -> Self {
        self.0 |= 0x01;
        self
    }

    /// Set urgent flag
    pub const fn urgent(mut self) -> Self {
        self.0 |= 0x02;
        self
    }
}

/// Common message header per PROTOCOL_SPECIFICATION.md Section 4.3.1
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageHeader {
    /// Protocol version number
    pub version: ProtocolVersion,
    /// Protocol layer
    pub layer: ProtocolLayer,
    /// Message type within layer
    pub message_type: u8,
    /// Message flags
    pub flags: MessageFlags,
    /// Total message length including header
    pub length: u32,
    /// Unix timestamp in milliseconds
    pub timestamp: u64,
    /// Unique message identifier
    pub message_id: MessageId,
}

impl MessageHeader {
    /// Create a new message header
    pub fn new(layer: ProtocolLayer, message_type: u8) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        Self {
            version: ProtocolVersion::CURRENT,
            layer,
            message_type,
            flags: MessageFlags::new(),
            length: 0, // Set when serializing
            timestamp,
            message_id: MessageId::new([0u8; 32]), // Generate when creating
        }
    }
}

/// Device registration message per PROTOCOL_SPECIFICATION.md Section 4.3.2
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRegistration {
    /// Message header
    pub header: MessageHeader,
    /// Device public key
    pub device_public_key: PublicKey,
    /// User ID
    pub user_id: UserId,
    /// Device information/description
    pub device_info: String,
    /// Supported feature flags
    pub capabilities: u32,
    /// Self-signed signature
    pub signature: Signature,
}

/// Encrypted message container
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedMessage {
    /// Message header
    pub header: MessageHeader,
    /// Sender device ID
    pub sender: DeviceId,
    /// Recipient device ID
    pub recipient: DeviceId,
    /// Conversation ID
    pub conversation_id: ConvId,
    /// Encryption nonce
    pub nonce: Nonce,
    /// Encrypted payload
    pub ciphertext: Vec<u8>,
    /// Previous message hash (for hash chain)
    pub prev_message_hash: Hash,
}

/// Client hello message (handshake)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientHello {
    /// Supported protocol versions
    pub versions: Vec<ProtocolVersion>,
    /// Supported capabilities (ordered)
    pub capabilities: Vec<String>,
    /// Client nonce
    pub nonce: [u8; 32],
    /// Ephemeral X25519 public key
    pub ephemeral_public_key: [u8; 32],
    /// Optional post-quantum public key
    pub pq_public_key: Option<Vec<u8>>,
}

/// Server hello message (handshake)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerHello {
    /// Selected protocol version
    pub selected_version: ProtocolVersion,
    /// Selected capabilities (ordered)
    pub capabilities: Vec<String>,
    /// Server nonce
    pub nonce: [u8; 32],
    /// Ephemeral X25519 public key
    pub ephemeral_public_key: [u8; 32],
    /// Optional post-quantum public key
    pub pq_public_key: Option<Vec<u8>>,
}

/// Authentication challenge request (client → server)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthChallengeRequest {
    /// Device ID requesting authentication
    pub device_id: DeviceId,
    /// Device public key
    pub public_key: PublicKey,
}

/// Authentication challenge response (server → client)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthChallenge {
    /// Challenge nonce (32 bytes)
    pub challenge: [u8; 32],
    /// Challenge expiry timestamp (Unix milliseconds)
    pub expires_at: u64,
}

/// Authentication response (client → server)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    /// Device ID
    pub device_id: DeviceId,
    /// Challenge that was signed
    pub challenge: [u8; 32],
    /// Ed25519 signature over challenge
    pub signature: Signature,
}

/// Authentication result (server → client)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResult {
    /// Authentication success
    pub success: bool,
    /// Session token (if successful)
    pub session_token: Option<[u8; 32]>,
    /// Error message (if failed)
    pub error: Option<String>,
    /// Session expiry (if successful)
    pub expires_at: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_flags_default() {
        let flags = MessageFlags::default();
        assert_eq!(flags.0, 0);
    }

    #[test]
    fn test_message_flags_encrypted() {
        let flags = MessageFlags::new().encrypted();
        assert_eq!(flags.0 & 0x01, 0x01);
    }

    #[test]
    fn test_message_flags_urgent() {
        let flags = MessageFlags::new().urgent();
        assert_eq!(flags.0 & 0x02, 0x02);
    }

    #[test]
    fn test_message_flags_combined() {
        let flags = MessageFlags::new().encrypted().urgent();
        assert_eq!(flags.0 & 0x01, 0x01);
        assert_eq!(flags.0 & 0x02, 0x02);
    }

    #[test]
    fn test_protocol_layer_values() {
        assert_eq!(ProtocolLayer::Client as u8, 1);
        assert_eq!(ProtocolLayer::Federation as u8, 2);
        assert_eq!(ProtocolLayer::Trust as u8, 3);
    }

    #[test]
    fn test_client_hello_serialization() {
        let hello = ClientHello {
            versions: vec![ProtocolVersion::CURRENT],
            capabilities: vec!["encryption".to_string(), "federation".to_string()],
            nonce: [42u8; 32],
            ephemeral_public_key: [1u8; 32],
            pq_public_key: None,
        };

        // Test serialization/deserialization
        let serialized = serde_json::to_string(&hello).unwrap();
        let deserialized: ClientHello = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.versions, hello.versions);
        assert_eq!(deserialized.capabilities, hello.capabilities);
        assert_eq!(deserialized.nonce, hello.nonce);
    }

    #[test]
    fn test_server_hello_serialization() {
        let hello = ServerHello {
            selected_version: ProtocolVersion::CURRENT,
            capabilities: vec!["encryption".to_string()],
            nonce: [99u8; 32],
            ephemeral_public_key: [2u8; 32],
            pq_public_key: Some(vec![3u8; 64]),
        };

        let serialized = serde_json::to_string(&hello).unwrap();
        let deserialized: ServerHello = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.selected_version, hello.selected_version);
        assert_eq!(deserialized.pq_public_key, hello.pq_public_key);
    }
}
