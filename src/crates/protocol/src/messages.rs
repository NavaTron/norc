//! NORC protocol message types and serialization
//!
//! This module defines all message types used in the NORC protocol layers:
//! - NORC-C: Client ↔ Server messages
//! - NORC-F: Server ↔ Server federation messages  
//! - NORC-T: Trust establishment messages

use crate::error::{NorcError, Result};
use crate::types::*;
use crate::version::Version;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Message type registry following NORC specification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum MessageType {
    // NORC-C Message Types (Client-Server)
    ConnectionRequest = 0x00,
    ConnectionAccepted = 0x01,
    DeviceRegister = 0x02,
    AuthRequest = 0x03,
    AuthResponse = 0x04,
    DeviceRevoke = 0x05,
    MessageSend = 0x10,
    MessageAck = 0x11,
    PresenceUpdate = 0x20,
    KeyRequest = 0x30,
    KeyResponse = 0x31,
    SessionKeyExchange = 0x32,
    TimeSync = 0x33,
    FileManifest = 0x40,

    // NORC-F Message Types (Federation)
    FederationHello = 0x70,
    FederationHelloResponse = 0x71,
    MessageRelay = 0x80,
    DeliveryAck = 0x81,
    ServerDiscovery = 0x90,
    ServerInfo = 0x91,

    // NORC-T Message Types (Trust)
    TrustCapability = 0x9F,
    TrustRequest = 0xA0,
    TrustChallenge = 0xA1,
    TrustResponse = 0xA2,
    TrustRevoke = 0xA3,

    // Error message
    Error = 0xFF,
}

impl MessageType {
    /// Get the message type as a byte
    pub fn as_byte(self) -> u8 {
        self as u8
    }

    /// Create message type from byte
    pub fn from_byte(byte: u8) -> Result<Self> {
        match byte {
            0x00 => Ok(Self::ConnectionRequest),
            0x01 => Ok(Self::ConnectionAccepted),
            0x02 => Ok(Self::DeviceRegister),
            0x03 => Ok(Self::AuthRequest),
            0x04 => Ok(Self::AuthResponse),
            0x05 => Ok(Self::DeviceRevoke),
            0x10 => Ok(Self::MessageSend),
            0x11 => Ok(Self::MessageAck),
            0x20 => Ok(Self::PresenceUpdate),
            0x30 => Ok(Self::KeyRequest),
            0x31 => Ok(Self::KeyResponse),
            0x32 => Ok(Self::SessionKeyExchange),
            0x33 => Ok(Self::TimeSync),
            0x40 => Ok(Self::FileManifest),
            0x70 => Ok(Self::FederationHello),
            0x71 => Ok(Self::FederationHelloResponse),
            0x80 => Ok(Self::MessageRelay),
            0x81 => Ok(Self::DeliveryAck),
            0x90 => Ok(Self::ServerDiscovery),
            0x91 => Ok(Self::ServerInfo),
            0x9F => Ok(Self::TrustCapability),
            0xA0 => Ok(Self::TrustRequest),
            0xA1 => Ok(Self::TrustChallenge),
            0xA2 => Ok(Self::TrustResponse),
            0xA3 => Ok(Self::TrustRevoke),
            0xFF => Ok(Self::Error),
            _ => Err(NorcError::codec(format!("Unknown message type: {byte:#04x}"))),
        }
    }

    /// Check if this message type is valid for the given protocol layer
    pub fn valid_for_layer(self, layer: ProtocolLayer) -> bool {
        match layer {
            ProtocolLayer::Client => matches!(
                self,
                Self::ConnectionRequest
                    | Self::ConnectionAccepted
                    | Self::DeviceRegister
                    | Self::AuthRequest
                    | Self::AuthResponse
                    | Self::DeviceRevoke
                    | Self::MessageSend
                    | Self::MessageAck
                    | Self::PresenceUpdate
                    | Self::KeyRequest
                    | Self::KeyResponse
                    | Self::SessionKeyExchange
                    | Self::TimeSync
                    | Self::FileManifest
                    | Self::Error
            ),
            ProtocolLayer::Federation => matches!(
                self,
                Self::FederationHello
                    | Self::FederationHelloResponse
                    | Self::MessageRelay
                    | Self::DeliveryAck
                    | Self::ServerDiscovery
                    | Self::ServerInfo
                    | Self::Error
            ),
            ProtocolLayer::Trust => matches!(
                self,
                Self::TrustCapability
                    | Self::TrustRequest
                    | Self::TrustChallenge
                    | Self::TrustResponse
                    | Self::TrustRevoke
                    | Self::Error
            ),
        }
    }
}

/// NORC protocol layers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolLayer {
    /// NORC-C: Client-Server
    Client,
    /// NORC-F: Federation
    Federation,
    /// NORC-T: Trust
    Trust,
}

/// Generic message wrapper for all NORC messages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NorcMessage {
    /// Protocol version
    pub version: Version,
    /// Message type
    pub message_type: MessageType,
    /// Unique message identifier
    pub message_id: MessageId,
    /// Sequence number for ordering
    pub sequence_number: SequenceNumber,
    /// Hash of previous message in chain (for ordering)
    pub prev_message_hash: Hash,
    /// Timestamp when message was created
    pub timestamp: DateTime<Utc>,
    /// Message payload
    pub payload: Message,
}

impl NorcMessage {
    /// Create a new NORC message
    pub fn new(
        version: Version,
        message_type: MessageType,
        sequence_number: SequenceNumber,
        prev_message_hash: Hash,
        payload: Message,
    ) -> Self {
        Self {
            version,
            message_type,
            message_id: Uuid::new_v4(),
            sequence_number,
            prev_message_hash,
            timestamp: Utc::now(),
            payload,
        }
    }

    /// Validate message structure
    pub fn validate(&self) -> Result<()> {
        // Check that message type matches payload
        match (&self.message_type, &self.payload) {
            (MessageType::ConnectionRequest, Message::ConnectionRequest(_)) => Ok(()),
            (MessageType::ConnectionAccepted, Message::ConnectionAccepted(_)) => Ok(()),
            (MessageType::DeviceRegister, Message::DeviceRegister(_)) => Ok(()),
            (MessageType::AuthRequest, Message::AuthRequest(_)) => Ok(()),
            (MessageType::AuthResponse, Message::AuthResponse(_)) => Ok(()),
            (MessageType::MessageSend, Message::MessageSend(_)) => Ok(()),
            (MessageType::Error, Message::Error(_)) => Ok(()),
            // Add other message type validations...
            _ => Err(NorcError::validation(format!(
                "Message type {:?} does not match payload",
                self.message_type
            ))),
        }
    }

    /// Get the canonical hash of this message for chaining
    pub fn canonical_hash(&self) -> Result<Hash> {
        let canonical = self.to_canonical_bytes()?;
        Ok(crate::crypto::NorcCrypto::hash(&canonical))
    }

    /// Convert to canonical byte representation for hashing/signing
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        // Use deterministic serialization
        bincode::serialize(self).map_err(Into::into)
    }
}

/// Union of all possible message payloads
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    // NORC-C Messages
    ConnectionRequest(ConnectionRequestMessage),
    ConnectionAccepted(ConnectionAcceptedMessage),
    DeviceRegister(DeviceRegisterMessage),
    AuthRequest(AuthRequestMessage),
    AuthResponse(AuthResponseMessage),
    DeviceRevoke(DeviceRevokeMessage),
    MessageSend(MessageSendMessage),
    MessageAck(MessageAckMessage),
    PresenceUpdate(PresenceUpdateMessage),
    KeyRequest(KeyRequestMessage),
    KeyResponse(KeyResponseMessage),
    SessionKeyExchange(SessionKeyExchangeMessage),
    TimeSync(TimeSyncMessage),
    FileManifest(FileManifestMessage),

    // NORC-F Messages
    FederationHello(FederationHelloMessage),
    FederationHelloResponse(FederationHelloResponseMessage),
    MessageRelay(MessageRelayMessage),
    DeliveryAck(DeliveryAckMessage),
    ServerDiscovery(ServerDiscoveryMessage),
    ServerInfo(ServerInfoMessage),

    // NORC-T Messages
    TrustCapability(TrustCapabilityMessage),
    TrustRequest(TrustRequestMessage),
    TrustChallenge(TrustChallengeMessage),
    TrustResponse(TrustResponseMessage),
    TrustRevoke(TrustRevokeMessage),

    // Error message
    Error(ErrorMessage),
}

// NORC-C Message Definitions

/// Initial connection request with version negotiation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionRequestMessage {
    /// Supported protocol versions (ordered by preference)
    pub client_versions: Vec<Version>,
    /// Preferred version
    pub preferred_version: Version,
    /// Client capabilities
    pub capabilities: Vec<Capability>,
    /// Client nonce for key derivation
    pub client_nonce: Vec<u8>,
    /// Ephemeral public key for session establishment
    pub ephemeral_public_key: EphemeralPublicKey,
    /// Optional post-quantum public key
    pub pq_public_key: Option<Vec<u8>>,
}

/// Connection accepted with negotiated parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionAcceptedMessage {
    /// Negotiated protocol version
    pub negotiated_version: Version,
    /// Server capabilities  
    pub server_capabilities: Vec<Capability>,
    /// Whether compatibility mode is active
    pub compatibility_mode: bool,
    /// Server nonce for key derivation
    pub server_nonce: Vec<u8>,
    /// Server ephemeral public key
    pub ephemeral_public_key: EphemeralPublicKey,
    /// Optional post-quantum response
    pub pq_response: Option<Vec<u8>>,
    /// Session ID
    pub session_id: SessionId,
}

/// Device registration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRegisterMessage {
    /// Device identifier
    pub device_id: DeviceId,
    /// Device public key for signatures
    pub public_key: PublicKey,
    /// Device information
    pub device_info: DeviceInfo,
    /// Optional proof of work for anti-spam
    pub proof_of_work: Option<Vec<u8>>,
}

/// Authentication request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRequestMessage {
    /// User identifier
    pub user_id: UserId,
    /// Device making the request
    pub device_id: DeviceId,
    /// Authentication timestamp
    pub timestamp: DateTime<Utc>,
    /// Signature over challenge
    pub signature: Signature,
    /// Authentication method
    pub auth_method: AuthMethod,
}

/// Authentication methods
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    /// Device key signature
    DeviceKey,
    /// External OAuth/OIDC
    External { provider: String, token: String },
    /// Certificate-based
    Certificate { cert_chain: Vec<Vec<u8>> },
}

/// Authentication response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponseMessage {
    /// Whether authentication succeeded
    pub success: bool,
    /// Optional error message
    pub error: Option<String>,
    /// Authentication token if successful
    pub auth_token: Option<String>,
    /// Token expiration
    pub expires_at: Option<DateTime<Utc>>,
    /// User's current device list
    pub user_devices: Option<Vec<DeviceId>>,
}

/// Device key revocation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRevokeMessage {
    /// Device being revoked
    pub device_id: DeviceId,
    /// Revocation reason
    pub reason: RevocationReason,
    /// Effective timestamp
    pub effective_date: DateTime<Utc>,
    /// Signature by device or admin
    pub signature: Signature,
    /// Optional proof of authority
    pub revocation_proof: Option<Vec<u8>>,
}

/// Reasons for device revocation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationReason {
    /// Device was compromised
    Compromised,
    /// Policy violation
    Policy,
    /// User requested removal
    UserRequest,
    /// Administrative action
    Administrative,
    /// Key expired
    Expired,
}

/// Send encrypted message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageSendMessage {
    /// Conversation/room identifier
    pub conversation_id: ConversationId,
    /// Recipients
    pub recipients: Vec<UserId>,
    /// Per-device encrypted content
    pub encrypted_content: PerDeviceContent,
    /// Message metadata
    pub metadata: MessageMetadata,
    /// Classification level
    pub classification: Classification,
}

/// Message metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageMetadata {
    /// Content type
    pub content_type: ContentType,
    /// Original timestamp
    pub timestamp: DateTime<Utc>,
    /// Optional reply-to message
    pub reply_to: Option<MessageId>,
    /// Message thread ID
    pub thread_id: Option<MessageId>,
    /// Optional expiration time
    pub expires_at: Option<DateTime<Utc>>,
}

/// Message acknowledgment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageAckMessage {
    /// Message being acknowledged
    pub message_id: MessageId,
    /// Acknowledgment type
    pub ack_type: AckType,
    /// Timestamp of acknowledgment
    pub timestamp: DateTime<Utc>,
}

/// Types of acknowledgments
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AckType {
    /// Message received
    Received,
    /// Message read
    Read,
    /// Message processed
    Processed,
    /// Delivery failed
    Failed,
}

/// Presence status update
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresenceUpdateMessage {
    /// New presence status
    pub status: PresenceStatus,
    /// Optional status message
    pub status_message: Option<String>,
    /// Current device capabilities
    pub capabilities: Vec<Capability>,
    /// Last seen timestamp
    pub last_seen: DateTime<Utc>,
}

/// Request public keys for users/devices
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRequestMessage {
    /// Users to get keys for
    pub user_ids: Vec<UserId>,
    /// Optional device filter
    pub device_filter: Option<Vec<DeviceId>>,
    /// Key types requested
    pub key_types: Vec<KeyAlgorithm>,
}

/// Response with public keys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyResponseMessage {
    /// Keys by user and device
    pub keys: HashMap<UserId, HashMap<DeviceId, KeyInfo>>,
    /// Any lookup failures
    pub failures: Vec<KeyLookupFailure>,
}

/// Key lookup failure information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyLookupFailure {
    /// User ID that failed
    pub user_id: UserId,
    /// Device ID that failed (if applicable)
    pub device_id: Option<DeviceId>,
    /// Failure reason
    pub reason: String,
}

/// Session key exchange for forward secrecy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionKeyExchangeMessage {
    /// Session identifier
    pub session_id: SessionId,
    /// Ephemeral public key
    pub ephemeral_public_key: EphemeralPublicKey,
    /// Target device
    pub target_device: DeviceId,
    /// Key expiration
    pub expires_at: DateTime<Utc>,
}

/// Time synchronization message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeSyncMessage {
    /// Server timestamp
    pub server_time: DateTime<Utc>,
    /// Server time uncertainty (microseconds)
    pub uncertainty_micros: u64,
    /// Signature over timestamp
    pub signature: Signature,
}

/// Encrypted file metadata manifest
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileManifestMessage {
    /// File identifier
    pub file_id: Uuid,
    /// Encrypted file metadata
    pub encrypted_manifest: Vec<u8>,
    /// Manifest encryption nonce
    pub nonce: Nonce,
    /// Per-device manifest keys
    pub manifest_keys: PerDeviceContent,
}

// NORC-F Federation Messages (simplified for now)

/// Federation handshake initiation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationHelloMessage {
    /// Server identifier
    pub server_id: ServerId,
    /// Supported protocol versions
    pub protocol_versions: HashMap<String, Vec<Version>>,
    /// Server capabilities
    pub capabilities: Vec<Capability>,
    /// Server nonce
    pub nonce: Vec<u8>,
}

/// Federation handshake response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationHelloResponseMessage {
    /// Responding server ID
    pub server_id: ServerId,
    /// Negotiated versions
    pub negotiated_versions: HashMap<String, Version>,
    /// Compatibility warnings
    pub compatibility_warnings: Vec<String>,
    /// Server nonce
    pub nonce: Vec<u8>,
}

/// Relay message to federated server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageRelayMessage {
    /// Original message ID
    pub message_id: MessageId,
    /// Origin server
    pub origin_server: ServerId,
    /// Target users on this server
    pub target_users: Vec<UserId>,
    /// Encrypted payloads
    pub encrypted_payloads: PerDeviceContent,
    /// Relay metadata
    pub metadata: RelayMetadata,
}

/// Metadata for federated message relay
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayMetadata {
    /// Original timestamp
    pub timestamp: DateTime<Utc>,
    /// Hop count (TTL)
    pub hop_count: u32,
    /// Route signature for integrity
    pub route_signature: Signature,
    /// Classification level
    pub classification: Classification,
}

/// Delivery acknowledgment for federation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryAckMessage {
    /// Original message ID
    pub message_id: MessageId,
    /// Successfully delivered devices
    pub delivered_to: Vec<DeviceId>,
    /// Failed delivery devices  
    pub failed_devices: Vec<DeviceId>,
    /// Delivery timestamp
    pub timestamp: DateTime<Utc>,
}

/// Server discovery request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerDiscoveryMessage {
    /// Server domain to discover
    pub query_server: ServerId,
    /// Requesting server
    pub requesting_server: ServerId,
    /// Request timestamp
    pub timestamp: DateTime<Utc>,
    /// Request signature
    pub signature: Signature,
}

/// Server information response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfoMessage {
    /// Server identifier
    pub server_id: ServerId,
    /// Server endpoints
    pub endpoints: Vec<ServerEndpoint>,
    /// Trust anchors
    pub trust_anchors: Vec<Vec<u8>>,
    /// Federation policy
    pub federation_policy: FederationPolicy,
}

/// Server endpoint information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerEndpoint {
    /// Protocol (e.g., "norc_f")
    pub protocol: String,
    /// Address (IP or hostname)
    pub address: String,
    /// Port number
    pub port: u16,
    /// TLS certificate fingerprint
    pub tls_fingerprint: Vec<u8>,
}

/// Federation policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationPolicy {
    /// Auto-accept federation requests
    pub auto_accept: bool,
    /// Require verification
    pub require_verification: bool,
    /// Maximum message size
    pub max_message_size: u64,
    /// Required trust level
    pub required_trust_level: TrustLevel,
}

// NORC-T Trust Messages (simplified)

/// Trust capability announcement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustCapabilityMessage {
    /// Supported trust methods
    pub trust_methods: Vec<TrustMethod>,
    /// Supported verification methods
    pub verification_methods: Vec<VerificationMethod>,
    /// Server certificate chain
    pub certificate_chain: Vec<Vec<u8>>,
}

/// Trust establishment methods
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustMethod {
    /// Direct key exchange
    DirectKey,
    /// Certificate authority
    CertificateAuthority,
    /// Web of trust
    WebOfTrust,
    /// Government PKI
    GovernmentPki,
}

/// Verification methods for trust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationMethod {
    /// DNS verification
    Dns,
    /// Email verification
    Email,
    /// Manual verification
    Manual,
    /// Certificate authority
    Ca,
}

/// Trust establishment request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustRequestMessage {
    /// Requesting server
    pub requesting_server: ServerId,
    /// Target server
    pub requested_server: ServerId,
    /// Requested trust level
    pub trust_level: TrustLevel,
    /// Certificate chain
    pub certificate_chain: Vec<Vec<u8>>,
    /// Domain ownership proof
    pub proof_of_control: Vec<u8>,
    /// Contact information
    pub contact_info: ContactInfo,
}

/// Contact information for trust establishment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactInfo {
    /// Administrator email
    pub admin_email: String,
    /// Organization name
    pub organization: String,
    /// Country code
    pub country: String,
}

/// Trust validation challenge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustChallengeMessage {
    /// Challenge identifier
    pub challenge_id: Uuid,
    /// Challenge data to sign
    pub challenge_data: Vec<u8>,
    /// Validation method
    pub validation_method: VerificationMethod,
    /// Challenge expiration
    pub expires_at: DateTime<Utc>,
}

/// Trust challenge response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustResponseMessage {
    /// Challenge identifier
    pub challenge_id: Uuid,
    /// Signed challenge
    pub signature: Signature,
    /// Additional validation proofs
    pub additional_proofs: Vec<Vec<u8>>,
}

/// Trust revocation message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustRevokeMessage {
    /// Server being revoked
    pub revoked_server: ServerId,
    /// Revocation reason
    pub reason: TrustRevocationReason,
    /// Effective date
    pub effective_date: DateTime<Utc>,
    /// Revocation signature
    pub signature: Signature,
    /// Optional proof of authority
    pub revocation_proof: Option<Vec<u8>>,
}

/// Reasons for trust revocation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustRevocationReason {
    /// Server was compromised
    Compromised,
    /// Policy violation
    Policy,
    /// Administrative decision
    Administrative,
    /// Certificate expired
    Expired,
    /// Requested by server
    Requested,
}

/// Error message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorMessage {
    /// Error code
    pub error_code: u16,
    /// Error category
    pub error_category: String,
    /// Human-readable message
    pub message: String,
    /// Optional retry delay
    pub retry_after_secs: Option<u64>,
    /// Additional error details
    pub details: HashMap<String, String>,
}

impl From<NorcError> for ErrorMessage {
    fn from(error: NorcError) -> Self {
        Self {
            error_code: error.error_code(),
            error_category: match error {
                NorcError::Version { .. } => "version".to_string(),
                NorcError::Codec { .. } => "codec".to_string(),
                NorcError::Crypto { .. } => "crypto".to_string(),
                NorcError::Auth { .. } => "auth".to_string(),
                NorcError::Validation { .. } => "validation".to_string(),
                NorcError::InvalidState { .. } => "state".to_string(),
                NorcError::Transport { .. } => "transport".to_string(),
                NorcError::Federation { .. } => "federation".to_string(),
                NorcError::Trust { .. } => "trust".to_string(),
                NorcError::RateLimit { .. } => "rate_limit".to_string(),
                NorcError::Replay { .. } => "replay".to_string(),
                NorcError::Ordering { .. } => "ordering".to_string(),
                NorcError::Config { .. } => "config".to_string(),
                NorcError::Internal { .. } => "internal".to_string(),
            },
            message: error.to_string(),
            retry_after_secs: error.retry_after().map(|d| d.as_secs()),
            details: HashMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_type_conversion() {
        let msg_type = MessageType::MessageSend;
        let byte = msg_type.as_byte();
        assert_eq!(byte, 0x10);

        let parsed = MessageType::from_byte(byte).unwrap();
        assert_eq!(parsed, msg_type);
    }

    #[test]
    fn test_invalid_message_type() {
        assert!(MessageType::from_byte(0x99).is_err());
    }

    #[test]
    fn test_message_layer_validation() {
        assert!(MessageType::MessageSend.valid_for_layer(ProtocolLayer::Client));
        assert!(!MessageType::MessageSend.valid_for_layer(ProtocolLayer::Federation));
        assert!(MessageType::MessageRelay.valid_for_layer(ProtocolLayer::Federation));
    }

    #[test]
    fn test_norc_message_creation() {
        let version = Version::V2_0;
        let payload = Message::ConnectionRequest(ConnectionRequestMessage {
            client_versions: vec![version],
            preferred_version: version,
            capabilities: vec![Capability::Messaging],
            client_nonce: vec![1, 2, 3, 4],
            ephemeral_public_key: [0u8; 32],
            pq_public_key: None,
        });

        let msg = NorcMessage::new(
            version,
            MessageType::ConnectionRequest,
            1,
            [0u8; 32],
            payload,
        );

        assert_eq!(msg.version, version);
        assert_eq!(msg.message_type, MessageType::ConnectionRequest);
        assert_eq!(msg.sequence_number, 1);
    }

    #[test]
    fn test_message_validation() {
        let version = Version::V2_0;
        let payload = Message::ConnectionRequest(ConnectionRequestMessage {
            client_versions: vec![version],
            preferred_version: version,
            capabilities: vec![Capability::Messaging],
            client_nonce: vec![1, 2, 3, 4],
            ephemeral_public_key: [0u8; 32],
            pq_public_key: None,
        });

        let msg = NorcMessage::new(
            version,
            MessageType::ConnectionRequest,
            1,
            [0u8; 32],
            payload,
        );

        assert!(msg.validate().is_ok());

        // Test mismatched type and payload
        let mut bad_msg = msg.clone();
        bad_msg.message_type = MessageType::MessageSend;
        assert!(bad_msg.validate().is_err());
    }

    #[test]
    fn test_error_message_from_norc_error() {
        let error = NorcError::auth("Authentication failed");
        let error_msg = ErrorMessage::from(error);

        assert_eq!(error_msg.error_code, 2000);
        assert_eq!(error_msg.error_category, "auth");
        assert!(error_msg.message.contains("Authentication failed"));
    }
}