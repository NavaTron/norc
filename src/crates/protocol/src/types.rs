//! Core types used throughout the NORC protocol

use crate::error::{NorcError, Result};
use base64::Engine;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Device identifier - UUID v4
pub type DeviceId = Uuid;

/// User identifier - opaque string
pub type UserId = String;

/// Server identifier - domain name
pub type ServerId = String;

/// Message identifier - UUID v4  
pub type MessageId = Uuid;

/// Session identifier - UUID v4
pub type SessionId = Uuid;

/// Conversation identifier - UUID v4
pub type ConversationId = Uuid;

/// Sequence number for message ordering and replay protection
pub type SequenceNumber = u64;

/// Hash type - BLAKE3 256-bit hash
pub type Hash = [u8; 32];

/// Ed25519 public key (32 bytes)
pub type PublicKey = [u8; 32];

/// Ed25519 signature (64 bytes) - wrapper for proper serialization
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature([u8; 64]);

impl Signature {
    /// Create a new signature from bytes
    pub fn new(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// Get the signature bytes
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    /// Convert to bytes
    pub fn to_bytes(self) -> [u8; 64] {
        self.0
    }
}

impl From<[u8; 64]> for Signature {
    fn from(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }
}

impl From<Signature> for [u8; 64] {
    fn from(sig: Signature) -> Self {
        sig.0
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        base64::engine::general_purpose::STANDARD.encode(&self.0).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&s)
            .map_err(serde::de::Error::custom)?;
        if bytes.len() != 64 {
            return Err(serde::de::Error::custom("Invalid signature length"));
        }
        let mut array = [0u8; 64];
        array.copy_from_slice(&bytes);
        Ok(Self(array))
    }
}

/// X25519 public key for ephemeral key exchange (32 bytes)
pub type EphemeralPublicKey = [u8; 32];

/// Nonce for cryptographic operations (12 bytes for ChaCha20Poly1305)
pub type Nonce = [u8; 12];

/// Encrypted key material that should be zeroized
#[derive(Clone, Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey(Vec<u8>);

impl SecretKey {
    /// Create new secret key from bytes
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Get the key bytes (use carefully)
    pub fn expose_secret(&self) -> &[u8] {
        &self.0
    }

    /// Get length of key
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if key is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Protocol capabilities that can be negotiated
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// Basic text messaging
    Messaging,
    /// Voice calls
    Voice,
    /// Video calls  
    Video,
    /// File transfers
    Files,
    /// Server federation
    Federation,
    /// End-to-end encryption
    E2ee,
    /// Post-quantum hybrid cryptography
    PostQuantum,
    /// Advanced message ratcheting
    Ratcheting,
    /// Typing indicators
    TypingIndicators,
    /// Read receipts
    ReadReceipts,
    /// Message reactions
    Reactions,
    /// Custom capability (for extensions)
    Custom(String),
}

impl std::fmt::Display for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Messaging => write!(f, "messaging"),
            Self::Voice => write!(f, "voice"),
            Self::Video => write!(f, "video"),
            Self::Files => write!(f, "files"),
            Self::Federation => write!(f, "federation"),
            Self::E2ee => write!(f, "e2ee"),
            Self::PostQuantum => write!(f, "post_quantum"),
            Self::Ratcheting => write!(f, "ratcheting"),
            Self::TypingIndicators => write!(f, "typing_indicators"),
            Self::ReadReceipts => write!(f, "read_receipts"),
            Self::Reactions => write!(f, "reactions"),
            Self::Custom(s) => write!(f, "custom:{s}"),
        }
    }
}

/// Message classification levels for compliance and security
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Classification {
    /// Unclassified information
    Unclassified,
    /// Official use only
    OfficialUseOnly,
    /// Confidential
    Confidential,
    /// Secret
    Secret,
    /// Top Secret
    TopSecret,
    /// NATO Restricted
    NatoRestricted,
    /// NATO Confidential
    NatoConfidential,
    /// NATO Secret
    NatoSecret,
}

impl Classification {
    /// Get the numeric level for comparison
    pub fn level(self) -> u8 {
        match self {
            Self::Unclassified => 0,
            Self::OfficialUseOnly => 1,
            Self::Confidential => 2,
            Self::Secret => 3,
            Self::TopSecret => 4,
            Self::NatoRestricted => 5,
            Self::NatoConfidential => 6,
            Self::NatoSecret => 7,
        }
    }

    /// Check if this classification allows access to data at the given level
    pub fn can_access(self, data_level: Self) -> bool {
        self.level() >= data_level.level()
    }
}

impl Default for Classification {
    fn default() -> Self {
        Self::Unclassified
    }
}

/// Device information for registration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// Human-readable device name
    pub name: String,
    /// Device type
    pub device_type: DeviceType,
    /// Supported capabilities
    pub capabilities: Vec<Capability>,
    /// Platform information
    pub platform: Option<String>,
    /// Application version
    pub app_version: Option<String>,
}

/// Type of device
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceType {
    /// Mobile phone
    Phone,
    /// Desktop computer
    Desktop,
    /// Tablet
    Tablet,
    /// Server/bot
    Server,
    /// IoT device
    Iot,
    /// Web browser
    Web,
    /// Other/unknown
    Other,
}

impl std::fmt::Display for DeviceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Phone => write!(f, "phone"),
            Self::Desktop => write!(f, "desktop"),
            Self::Tablet => write!(f, "tablet"),
            Self::Server => write!(f, "server"),
            Self::Iot => write!(f, "iot"),
            Self::Web => write!(f, "web"),
            Self::Other => write!(f, "other"),
        }
    }
}

/// User presence status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PresenceStatus {
    /// Online and available
    Online,
    /// Away from device
    Away,
    /// Busy/do not disturb
    Busy,
    /// Offline
    Offline,
    /// Invisible (appears offline to others)
    Invisible,
}

impl std::fmt::Display for PresenceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Online => write!(f, "online"),
            Self::Away => write!(f, "away"),
            Self::Busy => write!(f, "busy"),
            Self::Offline => write!(f, "offline"),
            Self::Invisible => write!(f, "invisible"),
        }
    }
}

/// Cryptographic key pair information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyInfo {
    /// Public key
    pub public_key: PublicKey,
    /// Key algorithm identifier
    pub algorithm: KeyAlgorithm,
    /// Key expiration timestamp
    pub expires_at: DateTime<Utc>,
    /// Whether this key has been verified
    pub verified: bool,
    /// Optional key fingerprint for display
    pub fingerprint: Option<String>,
}

/// Supported key algorithms
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyAlgorithm {
    /// Ed25519 signature key
    Ed25519,
    /// X25519 key exchange
    X25519,
    /// Hybrid post-quantum (Kyber768 + X25519)
    HybridPq,
}

impl KeyAlgorithm {
    /// Get the expected key size in bytes
    pub fn key_size(self) -> usize {
        match self {
            Self::Ed25519 | Self::X25519 => 32,
            Self::HybridPq => 32 + 1184, // X25519 + Kyber768 public key
        }
    }
}

/// Message content type
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentType {
    /// Plain text message
    Text,
    /// Rich text with formatting
    RichText,
    /// Image file
    Image,
    /// Audio file or voice message
    Audio,
    /// Video file
    Video,
    /// Generic file
    File,
    /// System message (joins, leaves, etc.)
    System,
    /// Typing indicator
    Typing,
    /// Read receipt
    ReadReceipt,
    /// Message reaction
    Reaction,
}

/// File metadata for file transfers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadata {
    /// Original filename
    pub filename: String,
    /// MIME type
    pub mime_type: String,
    /// File size in bytes
    pub size: u64,
    /// File hash for integrity verification
    pub hash: Hash,
    /// Optional thumbnail data
    pub thumbnail: Option<Vec<u8>>,
}

/// Trust level for servers and devices
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevel {
    /// No verification
    None,
    /// Basic domain verification
    Basic,
    /// Extended validation
    Extended,
    /// Government/enterprise PKI
    Enterprise,
    /// NATO/military grade
    Military,
}

impl TrustLevel {
    /// Check if this trust level is sufficient for the given requirement
    pub fn meets_requirement(self, required: Self) -> bool {
        self >= required
    }
}

/// Per-device encrypted content
pub type PerDeviceContent = HashMap<DeviceId, Vec<u8>>;

/// Conversation metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationMetadata {
    /// Conversation ID
    pub id: ConversationId,
    /// Conversation type
    pub conversation_type: ConversationType,
    /// Display name
    pub name: Option<String>,
    /// Participant list (if not private)
    pub participants: Vec<UserId>,
    /// Classification level
    pub classification: Classification,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last activity timestamp
    pub last_activity: DateTime<Utc>,
}

/// Type of conversation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConversationType {
    /// Direct message between two users
    DirectMessage,
    /// Group chat with multiple users
    Group,
    /// Public channel
    Channel,
    /// Broadcast channel
    Broadcast,
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Maximum requests per time window
    pub max_requests: u32,
    /// Time window in seconds
    pub window_secs: u32,
    /// Burst allowance above average rate
    pub burst_allowance: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_requests: 60,
            window_secs: 60,
            burst_allowance: 10,
        }
    }
}

/// Timestamp type with microsecond precision
pub type Timestamp = DateTime<Utc>;

/// Helper to get current timestamp
pub fn now() -> Timestamp {
    Utc::now()
}

/// Validate a user ID according to NORC rules
pub fn validate_user_id(user_id: &str) -> Result<()> {
    if user_id.is_empty() {
        return Err(NorcError::validation("User ID cannot be empty"));
    }
    if user_id.len() > 255 {
        return Err(NorcError::validation("User ID too long (max 255 chars)"));
    }
    if !user_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        return Err(NorcError::validation(
            "User ID contains invalid characters",
        ));
    }
    Ok(())
}

/// Validate a server ID (domain name)
pub fn validate_server_id(server_id: &str) -> Result<()> {
    if server_id.is_empty() {
        return Err(NorcError::validation("Server ID cannot be empty"));
    }
    if server_id.len() > 253 {
        return Err(NorcError::validation("Server ID too long (max 253 chars)"));
    }
    // Basic domain name validation
    if !server_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return Err(NorcError::validation(
            "Server ID contains invalid characters",
        ));
    }
    if server_id.starts_with('-') || server_id.ends_with('-') {
        return Err(NorcError::validation(
            "Server ID cannot start or end with hyphen",
        ));
    }
    
    // Check each label (component separated by dots)
    for label in server_id.split('.') {
        if label.is_empty() {
            return Err(NorcError::validation("Server ID cannot have empty labels"));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(NorcError::validation(
                "Domain labels cannot start or end with hyphen",
            ));
        }
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classification_levels() {
        assert!(Classification::Secret.can_access(Classification::Confidential));
        assert!(!Classification::Confidential.can_access(Classification::Secret));
        assert!(Classification::TopSecret.can_access(Classification::Unclassified));
    }

    #[test]
    fn test_trust_levels() {
        assert!(TrustLevel::Enterprise.meets_requirement(TrustLevel::Basic));
        assert!(!TrustLevel::Basic.meets_requirement(TrustLevel::Enterprise));
    }

    #[test]
    fn test_key_algorithms() {
        assert_eq!(KeyAlgorithm::Ed25519.key_size(), 32);
        assert_eq!(KeyAlgorithm::X25519.key_size(), 32);
        assert_eq!(KeyAlgorithm::HybridPq.key_size(), 32 + 1184);
    }

    #[test]
    fn test_user_id_validation() {
        assert!(validate_user_id("alice").is_ok());
        assert!(validate_user_id("alice_123").is_ok());
        assert!(validate_user_id("alice-bob").is_ok());
        assert!(validate_user_id("alice.domain").is_ok());

        assert!(validate_user_id("").is_err());
        assert!(validate_user_id("alice@domain").is_err()); // @ not allowed
        assert!(validate_user_id(&"x".repeat(256)).is_err()); // Too long
    }

    #[test]
    fn test_server_id_validation() {
        assert!(validate_server_id("example.com").is_ok());
        assert!(validate_server_id("sub.example.com").is_ok());
        assert!(validate_server_id("test-server.local").is_ok());

        assert!(validate_server_id("").is_err());
        assert!(validate_server_id("-invalid.com").is_err());
        assert!(validate_server_id("invalid-.com").is_err());
        assert!(validate_server_id("invalid@domain").is_err());
    }

    #[test]
    fn test_secret_key_zeroize() {
        let mut key = SecretKey::new(vec![1, 2, 3, 4]);
        assert_eq!(key.len(), 4);
        assert_eq!(key.expose_secret(), &[1, 2, 3, 4]);

        drop(key); // Should zeroize on drop
    }

    #[test]
    fn test_capability_display() {
        assert_eq!(Capability::Messaging.to_string(), "messaging");
        assert_eq!(Capability::Custom("test".to_string()).to_string(), "custom:test");
    }
}