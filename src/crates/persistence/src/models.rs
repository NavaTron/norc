//! Data models for persistence layer

use chrono::{DateTime, Utc};
use norc_protocol::{DeviceId, TrustLevel};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// User account
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct User {
    /// User ID (UUID)
    pub id: String,
    /// Username
    pub username: String,
    /// Organization ID
    pub organization_id: String,
    /// Display name
    pub display_name: Option<String>,
    /// Email address
    pub email: Option<String>,
    /// Account status (active, suspended, deleted)
    pub status: String,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Updated timestamp
    pub updated_at: DateTime<Utc>,
}

/// Device registration
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Device {
    /// Device ID
    pub id: String,
    /// User ID
    pub user_id: String,
    /// Device name/description
    pub name: String,
    /// Device type (mobile, desktop, web)
    pub device_type: String,
    /// Public key (Ed25519)
    pub public_key: Vec<u8>,
    /// Device status (active, revoked)
    pub status: String,
    /// Last seen timestamp
    pub last_seen: Option<DateTime<Utc>>,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
}

/// Authentication session
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Session {
    /// Session ID
    pub id: String,
    /// User ID
    pub user_id: String,
    /// Device ID
    pub device_id: String,
    /// Session token
    pub token: String,
    /// IP address
    pub ip_address: Option<String>,
    /// User agent
    pub user_agent: Option<String>,
    /// Expiry timestamp
    pub expires_at: DateTime<Utc>,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
}

/// Persisted message for offline delivery
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct PersistedMessage {
    /// Message ID
    pub id: String,
    /// Sender device ID
    pub sender_device_id: String,
    /// Recipient device ID
    pub recipient_device_id: String,
    /// Encrypted message payload
    pub payload: Vec<u8>,
    /// Message priority
    pub priority: i32,
    /// Delivery status (pending, delivered, failed)
    pub status: String,
    /// Number of delivery attempts
    pub attempts: i32,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Delivered timestamp
    pub delivered_at: Option<DateTime<Utc>>,
    /// Expires at timestamp
    pub expires_at: DateTime<Utc>,
}

/// Federation partner trust relationship
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct FederationTrust {
    /// Trust ID
    pub id: String,
    /// Partner organization ID
    pub organization_id: String,
    /// Partner server address
    pub server_address: String,
    /// Trust level
    pub trust_level: String,
    /// Certificate fingerprint
    pub cert_fingerprint: String,
    /// Trust status (active, suspended, revoked)
    pub status: String,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Updated timestamp
    pub updated_at: DateTime<Utc>,
}

/// Presence information
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Presence {
    /// User ID
    pub user_id: String,
    /// Device ID
    pub device_id: String,
    /// Presence status (online, away, busy, offline)
    pub status: String,
    /// Custom status message
    pub status_message: Option<String>,
    /// Last activity timestamp
    pub last_activity: DateTime<Utc>,
    /// Updated timestamp
    pub updated_at: DateTime<Utc>,
}

/// Push notification token
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct PushToken {
    /// Token ID
    pub id: String,
    /// User ID
    pub user_id: String,
    /// Device ID
    pub device_id: String,
    /// Platform (apns, fcm)
    pub platform: String,
    /// Push token
    pub token: String,
    /// Token status (active, invalid)
    pub status: String,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Updated timestamp
    pub updated_at: DateTime<Utc>,
}

/// Audit log entry
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AuditLog {
    /// Log ID
    pub id: String,
    /// Event type
    pub event_type: String,
    /// User ID (if applicable)
    pub user_id: Option<String>,
    /// Device ID (if applicable)
    pub device_id: Option<String>,
    /// IP address
    pub ip_address: Option<String>,
    /// Event data (JSON)
    pub event_data: String,
    /// Event result (success, failure)
    pub result: String,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
}
