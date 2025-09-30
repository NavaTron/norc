//! Data models for Admin API requests and responses

use crate::rbac::Role;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

/// Health check response
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub timestamp: DateTime<Utc>,
    pub version: String,
    pub uptime_seconds: u64,
}

/// API version information
#[derive(Debug, Serialize)]
pub struct VersionResponse {
    pub version: String,
    pub api_version: String,
    pub build_date: String,
}

// ============================================================================
// User Management Models
// ============================================================================

/// User creation request
#[derive(Debug, Deserialize, Validate)]
pub struct CreateUserRequest {
    #[validate(length(min = 3, max = 100))]
    pub username: String,
    
    #[validate(email)]
    pub email: Option<String>,
    
    pub display_name: Option<String>,
    
    pub organization_id: String,
    
    pub enabled: Option<bool>,
}

/// User update request
#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct UpdateUserRequest {
    #[validate(length(min = 3, max = 100))]
    pub username: Option<String>,
    
    #[validate(email)]
    pub email: Option<String>,
    
    pub display_name: Option<String>,
    
    pub enabled: Option<bool>,
}

/// User response
#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub username: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub organization_id: String,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// List of users response
#[derive(Debug, Serialize)]
pub struct UserListResponse {
    pub users: Vec<UserResponse>,
    pub total: usize,
    pub page: usize,
    pub page_size: usize,
}

// ============================================================================
// Device Management Models
// ============================================================================

/// Device registration request
#[derive(Debug, Deserialize, Validate)]
pub struct RegisterDeviceRequest {
    pub user_id: Uuid,
    
    #[validate(length(min = 1, max = 100))]
    pub device_name: String,
    
    pub device_type: String,
    
    pub public_key: String,
}

/// Device response
#[derive(Debug, Serialize)]
pub struct DeviceResponse {
    pub id: Uuid,
    pub user_id: Uuid,
    pub device_name: String,
    pub device_type: String,
    pub public_key_hash: String,
    pub enabled: bool,
    pub registered_at: DateTime<Utc>,
    pub last_seen_at: Option<DateTime<Utc>>,
}

/// Device list response
#[derive(Debug, Serialize)]
pub struct DeviceListResponse {
    pub devices: Vec<DeviceResponse>,
    pub total: usize,
}

// ============================================================================
// Configuration Management Models
// ============================================================================

/// Configuration update request
#[derive(Debug, Deserialize)]
pub struct ConfigUpdateRequest {
    pub section: String,
    pub key: String,
    pub value: serde_json::Value,
    pub comment: Option<String>,
}

/// Configuration response
#[derive(Debug, Serialize)]
pub struct ConfigResponse {
    pub section: String,
    pub key: String,
    pub value: serde_json::Value,
    pub version: u64,
    pub updated_at: DateTime<Utc>,
    pub updated_by: String,
}

/// Configuration diff response
#[derive(Debug, Serialize)]
pub struct ConfigDiffResponse {
    pub old_value: serde_json::Value,
    pub new_value: serde_json::Value,
    pub section: String,
    pub key: String,
}

/// Configuration validation result
#[derive(Debug, Serialize)]
pub struct ConfigValidationResponse {
    pub valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

// ============================================================================
// Server Monitoring Models
// ============================================================================

/// Server status response
#[derive(Debug, Serialize)]
pub struct ServerStatusResponse {
    pub status: String,
    pub uptime_seconds: u64,
    pub connections: usize,
    pub federation_partners: usize,
    pub messages_processed: u64,
}

/// Metrics response
#[derive(Debug, Serialize)]
pub struct MetricsResponse {
    pub timestamp: DateTime<Utc>,
    pub connections: ConnectionMetrics,
    pub messages: MessageMetrics,
    pub federation: FederationMetrics,
    pub system: SystemMetrics,
}

#[derive(Debug, Serialize)]
pub struct ConnectionMetrics {
    pub active: usize,
    pub total: u64,
    pub failed: u64,
}

#[derive(Debug, Serialize)]
pub struct MessageMetrics {
    pub sent: u64,
    pub received: u64,
    pub queued: u64,
    pub failed: u64,
}

#[derive(Debug, Serialize)]
pub struct FederationMetrics {
    pub partners: usize,
    pub active_connections: usize,
    pub messages_routed: u64,
}

#[derive(Debug, Serialize)]
pub struct SystemMetrics {
    pub cpu_usage: f64,
    pub memory_mb: u64,
    pub disk_usage_mb: u64,
}

// ============================================================================
// Federation Management Models
// ============================================================================

/// Federation partner creation request
#[derive(Debug, Deserialize, Validate)]
pub struct CreateFederationPartnerRequest {
    #[validate(length(min = 1, max = 100))]
    pub organization_id: String,
    
    #[validate(url)]
    pub address: String,
    
    pub trust_level: String,
    
    pub certificate: String,
}

/// Federation partner response
#[derive(Debug, Serialize)]
pub struct FederationPartnerResponse {
    pub id: Uuid,
    pub organization_id: String,
    pub address: String,
    pub trust_level: String,
    pub state: String,
    pub created_at: DateTime<Utc>,
    pub last_connected_at: Option<DateTime<Utc>>,
}

// ============================================================================
// Audit Log Models
// ============================================================================

/// Audit log query request
#[derive(Debug, Deserialize)]
pub struct AuditLogQueryRequest {
    pub start_date: Option<DateTime<Utc>>,
    pub end_date: Option<DateTime<Utc>>,
    pub event_type: Option<String>,
    pub user_id: Option<Uuid>,
    pub limit: Option<usize>,
}

/// Audit log entry response
#[derive(Debug, Serialize)]
pub struct AuditLogResponse {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub actor_id: String,
    pub resource_type: String,
    pub resource_id: String,
    pub action: String,
    pub result: String,
    pub details: Option<serde_json::Value>,
}

/// Audit log list response
#[derive(Debug, Serialize)]
pub struct AuditLogListResponse {
    pub logs: Vec<AuditLogResponse>,
    pub total: usize,
}

// ============================================================================
// API Key Management Models
// ============================================================================

/// API key creation request
#[derive(Debug, Deserialize, Validate)]
pub struct CreateApiKeyRequest {
    #[validate(length(min = 1, max = 100))]
    pub name: String,
    
    pub roles: Vec<Role>,
    
    pub organization_id: Option<String>,
    
    pub expires_in_days: Option<u64>,
}

/// API key response (includes the raw key only on creation)
#[derive(Debug, Serialize)]
pub struct ApiKeyResponse {
    pub id: Uuid,
    pub name: String,
    pub roles: Vec<Role>,
    pub organization_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub active: bool,
    pub last_used_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>, // Only included on creation
}

/// API key list response
#[derive(Debug, Serialize)]
pub struct ApiKeyListResponse {
    pub keys: Vec<ApiKeyResponse>,
    pub total: usize,
}

// ============================================================================
// Bulk Operations Models
// ============================================================================

/// Bulk operation request
#[derive(Debug, Deserialize)]
pub struct BulkOperationRequest<T> {
    pub operations: Vec<T>,
}

/// Bulk operation result
#[derive(Debug, Serialize)]
pub struct BulkOperationResult {
    pub successful: usize,
    pub failed: usize,
    pub errors: Vec<BulkOperationError>,
}

#[derive(Debug, Serialize)]
pub struct BulkOperationError {
    pub index: usize,
    pub error: String,
}

// ============================================================================
// Pagination Models
// ============================================================================

/// Pagination parameters
#[derive(Debug, Deserialize)]
pub struct PaginationParams {
    #[serde(default = "default_page")]
    pub page: usize,
    
    #[serde(default = "default_page_size")]
    pub page_size: usize,
}

fn default_page() -> usize {
    1
}

fn default_page_size() -> usize {
    50
}

impl PaginationParams {
    pub fn offset(&self) -> usize {
        (self.page - 1) * self.page_size
    }
}
