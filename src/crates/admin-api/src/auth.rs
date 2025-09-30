//! Authentication and authorization for Admin API
//!
//! Implements T-S-F-08.02.01.02: Authentication and authorization requirements

use crate::{rbac::Role, ApiError, ApiResult};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// API key structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    /// Unique key ID
    pub id: Uuid,
    
    /// API key name/description
    pub name: String,
    
    /// Hashed key value (never store plaintext)
    pub key_hash: String,
    
    /// Assigned roles
    pub roles: Vec<Role>,
    
    /// Key creation timestamp
    pub created_at: DateTime<Utc>,
    
    /// Optional expiration timestamp
    pub expires_at: Option<DateTime<Utc>>,
    
    /// Whether the key is active
    pub active: bool,
    
    /// Organization ID (for multi-tenancy)
    pub organization_id: Option<String>,
    
    /// Last used timestamp
    pub last_used_at: Option<DateTime<Utc>>,
}

impl ApiKey {
    /// Create a new API key
    pub fn new(name: String, roles: Vec<Role>, organization_id: Option<String>) -> (Self, String) {
        let id = Uuid::new_v4();
        let raw_key = format!("norc_{}", Uuid::new_v4());
        let key_hash = hash_api_key(&raw_key);
        
        let api_key = Self {
            id,
            name,
            key_hash,
            roles,
            created_at: Utc::now(),
            expires_at: None,
            active: true,
            organization_id,
            last_used_at: None,
        };
        
        (api_key, raw_key)
    }
    
    /// Verify if a raw key matches this API key
    pub fn verify_key(&self, raw_key: &str) -> bool {
        if !self.active {
            return false;
        }
        
        if let Some(expires_at) = self.expires_at {
            if Utc::now() > expires_at {
                return false;
            }
        }
        
        let provided_hash = hash_api_key(raw_key);
        constant_time_compare(&self.key_hash, &provided_hash)
    }
    
    /// Check if key is expired
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            Utc::now() > expires_at
        } else {
            false
        }
    }
}

/// Authentication context for a request
#[derive(Debug, Clone)]
pub struct AuthContext {
    /// Authenticated API key
    pub api_key: ApiKey,
    
    /// Request ID for audit trail
    pub request_id: Uuid,
    
    /// Client IP address
    pub client_ip: String,
    
    /// Request timestamp
    pub timestamp: DateTime<Utc>,
}

impl AuthContext {
    /// Check if context has a specific permission
    pub fn has_permission(&self, permission: crate::rbac::Permission) -> bool {
        crate::rbac::has_permission(&self.api_key.roles, permission)
    }
    
    /// Require a specific permission, return error if not authorized
    pub fn require_permission(&self, permission: crate::rbac::Permission) -> ApiResult<()> {
        if self.has_permission(permission) {
            Ok(())
        } else {
            Err(ApiError::Forbidden(format!(
                "Permission {:?} required for this operation",
                permission
            )))
        }
    }
}

/// API key store (in-memory, should be backed by database in production)
pub struct ApiKeyStore {
    keys: Arc<RwLock<HashMap<Uuid, ApiKey>>>,
}

impl ApiKeyStore {
    /// Create a new API key store
    pub fn new() -> Self {
        Self {
            keys: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Add an API key
    pub async fn add_key(&self, key: ApiKey) -> ApiResult<()> {
        let mut keys = self.keys.write().await;
        keys.insert(key.id, key);
        Ok(())
    }
    
    /// Verify and retrieve an API key by raw key value
    pub async fn verify_key(&self, raw_key: &str) -> ApiResult<ApiKey> {
        let mut keys = self.keys.write().await;
        
        for key in keys.values_mut() {
            if key.verify_key(raw_key) {
                // Update last used timestamp
                key.last_used_at = Some(Utc::now());
                return Ok(key.clone());
            }
        }
        
        Err(ApiError::Unauthorized("Invalid API key".to_string()))
    }
    
    /// Get all API keys
    pub async fn list_keys(&self) -> Vec<ApiKey> {
        let keys = self.keys.read().await;
        keys.values().cloned().collect()
    }
    
    /// Revoke an API key
    pub async fn revoke_key(&self, key_id: Uuid) -> ApiResult<()> {
        let mut keys = self.keys.write().await;
        
        if let Some(key) = keys.get_mut(&key_id) {
            key.active = false;
            Ok(())
        } else {
            Err(ApiError::NotFound(format!("API key {} not found", key_id)))
        }
    }
    
    /// Delete an API key
    pub async fn delete_key(&self, key_id: Uuid) -> ApiResult<()> {
        let mut keys = self.keys.write().await;
        
        if keys.remove(&key_id).is_some() {
            Ok(())
        } else {
            Err(ApiError::NotFound(format!("API key {} not found", key_id)))
        }
    }
}

impl Default for ApiKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Hash an API key using SHA-256
fn hash_api_key(key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    hex::encode(hasher.finalize())
}

/// Constant-time string comparison to prevent timing attacks
fn constant_time_compare(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    
    let mut result = 0u8;
    for (x, y) in a_bytes.iter().zip(b_bytes.iter()) {
        result |= x ^ y;
    }
    
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_key_creation() {
        let (api_key, raw_key) = ApiKey::new(
            "Test Key".to_string(),
            vec![Role::OrgAdmin],
            Some("org1".to_string()),
        );
        
        assert!(api_key.verify_key(&raw_key));
        assert!(!api_key.is_expired());
        assert!(api_key.active);
    }

    #[test]
    fn test_api_key_verification_fails_wrong_key() {
        let (api_key, _) = ApiKey::new(
            "Test Key".to_string(),
            vec![Role::OrgAdmin],
            None,
        );
        
        assert!(!api_key.verify_key("wrong_key"));
    }

    #[test]
    fn test_constant_time_compare() {
        assert!(constant_time_compare("hello", "hello"));
        assert!(!constant_time_compare("hello", "world"));
        assert!(!constant_time_compare("hello", "hello!"));
    }

    #[tokio::test]
    async fn test_api_key_store() {
        let store = ApiKeyStore::new();
        let (api_key, raw_key) = ApiKey::new(
            "Test Key".to_string(),
            vec![Role::OrgAdmin],
            None,
        );
        
        store.add_key(api_key.clone()).await.unwrap();
        
        let verified = store.verify_key(&raw_key).await.unwrap();
        assert_eq!(verified.id, api_key.id);
        
        store.revoke_key(api_key.id).await.unwrap();
        assert!(store.verify_key(&raw_key).await.is_err());
    }
}
