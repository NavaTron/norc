//! Session management
//!
//! Handles session lifecycle, token generation, and validation

use crate::ServerError;
use norc_protocol::types::DeviceId;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Session token
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionToken(String);

impl SessionToken {
    /// Generate a new random session token
    pub fn generate() -> Self {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let token: String = (0..64)
            .map(|_| format!("{:02x}", rng.r#gen::<u8>()))
            .collect();
        Self(token)
    }

    /// Create from string
    pub fn from_string(s: String) -> Self {
        Self(s)
    }

    /// Get token as string
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SessionToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Session data
#[derive(Debug, Clone)]
pub struct Session {
    /// Session ID
    pub id: String,
    /// Session token
    pub token: SessionToken,
    /// Device ID
    pub device_id: DeviceId,
    /// User ID (if applicable)
    pub user_id: Option<String>,
    /// Organization ID
    pub organization_id: String,
    /// Role
    pub role: super::Role,
    /// Created at
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Last accessed at
    pub last_accessed_at: chrono::DateTime<chrono::Utc>,
    /// Expires at
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

impl Session {
    /// Check if session is expired
    pub fn is_expired(&self) -> bool {
        chrono::Utc::now() > self.expires_at
    }

    /// Update last accessed time
    pub fn touch(&mut self) {
        self.last_accessed_at = chrono::Utc::now();
    }
}

/// Session configuration
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Session timeout in seconds
    pub timeout_secs: i64,
    /// Maximum sessions per device
    pub max_sessions_per_device: usize,
    /// Enable session renewal
    pub enable_renewal: bool,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            timeout_secs: 3600, // 1 hour
            max_sessions_per_device: 5,
            enable_renewal: true,
        }
    }
}

/// Session manager
pub struct SessionManager {
    /// Active sessions by token
    sessions: HashMap<SessionToken, Session>,
    /// Sessions by device ID (for limiting concurrent sessions)
    sessions_by_device: HashMap<DeviceId, Vec<SessionToken>>,
    /// Configuration
    config: SessionConfig,
}

impl SessionManager {
    /// Create a new session manager
    pub fn new(config: SessionConfig) -> Self {
        Self {
            sessions: HashMap::new(),
            sessions_by_device: HashMap::new(),
            config,
        }
    }

    /// Create a new session
    pub async fn create_session(
        &mut self,
        device_id: DeviceId,
        role: super::Role,
    ) -> Result<Session, ServerError> {
        // Check session limit for this device
        let oldest_token_to_remove = if let Some(device_sessions) = self.sessions_by_device.get(&device_id) {
            if device_sessions.len() >= self.config.max_sessions_per_device {
                // Get oldest session to remove
                device_sessions.first().cloned()
            } else {
                None
            }
        } else {
            None
        };

        // Remove oldest session if needed
        if let Some(token) = oldest_token_to_remove {
            self.revoke_session_internal(&token);
            warn!(
                "Removed oldest session for device {:?} (session limit reached)",
                device_id
            );
        }

        let token = SessionToken::generate();
        let now = chrono::Utc::now();
        let expires_at = now + chrono::Duration::seconds(self.config.timeout_secs);

        let session = Session {
            id: uuid::Uuid::new_v4().to_string(),
            token: token.clone(),
            device_id: device_id.clone(),
            user_id: None, // Set by caller if needed
            organization_id: String::new(), // Set by caller
            role,
            created_at: now,
            last_accessed_at: now,
            expires_at,
        };

        // Store session
        self.sessions.insert(token.clone(), session.clone());

        // Track by device
        self.sessions_by_device
            .entry(device_id.clone())
            .or_insert_with(Vec::new)
            .push(token.clone());

        info!("Created session {} for device {:?}", session.id, device_id);

        Ok(session)
    }

    /// Validate a session token
    pub async fn validate_session(&self, token: &SessionToken) -> Result<Session, ServerError> {
        let session = self
            .sessions
            .get(token)
            .ok_or_else(|| ServerError::Unauthorized("Invalid session token".to_string()))?;

        if session.is_expired() {
            warn!("Session {} has expired", session.id);
            return Err(ServerError::Unauthorized("Session expired".to_string()));
        }

        Ok(session.clone())
    }

    /// Renew a session
    pub async fn renew_session(&mut self, token: &SessionToken) -> Result<Session, ServerError> {
        if !self.config.enable_renewal {
            return Err(ServerError::Unauthorized(
                "Session renewal disabled".to_string(),
            ));
        }

        let session = self
            .sessions
            .get_mut(token)
            .ok_or_else(|| ServerError::Unauthorized("Invalid session token".to_string()))?;

        if session.is_expired() {
            return Err(ServerError::Unauthorized("Session expired".to_string()));
        }

        // Extend expiration
        let now = chrono::Utc::now();
        session.expires_at = now + chrono::Duration::seconds(self.config.timeout_secs);
        session.touch();

        info!("Renewed session {}", session.id);

        Ok(session.clone())
    }

    /// Revoke a session
    pub async fn revoke_session(&mut self, token: &SessionToken) -> Result<(), ServerError> {
        self.revoke_session_internal(token);
        Ok(())
    }

    /// Internal session revocation
    fn revoke_session_internal(&mut self, token: &SessionToken) {
        if let Some(session) = self.sessions.remove(token) {
            // Remove from device tracking
            if let Some(device_sessions) = self.sessions_by_device.get_mut(&session.device_id) {
                device_sessions.retain(|t| t != token);
                if device_sessions.is_empty() {
                    self.sessions_by_device.remove(&session.device_id);
                }
            }
            info!("Revoked session {}", session.id);
        }
    }

    /// Revoke all sessions for a device
    pub async fn revoke_device_sessions(&mut self, device_id: &DeviceId) -> Result<(), ServerError> {
        if let Some(device_sessions) = self.sessions_by_device.remove(device_id) {
            for token in device_sessions {
                self.sessions.remove(&token);
            }
            info!("Revoked all sessions for device {:?}", device_id);
        }
        Ok(())
    }

    /// Clean up expired sessions
    pub async fn cleanup_expired_sessions(&mut self) {
        let expired_tokens: Vec<SessionToken> = self
            .sessions
            .iter()
            .filter(|(_, session)| session.is_expired())
            .map(|(token, _)| token.clone())
            .collect();

        for token in expired_tokens {
            self.revoke_session_internal(&token);
        }

        if !self.sessions.is_empty() {
            info!("Cleaned up expired sessions, {} active sessions remaining", self.sessions.len());
        }
    }

    /// Get session count
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Get active device count
    pub fn active_device_count(&self) -> usize {
        self.sessions_by_device.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::rbac::Role;

    fn create_test_device_id() -> DeviceId {
        // DeviceId uses [u8; 32], so we create a test ID
        let mut id = [0u8; 32];
        id[0] = 1; // Just to have some test data
        DeviceId::new(id)
    }

    #[tokio::test]
    async fn test_session_creation() {
        let mut manager = SessionManager::new(SessionConfig::default());
        let device_id = create_test_device_id();
        let role = Role::User;

        let session = manager.create_session(device_id.clone(), role).await.unwrap();

        assert_eq!(session.device_id, device_id);
        assert_eq!(manager.session_count(), 1);
    }

    #[tokio::test]
    async fn test_session_validation() {
        let mut manager = SessionManager::new(SessionConfig::default());
        let device_id = create_test_device_id();
        let role = Role::User;

        let session = manager.create_session(device_id, role).await.unwrap();
        let token = session.token.clone();

        // Should validate successfully
        let validated = manager.validate_session(&token).await.unwrap();
        assert_eq!(validated.id, session.id);
    }

    #[tokio::test]
    async fn test_session_revocation() {
        let mut manager = SessionManager::new(SessionConfig::default());
        let device_id = create_test_device_id();
        let role = Role::User;

        let session = manager.create_session(device_id, role).await.unwrap();
        let token = session.token.clone();

        manager.revoke_session(&token).await.unwrap();
        assert_eq!(manager.session_count(), 0);

        // Should fail validation
        assert!(manager.validate_session(&token).await.is_err());
    }
}
