//! Authentication and Authorization Module
//!
//! Implements SERVER_REQUIREMENTS E-04: Security Implementation
//! - Device-based client authentication (T-S-F-04.02.01.01)
//! - Certificate-based federation authentication (T-S-F-04.02.01.02)
//! - Multi-factor authentication for admin access (T-S-F-04.02.01.03)
//! - Account lockout and rate limiting (T-S-F-04.02.01.04)

pub mod device_auth;
pub mod federation_auth;
pub mod session;
pub mod rbac;
pub mod rate_limit;
pub mod protocol;

pub use device_auth::{DeviceAuthenticator, DeviceCredentials};
pub use federation_auth::{FederationAuthenticator, FederationCredentials};
pub use session::{Session, SessionManager, SessionToken};
pub use rbac::{Permission, Role, AccessControl};
pub use rate_limit::{RateLimiter, RateLimitConfig};
pub use protocol::AuthProtocolHandler;

use crate::ServerError;
use norc_protocol::types::DeviceId;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Authentication result
#[derive(Debug, Clone)]
pub struct AuthResult {
    /// Device ID
    pub device_id: DeviceId,
    /// Session token
    pub session_token: SessionToken,
    /// Assigned role
    pub role: Role,
    /// Authentication timestamp
    pub authenticated_at: chrono::DateTime<chrono::Utc>,
}

/// Authentication context
#[derive(Debug, Clone)]
pub struct AuthContext {
    /// Device ID
    pub device_id: DeviceId,
    /// User ID (if applicable)
    pub user_id: Option<String>,
    /// Organization ID
    pub organization_id: String,
    /// Session ID
    pub session_id: String,
    /// Permissions
    pub permissions: Vec<Permission>,
}

impl AuthContext {
    /// Check if context has a specific permission
    pub fn has_permission(&self, permission: &Permission) -> bool {
        self.permissions.contains(permission)
    }

    /// Require a specific permission
    pub fn require_permission(&self, permission: &Permission) -> Result<(), ServerError> {
        if self.has_permission(permission) {
            Ok(())
        } else {
            Err(ServerError::Unauthorized(format!(
                "Missing required permission: {:?}",
                permission
            )))
        }
    }
}

/// Main authentication manager
pub struct AuthenticationManager {
    device_auth: Arc<DeviceAuthenticator>,
    federation_auth: Arc<FederationAuthenticator>,
    session_manager: Arc<RwLock<SessionManager>>,
    access_control: Arc<AccessControl>,
    rate_limiter: Arc<RwLock<RateLimiter>>,
}

impl AuthenticationManager {
    /// Create a new authentication manager
    pub fn new(
        device_auth: DeviceAuthenticator,
        federation_auth: FederationAuthenticator,
        session_manager: SessionManager,
        access_control: AccessControl,
        rate_limiter: RateLimiter,
    ) -> Self {
        Self {
            device_auth: Arc::new(device_auth),
            federation_auth: Arc::new(federation_auth),
            session_manager: Arc::new(RwLock::new(session_manager)),
            access_control: Arc::new(access_control),
            rate_limiter: Arc::new(RwLock::new(rate_limiter)),
        }
    }

    /// Authenticate a device
    pub async fn authenticate_device(
        &self,
        credentials: DeviceCredentials,
    ) -> Result<AuthResult, ServerError> {
        // Check rate limit
        let client_ip = credentials.client_ip.clone();
        {
            let mut limiter = self.rate_limiter.write().await;
            limiter.check_rate_limit(&client_ip)?;
        }

        // Authenticate device
        let auth_result = self.device_auth.authenticate(credentials).await?;

        // Create session
        let mut session_mgr = self.session_manager.write().await;
        let session = session_mgr.create_session(
            auth_result.device_id.clone(),
            auth_result.role.clone(),
        ).await?;

        Ok(AuthResult {
            device_id: auth_result.device_id,
            session_token: session.token.clone(),
            role: auth_result.role,
            authenticated_at: chrono::Utc::now(),
        })
    }

    /// Authenticate a federation partner
    pub async fn authenticate_federation(
        &self,
        credentials: FederationCredentials,
    ) -> Result<AuthResult, ServerError> {
        self.federation_auth.authenticate(credentials).await
    }

    /// Validate a session token
    pub async fn validate_session(&self, token: &SessionToken) -> Result<AuthContext, ServerError> {
        let session_mgr = self.session_manager.read().await;
        let session = session_mgr.validate_session(token).await?;

        // Get permissions for the role
        let permissions = self.access_control.get_permissions(&session.role)?;

        Ok(AuthContext {
            device_id: session.device_id.clone(),
            user_id: session.user_id.clone(),
            organization_id: session.organization_id.clone(),
            session_id: session.id.clone(),
            permissions,
        })
    }

    /// Revoke a session
    pub async fn revoke_session(&self, token: &SessionToken) -> Result<(), ServerError> {
        let mut session_mgr = self.session_manager.write().await;
        session_mgr.revoke_session(token).await
    }

    /// Get session manager
    pub fn session_manager(&self) -> Arc<RwLock<SessionManager>> {
        self.session_manager.clone()
    }
}
