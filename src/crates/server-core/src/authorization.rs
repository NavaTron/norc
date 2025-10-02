//! Authorization Middleware
//!
//! Implements per-message authorization and access control per SERVER_REQUIREMENTS E-02.

use crate::{
    ServerError,
    auth::{AuthenticationManager, Permission},
};
use norc_protocol::messages::EncryptedMessage;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, warn};

/// Message authorization result
#[derive(Debug)]
pub enum AuthorizationResult {
    /// Message is authorized to proceed
    Allowed,
    /// Message is denied with reason
    Denied(String),
}

/// Authorization middleware
pub struct AuthorizationMiddleware {
    /// Authentication manager for session validation
    auth_manager: Arc<AuthenticationManager>,
    /// Organization boundaries enforcement
    enforce_org_boundaries: bool,
}

impl AuthorizationMiddleware {
    /// Create a new authorization middleware
    pub fn new(auth_manager: Arc<AuthenticationManager>, enforce_org_boundaries: bool) -> Self {
        Self {
            auth_manager,
            enforce_org_boundaries,
        }
    }

    /// Authorize a message for routing
    ///
    /// Checks:
    /// 1. Sender is authenticated
    /// 2. Sender has permission to send messages
    /// 3. Recipient exists and can receive messages
    /// 4. Organization boundaries (if enabled)
    /// 5. Rate limits
    pub async fn authorize_message(
        &self,
        message: &EncryptedMessage,
        session_token: &str,
    ) -> Result<AuthorizationResult, ServerError> {
        // Step 1: Validate session token
        let session_token_obj = crate::auth::SessionToken::from_string(session_token.to_string());
        let auth_context = match self.auth_manager.validate_session(&session_token_obj).await {
            Ok(ctx) => ctx,
            Err(e) => {
                warn!("Session validation failed: {}", e);
                return Ok(AuthorizationResult::Denied(
                    "Invalid or expired session".to_string(),
                ));
            }
        };

        // Step 2: Verify sender device ID matches authenticated device
        let sender_id = hex::encode(message.sender.as_bytes());
        let auth_device_id = hex::encode(auth_context.device_id.as_bytes());

        if sender_id != auth_device_id {
            warn!(
                "Device ID mismatch: message from {:?}, authenticated as {:?}",
                message.sender, auth_context.device_id
            );
            return Ok(AuthorizationResult::Denied(
                "Device ID mismatch".to_string(),
            ));
        }

        // Step 3: Check sender has permission to send messages
        if !auth_context.has_permission(&Permission::MessageSend) {
            warn!(
                "Device {:?} does not have MessageSend permission",
                message.sender
            );
            return Ok(AuthorizationResult::Denied(
                "No permission to send messages".to_string(),
            ));
        }

        // Step 4: Validate recipient (basic check - recipient device exists)
        // TODO: Look up recipient device in DeviceRepository
        // For now, we assume recipient is valid if message is properly encrypted

        // Step 5: Enforce organization boundaries if enabled
        if self.enforce_org_boundaries {
            // TODO: Check that sender and recipient are in the same organization
            // or that cross-org messaging is allowed
            // This requires organization_id in the auth context and recipient lookup
            debug!("Organization boundary check: enabled but not yet implemented");
        }

        // Step 6: Rate limiting check
        // The RateLimiter is already checked at authentication time,
        // but we could add per-message rate limiting here
        // TODO: Implement per-message rate limiting

        debug!(
            "Message authorized: from {:?} to {:?}",
            message.sender, message.recipient
        );

        Ok(AuthorizationResult::Allowed)
    }

    /// Authorize a user to access a specific resource
    pub async fn authorize_resource_access(
        &self,
        session_token: &str,
        required_permission: Permission,
    ) -> Result<AuthorizationResult, ServerError> {
        // Validate session
        let session_token_obj = crate::auth::SessionToken::from_string(session_token.to_string());
        let auth_context = match self.auth_manager.validate_session(&session_token_obj).await {
            Ok(ctx) => ctx,
            Err(_) => {
                return Ok(AuthorizationResult::Denied(
                    "Invalid or expired session".to_string(),
                ));
            }
        };

        // Check permission
        if auth_context.has_permission(&required_permission) {
            Ok(AuthorizationResult::Allowed)
        } else {
            Ok(AuthorizationResult::Denied(format!(
                "Missing required permission: {:?}",
                required_permission
            )))
        }
    }

    /// Check if a user can manage a specific device
    pub async fn authorize_device_management(
        &self,
        session_token: &str,
        device_id: &str,
    ) -> Result<AuthorizationResult, ServerError> {
        // Validate session
        let session_token_obj = crate::auth::SessionToken::from_string(session_token.to_string());
        let auth_context = match self.auth_manager.validate_session(&session_token_obj).await {
            Ok(ctx) => ctx,
            Err(_) => {
                return Ok(AuthorizationResult::Denied(
                    "Invalid or expired session".to_string(),
                ));
            }
        };

        // Check if user has device management permission
        if !auth_context.has_permission(&Permission::DeviceRevoke) {
            return Ok(AuthorizationResult::Denied(
                "No permission to manage devices".to_string(),
            ));
        }

        // Check if device belongs to the user (or user is admin)
        if let Some(ref user_id) = auth_context.user_id {
            // TODO: Look up device and verify ownership
            // For now, allow if user has the permission
            debug!(
                "Device management authorized: user {} managing device {}",
                user_id, device_id
            );
            Ok(AuthorizationResult::Allowed)
        } else {
            Ok(AuthorizationResult::Denied(
                "No user context available".to_string(),
            ))
        }
    }
}

/// Per-user rate limiter for message sending
pub struct MessageRateLimiter {
    /// Rate limit: messages per minute per user
    messages_per_minute: u32,
    /// Message counters by user ID
    counters: Arc<RwLock<HashMap<String, UserMessageCounter>>>,
}

#[derive(Debug, Clone)]
struct UserMessageCounter {
    /// Message count in current window
    count: u32,
    /// Window start time
    window_start: std::time::Instant,
}

impl MessageRateLimiter {
    /// Create a new message rate limiter
    pub fn new(messages_per_minute: u32) -> Self {
        Self {
            messages_per_minute,
            counters: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Check if user can send a message
    pub async fn check_rate_limit(&self, user_id: &str) -> Result<(), ServerError> {
        let now = std::time::Instant::now();
        let mut counters = self.counters.write().await;

        let counter = counters
            .entry(user_id.to_string())
            .or_insert(UserMessageCounter {
                count: 0,
                window_start: now,
            });

        // Reset counter if window has expired (1 minute)
        if now.duration_since(counter.window_start).as_secs() >= 60 {
            counter.count = 0;
            counter.window_start = now;
        }

        // Check limit
        if counter.count >= self.messages_per_minute {
            warn!(
                "Rate limit exceeded for user {}: {} messages/min",
                user_id, counter.count
            );
            return Err(ServerError::RateLimitExceeded(format!(
                "Rate limit exceeded: {} messages per minute",
                self.messages_per_minute
            )));
        }

        // Increment counter
        counter.count += 1;
        Ok(())
    }

    /// Get current message count for a user
    pub async fn get_message_count(&self, user_id: &str) -> u32 {
        let counters = self.counters.read().await;
        counters.get(user_id).map(|c| c.count).unwrap_or(0)
    }

    /// Reset rate limit for a user (admin operation)
    pub async fn reset_user_limit(&self, user_id: &str) {
        let mut counters = self.counters.write().await;
        counters.remove(user_id);
    }

    /// Cleanup expired counters (should be called periodically)
    pub async fn cleanup_expired(&self) {
        let now = std::time::Instant::now();
        let mut counters = self.counters.write().await;

        counters.retain(|_, counter| {
            now.duration_since(counter.window_start).as_secs() < 120 // Keep for 2 minutes
        });
    }
}

use std::collections::HashMap;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rate_limiter_basic() {
        let limiter = MessageRateLimiter::new(10);

        // Should allow first 10 messages
        for _ in 0..10 {
            assert!(limiter.check_rate_limit("user1").await.is_ok());
        }

        // 11th message should be denied
        assert!(limiter.check_rate_limit("user1").await.is_err());
    }

    #[tokio::test]
    async fn test_rate_limiter_different_users() {
        let limiter = MessageRateLimiter::new(5);

        // Each user should have independent limits
        for _ in 0..5 {
            assert!(limiter.check_rate_limit("user1").await.is_ok());
            assert!(limiter.check_rate_limit("user2").await.is_ok());
        }

        assert!(limiter.check_rate_limit("user1").await.is_err());
        assert!(limiter.check_rate_limit("user2").await.is_err());
    }
}
