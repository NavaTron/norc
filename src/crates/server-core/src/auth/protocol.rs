//! Authentication Protocol Handler
//!
//! Implements challenge-response authentication flow per SERVER_REQUIREMENTS E-02.

use crate::{ServerError, auth::DeviceAuthenticator};
use norc_protocol::{
    messages::{AuthChallenge, AuthChallengeRequest, AuthResponse, AuthResult},
    types::DeviceId,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

/// Challenge lifetime in seconds
const CHALLENGE_LIFETIME_SECS: u64 = 300; // 5 minutes

/// Pending authentication challenge
#[derive(Debug, Clone)]
struct PendingChallenge {
    /// Challenge nonce
    challenge: [u8; 32],
    /// Device ID
    #[allow(dead_code)]
    device_id: DeviceId,
    /// Creation timestamp
    #[allow(dead_code)]
    created_at: u64,
    /// Expiry timestamp
    expires_at: u64,
}

/// Authentication protocol handler
pub struct AuthProtocolHandler {
    /// Device authenticator
    authenticator: Arc<DeviceAuthenticator>,
    /// Pending challenges by device ID
    pending_challenges: Arc<Mutex<HashMap<DeviceId, PendingChallenge>>>,
}

impl AuthProtocolHandler {
    /// Create a new authentication protocol handler
    pub fn new(authenticator: Arc<DeviceAuthenticator>) -> Self {
        Self {
            authenticator,
            pending_challenges: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Handle authentication challenge request
    pub async fn handle_challenge_request(
        &self,
        request: AuthChallengeRequest,
    ) -> Result<AuthChallenge, ServerError> {
        // Generate challenge
        let challenge_vec = self.authenticator.generate_challenge(&request.device_id);
        
        // Convert to fixed-size array
        let mut challenge = [0u8; 32];
        challenge.copy_from_slice(&challenge_vec[..32]);
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        
        let expires_at = now + (CHALLENGE_LIFETIME_SECS * 1000);

        // Store pending challenge
        let pending = PendingChallenge {
            challenge,
            device_id: request.device_id.clone(),
            created_at: now,
            expires_at,
        };

        {
            let mut pending_map = self.pending_challenges.lock().await;
            pending_map.insert(request.device_id.clone(), pending);
        }

        tracing::debug!(
            device_id = ?request.device_id,
            "Generated authentication challenge"
        );

        Ok(AuthChallenge {
            challenge,
            expires_at,
        })
    }

    /// Handle authentication response
    pub async fn handle_auth_response(
        &self,
        response: AuthResponse,
    ) -> Result<AuthResult, ServerError> {
        // Get pending challenge
        let pending = {
            let mut pending_map = self.pending_challenges.lock().await;
            pending_map.remove(&response.device_id)
        };

        let pending = match pending {
            Some(p) => p,
            None => {
                return Ok(AuthResult {
                    success: false,
                    session_token: None,
                    error: Some("No pending challenge found".to_string()),
                    expires_at: None,
                });
            }
        };

        // Verify challenge matches
        if pending.challenge != response.challenge {
            return Ok(AuthResult {
                success: false,
                session_token: None,
                error: Some("Challenge mismatch".to_string()),
                expires_at: None,
            });
        }

        // Check expiry
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        if now > pending.expires_at {
            return Ok(AuthResult {
                success: false,
                session_token: None,
                error: Some("Challenge expired".to_string()),
                expires_at: None,
            });
        }

        // Verify signature
        // Note: This would need to integrate with the DeviceAuthenticator's verify_challenge_signature
        // For now, returning a placeholder result

        // TODO: Complete signature verification and session creation
        // This needs to be wired to the SessionManager

        Ok(AuthResult {
            success: true,
            session_token: Some([0u8; 32]), // Placeholder
            error: None,
            expires_at: Some(now + (3600 * 1000)), // 1 hour
        })
    }

    /// Cleanup expired challenges (should be called periodically)
    pub async fn cleanup_expired_challenges(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let mut pending_map = self.pending_challenges.lock().await;
        pending_map.retain(|_, pending| now <= pending.expires_at);

        tracing::debug!(
            remaining = pending_map.len(),
            "Cleaned up expired authentication challenges"
        );
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn test_challenge_lifecycle() {
        // This would require a mock DeviceAuthenticator
        // Placeholder test
    }
}
