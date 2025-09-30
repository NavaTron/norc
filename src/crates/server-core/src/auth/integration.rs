//! Authentication Integration Example
//!
//! Shows how to integrate the authentication system into the server

use norc_server_core::{
    AuthenticationManager, DeviceAuthenticator, FederationAuthenticator, SessionManager,
    AccessControl, AuthRateLimiter, AuthRateLimitConfig, ServerError,
};
use norc_persistence::repositories::{DeviceRepository, FederationRepository};
use norc_persistence::Database;
use std::sync::Arc;

/// Initialize the authentication system
pub async fn init_authentication(
    database: Arc<Database>,
) -> Result<AuthenticationManager, ServerError> {
    // Create repositories
    let device_repo = Arc::new(DeviceRepository::new(database.clone()));
    let federation_repo = Arc::new(FederationRepository::new(database.clone()));

    // Create device authenticator
    let device_auth = DeviceAuthenticator::new(device_repo);

    // Create federation authenticator with trusted CAs
    let trusted_cas = load_trusted_cas()?;
    let federation_auth = FederationAuthenticator::new(
        federation_repo,
        trusted_cas,
        true, // strict validation
    );

    // Create session manager with default config
    let session_manager = SessionManager::new(Default::default());

    // Create access control
    let access_control = AccessControl::new();

    // Create rate limiter
    let rate_limit_config = AuthRateLimitConfig {
        max_attempts: 5,
        window_secs: 60,
        lockout_duration_secs: 300,
        progressive_backoff: true,
    };
    let rate_limiter = AuthRateLimiter::new(rate_limit_config);

    // Create authentication manager
    let auth_manager = AuthenticationManager::new(
        device_auth,
        federation_auth,
        session_manager,
        access_control,
        rate_limiter,
    );

    Ok(auth_manager)
}

/// Load trusted CA certificates
fn load_trusted_cas() -> Result<Vec<Vec<u8>>, ServerError> {
    // In a real implementation, this would load from configuration
    // For now, return empty list
    Ok(Vec::new())
}

/// Example: Authenticate a device
pub async fn example_authenticate_device(
    auth_manager: &AuthenticationManager,
) -> Result<(), ServerError> {
    use norc_server_core::DeviceCredentials;
    use norc_protocol::types::{DeviceId, PublicKey, Signature};

    // Prepare credentials (would come from client request)
    let credentials = DeviceCredentials {
        device_id: DeviceId::new("device-123".to_string()),
        public_key: PublicKey::new([0u8; 32]),
        signature: Signature::new([0u8; 64]),
        nonce: vec![1, 2, 3, 4],
        client_ip: "192.168.1.100".to_string(),
    };

    // Authenticate
    match auth_manager.authenticate_device(credentials).await {
        Ok(result) => {
            println!("Device authenticated successfully!");
            println!("Device ID: {}", result.device_id);
            println!("Session Token: {}", result.session_token);
            println!("Role: {:?}", result.role);
            Ok(())
        }
        Err(e) => {
            eprintln!("Authentication failed: {}", e);
            Err(e)
        }
    }
}

/// Example: Validate a session
pub async fn example_validate_session(
    auth_manager: &AuthenticationManager,
    token: &norc_server_core::SessionToken,
) -> Result<(), ServerError> {
    use norc_server_core::Permission;

    match auth_manager.validate_session(token).await {
        Ok(context) => {
            println!("Session valid!");
            println!("Device ID: {}", context.device_id);
            println!("Organization: {}", context.organization_id);
            
            // Check specific permission
            if context.has_permission(&Permission::MessageSend) {
                println!("User can send messages");
            }
            
            Ok(())
        }
        Err(e) => {
            eprintln!("Session validation failed: {}", e);
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_authentication_flow() {
        // This would require a test database
        // Placeholder for integration test
    }
}
