//! Device-based authentication
//!
//! Implements T-S-F-04.02.01.01: Device client authentication

use crate::ServerError;
use norc_persistence::repositories::DeviceRepository;
use norc_protocol::types::{DeviceId, PublicKey, Signature};
use std::sync::Arc;
use tracing::{info, warn};

/// Device credentials for authentication
#[derive(Debug, Clone)]
pub struct DeviceCredentials {
    /// Device ID
    pub device_id: DeviceId,
    /// Device public key
    pub public_key: PublicKey,
    /// Challenge signature
    pub signature: Signature,
    /// Challenge nonce (to prevent replay attacks)
    pub nonce: Vec<u8>,
    /// Client IP address (for rate limiting)
    pub client_ip: String,
}

/// Device authentication result
#[derive(Debug, Clone)]
pub struct DeviceAuthResult {
    /// Device ID
    pub device_id: DeviceId,
    /// User ID (if device is registered to a user)
    pub user_id: Option<String>,
    /// Organization ID (not currently stored in Device model)
    pub organization_id: Option<String>,
    /// Assigned role
    pub role: super::Role,
}

/// Device authenticator
pub struct DeviceAuthenticator {
    device_repo: Arc<DeviceRepository>,
}

impl DeviceAuthenticator {
    /// Create a new device authenticator
    pub fn new(device_repo: Arc<DeviceRepository>) -> Self {
        Self { device_repo }
    }

    /// Authenticate a device using certificate-based authentication
    pub async fn authenticate(
        &self,
        credentials: DeviceCredentials,
    ) -> Result<DeviceAuthResult, ServerError> {
        // Convert DeviceId to string (hex representation)
        let device_id_str = hex::encode(credentials.device_id.as_bytes());

        // Step 1: Retrieve device from database
        let device = self
            .device_repo
            .find_by_id(&device_id_str)
            .await
            .map_err(|e| {
                warn!(
                    "Device authentication failed: device not found: {:?}",
                    credentials.device_id
                );
                ServerError::Unauthorized(format!("Device not found: {}", e))
            })?;

        // Step 2: Verify device is active
        if device.status != "active" {
            warn!(
                "Device authentication failed: device is inactive: {:?}",
                credentials.device_id
            );
            return Err(ServerError::Unauthorized(
                "Device is inactive or revoked".to_string(),
            ));
        }

        // Step 3: Verify public key matches
        if device.public_key != credentials.public_key.0.to_vec() {
            warn!(
                "Device authentication failed: public key mismatch: {:?}",
                credentials.device_id
            );
            return Err(ServerError::Unauthorized("Public key mismatch".to_string()));
        }

        // Step 4: Verify signature on challenge nonce
        self.verify_challenge_signature(&credentials)?;

        // Step 5: Get user info
        let user = device.user_id.clone();

        info!(
            "Device authenticated successfully: {:?} (user: {})",
            credentials.device_id, user
        );

        // Step 6: Determine role based on device type and user
        let role = self.determine_role(&device).await?;

        Ok(DeviceAuthResult {
            device_id: credentials.device_id,
            user_id: Some(user),
            organization_id: None, // Device model doesn't have organization_id
            role,
        })
    }

    /// Verify the challenge signature
    fn verify_challenge_signature(
        &self,
        credentials: &DeviceCredentials,
    ) -> Result<(), ServerError> {
        // Reconstruct the challenge message
        let challenge_message =
            self.build_challenge_message(&credentials.device_id, &credentials.nonce);

        // Verify signature using Ed25519
        use ed25519_dalek::{Signature as Ed25519Sig, Verifier, VerifyingKey};

        let verifying_key = VerifyingKey::from_bytes(credentials.public_key.as_bytes())
            .map_err(|e| ServerError::CryptoError(format!("Invalid public key: {}", e)))?;

        let signature = Ed25519Sig::from_bytes(credentials.signature.as_bytes());

        verifying_key
            .verify(&challenge_message, &signature)
            .map_err(|e| {
                warn!("Challenge signature verification failed: {}", e);
                ServerError::Unauthorized("Invalid challenge signature".to_string())
            })?;

        Ok(())
    }

    /// Build challenge message for signing
    fn build_challenge_message(&self, device_id: &DeviceId, nonce: &[u8]) -> Vec<u8> {
        let mut message = Vec::new();
        message.extend_from_slice(b"NORC-DEVICE-AUTH:");
        message.extend_from_slice(device_id.as_bytes());
        message.extend_from_slice(b":");
        message.extend_from_slice(nonce);
        message
    }

    /// Determine role based on device properties
    async fn determine_role(
        &self,
        device: &norc_persistence::models::Device,
    ) -> Result<super::Role, ServerError> {
        // For now, all authenticated devices get the "User" role
        // In a full implementation, this would check device properties,
        // user roles, organization policies, etc.
        // Use device_type to potentially assign different roles
        match device.device_type.as_str() {
            "admin" => Ok(super::Role::SystemAdmin),
            _ => Ok(super::Role::User),
        }
    }

    /// Generate a challenge nonce for a device
    pub fn generate_challenge(&self, _device_id: &DeviceId) -> Vec<u8> {
        use rand::RngCore;
        let mut nonce = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce);

        // Store nonce with timestamp for validation
        // TODO: Implement nonce storage with expiration

        nonce
    }

    /// Register a new device (admin operation)
    pub async fn register_device(
        &self,
        device_id: DeviceId,
        public_key: PublicKey,
        user_id: String,
        device_name: String,
    ) -> Result<(), ServerError> {
        let device_id_str = hex::encode(device_id.as_bytes());

        self.device_repo
            .create(
                &device_id_str,
                &user_id,
                &device_name,
                "client", // device_type
                &public_key.0,
            )
            .await
            .map_err(|e| ServerError::Database(format!("Failed to register device: {}", e)))?;

        info!("Device registered successfully: {:?}", device_id);
        Ok(())
    }

    /// Revoke a device (admin operation)
    pub async fn revoke_device(&self, device_id: &DeviceId) -> Result<(), ServerError> {
        let device_id_str = hex::encode(device_id.as_bytes());

        self.device_repo
            .revoke(&device_id_str)
            .await
            .map_err(|e| ServerError::Database(format!("Failed to revoke device: {}", e)))?;

        info!("Device revoked: {:?}", device_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_device_id() -> DeviceId {
        DeviceId::new([0u8; 32])
    }

    #[test]
    fn test_device_credentials_creation() {
        let device_id = create_test_device_id();
        let public_key = PublicKey([0u8; 32]);
        let signature = Signature([0u8; 64]);

        let credentials = DeviceCredentials {
            device_id,
            public_key,
            signature,
            nonce: vec![1, 2, 3, 4],
            client_ip: "127.0.0.1".to_string(),
        };

        assert_eq!(credentials.nonce.len(), 4);
    }
}
