//! Message Input Validation
//!
//! Validates and sanitizes all incoming messages per E-04 requirements.
//! Prevents injection attacks, oversized messages, and malformed data.

use norc_protocol::{DeviceId, MessageId};
use thiserror::Error;

/// Validation error types
#[derive(Debug, Error, Clone)]
pub enum ValidationError {
    #[error("Message too large: {0} bytes (max: {1})")]
    MessageTooLarge(usize, usize),

    #[error("Invalid device ID: {0}")]
    InvalidDeviceId(String),

    #[error("Invalid message ID: {0}")]
    InvalidMessageId(String),

    #[error("Invalid timestamp: {0}")]
    InvalidTimestamp(String),

    #[error("Missing required field: {0}")]
    MissingField(String),

    #[error("Invalid field format: {0}")]
    InvalidFormat(String),

    #[error("Protocol version mismatch: {0}")]
    ProtocolVersionMismatch(String),

    #[error("Payload exceeds limit: {0} bytes")]
    PayloadTooLarge(usize),

    #[error("Invalid encryption nonce")]
    InvalidNonce,

    #[error("Invalid signature")]
    InvalidSignature,
}

/// Message validator
pub struct MessageValidator {
    max_message_size: usize,
    max_payload_size: usize,
    max_recipients: usize,
}

impl MessageValidator {
    /// Create a new validator with custom limits
    pub fn new(max_message_size: usize, max_payload_size: usize, max_recipients: usize) -> Self {
        Self {
            max_message_size,
            max_payload_size,
            max_recipients,
        }
    }

    /// Create with default limits
    pub fn with_defaults() -> Self {
        Self {
            max_message_size: 16 * 1024 * 1024, // 16 MB
            max_payload_size: 15 * 1024 * 1024, // 15 MB (leave room for metadata)
            max_recipients: 1000,               // Max 1000 recipients
        }
    }

    /// Validate message size
    pub fn validate_size(&self, size: usize) -> Result<(), ValidationError> {
        if size > self.max_message_size {
            return Err(ValidationError::MessageTooLarge(
                size,
                self.max_message_size,
            ));
        }
        Ok(())
    }

    /// Validate payload size
    pub fn validate_payload_size(&self, size: usize) -> Result<(), ValidationError> {
        if size > self.max_payload_size {
            return Err(ValidationError::PayloadTooLarge(size));
        }
        Ok(())
    }

    /// Validate device ID format
    pub fn validate_device_id(&self, device_id: &DeviceId) -> Result<(), ValidationError> {
        let id_str = format!("{:?}", device_id);

        // Check if empty
        if id_str.is_empty() {
            return Err(ValidationError::InvalidDeviceId(
                "Device ID cannot be empty".to_string(),
            ));
        }

        // Check length (reasonable limit)
        if id_str.len() > 256 {
            return Err(ValidationError::InvalidDeviceId(
                "Device ID too long".to_string(),
            ));
        }

        Ok(())
    }

    /// Validate message ID format
    pub fn validate_message_id(&self, message_id: &MessageId) -> Result<(), ValidationError> {
        let id_str = format!("{:?}", message_id);

        // Check if empty
        if id_str.is_empty() {
            return Err(ValidationError::InvalidMessageId(
                "Message ID cannot be empty".to_string(),
            ));
        }

        Ok(())
    }

    /// Validate timestamp (not too far in past or future)
    pub fn validate_timestamp(&self, timestamp: u64) -> Result<(), ValidationError> {
        use std::time::{SystemTime, UNIX_EPOCH};

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Allow 5 minutes clock skew in either direction
        let max_skew = 300;

        if timestamp > now + max_skew {
            return Err(ValidationError::InvalidTimestamp(
                "Timestamp too far in future".to_string(),
            ));
        }

        if timestamp < now.saturating_sub(86400) {
            // Messages older than 24 hours
            return Err(ValidationError::InvalidTimestamp(
                "Timestamp too old".to_string(),
            ));
        }

        Ok(())
    }

    /// Validate nonce (should be 12 bytes for ChaCha20-Poly1305)
    pub fn validate_nonce(&self, nonce: &[u8]) -> Result<(), ValidationError> {
        if nonce.len() != 12 {
            return Err(ValidationError::InvalidNonce);
        }
        Ok(())
    }

    /// Validate signature (should be 64 bytes for Ed25519)
    pub fn validate_signature(&self, signature: &[u8]) -> Result<(), ValidationError> {
        if signature.len() != 64 {
            return Err(ValidationError::InvalidSignature);
        }
        Ok(())
    }

    /// Validate recipient count
    pub fn validate_recipient_count(&self, count: usize) -> Result<(), ValidationError> {
        if count == 0 {
            return Err(ValidationError::MissingField(
                "At least one recipient required".to_string(),
            ));
        }

        if count > self.max_recipients {
            return Err(ValidationError::InvalidFormat(format!(
                "Too many recipients: {} (max: {})",
                count, self.max_recipients
            )));
        }

        Ok(())
    }

    /// Sanitize string input (remove control characters, limit length)
    pub fn sanitize_string(&self, input: &str, max_length: usize) -> String {
        input
            .chars()
            .filter(|c| !c.is_control() || c.is_whitespace())
            .take(max_length)
            .collect()
    }

    /// Validate protocol version
    pub fn validate_protocol_version(&self, major: u8, minor: u8) -> Result<(), ValidationError> {
        // Currently support version 1.x only
        if major != 1 {
            return Err(ValidationError::ProtocolVersionMismatch(format!(
                "Unsupported major version: {}",
                major
            )));
        }

        // Support minor versions 0-9
        if minor > 9 {
            return Err(ValidationError::ProtocolVersionMismatch(format!(
                "Unsupported minor version: {}",
                minor
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_size() {
        let validator = MessageValidator::with_defaults();

        assert!(validator.validate_size(1000).is_ok());
        assert!(validator.validate_size(16 * 1024 * 1024).is_ok());
        assert!(validator.validate_size(17 * 1024 * 1024).is_err());
    }

    #[test]
    fn test_validate_payload_size() {
        let validator = MessageValidator::with_defaults();

        assert!(validator.validate_payload_size(1000).is_ok());
        assert!(validator.validate_payload_size(15 * 1024 * 1024).is_ok());
        assert!(validator.validate_payload_size(16 * 1024 * 1024).is_err());
    }

    #[test]
    fn test_validate_timestamp() {
        let validator = MessageValidator::with_defaults();

        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Current time should be valid
        assert!(validator.validate_timestamp(now).is_ok());

        // 1 minute in future should be valid
        assert!(validator.validate_timestamp(now + 60).is_ok());

        // 10 minutes in future should be invalid
        assert!(validator.validate_timestamp(now + 600).is_err());

        // 1 hour ago should be valid
        assert!(validator.validate_timestamp(now - 3600).is_ok());

        // 2 days ago should be invalid
        assert!(validator.validate_timestamp(now - 172800).is_err());
    }

    #[test]
    fn test_validate_nonce() {
        let validator = MessageValidator::with_defaults();

        let valid_nonce = vec![0u8; 12];
        assert!(validator.validate_nonce(&valid_nonce).is_ok());

        let invalid_nonce = vec![0u8; 10];
        assert!(validator.validate_nonce(&invalid_nonce).is_err());
    }

    #[test]
    fn test_validate_signature() {
        let validator = MessageValidator::with_defaults();

        let valid_sig = vec![0u8; 64];
        assert!(validator.validate_signature(&valid_sig).is_ok());

        let invalid_sig = vec![0u8; 32];
        assert!(validator.validate_signature(&invalid_sig).is_err());
    }

    #[test]
    fn test_validate_recipient_count() {
        let validator = MessageValidator::with_defaults();

        assert!(validator.validate_recipient_count(0).is_err());
        assert!(validator.validate_recipient_count(1).is_ok());
        assert!(validator.validate_recipient_count(1000).is_ok());
        assert!(validator.validate_recipient_count(1001).is_err());
    }

    #[test]
    fn test_sanitize_string() {
        let validator = MessageValidator::with_defaults();

        // Remove control characters
        let input = "Hello\x00World\x01Test";
        let sanitized = validator.sanitize_string(input, 100);
        assert_eq!(sanitized, "HelloWorldTest");

        // Preserve whitespace
        let input = "Hello World\tTest\n";
        let sanitized = validator.sanitize_string(input, 100);
        assert_eq!(sanitized, "Hello World\tTest\n");

        // Truncate to max length
        let input = "a".repeat(200);
        let sanitized = validator.sanitize_string(&input, 50);
        assert_eq!(sanitized.len(), 50);
    }

    #[test]
    fn test_validate_protocol_version() {
        let validator = MessageValidator::with_defaults();

        assert!(validator.validate_protocol_version(1, 0).is_ok());
        assert!(validator.validate_protocol_version(1, 5).is_ok());
        assert!(validator.validate_protocol_version(1, 9).is_ok());
        assert!(validator.validate_protocol_version(1, 10).is_err());
        assert!(validator.validate_protocol_version(2, 0).is_err());
    }
}
