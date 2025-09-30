//! Federation authentication with mutual TLS
//!
//! Implements T-S-F-04.02.01.02: Certificate-based federation authentication
//! Implements T-S-F-03.01.02.01: Mutual TLS for federation connections

use crate::ServerError;
use norc_persistence::repositories::FederationRepository;
use std::sync::Arc;
use tracing::{info, warn, error};
use x509_parser::prelude::*;

/// Federation credentials for authentication
#[derive(Debug, Clone)]
pub struct FederationCredentials {
    /// Organization ID from certificate
    pub organization_id: String,
    /// Certificate chain (DER encoded)
    pub certificate_chain: Vec<Vec<u8>>,
    /// Client IP address
    pub client_ip: String,
    /// Server Name Indication (SNI) from TLS handshake
    pub sni_hostname: Option<String>,
}

/// Federation authentication result
#[derive(Debug, Clone)]
pub struct FederationAuthResult {
    /// Organization ID
    pub organization_id: String,
    /// Trust level
    pub trust_level: TrustLevel,
    /// Verified certificate subject
    pub certificate_subject: String,
}

/// Trust levels for federation partners
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustLevel {
    /// No trust - reject all communication
    None,
    /// Basic trust - allow minimal functionality
    Basic,
    /// Standard trust - normal federation operations
    Standard,
    /// Enhanced trust - full functionality with minimal restrictions
    Enhanced,
    /// Full trust - complete access (same organization)
    Full,
}

impl TrustLevel {
    /// Parse from string
    pub fn from_str(s: &str) -> Result<Self, ServerError> {
        match s.to_lowercase().as_str() {
            "none" => Ok(Self::None),
            "basic" => Ok(Self::Basic),
            "standard" => Ok(Self::Standard),
            "enhanced" => Ok(Self::Enhanced),
            "full" => Ok(Self::Full),
            _ => Err(ServerError::Config(format!("Invalid trust level: {}", s))),
        }
    }
}

/// Federation authenticator
pub struct FederationAuthenticator {
    federation_repo: Arc<FederationRepository>,
    /// Trusted CA certificates for federation (DER encoded)
    trusted_cas: Vec<Vec<u8>>,
    /// Enable strict certificate validation
    strict_validation: bool,
}

impl FederationAuthenticator {
    /// Create a new federation authenticator
    pub fn new(
        federation_repo: Arc<FederationRepository>,
        trusted_cas: Vec<Vec<u8>>,
        strict_validation: bool,
    ) -> Self {
        Self {
            federation_repo,
            trusted_cas,
            strict_validation,
        }
    }

    /// Authenticate a federation partner using mutual TLS
    pub async fn authenticate(
        &self,
        credentials: FederationCredentials,
    ) -> Result<super::AuthResult, ServerError> {
        info!(
            "Authenticating federation partner: {}",
            credentials.organization_id
        );

        // Step 1: Validate certificate chain
        self.validate_certificate_chain(&credentials.certificate_chain)?;

        // Step 2: Extract organization ID from certificate
        let cert_org_id = self.extract_organization_id(&credentials.certificate_chain[0])?;

        // Step 3: Verify organization ID matches
        if cert_org_id != credentials.organization_id {
            warn!(
                "Organization ID mismatch: cert={}, claimed={}",
                cert_org_id, credentials.organization_id
            );
            return Err(ServerError::Unauthorized(
                "Organization ID mismatch".to_string(),
            ));
        }

        // Step 4: Check if federation partner is registered
        let partner = self
            .federation_repo
            .get_by_organization_id(&credentials.organization_id)
            .await
            .map_err(|e| {
                warn!(
                    "Federation partner not found: {}",
                    credentials.organization_id
                );
                ServerError::Unauthorized(format!("Unknown federation partner: {}", e))
            })?;

        // Step 5: Verify partner is active
        if !partner.is_active {
            warn!(
                "Federation partner is inactive: {}",
                credentials.organization_id
            );
            return Err(ServerError::Unauthorized(
                "Federation partner is inactive".to_string(),
            ));
        }

        // Step 6: Verify trust level
        let trust_level = TrustLevel::from_str(&partner.trust_level)?;
        if trust_level == TrustLevel::None {
            warn!(
                "Federation partner has no trust: {}",
                credentials.organization_id
            );
            return Err(ServerError::Unauthorized(
                "No trust relationship".to_string(),
            ));
        }

        // Step 7: Check certificate revocation (OCSP/CRL)
        if self.strict_validation {
            self.check_revocation(&credentials.certificate_chain).await?;
        }

        info!(
            "Federation partner authenticated: {} (trust: {:?})",
            credentials.organization_id, trust_level
        );

        Ok(super::AuthResult {
            device_id: norc_protocol::types::DeviceId::new(format!(
                "federation:{}",
                credentials.organization_id
            )),
            session_token: super::SessionToken::generate(),
            role: super::Role::FederationPartner(trust_level),
            authenticated_at: chrono::Utc::now(),
        })
    }

    /// Validate certificate chain
    fn validate_certificate_chain(&self, chain: &[Vec<u8>]) -> Result<(), ServerError> {
        if chain.is_empty() {
            return Err(ServerError::Unauthorized(
                "Empty certificate chain".to_string(),
            ));
        }

        // Parse leaf certificate
        let (_, leaf_cert) = X509Certificate::from_der(&chain[0]).map_err(|e| {
            error!("Failed to parse leaf certificate: {}", e);
            ServerError::CryptoError(format!("Invalid certificate: {}", e))
        })?;

        // Step 1: Check certificate validity period
        let now = std::time::SystemTime::now();
        if !leaf_cert.validity().is_valid_at(ASN1Time::from_timestamp(
            now.duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
        )) {
            warn!("Certificate is not valid at current time");
            return Err(ServerError::Unauthorized(
                "Certificate expired or not yet valid".to_string(),
            ));
        }

        // Step 2: Check key usage
        if let Some(key_usage) = leaf_cert.key_usage() {
            if !key_usage.value.digital_signature() {
                warn!("Certificate does not have digital signature key usage");
                return Err(ServerError::Unauthorized(
                    "Invalid key usage".to_string(),
                ));
            }
        }

        // Step 3: Verify certificate chain against trusted CAs
        if !self.trusted_cas.is_empty() {
            self.verify_against_trusted_cas(chain)?;
        }

        Ok(())
    }

    /// Verify certificate chain against trusted CAs
    fn verify_against_trusted_cas(&self, chain: &[Vec<u8>]) -> Result<(), ServerError> {
        // For now, just check that at least one CA in the chain matches a trusted CA
        // In a full implementation, this would perform complete chain validation
        
        for cert_der in chain.iter().skip(1) {
            for trusted_ca_der in &self.trusted_cas {
                if cert_der == trusted_ca_der {
                    return Ok(());
                }
            }
        }

        if self.strict_validation {
            warn!("No trusted CA found in certificate chain");
            Err(ServerError::Unauthorized(
                "Certificate not issued by trusted CA".to_string(),
            ))
        } else {
            // In non-strict mode, allow if we have any chain
            Ok(())
        }
    }

    /// Extract organization ID from certificate
    fn extract_organization_id(&self, cert_der: &[u8]) -> Result<String, ServerError> {
        let (_, cert) = X509Certificate::from_der(cert_der).map_err(|e| {
            ServerError::CryptoError(format!("Failed to parse certificate: {}", e))
        })?;

        // Try to get organization from subject
        for attr in cert.subject().iter_organization() {
            if let Ok(org) = attr.as_str() {
                return Ok(org.to_string());
            }
        }

        // Try to get from subject alternative names
        if let Some(san_ext) = cert.get_extension_unique(&oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME)? {
            // Parse SAN extension for organization ID
            // This is a simplified implementation
        }

        Err(ServerError::Unauthorized(
            "No organization ID in certificate".to_string(),
        ))
    }

    /// Check certificate revocation status (OCSP/CRL)
    async fn check_revocation(&self, _chain: &[Vec<u8>]) -> Result<(), ServerError> {
        // TODO: Implement OCSP checking (T-S-F-03.01.02.02)
        // This is a placeholder for the full implementation
        
        // Steps for full implementation:
        // 1. Extract OCSP responder URL from certificate
        // 2. Build OCSP request
        // 3. Send request to OCSP responder
        // 4. Validate OCSP response signature
        // 5. Check revocation status
        // 6. If OCSP fails, fall back to CRL checking
        
        warn!("Certificate revocation checking not yet implemented (OCSP/CRL)");
        Ok(())
    }

    /// Add a trusted CA certificate
    pub fn add_trusted_ca(&mut self, ca_cert_der: Vec<u8>) -> Result<(), ServerError> {
        // Validate it's a valid certificate
        let (_, _cert) = X509Certificate::from_der(&ca_cert_der).map_err(|e| {
            ServerError::CryptoError(format!("Invalid CA certificate: {}", e))
        })?;

        self.trusted_cas.push(ca_cert_der);
        info!("Added trusted CA certificate");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trust_level_parsing() {
        assert_eq!(TrustLevel::from_str("basic").unwrap(), TrustLevel::Basic);
        assert_eq!(TrustLevel::from_str("STANDARD").unwrap(), TrustLevel::Standard);
        assert!(TrustLevel::from_str("invalid").is_err());
    }
}
