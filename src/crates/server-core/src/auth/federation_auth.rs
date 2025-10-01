//! Federation authentication with mutual TLS
//!
//! Implements T-S-F-04.02.01.02: Certificate-based federation authentication
//! Implements T-S-F-03.01.02.01: Mutual TLS for federation connections
//! Implements T-S-F-03.01.02.02: Certificate chain and revocation validation
//! Implements T-S-F-03.01.02.03: Certificate pinning

use crate::ServerError;
use norc_config::CertificatePinningConfig;
use norc_persistence::repositories::FederationRepository;
use norc_transport::{RevocationChecker, RevocationStatus};
use rustls::pki_types::CertificateDer;
use std::sync::Arc;
use tracing::{error, info, warn};
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
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
            _ => Err(ServerError::Config(
                norc_config::ConfigError::Validation(format!("Invalid trust level: {}", s))
            )),
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
    /// Certificate revocation checker
    revocation_checker: Option<Arc<RevocationChecker>>,
    /// Certificate pinning configuration
    pinning_config: Option<CertificatePinningConfig>,
    /// Pinned certificate fingerprints (SHA-256)
    pinned_fingerprints: Vec<Vec<u8>>,
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
            revocation_checker: None,
            pinning_config: None,
            pinned_fingerprints: Vec::new(),
        }
    }

    /// Create a new federation authenticator with revocation checking
    pub fn with_revocation_checker(
        mut self,
        checker: Arc<RevocationChecker>,
    ) -> Self {
        self.revocation_checker = Some(checker);
        self
    }

    /// Configure certificate pinning
    pub fn with_pinning(
        mut self,
        pinning_config: CertificatePinningConfig,
        pinned_fingerprints: Vec<Vec<u8>>,
    ) -> Self {
        self.pinning_config = Some(pinning_config);
        self.pinned_fingerprints = pinned_fingerprints;
        self
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

        // Step 1: Check certificate pinning if enabled
        if let Some(ref pinning_config) = self.pinning_config {
            if pinning_config.enabled {
                self.verify_certificate_pinning(&credentials.certificate_chain[0])?;
            }
        }

        // Step 2: Validate certificate chain
        self.validate_certificate_chain(&credentials.certificate_chain)?;

        // Step 3: Extract organization ID from certificate using utility
        let cert_org_id = norc_transport::tls_config::extract_organization_id(
            &credentials.certificate_chain[0]
        ).map_err(|e| {
            error!("Failed to extract organization ID: {}", e);
            ServerError::Unauthorized("Invalid certificate: no organization ID".to_string())
        })?;

        // Step 4: Verify organization ID matches
        if cert_org_id != credentials.organization_id {
            warn!(
                "Organization ID mismatch: cert={}, claimed={}",
                cert_org_id, credentials.organization_id
            );
            return Err(ServerError::Unauthorized(
                "Organization ID mismatch".to_string(),
            ));
        }

        info!(
            "Certificate organization ID validated: {}",
            cert_org_id
        );

                // Step 1: Look up federation trust
        let trust = self
            .federation_repo
            .find_by_organization(&credentials.organization_id)
            .await
            .map_err(|e| {
                warn!(
                    "Federation authentication failed: organization not found: {}",
                    credentials.organization_id
                );
                ServerError::Unauthorized(format!("Federation trust not found: {}", e))
            })?;

        // Step 5: Verify partner is active
        if trust.status != "active" {
            warn!(
                "Federation partner is inactive: {}",
                credentials.organization_id
            );
            return Err(ServerError::Unauthorized(
                "Federation partner is inactive".to_string(),
            ));
        }

        // Step 6: Verify trust level
        let trust_level = TrustLevel::from_str(&trust.trust_level)?;
        if trust_level == TrustLevel::None {
            warn!(
                "Federation partner has no trust: {}",
                credentials.organization_id
            );
            return Err(ServerError::Unauthorized(
                "No trust relationship".to_string(),
            ));
        }

        // Step 7: Check certificate revocation (OCSP/CRL) using RevocationChecker
        if self.strict_validation && self.revocation_checker.is_some() {
            self.check_revocation_with_checker(&credentials.certificate_chain).await?;
        }

        info!(
            "Federation partner authenticated: {} (trust: {:?})",
            credentials.organization_id, trust_level
        );

        // Create a device ID from the organization ID hash
        let org_hash = blake3::hash(credentials.organization_id.as_bytes());
        let device_id = norc_protocol::types::DeviceId::new(*org_hash.as_bytes());

        Ok(super::AuthResult {
            device_id,
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
        let timestamp = now.duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        
        let asn1_time = ASN1Time::from_timestamp(timestamp)
            .map_err(|e| ServerError::CryptoError(format!("Invalid timestamp: {}", e)))?;
        
        if !leaf_cert.validity().is_valid_at(asn1_time) {
            warn!("Certificate is not valid at current time");
            return Err(ServerError::Unauthorized(
                "Certificate expired or not yet valid".to_string(),
            ));
        }

        // Step 2: Check key usage
        match leaf_cert.key_usage() {
            Ok(Some(key_usage)) => {
                if !key_usage.value.digital_signature() {
                    warn!("Certificate does not have digital signature key usage");
                    return Err(ServerError::Unauthorized(
                        "Invalid key usage".to_string(),
                    ));
                }
            }
            Ok(None) => {
                // Key usage extension not present - acceptable for some certs
            }
            Err(e) => {
                warn!("Failed to parse key usage extension: {}", e);
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



    /// Verify certificate pinning
    fn verify_certificate_pinning(&self, cert_der: &[u8]) -> Result<(), ServerError> {
        if self.pinned_fingerprints.is_empty() {
            // No pins configured, skip verification
            return Ok(());
        }

        // Convert to CertificateDer for fingerprint computation
        let cert = CertificateDer::from(cert_der.to_vec());
        
        // Use transport utility to verify pin
        if norc_transport::tls_config::verify_certificate_pin(&cert, &self.pinned_fingerprints) {
            info!("Certificate pin verification successful");
            Ok(())
        } else {
            let pinning_mode = self.pinning_config.as_ref()
                .map(|c| c.mode.as_str())
                .unwrap_or("strict");

            if pinning_mode == "strict" {
                error!("Certificate pin verification failed in strict mode");
                Err(ServerError::Unauthorized(
                    "Certificate does not match any pinned fingerprints".to_string(),
                ))
            } else {
                warn!("Certificate pin verification failed in relaxed mode - allowing connection");
                Ok(())
            }
        }
    }

    /// Check certificate revocation using RevocationChecker
    async fn check_revocation_with_checker(&self, chain: &[Vec<u8>]) -> Result<(), ServerError> {
        let checker = self.revocation_checker.as_ref()
            .ok_or_else(|| ServerError::Config(
                norc_config::ConfigError::Validation("Revocation checker not configured".to_string())
            ))?;

        if chain.is_empty() {
            return Err(ServerError::Unauthorized("Empty certificate chain".to_string()));
        }

        // Convert to CertificateDer
        let cert = CertificateDer::from(chain[0].clone());
        let issuer = if chain.len() > 1 {
            Some(CertificateDer::from(chain[1].clone()))
        } else {
            None
        };

        info!("Checking certificate revocation status");

        // Check revocation status
        match checker.check_revocation(&cert, issuer.as_ref()).await {
            Ok(RevocationStatus::Valid) => {
                info!("Certificate revocation check passed: certificate is valid");
                Ok(())
            }
            Ok(RevocationStatus::Revoked) => {
                error!("Certificate has been revoked");
                Err(ServerError::Unauthorized(
                    "Certificate has been revoked".to_string(),
                ))
            }
            Ok(RevocationStatus::Unknown) => {
                warn!("Certificate revocation status unknown");
                // Fail-open or fail-closed based on configuration
                if self.strict_validation {
                    Err(ServerError::Unauthorized(
                        "Cannot verify certificate revocation status".to_string(),
                    ))
                } else {
                    warn!("Allowing connection despite unknown revocation status");
                    Ok(())
                }
            }
            Err(e) => {
                error!("Revocation check failed: {}", e);
                if self.strict_validation {
                    Err(ServerError::CryptoError(format!("Revocation check failed: {}", e)))
                } else {
                    warn!("Revocation check failed but continuing in non-strict mode");
                    Ok(())
                }
            }
        }
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
