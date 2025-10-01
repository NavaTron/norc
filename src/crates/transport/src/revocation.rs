//! Certificate revocation checking via OCSP and CRL
//! Implements SERVER_REQUIREMENTS T-S-F-03.01.02.02 (Certificate chain and revocation validation)

use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tracing::{debug, error, info, warn};
use x509_parser::prelude::*;
use rustls::pki_types::CertificateDer;

/// Certificate revocation check error
#[derive(Debug, Error)]
pub enum RevocationError {
    #[error("HTTP request error: {0}")]
    HttpError(#[from] reqwest::Error),
    
    #[error("Certificate parse error: {0}")]
    ParseError(String),
    
    #[error("OCSP response error: {0}")]
    OcspError(String),
    
    #[error("CRL parse error: {0}")]
    CrlError(String),
    
    #[error("Certificate is revoked")]
    CertificateRevoked,
    
    #[error("Revocation status unknown")]
    StatusUnknown,
    
    #[error("No revocation information available")]
    NoRevocationInfo,
}

/// Certificate revocation status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationStatus {
    /// Certificate is valid (not revoked)
    Valid,
    /// Certificate has been revoked
    Revoked,
    /// Revocation status cannot be determined
    Unknown,
}

/// Configuration for certificate revocation checking
#[derive(Debug, Clone)]
pub struct RevocationConfig {
    /// Enable OCSP checking
    pub enable_ocsp: bool,
    /// Enable CRL checking
    pub enable_crl: bool,
    /// Timeout for OCSP/CRL requests
    pub timeout: Duration,
    /// Maximum CRL size to download (bytes)
    pub max_crl_size: usize,
    /// Whether to fail if revocation status is unknown
    pub fail_on_unknown: bool,
    /// Cache duration for OCSP responses
    pub ocsp_cache_duration: Duration,
    /// Cache duration for CRLs
    pub crl_cache_duration: Duration,
}

impl Default for RevocationConfig {
    fn default() -> Self {
        Self {
            enable_ocsp: true,
            enable_crl: true,
            timeout: Duration::from_secs(10),
            max_crl_size: 10 * 1024 * 1024, // 10 MB
            fail_on_unknown: false,
            ocsp_cache_duration: Duration::from_secs(3600), // 1 hour
            crl_cache_duration: Duration::from_secs(86400), // 24 hours
        }
    }
}

/// Certificate revocation checker
pub struct RevocationChecker {
    config: RevocationConfig,
    http_client: reqwest::Client,
}

impl RevocationChecker {
    /// Create a new revocation checker with the given configuration
    pub fn new(config: RevocationConfig) -> Result<Self, RevocationError> {
        let http_client = reqwest::Client::builder()
            .timeout(config.timeout)
            .build()?;
        
        Ok(Self {
            config,
            http_client,
        })
    }

    /// Check the revocation status of a certificate
    /// 
    /// This method will:
    /// 1. Try OCSP if enabled and available
    /// 2. Fall back to CRL if OCSP fails or is not available
    /// 3. Return Unknown if neither method is available or both fail
    pub async fn check_revocation<'a>(
        &self,
        cert: &'a CertificateDer<'a>,
        issuer: Option<&'a CertificateDer<'a>>,
    ) -> Result<RevocationStatus, RevocationError> {
        let parsed_cert = self.parse_certificate(cert)?;
        
        // Try OCSP first
        if self.config.enable_ocsp {
            match self.check_ocsp(&parsed_cert, issuer).await {
                Ok(status) => {
                    info!("OCSP check succeeded: {:?}", status);
                    return Ok(status);
                }
                Err(e) => {
                    warn!("OCSP check failed, will try CRL: {}", e);
                }
            }
        }
        
        // Fall back to CRL
        if self.config.enable_crl {
            match self.check_crl(&parsed_cert).await {
                Ok(status) => {
                    info!("CRL check succeeded: {:?}", status);
                    return Ok(status);
                }
                Err(e) => {
                    warn!("CRL check failed: {}", e);
                }
            }
        }
        
        // Neither method succeeded
        if self.config.fail_on_unknown {
            Err(RevocationError::StatusUnknown)
        } else {
            warn!("Unable to verify revocation status, treating as valid");
            Ok(RevocationStatus::Unknown)
        }
    }

    /// Parse a DER-encoded certificate
    fn parse_certificate<'a>(&self, cert: &'a CertificateDer) -> Result<X509Certificate<'a>, RevocationError> {
        let (_, parsed) = X509Certificate::from_der(cert.as_ref())
            .map_err(|e| RevocationError::ParseError(format!("Failed to parse certificate: {}", e)))?;
        Ok(parsed)
    }

    /// Check certificate revocation via OCSP
    async fn check_ocsp<'a>(
        &self,
        cert: &X509Certificate<'_>,
        _issuer: Option<&'a CertificateDer<'a>>,
    ) -> Result<RevocationStatus, RevocationError> {
        // Extract OCSP responder URL from certificate
        let ocsp_url = self.extract_ocsp_url(cert)?;
        
        debug!("OCSP responder URL: {}", ocsp_url);
        
        // TODO: Implement OCSP request/response handling
        // This requires:
        // 1. Build OCSP request with cert serial number and issuer info
        // 2. Send HTTP POST to OCSP responder
        // 3. Parse and validate OCSP response
        // 4. Check response signature
        // 5. Return revocation status
        
        warn!("OCSP checking not yet fully implemented");
        Err(RevocationError::OcspError("Not implemented".to_string()))
    }

    /// Check certificate revocation via CRL
    async fn check_crl(&self, cert: &X509Certificate<'_>) -> Result<RevocationStatus, RevocationError> {
        // Extract CRL distribution point URLs from certificate
        let crl_urls = self.extract_crl_urls(cert)?;
        
        if crl_urls.is_empty() {
            return Err(RevocationError::NoRevocationInfo);
        }
        
        // Try each CRL URL until one succeeds
        for url in &crl_urls {
            debug!("Downloading CRL from: {}", url);
            
            match self.download_and_check_crl(url, cert).await {
                Ok(status) => return Ok(status),
                Err(e) => {
                    warn!("CRL check failed for {}: {}", url, e);
                    continue;
                }
            }
        }
        
        Err(RevocationError::CrlError("All CRL URLs failed".to_string()))
    }

    /// Download and check a CRL
    async fn download_and_check_crl(
        &self,
        url: &str,
        cert: &X509Certificate<'_>,
    ) -> Result<RevocationStatus, RevocationError> {
        // Download CRL with size limit
        let response = self.http_client
            .get(url)
            .send()
            .await?;
        
        if !response.status().is_success() {
            return Err(RevocationError::CrlError(
                format!("HTTP error: {}", response.status())
            ));
        }
        
        // Check content length
        if let Some(length) = response.content_length() {
            if length > self.config.max_crl_size as u64 {
                return Err(RevocationError::CrlError(
                    format!("CRL too large: {} bytes", length)
                ));
            }
        }
        
        let crl_bytes = response.bytes().await?;
        
        if crl_bytes.len() > self.config.max_crl_size {
            return Err(RevocationError::CrlError(
                format!("CRL too large: {} bytes", crl_bytes.len())
            ));
        }
        
        debug!("Downloaded CRL: {} bytes", crl_bytes.len());
        
        // Parse and check CRL
        self.check_crl_for_cert(&crl_bytes, cert)
    }

    /// Check if certificate is revoked in the given CRL
    fn check_crl_for_cert(
        &self,
        crl_bytes: &[u8],
        cert: &X509Certificate<'_>,
    ) -> Result<RevocationStatus, RevocationError> {
        use x509_parser::revocation_list::*;
        
        let (_, crl) = CertificateRevocationList::from_der(crl_bytes)
            .map_err(|e| RevocationError::CrlError(format!("Failed to parse CRL: {}", e)))?;
        
        // Get certificate serial number
        let cert_serial = &cert.serial;
        
        debug!("Checking CRL for certificate serial: {}", cert_serial);
        
        // Check if certificate is in the revoked list
        for revoked_cert in crl.iter_revoked_certificates() {
            let revoked_serial = revoked_cert.raw_serial();
            let cert_serial_bytes = cert_serial.to_bytes_be();
            
            if revoked_serial == cert_serial_bytes.as_slice() {
                error!("Certificate is revoked (serial: {})", cert_serial);
                return Ok(RevocationStatus::Revoked);
            }
        }
        
        debug!("Certificate not found in CRL (serial: {})", cert_serial);
        Ok(RevocationStatus::Valid)
    }

    /// Extract OCSP responder URL from certificate
    fn extract_ocsp_url(&self, cert: &X509Certificate<'_>) -> Result<String, RevocationError> {
        // Look for Authority Information Access extension
        for ext in cert.extensions() {
            if ext.oid == x509_parser::oid_registry::OID_PKIX_AUTHORITY_INFO_ACCESS {
                // Parse AIA extension to extract OCSP URL
                // This is simplified - actual implementation needs proper ASN.1 parsing
                let value = ext.value;
                if let Ok(s) = std::str::from_utf8(value) {
                    // Very naive parsing - look for http:// or https://
                    if let Some(start) = s.find("http") {
                        if let Some(end) = s[start..].find(|c: char| c.is_ascii_control() || c == '\0') {
                            let url = &s[start..start + end];
                            return Ok(url.to_string());
                        }
                    }
                }
            }
        }
        
        Err(RevocationError::NoRevocationInfo)
    }

    /// Extract CRL distribution point URLs from certificate
    fn extract_crl_urls(&self, cert: &X509Certificate<'_>) -> Result<Vec<String>, RevocationError> {
        let mut urls = Vec::new();
        
        // Look for CRL Distribution Points extension
        for ext in cert.extensions() {
            if ext.oid == x509_parser::oid_registry::OID_X509_EXT_CRL_DISTRIBUTION_POINTS {
                // Parse CRL distribution points extension
                // This is simplified - actual implementation needs proper ASN.1 parsing
                let value = ext.value;
                if let Ok(s) = std::str::from_utf8(value) {
                    // Very naive parsing - look for http:// or https://
                    let mut start_pos = 0;
                    while let Some(start) = s[start_pos..].find("http") {
                        let start = start_pos + start;
                        if let Some(end) = s[start..].find(|c: char| c.is_ascii_control() || c == '\0' || c == ' ') {
                            let url = &s[start..start + end];
                            urls.push(url.to_string());
                            start_pos = start + end;
                        } else {
                            break;
                        }
                    }
                }
            }
        }
        
        if urls.is_empty() {
            return Err(RevocationError::NoRevocationInfo);
        }
        
        Ok(urls)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_revocation_checker_creation() {
        let config = RevocationConfig::default();
        let checker = RevocationChecker::new(config);
        assert!(checker.is_ok());
    }

    // TODO: Add more tests with mock certificates and CRLs
}
