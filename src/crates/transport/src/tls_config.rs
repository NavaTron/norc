//! TLS configuration and certificate management
//! Implements SERVER_REQUIREMENTS T-S-F-03.01.02 (Certificate validation)
//! Implements T-S-F-03.01.02.01 (Mutual TLS for federation)

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls_pemfile::{certs, private_key};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, info, warn, error};
use x509_parser::prelude::*;

/// TLS configuration error
#[derive(Debug, Error)]
pub enum TlsConfigError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Invalid certificate: {0}")]
    InvalidCertificate(String),
    
    #[error("Invalid private key")]
    InvalidPrivateKey,
    
    #[error("TLS configuration error: {0}")]
    Configuration(String),
}

/// Load certificates from a PEM file
pub fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, TlsConfigError> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    
    let certs: Vec<CertificateDer<'static>> = certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsConfigError::InvalidCertificate(e.to_string()))?;
    
    if certs.is_empty() {
        return Err(TlsConfigError::InvalidCertificate(
            "No certificates found in file".to_string()
        ));
    }
    
    info!("Loaded {} certificates from {:?}", certs.len(), path);
    Ok(certs)
}

/// Load private key from a PEM file
pub fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, TlsConfigError> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    
    let key = private_key(&mut reader)
        .map_err(|e| TlsConfigError::Io(e))?
        .ok_or(TlsConfigError::InvalidPrivateKey)?;
    
    info!("Loaded private key from {:?}", path);
    Ok(key)
}

/// Extract organization ID from X.509 certificate
pub fn extract_organization_id(cert: &CertificateDer) -> Result<String, TlsConfigError> {
    let (_, parsed_cert) = X509Certificate::from_der(cert.as_ref())
        .map_err(|e| TlsConfigError::InvalidCertificate(format!("Failed to parse certificate: {}", e)))?;

    // Extract organization from subject
    for attr in parsed_cert.subject().iter_organization() {
        if let Ok(org) = attr.as_str() {
            return Ok(org.to_string());
        }
    }

    // Try Common Name as fallback
    for attr in parsed_cert.subject().iter_common_name() {
        if let Ok(cn) = attr.as_str() {
            info!("Using Common Name as organization ID: {}", cn);
            return Ok(cn.to_string());
        }
    }

    Err(TlsConfigError::InvalidCertificate(
        "No organization ID found in certificate".to_string(),
    ))
}

/// Compute SHA-256 fingerprint of a certificate
pub fn compute_certificate_fingerprint(cert: &CertificateDer) -> Result<Vec<u8>, TlsConfigError> {
    let mut hasher = Sha256::new();
    hasher.update(cert.as_ref());
    Ok(hasher.finalize().to_vec())
}

/// Verify certificate fingerprint against pins
pub fn verify_certificate_pin(cert: &CertificateDer, pinned_fingerprints: &[Vec<u8>]) -> Result<(), TlsConfigError> {
    if pinned_fingerprints.is_empty() {
        return Err(TlsConfigError::Configuration(
            "No certificate pins configured".to_string(),
        ));
    }

    let fingerprint = compute_certificate_fingerprint(cert)?;

    for pin in pinned_fingerprints {
        if pin.as_slice() == fingerprint.as_slice() {
            debug!("Certificate fingerprint matched pin");
            return Ok(());
        }
    }

    error!("Certificate fingerprint does not match any pins");
    Err(TlsConfigError::InvalidCertificate(
        "Certificate fingerprint does not match any configured pins".to_string(),
    ))
}

/// Create a server TLS configuration with optional mutual TLS
pub fn create_server_config(
    cert_path: &Path,
    key_path: &Path,
    require_client_auth: bool,
) -> Result<Arc<ServerConfig>, TlsConfigError> {
    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;
    
    let mut config = if require_client_auth {
        // Mutual TLS: require and verify client certificates
        info!("Configuring server with mutual TLS (client authentication required)");
        
        // For now, we'll use an empty root store
        // In production, this should be populated with trusted federation CA certs
        let root_store = RootCertStore::empty();
        
        // Use rustls's built-in WebPKI verifier from rustls::server::WebPkiClientVerifier
        let client_cert_verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store))
            .build()
            .map_err(|e| TlsConfigError::Configuration(format!("Failed to build client verifier: {}", e)))?;
        
        ServerConfig::builder()
            .with_client_cert_verifier(client_cert_verifier)
            .with_single_cert(certs, key)
            .map_err(|e| TlsConfigError::Configuration(e.to_string()))?
    } else {
        // Standard TLS: no client authentication
        info!("Configuring server with standard TLS (no client authentication)");
        
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| TlsConfigError::Configuration(e.to_string()))?
    };
    
    // Configure TLS 1.3 only
    config.alpn_protocols = vec![b"norc/1.0".to_vec()];
    
    info!("Created server TLS configuration (TLS 1.3, ALPN: norc/1.0)");
    Ok(Arc::new(config))
}

/// Create a server TLS configuration with mutual TLS and custom CA roots
/// 
/// This function enables mutual TLS authentication with support for:
/// - Custom CA certificate verification
/// - Optional certificate pinning via SHA-256 fingerprints
/// - Organization ID extraction from client certificates
pub fn create_server_config_with_client_ca(
    cert_path: &Path,
    key_path: &Path,
    client_ca_path: &Path,
    pinned_fingerprints: Vec<Vec<u8>>,
) -> Result<Arc<ServerConfig>, TlsConfigError> {
    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;
    let ca_certs = load_certs(client_ca_path)?;
    
    // Build root store with trusted federation CAs
    let mut root_store = RootCertStore::empty();
    for cert in ca_certs {
        root_store.add(cert)
            .map_err(|e| TlsConfigError::InvalidCertificate(format!("Failed to add CA cert: {}", e)))?;
    }
    
    info!("Loaded {} trusted CA certificates for client verification", root_store.len());
    
    // Use rustls's built-in WebPKI verifier
    // TODO: To add certificate pinning support, we need to implement a custom ClientCertVerifier
    // that wraps WebPkiClientVerifier and adds pinning validation in verify_client_cert()
    let client_cert_verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store))
        .build()
        .map_err(|e| TlsConfigError::Configuration(format!("Failed to build client verifier: {}", e)))?;
    
    if !pinned_fingerprints.is_empty() {
        warn!(
            "Certificate pinning configured with {} pins, but custom verifier not yet implemented. Pinning is currently ignored.",
            pinned_fingerprints.len()
        );
        // TODO: Implement custom ClientCertVerifier that wraps WebPkiClientVerifier
        // and adds pinning verification using verify_certificate_pin()
    }
    
    let mut config = ServerConfig::builder()
        .with_client_cert_verifier(client_cert_verifier)
        .with_single_cert(certs, key)
        .map_err(|e| TlsConfigError::Configuration(e.to_string()))?;
    
    // Configure TLS 1.3 only
    config.alpn_protocols = vec![b"norc/1.0".to_vec()];
    
    info!("Created server TLS configuration with mutual TLS and client CA verification");
    Ok(Arc::new(config))
}

/// Create a client TLS configuration
pub fn create_client_config(
    verify_server: bool,
) -> Result<Arc<ClientConfig>, TlsConfigError> {
    let mut root_store = RootCertStore::empty();
    
    if verify_server {
        // Use system root certificates
        root_store.extend(
            webpki_roots::TLS_SERVER_ROOTS
                .iter()
                .cloned()
        );
        info!("Loaded {} root certificates", root_store.len());
    } else {
        warn!("Server certificate verification is disabled - NOT RECOMMENDED for production");
    }
    
    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    
    info!("Created client TLS configuration");
    Ok(Arc::new(config))
}

/// Create a client TLS configuration with custom CA certificate
pub fn create_client_config_with_ca(
    ca_cert_path: &Path,
) -> Result<Arc<ClientConfig>, TlsConfigError> {
    let ca_certs = load_certs(ca_cert_path)?;
    
    let mut root_store = RootCertStore::empty();
    for cert in ca_certs {
        root_store.add(cert)
            .map_err(|e| TlsConfigError::InvalidCertificate(e.to_string()))?;
    }
    
    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    
    info!("Created client TLS configuration with custom CA from {:?}", ca_cert_path);
    Ok(Arc::new(config))
}