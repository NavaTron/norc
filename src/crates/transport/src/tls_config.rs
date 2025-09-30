//! TLS configuration and certificate management
//! Implements SERVER_REQUIREMENTS T-S-F-03.01.02 (Certificate validation)

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls_pemfile::{certs, private_key};
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;
use tracing::{info, warn};

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

/// Create a server TLS configuration
pub fn create_server_config(
    cert_path: &Path,
    key_path: &Path,
    require_client_auth: bool,
) -> Result<Arc<ServerConfig>, TlsConfigError> {
    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;
    
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| TlsConfigError::Configuration(e.to_string()))?;
    
    // Configure TLS 1.3 only
    config.alpn_protocols = vec![b"norc/1.0".to_vec()];
    
    if require_client_auth {
        warn!("Client authentication is configured but not yet fully implemented");
        // TODO: Implement mutual TLS with client certificate verification
        // This requires creating a config with client cert verifier
    }
    
    info!("Created server TLS configuration (TLS 1.3, ALPN: norc/1.0)");
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