//! TLS connection handling for NORC protocol

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ServerConfig, RootCertStore};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::{debug, error, info, warn};

use crate::error::{Result, TransportError};

/// NORC protocol ALPN identifier
pub const NORC_ALPN: &[u8] = b"norc/1.0";

/// Default connection timeout
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Default handshake timeout
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// TLS client configuration
#[derive(Debug)]
pub struct TlsClientConfig {
    /// Root certificate store
    pub root_store: RootCertStore,
    /// Client certificate chain (for mTLS)
    pub client_cert_chain: Option<Vec<CertificateDer<'static>>>,
    /// Client private key (for mTLS)
    pub client_private_key: Option<PrivateKeyDer<'static>>,
    /// Enable SNI (Server Name Indication)
    pub enable_sni: bool,
    /// Accepted ALPN protocols
    pub alpn_protocols: Vec<Vec<u8>>,
    /// Connection timeout
    pub connect_timeout: Duration,
    /// Handshake timeout
    pub handshake_timeout: Duration,
}

impl Default for TlsClientConfig {
    fn default() -> Self {
        let mut root_store = RootCertStore::empty();
        
        // Add system root certificates
        for cert in rustls_native_certs::load_native_certs()
            .unwrap_or_else(|e| {
                warn!("Failed to load native root certificates: {}", e);
                Vec::new()
            })
        {
            if let Err(e) = root_store.add(cert) {
                warn!("Failed to add root certificate: {}", e);
            }
        }
        
        // Add webpki roots as fallback
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        Self {
            root_store,
            client_cert_chain: None,
            client_private_key: None,
            enable_sni: true,
            alpn_protocols: vec![NORC_ALPN.to_vec()],
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
        }
    }
}

impl TlsClientConfig {
    /// Create a new TLS client configuration
    pub fn new() -> Self {
        Self::default()
    }

    /// Set client certificate and private key for mTLS
    pub fn with_client_auth(
        mut self,
        cert_chain: Vec<CertificateDer<'static>>,
        private_key: PrivateKeyDer<'static>,
    ) -> Self {
        self.client_cert_chain = Some(cert_chain);
        self.client_private_key = Some(private_key);
        self
    }

    /// Disable SNI
    pub fn without_sni(mut self) -> Self {
        self.enable_sni = false;
        self
    }

    /// Set custom ALPN protocols
    pub fn with_alpn_protocols(mut self, protocols: Vec<Vec<u8>>) -> Self {
        self.alpn_protocols = protocols;
        self
    }

    /// Set connection timeout
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Set handshake timeout
    pub fn with_handshake_timeout(mut self, timeout: Duration) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    /// Build the rustls ClientConfig
    pub fn build_rustls_config(&self) -> Result<ClientConfig> {
        let mut config_builder = ClientConfig::builder();

        // Configure client authentication if provided
        let config = if let (Some(cert_chain), Some(private_key)) = 
            (&self.client_cert_chain, &self.client_private_key) {
            config_builder
                .with_root_certificates(self.root_store.clone())
                .with_client_auth_cert(cert_chain.clone(), private_key.clone_key())
                .map_err(|e| TransportError::certificate(format!("Invalid client certificate: {}", e)))?
        } else {
            config_builder
                .with_root_certificates(self.root_store.clone())
                .with_no_client_auth()
        };

        Ok(config)
    }
}

/// TLS server configuration
#[derive(Debug)]
pub struct TlsServerConfig {
    /// Server certificate chain
    pub cert_chain: Vec<CertificateDer<'static>>,
    /// Server private key
    pub private_key: PrivateKeyDer<'static>,
    /// Client certificate verification mode
    pub client_cert_verifier: ClientCertVerification,
    /// Accepted ALPN protocols
    pub alpn_protocols: Vec<Vec<u8>>,
    /// Handshake timeout
    pub handshake_timeout: Duration,
}

/// Client certificate verification modes
#[derive(Debug, Clone)]
pub enum ClientCertVerification {
    /// No client certificate required
    None,
    /// Client certificate optional
    Optional,
    /// Client certificate required
    Required,
}

impl TlsServerConfig {
    /// Create a new TLS server configuration
    pub fn new(
        cert_chain: Vec<CertificateDer<'static>>,
        private_key: PrivateKeyDer<'static>,
    ) -> Self {
        Self {
            cert_chain,
            private_key,
            client_cert_verifier: ClientCertVerification::None,
            alpn_protocols: vec![NORC_ALPN.to_vec()],
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
        }
    }

    /// Require client certificate verification
    pub fn with_client_cert_verification(mut self, mode: ClientCertVerification) -> Self {
        self.client_cert_verifier = mode;
        self
    }

    /// Set custom ALPN protocols
    pub fn with_alpn_protocols(mut self, protocols: Vec<Vec<u8>>) -> Self {
        self.alpn_protocols = protocols;
        self
    }

    /// Set handshake timeout
    pub fn with_handshake_timeout(mut self, timeout: Duration) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    /// Build the rustls ServerConfig
    pub fn build_rustls_config(&self) -> Result<ServerConfig> {
        let config = ServerConfig::builder();

        // Configure client certificate verification
        let config = match self.client_cert_verifier {
            ClientCertVerification::None => config.with_no_client_auth(),
            ClientCertVerification::Optional | ClientCertVerification::Required => {
                // For now, use no client auth - proper mTLS would require setting up
                // a client certificate verifier
                warn!("Client certificate verification not yet implemented, using no client auth");
                config.with_no_client_auth()
            }
        };

        let mut tls_config = config
            .with_single_cert(self.cert_chain.clone(), self.private_key.clone_key())
            .map_err(|e| TransportError::certificate(format!("Invalid server certificate: {}", e)))?;

        // Set ALPN protocols 
        if !self.alpn_protocols.is_empty() {
            tls_config.alpn_protocols = self.alpn_protocols.clone();
        }

        Ok(tls_config)
    }
}

/// TLS connection wrapper
pub struct TlsConnection<S> {
    /// Inner connection
    pub inner: S,
    /// Connection metadata
    pub metadata: TlsConnectionMetadata,
}

/// TLS connection metadata
#[derive(Debug, Clone)]
pub struct TlsConnectionMetadata {
    /// Negotiated ALPN protocol
    pub alpn_protocol: Option<Vec<u8>>,
    /// Peer certificates
    pub peer_certificates: Option<Vec<CertificateDer<'static>>>,
    /// TLS version
    pub protocol_version: String,
    /// Cipher suite
    pub cipher_suite: String,
}

impl<S> TlsConnection<S> {
    /// Create a new TLS connection
    pub fn new(inner: S, metadata: TlsConnectionMetadata) -> Self {
        Self { inner, metadata }
    }

    /// Get the inner connection
    pub fn into_inner(self) -> S {
        self.inner
    }

    /// Get a reference to the inner connection
    pub fn inner_ref(&self) -> &S {
        &self.inner
    }

    /// Get a mutable reference to the inner connection
    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    /// Get the connection metadata
    pub fn metadata(&self) -> &TlsConnectionMetadata {
        &self.metadata
    }

    /// Check if ALPN protocol matches expected
    pub fn verify_alpn(&self, expected: &[u8]) -> Result<()> {
        match &self.metadata.alpn_protocol {
            Some(negotiated) if negotiated == expected => Ok(()),
            Some(negotiated) => Err(TransportError::AlpnMismatch {
                expected: vec![String::from_utf8_lossy(expected).to_string()],
                actual: Some(String::from_utf8_lossy(negotiated).to_string()),
            }),
            None => Err(TransportError::AlpnMismatch {
                expected: vec![String::from_utf8_lossy(expected).to_string()],
                actual: None,
            }),
        }
    }
}

/// TLS client connector
pub struct NorcTlsConnector {
    /// Rustls connector
    connector: TlsConnector,
    /// Configuration
    config: TlsClientConfig,
}

impl NorcTlsConnector {
    /// Create a new TLS connector
    pub fn new(config: TlsClientConfig) -> Result<Self> {
        let rustls_config = config.build_rustls_config()?;
        let connector = TlsConnector::from(Arc::new(rustls_config));

        Ok(Self { connector, config })
    }

    /// Connect to a server with TLS
    pub async fn connect(
        &self,
        addr: SocketAddr,
        server_name: ServerName<'static>,
    ) -> Result<TlsConnection<tokio_rustls::client::TlsStream<TcpStream>>> {
        // Connect to the server
        let tcp_stream = tokio::time::timeout(
            self.config.connect_timeout,
            TcpStream::connect(addr),
        )
        .await
        .map_err(|_| TransportError::Timeout {
            duration_ms: self.config.connect_timeout.as_millis() as u64,
        })?
        .map_err(|e| TransportError::Io { message: e.to_string() })?;

        debug!("TCP connection established to {}", addr);

        // Perform TLS handshake
        let tls_stream = tokio::time::timeout(
            self.config.handshake_timeout,
            self.connector.connect(server_name.clone(), tcp_stream),
        )
        .await
        .map_err(|_| TransportError::Timeout {
            duration_ms: self.config.handshake_timeout.as_millis() as u64,
        })?
        .map_err(|e| TransportError::Tls { message: e.to_string() })?;

        info!("TLS handshake completed with {}", addr);

        // Extract connection metadata
        let (_, connection) = tls_stream.get_ref();
        let alpn_protocol = connection.alpn_protocol().map(|p| p.to_vec());
        let protocol_version = connection.protocol_version()
            .map(|v| format!("{:?}", v))
            .unwrap_or_else(|| "Unknown".to_string());
        let cipher_suite = connection.negotiated_cipher_suite()
            .map(|cs| format!("{:?}", cs))
            .unwrap_or_else(|| "Unknown".to_string());

        let metadata = TlsConnectionMetadata {
            alpn_protocol,
            peer_certificates: None, // TODO: Extract peer certificates
            protocol_version,
            cipher_suite,
        };

        let connection = TlsConnection::new(tls_stream, metadata);
        
        // Verify ALPN protocol
        connection.verify_alpn(NORC_ALPN)?;

        Ok(connection)
    }
}

/// TLS server acceptor
pub struct NorcTlsAcceptor {
    /// Rustls acceptor
    acceptor: TlsAcceptor,
    /// Configuration
    config: TlsServerConfig,
}

impl NorcTlsAcceptor {
    /// Create a new TLS acceptor
    pub fn new(config: TlsServerConfig) -> Result<Self> {
        let rustls_config = config.build_rustls_config()?;
        let acceptor = TlsAcceptor::from(Arc::new(rustls_config));

        Ok(Self { acceptor, config })
    }

    /// Accept a TLS connection
    pub async fn accept(
        &self,
        tcp_stream: TcpStream,
    ) -> Result<TlsConnection<tokio_rustls::server::TlsStream<TcpStream>>> {
        // Perform TLS handshake
        let tls_stream = tokio::time::timeout(
            self.config.handshake_timeout,
            self.acceptor.accept(tcp_stream),
        )
        .await
        .map_err(|_| TransportError::Timeout {
            duration_ms: self.config.handshake_timeout.as_millis() as u64,
        })?
        .map_err(|e| TransportError::Tls { message: e.to_string() })?;

        info!("TLS handshake completed with client");

        // Extract connection metadata
        let (_, connection) = tls_stream.get_ref();
        let alpn_protocol = connection.alpn_protocol().map(|p| p.to_vec());
        let protocol_version = connection.protocol_version()
            .map(|v| format!("{:?}", v))
            .unwrap_or_else(|| "Unknown".to_string());
        let cipher_suite = connection.negotiated_cipher_suite()
            .map(|cs| format!("{:?}", cs))
            .unwrap_or_else(|| "Unknown".to_string());

        let metadata = TlsConnectionMetadata {
            alpn_protocol,
            peer_certificates: None, // TODO: Extract peer certificates
            protocol_version,
            cipher_suite,
        };

        let connection = TlsConnection::new(tls_stream, metadata);
        
        // Verify ALPN protocol
        connection.verify_alpn(NORC_ALPN)?;

        Ok(connection)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::PrivatePkcs8KeyDer;

    #[test]
    fn test_tls_client_config_default() {
        let config = TlsClientConfig::default();
        assert!(config.enable_sni);
        assert_eq!(config.alpn_protocols, vec![NORC_ALPN.to_vec()]);
        assert_eq!(config.connect_timeout, DEFAULT_CONNECT_TIMEOUT);
        assert_eq!(config.handshake_timeout, DEFAULT_HANDSHAKE_TIMEOUT);
    }

    #[test]
    fn test_tls_client_config_builder() {
        let config = TlsClientConfig::new()
            .without_sni()
            .with_connect_timeout(Duration::from_secs(60))
            .with_handshake_timeout(Duration::from_secs(20));

        assert!(!config.enable_sni);
        assert_eq!(config.connect_timeout, Duration::from_secs(60));
        assert_eq!(config.handshake_timeout, Duration::from_secs(20));
    }

    #[test]
    fn test_alpn_verification() {
        let metadata = TlsConnectionMetadata {
            alpn_protocol: Some(NORC_ALPN.to_vec()),
            peer_certificates: None,
            protocol_version: "TLS 1.3".to_string(),
            cipher_suite: "TLS13_AES_256_GCM_SHA384".to_string(),
        };

        let connection = TlsConnection::new((), metadata);
        assert!(connection.verify_alpn(NORC_ALPN).is_ok());
        assert!(connection.verify_alpn(b"http/1.1").is_err());
    }

    #[test]
    fn test_client_cert_verification_modes() {
        let cert = CertificateDer::from(vec![1, 2, 3]);
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(vec![4, 5, 6]));

        let config = TlsServerConfig::new(vec![cert], key)
            .with_client_cert_verification(ClientCertVerification::Required);

        matches!(config.client_cert_verifier, ClientCertVerification::Required);
    }
}