//! Network listener for accepting client and federation connections
//! Implements SERVER_REQUIREMENTS F-03.02 (Connection Management)

use crate::{
    create_server_config, Result, TlsServerTransport, TransportError,
};
use rustls::ServerConfig;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use tokio::net::TcpListener as TokioTcpListener;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

/// Network listener configuration
#[derive(Debug, Clone)]
pub struct ListenerConfig {
    /// Bind address
    pub bind_addr: String,
    /// TLS certificate path
    pub cert_path: Option<std::path::PathBuf>,
    /// TLS key path
    pub key_path: Option<std::path::PathBuf>,
    /// Require client authentication
    pub require_client_auth: bool,
}

/// Network listener for accepting connections
pub struct NetworkListener {
    config: ListenerConfig,
    tls_config: Option<Arc<ServerConfig>>,
}

impl NetworkListener {
    /// Create a new network listener
    pub async fn new(config: ListenerConfig) -> Result<Self> {
        // Load TLS configuration if certificates are provided
        let tls_config = if let (Some(cert_path), Some(key_path)) = 
            (&config.cert_path, &config.key_path) 
        {
            let tls_cfg = create_server_config(
                cert_path.as_path(),
                key_path.as_path(),
                config.require_client_auth,
            ).map_err(|e| TransportError::Configuration(e.to_string()))?;
            
            info!("TLS configuration loaded for listener");
            Some(tls_cfg)
        } else {
            warn!("No TLS configuration - running in plaintext mode (NOT RECOMMENDED)");
            None
        };

        Ok(Self {
            config,
            tls_config,
        })
    }

    /// Start listening for connections
    pub async fn listen<F>(self, handler: F) -> Result<JoinHandle<()>>
    where
        F: Fn(TlsServerTransport, SocketAddr) + Send + 'static + Clone,
    {
        let listener = TokioTcpListener::bind(&self.config.bind_addr).await?;
        let local_addr = listener.local_addr()?;
        
        info!("Network listener started on {}", local_addr);

        let tls_config = self.tls_config.clone();
        
        let handle = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((tcp_stream, peer_addr)) => {
                        info!("Accepted connection from {}", peer_addr);

                        if let Some(ref tls_cfg) = tls_config {
                            // TLS connection
                            let tls_cfg = tls_cfg.clone();
                            let handler = handler.clone();
                            
                            tokio::spawn(async move {
                                match TlsServerTransport::accept(tcp_stream, tls_cfg).await {
                                    Ok(tls_transport) => {
                                        handler(tls_transport, peer_addr);
                                    }
                                    Err(e) => {
                                        error!("TLS handshake failed from {}: {}", peer_addr, e);
                                    }
                                }
                            });
                        } else {
                            // Plaintext connection (not recommended)
                            warn!("Plaintext connection from {} - TLS not configured", peer_addr);
                            // TODO: Handle plaintext if needed for testing
                        }
                    }
                    Err(e) => {
                        error!("Failed to accept connection: {}", e);
                        // Continue listening despite errors
                    }
                }
            }
        });

        Ok(handle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_listener_creation() {
        let config = ListenerConfig {
            bind_addr: "127.0.0.1:0".to_string(),
            cert_path: None,
            key_path: None,
            require_client_auth: false,
        };

        let listener = NetworkListener::new(config).await.unwrap();
        assert!(listener.tls_config.is_none());
    }
}
