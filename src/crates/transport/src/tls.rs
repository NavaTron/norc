//! TLS 1.3 transport implementation per SERVER_REQUIREMENTS F-03.01

use crate::{Result, Transport, TransportError};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use rustls::{ClientConfig, ServerConfig};
use rustls::pki_types::ServerName;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::{debug, info};

/// TLS client transport
pub struct TlsClientTransport {
    stream: tokio_rustls::client::TlsStream<TcpStream>,
}

impl TlsClientTransport {
    /// Connect to a TLS server
    pub async fn connect(
        addr: &str,
        config: Arc<ClientConfig>,
    ) -> Result<Self> {
        let connector = TlsConnector::from(config);
        let tcp_stream = TcpStream::connect(addr).await?;
        
        // Extract hostname from address
        let hostname = addr
            .split(':')
            .next()
            .ok_or_else(|| TransportError::Connection("Invalid address".to_string()))?;
        
        let server_name = ServerName::try_from(hostname.to_string())
            .map_err(|e| TransportError::Connection(format!("Invalid hostname: {}", e)))?;
        
        let stream = connector.connect(server_name, tcp_stream).await?;
        
        info!("TLS connection established to {}", addr);
        Ok(Self { stream })
    }

    /// Get peer certificates
    pub fn peer_certificates(&self) -> Option<Vec<rustls::pki_types::CertificateDer<'static>>> {
        self.stream
            .get_ref()
            .1
            .peer_certificates()
            .map(|certs| certs.to_vec())
    }

    /// Get negotiated protocol (ALPN)
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.stream
            .get_ref()
            .1
            .alpn_protocol()
    }
}

#[async_trait]
impl Transport for TlsClientTransport {
    async fn send(&mut self, data: &[u8]) -> Result<()> {
        // Validate message size
        if data.len() > 16 * 1024 * 1024 {
            return Err(TransportError::Protocol(
                format!("Message too large: {} bytes", data.len())
            ));
        }

        // Write length prefix (4 bytes, big-endian)
        let len = data.len() as u32;
        self.stream.write_all(&len.to_be_bytes()).await?;
        
        // Write data
        self.stream.write_all(data).await?;
        self.stream.flush().await?;
        
        debug!("Sent {} bytes over TLS", data.len());
        Ok(())
    }

    async fn receive(&mut self) -> Result<Bytes> {
        // Read length prefix
        let mut len_buf = [0u8; 4];
        self.stream.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        
        // Validate message size
        if len > 16 * 1024 * 1024 {
            return Err(TransportError::Protocol(
                format!("Message too large: {} bytes", len)
            ));
        }
        
        // Read data
        let mut buf = BytesMut::with_capacity(len);
        buf.resize(len, 0);
        self.stream.read_exact(&mut buf).await?;
        
        debug!("Received {} bytes over TLS", len);
        Ok(buf.freeze())
    }

    async fn close(&mut self) -> Result<()> {
        self.stream.shutdown().await?;
        info!("TLS connection closed");
        Ok(())
    }

    fn is_connected(&self) -> bool {
        // Check underlying TCP connection
        self.stream.get_ref().0.peer_addr().is_ok()
    }
}

/// TLS server transport
pub struct TlsServerTransport {
    stream: tokio_rustls::server::TlsStream<TcpStream>,
    peer_addr: std::net::SocketAddr,
}

impl TlsServerTransport {
    /// Accept a TLS connection
    pub async fn accept(
        tcp_stream: TcpStream,
        config: Arc<ServerConfig>,
    ) -> Result<Self> {
        let peer_addr = tcp_stream.peer_addr()?;
        let acceptor = TlsAcceptor::from(config);
        let stream = acceptor.accept(tcp_stream).await?;
        
        info!("TLS connection accepted from {}", peer_addr);
        Ok(Self { stream, peer_addr })
    }

    /// Get peer address
    pub fn peer_addr(&self) -> std::net::SocketAddr {
        self.peer_addr
    }

    /// Get peer certificates
    pub fn peer_certificates(&self) -> Option<Vec<rustls::pki_types::CertificateDer<'static>>> {
        self.stream
            .get_ref()
            .1
            .peer_certificates()
            .map(|certs| certs.to_vec())
    }

    /// Get negotiated protocol (ALPN)
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.stream
            .get_ref()
            .1
            .alpn_protocol()
    }
}

#[async_trait]
impl Transport for TlsServerTransport {
    async fn send(&mut self, data: &[u8]) -> Result<()> {
        // Validate message size
        if data.len() > 16 * 1024 * 1024 {
            return Err(TransportError::Protocol(
                format!("Message too large: {} bytes", data.len())
            ));
        }

        // Write length prefix (4 bytes, big-endian)
        let len = data.len() as u32;
        self.stream.write_all(&len.to_be_bytes()).await?;
        
        // Write data
        self.stream.write_all(data).await?;
        self.stream.flush().await?;
        
        debug!("Sent {} bytes over TLS to {}", data.len(), self.peer_addr);
        Ok(())
    }

    async fn receive(&mut self) -> Result<Bytes> {
        // Read length prefix
        let mut len_buf = [0u8; 4];
        self.stream.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        
        // Validate message size
        if len > 16 * 1024 * 1024 {
            return Err(TransportError::Protocol(
                format!("Message too large: {} bytes", len)
            ));
        }
        
        // Read data
        let mut buf = BytesMut::with_capacity(len);
        buf.resize(len, 0);
        self.stream.read_exact(&mut buf).await?;
        
        debug!("Received {} bytes over TLS from {}", len, self.peer_addr);
        Ok(buf.freeze())
    }

    async fn close(&mut self) -> Result<()> {
        self.stream.shutdown().await?;
        info!("TLS connection from {} closed", self.peer_addr);
        Ok(())
    }

    fn is_connected(&self) -> bool {
        // Check underlying TCP connection
        self.stream.get_ref().0.peer_addr().is_ok()
    }
}

#[cfg(test)]
mod tests {
    // Note: These tests require valid test certificates
    // In a real implementation, we would generate test certs programmatically
}
