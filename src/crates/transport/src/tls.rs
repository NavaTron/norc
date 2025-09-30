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
        
        Ok(Self { stream })
    }
}

#[async_trait]
impl Transport for TlsClientTransport {
    async fn send(&mut self, data: &[u8]) -> Result<()> {
        // Write length prefix (4 bytes, big-endian)
        let len = data.len() as u32;
        self.stream.write_all(&len.to_be_bytes()).await?;
        
        // Write data
        self.stream.write_all(data).await?;
        self.stream.flush().await?;
        
        Ok(())
    }

    async fn receive(&mut self) -> Result<Bytes> {
        // Read length prefix
        let mut len_buf = [0u8; 4];
        self.stream.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        
        // Read data
        let mut buf = BytesMut::with_capacity(len);
        buf.resize(len, 0);
        self.stream.read_exact(&mut buf).await?;
        
        Ok(buf.freeze())
    }

    async fn close(&mut self) -> Result<()> {
        self.stream.shutdown().await?;
        Ok(())
    }

    fn is_connected(&self) -> bool {
        // TLS stream doesn't provide a direct way to check connection state
        // Assume connected unless explicitly closed
        true
    }
}

/// TLS server transport
pub struct TlsServerTransport {
    stream: tokio_rustls::server::TlsStream<TcpStream>,
}

impl TlsServerTransport {
    /// Accept a TLS connection
    pub async fn accept(
        tcp_stream: TcpStream,
        config: Arc<ServerConfig>,
    ) -> Result<Self> {
        let acceptor = TlsAcceptor::from(config);
        let stream = acceptor.accept(tcp_stream).await?;
        
        Ok(Self { stream })
    }
}

#[async_trait]
impl Transport for TlsServerTransport {
    async fn send(&mut self, data: &[u8]) -> Result<()> {
        // Write length prefix (4 bytes, big-endian)
        let len = data.len() as u32;
        self.stream.write_all(&len.to_be_bytes()).await?;
        
        // Write data
        self.stream.write_all(data).await?;
        self.stream.flush().await?;
        
        Ok(())
    }

    async fn receive(&mut self) -> Result<Bytes> {
        // Read length prefix
        let mut len_buf = [0u8; 4];
        self.stream.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        
        // Read data
        let mut buf = BytesMut::with_capacity(len);
        buf.resize(len, 0);
        self.stream.read_exact(&mut buf).await?;
        
        Ok(buf.freeze())
    }

    async fn close(&mut self) -> Result<()> {
        self.stream.shutdown().await?;
        Ok(())
    }

    fn is_connected(&self) -> bool {
        // TLS stream doesn't provide a direct way to check connection state
        // Assume connected unless explicitly closed
        true
    }
}
