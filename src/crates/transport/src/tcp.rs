//! TCP transport implementation per SERVER_REQUIREMENTS F-03.01

use crate::{Result, Transport, TransportError};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener as TokioTcpListener, TcpStream};
use tracing::{debug, error, info};

/// TCP stream wrapper
pub struct TcpTransport {
    stream: TcpStream,
}

impl TcpTransport {
    /// Create from an existing TCP stream
    pub fn new(stream: TcpStream) -> Self {
        Self { stream }
    }

    /// Connect to a TCP server
    pub async fn connect(addr: &str) -> Result<Self> {
        let stream = TcpStream::connect(addr).await?;
        info!("Connected to TCP server: {}", addr);
        Ok(Self { stream })
    }
}

#[async_trait]
impl Transport for TcpTransport {
    async fn send(&mut self, data: &[u8]) -> Result<()> {
        // Write length prefix (4 bytes, big-endian)
        let len = data.len() as u32;
        self.stream.write_all(&len.to_be_bytes()).await?;
        
        // Write data
        self.stream.write_all(data).await?;
        self.stream.flush().await?;
        
        debug!("Sent {} bytes over TCP", data.len());
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
        
        debug!("Received {} bytes over TCP", len);
        Ok(buf.freeze())
    }

    async fn close(&mut self) -> Result<()> {
        self.stream.shutdown().await?;
        info!("TCP connection closed");
        Ok(())
    }

    fn is_connected(&self) -> bool {
        // Check if stream is readable/writable
        self.stream.peer_addr().is_ok()
    }
}

/// TCP listener for accepting connections
pub struct TcpListener {
    listener: TokioTcpListener,
}

impl TcpListener {
    /// Bind to an address
    pub async fn bind(addr: &str) -> Result<Self> {
        let listener = TokioTcpListener::bind(addr).await?;
        info!("TCP listener bound to: {}", addr);
        Ok(Self { listener })
    }

    /// Accept a new connection
    pub async fn accept(&self) -> Result<(TcpStream, std::net::SocketAddr)> {
        match self.listener.accept().await {
            Ok((stream, addr)) => {
                debug!("Accepted TCP connection from: {}", addr);
                Ok((stream, addr))
            }
            Err(e) => {
                error!("Failed to accept TCP connection: {}", e);
                Err(e.into())
            }
        }
    }

    /// Get the local address
    pub fn local_addr(&self) -> Result<std::net::SocketAddr> {
        Ok(self.listener.local_addr()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_tcp_listener_bind() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        assert!(addr.port() > 0);
    }
}

