//! WebSocket transport implementation for NORC protocol

use std::net::SocketAddr;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::{
    accept_async, connect_async, tungstenite::Message as WsMessage, WebSocketStream, MaybeTlsStream,
};
use tracing::{debug, info};
use url::Url;

use crate::connection::{ConnectionHandle, ConnectionMetadata, create_connection};
use crate::error::{Result, TransportError};
use tokio::sync::mpsc;
use crate::connection::ConnectionEvent;

/// WebSocket configuration
#[derive(Debug, Clone)]
pub struct WebSocketConfig {
    /// Maximum frame size (in bytes)
    pub max_frame_size: usize,
    /// Maximum message size (in bytes)  
    pub max_message_size: Option<usize>,
    /// Connection timeout
    pub connect_timeout: Duration,
    /// Write buffer size
    pub write_buffer_size: usize,
    /// Maximum number of write buffers
    pub max_write_buffer_size: usize,
    /// Accept unmasked frames (server only)
    pub accept_unmasked_frames: bool,
}

impl Default for WebSocketConfig {
    fn default() -> Self {
        Self {
            max_frame_size: 16 * 1024 * 1024, // 16MB
            max_message_size: Some(64 * 1024 * 1024), // 64MB
            connect_timeout: Duration::from_secs(30),
            write_buffer_size: 128 * 1024, // 128KB
            max_write_buffer_size: 16,
            accept_unmasked_frames: false,
        }
    }
}

impl WebSocketConfig {
    /// Create a new WebSocket configuration
    pub fn new() -> Self {
        Self::default()
    }

    /// Set maximum frame size
    pub fn with_max_frame_size(mut self, size: usize) -> Self {
        self.max_frame_size = size;
        self
    }

    /// Set maximum message size
    pub fn with_max_message_size(mut self, size: Option<usize>) -> Self {
        self.max_message_size = size;
        self
    }

    /// Set connection timeout
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Set write buffer size
    pub fn with_write_buffer_size(mut self, size: usize) -> Self {
        self.write_buffer_size = size;
        self
    }

    /// Accept unmasked frames (for server)
    pub fn with_accept_unmasked_frames(mut self, accept: bool) -> Self {
        self.accept_unmasked_frames = accept;
        self
    }
}

/// WebSocket transport adapter for NORC protocol
pub struct WebSocketTransport<S> {
    stream: WebSocketStream<S>,
}

impl<S> WebSocketTransport<S> {
    /// Create from an existing WebSocket stream
    pub fn new(stream: WebSocketStream<S>) -> Self {
        Self { stream }
    }
}

impl WebSocketTransport<MaybeTlsStream<TcpStream>> {
    /// Connect to a WebSocket server
    pub async fn connect(
        url: Url,
        config: &WebSocketConfig,
    ) -> Result<Self> {
        debug!("Connecting to WebSocket server at {}", url);

        let (stream, response) = tokio::time::timeout(
            config.connect_timeout,
            connect_async(&url),
        )
        .await
        .map_err(|_| TransportError::Timeout {
            duration_ms: config.connect_timeout.as_millis() as u64,
        })?
        .map_err(|e| TransportError::WebSocket { message: e.to_string() })?;

        info!("WebSocket connection established to {}", url);
        debug!("WebSocket response: {:?}", response);

        Ok(Self::new(stream))
    }
}

impl WebSocketTransport<TcpStream> {
    /// Accept a WebSocket connection from a TCP stream
    pub async fn accept(
        tcp_stream: TcpStream,
        config: &WebSocketConfig,
    ) -> Result<Self> {
        debug!("Accepting WebSocket connection");

        let stream = tokio::time::timeout(
            config.connect_timeout,
            accept_async(tcp_stream),
        )
        .await
        .map_err(|_| TransportError::Timeout {
            duration_ms: config.connect_timeout.as_millis() as u64,
        })?
        .map_err(|e| TransportError::WebSocket { message: e.to_string() })?;

        info!("WebSocket connection accepted");

        Ok(Self::new(stream))
    }

    /// Get the local address
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.stream.get_ref().local_addr().ok()
    }

    /// Get the remote address
    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.stream.get_ref().peer_addr().ok()
    }

    /// Convert to a connection handle
    pub async fn into_connection_handle(
        self,
        protocol_version: navatron_protocol::Version,
        event_tx: mpsc::UnboundedSender<ConnectionEvent>,
    ) -> Result<ConnectionHandle> {
        let local_addr = self.local_addr();
        let remote_addr = self.peer_addr().ok_or_else(|| {
            TransportError::connection("Could not get peer address")
        })?;

        let metadata = ConnectionMetadata::new(remote_addr, local_addr, protocol_version);
        let adapter = WebSocketAdapter::new(self.stream);

        create_connection(adapter, metadata, event_tx).await
    }
}

/// WebSocket adapter that implements AsyncRead + AsyncWrite for integration with connection handling
pub struct WebSocketAdapter {
    stream: WebSocketStream<TcpStream>,
    read_buffer: Vec<u8>,
    read_pos: usize,
}

impl WebSocketAdapter {
    /// Create a new WebSocket adapter
    pub fn new(stream: WebSocketStream<TcpStream>) -> Self {
        Self {
            stream,
            read_buffer: Vec::new(),
            read_pos: 0,
        }
    }
}

impl tokio::io::AsyncRead for WebSocketAdapter {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // If we have data in our buffer, copy it to the output buffer
        if self.read_pos < self.read_buffer.len() {
            let available = self.read_buffer.len() - self.read_pos;
            let to_copy = available.min(buf.remaining());
            
            buf.put_slice(&self.read_buffer[self.read_pos..self.read_pos + to_copy]);
            self.read_pos += to_copy;
            
            // If we've consumed all buffered data, clear the buffer
            if self.read_pos >= self.read_buffer.len() {
                self.read_buffer.clear();
                self.read_pos = 0;
            }
            
            return std::task::Poll::Ready(Ok(()));
        }

        // Poll for the next WebSocket message
        match futures::ready!(self.stream.poll_next_unpin(cx)) {
            Some(Ok(msg)) => {
                match msg {
                    WsMessage::Binary(data) => {
                        self.read_buffer = data;
                        self.read_pos = 0;
                        
                        // Copy data to output buffer
                        let to_copy = self.read_buffer.len().min(buf.remaining());
                        buf.put_slice(&self.read_buffer[..to_copy]);
                        self.read_pos = to_copy;
                        
                        std::task::Poll::Ready(Ok(()))
                    }
                    WsMessage::Close(_) => {
                        std::task::Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "WebSocket connection closed"
                        )))
                    }
                    WsMessage::Ping(_) | WsMessage::Pong(_) => {
                        // Skip control frames and poll again
                        cx.waker().wake_by_ref();
                        std::task::Poll::Pending
                    }
                    WsMessage::Text(_) => {
                        std::task::Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Expected binary frame, got text frame"
                        )))
                    }
                    WsMessage::Frame(_) => {
                        // Raw frame handling - typically not needed at this level
                        cx.waker().wake_by_ref();
                        std::task::Poll::Pending
                    }
                }
            }
            Some(Err(e)) => {
                std::task::Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e
                )))
            }
            None => {
                std::task::Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "WebSocket stream ended"
                )))
            }
        }
    }
}

impl tokio::io::AsyncWrite for WebSocketAdapter {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let msg = WsMessage::Binary(buf.to_vec());
        
        match futures::ready!(self.stream.poll_ready_unpin(cx)) {
            Ok(()) => {
                match self.stream.start_send_unpin(msg) {
                    Ok(()) => std::task::Poll::Ready(Ok(buf.len())),
                    Err(e) => std::task::Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        e
                    ))),
                }
            }
            Err(e) => std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                e
            ))),
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match futures::ready!(self.stream.poll_flush_unpin(cx)) {
            Ok(()) => std::task::Poll::Ready(Ok(())),
            Err(e) => std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                e
            ))),
        }
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match futures::ready!(self.stream.poll_close_unpin(cx)) {
            Ok(()) => std::task::Poll::Ready(Ok(())),
            Err(e) => std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                e
            ))),
        }
    }
}

/// WebSocket server for accepting NORC connections
pub struct WebSocketServer {
    /// TCP listener
    listener: TcpListener,
    /// Configuration
    config: WebSocketConfig,
}

impl WebSocketServer {
    /// Create a new WebSocket server
    pub async fn bind(addr: SocketAddr, config: WebSocketConfig) -> Result<Self> {
        let listener = TcpListener::bind(addr).await.map_err(|e| TransportError::Io { message: e.to_string() })?;
        info!("WebSocket server listening on {}", addr);
        
        Ok(Self { listener, config })
    }

    /// Get the local address
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.listener.local_addr().map_err(|e| TransportError::Io { message: e.to_string() })
    }

    /// Accept the next connection
    pub async fn accept(&self) -> Result<WebSocketTransport<TcpStream>> {
        let (tcp_stream, addr) = self.listener.accept().await.map_err(|e| TransportError::Io { message: e.to_string() })?;
        debug!("Accepted TCP connection from {}", addr);
        
        WebSocketTransport::accept(tcp_stream, &self.config).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn test_websocket_config() {
        let config = WebSocketConfig::new()
            .with_max_frame_size(1024)
            .with_max_message_size(Some(2048))
            .with_connect_timeout(Duration::from_secs(60))
            .with_accept_unmasked_frames(true);

        assert_eq!(config.max_frame_size, 1024);
        assert_eq!(config.max_message_size, Some(2048));
        assert_eq!(config.connect_timeout, Duration::from_secs(60));
        assert!(config.accept_unmasked_frames);
    }

    #[tokio::test]
    async fn test_websocket_server_bind() {
        let addr = "127.0.0.1:0".parse().unwrap();
        let config = WebSocketConfig::default();
        
        let server = WebSocketServer::bind(addr, config).await.unwrap();
        let bound_addr = server.local_addr().unwrap();
        
        assert_eq!(bound_addr.ip(), addr.ip());
        assert_ne!(bound_addr.port(), 0); // Should be assigned a port
    }

    // Note: Full integration tests would require setting up actual WebSocket connections
    // which is complex in a unit test environment. These would be better suited for
    // integration tests.
}