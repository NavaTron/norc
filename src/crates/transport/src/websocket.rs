//! WebSocket transport implementation

use crate::error::{Result, TransportError};
use crate::{Transport, TransportConfig};
use async_trait::async_trait;
use bytes::Bytes;
use tokio_tungstenite::{connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream};
use tokio::net::TcpStream;
use futures_util::{SinkExt, StreamExt};

/// WebSocket client transport
pub struct WebSocketTransport {
    stream: WebSocketStream<MaybeTlsStream<TcpStream>>,
    config: TransportConfig,
}

impl WebSocketTransport {
    /// Connect to a WebSocket server
    pub async fn connect(url: &str, config: TransportConfig) -> Result<Self> {
        let (stream, _response) = connect_async(url)
            .await
            .map_err(|e| TransportError::WebSocket(format!("Connection failed: {}", e)))?;

        Ok(Self { stream, config })
    }
}

#[async_trait]
impl Transport for WebSocketTransport {
    async fn send(&mut self, data: &[u8]) -> Result<()> {
        if data.len() > self.config.max_message_size {
            return Err(TransportError::MessageTooLarge(data.len()));
        }

        let message = Message::Binary(data.to_vec());
        self.stream
            .send(message)
            .await
            .map_err(|e| TransportError::WebSocket(format!("Send failed: {}", e)))?;

        Ok(())
    }

    async fn receive(&mut self) -> Result<Bytes> {
        match self.stream.next().await {
            Some(Ok(Message::Binary(data))) => {
                if data.len() > self.config.max_message_size {
                    return Err(TransportError::MessageTooLarge(data.len()));
                }
                Ok(Bytes::from(data))
            }
            Some(Ok(Message::Close(_))) => {
                Err(TransportError::Connection("Connection closed".to_string()))
            }
            Some(Ok(_)) => Err(TransportError::Protocol(
                "Unexpected message type".to_string(),
            )),
            Some(Err(e)) => Err(TransportError::WebSocket(format!("Receive failed: {}", e))),
            None => Err(TransportError::Connection(
                "Stream ended unexpectedly".to_string(),
            )),
        }
    }

    async fn close(&mut self) -> Result<()> {
        self.stream
            .close(None)
            .await
            .map_err(|e| TransportError::WebSocket(format!("Close failed: {}", e)))?;
        Ok(())
    }

    fn is_connected(&self) -> bool {
        true // TODO: Implement proper connection state tracking
    }
}
