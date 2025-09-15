//! Client errors

use thiserror::Error;

/// Result type for client operations
pub type Result<T> = std::result::Result<T, ClientError>;

/// Client errors that can occur during operation
#[derive(Error, Debug, Clone)]
pub enum ClientError {
    /// Connection establishment failed
    #[error("Connection failed: {message}")]
    Connection { message: String },
    
    /// Authentication failed
    #[error("Authentication failed: {message}")]
    Authentication { message: String },
    
    /// Configuration error
    #[error("Configuration error: {message}")]
    Configuration { message: String },
    
    /// Protocol error from underlying layers
    #[error("Protocol error: {message}")]
    Protocol { message: String },
    
    /// Transport layer error
    #[error("Transport error: {message}")]
    Transport { message: String },
    
    /// Client is not connected
    #[error("Client not connected")]
    NotConnected,
    
    /// Client is already connected
    #[error("Client already connected")]
    AlreadyConnected,
    
    /// Message send failed
    #[error("Send failed: {message}")]
    SendFailed { message: String },
    
    /// Message receive failed
    #[error("Receive failed: {message}")]
    ReceiveFailed { message: String },
    
    /// Invalid state transition
    #[error("Invalid state: expected {expected}, got {actual}")]
    InvalidState { expected: String, actual: String },
    
    /// Generic client error
    #[error("Client error: {message}")]
    Generic { message: String },
}

impl From<navatron_protocol::error::NorcError> for ClientError {
    fn from(err: navatron_protocol::error::NorcError) -> Self {
        Self::Protocol {
            message: err.to_string(),
        }
    }
}

impl From<navatron_transport::error::TransportError> for ClientError {
    fn from(err: navatron_transport::error::TransportError) -> Self {
        Self::Transport {
            message: err.to_string(),
        }
    }
}

impl ClientError {
    /// Create a connection error
    pub fn connection(message: impl Into<String>) -> Self {
        Self::Connection {
            message: message.into(),
        }
    }
    
    /// Create an authentication error
    pub fn authentication(message: impl Into<String>) -> Self {
        Self::Authentication {
            message: message.into(),
        }
    }
    
    /// Create a configuration error
    pub fn configuration(message: impl Into<String>) -> Self {
        Self::Configuration {
            message: message.into(),
        }
    }
    
    /// Create a send failed error
    pub fn send_failed(message: impl Into<String>) -> Self {
        Self::SendFailed {
            message: message.into(),
        }
    }
    
    /// Create a receive failed error
    pub fn receive_failed(message: impl Into<String>) -> Self {
        Self::ReceiveFailed {
            message: message.into(),
        }
    }
    
    /// Create a generic error
    pub fn generic(message: impl Into<String>) -> Self {
        Self::Generic {
            message: message.into(),
        }
    }
}