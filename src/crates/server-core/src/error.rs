//! Server error types

use thiserror::Error;

/// Result type for server operations
pub type Result<T> = std::result::Result<T, ServerError>;

/// Server errors that can occur during operation
#[derive(Error, Debug, Clone)]
pub enum ServerError {
    /// Server initialization failed
    #[error("Server initialization failed: {message}")]
    Initialization { message: String },
    
    /// Server startup failed
    #[error("Server startup failed: {message}")]
    Startup { message: String },
    
    /// Client connection handling failed
    #[error("Connection error: {message}")]
    Connection { message: String },
    
    /// Session management error
    #[error("Session error: {message}")]
    Session { message: String },
    
    /// Authentication failed
    #[error("Authentication failed: {message}")]
    Authentication { message: String },
    
    /// Authorization failed
    #[error("Authorization failed: {message}")]
    Authorization { message: String },
    
    /// Message routing failed
    #[error("Routing error: {message}")]
    Routing { message: String },
    
    /// Federation error
    #[error("Federation error: {message}")]
    Federation { message: String },
    
    /// Storage/database error
    #[error("Storage error: {message}")]
    Storage { message: String },
    
    /// Configuration error
    #[error("Configuration error: {message}")]
    Configuration { message: String },
    
    /// Protocol error from underlying layers
    #[error("Protocol error: {message}")]
    Protocol { message: String },
    
    /// Transport layer error
    #[error("Transport error: {message}")]
    Transport { message: String },
    
    /// Resource limit exceeded
    #[error("Resource limit exceeded: {resource}, limit: {limit}")]
    ResourceLimit { resource: String, limit: u64 },
    
    /// Service unavailable
    #[error("Service unavailable: {message}")]
    ServiceUnavailable { message: String },
    
    /// Invalid request
    #[error("Invalid request: {message}")]
    InvalidRequest { message: String },
    
    /// Server shutdown in progress
    #[error("Server shutting down")]
    Shutdown,
    
    /// Generic server error
    #[error("Server error: {message}")]
    Generic { message: String },
}

impl From<navatron_protocol::error::NorcError> for ServerError {
    fn from(err: navatron_protocol::error::NorcError) -> Self {
        Self::Protocol {
            message: err.to_string(),
        }
    }
}

impl From<navatron_transport::error::TransportError> for ServerError {
    fn from(err: navatron_transport::error::TransportError) -> Self {
        Self::Transport {
            message: err.to_string(),
        }
    }
}

impl ServerError {
    /// Create an initialization error
    pub fn initialization(message: impl Into<String>) -> Self {
        Self::Initialization {
            message: message.into(),
        }
    }
    
    /// Create a startup error
    pub fn startup(message: impl Into<String>) -> Self {
        Self::Startup {
            message: message.into(),
        }
    }
    
    /// Create a connection error
    pub fn connection(message: impl Into<String>) -> Self {
        Self::Connection {
            message: message.into(),
        }
    }
    
    /// Create a session error
    pub fn session(message: impl Into<String>) -> Self {
        Self::Session {
            message: message.into(),
        }
    }
    
    /// Create an authentication error
    pub fn authentication(message: impl Into<String>) -> Self {
        Self::Authentication {
            message: message.into(),
        }
    }
    
    /// Create an authorization error
    pub fn authorization(message: impl Into<String>) -> Self {
        Self::Authorization {
            message: message.into(),
        }
    }
    
    /// Create a routing error
    pub fn routing(message: impl Into<String>) -> Self {
        Self::Routing {
            message: message.into(),
        }
    }
    
    /// Create a federation error
    pub fn federation(message: impl Into<String>) -> Self {
        Self::Federation {
            message: message.into(),
        }
    }
    
    /// Create a storage error
    pub fn storage(message: impl Into<String>) -> Self {
        Self::Storage {
            message: message.into(),
        }
    }
    
    /// Create a configuration error
    pub fn configuration(message: impl Into<String>) -> Self {
        Self::Configuration {
            message: message.into(),
        }
    }
    
    /// Create a resource limit error
    pub fn resource_limit(resource: impl Into<String>, limit: u64) -> Self {
        Self::ResourceLimit {
            resource: resource.into(),
            limit,
        }
    }
    
    /// Create a service unavailable error
    pub fn service_unavailable(message: impl Into<String>) -> Self {
        Self::ServiceUnavailable {
            message: message.into(),
        }
    }
    
    /// Create an invalid request error
    pub fn invalid_request(message: impl Into<String>) -> Self {
        Self::InvalidRequest {
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