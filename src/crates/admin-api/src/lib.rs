//! NORC Administrative API
//!
//! Provides a secure REST API for server administration and management.
//! Implements SERVER_REQUIREMENTS Epic E-08 (Administrative Interfaces).
//!
//! ## Security Features
//! - API key authentication with cryptographic validation
//! - Mutual TLS (mTLS) support for high-security environments
//! - Role-Based Access Control (RBAC) with fine-grained permissions
//! - Rate limiting and abuse protection
//! - Comprehensive audit logging of all administrative actions
//! - Request signing and replay protection
//!
//! ## API Modules
//! - User and device management (F-08.04)
//! - Configuration management with validation and rollback (F-08.03)
//! - Server monitoring and health checks
//! - Federation partner management
//! - Audit log queries and compliance reporting

pub mod auth;
pub mod handlers;
pub mod models;
pub mod routes;
pub mod middleware;
pub mod error;
pub mod rbac;

pub use error::{ApiError, ApiResult};
pub use auth::{ApiKey, AuthContext};
pub use rbac::{Role, Permission};

use axum::Router;
use std::sync::Arc;
use norc_persistence::{
    Database,
    repositories::{
        UserRepository, DeviceRepository, SessionRepository,
        MessageRepository, FederationRepository, PresenceRepository,
        AuditRepository,
    },
};
use norc_config::ServerConfig;
use norc_server_core::{ConnectionPool, MessageRouter, ObservabilitySystem};

/// Admin API server configuration
#[derive(Debug, Clone)]
pub struct AdminApiConfig {
    /// Listen address for admin API
    pub bind_address: String,
    
    /// Enable mTLS for admin API
    pub enable_mtls: bool,
    
    /// Path to client CA certificates for mTLS
    pub client_ca_path: Option<String>,
    
    /// API key storage path
    pub api_keys_path: String,
    
    /// Session timeout in seconds
    pub session_timeout_secs: u64,
    
    /// Rate limit: requests per minute per API key
    pub rate_limit_per_minute: u32,
    
    /// Enable CORS (use with caution in production)
    pub enable_cors: bool,
}

impl Default for AdminApiConfig {
    fn default() -> Self {
        Self {
            bind_address: "127.0.0.1:8443".to_string(),
            enable_mtls: true,
            client_ca_path: None,
            api_keys_path: "/etc/norc/api-keys.json".to_string(),
            session_timeout_secs: 3600, // 1 hour
            rate_limit_per_minute: 100,
            enable_cors: false,
        }
    }
}

/// Admin API server state
#[derive(Clone)]
pub struct AdminApiState {
    pub database: Arc<Database>,
    pub config: AdminApiConfig,
    pub server_config: Arc<ServerConfig>,
    pub user_repo: Arc<UserRepository>,
    pub device_repo: Arc<DeviceRepository>,
    pub session_repo: Arc<SessionRepository>,
    pub message_repo: Arc<MessageRepository>,
    pub federation_repo: Arc<FederationRepository>,
    pub presence_repo: Arc<PresenceRepository>,
    pub audit_repo: Arc<AuditRepository>,
    
    // Server runtime components
    pub connection_pool: Arc<ConnectionPool>,
    pub message_router: Arc<MessageRouter>,
    pub observability: Arc<ObservabilitySystem>,
}

impl AdminApiState {
    /// Create a new AdminApiState from database, configs, and server components
    pub fn new(
        database: Arc<Database>,
        config: AdminApiConfig,
        server_config: Arc<ServerConfig>,
        connection_pool: Arc<ConnectionPool>,
        message_router: Arc<MessageRouter>,
        observability: Arc<ObservabilitySystem>,
    ) -> Self {
        let pool = database.pool().clone();
        
        Self {
            database,
            config,
            server_config,
            user_repo: Arc::new(UserRepository::new(pool.clone())),
            device_repo: Arc::new(DeviceRepository::new(pool.clone())),
            session_repo: Arc::new(SessionRepository::new(pool.clone())),
            message_repo: Arc::new(MessageRepository::new(pool.clone())),
            federation_repo: Arc::new(FederationRepository::new(pool.clone())),
            presence_repo: Arc::new(PresenceRepository::new(pool.clone())),
            audit_repo: Arc::new(AuditRepository::new(pool)),
            connection_pool,
            message_router,
            observability,
        }
    }
}

/// Build the admin API router
pub fn build_router(state: AdminApiState) -> Router {
    routes::build_routes(state)
}
