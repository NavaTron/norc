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
use norc_persistence::Database;

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
}

/// Build the admin API router
pub fn build_router(state: AdminApiState) -> Router {
    routes::build_routes(state)
}
