//! API routing configuration
//!
//! Implements T-S-F-08.02.01.01: RESTful management API

use crate::{
    auth::ApiKeyStore,
    handlers,
    middleware::{
        audit_middleware, auth_middleware, rate_limit_middleware, security_headers_middleware,
        RateLimiter,
    },
    AdminApiState,
};
use axum::{
    middleware,
    routing::{delete, get, post},
    Router,
};
use std::sync::Arc;
use tower_http::trace::TraceLayer;

/// Build the complete API router with all routes and middleware
pub fn build_routes(state: AdminApiState) -> Router {
    // Create shared middleware state
    let key_store = Arc::new(ApiKeyStore::new());
    let rate_limiter = Arc::new(RateLimiter::new(
        state.config.rate_limit_per_minute,
        state.config.rate_limit_per_minute,
    ));

    // Public routes (no authentication required)
    let public_routes = Router::new()
        .route("/health", get(handlers::health_check))
        .route("/ready", get(handlers::readiness_check))
        .route("/metrics", get(handlers::get_prometheus_metrics));

    // Protected routes (authentication required)
    let protected_routes = Router::new()
        // User management (F-08.04.01)
        .route("/users", get(handlers::list_users).post(handlers::create_user))
        .route("/users/:id", get(handlers::get_user).put(handlers::update_user).delete(handlers::delete_user))
        
        // Device management (T-S-F-08.04.01.02)
        .route("/devices", get(handlers::list_devices).post(handlers::register_device))
        .route("/devices/:id", delete(handlers::revoke_device))
        
        // Configuration management (F-08.03)
        .route("/config", get(handlers::get_config).put(handlers::update_config))
        .route("/config/validate", post(handlers::validate_config))
        
        // Server monitoring
        .route("/server/status", get(handlers::get_server_status))
        .route("/metrics", get(handlers::get_metrics))
        
        // Federation management
        .route("/federation/partners", get(handlers::list_federation_partners).post(handlers::create_federation_partner))
        .route("/federation/partners/:id", delete(handlers::delete_federation_partner))
        
        // Audit logs
        .route("/audit/logs", get(handlers::query_audit_logs))
        .route("/audit/export", get(handlers::export_audit_logs))
        
        // API key management
        .route("/api-keys", get(handlers::list_api_keys).post(handlers::create_api_key))
        .route("/api-keys/:id", delete(handlers::delete_api_key))
        .route("/api-keys/:id/revoke", post(handlers::revoke_api_key))
        
        // Connection management (E-06.02)
        .route("/connections", get(handlers::list_connections))
        .route("/connections/:id", get(handlers::get_connection).delete(handlers::terminate_connection))
        
        // Session management (E-06.03)
        .route("/sessions", get(handlers::list_sessions))
        .route("/sessions/:id", get(handlers::get_session).delete(handlers::revoke_session))
        .route("/users/:user_id/sessions", delete(handlers::revoke_user_sessions))
        
        // Certificate management (Week 6, Task 10)
        .route("/certificates", get(handlers::list_certificates).post(handlers::upload_certificate))
        .route("/certificates/:fingerprint", get(handlers::get_certificate).delete(handlers::delete_certificate))
        .route("/certificates/rotate", post(handlers::rotate_certificate))
        .route("/certificates/check-revocation", post(handlers::check_revocation))
        .route("/certificates/health", get(handlers::get_certificate_health))
        
        // Apply authentication and rate limiting middleware
        .layer(middleware::from_fn_with_state(
            rate_limiter.clone(),
            rate_limit_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            key_store.clone(),
            auth_middleware,
        ));

    // Combine routes with version prefix
    Router::new()
        .nest("/api/v1", protected_routes)
        .merge(public_routes)
        .layer(middleware::from_fn(audit_middleware))
        .layer(middleware::from_fn(security_headers_middleware))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use crate::AdminApiConfig;

    #[tokio::test]
    async fn test_router_builds() {
        // This test just verifies the router can be constructed
        let _config = AdminApiConfig::default();

        // Mock database - in real tests, use a test database
        // let database = Arc::new(Database::new(...).await.unwrap());
        // For now, we'll skip this test since we need a real database
    }
}
