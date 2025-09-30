//! Server monitoring handlers

use crate::{auth::AuthContext, models::*, rbac::Permission, AdminApiState, ApiResult};
use axum::{extract::State, Extension, Json};
use chrono::Utc;

/// Get server status
pub async fn get_server_status(
    State(_state): State<AdminApiState>,
    Extension(auth): Extension<AuthContext>,
) -> ApiResult<Json<ServerStatusResponse>> {
    auth.require_permission(Permission::ServerStatus)?;
    
    // TODO: Get actual connection count from ConnectionPool when available
    let active_connections = 0;
    
    // TODO: Get federation partner count from FederationRepository when available
    let federation_partners = 0;
    
    // TODO: Get message count from metrics when available
    let messages_processed = 0;
    
    // Calculate uptime
    let uptime = crate::handlers::health::get_uptime_seconds();
    
    Ok(Json(ServerStatusResponse {
        status: "running".to_string(),
        uptime_seconds: uptime,
        connections: active_connections,
        federation_partners,
        messages_processed,
    }))
}

/// Get server metrics in JSON format
pub async fn get_metrics(
    State(_state): State<AdminApiState>,
    Extension(auth): Extension<AuthContext>,
) -> ApiResult<Json<MetricsResponse>> {
    auth.require_permission(Permission::MetricsRead)?;
    
    // TODO: Integrate with actual Metrics system from observability
    // For now, return mock data structure
    
    Ok(Json(MetricsResponse {
        timestamp: Utc::now(),
        connections: ConnectionMetrics {
            active: 0,
            total: 0,
            failed: 0,
        },
        messages: MessageMetrics {
            sent: 0,
            received: 0,
            queued: 0,
            failed: 0,
        },
        federation: FederationMetrics {
            partners: 0,
            active_connections: 0,
            messages_routed: 0,
            errors: 0,
        },
        system: SystemMetrics {
            cpu_usage: 0.0,
            memory_mb: 0,
            disk_usage_mb: 0,
            uptime_seconds: crate::handlers::health::get_uptime_seconds(),
        },
    }))
}

/// Get Prometheus metrics in text format
pub async fn get_prometheus_metrics(
    State(_state): State<AdminApiState>,
) -> Result<String, crate::ApiError> {
    // TODO: Integrate with Metrics::gather() from observability system
    // For now, return basic Prometheus format
    
    let uptime = crate::handlers::health::get_uptime_seconds();
    
    let metrics = format!(
        r#"# HELP norc_uptime_seconds Server uptime in seconds
# TYPE norc_uptime_seconds gauge
norc_uptime_seconds {}

# HELP norc_active_connections Number of currently active client connections
# TYPE norc_active_connections gauge
norc_active_connections 0

# HELP norc_total_connections Total number of client connections since startup
# TYPE norc_total_connections counter
norc_total_connections 0

# HELP norc_messages_received_total Total number of messages received
# TYPE norc_messages_received_total counter
norc_messages_received_total 0

# HELP norc_messages_sent_total Total number of messages sent
# TYPE norc_messages_sent_total counter
norc_messages_sent_total 0

# HELP norc_federation_partners_connected Number of federation partners currently connected
# TYPE norc_federation_partners_connected gauge
norc_federation_partners_connected 0
"#,
        uptime
    );
    
    Ok(metrics)
}
