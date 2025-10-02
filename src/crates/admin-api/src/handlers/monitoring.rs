//! Server monitoring handlers

use crate::{auth::AuthContext, models::*, rbac::Permission, AdminApiState, ApiResult};
use axum::{extract::State, Extension, Json};
use chrono::Utc;

/// Get server status
pub async fn get_server_status(
    State(state): State<AdminApiState>,
    Extension(auth): Extension<AuthContext>,
) -> ApiResult<Json<ServerStatusResponse>> {
    auth.require_permission(Permission::ServerStatus)?;

    // Get actual connection count from ConnectionPool
    let active_connections = state.connection_pool.count().await;

    // TODO: Get federation partner count from FederationRepository when available
    let federation_partners = 0;

    // Get message count from metrics
    let messages_received = state
        .observability
        .metrics
        .messages_received
        .with_label_values(&["all"])
        .get();
    let messages_sent = state
        .observability
        .metrics
        .messages_sent
        .with_label_values(&["all"])
        .get();
    let messages_processed = messages_received + messages_sent;

    // Calculate uptime
    let uptime = crate::handlers::health::get_uptime_seconds();

    Ok(Json(ServerStatusResponse {
        status: "running".to_string(),
        uptime_seconds: uptime,
        connections: active_connections,
        federation_partners,
        messages_processed: messages_processed as u64,
    }))
}

/// Get server metrics in JSON format
pub async fn get_metrics(
    State(state): State<AdminApiState>,
    Extension(auth): Extension<AuthContext>,
) -> ApiResult<Json<MetricsResponse>> {
    auth.require_permission(Permission::MetricsRead)?;

    // Get metrics from ObservabilitySystem
    let metrics = &state.observability.metrics;

    // Connection metrics
    let active_connections = state.connection_pool.count().await;
    let total_connections = metrics.total_connections.get();

    // Message metrics
    let messages_received = metrics.messages_received.with_label_values(&["all"]).get();
    let messages_sent = metrics.messages_sent.with_label_values(&["all"]).get();

    // Federation metrics
    let federation_partners = metrics.federation_partners_connected.get();
    let federation_messages = metrics
        .federation_messages_routed
        .with_label_values(&["all"])
        .get();
    let federation_errors = metrics
        .federation_errors
        .with_label_values(&["all", "all"])
        .get();

    // System metrics
    let cpu_usage = metrics.cpu_usage_percent.get();
    let memory_mb = (metrics.memory_usage_bytes.get() as f64) / (1024.0 * 1024.0);

    Ok(Json(MetricsResponse {
        timestamp: Utc::now(),
        connections: ConnectionMetrics {
            active: active_connections,
            total: total_connections,
            failed: 0, // TODO: Track failed connections
        },
        messages: MessageMetrics {
            sent: messages_sent,
            received: messages_received,
            queued: 0, // TODO: Get queued message count from MessageRouter
            failed: 0, // TODO: Track failed messages
        },
        federation: FederationMetrics {
            partners: federation_partners as usize,
            active_connections: federation_partners as usize,
            messages_routed: federation_messages,
            errors: federation_errors,
        },
        system: SystemMetrics {
            cpu_usage,
            memory_mb: memory_mb as u64,
            disk_usage_mb: 0, // TODO: Track disk usage
            uptime_seconds: crate::handlers::health::get_uptime_seconds(),
        },
    }))
}

/// Get Prometheus metrics in text format
pub async fn get_prometheus_metrics(
    State(state): State<AdminApiState>,
) -> Result<String, crate::ApiError> {
    // Get metrics from ObservabilitySystem
    let metrics_text = state
        .observability
        .metrics
        .gather()
        .map_err(|e| crate::ApiError::Internal(format!("Failed to gather metrics: {}", e)))?;

    Ok(metrics_text)
}
