//! Health check handlers

use crate::{models::{HealthResponse, ComponentHealthStatus, ComponentHealth}, ApiResult, AdminApiState};
use axum::{Json, extract::State};
use chrono::Utc;
use std::time::SystemTime;

/// Global server start time for uptime calculation
static START_TIME: std::sync::OnceLock<SystemTime> = std::sync::OnceLock::new();

/// Initialize the server start time
pub fn init_start_time() {
    START_TIME.get_or_init(|| SystemTime::now());
}

/// Get server uptime in seconds
pub fn get_uptime_seconds() -> u64 {
    if let Some(start_time) = START_TIME.get() {
        SystemTime::now()
            .duration_since(*start_time)
            .unwrap_or_default()
            .as_secs()
    } else {
        0
    }
}

/// Health check endpoint with detailed component status
pub async fn health_check(
    State(state): State<AdminApiState>,
) -> ApiResult<Json<HealthResponse>> {
    let now = Utc::now();
    
    // Check database health
    let database_health = check_database_health(&state).await;
    
    // Check transport health (basic check - listener would be in ServerCore)
    let transport_health = ComponentHealth {
        status: "healthy".to_string(),
        message: Some("Transport layer operational".to_string()),
        last_check: now,
    };
    
    // Check federation health (basic check)
    let federation_health = check_federation_health(&state).await;
    
    // Check crypto health (basic check - crypto is stateless)
    let crypto_health = ComponentHealth {
        status: "healthy".to_string(),
        message: Some("Cryptographic functions operational".to_string()),
        last_check: now,
    };
    
    // Determine overall status based on components
    let overall_status = if database_health.status == "healthy" {
        "healthy"
    } else if database_health.status == "degraded" {
        "degraded"
    } else {
        "unhealthy"
    };
    
    Ok(Json(HealthResponse {
        status: overall_status.to_string(),
        timestamp: now,
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: get_uptime_seconds(),
        components: ComponentHealthStatus {
            database: database_health,
            transport: transport_health,
            federation: federation_health,
            crypto: crypto_health,
        },
    }))
}

/// Check database health by attempting a simple query
async fn check_database_health(state: &AdminApiState) -> ComponentHealth {
    let now = Utc::now();
    
    match state.database.pool().acquire().await {
        Ok(_) => ComponentHealth {
            status: "healthy".to_string(),
            message: Some("Database connection pool operational".to_string()),
            last_check: now,
        },
        Err(e) => ComponentHealth {
            status: "unhealthy".to_string(),
            message: Some(format!("Database connection failed: {}", e)),
            last_check: now,
        },
    }
}

/// Check federation health by counting active federation partners
async fn check_federation_health(_state: &AdminApiState) -> ComponentHealth {
    let now = Utc::now();
    
    // TODO: Implement actual federation partner count when repository supports it
    // For now, return healthy status
    ComponentHealth {
        status: "healthy".to_string(),
        message: Some("Federation engine operational".to_string()),
        last_check: now,
    }
}

/// Readiness check endpoint
pub async fn readiness_check(
    State(state): State<AdminApiState>,
) -> ApiResult<Json<HealthResponse>> {
    // For readiness, we just check if database is accessible
    let now = Utc::now();
    let database_health = check_database_health(&state).await;
    
    let status = if database_health.status == "healthy" {
        "ready"
    } else {
        "not_ready"
    };
    
    Ok(Json(HealthResponse {
        status: status.to_string(),
        timestamp: now,
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: get_uptime_seconds(),
        components: ComponentHealthStatus {
            database: database_health,
            transport: ComponentHealth {
                status: "healthy".to_string(),
                message: None,
                last_check: now,
            },
            federation: ComponentHealth {
                status: "healthy".to_string(),
                message: None,
                last_check: now,
            },
            crypto: ComponentHealth {
                status: "healthy".to_string(),
                message: None,
                last_check: now,
            },
        },
    }))
}
