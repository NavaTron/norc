//! Health check handlers

use crate::{models::HealthResponse, ApiResult};
use axum::Json;
use chrono::Utc;

/// Health check endpoint
pub async fn health_check() -> ApiResult<Json<HealthResponse>> {
    Ok(Json(HealthResponse {
        status: "healthy".to_string(),
        timestamp: Utc::now(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: 0, // TODO: Track actual uptime
    }))
}

/// Readiness check endpoint
pub async fn readiness_check() -> ApiResult<Json<HealthResponse>> {
    // TODO: Check if database is accessible, services are ready, etc.
    Ok(Json(HealthResponse {
        status: "ready".to_string(),
        timestamp: Utc::now(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: 0,
    }))
}
