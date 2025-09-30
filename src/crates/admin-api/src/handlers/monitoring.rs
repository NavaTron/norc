//! Server monitoring handlers

use crate::{auth::AuthContext, models::*, rbac::Permission, AdminApiState, ApiResult};
use axum::{extract::State, Extension, Json};

/// Get server status
pub async fn get_server_status(
    State(_state): State<AdminApiState>,
    Extension(auth): Extension<AuthContext>,
) -> ApiResult<Json<ServerStatusResponse>> {
    auth.require_permission(Permission::ServerStatus)?;
    todo!("Implement server status")
}

/// Get server metrics
pub async fn get_metrics(
    State(_state): State<AdminApiState>,
    Extension(auth): Extension<AuthContext>,
) -> ApiResult<Json<MetricsResponse>> {
    auth.require_permission(Permission::MetricsRead)?;
    todo!("Implement metrics retrieval")
}
