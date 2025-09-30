//! Device management handlers

use crate::{auth::AuthContext, models::*, rbac::Permission, AdminApiState, ApiResult};
use axum::{extract::{Path, State}, Extension, Json};
use uuid::Uuid;

/// List devices
pub async fn list_devices(
    State(_state): State<AdminApiState>,
    Extension(auth): Extension<AuthContext>,
) -> ApiResult<Json<DeviceListResponse>> {
    auth.require_permission(Permission::DeviceRead)?;
    Ok(Json(DeviceListResponse { devices: vec![], total: 0 }))
}

/// Register a new device
pub async fn register_device(
    State(_state): State<AdminApiState>,
    Extension(auth): Extension<AuthContext>,
    Json(_request): Json<RegisterDeviceRequest>,
) -> ApiResult<Json<DeviceResponse>> {
    auth.require_permission(Permission::DeviceRegister)?;
    todo!("Implement device registration")
}

/// Revoke a device
pub async fn revoke_device(
    State(_state): State<AdminApiState>,
    Extension(auth): Extension<AuthContext>,
    Path(_device_id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    auth.require_permission(Permission::DeviceRevoke)?;
    todo!("Implement device revocation")
}
