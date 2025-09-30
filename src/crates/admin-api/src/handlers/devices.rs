//! Device management handlers
//!
//! Implements T-S-F-08.04.01.02: Device lifecycle management capabilities

use crate::{
    auth::AuthContext,
    models::{DeviceListResponse, DeviceResponse, RegisterDeviceRequest},
    rbac::Permission,
    AdminApiState, ApiError, ApiResult,
};
use axum::{
    extract::{Path, State},
    Extension, Json,
};
use norc_persistence::models::Device;
use tracing::info;
use uuid::Uuid;
use validator::Validate;

/// Convert database Device to API DeviceResponse
fn device_to_response(device: Device) -> DeviceResponse {
    // Parse string IDs back to UUIDs for API response
    let id = Uuid::parse_str(&device.id).unwrap_or_else(|_| Uuid::nil());
    let user_id = Uuid::parse_str(&device.user_id).unwrap_or_else(|_| Uuid::nil());
    
    // Hash the public key for the response
    let public_key_hash = blake3::hash(&device.public_key).to_hex().to_string();
    
    DeviceResponse {
        id,
        user_id,
        device_name: device.name,
        device_type: device.device_type,
        public_key_hash,
        enabled: device.status == "active",
        registered_at: device.created_at,
        last_seen_at: device.last_seen,
    }
}

/// List devices for a user
pub async fn list_devices(
    State(state): State<AdminApiState>,
    Extension(auth): Extension<AuthContext>,
) -> ApiResult<Json<DeviceListResponse>> {
    // Check permission
    auth.require_permission(Permission::DeviceRead)?;
    
    info!(
        request_id = %auth.request_id,
        "Listing all devices"
    );
    
    // For now, list all devices across all users
    // In a real implementation, this would be filtered by organization
    let org_id = auth.api_key.organization_id.as_deref().unwrap_or("default");
    
    // Fetch all users in the organization first
    let users = state.user_repo
        .find_by_organization(org_id)
        .await?;
    
    // Then fetch devices for each user
    let mut all_devices = Vec::new();
    for user in users {
        let user_devices = state.device_repo
            .find_by_user(&user.id)
            .await?;
        all_devices.extend(user_devices);
    }
    
    let total = all_devices.len();
    
    let device_responses: Vec<DeviceResponse> = all_devices
        .into_iter()
        .map(device_to_response)
        .collect();
    
    Ok(Json(DeviceListResponse {
        devices: device_responses,
        total,
    }))
}

/// Get device details
pub async fn get_device(
    State(state): State<AdminApiState>,
    Extension(auth): Extension<AuthContext>,
    Path(device_id): Path<Uuid>,
) -> ApiResult<Json<DeviceResponse>> {
    // Check permission
    auth.require_permission(Permission::DeviceRead)?;
    
    info!(
        request_id = %auth.request_id,
        device_id = %device_id,
        "Getting device details"
    );
    
    // Fetch device from database
    let device = state.device_repo
        .find_by_id(&device_id.to_string())
        .await?;
    
    Ok(Json(device_to_response(device)))
}

/// Register a new device
pub async fn register_device(
    State(state): State<AdminApiState>,
    Extension(auth): Extension<AuthContext>,
    Json(request): Json<RegisterDeviceRequest>,
) -> ApiResult<Json<DeviceResponse>> {
    // Check permission
    auth.require_permission(Permission::DeviceRegister)?;
    
    // Validate request
    request.validate().map_err(|e| ApiError::Validation(e.to_string()))?;
    
    info!(
        request_id = %auth.request_id,
        user_id = %request.user_id,
        device_name = %request.device_name,
        "Registering new device"
    );
    
    // Decode public key (assuming it's base64 encoded)
    use base64::Engine as _;
    let public_key = base64::engine::general_purpose::STANDARD
        .decode(&request.public_key)
        .map_err(|e| ApiError::Validation(format!("Invalid public key encoding: {}", e)))?;
    
    // Generate device ID
    let device_id = Uuid::new_v4();
    
    // Create device in database
    let device = state.device_repo
        .create(
            &device_id.to_string(),
            &request.user_id.to_string(),
            &request.device_name,
            &request.device_type,
            &public_key,
        )
        .await?;
    
    // Log audit event
    let event_data = serde_json::json!({
        "device_id": device_id.to_string(),
        "user_id": request.user_id.to_string(),
        "device_name": request.device_name,
    });
    
    state.audit_repo.log(
        "device.register",
        None,
        None,
        Some(&auth.client_ip),
        &event_data,
        "success",
    ).await.ok();
    
    Ok(Json(device_to_response(device)))
}

/// Revoke a device
pub async fn revoke_device(
    State(state): State<AdminApiState>,
    Extension(auth): Extension<AuthContext>,
    Path(device_id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    // Check permission
    auth.require_permission(Permission::DeviceRevoke)?;
    
    info!(
        request_id = %auth.request_id,
        device_id = %device_id,
        "Revoking device"
    );
    
    let device_id_str = device_id.to_string();
    
    // Check if device exists
    let _device = state.device_repo.find_by_id(&device_id_str).await?;
    
    // Revoke device
    state.device_repo.revoke(&device_id_str).await?;
    
    // Log audit event
    let event_data = serde_json::json!({
        "device_id": device_id_str,
    });
    
    state.audit_repo.log(
        "device.revoke",
        None,
        None,
        Some(&auth.client_ip),
        &event_data,
        "success",
    ).await.ok();
    
    Ok(Json(serde_json::json!({
        "status": "revoked",
        "device_id": device_id
    })))
}

