//! API key management handlers

use crate::{auth::{ApiKey, AuthContext}, models::*, rbac::Permission, AdminApiState, ApiResult};
use axum::{extract::{Path, State}, Extension, Json};
use chrono::Utc;
use uuid::Uuid;
use validator::Validate;

/// List API keys
pub async fn list_api_keys(
    State(_state): State<AdminApiState>,
    Extension(auth): Extension<AuthContext>,
) -> ApiResult<Json<ApiKeyListResponse>> {
    auth.require_permission(Permission::ApiKeyRead)?;
    
    // TODO: Fetch from key store
    Ok(Json(ApiKeyListResponse {
        keys: vec![],
        total: 0,
    }))
}

/// Create a new API key
pub async fn create_api_key(
    State(_state): State<AdminApiState>,
    Extension(auth): Extension<AuthContext>,
    Json(request): Json<CreateApiKeyRequest>,
) -> ApiResult<Json<ApiKeyResponse>> {
    auth.require_permission(Permission::ApiKeyCreate)?;
    
    // Validate request
    request.validate().map_err(|e| crate::ApiError::Validation(e.to_string()))?;
    
    // Create the API key
    let (api_key, raw_key) = ApiKey::new(
        request.name.clone(),
        request.roles.clone(),
        request.organization_id.clone(),
    );
    
    // TODO: Store in key store
    
    // Return response with the raw key (only time it's exposed)
    Ok(Json(ApiKeyResponse {
        id: api_key.id,
        name: api_key.name,
        roles: api_key.roles,
        organization_id: api_key.organization_id,
        created_at: api_key.created_at,
        expires_at: api_key.expires_at,
        active: api_key.active,
        last_used_at: api_key.last_used_at,
        key: Some(raw_key), // Include the raw key only on creation
    }))
}

/// Revoke an API key
pub async fn revoke_api_key(
    State(_state): State<AdminApiState>,
    Extension(auth): Extension<AuthContext>,
    Path(_key_id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    auth.require_permission(Permission::ApiKeyRevoke)?;
    
    // TODO: Revoke in key store
    Ok(Json(serde_json::json!({"status": "revoked"})))
}

/// Delete an API key
pub async fn delete_api_key(
    State(_state): State<AdminApiState>,
    Extension(auth): Extension<AuthContext>,
    Path(_key_id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    auth.require_permission(Permission::ApiKeyRevoke)?;
    
    // TODO: Delete from key store
    Ok(Json(serde_json::json!({"status": "deleted"})))
}
