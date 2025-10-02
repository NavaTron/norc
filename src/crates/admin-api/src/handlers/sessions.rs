//! Session management handlers

use crate::{auth::AuthContext, models::*, rbac::Permission, AdminApiState, ApiResult};
use axum::{
    extract::{Query, State},
    Extension, Json,
};
use chrono::Utc;
use uuid::Uuid;

/// List active sessions
pub async fn list_sessions(
    State(state): State<AdminApiState>,
    Extension(auth): Extension<AuthContext>,
    Query(params): Query<SessionQueryParams>,
) -> ApiResult<Json<SessionListResponse>> {
    auth.require_permission(Permission::SessionsRead)?;

    // Query sessions from repository based on filters
    let sessions_result = if let Some(user_id) = params.user_id {
        // Filter by user ID
        state
            .session_repo
            .list_by_user(&user_id.to_string(), Some(params.limit.unwrap_or(50)))
            .await
    } else if let Some(device_id) = params.device_id {
        // Filter by device ID
        state
            .session_repo
            .list_by_device(&device_id.to_string(), Some(params.limit.unwrap_or(50)))
            .await
    } else {
        // Get all active sessions
        state
            .session_repo
            .list_active(Some(params.limit.unwrap_or(50)))
            .await
    };

    let sessions = sessions_result
        .map_err(|e| crate::ApiError::Internal(format!("Failed to query sessions: {}", e)))?;

    // Convert to API response format
    let session_responses: Vec<SessionResponse> = sessions
        .into_iter()
        .filter(|session| {
            // Apply active filter if specified
            if let Some(active) = params.active {
                let is_active = session.expires_at > Utc::now();
                if is_active != active {
                    return false;
                }
            }
            true
        })
        .map(|session| {
            let user_id = Uuid::parse_str(&session.user_id).unwrap_or_default();
            let device_id = Uuid::parse_str(&session.device_id).unwrap_or_default();

            SessionResponse {
                id: session.id,
                user_id,
                device_id,
                username: session.username,
                device_name: session
                    .device_name
                    .unwrap_or_else(|| "Unknown Device".to_string()),
                state: if session.expires_at > Utc::now() {
                    "active".to_string()
                } else {
                    "expired".to_string()
                },
                created_at: session.created_at,
                last_active: session.created_at, // TODO: Track last_active separately
                expires_at: Some(session.expires_at),
                connection_id: None, // TODO: Map session to active connection
                remote_address: session.ip_address,
            }
        })
        .collect();

    let total = session_responses.len();

    Ok(Json(SessionListResponse {
        sessions: session_responses,
        total,
    }))
}

/// Get session details
pub async fn get_session(
    State(state): State<AdminApiState>,
    Extension(auth): Extension<AuthContext>,
    axum::extract::Path(session_id): axum::extract::Path<String>,
) -> ApiResult<Json<SessionResponse>> {
    auth.require_permission(Permission::SessionsRead)?;

    // Get session from repository
    let session = state
        .session_repo
        .find_by_id(&session_id)
        .await
        .map_err(|e| match e {
            norc_persistence::error::PersistenceError::NotFound(_) => {
                crate::ApiError::NotFound("Session not found".to_string())
            }
            _ => crate::ApiError::Internal(format!("Failed to query session: {}", e)),
        })?;

    let user_id = Uuid::parse_str(&session.user_id).unwrap_or_default();
    let device_id = Uuid::parse_str(&session.device_id).unwrap_or_default();

    Ok(Json(SessionResponse {
        id: session.id,
        user_id,
        device_id,
        username: session.username,
        device_name: session
            .device_name
            .unwrap_or_else(|| "Unknown Device".to_string()),
        state: if session.expires_at > Utc::now() {
            "active".to_string()
        } else {
            "expired".to_string()
        },
        created_at: session.created_at,
        last_active: session.created_at, // TODO: Track last_active separately
        expires_at: Some(session.expires_at),
        connection_id: None, // TODO: Map session to active connection
        remote_address: session.ip_address,
    }))
}

/// Revoke a session
pub async fn revoke_session(
    State(state): State<AdminApiState>,
    Extension(auth): Extension<AuthContext>,
    axum::extract::Path(session_id): axum::extract::Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    auth.require_permission(Permission::SessionsManage)?;

    // Delete session from repository
    state
        .session_repo
        .delete(&session_id)
        .await
        .map_err(|e| crate::ApiError::Internal(format!("Failed to revoke session: {}", e)))?;

    Ok(Json(serde_json::json!({
        "session_id": session_id,
        "status": "revoked",
        "message": "Session revoked successfully"
    })))
}

/// Revoke all sessions for a user
pub async fn revoke_user_sessions(
    State(state): State<AdminApiState>,
    Extension(auth): Extension<AuthContext>,
    axum::extract::Path(user_id): axum::extract::Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    auth.require_permission(Permission::SessionsManage)?;

    // Delete all sessions for the user
    let revoked_count = state
        .session_repo
        .delete_by_user(&user_id.to_string())
        .await
        .map_err(|e| crate::ApiError::Internal(format!("Failed to revoke user sessions: {}", e)))?;

    Ok(Json(serde_json::json!({
        "user_id": user_id,
        "revoked_count": revoked_count,
        "message": format!("Revoked {} session(s) for user", revoked_count)
    })))
}
