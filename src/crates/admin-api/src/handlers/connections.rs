//! Connection management handlers

use crate::{auth::AuthContext, models::*, rbac::Permission, AdminApiState, ApiResult};
use axum::{extract::{State, Query}, Extension, Json};
use chrono::Utc;

/// List active connections
pub async fn list_connections(
    State(state): State<AdminApiState>,
    Extension(auth): Extension<AuthContext>,
    Query(params): Query<ConnectionQueryParams>,
) -> ApiResult<Json<ConnectionListResponse>> {
    auth.require_permission(Permission::ConnectionsRead)?;
    
    // Get all active connections from ConnectionPool
    let connections = state.connection_pool.get_all().await;
    
    // Convert ConnectionInfo to ConnectionResponse and apply filters
    let filtered: Vec<ConnectionResponse> = connections
        .into_iter()
        .filter_map(|info| {
            // Apply state filter (all connections are "active" for now)
            if let Some(ref state_filter) = params.state {
                if state_filter != "active" {
                    return None;
                }
            }
            
            // Apply user_id filter
            if let Some(ref user_filter) = params.user_id {
                if let Some(ref user_id) = info.user_id {
                    if let Ok(uuid) = uuid::Uuid::parse_str(user_id) {
                        if uuid != *user_filter {
                            return None;
                        }
                    }
                } else {
                    return None;
                }
            }
            
            // Apply device_id filter
            if let Some(ref device_filter) = params.device_id {
                if let Some(ref device_id) = info.device_id {
                    if let Ok(uuid) = uuid::Uuid::parse_str(device_id) {
                        if uuid != *device_filter {
                            return None;
                        }
                    }
                } else {
                    return None;
                }
            }
            
            // Convert user_id and device_id strings to UUIDs
            let user_id_uuid = info.user_id.as_ref()
                .and_then(|id| uuid::Uuid::parse_str(id).ok());
            let device_id_uuid = info.device_id.as_ref()
                .and_then(|id| uuid::Uuid::parse_str(id).ok());
            
            // Calculate timestamps by going back from now
            let now = Utc::now();
            let connected_duration = info.established_at.elapsed();
            let last_activity_duration = info.last_activity.elapsed();
            
            Some(ConnectionResponse {
                id: format!("conn-{}", info.id),
                user_id: user_id_uuid,
                device_id: device_id_uuid,
                remote_address: info.remote_addr.to_string(),
                state: "active".to_string(),
                protocol: "tcp".to_string(), // TODO: Get actual protocol from connection
                connected_at: now - chrono::Duration::from_std(connected_duration).unwrap_or_default(),
                last_activity: now - chrono::Duration::from_std(last_activity_duration).unwrap_or_default(),
                bytes_sent: info.bytes_sent,
                bytes_received: info.bytes_received,
                messages_sent: info.messages_sent,
                messages_received: info.messages_received,
            })
        })
        .take(params.limit.unwrap_or(50))
        .collect();
    
    let total = filtered.len();
    
    Ok(Json(ConnectionListResponse {
        connections: filtered,
        total,
    }))
}

/// Get connection details
pub async fn get_connection(
    State(state): State<AdminApiState>,
    Extension(auth): Extension<AuthContext>,
    axum::extract::Path(connection_id): axum::extract::Path<String>,
) -> ApiResult<Json<ConnectionResponse>> {
    auth.require_permission(Permission::ConnectionsRead)?;
    
    // Parse connection ID from "conn-{id}" format
    let id: u64 = connection_id
        .strip_prefix("conn-")
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| crate::ApiError::BadRequest("Invalid connection ID format".to_string()))?;
    
    // Get connection info from pool
    let info = state.connection_pool
        .get_info(id)
        .await
        .ok_or_else(|| crate::ApiError::NotFound("Connection not found".to_string()))?;
    
    // Convert user_id and device_id strings to UUIDs
    let user_id_uuid = info.user_id.as_ref()
        .and_then(|id| uuid::Uuid::parse_str(id).ok());
    let device_id_uuid = info.device_id.as_ref()
        .and_then(|id| uuid::Uuid::parse_str(id).ok());
    
    // Calculate timestamps by going back from now
    let now = Utc::now();
    let connected_duration = info.established_at.elapsed();
    let last_activity_duration = info.last_activity.elapsed();
    
    Ok(Json(ConnectionResponse {
        id: connection_id,
        user_id: user_id_uuid,
        device_id: device_id_uuid,
        remote_address: info.remote_addr.to_string(),
        state: "active".to_string(),
        protocol: "tcp".to_string(), // TODO: Get actual protocol
        connected_at: now - chrono::Duration::from_std(connected_duration).unwrap_or_default(),
        last_activity: now - chrono::Duration::from_std(last_activity_duration).unwrap_or_default(),
        bytes_sent: info.bytes_sent,
        bytes_received: info.bytes_received,
        messages_sent: info.messages_sent,
        messages_received: info.messages_received,
    }))
}

/// Terminate a connection
pub async fn terminate_connection(
    State(state): State<AdminApiState>,
    Extension(auth): Extension<AuthContext>,
    axum::extract::Path(connection_id): axum::extract::Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    auth.require_permission(Permission::ConnectionsManage)?;
    
    // Parse connection ID from "conn-{id}" format
    let id: u64 = connection_id
        .strip_prefix("conn-")
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| crate::ApiError::BadRequest("Invalid connection ID format".to_string()))?;
    
    // Verify connection exists before trying to terminate
    if state.connection_pool.get_info(id).await.is_none() {
        return Err(crate::ApiError::NotFound("Connection not found".to_string()));
    }
    
    // Terminate the connection
    state.connection_pool.unregister(id).await;
    
    Ok(Json(serde_json::json!({
        "connection_id": connection_id,
        "status": "terminated",
        "message": "Connection terminated successfully"
    })))
}
