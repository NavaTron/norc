//! User management handlers
//!
//! Implements T-S-F-08.04.01.01: User lifecycle management capabilities

use crate::{
    auth::AuthContext,
    models::{
        CreateUserRequest, PaginationParams, UpdateUserRequest, UserListResponse, UserResponse,
    },
    rbac::Permission,
    AdminApiState, ApiError, ApiResult,
};
use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use norc_persistence::models::User;
use tracing::info;
use uuid::Uuid;
use validator::Validate;

/// Convert database User to API UserResponse
fn user_to_response(user: User) -> UserResponse {
    // Parse string ID back to UUID for API response
    let id = Uuid::parse_str(&user.id).unwrap_or_else(|_| Uuid::nil());

    UserResponse {
        id,
        username: user.username,
        email: user.email,
        display_name: user.display_name,
        organization_id: user.organization_id,
        enabled: user.status == "active",
        created_at: user.created_at,
        updated_at: user.updated_at,
    }
}

/// List all users
pub async fn list_users(
    State(state): State<AdminApiState>,
    Extension(auth): Extension<AuthContext>,
    Query(_pagination): Query<PaginationParams>,
) -> ApiResult<Json<UserListResponse>> {
    // Check permission
    auth.require_permission(Permission::UserRead)?;

    info!(
        request_id = %auth.request_id,
        "Listing users for organization"
    );

    // Fetch users from database by organization
    // Note: Current repository doesn't have pagination, using find_by_organization
    let org_id = auth.api_key.organization_id.as_deref().unwrap_or("default");

    let users = state.user_repo.find_by_organization(org_id).await?;

    let total = users.len();

    let user_responses: Vec<UserResponse> = users.into_iter().map(user_to_response).collect();

    Ok(Json(UserListResponse {
        users: user_responses,
        total,
        page: 1,
        page_size: total,
    }))
}

/// Get user by ID
pub async fn get_user(
    State(state): State<AdminApiState>,
    Extension(auth): Extension<AuthContext>,
    Path(user_id): Path<Uuid>,
) -> ApiResult<Json<UserResponse>> {
    // Check permission
    auth.require_permission(Permission::UserRead)?;

    info!(
        request_id = %auth.request_id,
        user_id = %user_id,
        "Getting user details"
    );

    // Fetch user from database
    let user = state.user_repo.find_by_id(&user_id.to_string()).await?;

    Ok(Json(user_to_response(user)))
}

/// Create a new user
pub async fn create_user(
    State(state): State<AdminApiState>,
    Extension(auth): Extension<AuthContext>,
    Json(request): Json<CreateUserRequest>,
) -> ApiResult<Json<UserResponse>> {
    // Check permission
    auth.require_permission(Permission::UserCreate)?;

    // Validate request
    request
        .validate()
        .map_err(|e| ApiError::Validation(e.to_string()))?;

    info!(
        request_id = %auth.request_id,
        username = %request.username,
        organization_id = %request.organization_id,
        "Creating new user"
    );

    // Check if username already exists
    if state
        .user_repo
        .find_by_username(&request.username)
        .await
        .is_ok()
    {
        return Err(ApiError::Conflict(format!(
            "User with username '{}' already exists",
            request.username
        )));
    }

    // Create user in database
    let user = state
        .user_repo
        .create(&request.username, &request.organization_id)
        .await?;

    // Update optional fields if provided
    if let Some(display_name) = &request.display_name {
        state
            .user_repo
            .update_display_name(&user.id, display_name)
            .await?;
    }

    // Log audit event
    let event_data = serde_json::json!({
        "username": request.username,
        "organization_id": request.organization_id,
    });

    state
        .audit_repo
        .log(
            "user.create",
            None,
            None,
            Some(&auth.client_ip),
            &event_data,
            "success",
        )
        .await
        .ok(); // Don't fail if audit logging fails

    // Fetch the updated user
    let user = state.user_repo.find_by_id(&user.id).await?;

    Ok(Json(user_to_response(user)))
}

/// Update an existing user
pub async fn update_user(
    State(state): State<AdminApiState>,
    Extension(auth): Extension<AuthContext>,
    Path(user_id): Path<Uuid>,
    Json(request): Json<UpdateUserRequest>,
) -> ApiResult<Json<UserResponse>> {
    // Check permission
    auth.require_permission(Permission::UserUpdate)?;

    // Validate request
    request
        .validate()
        .map_err(|e| ApiError::Validation(e.to_string()))?;

    info!(
        request_id = %auth.request_id,
        user_id = %user_id,
        "Updating user"
    );

    let user_id_str = user_id.to_string();

    // Fetch existing user to verify it exists
    let _user = state.user_repo.find_by_id(&user_id_str).await?;

    // Update display name if provided
    if let Some(display_name) = &request.display_name {
        state
            .user_repo
            .update_display_name(&user_id_str, display_name)
            .await?;
    }

    // Update status based on enabled flag
    if let Some(enabled) = request.enabled {
        let status = if enabled { "active" } else { "suspended" };
        state.user_repo.update_status(&user_id_str, status).await?;
    }

    // Log audit event
    let event_data = serde_json::json!({
        "user_id": user_id_str,
        "changes": request,
    });

    state
        .audit_repo
        .log(
            "user.update",
            None,
            None,
            Some(&auth.client_ip),
            &event_data,
            "success",
        )
        .await
        .ok();

    // Fetch updated user
    let user = state.user_repo.find_by_id(&user_id_str).await?;

    Ok(Json(user_to_response(user)))
}

/// Delete a user
pub async fn delete_user(
    State(state): State<AdminApiState>,
    Extension(auth): Extension<AuthContext>,
    Path(user_id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    // Check permission
    auth.require_permission(Permission::UserDelete)?;

    info!(
        request_id = %auth.request_id,
        user_id = %user_id,
        "Deleting user"
    );

    let user_id_str = user_id.to_string();

    // Check if user exists
    let _user = state.user_repo.find_by_id(&user_id_str).await?;

    // Delete user (soft delete)
    state.user_repo.delete(&user_id_str).await?;

    // Log audit event
    let event_data = serde_json::json!({
        "user_id": user_id_str,
    });

    state
        .audit_repo
        .log(
            "user.delete",
            None,
            None,
            Some(&auth.client_ip),
            &event_data,
            "success",
        )
        .await
        .ok();

    Ok(Json(serde_json::json!({
        "status": "deleted",
        "user_id": user_id
    })))
}
