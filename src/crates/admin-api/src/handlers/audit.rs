//! Audit log query handlers

use crate::{auth::AuthContext, models::*, rbac::Permission, AdminApiState, ApiResult};
use axum::{
    extract::{Query, State},
    Extension, Json,
};

/// Query audit logs
pub async fn query_audit_logs(
    State(_state): State<AdminApiState>,
    Extension(auth): Extension<AuthContext>,
    Query(_query): Query<AuditLogQueryRequest>,
) -> ApiResult<Json<AuditLogListResponse>> {
    auth.require_permission(Permission::AuditRead)?;
    todo!("Implement audit log query")
}

/// Export audit logs
pub async fn export_audit_logs(
    State(_state): State<AdminApiState>,
    Extension(auth): Extension<AuthContext>,
    Query(_query): Query<AuditLogQueryRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    auth.require_permission(Permission::AuditExport)?;
    todo!("Implement audit log export")
}
