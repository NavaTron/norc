//! Audit log repository

use crate::error::Result;
use crate::models::AuditLog;
use chrono::Utc;
use serde_json::Value;
use sqlx::SqlitePool;
use uuid::Uuid;

/// Audit repository for security audit logging
pub struct AuditRepository {
    pool: SqlitePool,
}

impl AuditRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Log an audit event
    pub async fn log(
        &self,
        event_type: &str,
        user_id: Option<&str>,
        device_id: Option<&str>,
        ip_address: Option<&str>,
        event_data: &Value,
        result: &str,
    ) -> Result<()> {
        let id = Uuid::new_v4().to_string();
        let event_data_str = serde_json::to_string(event_data)?;

        sqlx::query(
            r#"INSERT INTO audit_log (id, event_type, user_id, device_id, ip_address, event_data, result, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)"#,
        )
        .bind(&id)
        .bind(event_type)
        .bind(user_id)
        .bind(device_id)
        .bind(ip_address)
        .bind(&event_data_str)
        .bind(result)
        .bind(Utc::now())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Query audit logs
    pub async fn query(&self, limit: i64, offset: i64) -> Result<Vec<AuditLog>> {
        Ok(sqlx::query_as::<_, AuditLog>(
            "SELECT * FROM audit_log ORDER BY created_at DESC LIMIT ? OFFSET ?",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?)
    }

    /// Query audit logs by user
    pub async fn query_by_user(&self, user_id: &str, limit: i64) -> Result<Vec<AuditLog>> {
        Ok(sqlx::query_as::<_, AuditLog>(
            "SELECT * FROM audit_log WHERE user_id = ? ORDER BY created_at DESC LIMIT ?",
        )
        .bind(user_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?)
    }
}
