//! Session repository

use crate::error::{PersistenceError, Result};
use crate::models::Session;
use chrono::{Duration, Utc};
use sqlx::SqlitePool;
use uuid::Uuid;

/// Session repository for managing authentication sessions
pub struct SessionRepository {
    pool: SqlitePool,
}

impl SessionRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Create a new session
    pub async fn create(
        &self,
        user_id: &str,
        device_id: &str,
        token: &str,
        ttl_hours: i64,
    ) -> Result<Session> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let expires_at = now + Duration::hours(ttl_hours);

        let session = sqlx::query_as::<_, Session>(
            r#"INSERT INTO sessions (id, user_id, device_id, token, expires_at, created_at)
               VALUES (?, ?, ?, ?, ?, ?) RETURNING *"#,
        )
        .bind(&id)
        .bind(user_id)
        .bind(device_id)
        .bind(token)
        .bind(expires_at)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;

        Ok(session)
    }

    /// Find session by token
    pub async fn find_by_token(&self, token: &str) -> Result<Session> {
        sqlx::query_as::<_, Session>("SELECT * FROM sessions WHERE token = ? AND expires_at > ?")
            .bind(token)
            .bind(Utc::now())
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| PersistenceError::NotFound("Session not found or expired".to_string()))
    }

    /// Delete session
    pub async fn delete(&self, session_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM sessions WHERE id = ?")
            .bind(session_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Delete all sessions for a device
    pub async fn delete_by_device(&self, device_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM sessions WHERE device_id = ?")
            .bind(device_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Clean up expired sessions
    pub async fn cleanup_expired(&self) -> Result<u64> {
        let result = sqlx::query("DELETE FROM sessions WHERE expires_at <= ?")
            .bind(Utc::now())
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    /// List all active sessions with user and device details
    pub async fn list_active(
        &self,
        limit: Option<usize>,
    ) -> Result<Vec<crate::models::SessionWithDetails>> {
        let limit = limit.unwrap_or(100).min(1000); // Cap at 1000

        let sessions = sqlx::query_as::<_, crate::models::SessionWithDetails>(
            r#"SELECT s.*, u.username, d.name as device_name
               FROM sessions s
               JOIN users u ON s.user_id = u.id
               JOIN devices d ON s.device_id = d.id
               WHERE s.expires_at > ?
               ORDER BY s.created_at DESC
               LIMIT ?"#,
        )
        .bind(Utc::now())
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;

        Ok(sessions)
    }

    /// List sessions by user ID with details
    pub async fn list_by_user(
        &self,
        user_id: &str,
        limit: Option<usize>,
    ) -> Result<Vec<crate::models::SessionWithDetails>> {
        let limit = limit.unwrap_or(100).min(1000);

        let sessions = sqlx::query_as::<_, crate::models::SessionWithDetails>(
            r#"SELECT s.*, u.username, d.name as device_name
               FROM sessions s
               JOIN users u ON s.user_id = u.id
               JOIN devices d ON s.device_id = d.id
               WHERE s.user_id = ? AND s.expires_at > ?
               ORDER BY s.created_at DESC
               LIMIT ?"#,
        )
        .bind(user_id)
        .bind(Utc::now())
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;

        Ok(sessions)
    }

    /// List sessions by device ID with details
    pub async fn list_by_device(
        &self,
        device_id: &str,
        limit: Option<usize>,
    ) -> Result<Vec<crate::models::SessionWithDetails>> {
        let limit = limit.unwrap_or(100).min(1000);

        let sessions = sqlx::query_as::<_, crate::models::SessionWithDetails>(
            r#"SELECT s.*, u.username, d.name as device_name
               FROM sessions s
               JOIN users u ON s.user_id = u.id
               JOIN devices d ON s.device_id = d.id
               WHERE s.device_id = ? AND s.expires_at > ?
               ORDER BY s.created_at DESC
               LIMIT ?"#,
        )
        .bind(device_id)
        .bind(Utc::now())
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;

        Ok(sessions)
    }

    /// Find session by ID with details
    pub async fn find_by_id(&self, session_id: &str) -> Result<crate::models::SessionWithDetails> {
        sqlx::query_as::<_, crate::models::SessionWithDetails>(
            r#"SELECT s.*, u.username, d.name as device_name
               FROM sessions s
               JOIN users u ON s.user_id = u.id
               JOIN devices d ON s.device_id = d.id
               WHERE s.id = ?"#,
        )
        .bind(session_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| PersistenceError::NotFound("Session not found".to_string()))
    }

    /// Delete all sessions for a user (for security response)
    pub async fn delete_by_user(&self, user_id: &str) -> Result<u64> {
        let result = sqlx::query("DELETE FROM sessions WHERE user_id = ?")
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }
}
