//! Message repository for offline message storage

use crate::error::Result;
use crate::models::PersistedMessage;
use chrono::{Duration, Utc};
use sqlx::SqlitePool;
use uuid::Uuid;

/// Message repository for offline delivery
pub struct MessageRepository {
    pool: SqlitePool,
}

impl MessageRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Store message for offline delivery
    pub async fn store(
        &self,
        sender_device_id: &str,
        recipient_device_id: &str,
        payload: &[u8],
        priority: i32,
        ttl_hours: i64,
    ) -> Result<String> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let expires_at = now + Duration::hours(ttl_hours);

        sqlx::query(
            r#"INSERT INTO persisted_messages 
               (id, sender_device_id, recipient_device_id, payload, priority, status, attempts, created_at, expires_at)
               VALUES (?, ?, ?, ?, ?, 'pending', 0, ?, ?)"#,
        )
        .bind(&id)
        .bind(sender_device_id)
        .bind(recipient_device_id)
        .bind(payload)
        .bind(priority)
        .bind(now)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;

        Ok(id)
    }

    /// Get pending messages for a device
    pub async fn get_pending(&self, recipient_device_id: &str) -> Result<Vec<PersistedMessage>> {
        Ok(sqlx::query_as::<_, PersistedMessage>(
            "SELECT * FROM persisted_messages WHERE recipient_device_id = ? AND status = 'pending' AND expires_at > ? ORDER BY priority DESC, created_at ASC",
        )
        .bind(recipient_device_id)
        .bind(Utc::now())
        .fetch_all(&self.pool)
        .await?)
    }

    /// Mark message as delivered
    pub async fn mark_delivered(&self, message_id: &str) -> Result<()> {
        sqlx::query(
            "UPDATE persisted_messages SET status = 'delivered', delivered_at = ? WHERE id = ?",
        )
        .bind(Utc::now())
        .bind(message_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Increment delivery attempts
    pub async fn increment_attempts(&self, message_id: &str) -> Result<()> {
        sqlx::query("UPDATE persisted_messages SET attempts = attempts + 1 WHERE id = ?")
            .bind(message_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Delete expired messages
    pub async fn cleanup_expired(&self) -> Result<u64> {
        let result = sqlx::query("DELETE FROM persisted_messages WHERE expires_at <= ?")
            .bind(Utc::now())
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }
}
