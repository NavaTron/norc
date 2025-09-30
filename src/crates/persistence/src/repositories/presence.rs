//! Presence repository

use crate::error::Result;
use crate::models::Presence;
use chrono::Utc;
use sqlx::SqlitePool;

/// Presence repository for managing user presence
pub struct PresenceRepository {
    pool: SqlitePool,
}

impl PresenceRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Update user presence
    pub async fn update(
        &self,
        user_id: &str,
        device_id: &str,
        status: &str,
        status_message: Option<&str>,
    ) -> Result<()> {
        let now = Utc::now();

        sqlx::query(
            r#"INSERT OR REPLACE INTO presence (user_id, device_id, status, status_message, last_activity, updated_at)
               VALUES (?, ?, ?, ?, ?, ?)"#,
        )
        .bind(user_id)
        .bind(device_id)
        .bind(status)
        .bind(status_message)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get user presence
    pub async fn get(&self, user_id: &str) -> Result<Vec<Presence>> {
        Ok(sqlx::query_as::<_, Presence>(
            "SELECT * FROM presence WHERE user_id = ? ORDER BY last_activity DESC",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?)
    }

    /// Get presence for multiple users
    pub async fn get_bulk(&self, user_ids: &[String]) -> Result<Vec<Presence>> {
        // Build query with IN clause
        let placeholders = user_ids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        let query_str = format!(
            "SELECT * FROM presence WHERE user_id IN ({}) ORDER BY user_id, last_activity DESC",
            placeholders
        );

        let mut query = sqlx::query_as::<_, Presence>(&query_str);
        for user_id in user_ids {
            query = query.bind(user_id);
        }

        Ok(query.fetch_all(&self.pool).await?)
    }

    /// Set user offline
    pub async fn set_offline(&self, user_id: &str, device_id: &str) -> Result<()> {
        self.update(user_id, device_id, "offline", None).await
    }
}
