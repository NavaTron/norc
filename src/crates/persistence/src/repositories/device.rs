//! Device repository

use crate::error::{PersistenceError, Result};
use crate::models::Device;
use chrono::Utc;
use sqlx::SqlitePool;

/// Device repository for managing user devices
pub struct DeviceRepository {
    pool: SqlitePool,
}

impl DeviceRepository {
    /// Create a new device repository
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Register a new device
    pub async fn create(
        &self,
        device_id: &str,
        user_id: &str,
        name: &str,
        device_type: &str,
        public_key: &[u8],
    ) -> Result<Device> {
        let now = Utc::now();

        let device = sqlx::query_as::<_, Device>(
            r#"
            INSERT INTO devices (id, user_id, name, device_type, public_key, status, created_at)
            VALUES (?, ?, ?, ?, ?, 'active', ?)
            RETURNING *
            "#,
        )
        .bind(device_id)
        .bind(user_id)
        .bind(name)
        .bind(device_type)
        .bind(public_key)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;

        Ok(device)
    }

    /// Find device by ID
    pub async fn find_by_id(&self, device_id: &str) -> Result<Device> {
        sqlx::query_as::<_, Device>("SELECT * FROM devices WHERE id = ?")
            .bind(device_id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| PersistenceError::NotFound(format!("Device not found: {}", device_id)))
    }

    /// Find devices by user
    pub async fn find_by_user(&self, user_id: &str) -> Result<Vec<Device>> {
        Ok(sqlx::query_as::<_, Device>(
            "SELECT * FROM devices WHERE user_id = ? AND status = 'active' ORDER BY created_at DESC",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?)
    }

    /// Update device last seen
    pub async fn update_last_seen(&self, device_id: &str) -> Result<()> {
        let result = sqlx::query("UPDATE devices SET last_seen = ? WHERE id = ?")
            .bind(Utc::now())
            .bind(device_id)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(PersistenceError::NotFound(format!("Device not found: {}", device_id)));
        }

        Ok(())
    }

    /// Revoke device
    pub async fn revoke(&self, device_id: &str) -> Result<()> {
        let result = sqlx::query("UPDATE devices SET status = 'revoked' WHERE id = ?")
            .bind(device_id)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(PersistenceError::NotFound(format!("Device not found: {}", device_id)));
        }

        Ok(())
    }

    /// Get device public key
    pub async fn get_public_key(&self, device_id: &str) -> Result<Vec<u8>> {
        let device = self.find_by_id(device_id).await?;
        Ok(device.public_key)
    }

    /// Verify device is active
    pub async fn is_active(&self, device_id: &str) -> Result<bool> {
        let count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM devices WHERE id = ? AND status = 'active'",
        )
        .bind(device_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(count.0 > 0)
    }
}
