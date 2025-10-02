//! User repository

use crate::error::{PersistenceError, Result};
use crate::models::User;
use chrono::Utc;
use sqlx::SqlitePool;
use uuid::Uuid;

/// User repository for managing user accounts
pub struct UserRepository {
    pool: SqlitePool,
}

impl UserRepository {
    /// Create a new user repository
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Create a new user
    pub async fn create(&self, username: &str, organization_id: &str) -> Result<User> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        let user = sqlx::query_as::<_, User>(
            r#"
            INSERT INTO users (id, username, organization_id, status, created_at, updated_at)
            VALUES (?, ?, ?, 'active', ?, ?)
            RETURNING *
            "#,
        )
        .bind(&id)
        .bind(username)
        .bind(organization_id)
        .bind(now)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;

        Ok(user)
    }

    /// Find user by ID
    pub async fn find_by_id(&self, user_id: &str) -> Result<User> {
        sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = ?")
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| PersistenceError::NotFound(format!("User not found: {}", user_id)))
    }

    /// Find user by username
    pub async fn find_by_username(&self, username: &str) -> Result<User> {
        sqlx::query_as::<_, User>("SELECT * FROM users WHERE username = ?")
            .bind(username)
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| PersistenceError::NotFound(format!("User not found: {}", username)))
    }

    /// Find users by organization
    pub async fn find_by_organization(&self, organization_id: &str) -> Result<Vec<User>> {
        Ok(sqlx::query_as::<_, User>(
            "SELECT * FROM users WHERE organization_id = ? AND status = 'active' ORDER BY username",
        )
        .bind(organization_id)
        .fetch_all(&self.pool)
        .await?)
    }

    /// Update user display name
    pub async fn update_display_name(&self, user_id: &str, display_name: &str) -> Result<()> {
        let result = sqlx::query("UPDATE users SET display_name = ?, updated_at = ? WHERE id = ?")
            .bind(display_name)
            .bind(Utc::now())
            .bind(user_id)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(PersistenceError::NotFound(format!(
                "User not found: {}",
                user_id
            )));
        }

        Ok(())
    }

    /// Update user status
    pub async fn update_status(&self, user_id: &str, status: &str) -> Result<()> {
        let result = sqlx::query("UPDATE users SET status = ?, updated_at = ? WHERE id = ?")
            .bind(status)
            .bind(Utc::now())
            .bind(user_id)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(PersistenceError::NotFound(format!(
                "User not found: {}",
                user_id
            )));
        }

        Ok(())
    }

    /// Delete user (soft delete by setting status to 'deleted')
    pub async fn delete(&self, user_id: &str) -> Result<()> {
        self.update_status(user_id, "deleted").await
    }

    /// Count users by organization
    pub async fn count_by_organization(&self, organization_id: &str) -> Result<i64> {
        let count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM users WHERE organization_id = ? AND status = 'active'",
        )
        .bind(organization_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(count.0)
    }
}
