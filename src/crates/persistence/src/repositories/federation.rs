//! Federation trust repository

use crate::error::{PersistenceError, Result};
use crate::models::FederationTrust;
use chrono::Utc;
use sqlx::SqlitePool;
use uuid::Uuid;

/// Federation repository for managing trust relationships
pub struct FederationRepository {
    pool: SqlitePool,
}

impl FederationRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Create federation trust relationship
    pub async fn create(
        &self,
        organization_id: &str,
        server_address: &str,
        trust_level: &str,
        cert_fingerprint: &str,
    ) -> Result<FederationTrust> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        let trust = sqlx::query_as::<_, FederationTrust>(
            r#"INSERT INTO federation_trust (id, organization_id, server_address, trust_level, cert_fingerprint, status, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, 'active', ?, ?) RETURNING *"#,
        )
        .bind(&id)
        .bind(organization_id)
        .bind(server_address)
        .bind(trust_level)
        .bind(cert_fingerprint)
        .bind(now)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;

        Ok(trust)
    }

    /// Find federation trust by organization ID
    pub async fn find_by_organization(&self, organization_id: &str) -> Result<FederationTrust> {
        sqlx::query_as::<_, FederationTrust>(
            "SELECT * FROM federation_trust WHERE organization_id = ? AND status = 'active'",
        )
        .bind(organization_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| PersistenceError::NotFound(format!("Federation trust not found: {}", organization_id)))
    }

    /// Get all active federation partners
    pub async fn get_all_active(&self) -> Result<Vec<FederationTrust>> {
        Ok(sqlx::query_as::<_, FederationTrust>(
            "SELECT * FROM federation_trust WHERE status = 'active' ORDER BY organization_id",
        )
        .fetch_all(&self.pool)
        .await?)
    }

    /// Update trust level
    pub async fn update_trust_level(&self, organization_id: &str, trust_level: &str) -> Result<()> {
        sqlx::query(
            "UPDATE federation_trust SET trust_level = ?, updated_at = ? WHERE organization_id = ?",
        )
        .bind(trust_level)
        .bind(Utc::now())
        .bind(organization_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Revoke federation trust
    pub async fn revoke(&self, organization_id: &str) -> Result<()> {
        sqlx::query(
            "UPDATE federation_trust SET status = 'revoked', updated_at = ? WHERE organization_id = ?",
        )
        .bind(Utc::now())
        .bind(organization_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
