//! Database connection and pool management

use crate::error::{PersistenceError, Result};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
use sqlx::migrate::MigrateDatabase;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;
use tracing::{info, warn};

/// Database configuration
#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    /// Database file path
    pub path: String,
    /// Maximum number of connections
    pub max_connections: u32,
    /// Connection timeout
    pub connection_timeout: Duration,
    /// Enable WAL mode
    pub enable_wal: bool,
    /// Enable foreign keys
    pub enable_foreign_keys: bool,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            path: "norc.db".to_string(),
            max_connections: 32,
            connection_timeout: Duration::from_secs(30),
            enable_wal: true,
            enable_foreign_keys: true,
        }
    }
}

/// Database connection pool
pub struct Database {
    pool: SqlitePool,
}

impl Database {
    /// Create a new database connection pool
    pub async fn new(config: DatabaseConfig) -> Result<Self> {
        info!("Initializing database at: {}", config.path);

        // Create database if it doesn't exist
        let db_url = format!("sqlite://{}", config.path);
        
        if !sqlx::Sqlite::database_exists(&db_url).await.unwrap_or(false) {
            info!("Creating database file...");
            sqlx::Sqlite::create_database(&db_url)
                .await
                .map_err(|e| PersistenceError::Configuration(e.to_string()))?;
        }

        // Configure connection options
        let mut connect_options = SqliteConnectOptions::from_str(&db_url)
            .map_err(|e| PersistenceError::Configuration(e.to_string()))?
            .create_if_missing(true)
            .foreign_keys(config.enable_foreign_keys);

        // Enable WAL mode for better concurrency
        if config.enable_wal {
            connect_options = connect_options.journal_mode(sqlx::sqlite::SqliteJournalMode::Wal);
        }

        // Create connection pool
        let pool = SqlitePoolOptions::new()
            .max_connections(config.max_connections)
            .acquire_timeout(config.connection_timeout)
            .connect_with(connect_options)
            .await?;

        info!("Database initialized successfully");

        Ok(Self { pool })
    }

    /// Get a reference to the connection pool
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Run database migrations
    pub async fn migrate(&self) -> Result<()> {
        info!("Running database migrations...");
        
        sqlx::migrate!("./migrations")
            .run(&self.pool)
            .await
            .map_err(|e| PersistenceError::Migration(e.to_string()))?;

        info!("Migrations completed successfully");
        Ok(())
    }

    /// Check database health
    pub async fn health_check(&self) -> Result<()> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Close the database pool
    pub async fn close(&self) {
        info!("Closing database connection pool");
        self.pool.close().await;
    }

    /// Get database statistics
    pub async fn stats(&self) -> DatabaseStats {
        DatabaseStats {
            active_connections: self.pool.size(),
            idle_connections: self.pool.num_idle(),
        }
    }
}

/// Database statistics
#[derive(Debug, Clone)]
pub struct DatabaseStats {
    /// Number of active connections
    pub active_connections: u32,
    /// Number of idle connections
    pub idle_connections: usize,
}
