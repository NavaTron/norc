//! Database migrations
//!
//! This module provides database schema migrations.
//! Actual migration SQL files should be placed in the migrations/ directory
//! and will be run by sqlx::migrate!() macro.

// Migrations are managed by sqlx-cli
// Run: sqlx migrate add <migration_name>
