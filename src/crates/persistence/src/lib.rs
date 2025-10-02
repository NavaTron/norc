//! Persistence layer for NORC server
//!
//! Provides database abstraction and repository pattern for:
//! - User and device management
//! - Message persistence and offline delivery
//! - Federation trust relationships
//! - Session and authentication state
//! - Audit logging

pub mod database;
pub mod error;
pub mod migrations;
pub mod models;
pub mod repositories;

pub use database::Database;
pub use error::{PersistenceError, Result};
