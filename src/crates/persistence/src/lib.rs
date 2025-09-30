//! Persistence layer for NORC server
//! 
//! Provides database abstraction and repository pattern for:
//! - User and device management
//! - Message persistence and offline delivery
//! - Federation trust relationships
//! - Session and authentication state
//! - Audit logging

pub mod error;
pub mod database;
pub mod repositories;
pub mod models;
pub mod migrations;

pub use error::{PersistenceError, Result};
pub use database::Database;
