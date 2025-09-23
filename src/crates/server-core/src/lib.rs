//! NORC Server Core
//!
//! Core server functionality for the NavaTron Open Real-time Communication (NORC) server.
//! Provides daemon management, connection handling, and server lifecycle management.

pub mod daemon;
pub mod server;
pub mod connection;
pub mod error;

pub use daemon::{Daemon, DaemonConfig};
pub use server::{Server, ServerConfig};
pub use connection::{Connection, ConnectionManager};
pub use error::{ServerError, Result};