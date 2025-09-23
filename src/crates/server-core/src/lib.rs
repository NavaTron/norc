//! NORC Server Core
//!
//! Core server functionality for the NavaTron Open Real-time Communication (NORC) server.
//! Provides daemon management, connection handling, and server lifecycle management.

pub mod connection;
pub mod daemon;
pub mod error;
pub mod server;

pub use connection::{Connection, ConnectionManager};
pub use daemon::{Daemon, DaemonConfig};
pub use error::{Result, ServerError};
pub use server::{Server, ServerConfig};
