//! NavaTron NORC Client Core
//!
//! Headless client library for NORC protocol.

#![deny(unsafe_code)]
#![warn(missing_docs)]

/// Client errors
pub mod error;

/// Client implementation
pub mod client;

/// Re-exports
pub use error::{ClientError, Result};
pub use client::Client;

/// Placeholder
pub fn placeholder() {
    // TODO: Implement client core
}