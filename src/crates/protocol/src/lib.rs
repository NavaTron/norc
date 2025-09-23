//! NORC Protocol Core
//!
//! This crate contains the core protocol types, message definitions, and cryptographic
//! primitives for the NavaTron Open Real-time Communication (NORC) protocol.

pub mod crypto;
pub mod error;
pub mod identity;
pub mod message;

pub use error::{ProtocolError, Result};
pub use identity::{Identity, IdentityKeyPair, PublicKey};
pub use message::{Message, MessageHeader, MessagePayload, MessageType};

/// Protocol version constants
pub const PROTOCOL_VERSION_MAJOR: u16 = 1;
pub const PROTOCOL_VERSION_MINOR: u16 = 0;
pub const PROTOCOL_VERSION_PATCH: u16 = 0;

/// Maximum message size in bytes
pub const MAX_MESSAGE_SIZE: usize = 1024 * 1024; // 1MB

/// Network port constants
pub const DEFAULT_SERVER_PORT: u16 = 4242;
pub const DEFAULT_FEDERATION_PORT: u16 = 4243;
