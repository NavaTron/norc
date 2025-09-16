//! # NavaTron NORC Protocol
//!
//! Rust reference (work‑in‑progress) for the NavaTron Open Real‑time Communication (NORC)
//! protocol. Focus areas in this crate: message model, version negotiation, framing
//! primitives, and cryptographic scaffolding. Security properties not yet implemented are
//! explicitly documented and in some cases guarded behind `compile_error!` in ambiguous
//! spec regions.
//!
//! See: `../../../../PROTOCOL_SPECIFICATION.md` & `SECURITY_MODEL.md` for design intent and
//! `SECURITY.md` for current implementation posture / gaps.
//!
//! ## Protocol Layers
//!
//! The NORC protocol consists of three main layers:
//! - **NORC-C**: Client ↔ Server communication
//! - **NORC-F**: Server ↔ Server federation  
//! - **NORC-T**: Trust establishment and management
//!
//! ## Current / Planned Features
//!
//! Implemented (scaffold level):
//! - Version negotiation (Adjacent‑Major Compatibility constraint)
//! - Wire framing with size limits & hash‑chaining placeholder
//! - Handshake state machine & capability negotiation placeholders
//!
//! Planned / Not Yet Implemented:
//! - Forward secrecy & key schedule finalization
//! - Replay protection (hash chain validator integration)
//! - Authenticated encryption of payload frames
//! - Post‑quantum hybrid key agreement (feature gated)
//! - Metadata resistance (length padding, cover traffic)
//!
//! ## Example (Encoding a Message)
//!
//! ```rust
//! use navatron_protocol::{Version, MessageType, NorcMessage, Message, WireFormat};
//! use navatron_protocol::messages::ErrorMessage;
//! use std::collections::HashMap;
//! 
//! // Create a version-aware message
//! let version = Version::new(2, 0)?;
//! let error_msg = ErrorMessage {
//!     error_code: 1,
//!     error_category: "test".to_string(),
//!     message: "Example error".to_string(),
//!     retry_after_secs: None,
//!     details: HashMap::new(),
//! };
//! let message = NorcMessage::new(
//!     version,
//!     MessageType::Error,
//!     1, // sequence number
//!     [0u8; 32], // prev message hash
//!     Message::Error(error_msg)
//! );
//! 
//! // Encode to binary wire format
//! let encoded = message.encode()?;
//! 
//! // Decode from wire format
//! let decoded = NorcMessage::decode(&encoded)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs)]
#![warn(
    missing_debug_implementations,
    rust_2018_idioms,
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    variant_size_differences
)]

pub mod crypto;
pub mod error;
pub mod handshake;
pub mod framing;
pub mod messages;
pub mod types;
pub mod version;
pub mod wire;

// Re-export main types for convenience
pub use error::{NorcError, Result};
pub use handshake::*;
pub use messages::{Message, MessageType, NorcMessage};
pub use types::*;
pub use version::{Version, VersionNegotiation};
pub use wire::{WireFormat, FrameDecoder, FrameEncoder};