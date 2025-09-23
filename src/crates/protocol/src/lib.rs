//! NORC Protocol Implementation
//!
//! This crate implements the NavaTron Open Real-time Communication (NORC) protocol.
//! It provides core message types, cryptographic primitives, wire format definitions,
//! and protocol state machines required for implementing NORC-compliant clients and servers.
//!
//! # Protocol Overview
//!
//! The NORC protocol is designed around three core layers:
//! - **NORC-C**: Client communication layer
//! - **NORC-F**: Federation layer for server-to-server communication  
//! - **NORC-T**: Trust management layer
//!
//! # Example Usage
//!
//! ```rust
//! use norc_protocol::{Message, MessageType, ProtocolVersion};
//!
//! // Create a protocol message
//! let msg = Message::new(
//!     MessageType::TextMessage,
//!     b"Hello, NORC!".to_vec(),
//! );
//!
//! // Serialize for transmission
//! let serialized = msg.to_wire_format()?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
