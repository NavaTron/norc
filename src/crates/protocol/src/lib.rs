//! NORC Protocol Implementation
//!
//! This crate implements the NavaTron Open Real-time Communication (NORC) Protocol
//! as specified in PROTOCOL_SPECIFICATION.md and PROTOCOL_REQUIREMENTS.md.
//!
//! The implementation provides:
//! - Cryptographic primitives (Ed25519, X25519, ChaCha20-Poly1305, BLAKE3)
//! - Post-quantum hybrid cryptography (Kyber)
//! - Protocol message types and serialization
//! - Trust level management and verification
//! - Handshake and key derivation
//!
//! # Security
//!
//! All cryptographic operations use constant-time implementations to prevent
//! timing side-channel attacks. Keys are zeroized on drop.

#![warn(missing_docs)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod crypto;
pub mod error;
pub mod handshake;
pub mod messages;
pub mod trust;
pub mod types;
pub mod version;

pub use error::{ProtocolError, Result};
pub use trust::TrustLevel;
pub use types::*;
pub use version::ProtocolVersion;

/// Protocol layer constants
pub mod constants {
    /// Maximum message size (16 MB)
    pub const MAX_MESSAGE_SIZE: u32 = 16 * 1024 * 1024;

    /// Session key rotation interval (1 hour)
    pub const KEY_ROTATION_INTERVAL_SECS: u64 = 3600;

    /// Maximum handshake duration (30 seconds)
    pub const HANDSHAKE_TIMEOUT_SECS: u64 = 30;

    /// Nonce size for ChaCha20-Poly1305
    pub const NONCE_SIZE: usize = 12;

    /// Key size for symmetric encryption
    pub const KEY_SIZE: usize = 32;

    /// Hash size for BLAKE3
    pub const HASH_SIZE: usize = 32;

    /// Signature size for Ed25519
    pub const SIGNATURE_SIZE: usize = 64;

    /// Public key size for Ed25519
    pub const PUBLIC_KEY_SIZE: usize = 32;

    /// Domain separation prefix for all HKDF labels
    pub const DOMAIN_PREFIX: &str = "norc:";
}
