//! NORC framing & masking scaffolding
//!
//! This module documents and scaffolds the NavaTron NORC length‑prefixed
//! binary framing layer beyond the raw wire frame structure in `wire.rs`.
//! It provides extension points for:
//!  * Frame masking (confidentiality of metadata vs payload) – currently a no‑op.
//!  * Backpressure & size policy hooks (token bucket integration will live in higher layer).
//!  * Previous message hash validation helper.
//!
//! Ambiguities (will deliberately fail builds under `strict-spec`):
//!  1. Masking key derivation salt and whether header length field is masked (Spec NORC-C §Framing Masking).
//!  2. Handling of frame fragmentation vs requirement that each NORC message == one frame (Spec NORC-C §Segmentation).
//!  3. Whether `prev_message_hash` of the first message MUST be all zeroes or omitted (Spec NORC-C §Ordering & Chaining).
//!  4. Required action on hash chain discontinuity: soft error (warning + accept) vs hard protocol error (Spec NORC-C §Ordering Integrity Enforcement).
//!
//! Enable feature `strict-spec` to surface these as compile errors instead of silently accepting defaults.
#![deny(unsafe_code)]
#![allow(dead_code)]

#[cfg(feature = "strict-spec")]
compile_error!("Unresolved NORC framing ambiguities: see framing.rs doc comment list (enable after specification clarification).");

use crate::error::{NorcError, Result};
use crate::messages::NorcMessage;
use crate::wire::WireFrame;

/// Strategy trait for frame masking (metadata/payload obfuscation)
pub trait FrameMasker: Send + Sync {
    /// Apply masking in-place. Default: no-op.
    fn mask(&self, _frame: &mut WireFrame) -> Result<()> { Ok(()) }
    /// Remove masking in-place. Default: no-op.
    fn unmask(&self, _frame: &mut WireFrame) -> Result<()> { Ok(()) }
}

/// No-op masker implementation
#[derive(Debug, Default)]
pub struct NoOpMasker;
impl FrameMasker for NoOpMasker {}

/// Hash chain validator helper
pub struct HashChainValidator {
    /// Last observed message hash (None before first)
    last_hash: Option<[u8;32]>,
    /// Strict enforcement (hard error) flag
    strict: bool,
}

impl HashChainValidator {
    /// Create a new validator
    pub fn new(strict: bool) -> Self { Self { last_hash: None, strict } }

    /// Validate chaining for next message; updates internal state on success.
    pub fn validate_and_update(&mut self, msg: &NorcMessage) -> Result<()> {
        if let Some(prev) = self.last_hash {
            if prev != msg.prev_message_hash {
                if self.strict { return Err(NorcError::ordering("Hash chain discontinuity")); }
                // Non-strict: treat as soft reset.
            }
        } else {
            // First message chain rule ambiguous; accept any 32-byte value.
        }
        // Compute canonical hash for next link reference (errors ignored if serialization fails)
        if let Ok(h) = msg.canonical_hash() { self.last_hash = Some(h); }
        Ok(())
    }
}

/// Backpressure advisory returned by policy checks
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackpressureDecision { Allow, Delay, Reject }

/// Frame size / rate policy hook
pub trait FramePolicy: Send + Sync {
    /// Decide whether a frame of `size` bytes is currently allowed.
    fn on_frame_size(&self, size: usize) -> BackpressureDecision;
}

/// Default permissive frame policy
pub struct AllowAllPolicy;
impl FramePolicy for AllowAllPolicy { fn on_frame_size(&self, _size: usize) -> BackpressureDecision { BackpressureDecision::Allow } }

/// Convenience function to perform pre-send processing (mask + policy)
pub fn prepare_outbound_frame<F: FrameMasker, P: FramePolicy>(
    frame: &mut WireFrame,
    masker: &F,
    policy: &P,
) -> Result<()> {
    match policy.on_frame_size(frame.total_size()) {
        BackpressureDecision::Allow => {},
        BackpressureDecision::Delay => return Err(NorcError::rate_limit("Temporary backpressure", 1)),
        BackpressureDecision::Reject => return Err(NorcError::rate_limit("Frame rejected due to policy", 5)),
    }
    masker.mask(frame)?;
    Ok(())
}

/// Reverse masking for inbound frames
pub fn process_inbound_frame<F: FrameMasker>(frame: &mut WireFrame, masker: &F) -> Result<()> {
    masker.unmask(frame)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::{ConnectionRequestMessage, Message, MessageType};
    use crate::version::Version;
    use crate::wire::WireFormat;
    use crate::types::Capability;

    #[test]
    fn test_noop_masker_roundtrip() {
        let payload = Message::ConnectionRequest(ConnectionRequestMessage { client_versions: vec![Version::V2_0], preferred_version: Version::V2_0, capabilities: vec![Capability::Messaging], client_nonce: vec![1,2,3], ephemeral_public_key: [0u8;32], pq_public_key: None });
        let msg = crate::messages::NorcMessage::new(Version::V2_0, MessageType::ConnectionRequest, 1, [0u8;32], payload);
        let mut frame_bytes = msg.encode().unwrap();
        // Decode to frame, then apply mask/unmask (no-op)
        let mut frame = crate::wire::WireFrame::decode(&frame_bytes).unwrap();
        let masker = NoOpMasker::default();
        prepare_outbound_frame(&mut frame, &masker, &AllowAllPolicy).unwrap();
        process_inbound_frame(&mut frame, &masker).unwrap();
        frame_bytes = frame.encode().unwrap();
        let decoded = crate::messages::NorcMessage::decode(&frame_bytes).unwrap();
        assert_eq!(decoded.message_type, MessageType::ConnectionRequest);
    }
}
