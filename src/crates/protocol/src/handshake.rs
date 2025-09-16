//! NORC handshake state machine and negotiation logic (scaffolding)
//!
//! This module defines the NavaTron NORC handshake flow between client and server.
//! It currently provides a strongly-typed state machine skeleton; detailed cryptographic
//! operations and capability/extension negotiation will be implemented in subsequent phases.
//!
//! IMPORTANT: Certain aspects of the NORC spec are ambiguous or not yet fully
//! specified in the provided documentation. To avoid silently guessing, we
//! insert `compile_error!` gates under the `strict-spec` feature so that
//! builds can purposefully fail in CI until clarifications are supplied.
//!
//! Ambiguities tracked:
//! 1. Resume Ticket Format (Spec NORC-C §Handshake Resume): exact field ordering & AEAD tag size.
//! 2. Capability Bitmask vs Vector Semantics (Spec NORC-C §Capabilities): precedence rules when duplicates.
//! 3. Extension Negotiation Conflict Resolution (Spec NORC-C §Extensions): tie‑breaking when both sides propose differing parameter values.
//! 4. Masking Algorithm Parameters (Spec NORC-C §Framing): mask key derivation salt not defined.
//!
//! Enable `strict-spec` feature to surface these blockers as compile errors.
#![allow(dead_code)]

#[cfg(feature = "strict-spec")]
compile_error!("NORC spec ambiguities unresolved: see src/crates/protocol/src/handshake.rs doc comments.");

use crate::version::Version;
use crate::error::{NorcError, Result};
use crate::messages::{Capability, ConnectionRequestMessage, ConnectionAcceptedMessage};
use std::time::Duration;

/// Handshake role (client or server)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeRole {
    /// Initiating side
    Client,
    /// Accepting side
    Server,
}

/// Negotiated capability outcome
#[derive(Debug, Clone)]
pub struct NegotiatedCapabilities {
    /// Capabilities agreed upon (intersection after policy filtering)
    pub agreed: Vec<Capability>,
    /// Capabilities offered by peer but locally unsupported (ignored)
    pub ignored_peer: Vec<Capability>,
    /// Capabilities locally supported but peer rejected or absent
    pub downgraded: Vec<Capability>,
}

impl NegotiatedCapabilities {
    /// Create empty negotiation result
    pub fn empty() -> Self { Self { agreed: vec![], ignored_peer: vec![], downgraded: vec![] } }
}

/// Handshake states (simplified)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeState {
    /// Initial state prior to sending/receiving anything
    Idle,
    /// Initial message (ConnectionRequest) sent/received
    HelloSent,
    /// Response (ConnectionAccepted) processed
    Accepted,
    /// Capability negotiation completed
    CapabilitiesFinalized,
    /// Cryptographic key schedule derived
    KeysDerived,
    /// Handshake fully complete
    Complete,
    /// Failed with protocol error
    Failed(NorcError),
}

impl HandshakeState {
    /// Returns true if terminal (Complete or Failed)
    pub fn is_terminal(&self) -> bool { matches!(self, Self::Complete | Self::Failed(_)) }
}

/// Handshake transcript data collected for key derivation
#[derive(Debug, Default, Clone)]
pub struct HandshakeTranscript {
    pub client_nonce: Option<Vec<u8>>,
    pub server_nonce: Option<Vec<u8>>,
    pub client_ephemeral: Option<[u8;32]>,
    pub server_ephemeral: Option<[u8;32]>,
    pub negotiated_version: Option<Version>,
    pub negotiated_capabilities: Option<NegotiatedCapabilities>,
}

/// Policy controlling which capabilities are permitted
pub trait CapabilityPolicy: Send + Sync {
    /// Decide if a capability is allowed.
    fn allow(&self, cap: &Capability) -> bool;
}

/// Default permissive policy (accept all capabilities)
pub struct AllowAllCapabilities;
impl CapabilityPolicy for AllowAllCapabilities { fn allow(&self, _cap:&Capability)->bool { true } }

/// Handshake configuration parameters
#[derive(Debug, Clone)]
pub struct HandshakeConfig<P: CapabilityPolicy + 'static> {
    /// Local supported protocol versions (ordered preference ascending)
    pub supported_versions: Vec<Version>,
    /// Capability policy
    pub capability_policy: P,
    /// Maximum duration allowed for full handshake completion
    pub max_duration: Duration,
}

impl<P: CapabilityPolicy + Default> Default for HandshakeConfig<P> {
    fn default() -> Self {
        Self {
            supported_versions: vec![Version::V1_0, Version::V1_1, Version::V2_0],
            capability_policy: P::default(),
            max_duration: Duration::from_secs(10),
        }
    }
}

impl Default for AllowAllCapabilities { fn default() -> Self { Self } }

/// Handshake driver carrying state & transcript
pub struct Handshake<P: CapabilityPolicy + 'static> {
    role: HandshakeRole,
    state: HandshakeState,
    config: HandshakeConfig<P>,
    transcript: HandshakeTranscript,
}

impl<P: CapabilityPolicy> Handshake<P> {
    /// Create new handshake context
    pub fn new(role: HandshakeRole, config: HandshakeConfig<P>) -> Self {
        Self { role, state: HandshakeState::Idle, config, transcript: HandshakeTranscript::default() }
    }

    /// Get current state
    pub fn state(&self) -> &HandshakeState { &self.state }

    /// Begin as client with prepared ConnectionRequest
    pub fn initiate_client(&mut self, _req:&ConnectionRequestMessage) -> Result<()> {
        if self.role != HandshakeRole::Client { return Err(NorcError::invalid_state("client", "server")); }
        self.ensure_state(HandshakeState::Idle)?;
        self.state = HandshakeState::HelloSent;
        Ok(())
    }

    /// Process server acceptance; record negotiated parameters
    pub fn on_server_accept(&mut self, msg:&ConnectionAcceptedMessage) -> Result<()> {
        self.ensure_not_terminal()?;
        // Record negotiated version
        self.transcript.negotiated_version = Some(msg.negotiated_version);
        self.state = HandshakeState::Accepted;
        Ok(())
    }

    /// Finalize capabilities (placeholder intersection logic)
    pub fn finalize_capabilities(&mut self, offered:&[Capability], peer:&[Capability]) -> Result<()> {
        self.ensure_not_terminal()?;
        let policy = &self.config.capability_policy;
        let mut agreed = Vec::new();
        let mut ignored_peer = Vec::new();
        for cap in peer { if policy.allow(cap) && offered.contains(cap) { agreed.push(cap.clone()); } else { ignored_peer.push(cap.clone()); } }
        let downgraded: Vec<Capability> = offered.iter().filter(|c| !agreed.contains(c)).cloned().collect();
        self.transcript.negotiated_capabilities = Some(NegotiatedCapabilities { agreed, ignored_peer, downgraded });
        self.state = HandshakeState::CapabilitiesFinalized;
        Ok(())
    }

    /// Derive keys (placeholder – actual KDF & transcript hashing deferred)
    pub fn derive_keys(&mut self) -> Result<()> {
        self.ensure_not_terminal()?;
        if !matches!(self.state, HandshakeState::CapabilitiesFinalized) {
            return Err(NorcError::invalid_state("CapabilitiesFinalized", format!("{:?}", self.state)));
        }
        // TODO: Implement HKDF over concatenated transcript components (spec §KeySchedule pending clarification of salt/mask).
        self.state = HandshakeState::KeysDerived;
        Ok(())
    }

    /// Mark complete once keys installed in transport
    pub fn complete(&mut self) -> Result<()> {
        self.ensure_not_terminal()?;
        if !matches!(self.state, HandshakeState::KeysDerived) {
            return Err(NorcError::invalid_state("KeysDerived", format!("{:?}", self.state)));
        }
        self.state = HandshakeState::Complete;
        Ok(())
    }

    fn ensure_state(&self, expected: HandshakeState) -> Result<()> {
        if self.state != expected { return Err(NorcError::invalid_state(format!("{:?}", expected), format!("{:?}", self.state))); }
        Ok(())
    }
    fn ensure_not_terminal(&self) -> Result<()> { if self.state.is_terminal() { return Err(NorcError::invalid_state("non-terminal", format!("{:?}", self.state))); } Ok(()) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::version::Version;
    use crate::messages::{ConnectionAcceptedMessage};

    fn sample_accept() -> ConnectionAcceptedMessage {
        ConnectionAcceptedMessage {
            negotiated_version: Version::V2_0,
            server_capabilities: vec![Capability::Messaging],
            compatibility_mode: false,
            server_nonce: vec![1,2,3],
            ephemeral_public_key: [0u8;32],
            pq_response: None,
            session_id: uuid::Uuid::new_v4(),
        }
    }

    #[test]
    fn test_handshake_basic_flow() {
        let cfg = HandshakeConfig { supported_versions: vec![Version::V2_0], capability_policy: AllowAllCapabilities, max_duration: Duration::from_secs(5) };
        let mut hs = Handshake::new(HandshakeRole::Client, cfg);
        assert!(matches!(hs.state(), HandshakeState::Idle));
        // Simulate initiating client (placeholder request not validated yet)
        // We'll fabricate a minimal ConnectionRequestMessage consistent with types.
        let req = ConnectionRequestMessage { client_versions: vec![Version::V2_0], preferred_version: Version::V2_0, capabilities: vec![Capability::Messaging], client_nonce: vec![1], ephemeral_public_key: [0u8;32], pq_public_key: None };
        hs.initiate_client(&req).unwrap();
        assert!(matches!(hs.state(), HandshakeState::HelloSent));
        hs.on_server_accept(&sample_accept()).unwrap();
        assert!(matches!(hs.state(), HandshakeState::Accepted));
        hs.finalize_capabilities(&[Capability::Messaging], &[Capability::Messaging]).unwrap();
        hs.derive_keys().unwrap();
        hs.complete().unwrap();
        assert!(matches!(hs.state(), HandshakeState::Complete));
    }
}
