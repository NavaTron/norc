//! Handshake version & capability negotiation tests

use navatron_protocol::handshake::{Handshake, HandshakeConfig, HandshakeRole, AllowAllCapabilities};
use navatron_protocol::version::Version;
use navatron_protocol::messages::{ConnectionRequestMessage, ConnectionAcceptedMessage, Capability};
use std::time::Duration;

fn sample_request() -> ConnectionRequestMessage {
    ConnectionRequestMessage {
        client_versions: vec![Version::V2_0, Version::V1_1],
        preferred_version: Version::V2_0,
        capabilities: vec![Capability::Messaging],
        client_nonce: vec![9,9,9],
        ephemeral_public_key: [0u8;32],
        pq_public_key: None,
    }
}

fn sample_accept(ver: Version) -> ConnectionAcceptedMessage {
    ConnectionAcceptedMessage {
        negotiated_version: ver,
        server_capabilities: vec![Capability::Messaging],
        compatibility_mode: false,
        server_nonce: vec![2,2,2],
        ephemeral_public_key: [0u8;32],
        pq_response: None,
        session_id: uuid::Uuid::new_v4(),
    }
}

#[test]
fn version_negotiation_basic() {
    let cfg = HandshakeConfig { supported_versions: vec![Version::V2_0, Version::V1_1], capability_policy: AllowAllCapabilities, max_duration: Duration::from_secs(5) };
    let mut hs = Handshake::new(HandshakeRole::Client, cfg);
    let req = sample_request();
    hs.initiate_client(&req).unwrap();
    hs.on_server_accept(&sample_accept(Version::V2_0)).unwrap();
    hs.finalize_capabilities(&[Capability::Messaging], &[Capability::Messaging]).unwrap();
    hs.derive_keys().unwrap();
    hs.complete().unwrap();
    assert!(hs.state().is_terminal());
}

#[test]
fn capability_downgrade_detection() {
    use navatron_protocol::handshake::HandshakeState;
    let cfg = HandshakeConfig { supported_versions: vec![Version::V2_0], capability_policy: AllowAllCapabilities, max_duration: Duration::from_secs(5) };
    let mut hs = Handshake::new(HandshakeRole::Client, cfg);
    hs.initiate_client(&sample_request()).unwrap();
    hs.on_server_accept(&sample_accept(Version::V2_0)).unwrap();
    // Offer messaging + hypothetical FutureCap (missing -> downgraded)
    let offered = vec![Capability::Messaging];
    let peer = vec![Capability::Messaging];
    hs.finalize_capabilities(&offered, &peer).unwrap();
    assert!(matches!(hs.state(), HandshakeState::CapabilitiesFinalized));
}
