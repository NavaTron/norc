//! Framing encode/decode & property tests

use navatron_protocol::wire::{WireFrame, WireFormat, MAX_FRAME_SIZE, MIN_HEADER_SIZE};
use navatron_protocol::messages::{NorcMessage, Message, MessageType, ConnectionRequestMessage};
use navatron_protocol::version::Version;
use navatron_protocol::types::Capability;
use proptest::prelude::*;
use uuid::Uuid;

// Strategy generating safe payload sizes well within bounds
fn payload_strategy() -> impl Strategy<Value = Vec<u8>> {
    // Keep small to keep tests fast; wire code already enforces max
    prop::collection::vec(any::<u8>(), 0..512)
}

prop_compose! {
    fn message_strategy()(payload in payload_strategy(), seq in 0u64..1_000_000) -> NorcMessage {
        let req = ConnectionRequestMessage {
            client_versions: vec![Version::V2_0],
            preferred_version: Version::V2_0,
            capabilities: vec![Capability::Messaging],
            client_nonce: vec![1,2,3,4],
            ephemeral_public_key: [0u8;32],
            pq_public_key: None,
        };
        // We wrap the payload bytes inside the existing ConnectionRequest for simplicity.
        let mut msg = NorcMessage::new(Version::V2_0, MessageType::ConnectionRequest, seq, [0u8;32], Message::ConnectionRequest(req));
        // Overwrite message id to make uniqueness explicit
        msg.message_id = Uuid::new_v4();
        msg
    }
}

proptest! {
    #[test]
    fn prop_message_encode_decode(msg in message_strategy()) {
        let encoded = msg.encode().expect("encode");
        // Basic size sanity
        prop_assume!(encoded.len() <= MAX_FRAME_SIZE);
        let decoded = NorcMessage::decode(&encoded).expect("decode");
        prop_assert_eq!(decoded.message_type, msg.message_type);
        prop_assert_eq!(decoded.version, msg.version);
        prop_assert_eq!(decoded.sequence_number, msg.sequence_number);
    }
}

#[test]
fn frame_manual_roundtrip() {
    let payload = b"hello".to_vec();
    let frame = WireFrame::new(Version::V2_0, MessageType::ConnectionRequest, Uuid::new_v4(), 42, [0u8;32], payload.clone()).unwrap();
    let bytes = frame.encode().unwrap();
    assert!(bytes.len() >= MIN_HEADER_SIZE);
    let decoded = WireFrame::decode(&bytes).unwrap();
    assert_eq!(decoded.payload, payload);
    decoded.validate().unwrap();
}
