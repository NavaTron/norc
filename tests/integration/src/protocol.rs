//! Protocol-level integration tests

use navatron_protocol::{
    messages::{Message, MessageSendMessage, NorcMessage},
    types::{ConversationId, MessageId},
    Version,
};

#[tokio::test]
async fn test_message_serialization() {
    let message_id = MessageId::new_v4();
    let conversation_id = ConversationId::new_v4();
    let device_id = uuid::Uuid::new_v4();
    
    let original_message = NorcMessage {
        message_id,
        timestamp: chrono::Utc::now(),
        version: Version::V1,
        payload: Message::MessageSend(MessageSendMessage {
            conversation_id,
            recipients: vec![device_id],
            encrypted_content: b"Protocol integration test".to_vec(),
        }),
    };

    // Test serialization
    let serialized = original_message.to_bytes().expect("Failed to serialize message");
    assert!(!serialized.is_empty(), "Serialized message should not be empty");

    // Test deserialization
    let deserialized = NorcMessage::from_bytes(&serialized)
        .expect("Failed to deserialize message");

    // Verify round-trip
    assert_eq!(original_message.message_id, deserialized.message_id);
    assert_eq!(original_message.version, deserialized.version);
    
    match (&original_message.payload, &deserialized.payload) {
        (Message::MessageSend(orig), Message::MessageSend(deser)) => {
            assert_eq!(orig.conversation_id, deser.conversation_id);
            assert_eq!(orig.recipients, deser.recipients);
            assert_eq!(orig.encrypted_content, deser.encrypted_content);
        }
        _ => panic!("Message payload type mismatch"),
    }
}