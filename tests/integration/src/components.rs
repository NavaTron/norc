//! Component-level integration tests

use std::sync::Arc;
use navatron_server_core::{
    session::SessionManager,
    router::MessageRouter,
    federation::FederationManager,
};
use navatron_transport::connection::ConnectionHandle;
use navatron_protocol::{
    messages::{Message, MessageSendMessage, NorcMessage},
    types::{ConversationId, MessageId},
    Version,
};

#[tokio::test]
async fn test_session_management() {
    let session_manager = Arc::new(SessionManager::new());

    let device_id = uuid::Uuid::new_v4();
    
    // Create a mock connection handle using actual constructor
    let (connection_handle, _receiver) = ConnectionHandle::new(
        uuid::Uuid::new_v4(),
        Default::default(),
    ).await.expect("Failed to create connection handle");

    let session_id = session_manager
        .create_session(device_id, connection_handle)
        .await
        .expect("Failed to create session");

    // Test session lookup
    let found_session = session_manager.get_session_by_device(device_id).await;
    assert!(found_session.is_some(), "Session should be found by device ID");
    assert_eq!(found_session.unwrap(), session_id, "Session IDs should match");
}

#[tokio::test]
async fn test_message_routing() {
    let session_manager = Arc::new(SessionManager::new());
    let message_router = Arc::new(MessageRouter::new(session_manager.clone()));

    let conversation_id = uuid::Uuid::new_v4();
    let message_id = uuid::Uuid::new_v4();
    let device_id = uuid::Uuid::new_v4();
    
    let test_message = NorcMessage {
        message_id,
        timestamp: chrono::Utc::now(),
        version: Version::V1,
        payload: Message::MessageSend(MessageSendMessage {
            conversation_id,
            recipients: vec![device_id],
            encrypted_content: b"Component test message".to_vec(),
        }),
    };

    let route_result = message_router.route_message(test_message).await;
    assert!(route_result.is_ok(), "Message routing should succeed");
}

#[tokio::test]
async fn test_federation_management() {
    let federation_manager = Arc::new(FederationManager::new());

    let server_domain = "test.example.com".to_string();
    federation_manager.add_server(server_domain.clone()).await
        .expect("Failed to add server to federation");

    let servers = federation_manager.list_servers().await;
    assert!(servers.contains(&server_domain), "Server should be in federation list");
}