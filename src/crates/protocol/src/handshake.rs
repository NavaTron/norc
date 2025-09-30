//! Handshake and key derivation per PROTOCOL_SPECIFICATION.md Section 3.4

use crate::crypto::{Blake3Hasher, HkdfBlake3, X25519EphemeralKeyPair};
use crate::error::{ProtocolError, Result};
use crate::messages::{ClientHello, ServerHello};
use crate::types::{Hash, SymmetricKey};
use crate::version::ProtocolVersion;

/// Handshake state machine
pub struct HandshakeState {
    /// Client or server role
    is_client: bool,
    /// Our ephemeral key pair
    ephemeral_keypair: Option<X25519EphemeralKeyPair>,
    /// Peer's ephemeral public key
    peer_ephemeral_public: Option<[u8; 32]>,
    /// Our nonce
    our_nonce: [u8; 32],
    /// Peer's nonce
    peer_nonce: Option<[u8; 32]>,
    /// Negotiated version
    negotiated_version: Option<ProtocolVersion>,
    /// Transcript hash
    transcript_hash: Option<Hash>,
}

impl HandshakeState {
    /// Create a new handshake state for a client
    pub fn new_client() -> Self {
        Self {
            is_client: true,
            ephemeral_keypair: None,
            peer_ephemeral_public: None,
            our_nonce: crate::crypto::generate_random_bytes(32).try_into().unwrap(),
            peer_nonce: None,
            negotiated_version: None,
            transcript_hash: None,
        }
    }

    /// Create a new handshake state for a server
    pub fn new_server() -> Self {
        Self {
            is_client: false,
            ephemeral_keypair: None,
            peer_ephemeral_public: None,
            our_nonce: crate::crypto::generate_random_bytes(32).try_into().unwrap(),
            peer_nonce: None,
            negotiated_version: None,
            transcript_hash: None,
        }
    }

    /// Generate ClientHello message
    pub fn generate_client_hello(&mut self) -> Result<ClientHello> {
        let keypair = X25519EphemeralKeyPair::generate();
        let ephemeral_public_key = keypair.public_key();
        self.ephemeral_keypair = Some(keypair);

        Ok(ClientHello {
            versions: vec![ProtocolVersion::CURRENT],
            capabilities: vec!["encryption".to_string(), "federation".to_string()],
            nonce: self.our_nonce,
            ephemeral_public_key,
            pq_public_key: None, // TODO: Add post-quantum support
        })
    }

    /// Process ClientHello and generate ServerHello
    pub fn process_client_hello(&mut self, client_hello: &ClientHello) -> Result<ServerHello> {
        // Store peer nonce and ephemeral key
        self.peer_nonce = Some(client_hello.nonce);
        self.peer_ephemeral_public = Some(client_hello.ephemeral_public_key);

        // Negotiate version
        let our_version = ProtocolVersion::CURRENT;
        let negotiated = client_hello
            .versions
            .iter()
            .find(|v| our_version.is_compatible_with(v))
            .ok_or_else(|| {
                ProtocolError::HandshakeError("No compatible version found".to_string())
            })?;

        self.negotiated_version = Some(*negotiated);

        // Generate our ephemeral key pair
        let keypair = X25519EphemeralKeyPair::generate();
        let ephemeral_public_key = keypair.public_key();
        self.ephemeral_keypair = Some(keypair);

        Ok(ServerHello {
            selected_version: *negotiated,
            capabilities: vec!["encryption".to_string(), "federation".to_string()],
            nonce: self.our_nonce,
            ephemeral_public_key,
            pq_public_key: None,
        })
    }

    /// Process ServerHello (client side)
    pub fn process_server_hello(&mut self, server_hello: &ServerHello) -> Result<()> {
        // Store peer nonce and ephemeral key
        self.peer_nonce = Some(server_hello.nonce);
        self.peer_ephemeral_public = Some(server_hello.ephemeral_public_key);
        self.negotiated_version = Some(server_hello.selected_version);

        Ok(())
    }

    /// Complete handshake and derive session keys
    pub fn finalize(&mut self) -> Result<SessionKeys> {
        let ephemeral_keypair = self
            .ephemeral_keypair
            .take()
            .ok_or_else(|| ProtocolError::HandshakeError("Missing ephemeral keypair".to_string()))?;

        let peer_ephemeral_public = self
            .peer_ephemeral_public
            .ok_or_else(|| ProtocolError::HandshakeError("Missing peer ephemeral public key".to_string()))?;

        let peer_nonce = self
            .peer_nonce
            .ok_or_else(|| ProtocolError::HandshakeError("Missing peer nonce".to_string()))?;

        // Perform ECDH
        let shared_secret = ephemeral_keypair.diffie_hellman(&peer_ephemeral_public)?;

        // Combine nonces for salt (client nonce first for consistency)
        let mut combined_nonce = Vec::with_capacity(64);
        if self.is_client {
            combined_nonce.extend_from_slice(&self.our_nonce);
            combined_nonce.extend_from_slice(&peer_nonce);
        } else {
            combined_nonce.extend_from_slice(&peer_nonce);
            combined_nonce.extend_from_slice(&self.our_nonce);
        }

        // Derive master secret
        let master_secret = HkdfBlake3::derive_32(
            shared_secret.as_bytes(),
            &combined_nonce,
            "norc:ms:v1",
        )?;

        // Derive directional traffic keys
        let key_c2s = HkdfBlake3::derive_32(&master_secret, &[0], "norc:tk:c2s:v1")?;
        let key_s2c = HkdfBlake3::derive_32(&master_secret, &[0], "norc:tk:s2c:v1")?;

        Ok(SessionKeys {
            client_to_server: SymmetricKey::new(key_c2s),
            server_to_client: SymmetricKey::new(key_s2c),
            master_secret: SymmetricKey::new(master_secret),
        })
    }
}

/// Derived session keys
pub struct SessionKeys {
    /// Client-to-server encryption key
    pub client_to_server: SymmetricKey,
    /// Server-to-client encryption key
    pub server_to_client: SymmetricKey,
    /// Master secret for future derivation
    pub master_secret: SymmetricKey,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake() {
        // Client initiates
        let mut client = HandshakeState::new_client();
        let client_hello = client.generate_client_hello().unwrap();

        // Server responds
        let mut server = HandshakeState::new_server();
        let server_hello = server.process_client_hello(&client_hello).unwrap();

        // Client processes response
        client.process_server_hello(&server_hello).unwrap();

        // Both finalize
        let client_keys = client.finalize().unwrap();
        let server_keys = server.finalize().unwrap();

        // Keys should match from opposite perspectives:
        // Client's c2s key == Server's c2s key
        // Client's s2c key == Server's s2c key
        assert_eq!(
            client_keys.client_to_server.as_bytes(),
            server_keys.client_to_server.as_bytes(),
            "Client-to-server keys should match"
        );
        assert_eq!(
            client_keys.server_to_client.as_bytes(),
            server_keys.server_to_client.as_bytes(),
            "Server-to-client keys should match"
        );
        
        // Keys should be different from each other
        assert_ne!(
            client_keys.client_to_server.as_bytes(),
            client_keys.server_to_client.as_bytes(),
            "Directional keys should be different"
        );
    }

    #[test]
    fn test_handshake_version_negotiation() {
        let mut client = HandshakeState::new_client();
        let client_hello = client.generate_client_hello().unwrap();
        
        assert!(client_hello.versions.contains(&ProtocolVersion::CURRENT));
        
        let mut server = HandshakeState::new_server();
        let server_hello = server.process_client_hello(&client_hello).unwrap();
        
        assert_eq!(server_hello.selected_version, ProtocolVersion::CURRENT);
    }

    #[test]
    fn test_handshake_nonce_uniqueness() {
        let client1 = HandshakeState::new_client();
        let client2 = HandshakeState::new_client();
        
        // Nonces should be unique (with overwhelming probability)
        assert_ne!(client1.our_nonce, client2.our_nonce);
    }
}
