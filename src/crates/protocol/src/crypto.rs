//! Cryptographic operations for the NORC protocol
//!
//! This module implements the cryptographic primitives required by NORC:
//! - Ed25519 signatures
//! - X25519 key exchange  
//! - ChaCha20-Poly1305 AEAD
//! - BLAKE3 hashing
//! - HKDF key derivation
//! - Optional post-quantum hybrid operations

use crate::error::{NorcError, Result};
use crate::types::{EphemeralPublicKey, Hash, Nonce, PublicKey, SecretKey, Signature};
use blake3::Hasher;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key as ChaChaKey, Nonce as ChaChaNonce,
};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::X25519_BASEPOINT;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use std::convert::TryInto;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Domain separation prefix for all NORC HKDF operations
pub const NORC_HKDF_PREFIX: &[u8] = b"norc:";

/// NORC cryptographic suite implementation
#[derive(Debug)]
pub struct NorcCrypto;

impl NorcCrypto {
    /// Generate a new Ed25519 signing key pair
    ///
    /// # Examples
    ///
    /// ```
    /// # use navatron_protocol::crypto::NorcCrypto;
    /// let mut rng = rand::thread_rng();
    /// let (public_key, secret_key) = NorcCrypto::generate_signing_keypair(&mut rng);
    /// assert_eq!(public_key.len(), 32);
    /// ```
    pub fn generate_signing_keypair<R: CryptoRng + RngCore>(
        rng: &mut R,
    ) -> (PublicKey, SecretKey) {
        let signing_key = SigningKey::generate(rng);
        let verifying_key = signing_key.verifying_key();

        (
            verifying_key.to_bytes(),
            SecretKey::new(signing_key.to_bytes().to_vec()),
        )
    }

    /// Generate a new X25519 key exchange key pair
    ///
    /// # Examples
    ///
    /// ```
    /// # use navatron_protocol::crypto::NorcCrypto;
    /// let mut rng = rand::thread_rng();
    /// let (public_key, secret_key) = NorcCrypto::generate_exchange_keypair(&mut rng);
    /// assert_eq!(public_key.len(), 32);
    /// ```
    pub fn generate_exchange_keypair<R: CryptoRng + RngCore>(
        rng: &mut R,
    ) -> (EphemeralPublicKey, SecretKey) {
        // Generate a random 32-byte secret key for x25519
        let mut secret_bytes = [0u8; 32];
        rng.fill_bytes(&mut secret_bytes);
        
        // Clamp the secret key according to x25519 spec
        secret_bytes[0] &= 248;
        secret_bytes[31] &= 127;
        secret_bytes[31] |= 64;
        
        // Compute the public key using scalar multiplication
        let secret_scalar = curve25519_dalek::scalar::Scalar::from_bytes_mod_order(secret_bytes);
        let basepoint = curve25519_dalek::constants::X25519_BASEPOINT;
        let public_point = secret_scalar * basepoint;
        
        (
            public_point.to_bytes(),
            SecretKey::new(secret_bytes.to_vec()),
        )
    }

    /// Sign data with Ed25519
    ///
    /// # Examples
    ///
    /// ```
    /// # use navatron_protocol::crypto::NorcCrypto;
    /// let mut rng = rand::thread_rng();
    /// let (public_key, secret_key) = NorcCrypto::generate_signing_keypair(&mut rng);
    /// let data = b"hello world";
    /// let signature = NorcCrypto::sign(&secret_key, data)?;
    /// assert!(NorcCrypto::verify(&public_key, data, &signature)?);
    /// # Ok::<(), navatron_protocol::NorcError>(())
    /// ```
    pub fn sign(secret_key: &SecretKey, data: &[u8]) -> Result<Signature> {
        if secret_key.len() != 32 {
            return Err(NorcError::crypto("Invalid Ed25519 secret key length"));
        }

        let key_bytes: [u8; 32] = secret_key
            .expose_secret()
            .try_into()
            .map_err(|_| NorcError::crypto("Invalid key format"))?;

        let signing_key = SigningKey::from_bytes(&key_bytes);
        let signature = signing_key.sign(data);

        Ok(Signature::new(signature.to_bytes()))
    }

    /// Verify Ed25519 signature
    pub fn verify(public_key: &PublicKey, data: &[u8], signature: &Signature) -> Result<bool> {
        let verifying_key = VerifyingKey::from_bytes(public_key)
            .map_err(|e| NorcError::crypto(format!("Invalid public key: {e}")))?;

        let signature = ed25519_dalek::Signature::from_bytes(signature.as_bytes());

        match verifying_key.verify(data, &signature) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Perform X25519 key exchange
    ///
    /// # Examples
    ///
    /// ```
    /// # use navatron_protocol::crypto::NorcCrypto;
    /// let mut rng = rand::thread_rng();
    /// let (alice_public, alice_secret) = NorcCrypto::generate_exchange_keypair(&mut rng);
    /// let (bob_public, bob_secret) = NorcCrypto::generate_exchange_keypair(&mut rng);
    /// 
    /// let alice_shared = NorcCrypto::key_exchange(&alice_secret, &bob_public)?;
    /// let bob_shared = NorcCrypto::key_exchange(&bob_secret, &alice_public)?;
    /// assert_eq!(alice_shared.expose_secret(), bob_shared.expose_secret());
    /// # Ok::<(), navatron_protocol::NorcError>(())
    /// ```
    pub fn key_exchange(
        secret_key: &SecretKey,
        public_key: &EphemeralPublicKey,
    ) -> Result<SecretKey> {
        if secret_key.len() != 32 || public_key.len() != 32 {
            return Err(NorcError::crypto("Invalid key length for X25519"));
        }

        let secret_bytes: [u8; 32] = secret_key
            .expose_secret()
            .try_into()
            .map_err(|_| NorcError::crypto("Invalid secret key format"))?;

        let public_bytes: [u8; 32] = (*public_key)
            .try_into()
            .map_err(|_| NorcError::crypto("Invalid public key format"))?;

        // Use curve25519-dalek for the scalar multiplication directly
        let secret_scalar = curve25519_dalek::scalar::Scalar::from_bytes_mod_order(secret_bytes);
        let public_point = curve25519_dalek::montgomery::MontgomeryPoint(public_bytes);
        
        let shared_point = secret_scalar * public_point;
        let shared_secret = shared_point.to_bytes();

        Ok(SecretKey::new(shared_secret.to_vec()))
    }

    /// Generate a random nonce for AEAD operations
    pub fn generate_nonce<R: CryptoRng + RngCore>(rng: &mut R) -> Nonce {
        let mut nonce = [0u8; 12];
        rng.fill_bytes(&mut nonce);
        nonce
    }

    /// Encrypt data with ChaCha20-Poly1305
    ///
    /// # Examples
    ///
    /// ```
    /// # use navatron_protocol::crypto::NorcCrypto;
    /// let key = NorcCrypto::generate_aead_key(&mut rand::thread_rng());
    /// let nonce = NorcCrypto::generate_nonce(&mut rand::thread_rng());
    /// let plaintext = b"secret message";
    /// let aad = b"associated data";
    /// 
    /// let ciphertext = NorcCrypto::encrypt(&key, &nonce, aad, plaintext)?;
    /// let decrypted = NorcCrypto::decrypt(&key, &nonce, aad, &ciphertext)?;
    /// assert_eq!(&decrypted, plaintext);
    /// # Ok::<(), navatron_protocol::NorcError>(())
    /// ```
    pub fn encrypt(
        key: &SecretKey,
        nonce: &Nonce,
        associated_data: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        if key.len() != 32 {
            return Err(NorcError::crypto("Invalid ChaCha20 key length"));
        }

        let key_bytes: [u8; 32] = key
            .expose_secret()
            .try_into()
            .map_err(|_| NorcError::crypto("Invalid key format"))?;

        let cipher = ChaCha20Poly1305::new(ChaChaKey::from_slice(&key_bytes));
        let nonce = ChaChaNonce::from_slice(nonce);

        let payload = Payload {
            msg: plaintext,
            aad: associated_data,
        };

        cipher
            .encrypt(nonce, payload)
            .map_err(|e| NorcError::crypto(format!("Encryption failed: {e}")))
    }

    /// Decrypt data with ChaCha20-Poly1305
    pub fn decrypt(
        key: &SecretKey,
        nonce: &Nonce,
        associated_data: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        if key.len() != 32 {
            return Err(NorcError::crypto("Invalid ChaCha20 key length"));
        }

        let key_bytes: [u8; 32] = key
            .expose_secret()
            .try_into()
            .map_err(|_| NorcError::crypto("Invalid key format"))?;

        let cipher = ChaCha20Poly1305::new(ChaChaKey::from_slice(&key_bytes));
        let nonce = ChaChaNonce::from_slice(nonce);

        let payload = Payload {
            msg: ciphertext,
            aad: associated_data,
        };

        cipher
            .decrypt(nonce, payload)
            .map_err(|e| NorcError::crypto(format!("Decryption failed: {e}")))
    }

    /// Generate a random AEAD key
    pub fn generate_aead_key<R: CryptoRng + RngCore>(rng: &mut R) -> SecretKey {
        let mut key = [0u8; 32];
        rng.fill_bytes(&mut key);
        SecretKey::new(key.to_vec())
    }

    /// Compute BLAKE3 hash
    ///
    /// # Examples
    ///
    /// ```
    /// # use navatron_protocol::crypto::NorcCrypto;
    /// let data = b"hello world";
    /// let hash = NorcCrypto::hash(data);
    /// assert_eq!(hash.len(), 32);
    /// ```
    pub fn hash(data: &[u8]) -> Hash {
        let mut hasher = Hasher::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    /// Compute BLAKE3 hash of multiple inputs
    pub fn hash_multi(inputs: &[&[u8]]) -> Hash {
        let mut hasher = Hasher::new();
        for input in inputs {
            hasher.update(input);
        }
        hasher.finalize().into()
    }

    /// HKDF key derivation with NORC domain separation
    ///
    /// # Examples
    ///
    /// ```
    /// # use navatron_protocol::crypto::NorcCrypto;
    /// let ikm = b"input key material";
    /// let salt = b"salt";
    /// let info = b"application info";
    /// let key = NorcCrypto::hkdf(ikm, salt, info, 32)?;
    /// assert_eq!(key.len(), 32);
    /// # Ok::<(), navatron_protocol::NorcError>(())
    /// ```
    pub fn hkdf(
        input_key_material: &[u8],
        salt: &[u8],
        info: &[u8],
        length: usize,
    ) -> Result<SecretKey> {
        let hk = Hkdf::<Sha256>::new(Some(salt), input_key_material);

        // Prepend NORC domain separation to info
        let mut norc_info = Vec::with_capacity(NORC_HKDF_PREFIX.len() + info.len());
        norc_info.extend_from_slice(NORC_HKDF_PREFIX);
        norc_info.extend_from_slice(info);

        let mut output = vec![0u8; length];
        hk.expand(&norc_info, &mut output)
            .map_err(|e| NorcError::crypto(format!("HKDF expand failed: {e}")))?;

        Ok(SecretKey::new(output))
    }

    /// Derive session keys from shared secret using NORC protocol
    pub fn derive_session_keys(
        shared_secret: &SecretKey,
        client_nonce: &[u8],
        server_nonce: &[u8],
        transcript_hash: &Hash,
    ) -> Result<SessionKeys> {
        // Combine nonces as salt
        let mut salt = Vec::with_capacity(client_nonce.len() + server_nonce.len());
        salt.extend_from_slice(client_nonce);
        salt.extend_from_slice(server_nonce);

        // Master secret with transcript hash in info
        let mut ms_info = Vec::new();
        ms_info.extend_from_slice(b"ms:v1");
        ms_info.extend_from_slice(transcript_hash);
        let master_secret = Self::hkdf(
            shared_secret.expose_secret(),
            &salt,
            &ms_info,
            32,
        )?;

        // Directional traffic keys
        let client_to_server = Self::hkdf(
            master_secret.expose_secret(),
            &[],
            b"tk:c2s:v1",
            32,
        )?;

        let server_to_client = Self::hkdf(
            master_secret.expose_secret(),
            &[],
            b"tk:s2c:v1",
            32,
        )?;

        Ok(SessionKeys {
            master_secret,
            client_to_server,
            server_to_client,
        })
    }

    /// Generate content key and per-device wrapping
    pub fn wrap_content_key<R: CryptoRng + RngCore>(
        rng: &mut R,
        recipient_public_keys: &[(crate::types::DeviceId, EphemeralPublicKey)],
        message_id: &[u8],
    ) -> Result<(SecretKey, Vec<(crate::types::DeviceId, Vec<u8>)>)> {
        // Generate content key
        let content_key = Self::generate_aead_key(rng);

        let mut wrapped_keys = Vec::new();

        for (device_id, recipient_public_key) in recipient_public_keys {
            // Generate ephemeral key pair for this recipient
            let (ephemeral_public, ephemeral_secret) = Self::generate_exchange_keypair(rng);

            // Perform key exchange
            let shared_secret = Self::key_exchange(&ephemeral_secret, recipient_public_key)?;

            // Derive wrapping key
            let device_id_bytes = device_id.as_bytes();
            let mut wrap_info = Vec::new();
            wrap_info.extend_from_slice(b"wrap:v1");
            wrap_info.extend_from_slice(device_id_bytes);
            wrap_info.extend_from_slice(message_id);
            let wrap_key = Self::hkdf(
                shared_secret.expose_secret(),
                &Self::hash(content_key.expose_secret()),
                &wrap_info,
                32,
            )?;

            // Encrypt content key
            let mut nonce_material = Vec::new();
            nonce_material.extend_from_slice(device_id_bytes);
            nonce_material.extend_from_slice(message_id);
            let nonce_hash = Self::hash(&nonce_material);
            let nonce = nonce_hash[..12].try_into().unwrap();

            let aad = Self::build_aad(0, 0, 0, 0, *device_id, &nonce_hash)?;
            let wrapped = Self::encrypt(&wrap_key, &nonce, &aad, content_key.expose_secret())?;

            // Include ephemeral public key with wrapped content
            let mut full_wrapped = Vec::with_capacity(32 + wrapped.len());
            full_wrapped.extend_from_slice(&ephemeral_public);
            full_wrapped.extend_from_slice(&wrapped);

            wrapped_keys.push((*device_id, full_wrapped));
        }

        Ok((content_key, wrapped_keys))
    }

    /// Build Additional Authenticated Data (AAD) for AEAD operations
    pub fn build_aad(
        proto_major: u8,
        proto_minor: u8,
        message_type: u8,
        sequence_number: u64,
        message_id: uuid::Uuid,
        prev_message_hash: &Hash,
    ) -> Result<Vec<u8>> {
        let mut aad = Vec::with_capacity(1 + 1 + 1 + 8 + 16 + 4 + 32 + 32);

        aad.push(proto_major);
        aad.push(proto_minor);
        aad.push(message_type);
        aad.extend_from_slice(&sequence_number.to_be_bytes());
        aad.extend_from_slice(message_id.as_bytes());
        aad.extend_from_slice(&0u32.to_be_bytes()); // ciphertext_length placeholder
        aad.extend_from_slice(prev_message_hash);
        aad.extend_from_slice(&[0u8; 32]); // transcript_hash placeholder for non-handshake

        Ok(aad)
    }

    /// Constant-time comparison for cryptographic operations
    pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }

        let mut result = 0u8;
        for (x, y) in a.iter().zip(b.iter()) {
            result |= x ^ y;
        }
        result == 0
    }
}

/// Session keys derived from handshake
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct SessionKeys {
    /// Master secret for further key derivation
    pub master_secret: SecretKey,
    /// Client-to-server traffic key
    pub client_to_server: SecretKey,
    /// Server-to-client traffic key
    pub server_to_client: SecretKey,
}

impl SessionKeys {
    /// Derive per-message key from traffic key
    pub fn derive_message_key(
        &self,
        direction: Direction,
        sequence_number: u64,
    ) -> Result<SecretKey> {
        let base_key = match direction {
            Direction::ClientToServer => &self.client_to_server,
            Direction::ServerToClient => &self.server_to_client,
        };

        let info = format!("msg:{}:{}", direction, sequence_number);
        NorcCrypto::hkdf(base_key.expose_secret(), &[], info.as_bytes(), 32)
    }
}

/// Message direction for key derivation
#[derive(Debug, Clone, Copy)]
pub enum Direction {
    /// Client to server
    ClientToServer,
    /// Server to client
    ServerToClient,
}

impl std::fmt::Display for Direction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ClientToServer => write!(f, "c2s"),
            Self::ServerToClient => write!(f, "s2c"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signing_roundtrip() {
        let mut rng = rand::thread_rng();
        let (public_key, secret_key) = NorcCrypto::generate_signing_keypair(&mut rng);
        let data = b"test message";

        let signature = NorcCrypto::sign(&secret_key, data).unwrap();
        assert!(NorcCrypto::verify(&public_key, data, &signature).unwrap());

        // Wrong data should fail
        assert!(!NorcCrypto::verify(&public_key, b"wrong data", &signature).unwrap());
    }

    #[test]
    fn test_key_exchange() {
        let mut rng = rand::thread_rng();
        let (alice_public, alice_secret) = NorcCrypto::generate_exchange_keypair(&mut rng);
        let (bob_public, bob_secret) = NorcCrypto::generate_exchange_keypair(&mut rng);

        let alice_shared = NorcCrypto::key_exchange(&alice_secret, &bob_public).unwrap();
        let bob_shared = NorcCrypto::key_exchange(&bob_secret, &alice_public).unwrap();

        assert_eq!(alice_shared.expose_secret(), bob_shared.expose_secret());
    }

    #[test]
    fn test_aead_roundtrip() {
        let mut rng = rand::thread_rng();
        let key = NorcCrypto::generate_aead_key(&mut rng);
        let nonce = NorcCrypto::generate_nonce(&mut rng);
        let plaintext = b"secret message";
        let aad = b"associated data";

        let ciphertext = NorcCrypto::encrypt(&key, &nonce, aad, plaintext).unwrap();
        let decrypted = NorcCrypto::decrypt(&key, &nonce, aad, &ciphertext).unwrap();

        assert_eq!(&decrypted, plaintext);

        // Wrong AAD should fail
        assert!(NorcCrypto::decrypt(&key, &nonce, b"wrong aad", &ciphertext).is_err());
    }

    #[test]
    fn test_hashing() {
        let data = b"test data";
        let hash1 = NorcCrypto::hash(data);
        let hash2 = NorcCrypto::hash(data);
        assert_eq!(hash1, hash2);

        let different_data = b"different data";
        let hash3 = NorcCrypto::hash(different_data);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_hkdf() {
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"application info";

        let key1 = NorcCrypto::hkdf(ikm, salt, info, 32).unwrap();
        let key2 = NorcCrypto::hkdf(ikm, salt, info, 32).unwrap();
        assert_eq!(key1.expose_secret(), key2.expose_secret());

        let key3 = NorcCrypto::hkdf(ikm, salt, b"different info", 32).unwrap();
        assert_ne!(key1.expose_secret(), key3.expose_secret());
    }

    #[test]
    fn test_session_key_derivation() {
        let mut rng = rand::thread_rng();
        let shared_secret = NorcCrypto::generate_aead_key(&mut rng);
        let client_nonce = b"client_nonce_123";
        let server_nonce = b"server_nonce_456";
        let transcript_hash = NorcCrypto::hash(b"transcript");

        let keys = NorcCrypto::derive_session_keys(
            &shared_secret,
            client_nonce,
            server_nonce,
            &transcript_hash,
        )
        .unwrap();

        // Keys should be different
        assert_ne!(
            keys.client_to_server.expose_secret(),
            keys.server_to_client.expose_secret()
        );

        // Message keys should be derivable
        let msg_key = keys
            .derive_message_key(Direction::ClientToServer, 1)
            .unwrap();
        assert_eq!(msg_key.len(), 32);
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(NorcCrypto::constant_time_eq(b"hello", b"hello"));
        assert!(!NorcCrypto::constant_time_eq(b"hello", b"world"));
        assert!(!NorcCrypto::constant_time_eq(b"hello", b"hell"));
    }
}