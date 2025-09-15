//! norc_core: shared protocol primitives for NORC client/server

use serde::{Serialize, Deserialize};
use base64::{engine::general_purpose::STANDARD as b64, Engine as _};
use hkdf::Hkdf;
use sha2::Sha256; // placeholder until HKDF-BLAKE3 decided
use uuid::Uuid;
use thiserror::Error;

// Supported versions (could later be built dynamically)
pub const SUPPORTED_VERSIONS: &[&str] = &["1.1", "1.0"];

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ClientHello {
    pub r#type: String,          // "client_hello"
    pub client_versions: Vec<String>,
    pub preferred_version: Option<String>,
    pub capabilities: Option<Vec<String>>,
    pub nonce: String,           // base64 16 bytes
    pub ephemeral_pub: String,   // base64 32 bytes
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServerHello {
    pub r#type: String, // "server_hello"
    pub negotiated_version: String,
    pub compatibility_mode: bool,
    pub server_capabilities: Vec<String>,
    pub nonce: String,
    pub ephemeral_pub: String,
    pub transcript_hash: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DeviceInfo {
    pub name: Option<String>,
    pub r#type: Option<String>,
    pub capabilities: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DeviceRegisterRequest {
    pub device_id: Uuid,
    pub public_key: String,
    pub device_info: Option<DeviceInfo>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum RegisterResponse {
    Registered { device: RegisteredDevice },
    AlreadyRegistered { device: RegisteredDevice },
    InvalidKey { message: String },
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RegisteredDevice {
    pub device_id: Uuid,
    pub public_key: String,
    pub device_info: Option<DeviceInfo>,
    pub first_registered_timestamp: i64,
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("invalid message type")] InvalidMessageType,
    #[error("decode error: {0}")] Decode(String),
    #[error("crypto error")] Crypto,
}

pub fn is_adjacent_major(a: &str, b: &str) -> bool {
    fn parse(v: &str) -> Option<(i32,i32)> {
        let parts: Vec<_> = v.split('.').collect();
        if parts.len() >= 2 { Some((parts[0].parse().ok()?, parts[1].parse().ok()?)) } else { None }
    }
    match (parse(a), parse(b)) { (Some((ma,_)), Some((mb,_))) => (ma - mb).abs() <= 1, _ => false }
}

pub fn negotiate_version(client_versions: &[String]) -> (String, bool) {
    // Choose highest mutual
    let mut chosen: Option<&str> = None;
    for v in SUPPORTED_VERSIONS.iter() {
        if client_versions.iter().any(|cv| cv == v) { chosen = Some(v); break; }
    }
    if chosen.is_none() {
        for sv in SUPPORTED_VERSIONS.iter() {
            if client_versions.iter().any(|cv| is_adjacent_major(cv, sv)) { chosen = Some(sv); break; }
        }
    }
    let negotiated = chosen.unwrap_or(SUPPORTED_VERSIONS.last().cloned().unwrap());
    let compatibility_mode = !(negotiated == SUPPORTED_VERSIONS[0] && client_versions.iter().any(|c| c == SUPPORTED_VERSIONS[0]));
    (negotiated.to_string(), compatibility_mode)
}

pub fn random_nonce() -> [u8;16] { rand::random::<[u8;16]>() }

pub fn canonical_json(input: &str) -> String {
    match serde_json::from_str::<serde_json::Value>(input) { Ok(v) => canonical_value(&v), Err(_) => input.to_string() }
}

fn canonical_value(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<_> = map.keys().collect();
            keys.sort();
            let mut parts = Vec::new();
            for k in keys { parts.push(format!("\"{}\":{}", k, canonical_value(&map[k]))); }
            format!("{{{}}}", parts.join(","))
        }
        serde_json::Value::Array(arr) => {
            let inner: Vec<_> = arr.iter().map(canonical_value).collect();
            format!("[{}]", inner.join(","))
        }
        _ => v.to_string(),
    }
}

// (Removed unused HandshakeSecrets and derive_handshake to reduce warnings.)

pub fn compute_transcript_hash(client_hello_raw: &str, provisional_server_json: &str) -> [u8;32] {
    let material = format!("{}{}", canonical_json(client_hello_raw), canonical_json(provisional_server_json));
    *blake3::hash(material.as_bytes()).as_bytes()
}

pub fn derive_master_secret(client_nonce_b64: &str, shared: &[u8]) -> [u8;32] {
    let salt = b64.decode(client_nonce_b64.as_bytes()).unwrap_or_default();
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut ms = [0u8;32];
    let _ = hk.expand(b"norc:ms:v1", &mut ms); // ignore error for now
    ms
}
