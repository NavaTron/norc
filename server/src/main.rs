use std::{collections::HashMap, net::SocketAddr};
use axum::{routing::post, Router, Json};
use axum::http::StatusCode;
use axum::serve; // serve(listener, app)
use axum::extract::ws::{WebSocketUpgrade, Message, WebSocket};
use axum::response::IntoResponse;
use tokio::net::TcpListener;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use uuid::Uuid;
use ed25519_dalek::VerifyingKey;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};
use rand::rngs::OsRng;
use blake3;
use hkdf::Hkdf;
use sha2::Sha256;
use base64::{engine::general_purpose::STANDARD as b64, Engine as _};
use std::convert::TryInto;

// Supported protocol versions (ordered descending preference)
static SUPPORTED_VERSIONS: &[&str] = &["1.1", "1.0"]; // scaffold
static SERVER_CAPABILITIES: &[&str] = &["messaging", "registration"]; // minimal example

// Global in-memory store (bear minimal; in production use persistent storage)
static DEVICE_STORE: Lazy<Mutex<HashMap<Uuid, RegisteredDevice>>> = Lazy::new(|| Mutex::new(HashMap::new()));

#[derive(Debug, Deserialize)]
struct DeviceRegisterRequest {
    device_id: Uuid,
    public_key: String, // base64 or hex; for minimal demo we'll accept hex
    device_info: Option<DeviceInfo>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct DeviceInfo {
    name: Option<String>,
    r#type: Option<String>,
    capabilities: Option<Vec<String>>, // e.g. ["messaging"]
}

#[derive(Debug, Serialize, Clone)]
struct RegisteredDevice {
    device_id: Uuid,
    public_key: String,
    device_info: Option<DeviceInfo>,
    first_registered_timestamp: i64,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum RegisterResponse {
    Registered { device: RegisteredDevice },
    AlreadyRegistered { device: RegisteredDevice },
    InvalidKey { message: String },
}

#[derive(Debug, Deserialize)]
struct ConnectRequest {
    client_versions: Vec<String>,
    preferred_version: Option<String>,
    capabilities: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
struct ConnectResponse {
    negotiated_version: String,
    compatibility_mode: bool,
    server_capabilities: Vec<&'static str>,
    // Echo back original for potential transcript binding later
    client_versions: Vec<String>,
    server_versions: Vec<&'static str>,
}

async fn connect(Json(req): Json<ConnectRequest>) -> (StatusCode, Json<ConnectResponse>) {
    // Pick highest mutual version using simple lexical descending order of our SUPPORTED_VERSIONS
    let mut chosen: Option<&str> = None;
    for v in SUPPORTED_VERSIONS.iter() {
        if req.client_versions.iter().any(|cv| cv == v) { chosen = Some(v); break; }
    }
    // Fall back: if none match, choose first compatible (adjacent-major) per simplified AMC rule
    if chosen.is_none() {
        for sv in SUPPORTED_VERSIONS.iter() {
            if req.client_versions.iter().any(|cv| is_adjacent_major(cv, sv)) { chosen = Some(sv); break; }
        }
    }
    let negotiated = chosen.unwrap_or(SUPPORTED_VERSIONS.last().cloned().unwrap());
    let highest_mutual = negotiated == SUPPORTED_VERSIONS[0] && req.client_versions.iter().any(|c| c == SUPPORTED_VERSIONS[0]);
    (
        StatusCode::OK,
        Json(ConnectResponse {
            negotiated_version: negotiated.to_string(),
            compatibility_mode: !highest_mutual,
            server_capabilities: SERVER_CAPABILITIES.to_vec(),
            client_versions: req.client_versions,
            server_versions: SUPPORTED_VERSIONS.to_vec(),
        })
    )
}

fn is_adjacent_major(a: &str, b: &str) -> bool {
    fn parse(v: &str) -> Option<(i32,i32)> {
        let parts: Vec<_> = v.split('.').collect();
        if parts.len() >= 2 { Some((parts[0].parse().ok()?, parts[1].parse().ok()?)) } else { None }
    }
    match (parse(a), parse(b)) {
        (Some((ma,_)), Some((mb,_))) => (ma - mb).abs() <= 1,
        _ => false
    }
}

async fn register_device(Json(req): Json<DeviceRegisterRequest>) -> (StatusCode, Json<RegisterResponse>) {
    // Validate public key (expect 64 hex chars for Ed25519 PK 32 bytes)
    if let Err(e) = parse_public_key_hex(&req.public_key) {
        return (StatusCode::BAD_REQUEST, Json(RegisterResponse::InvalidKey { message: e }));
    }

    let mut store = DEVICE_STORE.lock().expect("device store poisoned");
    let now = chrono::Utc::now().timestamp();
    if let Some(existing) = store.get(&req.device_id) {
        return (StatusCode::OK, Json(RegisterResponse::AlreadyRegistered { device: existing.clone() }));
    }
    let device = RegisteredDevice {
        device_id: req.device_id,
        public_key: req.public_key.clone(),
        device_info: req.device_info.clone(),
        first_registered_timestamp: now,
    };
    store.insert(req.device_id, device.clone());
    (StatusCode::CREATED, Json(RegisterResponse::Registered { device }))
}

fn parse_public_key_hex(pk_hex: &str) -> Result<VerifyingKey, String> {
    let bytes = hex::decode(pk_hex).map_err(|e| format!("invalid hex: {e}"))?;
    VerifyingKey::from_bytes(&bytes.try_into().map_err(|_| "public key must be 32 bytes" )?)
        .map_err(|e| format!("invalid Ed25519 key: {e}"))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Simple router with one endpoint
    let app = Router::new()
        .route("/connect", post(connect))
        .route("/register", post(register_device));
    let app = app.route("/ws", axum::routing::get(ws_handler));

    let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
    println!("NORC minimal registration server listening on {addr}");
    let listener = TcpListener::bind(addr).await?;
    serve(listener, app.into_make_service()).await?;
    Ok(())
}

// ---------------- WebSocket Handshake (NORC-C scaffold) ----------------

#[derive(Deserialize, Serialize, Debug)]
struct ClientHello {
    r#type: String, // "client_hello"
    client_versions: Vec<String>,
    preferred_version: Option<String>,
    capabilities: Option<Vec<String>>,
    nonce: String, // base64 16 bytes
    ephemeral_pub: String, // base64 X25519 32 bytes
}

#[derive(Deserialize, Serialize, Debug)]
struct ServerHello {
    r#type: String, // "server_hello"
    negotiated_version: String,
    compatibility_mode: bool,
    server_capabilities: Vec<String>,
    nonce: String, // base64 16 bytes
    ephemeral_pub: String, // base64 32 bytes
    transcript_hash: String, // base64 32 bytes (BLAKE3)
}

async fn ws_handler(ws: WebSocketUpgrade) -> impl IntoResponse { ws.on_upgrade(handle_ws) }

async fn handle_ws(mut socket: WebSocket) {
    // Expect first message ClientHello JSON text
    let Some(Ok(Message::Text(txt))) = socket.recv().await else { return; };
    let parsed: Result<ClientHello, _> = serde_json::from_str(&txt);
    let client_hello = match parsed { Ok(c) => c, Err(_) => { let _ = socket.send(Message::Close(None)).await; return; } };
    if client_hello.r#type != "client_hello" { let _ = socket.send(Message::Close(None)).await; return; }

    // Version negotiation similar to /connect
    let mut chosen: Option<&str> = None;
    for v in SUPPORTED_VERSIONS.iter() { if client_hello.client_versions.iter().any(|cv| cv == v) { chosen = Some(v); break; } }
    if chosen.is_none() {
        for sv in SUPPORTED_VERSIONS.iter() { if client_hello.client_versions.iter().any(|cv| is_adjacent_major(cv, sv)) { chosen = Some(sv); break; }}
    }
    let negotiated = chosen.unwrap_or(SUPPORTED_VERSIONS.last().cloned().unwrap());
    let compatibility_mode = !(negotiated == SUPPORTED_VERSIONS[0] && client_hello.client_versions.iter().any(|c| c == SUPPORTED_VERSIONS[0]));

    // Ephemeral X25519
    let server_secret = EphemeralSecret::random_from_rng(OsRng);
    let server_pub = X25519PublicKey::from(&server_secret);
    let client_pub_raw = match b64.decode(client_hello.ephemeral_pub.as_bytes()) { Ok(b) => b, Err(_) => { let _ = socket.send(Message::Close(None)).await; return;} };
    if client_pub_raw.len() != 32 { let _ = socket.send(Message::Close(None)).await; return; }
    let client_pub_arr: [u8;32] = match client_pub_raw.try_into() { Ok(a) => a, Err(_) => { let _ = socket.send(Message::Close(None)).await; return; } };
    let client_pub = X25519PublicKey::from(client_pub_arr);
    let shared = server_secret.diffie_hellman(&client_pub);

    // Transcript: canonical concat of JSON (client then server minus transcript field) using sorted keys of original string & provisional server fields
    let server_nonce = random_nonce();
    // Build preliminary server hello without transcript hash
    let pre_server = serde_json::json!({
        "type": "server_hello",
        "negotiated_version": negotiated,
        "compatibility_mode": compatibility_mode,
        "server_capabilities": SERVER_CAPABILITIES,
        "nonce": base64::engine::general_purpose::STANDARD.encode(&server_nonce),
        "ephemeral_pub": b64.encode(server_pub.as_bytes()),
    });
    let transcript_material = format!("{}{}", canonical(&txt), canonical(&pre_server.to_string()));
    let th_bytes = blake3::hash(transcript_material.as_bytes()).as_bytes().to_vec();
    let th_b64 = b64.encode(&th_bytes);

    // Derive master secret (HKDF-SHA256 for demo; spec uses HKDF with domain label + BLAKE3 by default; this is placeholder)
    let hk = Hkdf::<Sha256>::new(Some(&client_nonce_bytes(&client_hello.nonce)), shared.as_bytes());
    let mut ms = [0u8;32];
    if hk.expand(b"norc:ms:v1", &mut ms).is_err() { let _ = socket.send(Message::Close(None)).await; return; }

    let server_hello = ServerHello {
        r#type: "server_hello".into(),
        negotiated_version: negotiated.to_string(),
        compatibility_mode,
        server_capabilities: SERVER_CAPABILITIES.iter().map(|s| s.to_string()).collect(),
        nonce: b64.encode(server_nonce),
        ephemeral_pub: b64.encode(server_pub.as_bytes()),
        transcript_hash: th_b64.clone(),
    };

    let _ = socket.send(Message::Text(serde_json::to_string(&server_hello).unwrap())).await;

    // Optionally: wait for a follow-up message (e.g. device_register) (not implemented here)
}

fn random_nonce() -> [u8;16] { rand::random::<[u8;16]>() }

fn client_nonce_bytes(b64s: &str) -> Vec<u8> { b64.decode(b64s.as_bytes()).unwrap_or_default() }

// Simplistic canonicalization: parse -> serde_json::Value -> sort keys recursively -> reserialize
fn canonical(input: &str) -> String {
    match serde_json::from_str::<serde_json::Value>(input) {
        Ok(v) => canonical_value(&v),
        Err(_) => input.to_string(),
    }
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

