use std::{collections::HashMap, net::SocketAddr};
use axum::{routing::post, Router, Json};
use axum::http::StatusCode;
use axum::serve; // serve(listener, app)
use tokio::net::TcpListener;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use uuid::Uuid;
use ed25519_dalek::VerifyingKey;

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

    let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
    println!("NORC minimal registration server listening on {addr}");
    let listener = TcpListener::bind(addr).await?;
    serve(listener, app.into_make_service()).await?;
    Ok(())
}

