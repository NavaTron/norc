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
use rand::rngs::OsRng;
use base64::{engine::general_purpose::STANDARD as b64, Engine as _};
use std::convert::TryInto;
use norc_core::{ClientHello, ServerHello, SUPPORTED_VERSIONS, negotiate_version, compute_transcript_hash, derive_master_secret, DeviceRegisterRequest, RegisterResponse, RegisteredDevice};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

// Supported protocol versions (ordered descending preference)
// Supported versions now provided by norc_core; local server capabilities remain here.
static SERVER_CAPABILITIES: &[&str] = &["messaging", "registration"]; // minimal example

// Global in-memory store (bear minimal; in production use persistent storage)
static DEVICE_STORE: Lazy<Mutex<HashMap<Uuid, RegisteredDevice>>> = Lazy::new(|| Mutex::new(HashMap::new()));

// (Removed local duplicate protocol structs; using norc_core types)

#[derive(Debug, Deserialize)]
struct ConnectRequest {
    client_versions: Vec<String>,
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
    let (negotiated, compatibility_mode) = negotiate_version(&req.client_versions);
    (
        StatusCode::OK,
        Json(ConnectResponse {
            negotiated_version: negotiated.clone(),
            compatibility_mode,
            server_capabilities: SERVER_CAPABILITIES.to_vec(),
            client_versions: req.client_versions,
            server_versions: SUPPORTED_VERSIONS.to_vec(),
        })
    )
}

// (Removed unused is_adjacent_major; negotiation handled by norc_core.)

async fn register_device(Json(req): Json<DeviceRegisterRequest>) -> (StatusCode, Json<RegisterResponse>) {
    let resp = register_device_process(req);
    let status = match &resp {
        RegisterResponse::Registered { .. } => StatusCode::CREATED,
        RegisterResponse::AlreadyRegistered { .. } => StatusCode::OK,
        RegisterResponse::InvalidKey { .. } => StatusCode::BAD_REQUEST,
    };
    (status, Json(resp))
}

fn parse_public_key_hex(pk_hex: &str) -> Result<VerifyingKey, String> {
    let bytes = hex::decode(pk_hex).map_err(|e| format!("invalid hex: {e}"))?;
    VerifyingKey::from_bytes(&bytes.try_into().map_err(|_| "public key must be 32 bytes" )?)
        .map_err(|e| format!("invalid Ed25519 key: {e}"))
}

// Core registration logic reusable for HTTP + WebSocket
fn register_device_process(req: DeviceRegisterRequest) -> RegisterResponse {
    if let Err(e) = parse_public_key_hex(&req.public_key) {
        return RegisterResponse::InvalidKey { message: e };
    }
    let mut store = DEVICE_STORE.lock().expect("device store poisoned");
    if let Some(existing) = store.get(&req.device_id) {
        return RegisterResponse::AlreadyRegistered { device: existing.clone() };
    }
    let now = chrono::Utc::now().timestamp();
    let device = RegisteredDevice {
        device_id: req.device_id,
        public_key: req.public_key,
        device_info: req.device_info,
        first_registered_timestamp: now,
    };
    store.insert(device.device_id, device.clone());
    RegisterResponse::Registered { device }
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

async fn ws_handler(ws: WebSocketUpgrade) -> impl IntoResponse { ws.on_upgrade(handle_ws) }

async fn handle_ws(mut socket: WebSocket) {
    // Expect first message ClientHello JSON text
    let Some(Ok(Message::Text(txt))) = socket.recv().await else { return; };
    let parsed: Result<ClientHello, _> = serde_json::from_str(&txt);
    let client_hello = match parsed { Ok(c) => c, Err(_) => { let _ = socket.send(Message::Close(None)).await; return; } };
    if client_hello.r#type != "client_hello" { let _ = socket.send(Message::Close(None)).await; return; }

    // Version negotiation similar to /connect
    let (negotiated, compatibility_mode) = negotiate_version(&client_hello.client_versions);

    // Ephemeral X25519
    let server_secret = EphemeralSecret::random_from_rng(OsRng);
    let server_pub = X25519PublicKey::from(&server_secret);
    let client_pub_raw = match b64.decode(client_hello.ephemeral_pub.as_bytes()) { Ok(b) => b, Err(_) => { let _ = socket.send(Message::Close(None)).await; return;} };
    if client_pub_raw.len() != 32 { let _ = socket.send(Message::Close(None)).await; return; }
    let client_pub_arr: [u8;32] = match client_pub_raw.try_into() { Ok(a) => a, Err(_) => { let _ = socket.send(Message::Close(None)).await; return; } };
    let client_pub = X25519PublicKey::from(client_pub_arr);
    let shared = server_secret.diffie_hellman(&client_pub);

    // Transcript: canonical concat of JSON (client then server minus transcript field) using sorted keys of original string & provisional server fields
    let server_nonce = norc_core::random_nonce();
    // Build preliminary server hello without transcript hash
    let pre_server = serde_json::json!({
        "type": "server_hello",
        "negotiated_version": negotiated,
        "compatibility_mode": compatibility_mode,
        "server_capabilities": SERVER_CAPABILITIES,
        "nonce": base64::engine::general_purpose::STANDARD.encode(&server_nonce),
        "ephemeral_pub": b64.encode(server_pub.as_bytes()),
    });
    let th_bytes = compute_transcript_hash(&txt, &pre_server.to_string());
    let th_b64 = b64.encode(th_bytes);

    // Derive master secret (HKDF-SHA256 for demo; spec uses HKDF with domain label + BLAKE3 by default; this is placeholder)
    let _ms = derive_master_secret(&client_hello.nonce, shared.as_bytes());

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

    // Await optional device registration over WS
    if let Some(Ok(Message::Text(reg_txt))) = socket.recv().await {
        #[derive(Deserialize)]
        struct WsDeviceRegister {
            r#type: String,
            device_id: Uuid,
            public_key: String,
            device_info: Option<norc_core::DeviceInfo>,
        }
        if let Ok(ws_reg) = serde_json::from_str::<WsDeviceRegister>(&reg_txt) {
            if ws_reg.r#type == "device_register" {
                let resp = register_device_process(DeviceRegisterRequest {
                    device_id: ws_reg.device_id,
                    public_key: ws_reg.public_key,
                    device_info: ws_reg.device_info,
                });
                #[derive(Serialize)]
                struct WsRegisterResponse<'a> {
                    r#type: &'a str,
                    #[serde(flatten)]
                    inner: RegisterResponse,
                }
                let outbound = WsRegisterResponse { r#type: "register_response", inner: resp };
                let _ = socket.send(Message::Text(serde_json::to_string(&outbound).unwrap())).await;
            }
        }
    }
}

// Removed local canonicalization helpers (in norc_core now)

