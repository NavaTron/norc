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
use norc_core::{ClientHello, ServerHello, SUPPORTED_VERSIONS, negotiate_version, compute_transcript_hash, derive_master_secret, DeviceRegisterRequest, RegisterResponse, RegisteredDevice, derive_session_keys, aead_encrypt, aead_decrypt, AeadDirection, SessionKeys, NorcMessage, next_nonce};
use tracing::{info, debug};
use futures_util::{StreamExt, SinkExt};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

// Supported protocol versions (ordered descending preference)
// Supported versions now provided by norc_core; local server capabilities remain here.
static SERVER_CAPABILITIES: &[&str] = &["messaging", "registration"]; // minimal example

// Global in-memory store (bear minimal; in production use persistent storage)
static DEVICE_STORE: Lazy<Mutex<HashMap<Uuid, RegisteredDevice>>> = Lazy::new(|| Mutex::new(HashMap::new()));
// Active websocket sessions for broadcast (device_id -> session)
type Tx = tokio::sync::mpsc::UnboundedSender<Message>;
#[derive(Clone)]
struct Session {
    tx: Tx,
    session_keys: SessionKeys,
    s2c_nonce: u64,
    c2s_nonce: u64,
}
static SESSIONS: Lazy<Mutex<HashMap<Uuid, Session>>> = Lazy::new(|| Mutex::new(HashMap::new()));

// ChatCiphertext now represented by NorcMessage::ChatCiphertext in core

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
    init_tracing();
    info!(%addr, "NORC server listening");
    let listener = TcpListener::bind(addr).await?;
    serve(listener, app.into_make_service()).await?;
    Ok(())
}

// ---------------- WebSocket Handshake (NORC-C scaffold) ----------------

async fn ws_handler(ws: WebSocketUpgrade) -> impl IntoResponse { ws.on_upgrade(handle_ws) }

async fn handle_ws(mut socket: WebSocket) {
    // Expect first message ClientHello JSON text
    let Some(Ok(Message::Text(txt))) = socket.recv().await else { return; };
    debug!(len = txt.len(), "Received initial frame");
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
    let ms = derive_master_secret(&client_hello.nonce, shared.as_bytes());
    let session_keys = derive_session_keys(&ms, &th_bytes);
    info!(c2s = %hex::encode(&session_keys.client_to_server_key[..8]), s2c = %hex::encode(&session_keys.server_to_client_key[..8]), "Derived session keys");

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

    // Wrap socket with channel for broadcast
    let (mut ws_sender, mut ws_receiver) = socket.split();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Message>();
    // For now we don't know device_id until registration; stash provisional None
    let mut device_id_opt: Option<Uuid> = None;
    // Forward outgoing messages task
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            let _ = ws_sender.send(msg).await;
        }
    });

    // Await optional device registration over WS
    if let Some(Ok(Message::Text(reg_txt))) = ws_receiver.next().await {
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
                let outbound = WsRegisterResponse { r#type: "register_response", inner: resp.clone() };
                let _ = tx.send(Message::Text(serde_json::to_string(&outbound).unwrap()));
                // Store session for broadcast if registered
                if let RegisterResponse::Registered { device } | RegisterResponse::AlreadyRegistered { device } = resp {
                    device_id_opt = Some(device.device_id);
                    let session = Session { tx: tx.clone(), session_keys: session_keys.clone(), s2c_nonce: 0, c2s_nonce: 0 };
                    SESSIONS.lock().unwrap().insert(device.device_id, session);
                    info!(device_id = %device.device_id, "Device registered");
                }
            }
        }
    }

    // If registered, begin chat loop (encrypted inbound/outbound)
    if let Some(dev_id) = device_id_opt {
        while let Some(msg_res) = ws_receiver.next().await {
            let Ok(msg) = msg_res else { break };
            match msg {
                Message::Text(txt) => {
                    if let Ok(msg_enum) = serde_json::from_str::<NorcMessage>(&txt) {
                        match msg_enum {
                            NorcMessage::ChatCiphertext { sender: _, nonce, ciphertext_b64 } => {
                                let mut sessions = SESSIONS.lock().unwrap();
                                if let Some(session) = sessions.get_mut(&dev_id) {
                                    if let Ok(ct) = b64.decode(ciphertext_b64.as_bytes()) {
                                        if let Ok(plain) = aead_decrypt(AeadDirection::ClientToServer, &session.session_keys, nonce, &ct, b"chat") {
                                            if let Ok(plain_str) = String::from_utf8(plain) {
                                                debug!(from = %dev_id, nonce, len = plain_str.len(), "Inbound chat decrypted");
                                                broadcast_plain(&plain_str, dev_id);
                                            }
                                        }
                                    }
                                    let _ = next_nonce(&mut session.c2s_nonce); // increment with safeguard
                                }
                            }
                            NorcMessage::ChatPlain { body } => {
                                debug!(from = %dev_id, len = body.len(), "Inbound plaintext chat");
                                broadcast_plain(&body, dev_id);
                            }
                        }
                    }
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
        // Remove session on exit
        SESSIONS.lock().unwrap().remove(&dev_id);
        info!(device_id = %dev_id, "Session closed");
    }
}
fn broadcast_plain(plaintext: &str, from: Uuid) {
    let mut to_send: Vec<(Tx, String)> = Vec::new();
    {
        let mut sessions = SESSIONS.lock().unwrap();
        for (dev, session) in sessions.iter_mut() {
            if *dev == from { continue; }
            let nonce = session.s2c_nonce;
            if let Ok(ct) = aead_encrypt(AeadDirection::ServerToClient, &session.session_keys, nonce, plaintext.as_bytes(), b"chat") {
                session.s2c_nonce = session.s2c_nonce.wrapping_add(1);
                let chat_msg = NorcMessage::ChatCiphertext { sender: from, nonce, ciphertext_b64: b64.encode(ct) };
                to_send.push((session.tx.clone(), serde_json::to_string(&chat_msg).unwrap()));
            }
        }
    }
    for (tx, json) in to_send.iter() { let _ = tx.send(Message::Text(json.clone())); }
    if !to_send.is_empty() { debug!(recipients = to_send.len(), from = %from, len = plaintext.len(), "Broadcasted chat"); }
}

// Removed local canonicalization helpers (in norc_core now)

fn init_tracing() {
    static START: std::sync::Once = std::sync::Once::new();
    START.call_once(|| {
        use tracing_subscriber::EnvFilter;
        let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "info,server=debug".to_string());
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::new(filter))
            .with_target(false)
            .with_level(true)
            .compact()
            .init();
    });
}

