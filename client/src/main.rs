use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize};
use uuid::Uuid;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};
use tokio_tungstenite::connect_async;
use base64::{engine::general_purpose::STANDARD as b64, Engine as _};
use futures_util::{SinkExt, StreamExt};
use std::convert::TryInto;
use norc_core::{ClientHello as CoreClientHello, derive_master_secret, derive_session_keys, aead_encrypt, aead_decrypt, AeadDirection, NorcMessage, next_nonce};
use tokio_tungstenite::tungstenite::protocol::Message;
use std::io::{self, Write};
use tracing::{info, debug, warn};
use tokio::sync::mpsc;
use tokio::task;
fn init_tracing() {
    static START: std::sync::Once = std::sync::Once::new();
    START.call_once(|| {
        use tracing_subscriber::EnvFilter;
        let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "info,client=debug".to_string());
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::new(filter))
            .with_target(false)
            .with_level(true)
            .compact()
            .init();
    });
}

// Structures for WS registration round-trip
#[derive(Debug, serde::Serialize)]
struct WsDeviceRegister {
    r#type: &'static str,
    device_id: Uuid,
    public_key: String,
    device_info: WsDeviceInfo,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct WsDeviceInfo {
    name: String,
    r#type: String,
    capabilities: Vec<String>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum WsRegisterInner {
    Registered { device: WsServerDevice },
    AlreadyRegistered { device: WsServerDevice },
    InvalidKey { message: String },
}

#[derive(Debug, serde::Deserialize)]
struct WsRegisterResponse {
    r#type: String,
    #[serde(flatten)]
    inner: WsRegisterInner,
}

#[derive(Debug, serde::Deserialize)]
struct WsServerDevice {
    device_id: Uuid,
    public_key: String,
    device_info: Option<WsDeviceInfoOpt>,
    first_registered_timestamp: i64,
}

#[derive(Debug, serde::Deserialize)]
struct WsDeviceInfoOpt {
    name: Option<String>,
    r#type: Option<String>,
    capabilities: Option<Vec<String>>,
}

fn log_server_device(d: &WsServerDevice) {
    if let Some(info) = &d.device_info {
        let caps = info.capabilities.as_ref().map(|v| v.join(",")).unwrap_or_else(|| "-".into());
        info!(device_id=%d.device_id, first_registered_ts=d.first_registered_timestamp, name=?info.name, dtype=?info.r#type, caps=%caps, "Server device record");
    } else {
        info!(device_id=%d.device_id, first_registered_ts=d.first_registered_timestamp, "Server device record (no info)");
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let client_versions = vec!["1.1", "1.0"]; // descending preference
    let capabilities = vec!["messaging", "registration"];
    let server_host = std::env::var("NORC_SERVER").unwrap_or_else(|_| "127.0.0.1:8080".into());
    // Derive ws URL (no TLS for demo)
    let ws_url = format!("ws://{}/ws", server_host);
    init_tracing();
    info!(%ws_url, "Connecting WebSocket");
    let (mut ws_stream, _resp) = connect_async(&ws_url).await?;

    // Ephemeral X25519
    let client_secret = EphemeralSecret::random_from_rng(OsRng);
    let client_pub = X25519PublicKey::from(&client_secret);
    let client_nonce: [u8;16] = rand::random();

    // Build ClientHello using norc_core shape (convert &str vecs to owned Strings)
    let ch = CoreClientHello {
        r#type: "client_hello".to_string(),
        client_versions: client_versions.iter().map(|s| s.to_string()).collect(),
        preferred_version: Some("1.1".to_string()),
        capabilities: Some(capabilities.iter().map(|s| s.to_string()).collect()),
        nonce: b64.encode(client_nonce),
        ephemeral_pub: b64.encode(client_pub.as_bytes()),
    };
    let ch_json = serde_json::to_string(&ch)?;
    ws_stream.send(tokio_tungstenite::tungstenite::protocol::Message::Text(ch_json.clone())).await?;

    // Receive ServerHello
    let sh_msg = ws_stream.next().await;
    let server_text = match sh_msg {
        Some(Ok(tokio_tungstenite::tungstenite::protocol::Message::Text(t))) => t,
        other => {
            println!("Unexpected server response: {:?}", other);
            return Ok(());
        }
    };
    debug!(raw=%server_text, "Received ServerHello");
    #[derive(Deserialize)]
    struct ServerHelloResp {
        r#type: String,
        negotiated_version: String,
        compatibility_mode: bool,
        server_capabilities: Vec<String>,
        nonce: String,
        ephemeral_pub: String,
        transcript_hash: String,
    }
    let sh: ServerHelloResp = serde_json::from_str(&server_text)?;
    // Compute transcript hash locally to verify match
    // Accept server transcript hash (client-side recompute can be added later)
    // Use previously unused fields from ServerHello for logging & validation
    let nonce_bytes = match b64.decode(sh.nonce.as_bytes()) { Ok(b) => b, Err(_) => Vec::new() };
    let transcript_ok = sh.transcript_hash.len();
    let intersection: Vec<&str> = capabilities
        .iter()
        .copied()
        .filter(|c| sh.server_capabilities.iter().any(|sc| sc == c))
        .collect();
    info!(version=%sh.negotiated_version, compat=sh.compatibility_mode, server_caps=?sh.server_capabilities, shared_caps=?intersection, nonce_len=nonce_bytes.len(), th_len=transcript_ok, "Negotiated");

    // Derive shared secret + master secret (placeholder HKDF-SHA256 label)
    let server_pub_raw = b64.decode(sh.ephemeral_pub.as_bytes())?;
    if server_pub_raw.len() != 32 { warn!("Bad server ephemeral length"); return Ok(()); }
    let server_pub_arr: [u8;32] = match server_pub_raw.try_into() { Ok(a) => a, Err(_) => { warn!("Ephemeral conversion failed"); return Ok(()); } };
    let server_pub = X25519PublicKey::from(server_pub_arr);
    let shared = client_secret.diffie_hellman(&server_pub);
    let ms = derive_master_secret(&b64.encode(client_nonce), shared.as_bytes());
    let th_bytes = b64.decode(sh.transcript_hash.as_bytes()).unwrap_or_default();
    if th_bytes.len() == 32 {
        let mut th_arr = [0u8;32]; th_arr.copy_from_slice(&th_bytes);
        let session_keys = derive_session_keys(&ms, &th_arr);
        debug!(ms16=%hex::encode(&ms[..16]), c2s=%hex::encode(&session_keys.client_to_server_key[..8]), s2c=%hex::encode(&session_keys.server_to_client_key[..8]), "Derived session keys");
    } else {
        warn!(ms16=%hex::encode(&ms[..16]), "Bad transcript hash length");
    }

    // Perform device registration over WS
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key: VerifyingKey = signing_key.verifying_key();
    let public_key_hex = hex::encode(verifying_key.to_bytes());
    let device_id = Uuid::new_v4();
    let reg = WsDeviceRegister {
        r#type: "device_register",
        device_id,
        public_key: public_key_hex,
        device_info: WsDeviceInfo {
            name: format!("Dev-{}", &device_id.to_string()[..8]),
            r#type: "desktop".into(),
            capabilities: vec!["messaging".into(), "registration".into()],
        },
    };
    let reg_json = serde_json::to_string(&reg)?;
    info!(%device_id, "Sending device_register");
    ws_stream.send(tokio_tungstenite::tungstenite::protocol::Message::Text(reg_json)).await?;

    if let Some(Ok(Message::Text(reg_resp_txt))) = ws_stream.next().await {
        match serde_json::from_str::<WsRegisterResponse>(&reg_resp_txt) {
            Ok(resp) => {
                match resp.inner {
                    WsRegisterInner::Registered { device } | WsRegisterInner::AlreadyRegistered { device } => {
                        info!(r#type=%resp.r#type, "Register response consumed");
                        log_server_device(&device);
                        // After registration, derive session keys again for use in loop
                    }
                    WsRegisterInner::InvalidKey { message } => {
                        warn!(r#type=%resp.r#type, %message, "Registration failed");
                    }
                }
            }
            Err(e) => {
                warn!(error=%e.to_string(), raw=%reg_resp_txt, "Failed to parse WS register response");
            }
        }
    } else {
        warn!("No WS register response received");
    }

    // Interactive encrypted chat loop with duplex split
    let sh_val: serde_json::Value = serde_json::from_str(&server_text)?;
    if let Some(th_b64) = sh_val.get("transcript_hash").and_then(|t| t.as_str()) {
        if let Ok(th_raw) = b64.decode(th_b64) { if th_raw.len()==32 {
            let mut th_arr=[0u8;32]; th_arr.copy_from_slice(&th_raw);
            let session_keys = derive_session_keys(&ms, &th_arr);
            let (mut write, mut read) = ws_stream.split();
            let (tx, mut rx) = mpsc::unbounded_channel::<NorcMessage>();
            // Writer
            task::spawn(async move {
                while let Some(frame) = rx.recv().await {
                    let json = serde_json::to_string(&frame).unwrap();
                    let _ = write.send(Message::Text(json)).await;
                }
            });
            // Reader
            let reader_keys = session_keys.clone();
            task::spawn(async move {
                while let Some(Ok(Message::Text(txt))) = read.next().await {
                    if let Ok(NorcMessage::ChatCiphertext { sender, nonce, ciphertext_b64 }) = serde_json::from_str::<NorcMessage>(&txt) {
                        if let Ok(ct) = b64.decode(ciphertext_b64.as_bytes()) {
                            if let Ok(plain) = aead_decrypt(AeadDirection::ServerToClient, &reader_keys, nonce, &ct, b"chat") {
                                if let Ok(s) = String::from_utf8(plain) { debug!(from=%sender, nonce, len=s.len(), "Received chat"); println!("\n[from {}] {}", &sender.to_string()[..8], s); print!(" > "); let _=io::stdout().flush(); }
                            }
                        }
                    }
                }
            });
            info!("Enter messages (Ctrl+C to quit)");
            let mut c2s_nonce: u64 = 0;
            loop {
                print!(" > "); let _=io::stdout().flush();
                let mut line = String::new();
                if io::stdin().read_line(&mut line).is_err() { break; }
                let line = line.trim();
                if line.is_empty() { continue; }
                let nonce_val = match next_nonce(&mut c2s_nonce) { Ok(n)=>n, Err(_)=>{ warn!("Nonce exhausted; closing"); break; } };
                let ct = aead_encrypt(AeadDirection::ClientToServer, &session_keys, nonce_val, line.as_bytes(), b"chat").unwrap_or_default();
                let frame = NorcMessage::ChatCiphertext { sender: Uuid::nil(), nonce: nonce_val, ciphertext_b64: b64.encode(ct) };
                tx.send(frame).ok();
            }
        }}
    }
    Ok(())
}

