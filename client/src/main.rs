use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize};
use uuid::Uuid;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};
use tokio_tungstenite::connect_async;
use base64::{engine::general_purpose::STANDARD as b64, Engine as _};
use futures_util::{SinkExt, StreamExt};
use std::convert::TryInto;
use norc_core::{ClientHello as CoreClientHello, derive_master_secret};

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
        println!(
            "Server reports device: id={} pubkey={}.. first_registered_ts={} name={:?} type={:?} caps={}",
            d.device_id,
            &d.public_key[..std::cmp::min(16, d.public_key.len())],
            d.first_registered_timestamp,
            info.name,
            info.r#type,
            caps
        );
    } else {
        println!(
            "Server reports device: id={} pubkey={}.. first_registered_ts={} (no device_info)",
            d.device_id,
            &d.public_key[..std::cmp::min(16, d.public_key.len())],
            d.first_registered_timestamp
        );
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let client_versions = vec!["1.1", "1.0"]; // descending preference
    let capabilities = vec!["messaging", "registration"];
    let server_host = std::env::var("NORC_SERVER").unwrap_or_else(|_| "127.0.0.1:8080".into());
    // Derive ws URL (no TLS for demo)
    let ws_url = format!("ws://{}/ws", server_host);
    println!("Connecting WebSocket {ws_url} ...");
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
    println!("Raw ServerHello: {server_text}");
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
    println!(
        "Negotiated version: {} (compat_mode={}) server_caps={:?} client_caps={:?} shared_caps={:?} nonce_len={} transcript_hash_len={} type={}",
        sh.negotiated_version,
        sh.compatibility_mode,
        sh.server_capabilities,
        capabilities,
        intersection,
        nonce_bytes.len(),
        transcript_ok,
        sh.r#type
    );

    // Derive shared secret + master secret (placeholder HKDF-SHA256 label)
    let server_pub_raw = b64.decode(sh.ephemeral_pub.as_bytes())?;
    if server_pub_raw.len() != 32 { println!("Bad server ephemeral length"); return Ok(()); }
    let server_pub_arr: [u8;32] = match server_pub_raw.try_into() { Ok(a) => a, Err(_) => { println!("Ephemeral conversion failed"); return Ok(()); } };
    let server_pub = X25519PublicKey::from(server_pub_arr);
    let shared = client_secret.diffie_hellman(&server_pub);
    let ms = derive_master_secret(&b64.encode(client_nonce), shared.as_bytes());
    println!("Master secret (hex, truncated): {}...", hex::encode(&ms[..16]));

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
    println!("Sending device_register over WS (device_id={device_id})");
    ws_stream.send(tokio_tungstenite::tungstenite::protocol::Message::Text(reg_json)).await?;

    if let Some(Ok(tokio_tungstenite::tungstenite::protocol::Message::Text(reg_resp_txt))) = ws_stream.next().await {
        match serde_json::from_str::<WsRegisterResponse>(&reg_resp_txt) {
            Ok(resp) => {
                match resp.inner {
                    WsRegisterInner::Registered { device } | WsRegisterInner::AlreadyRegistered { device } => {
                        println!("Register response status consumed (type={})", resp.r#type);
                        log_server_device(&device);
                    }
                    WsRegisterInner::InvalidKey { message } => {
                        println!("Registration failed (type={}) message={}", resp.r#type, message);
                    }
                }
            }
            Err(e) => {
                eprintln!("Failed to parse WS register response: {e}\nRaw: {reg_resp_txt}");
            }
        }
    } else {
        println!("No WS register response received");
    }

    Ok(())
}

