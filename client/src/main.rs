use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};
use tokio_tungstenite::connect_async;
use hkdf::Hkdf;
use sha2::Sha256;
use base64::{engine::general_purpose::STANDARD as b64, Engine as _};
use futures_util::{SinkExt, StreamExt};
use std::convert::TryInto;

#[derive(Debug, Serialize)]
struct DeviceRegisterRequest {
    device_id: Uuid,
    public_key: String, // hex encoded
    device_info: DeviceInfo,
}

#[derive(Debug, Serialize)]
struct DeviceInfo {
    name: String,
    r#type: String,
    capabilities: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum RegisterResponse {
    Registered { device: ServerDevice },
    AlreadyRegistered { device: ServerDevice },
    InvalidKey { message: String },
}

#[derive(Debug, Deserialize)]
struct ServerDevice {
    device_id: Uuid,
    public_key: String,
    device_info: Option<DeviceInfoOpt>,
    first_registered_timestamp: i64,
}

#[derive(Debug, Deserialize)]
struct DeviceInfoOpt {
    name: Option<String>,
    r#type: Option<String>,
    capabilities: Option<Vec<String>>,
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

    // Build ClientHello
    #[derive(Serialize)]
    struct ClientHello<'a> {
        r#type: &'a str,
        client_versions: Vec<&'a str>,
        preferred_version: &'a str,
        capabilities: Vec<&'a str>,
        nonce: String,
        ephemeral_pub: String,
    }
    let ch = ClientHello {
        r#type: "client_hello",
        client_versions: client_versions.clone(),
        preferred_version: "1.1",
        capabilities: capabilities.clone(),
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
    println!("ServerHello: {server_text}");
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
    let local_th = {
        let server_minus_th: serde_json::Value = {
            let mut v: serde_json::Value = serde_json::from_str(&server_text)?;
            v
        };
        // For now just rely on server provided; full canonical recompute could mirror server logic
        sh.transcript_hash.clone()
    };
    println!("Negotiated version: {} (compat_mode={})", sh.negotiated_version, sh.compatibility_mode);

    // Derive shared secret + master secret (placeholder HKDF-SHA256 label)
    let server_pub_raw = b64.decode(sh.ephemeral_pub.as_bytes())?;
    if server_pub_raw.len() != 32 { println!("Bad server ephemeral length"); return Ok(()); }
    let server_pub_arr: [u8;32] = match server_pub_raw.try_into() { Ok(a) => a, Err(_) => { println!("Ephemeral conversion failed"); return Ok(()); } };
    let server_pub = X25519PublicKey::from(server_pub_arr);
    let shared = client_secret.diffie_hellman(&server_pub);
    let hk = Hkdf::<Sha256>::new(Some(&client_nonce), shared.as_bytes());
    let mut ms = [0u8;32];
    if let Err(e) = hk.expand(b"norc:ms:v1", &mut ms) { println!("HKDF expand failed: {e}"); return Ok(()); }
    println!("Master secret (hex, truncated): {}...", hex::encode(&ms[..16]));

    // Continue with HTTP registration for now
    let server_http = format!("http://{server_host}");
    let http = reqwest::Client::new();

    // Generate identity key pair (Ed25519) for the device
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key: VerifyingKey = signing_key.verifying_key();
    let public_key_hex = hex::encode(verifying_key.to_bytes());

    let device_id = Uuid::new_v4();
    let req_body = DeviceRegisterRequest {
        device_id,
        public_key: public_key_hex,
        device_info: DeviceInfo {
            name: format!("Dev-{}", &device_id.to_string()[..8]),
            r#type: "desktop".into(),
            capabilities: vec!["messaging".into()],
        },
    };

    let url = format!("{server_http}/register");
    println!("Registering device {device_id} at {url}");
    let client = reqwest::Client::new();
    let resp = client.post(url).json(&req_body).send().await?;

    let status = resp.status();
    let text = resp.text().await?;
    let parsed: Result<RegisterResponse, _> = serde_json::from_str(&text);
    match parsed {
        Ok(r) => {
            println!("Server HTTP status: {status}");
            println!("Response: {:#?}", r);
        }
        Err(e) => {
            eprintln!("Failed to parse response: {e}\nRaw: {text}");
        }
    }

    Ok(())
}

