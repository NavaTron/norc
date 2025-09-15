use ed25519_dalek::{SigningKey, VerifyingKey, SECRET_KEY_LENGTH};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

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

    let server = std::env::var("NORC_SERVER").unwrap_or_else(|_| "http://127.0.0.1:8080".into());
    let url = format!("{server}/register");
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

