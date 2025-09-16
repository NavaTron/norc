//! NavaTron NORC Client Binary
#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![deny(trivial_casts, trivial_numeric_casts, unused_import_braces, unused_qualifications)]
#![warn(missing_docs)]

use anyhow::Result;
use navatron_cli::{load, NavaTronCommand};

#[tokio::main]
async fn main() -> Result<()> {
    let (_cli, _server_cfg, client_cfg) = load().map_err(|e| anyhow::anyhow!(e.to_string()))?;
    if let Some(cfg) = client_cfg {
        println!("NavaTron Client starting -> server={} room={} tls={}", cfg.server, cfg.room, cfg.tls);
        // TODO: Instantiate client-core with effective config
    } else {
        println!("Client command required");
    }
    Ok(())
}