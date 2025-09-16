//! NavaTron NORC Server Binary
#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![deny(trivial_casts, trivial_numeric_casts, unused_import_braces, unused_qualifications)]
#![warn(missing_docs)]

use anyhow::Result;
use navatron_cli::{load, NavaTronCommand};

#[tokio::main]
async fn main() -> Result<()> {
    let (_cli, server_cfg, _client_cfg) = load().map_err(|e| anyhow::anyhow!(e.to_string()))?;
    if let Some(cfg) = server_cfg {
        println!("NavaTron Server binding on {} (max_connections={})", cfg.listen, cfg.max_connections);
        if cfg.metrics { println!("Metrics enabled on :9090/metrics (stub)"); }
        // TODO: Initialize server-core with effective config
    } else {
        println!("Server command required");
    }
    Ok(())
}