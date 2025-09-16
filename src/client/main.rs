//! NavaTron NORC Client Binary
#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![deny(trivial_casts, trivial_numeric_casts, unused_import_braces, unused_qualifications)]
#![warn(missing_docs)]

use anyhow::Result;
use navatron_cli::{load, NavaTronCommand, init_tracing};
use tracing::{info, warn, error};
use tokio::signal;
use navatron_client_core::{Client, ClientConfig};

#[tokio::main]
async fn main() -> Result<()> {
    let (cli, _server_cfg, client_cfg) = load().map_err(|e| anyhow::anyhow!(e.to_string()))?;
    init_tracing(cli.verbose, false);
    if let Some(cfg) = client_cfg {
        info!(server=%cfg.server, room=%cfg.room, tls=%cfg.tls, "NavaTron client starting");
        // Map effective config into client-core config
        let (host, port) = match cfg.server.split_once(':') { Some((h,p)) => (h.to_string(), p.parse::<u16>().unwrap_or(8443)), None => (cfg.server.clone(), 8443) };
        let client_config = ClientConfig { server_host: host, server_port: port, use_tls: cfg.tls, ..Default::default() };
        let client = Client::with_config(client_config);

        // Spawn background run placeholder (connect + auth not yet implemented) 
        let client_task = tokio::spawn(async move {
            if let Err(e) = client.connect().await { error!(error=%e, "client connect failed"); }
        });

        info!("press Ctrl+C to exit client");
        signal::ctrl_c().await.expect("install Ctrl+C handler");
        info!("shutdown signal received; terminating client");
        client_task.abort();
    } else { warn!("client command required"); }
    Ok(())
}