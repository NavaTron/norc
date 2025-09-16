//! NavaTron NORC Server Binary
#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![deny(trivial_casts, trivial_numeric_casts, unused_import_braces, unused_qualifications)]
#![warn(missing_docs)]

use anyhow::Result;
use navatron_cli::{load, NavaTronCommand, init_tracing};
use tracing::{info, warn};

#[tokio::main]
async fn main() -> Result<()> {
    let (cli, server_cfg, _client_cfg) = load().map_err(|e| anyhow::anyhow!(e.to_string()))?;
    // Initialize tracing (text by default; set NAVATRON_LOG for fine-grained filters)
    init_tracing(cli.verbose, false);

    if let Some(cfg) = server_cfg {
        info!(listen=%cfg.listen, max_connections=%cfg.max_connections, metrics=cfg.metrics, "NavaTron server starting");
        if cfg.metrics {
            // TODO: spawn metrics endpoint (Prometheus) feature gated
            warn!("metrics feature enabled but endpoint not yet implemented");
        }
        // TODO: Initialize server-core with effective config; attach shutdown signal handling later
    } else {
        warn!("server command required");
    }
    Ok(())
}