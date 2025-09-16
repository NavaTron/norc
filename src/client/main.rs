//! NavaTron NORC Client Binary
#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![deny(trivial_casts, trivial_numeric_casts, unused_import_braces, unused_qualifications)]
#![warn(missing_docs)]

use anyhow::Result;
use navatron_cli::{load, NavaTronCommand, init_tracing};
use tracing::{info, warn};

#[tokio::main]
async fn main() -> Result<()> {
    let (cli, _server_cfg, client_cfg) = load().map_err(|e| anyhow::anyhow!(e.to_string()))?;
    init_tracing(cli.verbose, false);
    if let Some(cfg) = client_cfg {
        info!(server=%cfg.server, room=%cfg.room, tls=%cfg.tls, "NavaTron client starting");
        // TODO: Instantiate client-core with effective config and session task
    } else {
        warn!("client command required");
    }
    Ok(())
}