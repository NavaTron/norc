//! NavaTron NORC Server Binary
#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![deny(trivial_casts, trivial_numeric_casts, unused_import_braces, unused_qualifications)]
#![warn(missing_docs)]

use anyhow::Result;
use navatron_cli::{load, NavaTronCommand, init_tracing};
use tracing::{info, warn, error};
use tokio::signal;
use navatron_server_core::{Server, ServerConfig};

#[tokio::main]
async fn main() -> Result<()> {
    let (cli, server_cfg, _client_cfg) = load().map_err(|e| anyhow::anyhow!(e.to_string()))?;
    // Initialize tracing (text by default; set NAVATRON_LOG for fine-grained filters)
    init_tracing(cli.verbose, false);

    if let Some(cfg) = server_cfg {
        info!(listen=%cfg.listen, max_connections=%cfg.max_connections, metrics=cfg.metrics, "NavaTron server starting");
        if cfg.metrics { warn!("metrics feature enabled but endpoint not yet implemented"); }

        // Map effective CLI config into server-core config
        let server_config = ServerConfig {
            bind_host: cfg.listen.ip().to_string(),
            bind_port: cfg.listen.port(),
            use_tls: cfg.cert.is_some() && cfg.key.is_some(),
            max_connections: cfg.max_connections,
            ..Default::default()
        };

        if server_config.use_tls {
            if let (Some(cert), Some(key)) = (cfg.cert.as_ref(), cfg.key.as_ref()) {
                if !cert.exists() || !key.exists() { warn!(?cert, ?key, "TLS enabled but cert/key path missing"); }
                // TODO: Load cert/key into rustls::pki_types structures and inject into ServerConfig.tls_config
            }
        }

        let mut server = Server::with_config(server_config);

        // Run server until CTRL-C
        let server_task = tokio::spawn(async move {
            if let Err(e) = server.run().await { error!(error=%e, "server run failed"); }
        });

        // Wait for shutdown signal
        info!("press Ctrl+C to stop");
        signal::ctrl_c().await.expect("install Ctrl+C handler");
        info!("shutdown signal received; stopping...");
        // Server::run loop exits on state change; we aborted via state transition triggered by stop.
        // For now we just abort the task since internal graceful path not yet implemented fully.
        server_task.abort();
    } else { warn!("server command required"); }
    Ok(())
}