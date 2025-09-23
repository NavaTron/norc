//! Daemon process management and lifecycle

use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use tracing::{info, warn, error, debug};

use crate::{ServerError, Result, Server, ServerConfig};

/// Daemon configuration
#[derive(Debug, Clone)]
pub struct DaemonConfig {
    /// Server configuration
    pub server: ServerConfig,
    /// Process ID file path
    pub pid_file: Option<String>,
    /// Daemon user (for privilege dropping)
    pub daemon_user: Option<String>,
    /// Daemon group (for privilege dropping)
    pub daemon_group: Option<String>,
    /// Enable daemon mode (background process)
    pub daemonize: bool,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            pid_file: None,
            daemon_user: None,
            daemon_group: None,
            daemonize: false,
        }
    }
}

/// Main daemon process manager
pub struct Daemon {
    config: DaemonConfig,
    server: Arc<RwLock<Option<Server>>>,
    shutdown_tx: Option<broadcast::Sender<()>>,
}

impl Daemon {
    /// Create a new daemon instance
    pub fn new(config: DaemonConfig) -> Self {
        Self {
            config,
            server: Arc::new(RwLock::new(None)),
            shutdown_tx: None,
        }
    }

    /// Start the daemon process
    pub async fn start(&mut self) -> Result<()> {
        info!("Starting NORC daemon...");

        // Setup signal handling
        let (shutdown_tx, mut shutdown_rx) = broadcast::channel(1);
        self.shutdown_tx = Some(shutdown_tx.clone());

        // Setup signal handlers for graceful shutdown
        self.setup_signal_handlers(shutdown_tx.clone())?;

        // Write PID file if configured
        if let Some(ref pid_file) = self.config.pid_file {
            self.write_pid_file(pid_file)?;
        }

        // Start the server
        let server = Server::new(self.config.server.clone()).await?;
        {
            let mut server_guard = self.server.write().await;
            *server_guard = Some(server);
        }

        // Start server listening
        if let Some(ref server) = *self.server.read().await {
            tokio::spawn({
                let server = server.clone();
                async move {
                    if let Err(e) = server.start().await {
                        error!("Server error: {}", e);
                    }
                }
            });
        }

        info!("NORC daemon started successfully");

        // Wait for shutdown signal
        let _ = shutdown_rx.recv().await;
        
        info!("Received shutdown signal, shutting down gracefully...");
        self.shutdown().await?;

        info!("NORC daemon stopped");
        Ok(())
    }

    /// Shutdown the daemon gracefully
    pub async fn shutdown(&self) -> Result<()> {
        debug!("Initiating daemon shutdown...");

        // Stop the server
        if let Some(ref server) = *self.server.read().await {
            server.shutdown().await?;
        }

        // Clean up PID file
        if let Some(ref pid_file) = self.config.pid_file {
            if let Err(e) = std::fs::remove_file(pid_file) {
                warn!("Failed to remove PID file {}: {}", pid_file, e);
            }
        }

        debug!("Daemon shutdown complete");
        Ok(())
    }

    /// Setup signal handlers for graceful shutdown
    fn setup_signal_handlers(&self, shutdown_tx: broadcast::Sender<()>) -> Result<()> {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            
            let mut sigterm = signal(SignalKind::terminate())
                .map_err(|e| ServerError::Lifecycle(format!("Failed to setup SIGTERM handler: {}", e)))?;
            let mut sigint = signal(SignalKind::interrupt())
                .map_err(|e| ServerError::Lifecycle(format!("Failed to setup SIGINT handler: {}", e)))?;

            let shutdown_tx_term = shutdown_tx.clone();
            tokio::spawn(async move {
                sigterm.recv().await;
                info!("Received SIGTERM");
                let _ = shutdown_tx_term.send(());
            });

            let shutdown_tx_int = shutdown_tx.clone();
            tokio::spawn(async move {
                sigint.recv().await;
                info!("Received SIGINT");
                let _ = shutdown_tx_int.send(());
            });
        }

        #[cfg(windows)]
        {
            use tokio::signal::windows::{ctrl_c, ctrl_break};
            
            let mut ctrl_c = ctrl_c()
                .map_err(|e| ServerError::Lifecycle(format!("Failed to setup Ctrl+C handler: {}", e)))?;
            let mut ctrl_break = ctrl_break()
                .map_err(|e| ServerError::Lifecycle(format!("Failed to setup Ctrl+Break handler: {}", e)))?;

            let shutdown_tx_c = shutdown_tx.clone();
            tokio::spawn(async move {
                ctrl_c.recv().await;
                info!("Received Ctrl+C");
                let _ = shutdown_tx_c.send(());
            });

            let shutdown_tx_break = shutdown_tx.clone();
            tokio::spawn(async move {
                ctrl_break.recv().await;
                info!("Received Ctrl+Break");
                let _ = shutdown_tx_break.send(());
            });
        }

        Ok(())
    }

    /// Write process ID to file
    fn write_pid_file(&self, pid_file: &str) -> Result<()> {
        let pid = std::process::id();
        std::fs::write(pid_file, pid.to_string())
            .map_err(|e| ServerError::Lifecycle(format!("Failed to write PID file: {}", e)))?;
        debug!("Wrote PID {} to file {}", pid, pid_file);
        Ok(())
    }

    /// Get current daemon status
    pub async fn is_running(&self) -> bool {
        self.server.read().await.is_some()
    }

    /// Get daemon configuration
    pub fn config(&self) -> &DaemonConfig {
        &self.config
    }
}