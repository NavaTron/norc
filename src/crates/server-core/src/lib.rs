//! NORC Server Core
//!
//! Core server functionality for the NavaTron Open Real-time Communication (NORC) server.
//! Provides daemon management, connection handling, and server lifecycle management.

pub mod daemon;
pub mod logging;
pub mod server;
pub mod signal_handler;

pub use daemon::*;
pub use logging::*;
pub use server::*;

use norc_config::ServerConfig;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

/// Server core errors
#[derive(Error, Debug)]
pub enum ServerError {
    #[error("Configuration error: {0}")]
    Config(#[from] norc_config::ConfigError),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Signal handling error: {0}")]
    Signal(String),
    #[error("Daemon error: {0}")]
    Daemon(String),
    #[error("Server startup failed: {0}")]
    Startup(String),
    #[error("Server shutdown failed: {0}")]
    Shutdown(String),
}

/// Server state
#[derive(Debug, Clone, PartialEq)]
pub enum ServerState {
    Starting,
    Running,
    Stopping,
    Stopped,
    Error(String),
}

/// Main server instance
pub struct Server {
    config: Arc<ServerConfig>,
    state: Arc<RwLock<ServerState>>,
    daemon_manager: Option<DaemonManager>,
}

impl Server {
    /// Create a new server instance
    pub fn new(config: ServerConfig) -> Self {
        Self {
            config: Arc::new(config),
            state: Arc::new(RwLock::new(ServerState::Stopped)),
            daemon_manager: None,
        }
    }

    /// Get current server state
    pub async fn state(&self) -> ServerState {
        self.state.read().await.clone()
    }

    /// Start the server
    pub async fn start(&mut self) -> Result<(), ServerError> {
        {
            let mut state = self.state.write().await;
            *state = ServerState::Starting;
        }

        tracing::info!("Starting NORC server...");

        // Initialize daemon manager if configured
        if self.config.daemon.auto_restart {
            let daemon_manager = DaemonManager::new(self.config.clone()).await?;
            self.daemon_manager = Some(daemon_manager);
        }

        // TODO: Initialize actual server logic here
        // For now, we just simulate a successful startup
        
        {
            let mut state = self.state.write().await;
            *state = ServerState::Running;
        }

        tracing::info!(
            "NORC server started successfully on {}",
            self.config.socket_addr()
        );

        Ok(())
    }

    /// Stop the server gracefully
    pub async fn stop(&mut self) -> Result<(), ServerError> {
        {
            let mut state = self.state.write().await;
            *state = ServerState::Stopping;
        }

        tracing::info!("Stopping NORC server...");

        // Stop daemon manager if active
        if let Some(daemon_manager) = &mut self.daemon_manager {
            daemon_manager.stop().await?;
        }

        // TODO: Shutdown actual server logic here
        // For now, we just simulate a successful shutdown

        {
            let mut state = self.state.write().await;
            *state = ServerState::Stopped;
        }

        tracing::info!("NORC server stopped successfully");

        Ok(())
    }

    /// Run the server until stopped
    pub async fn run(&mut self) -> Result<(), ServerError> {
        self.start().await?;

        // Main server loop - for now just wait for shutdown signal
        // TODO: Replace this with actual server logic
        loop {
            let state = self.state().await;
            match state {
                ServerState::Running => {
                    // Simulate server work
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                }
                ServerState::Stopping | ServerState::Stopped => {
                    break;
                }
                ServerState::Error(err) => {
                    return Err(ServerError::Daemon(err));
                }
                _ => {
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                }
            }
        }

        self.stop().await?;
        Ok(())
    }

    /// Get server configuration
    pub fn config(&self) -> &ServerConfig {
        &self.config
    }
}
