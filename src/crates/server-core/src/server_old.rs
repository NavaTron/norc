//! Server implementation
//!
//! Core server functionality and lifecycle management.

use crate::{signal_handler::wait_for_shutdown, DaemonManager, ServerError, ServerState};
use norc_config::ServerConfig;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

/// Main server implementation
pub struct ServerCore {
    config: Arc<ServerConfig>,
    state: Arc<RwLock<ServerState>>,
    daemon_manager: Option<DaemonManager>,
}

impl ServerCore {
    /// Create a new server instance
    pub fn new(config: ServerConfig) -> Self {
        Self {
            config: Arc::new(config),
            state: Arc::new(RwLock::new(ServerState::Stopped)),
            daemon_manager: None,
        }
    }

    /// Initialize the server
    pub async fn initialize(&mut self) -> Result<(), ServerError> {
        info!("Initializing NORC server...");

        // Check for existing instance
        if self.config.daemon.auto_restart {
            let daemon_manager = DaemonManager::new(self.config.clone()).await?;
            
            if daemon_manager.check_running_instance().await? {
                return Err(ServerError::Startup(
                    "Another instance of the server is already running".to_string(),
                ));
            }
            
            self.daemon_manager = Some(daemon_manager);
        }

        // Set up working directory
        if let Some(working_dir) = &self.config.daemon.working_dir {
            std::env::set_current_dir(working_dir).map_err(|e| {
                ServerError::Startup(format!("Failed to change working directory: {}", e))
            })?;
        }

        // Create data directory if it doesn't exist
        if !self.config.storage.data_dir.exists() {
            std::fs::create_dir_all(&self.config.storage.data_dir).map_err(|e| {
                ServerError::Startup(format!("Failed to create data directory: {}", e))
            })?;
        }

        info!("Server initialization complete");
        Ok(())
    }

    /// Start the server
    pub async fn start(&mut self) -> Result<(), ServerError> {
        {
            let mut state = self.state.write().await;
            *state = ServerState::Starting;
        }

        info!("Starting NORC server on {}", self.config.socket_addr());

        // Start daemon monitoring if configured
        if let Some(daemon_manager) = &self.daemon_manager {
            daemon_manager.start_monitoring().await?;
        }

        // TODO: Initialize actual server components here
        // For now, we simulate successful startup
        
        {
            let mut state = self.state.write().await;
            *state = ServerState::Running;
        }

        info!("NORC server started successfully");
        Ok(())
    }

    /// Run the server until shutdown
    pub async fn run(&mut self) -> Result<(), ServerError> {
        self.initialize().await?;
        self.start().await?;

        // Wait for shutdown signal
        let signal = wait_for_shutdown().await;
        info!("Received shutdown signal: {:?}", signal);

        self.stop().await?;
        Ok(())
    }

    /// Stop the server gracefully
    pub async fn stop(&mut self) -> Result<(), ServerError> {
        {
            let mut state = self.state.write().await;
            *state = ServerState::Stopping;
        }

        info!("Stopping NORC server...");

        // Stop daemon manager
        if let Some(daemon_manager) = &mut self.daemon_manager {
            daemon_manager.stop().await?;
        }

        // TODO: Shutdown actual server components here
        // For now, we simulate successful shutdown

        {
            let mut state = self.state.write().await;
            *state = ServerState::Stopped;
        }

        info!("NORC server stopped gracefully");
        Ok(())
    }

    /// Get current server state
    pub async fn state(&self) -> ServerState {
        self.state.read().await.clone()
    }

    /// Get server configuration
    pub fn config(&self) -> &ServerConfig {
        &self.config
    }

    /// Reload configuration (for SIGHUP)
    pub async fn reload_config(&mut self, new_config: ServerConfig) -> Result<(), ServerError> {
        info!("Reloading server configuration...");
        
        // Validate new configuration
        new_config.validate()?;
        
        // Update configuration
        self.config = Arc::new(new_config);
        
        // TODO: Apply configuration changes to running components
        // For now, we just log the reload
        
        info!("Configuration reloaded successfully");
        Ok(())
    }
}
