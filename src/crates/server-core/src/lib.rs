//! NORC Server Core
//!
//! Core server functionality including daemon management, connection handling,
//! and signal processing per SERVER_REQUIREMENTS.

pub mod auth;
pub mod authorization;
pub mod connection;
pub mod connection_handler;
pub mod connection_pool;
pub mod daemon;
pub mod error;
pub mod federation;
pub mod logging;
pub mod observability;
pub mod router;
pub mod runtime;
pub mod security;
pub mod server;
pub mod signal_handler;

pub use connection_handler::handle_connection;
pub use connection_pool::{ConnectionId, ConnectionInfo, ConnectionPool, ConnectionPoolStats};
pub use daemon::{DaemonManager, daemonize};
pub use error::ServerError;
pub use federation::FederationEngine;
pub use logging::init_logging;
pub use observability::{
    Logger, Metrics, ObservabilitySystem, Tracer,
    health::{HealthChecker, HealthStatus},
};
pub use router::MessageRouter;
pub use runtime::{AsyncRuntime, WorkloadType};
pub use security::{
    CircuitBreaker, CircuitBreakerConfig, CircuitState, MessageValidator, RateLimiter,
    RateLimiterConfig, ValidationError,
};
pub use server::ServerCore;
pub use signal_handler::{Signal, wait_for_shutdown};

// Re-export auth types
pub use auth::{
    AccessControl, AuthContext, AuthProtocolHandler, AuthResult, AuthenticationManager,
    DeviceAuthenticator, DeviceCredentials, FederationAuthenticator, FederationCredentials,
    Permission, RateLimitConfig as AuthRateLimitConfig, RateLimiter as AuthRateLimiter, Role,
    Session, SessionManager, SessionToken,
};

// Re-export authorization types
pub use authorization::{AuthorizationMiddleware, AuthorizationResult, MessageRateLimiter};

use norc_config::ServerConfig;
use std::sync::Arc;
use tokio::sync::RwLock;

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
}

impl Server {
    /// Create a new server instance
    pub fn new(config: ServerConfig) -> Self {
        Self {
            config: Arc::new(config),
            state: Arc::new(RwLock::new(ServerState::Stopped)),
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

        // Initialize observability system
        let observability = ObservabilitySystem::init(&self.config.observability).await?;
        observability.start(&self.config.observability).await?;

        // TODO: Initialize actual server logic here
        // - Start transport listeners
        // - Initialize federation engine
        // - Start message router

        {
            let mut state = self.state.write().await;
            *state = ServerState::Running;
        }

        tracing::info!(
            "NORC server started successfully on {}:{}",
            self.config.network.bind_address,
            self.config.network.bind_port
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

        // TODO: Shutdown actual server logic here
        // - Stop accepting new connections
        // - Drain existing connections
        // - Shutdown federation
        // - Shutdown observability

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
