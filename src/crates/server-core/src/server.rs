//! Server implementation
//!
//! Core server functionality and lifecycle management.

use crate::{
    handle_connection, signal_handler::wait_for_shutdown, ConnectionPool, DaemonManager,
    MessageRouter, ServerError, ServerState,
};
use norc_config::ServerConfig;
use norc_persistence::{
    Database,
    repositories::{
        UserRepository, DeviceRepository, SessionRepository, MessageRepository,
        FederationRepository, PresenceRepository, AuditRepository,
    },
};
use norc_transport::{ListenerConfig, NetworkListener};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tracing::{error, info};

/// Main server implementation
pub struct ServerCore {
    config: Arc<ServerConfig>,
    state: Arc<RwLock<ServerState>>,
    daemon_manager: Option<DaemonManager>,
    connection_pool: Arc<ConnectionPool>,
    router: Arc<MessageRouter>,
    listener_handle: Option<JoinHandle<()>>,
    
    // Persistence layer
    database: Arc<Database>,
    user_repo: Arc<UserRepository>,
    device_repo: Arc<DeviceRepository>,
    session_repo: Arc<SessionRepository>,
    message_repo: Arc<MessageRepository>,
    federation_repo: Arc<FederationRepository>,
    presence_repo: Arc<PresenceRepository>,
    audit_repo: Arc<AuditRepository>,
}

impl ServerCore {
    /// Create a new server instance
    pub async fn new(config: ServerConfig) -> Result<Self, ServerError> {
        // Create async runtime
        let runtime = match crate::runtime::AsyncRuntime::new(&config.limits) {
            Ok(rt) => Arc::new(rt),
            Err(e) => {
                error!("Failed to create async runtime: {}", e);
                return Err(ServerError::Startup(format!("Failed to create runtime: {}", e)));
            }
        };

        let connection_pool = Arc::new(ConnectionPool::new(
            config.limits.max_connections,
            300, // idle timeout in seconds
            runtime,
        ));

        let router = Arc::new(MessageRouter::new());

        // Initialize database
        info!("Initializing database...");
        let db_path = config.storage.data_dir.join("norc.db");
        let db_config = norc_persistence::database::DatabaseConfig {
            path: db_path.to_string_lossy().to_string(),
            max_connections: 32,
            connection_timeout: std::time::Duration::from_secs(30),
            enable_wal: true,
            enable_foreign_keys: true,
        };

        let database = Database::new(db_config)
            .await
            .map_err(|e| ServerError::Startup(format!("Failed to initialize database: {}", e)))?;
        
        // Run migrations
        database.migrate()
            .await
            .map_err(|e| ServerError::Startup(format!("Failed to run database migrations: {}", e)))?;

        let database = Arc::new(database);

        // Initialize repositories
        let pool = database.pool().clone();
        let user_repo = Arc::new(UserRepository::new(pool.clone()));
        let device_repo = Arc::new(DeviceRepository::new(pool.clone()));
        let session_repo = Arc::new(SessionRepository::new(pool.clone()));
        let message_repo = Arc::new(MessageRepository::new(pool.clone()));
        let federation_repo = Arc::new(FederationRepository::new(pool.clone()));
        let presence_repo = Arc::new(PresenceRepository::new(pool.clone()));
        let audit_repo = Arc::new(AuditRepository::new(pool));

        info!("Database and repositories initialized successfully");

        Ok(Self {
            config: Arc::new(config),
            state: Arc::new(RwLock::new(ServerState::Stopped)),
            daemon_manager: None,
            connection_pool,
            router,
            listener_handle: None,
            database,
            user_repo,
            device_repo,
            session_repo,
            message_repo,
            federation_repo,
            presence_repo,
            audit_repo,
        })
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

        // Start network listener
        self.start_listener().await?;

        {
            let mut state = self.state.write().await;
            *state = ServerState::Running;
        }

        info!("NORC server started successfully");
        Ok(())
    }

    /// Start the network listener
    async fn start_listener(&mut self) -> Result<(), ServerError> {
        let listener_config = ListenerConfig {
            bind_addr: format!(
                "{}:{}",
                self.config.network.bind_address, self.config.network.bind_port
            ),
            cert_path: self.config.network.tls_cert_path.clone(),
            key_path: self.config.network.tls_key_path.clone(),
            require_client_auth: false, // TODO: Get from config
        };

        let listener = NetworkListener::new(listener_config)
            .await
            .map_err(|e| ServerError::Startup(format!("Failed to create listener: {}", e)))?;

        let pool = self.connection_pool.clone();
        let router = self.router.clone();
        let device_repo = self.device_repo.clone();
        let session_repo = self.session_repo.clone();
        let presence_repo = self.presence_repo.clone();
        let message_repo = self.message_repo.clone();
        let audit_repo = self.audit_repo.clone();

        // Start accepting connections
        let handle = listener
            .listen(move |transport, peer_addr| {
                let pool_clone = pool.clone();
                let router_clone = router.clone();
                let device_repo_clone = device_repo.clone();
                let session_repo_clone = session_repo.clone();
                let presence_repo_clone = presence_repo.clone();
                let message_repo_clone = message_repo.clone();
                let audit_repo_clone = audit_repo.clone();

                tokio::spawn(async move {
                    // Register connection in pool
                    match pool_clone.register(peer_addr).await {
                        Ok(conn_id) => {
                            // Handle the connection
                            handle_connection(
                                conn_id,
                                transport,
                                peer_addr,
                                router_clone,
                                pool_clone,
                                device_repo_clone,
                                session_repo_clone,
                                presence_repo_clone,
                                message_repo_clone,
                                audit_repo_clone,
                            )
                            .await;
                        }
                        Err(e) => {
                            error!("Failed to register connection: {}", e);
                        }
                    }
                });
            })
            .await
            .map_err(|e| ServerError::Startup(format!("Failed to start listener: {}", e)))?;

        self.listener_handle = Some(handle);
        info!("Network listener started");

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

        // Stop listener
        if let Some(handle) = self.listener_handle.take() {
            handle.abort();
            info!("Network listener stopped");
        }

        // Close all connections gracefully
        let all_ids = self.connection_pool.get_all_ids().await;
        for id in all_ids {
            self.connection_pool.unregister(id).await;
        }
        info!("All connections closed");

        // Stop daemon manager
        if let Some(daemon_manager) = &mut self.daemon_manager {
            daemon_manager.stop().await?;
        }

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

    // Repository accessors

    /// Get database reference
    pub fn database(&self) -> &Arc<Database> {
        &self.database
    }

    /// Get user repository
    pub fn user_repo(&self) -> &Arc<UserRepository> {
        &self.user_repo
    }

    /// Get device repository
    pub fn device_repo(&self) -> &Arc<DeviceRepository> {
        &self.device_repo
    }

    /// Get session repository
    pub fn session_repo(&self) -> &Arc<SessionRepository> {
        &self.session_repo
    }

    /// Get message repository
    pub fn message_repo(&self) -> &Arc<MessageRepository> {
        &self.message_repo
    }

    /// Get federation repository
    pub fn federation_repo(&self) -> &Arc<FederationRepository> {
        &self.federation_repo
    }

    /// Get presence repository
    pub fn presence_repo(&self) -> &Arc<PresenceRepository> {
        &self.presence_repo
    }

    /// Get audit repository
    pub fn audit_repo(&self) -> &Arc<AuditRepository> {
        &self.audit_repo
    }

    /// Get connection pool
    pub fn connection_pool(&self) -> &Arc<ConnectionPool> {
        &self.connection_pool
    }

    /// Get message router
    pub fn router(&self) -> &Arc<MessageRouter> {
        &self.router
    }
}
