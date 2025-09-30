//! Server configuration structures per SERVER_REQUIREMENTS F-01.02

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Complete server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Organization ID for this server
    pub organization_id: String,

    /// Server network configuration
    pub network: NetworkConfig,

    /// Security configuration
    pub security: SecurityConfig,

    /// Observability configuration
    pub observability: ObservabilityConfig,

    /// Federation configuration
    pub federation: FederationConfig,

    /// Resource limits
    pub limits: ResourceLimits,

    /// Daemon process configuration
    pub daemon: DaemonConfig,

    /// Storage configuration
    pub storage: StorageConfig,
}

/// Network configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Bind address for client connections
    pub bind_address: String,

    /// Bind port for client connections
    pub bind_port: u16,

    /// Federation bind address
    pub federation_address: String,

    /// Federation bind port
    pub federation_port: u16,

    /// Enable TLS
    pub enable_tls: bool,

    /// TLS certificate path
    pub tls_cert_path: Option<PathBuf>,

    /// TLS key path
    pub tls_key_path: Option<PathBuf>,

    /// Enable WebSocket
    pub enable_websocket: bool,

    /// Enable QUIC
    pub enable_quic: bool,
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Organization ID
    pub organization_id: String,

    /// Default trust level
    pub default_trust_level: String,

    /// Enable post-quantum cryptography
    pub enable_pq_crypto: bool,

    /// Key rotation interval in seconds
    pub key_rotation_interval_secs: u64,

    /// Certificate validation strictness
    pub strict_cert_validation: bool,

    /// Enable HSM integration
    pub enable_hsm: bool,
}

/// Observability configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservabilityConfig {
    /// Log level (error, warn, info, debug, trace)
    pub log_level: String,

    /// Log format (json, pretty, compact)
    pub log_format: String,

    /// Log file path
    #[serde(default = "default_log_file_path")]
    pub log_file_path: std::path::PathBuf,

    /// Enable Prometheus metrics
    pub enable_metrics: bool,

    /// Metrics bind address
    pub metrics_address: String,

    /// Metrics bind port
    pub metrics_port: u16,

    /// Enable distributed tracing
    pub enable_tracing: bool,

    /// Tracing endpoint (OTLP)
    #[serde(default = "default_tracing_endpoint")]
    pub tracing_endpoint: String,

    /// Tracing sample rate (0.0 - 1.0)
    #[serde(default = "default_tracing_sample_rate")]
    pub tracing_sample_rate: f64,
}

fn default_log_file_path() -> std::path::PathBuf {
    std::path::PathBuf::from("/var/log/norc/server.log")
}

fn default_tracing_endpoint() -> String {
    "http://localhost:4317".to_string()
}

fn default_tracing_sample_rate() -> f64 {
    1.0
}

/// Federation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationConfig {
    /// Enable federation
    pub enable_federation: bool,

    /// Federation partners
    pub partners: Vec<FederationPartner>,

    /// Discovery method (static, dns, consul)
    pub discovery_method: String,
}

/// Federation partner configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationPartner {
    /// Partner organization ID
    pub organization_id: String,

    /// Partner address
    pub address: String,

    /// Trust level
    pub trust_level: String,

    /// Enable mutual TLS
    pub mutual_tls: bool,
}

/// Resource limits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// Maximum concurrent connections
    pub max_connections: usize,

    /// Maximum message size in bytes
    pub max_message_size: usize,

    /// Message rate limit per connection (messages/second)
    pub rate_limit_per_connection: u32,

    /// Maximum memory per connection in bytes
    pub max_memory_per_connection: usize,

    /// Worker thread pool size (0 = auto-detect)
    pub worker_threads: usize,
}

/// Daemon process configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    /// Enable daemonization (Unix) or service mode (Windows)
    pub daemonize: bool,

    /// PID file path
    pub pid_file: PathBuf,

    /// Working directory
    pub working_dir: Option<PathBuf>,

    /// Enable auto-restart on crash
    pub auto_restart: bool,

    /// Maximum restart attempts
    pub max_restarts: u32,

    /// Restart cooldown period in seconds
    pub restart_cooldown_secs: u64,
}

/// Storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Data directory for persistent storage
    pub data_dir: PathBuf,

    /// Enable persistence
    pub enable_persistence: bool,

    /// Snapshot interval in seconds
    pub snapshot_interval_secs: u64,

    /// Maximum snapshot files to keep
    pub max_snapshots: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            organization_id: "example.org".to_string(),
            network: NetworkConfig {
                bind_address: "0.0.0.0".to_string(),
                bind_port: 8443,
                federation_address: "0.0.0.0".to_string(),
                federation_port: 8444,
                enable_tls: true,
                tls_cert_path: None,
                tls_key_path: None,
                enable_websocket: false,
                enable_quic: false,
            },
            security: SecurityConfig {
                organization_id: "example.org".to_string(),
                default_trust_level: "Basic".to_string(),
                enable_pq_crypto: false,
                key_rotation_interval_secs: 3600,
                strict_cert_validation: true,
                enable_hsm: false,
            },
            observability: ObservabilityConfig {
                log_level: "info".to_string(),
                log_format: "json".to_string(),
                log_file_path: std::path::PathBuf::from("/var/log/norc/server.log"),
                enable_metrics: true,
                metrics_address: "0.0.0.0".to_string(),
                metrics_port: 9090,
                enable_tracing: false,
                tracing_endpoint: "http://localhost:4317".to_string(),
                tracing_sample_rate: 1.0,
            },
            federation: FederationConfig {
                enable_federation: true,
                partners: Vec::new(),
                discovery_method: "static".to_string(),
            },
            limits: ResourceLimits {
                max_connections: 50000,
                max_message_size: 16 * 1024 * 1024,
                rate_limit_per_connection: 100,
                max_memory_per_connection: 1024 * 1024,
                worker_threads: 0,
            },
            daemon: DaemonConfig {
                daemonize: false,
                pid_file: PathBuf::from("/var/run/norc/norc.pid"),
                working_dir: None,
                auto_restart: true,
                max_restarts: 3,
                restart_cooldown_secs: 30,
            },
            storage: StorageConfig {
                data_dir: PathBuf::from("/var/lib/norc"),
                enable_persistence: true,
                snapshot_interval_secs: 300,
                max_snapshots: 10,
            },
        }
    }
}

impl ServerConfig {
    /// Load configuration from a TOML file
    pub fn from_file(path: &std::path::Path) -> Result<Self, crate::error::ConfigError> {
        let contents = std::fs::read_to_string(path)?;
        let config: ServerConfig = toml::from_str(&contents)?;
        Ok(config)
    }

    /// Save configuration to a TOML file
    pub fn to_file(&self, path: &std::path::Path) -> Result<(), crate::error::ConfigError> {
        let contents = toml::to_string_pretty(self)?;
        std::fs::write(path, contents)?;
        Ok(())
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<(), crate::error::ConfigError> {
        // Validate network ports
        if self.network.bind_port == 0 {
            return Err(crate::error::ConfigError::Validation(
                "Invalid bind port".to_string(),
            ));
        }

        // Validate TLS configuration
        if self.network.enable_tls {
            if self.network.tls_cert_path.is_none() || self.network.tls_key_path.is_none() {
                return Err(crate::error::ConfigError::Validation(
                    "TLS enabled but cert/key paths not specified".to_string(),
                ));
            }
        }

        // Validate resource limits
        if self.limits.max_connections == 0 {
            return Err(crate::error::ConfigError::Validation(
                "max_connections must be > 0".to_string(),
            ));
        }

        Ok(())
    }

    /// Merge CLI overrides
    pub fn merge_cli_overrides(self, _cli: &crate::cli::Cli) -> Self {
        // Override log level if provided
        // This is a simplified example - full implementation would handle all CLI options
        self
    }

    /// Get socket address for client connections
    pub fn socket_addr(&self) -> String {
        format!("{}:{}", self.network.bind_address, self.network.bind_port)
    }

    /// Get socket address for federation connections
    pub fn federation_addr(&self) -> String {
        format!("{}:{}", self.network.federation_address, self.network.federation_port)
    }
}
