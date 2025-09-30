//! NORC Configuration Management
//!
//! Provides configuration loading, parsing, and validation for NORC server components.

pub mod cli;

pub use cli::*;

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use thiserror::Error;

/// Configuration errors
#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Failed to read config file: {0}")]
    FileRead(#[from] std::io::Error),
    #[error("Failed to parse config file: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("Config validation failed: {0}")]
    Validation(String),
}

/// Complete server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Server network configuration
    pub network: NetworkConfig,
    /// TLS/encryption settings
    pub tls: TlsConfig,
    /// Logging configuration
    pub logging: LoggingConfig,
    /// Storage configuration
    pub storage: StorageConfig,
    /// Daemon-specific settings
    pub daemon: DaemonConfig,
}

/// Network configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Address to bind the server to
    #[serde(default = "default_bind_address")]
    pub bind_address: IpAddr,
    /// Port to listen on
    #[serde(default = "default_port")]
    pub port: u16,
    /// Maximum number of concurrent connections
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    /// Connection timeout in seconds
    #[serde(default = "default_connection_timeout")]
    pub connection_timeout_secs: u64,
    /// Enable IPv6 support
    #[serde(default = "default_ipv6_enabled")]
    pub ipv6_enabled: bool,
}

/// TLS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Enable TLS
    #[serde(default = "default_tls_enabled")]
    pub enabled: bool,
    /// Path to TLS certificate file
    pub cert_file: Option<PathBuf>,
    /// Path to TLS private key file
    pub key_file: Option<PathBuf>,
    /// Path to CA certificate file for client verification
    pub ca_file: Option<PathBuf>,
    /// Require client certificates
    #[serde(default)]
    pub require_client_certs: bool,
    /// Minimum TLS version (1.2, 1.3)
    #[serde(default = "default_min_tls_version")]
    pub min_version: String,
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level (trace, debug, info, warn, error)
    #[serde(default = "default_log_level")]
    pub level: String,
    /// Log format (json, pretty, compact)
    #[serde(default = "default_log_format")]
    pub format: String,
    /// Log file path (if None, logs to stdout)
    pub file: Option<PathBuf>,
    /// Enable log file rotation
    #[serde(default = "default_log_rotation")]
    pub rotation: bool,
    /// Maximum log file size in MB
    #[serde(default = "default_max_log_size")]
    pub max_size_mb: u64,
    /// Number of rotated log files to keep
    #[serde(default = "default_max_log_files")]
    pub max_files: usize,
}

/// Storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Data directory for persistent storage
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
    /// Maximum disk usage in MB
    #[serde(default = "default_max_disk_usage")]
    pub max_disk_usage_mb: u64,
    /// Enable compression for stored data
    #[serde(default = "default_compression_enabled")]
    pub compression_enabled: bool,
    /// Backup interval in hours (0 = disabled)
    #[serde(default)]
    pub backup_interval_hours: u32,
    /// Number of backups to retain
    #[serde(default = "default_backup_retention")]
    pub backup_retention: usize,
}

/// Daemon configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    /// PID file path
    #[serde(default = "default_pid_file")]
    pub pid_file: PathBuf,
    /// User to run as (Unix only)
    pub user: Option<String>,
    /// Group to run as (Unix only)  
    pub group: Option<String>,
    /// Working directory
    pub working_dir: Option<PathBuf>,
    /// Enable auto-restart on crash
    #[serde(default = "default_auto_restart")]
    pub auto_restart: bool,
    /// Maximum restart attempts
    #[serde(default = "default_max_restarts")]
    pub max_restarts: u32,
    /// Restart cooldown period in seconds
    #[serde(default = "default_restart_cooldown")]
    pub restart_cooldown_secs: u64,
}

// Default value functions
fn default_bind_address() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
}

fn default_port() -> u16 {
    8443
}

fn default_max_connections() -> usize {
    1000
}

fn default_connection_timeout() -> u64 {
    30
}

fn default_ipv6_enabled() -> bool {
    true
}

fn default_tls_enabled() -> bool {
    true
}

fn default_min_tls_version() -> String {
    "1.3".to_string()
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_format() -> String {
    "json".to_string()
}

fn default_log_rotation() -> bool {
    true
}

fn default_max_log_size() -> u64 {
    100
}

fn default_max_log_files() -> usize {
    10
}

fn default_data_dir() -> PathBuf {
    PathBuf::from("./data")
}

fn default_max_disk_usage() -> u64 {
    10240 // 10GB
}

fn default_compression_enabled() -> bool {
    true
}

fn default_backup_retention() -> usize {
    7
}

fn default_pid_file() -> PathBuf {
    PathBuf::from("./norc-server.pid")
}

fn default_auto_restart() -> bool {
    true
}

fn default_max_restarts() -> u32 {
    5
}

fn default_restart_cooldown() -> u64 {
    60
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            network: NetworkConfig::default(),
            tls: TlsConfig::default(),
            logging: LoggingConfig::default(),
            storage: StorageConfig::default(),
            daemon: DaemonConfig::default(),
        }
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            bind_address: default_bind_address(),
            port: default_port(),
            max_connections: default_max_connections(),
            connection_timeout_secs: default_connection_timeout(),
            ipv6_enabled: default_ipv6_enabled(),
        }
    }
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: default_tls_enabled(),
            cert_file: None,
            key_file: None,
            ca_file: None,
            require_client_certs: false,
            min_version: default_min_tls_version(),
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: default_log_format(),
            file: None,
            rotation: default_log_rotation(),
            max_size_mb: default_max_log_size(),
            max_files: default_max_log_files(),
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            data_dir: default_data_dir(),
            max_disk_usage_mb: default_max_disk_usage(),
            compression_enabled: default_compression_enabled(),
            backup_interval_hours: 0,
            backup_retention: default_backup_retention(),
        }
    }
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            pid_file: default_pid_file(),
            user: None,
            group: None,
            working_dir: None,
            auto_restart: default_auto_restart(),
            max_restarts: default_max_restarts(),
            restart_cooldown_secs: default_restart_cooldown(),
        }
    }
}

impl ServerConfig {
    /// Load configuration from a TOML file
    pub fn from_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)?;
        let config: ServerConfig = toml::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }

    /// Load configuration from TOML string
    pub fn from_str(content: &str) -> Result<Self, ConfigError> {
        let config: ServerConfig = toml::from_str(content)?;
        config.validate()?;
        Ok(config)
    }

    /// Merge CLI overrides into the configuration
    pub fn merge_cli_overrides(mut self, cli: &Cli) -> Result<Self, ConfigError> {
        // Override log level
        if let Some(level) = &cli.log_level {
            self.logging.level = level.clone();
        }

        // Override bind address
        if let Some(bind) = &cli.bind {
            self.network.bind_address = bind.parse()
                .map_err(|_| ConfigError::Validation(format!("Invalid bind address: {}", bind)))?;
        }

        // Override port
        if let Some(port) = cli.port {
            self.network.port = port;
        }

        // Validate after applying overrides
        self.validate()?;
        Ok(self)
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Validate port range
        if self.network.port == 0 {
            return Err(ConfigError::Validation("Port cannot be 0".to_string()));
        }

        // Validate TLS configuration
        if self.tls.enabled {
            if self.tls.cert_file.is_none() {
                return Err(ConfigError::Validation(
                    "TLS enabled but no certificate file specified".to_string(),
                ));
            }
            if self.tls.key_file.is_none() {
                return Err(ConfigError::Validation(
                    "TLS enabled but no key file specified".to_string(),
                ));
            }
        }

        // Validate log level
        match self.logging.level.as_str() {
            "trace" | "debug" | "info" | "warn" | "error" => {}
            _ => {
                return Err(ConfigError::Validation(format!(
                    "Invalid log level: {}",
                    self.logging.level
                )));
            }
        }

        // Validate log format
        match self.logging.format.as_str() {
            "json" | "pretty" | "compact" => {}
            _ => {
                return Err(ConfigError::Validation(format!(
                    "Invalid log format: {}",
                    self.logging.format
                )));
            }
        }

        // Validate TLS version
        match self.tls.min_version.as_str() {
            "1.2" | "1.3" => {}
            _ => {
                return Err(ConfigError::Validation(format!(
                    "Invalid TLS version: {}",
                    self.tls.min_version
                )));
            }
        }

        Ok(())
    }

    /// Get the socket address for binding
    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.network.bind_address, self.network.port)
    }

    /// Generate a default configuration file as TOML
    pub fn to_toml(&self) -> Result<String, toml::ser::Error> {
        toml::to_string_pretty(self)
    }
}
