//! Server configuration structures

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use crate::{ConfigError, Result};

/// Complete server configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServerConfiguration {
    /// Network configuration
    pub network: NetworkConfig,
    /// Security configuration
    pub security: SecurityConfig,
    /// Logging configuration
    pub logging: LoggingConfig,
    /// Daemon configuration
    pub daemon: DaemonConfig,
    /// Performance configuration
    pub performance: PerformanceConfig,
}

/// Network configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Server bind address and port
    pub bind_address: String,
    /// Federation port (for server-to-server communication)
    pub federation_port: u16,
    /// Connection timeout in seconds
    pub connection_timeout: u64,
    /// Keep-alive interval in seconds
    pub keep_alive_interval: u64,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            bind_address: "0.0.0.0:4242".to_string(),
            federation_port: 4243,
            connection_timeout: 300,
            keep_alive_interval: 60,
        }
    }
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Enable TLS
    pub enable_tls: bool,
    /// TLS certificate file path
    pub tls_cert_path: Option<String>,
    /// TLS private key file path
    pub tls_key_path: Option<String>,
    /// Server name for TLS
    pub server_name: String,
    /// Require client certificates
    pub require_client_certs: bool,
    /// Client CA certificate path
    pub client_ca_path: Option<String>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enable_tls: false,
            tls_cert_path: None,
            tls_key_path: None,
            server_name: "norc-server".to_string(),
            require_client_certs: false,
            client_ca_path: None,
        }
    }
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level (trace, debug, info, warn, error)
    pub level: String,
    /// Log format (json, pretty, compact)
    pub format: String,
    /// Log file path (if None, logs to stdout)
    pub file_path: Option<String>,
    /// Enable log rotation
    pub rotation: bool,
    /// Maximum log file size in MB
    pub max_file_size_mb: u64,
    /// Maximum number of log files to keep
    pub max_files: u32,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            format: "pretty".to_string(),
            file_path: None,
            rotation: false,
            max_file_size_mb: 100,
            max_files: 10,
        }
    }
}

/// Daemon configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DaemonConfig {
    /// Run as daemon (background process)
    pub daemonize: bool,
    /// PID file path
    pub pid_file: Option<String>,
    /// User to run as (for privilege dropping)
    pub user: Option<String>,
    /// Group to run as (for privilege dropping)
    pub group: Option<String>,
    /// Working directory
    pub working_directory: Option<String>,
}

/// Performance configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    /// Maximum concurrent connections
    pub max_connections: usize,
    /// Worker thread pool size
    pub worker_threads: Option<usize>,
    /// Maximum message size in bytes
    pub max_message_size: usize,
    /// Connection backlog size
    pub connection_backlog: u32,
    /// Enable TCP no-delay
    pub tcp_nodelay: bool,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            max_connections: 1000,
            worker_threads: None,          // Use default (number of CPU cores)
            max_message_size: 1024 * 1024, // 1MB
            connection_backlog: 128,
            tcp_nodelay: true,
        }
    }
}

impl ServerConfiguration {
    /// Validate the configuration
    pub fn validate(&self) -> Result<()> {
        // Validate bind address
        self.network
            .bind_address
            .parse::<SocketAddr>()
            .map_err(|e| ConfigError::InvalidValue {
                field: "network.bind_address".to_string(),
                message: format!("Invalid socket address: {}", e),
            })?;

        // Validate federation port
        if self.network.federation_port == 0 {
            return Err(ConfigError::InvalidValue {
                field: "network.federation_port".to_string(),
                message: "Port cannot be 0".to_string(),
            });
        }

        // Validate timeouts
        if self.network.connection_timeout == 0 {
            return Err(ConfigError::InvalidValue {
                field: "network.connection_timeout".to_string(),
                message: "Timeout must be greater than 0".to_string(),
            });
        }

        // Validate TLS configuration
        if self.security.enable_tls {
            if self.security.tls_cert_path.is_none() {
                return Err(ConfigError::MissingRequired(
                    "security.tls_cert_path is required when TLS is enabled".to_string(),
                ));
            }
            if self.security.tls_key_path.is_none() {
                return Err(ConfigError::MissingRequired(
                    "security.tls_key_path is required when TLS is enabled".to_string(),
                ));
            }
        }

        // Validate log level
        match self.logging.level.to_lowercase().as_str() {
            "trace" | "debug" | "info" | "warn" | "error" => {}
            _ => {
                return Err(ConfigError::InvalidValue {
                    field: "logging.level".to_string(),
                    message: "Must be one of: trace, debug, info, warn, error".to_string(),
                });
            }
        }

        // Validate log format
        match self.logging.format.to_lowercase().as_str() {
            "json" | "pretty" | "compact" => {}
            _ => {
                return Err(ConfigError::InvalidValue {
                    field: "logging.format".to_string(),
                    message: "Must be one of: json, pretty, compact".to_string(),
                });
            }
        }

        // Validate performance settings
        if self.performance.max_connections == 0 {
            return Err(ConfigError::InvalidValue {
                field: "performance.max_connections".to_string(),
                message: "Must be greater than 0".to_string(),
            });
        }

        if self.performance.max_message_size == 0 {
            return Err(ConfigError::InvalidValue {
                field: "performance.max_message_size".to_string(),
                message: "Must be greater than 0".to_string(),
            });
        }

        Ok(())
    }

    /// Get the parsed bind address
    pub fn bind_address(&self) -> Result<SocketAddr> {
        self.network
            .bind_address
            .parse()
            .map_err(|e| ConfigError::InvalidValue {
                field: "network.bind_address".to_string(),
                message: format!("Invalid socket address: {}", e),
            })
    }
}
