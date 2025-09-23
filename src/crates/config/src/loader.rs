//! Configuration loading and parsing

use std::env;
use std::fs;
use std::path::Path;

use crate::{ConfigError, Result, ServerConfiguration};

/// Configuration loader with support for files and environment variables
pub struct ConfigLoader;

impl ConfigLoader {
    /// Load configuration from a TOML file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<ServerConfiguration> {
        let path = path.as_ref();
        
        // Check if file exists
        if !path.exists() {
            return Err(ConfigError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Configuration file not found: {}", path.display()),
            )));
        }

        // Read file content
        let content = fs::read_to_string(path)
            .map_err(|e| ConfigError::Io(e))?;

        // Parse TOML
        let mut config: ServerConfiguration = toml::from_str(&content)
            .map_err(ConfigError::Toml)?;

        // Apply environment variable overrides
        Self::apply_env_overrides(&mut config)?;

        // Validate configuration
        config.validate()?;

        Ok(config)
    }

    /// Load configuration from environment variables only
    pub fn from_env() -> Result<ServerConfiguration> {
        let mut config = ServerConfiguration::default();
        Self::apply_env_overrides(&mut config)?;
        config.validate()?;
        Ok(config)
    }

    /// Load configuration with file fallback to environment
    pub fn load() -> Result<ServerConfiguration> {
        // Try common configuration file paths
        let config_paths = [
            "norc-server.toml",
            "config/norc-server.toml",
            "/etc/norc/server.toml",
            "~/.config/norc/server.toml",
        ];

        for path in &config_paths {
            if Path::new(path).exists() {
                return Self::from_file(path);
            }
        }

        // Check for explicit config file in environment
        if let Ok(config_file) = env::var("NORC_CONFIG_FILE") {
            return Self::from_file(config_file);
        }

        // Fall back to environment variables only
        Self::from_env()
    }

    /// Apply environment variable overrides to configuration
    fn apply_env_overrides(config: &mut ServerConfiguration) -> Result<()> {
        // Network configuration
        if let Ok(bind_address) = env::var("NORC_BIND_ADDRESS") {
            config.network.bind_address = bind_address;
        }
        
        if let Ok(federation_port) = env::var("NORC_FEDERATION_PORT") {
            config.network.federation_port = federation_port.parse()
                .map_err(|e| ConfigError::Environment(
                    format!("Invalid NORC_FEDERATION_PORT: {}", e)
                ))?;
        }

        if let Ok(connection_timeout) = env::var("NORC_CONNECTION_TIMEOUT") {
            config.network.connection_timeout = connection_timeout.parse()
                .map_err(|e| ConfigError::Environment(
                    format!("Invalid NORC_CONNECTION_TIMEOUT: {}", e)
                ))?;
        }

        // Security configuration
        if let Ok(enable_tls) = env::var("NORC_ENABLE_TLS") {
            config.security.enable_tls = enable_tls.parse()
                .map_err(|e| ConfigError::Environment(
                    format!("Invalid NORC_ENABLE_TLS: {}", e)
                ))?;
        }

        if let Ok(tls_cert_path) = env::var("NORC_TLS_CERT_PATH") {
            config.security.tls_cert_path = Some(tls_cert_path);
        }

        if let Ok(tls_key_path) = env::var("NORC_TLS_KEY_PATH") {
            config.security.tls_key_path = Some(tls_key_path);
        }

        if let Ok(server_name) = env::var("NORC_SERVER_NAME") {
            config.security.server_name = server_name;
        }

        // Logging configuration
        if let Ok(log_level) = env::var("NORC_LOG_LEVEL") {
            config.logging.level = log_level;
        }

        if let Ok(log_format) = env::var("NORC_LOG_FORMAT") {
            config.logging.format = log_format;
        }

        if let Ok(log_file) = env::var("NORC_LOG_FILE") {
            config.logging.file_path = Some(log_file);
        }

        // Daemon configuration
        if let Ok(daemonize) = env::var("NORC_DAEMONIZE") {
            config.daemon.daemonize = daemonize.parse()
                .map_err(|e| ConfigError::Environment(
                    format!("Invalid NORC_DAEMONIZE: {}", e)
                ))?;
        }

        if let Ok(pid_file) = env::var("NORC_PID_FILE") {
            config.daemon.pid_file = Some(pid_file);
        }

        if let Ok(user) = env::var("NORC_USER") {
            config.daemon.user = Some(user);
        }

        if let Ok(group) = env::var("NORC_GROUP") {
            config.daemon.group = Some(group);
        }

        // Performance configuration
        if let Ok(max_connections) = env::var("NORC_MAX_CONNECTIONS") {
            config.performance.max_connections = max_connections.parse()
                .map_err(|e| ConfigError::Environment(
                    format!("Invalid NORC_MAX_CONNECTIONS: {}", e)
                ))?;
        }

        if let Ok(worker_threads) = env::var("NORC_WORKER_THREADS") {
            let threads: usize = worker_threads.parse()
                .map_err(|e| ConfigError::Environment(
                    format!("Invalid NORC_WORKER_THREADS: {}", e)
                ))?;
            config.performance.worker_threads = Some(threads);
        }

        if let Ok(max_message_size) = env::var("NORC_MAX_MESSAGE_SIZE") {
            config.performance.max_message_size = max_message_size.parse()
                .map_err(|e| ConfigError::Environment(
                    format!("Invalid NORC_MAX_MESSAGE_SIZE: {}", e)
                ))?;
        }

        Ok(())
    }

    /// Create a sample configuration file
    pub fn create_sample_config<P: AsRef<Path>>(path: P) -> Result<()> {
        let config = ServerConfiguration::default();
        let toml_content = toml::to_string_pretty(&config)
            .map_err(|e| ConfigError::Validation(format!("Failed to serialize config: {}", e)))?;

        fs::write(path, toml_content)
            .map_err(ConfigError::Io)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_default_config_validation() {
        let config = ServerConfiguration::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_env_override() {
        unsafe {
            env::set_var("NORC_BIND_ADDRESS", "127.0.0.1:8080");
            env::set_var("NORC_LOG_LEVEL", "debug");
        }
        
        let config = ConfigLoader::from_env().unwrap();
        assert_eq!(config.network.bind_address, "127.0.0.1:8080");
        assert_eq!(config.logging.level, "debug");
        
        unsafe {
            env::remove_var("NORC_BIND_ADDRESS");
            env::remove_var("NORC_LOG_LEVEL");
        }
    }
}