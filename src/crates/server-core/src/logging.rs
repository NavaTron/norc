//! Logging configuration and setup
//!
//! Provides structured logging with configurable outputs and formats.

use crate::ServerError;
use norc_config::ServerConfig;
use tracing::Level;
use tracing_subscriber::{EnvFilter, FmtSubscriber};

/// Initialize logging system
pub fn init_logging(config: &ServerConfig) -> Result<(), ServerError> {
    let logging_config = &config.logging;

    // Parse log level
    let level = parse_log_level(&logging_config.level)?;

    // Create environment filter
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(level.as_str()));

    // Initialize based on format
    match logging_config.format.as_str() {
        "json" => {
            let subscriber = FmtSubscriber::builder()
                .with_env_filter(env_filter)
                .json()
                .finish();
            tracing::subscriber::set_global_default(subscriber)
                .map_err(|e| ServerError::Config(
                    norc_config::ConfigError::Validation(format!("Failed to set logger: {}", e))
                ))?;
        }
        "pretty" => {
            let subscriber = FmtSubscriber::builder()
                .with_env_filter(env_filter)
                .pretty()
                .finish();
            tracing::subscriber::set_global_default(subscriber)
                .map_err(|e| ServerError::Config(
                    norc_config::ConfigError::Validation(format!("Failed to set logger: {}", e))
                ))?;
        }
        "compact" => {
            let subscriber = FmtSubscriber::builder()
                .with_env_filter(env_filter)
                .compact()
                .finish();
            tracing::subscriber::set_global_default(subscriber)
                .map_err(|e| ServerError::Config(
                    norc_config::ConfigError::Validation(format!("Failed to set logger: {}", e))
                ))?;
        }
        _ => {
            return Err(ServerError::Config(
                norc_config::ConfigError::Validation(format!(
                    "Unknown log format: {}",
                    logging_config.format
                )),
            ));
        }
    }

    tracing::info!("Logging initialized with level: {}", level);
    Ok(())
}

/// Parse log level string
fn parse_log_level(level: &str) -> Result<Level, ServerError> {
    match level.to_lowercase().as_str() {
        "trace" => Ok(Level::TRACE),
        "debug" => Ok(Level::DEBUG),
        "info" => Ok(Level::INFO),
        "warn" => Ok(Level::WARN),
        "error" => Ok(Level::ERROR),
        _ => Err(ServerError::Config(
            norc_config::ConfigError::Validation(format!("Invalid log level: {}", level)),
        )),
    }
}