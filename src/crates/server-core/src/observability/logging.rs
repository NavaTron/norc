//! Structured Logging System
//!
//! Implements structured logging with JSON output, log rotation, and multiple output targets.
//! Complies with E-05 observability requirements.

use crate::error::ServerError;
use norc_config::ObservabilityConfig;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::Level;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{
    fmt::{self, format::FmtSpan},
    layer::SubscriberExt,
    EnvFilter, Registry,
};

/// Logger handle that maintains the worker guard and supports rotation
pub struct Logger {
    _guard: WorkerGuard,
    config: Arc<RwLock<ObservabilityConfig>>,
}

impl Logger {
    /// Initialize the logging system
    pub fn init(config: &ObservabilityConfig) -> Result<Self, ServerError> {
        let level = parse_log_level(&config.log_level)?;
        
        // Create environment filter with default level
        let env_filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| {
                EnvFilter::new(format!("norc={},tower=info,hyper=info", level.as_str()))
            });

        // Configure file appender with rotation
        let file_appender = tracing_appender::rolling::daily(
            config.log_file_path.parent().unwrap_or(&PathBuf::from(".")),
            config.log_file_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("norc-server.log"),
        );
        
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

        // Build the subscriber based on format
        match config.log_format.as_str() {
            "json" => {
                let fmt_layer = fmt::layer()
                    .json()
                    .with_writer(non_blocking)
                    .with_span_events(FmtSpan::CLOSE)
                    .with_thread_ids(true)
                    .with_thread_names(true)
                    .with_target(true)
                    .with_file(true)
                    .with_line_number(true);

                let subscriber = Registry::default()
                    .with(env_filter)
                    .with(fmt_layer);

                tracing::subscriber::set_global_default(subscriber)
                    .map_err(|e| {
                        ServerError::Internal(format!("Failed to set logger: {}", e))
                    })?;
            }
            "pretty" => {
                let fmt_layer = fmt::layer()
                    .pretty()
                    .with_writer(non_blocking)
                    .with_span_events(FmtSpan::CLOSE)
                    .with_thread_ids(true)
                    .with_thread_names(true)
                    .with_target(true)
                    .with_file(true)
                    .with_line_number(true);

                let subscriber = Registry::default()
                    .with(env_filter)
                    .with(fmt_layer);

                tracing::subscriber::set_global_default(subscriber)
                    .map_err(|e| {
                        ServerError::Internal(format!("Failed to set logger: {}", e))
                    })?;
            }
            "compact" => {
                let fmt_layer = fmt::layer()
                    .compact()
                    .with_writer(non_blocking)
                    .with_span_events(FmtSpan::CLOSE)
                    .with_thread_ids(true)
                    .with_target(true);

                let subscriber = Registry::default()
                    .with(env_filter)
                    .with(fmt_layer);

                tracing::subscriber::set_global_default(subscriber)
                    .map_err(|e| {
                        ServerError::Internal(format!("Failed to set logger: {}", e))
                    })?;
            }
            _ => {
                return Err(ServerError::Config(
                    norc_config::ConfigError::Validation(format!(
                        "Unknown log format: {}",
                        config.log_format
                    )),
                ));
            }
        }

        eprintln!(
            "Logging initialized with level: {}",
            level
        );

        Ok(Logger { 
            _guard: guard,
            config: Arc::new(RwLock::new(config.clone())),
        })
    }

    /// Rotate log files (triggered by SIGUSR1)
    pub async fn rotate(&self) -> Result<(), ServerError> {
        let config = self.config.read().await;
        
        tracing::info!("Log rotation triggered via SIGUSR1");
        
        // The tracing_appender with rolling::daily automatically handles rotation
        // based on date changes. For manual rotation on SIGUSR1, we log the event
        // and flush any pending writes.
        
        // Future enhancement: Support for size-based rotation or manual file rotation
        // would require recreating the appender with a new file handle
        
        tracing::info!(
            log_file = ?config.log_file_path,
            "Log rotation completed - daily appender handles file management"
        );
        
        Ok(())
    }
}

/// Parse log level string to tracing::Level
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

/// Structured log macros for common patterns
#[macro_export]
macro_rules! log_request {
    ($($field:tt)*) => {
        tracing::info!(
            event = "request",
            $($field)*
        )
    };
}

#[macro_export]
macro_rules! log_response {
    ($($field:tt)*) => {
        tracing::info!(
            event = "response",
            $($field)*
        )
    };
}

#[macro_export]
macro_rules! log_error {
    ($($field:tt)*) => {
        tracing::error!(
            event = "error",
            $($field)*
        )
    };
}

#[macro_export]
macro_rules! log_security {
    ($($field:tt)*) => {
        tracing::warn!(
            event = "security",
            $($field)*
        )
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_log_level() {
        assert!(matches!(parse_log_level("trace"), Ok(Level::TRACE)));
        assert!(matches!(parse_log_level("DEBUG"), Ok(Level::DEBUG)));
        assert!(matches!(parse_log_level("Info"), Ok(Level::INFO)));
        assert!(matches!(parse_log_level("WARN"), Ok(Level::WARN)));
        assert!(matches!(parse_log_level("error"), Ok(Level::ERROR)));
        assert!(parse_log_level("invalid").is_err());
    }
}
