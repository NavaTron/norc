//! Observability Platform
//!
//! Comprehensive observability system including:
//! - Structured logging with JSON output and rotation
//! - Prometheus metrics collection and exposition
//! - Health checks (liveness and readiness probes)
//! - Distributed tracing with OpenTelemetry (optional)
//!
//! Complies with SERVER_REQUIREMENTS E-05.

pub mod health;
pub mod logging;
pub mod metrics;
pub mod tracing;

pub use health::{ComponentHealth, HealthCheckResponse, HealthChecker, HealthStatus};
pub use logging::Logger;
pub use metrics::Metrics;
pub use tracing::Tracer;

use crate::error::ServerError;
use norc_config::ObservabilityConfig;

/// Complete observability system
pub struct ObservabilitySystem {
    pub logger: Logger,
    pub metrics: Metrics,
    pub health: HealthChecker,
    pub tracer: Tracer,
}

impl ObservabilitySystem {
    /// Initialize the complete observability system
    pub async fn init(config: &ObservabilityConfig) -> Result<Self, ServerError> {
        // Initialize logging first so we can log subsequent initialization
        let logger = Logger::init(config)?;

        eprintln!("Initializing observability system");

        // Initialize metrics
        let metrics = Metrics::new()?;
        eprintln!("Metrics system initialized");

        // Initialize health checker
        let health = HealthChecker::new();

        // Register core components for health monitoring
        health.register_component("transport".to_string()).await;
        health.register_component("federation".to_string()).await;
        health.register_component("crypto".to_string()).await;
        health.register_component("database".to_string()).await;

        eprintln!("Health check system initialized");

        // Initialize distributed tracing
        let tracer = Tracer::init(config)?;

        eprintln!("Observability system fully initialized");

        Ok(Self {
            logger,
            metrics,
            health,
            tracer,
        })
    }

    /// Start background observability tasks
    pub async fn start(&self, config: &ObservabilityConfig) -> Result<(), ServerError> {
        // Start health monitoring
        let _health_handle = self.health.clone().start_monitoring();
        eprintln!("Health monitoring started");

        // Start metrics server
        if config.enable_metrics {
            let metrics = self.metrics.clone();
            let config_clone = config.clone();
            tokio::spawn(async move {
                if let Err(e) = metrics.serve(&config_clone).await {
                    eprintln!("Metrics server failed: {}", e);
                }
            });
        }

        Ok(())
    }

    /// Shutdown observability system gracefully
    pub async fn shutdown(self) {
        eprintln!("Shutting down observability system");

        // Shutdown tracing
        self.tracer.shutdown().await;

        // Final log message
        eprintln!("Observability system shutdown complete");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[tokio::test]
    async fn test_observability_system_init() {
        let config = ObservabilityConfig {
            log_level: "info".to_string(),
            log_format: "json".to_string(),
            log_file_path: PathBuf::from("/tmp/test-norc.log"),
            enable_metrics: false,
            metrics_address: "127.0.0.1".to_string(),
            metrics_port: 9091,
            enable_tracing: false,
            tracing_endpoint: "http://localhost:4317".to_string(),
            tracing_sample_rate: 1.0,
        };

        let system = ObservabilitySystem::init(&config).await;
        assert!(system.is_ok());
    }
}
