//! Distributed Tracing System
//!
//! Implements OpenTelemetry-compatible distributed tracing.
//! Complies with E-05 observability requirements.

use crate::error::ServerError;
use norc_config::ObservabilityConfig;

#[cfg(feature = "tracing-otlp")]
use opentelemetry::{global, KeyValue};
#[cfg(feature = "tracing-otlp")]
use opentelemetry_otlp::WithExportConfig;
#[cfg(feature = "tracing-otlp")]
use opentelemetry_sdk::{runtime, Resource};
#[cfg(feature = "tracing-otlp")]
use tracing_opentelemetry::OpenTelemetryLayer;
#[cfg(feature = "tracing-otlp")]
use tracing_subscriber::layer::SubscriberExt;

/// Tracer handle for distributed tracing
pub struct Tracer {
    #[cfg(feature = "tracing-otlp")]
    _guard: Option<()>,
}

impl Tracer {
    /// Initialize distributed tracing
    pub fn init(config: &ObservabilityConfig) -> Result<Self, ServerError> {
        if !config.enable_tracing {
            tracing::info!("Distributed tracing disabled");
            return Ok(Self {
                #[cfg(feature = "tracing-otlp")]
                _guard: None,
            });
        }

        #[cfg(feature = "tracing-otlp")]
        {
            Self::init_opentelemetry(config)
        }

        #[cfg(not(feature = "tracing-otlp"))]
        {
            tracing::warn!(
                "Tracing enabled in config but 'tracing-otlp' feature not compiled. \
                Enable with: cargo build --features tracing-otlp"
            );
            Ok(Self {})
        }
    }

    #[cfg(feature = "tracing-otlp")]
    fn init_opentelemetry(config: &ObservabilityConfig) -> Result<Self, ServerError> {
        use opentelemetry_sdk::trace::TracerProvider;
        
        // Parse service name from organization_id or use default
        let service_name = format!("norc-server");

        // Create OTLP exporter
        let exporter = opentelemetry_otlp::new_exporter()
            .tonic()
            .with_endpoint(&config.tracing_endpoint);

        // Create trace provider
        let tracer_provider = opentelemetry_otlp::new_pipeline()
            .tracing()
            .with_exporter(exporter)
            .with_trace_config(
                opentelemetry_sdk::trace::config().with_resource(Resource::new(vec![
                    KeyValue::new("service.name", service_name.clone()),
                    KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
                ])),
            )
            .install_batch(runtime::Tokio)
            .map_err(|e| {
                ServerError::Internal(format!("Failed to initialize OpenTelemetry: {}", e))
            })?;

        // Set global tracer provider
        global::set_tracer_provider(tracer_provider);

        tracing::info!(
            service_name = %service_name,
            endpoint = %config.tracing_endpoint,
            "OpenTelemetry tracing initialized"
        );

        Ok(Self { _guard: Some(()) })
    }

    /// Create a span for request tracking
    #[tracing::instrument(skip(self))]
    pub fn create_request_span(&self, request_id: &str, operation: &str) {
        tracing::info!(
            request_id = %request_id,
            operation = %operation,
            "Request started"
        );
    }

    /// Record span event
    #[tracing::instrument(skip(self))]
    pub fn record_event(&self, event: &str, attributes: Vec<(&str, &str)>) {
        let span = tracing::Span::current();
        for (key, value) in attributes {
            span.record(key, value);
        }
        eprintln!("Span event recorded: {}", event);
    }

    /// Shutdown tracing and flush remaining spans
    pub async fn shutdown(self) {
        #[cfg(feature = "tracing-otlp")]
        {
            global::shutdown_tracer_provider();
            tracing::info!("Tracing system shutdown complete");
        }
    }
}

/// Macro for creating traced spans with automatic context propagation
#[macro_export]
macro_rules! trace_span {
    ($name:expr) => {
        tracing::info_span!($name)
    };
    ($name:expr, $($field:tt)*) => {
        tracing::info_span!($name, $($field)*)
    };
}

/// Macro for tracing async operations
#[macro_export]
macro_rules! trace_async {
    ($name:expr, $future:expr) => {{
        let span = tracing::info_span!($name);
        $future.instrument(span).await
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tracer_creation_without_otlp() {
        // Without tracing-otlp feature, should create successfully but do nothing
        let config = ObservabilityConfig {
            log_level: "info".to_string(),
            log_format: "json".to_string(),
            log_file_path: "/tmp/test.log".into(),
            enable_metrics: false,
            metrics_address: "0.0.0.0".to_string(),
            metrics_port: 9090,
            enable_tracing: false,
            tracing_endpoint: "http://localhost:4317".to_string(),
            tracing_sample_rate: 1.0,
        };

        let tracer = Tracer::init(&config);
        assert!(tracer.is_ok());
    }
}
