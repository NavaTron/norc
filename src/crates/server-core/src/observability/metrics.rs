//! Prometheus Metrics System
//!
//! Implements Prometheus-compatible metrics collection and exposition.
//! Complies with E-05 observability requirements.

use crate::error::ServerError;
use norc_config::ObservabilityConfig;
use prometheus::{
    Counter, CounterVec, Encoder, Gauge, GaugeVec, Histogram, HistogramOpts, HistogramVec, IntCounter,
    IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry, TextEncoder,
};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Metrics collector for NORC server
#[derive(Clone)]
pub struct Metrics {
    registry: Arc<Registry>,
    
    // Connection metrics
    pub active_connections: IntGauge,
    pub total_connections: IntCounter,
    pub connection_duration: Histogram,
    
    // Message metrics
    pub messages_received: IntCounterVec,
    pub messages_sent: IntCounterVec,
    pub message_size: HistogramVec,
    pub message_processing_duration: HistogramVec,
    
    // Federation metrics
    pub federation_partners_connected: IntGauge,
    pub federation_messages_routed: IntCounterVec,
    pub federation_errors: IntCounterVec,
    
    // Protocol metrics
    pub handshakes_completed: IntCounter,
    pub handshakes_failed: IntCounterVec,
    pub encryption_operations: IntCounterVec,
    pub signature_operations: IntCounterVec,
    
    // System metrics
    pub memory_usage_bytes: IntGauge,
    pub cpu_usage_percent: Gauge,
    pub goroutines_count: IntGauge,
    
    // Error metrics
    pub errors_total: IntCounterVec,
    pub panics_total: IntCounter,
}

impl Metrics {
    /// Create new metrics collector
    pub fn new() -> Result<Self, ServerError> {
        let registry = Registry::new();

        // Connection metrics
        let active_connections = IntGauge::new(
            "norc_active_connections",
            "Number of currently active client connections",
        )
        .map_err(|e| ServerError::Internal(format!("Failed to create metric: {}", e)))?;
        
        let total_connections = IntCounter::new(
            "norc_total_connections",
            "Total number of client connections since startup",
        )
        .map_err(|e| ServerError::Internal(format!("Failed to create metric: {}", e)))?;
        
        let connection_duration = Histogram::with_opts(
            HistogramOpts::new(
                "norc_connection_duration_seconds",
                "Duration of client connections in seconds",
            )
            .buckets(vec![1.0, 5.0, 10.0, 30.0, 60.0, 300.0, 600.0, 1800.0, 3600.0]),
        )
        .map_err(|e| ServerError::Internal(format!("Failed to create metric: {}", e)))?;

        // Message metrics
        let messages_received = IntCounterVec::new(
            Opts::new("norc_messages_received_total", "Total number of messages received"),
            &["message_type"],
        )
        .map_err(|e| ServerError::Internal(format!("Failed to create metric: {}", e)))?;
        
        let messages_sent = IntCounterVec::new(
            Opts::new("norc_messages_sent_total", "Total number of messages sent"),
            &["message_type"],
        )
        .map_err(|e| ServerError::Internal(format!("Failed to create metric: {}", e)))?;
        
        let message_size = HistogramVec::new(
            HistogramOpts::new("norc_message_size_bytes", "Size of messages in bytes")
                .buckets(vec![
                    100.0, 1024.0, 10240.0, 102400.0, 1048576.0, 10485760.0, 16777216.0,
                ]),
            &["direction"],
        )
        .map_err(|e| ServerError::Internal(format!("Failed to create metric: {}", e)))?;
        
        let message_processing_duration = HistogramVec::new(
            HistogramOpts::new(
                "norc_message_processing_duration_seconds",
                "Time taken to process messages",
            )
            .buckets(vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0]),
            &["message_type"],
        )
        .map_err(|e| ServerError::Internal(format!("Failed to create metric: {}", e)))?;

        // Federation metrics
        let federation_partners_connected = IntGauge::new(
            "norc_federation_partners_connected",
            "Number of federation partners currently connected",
        )
        .map_err(|e| ServerError::Internal(format!("Failed to create metric: {}", e)))?;
        
        let federation_messages_routed = IntCounterVec::new(
            Opts::new(
                "norc_federation_messages_routed_total",
                "Total number of messages routed to federation partners",
            ),
            &["partner"],
        )
        .map_err(|e| ServerError::Internal(format!("Failed to create metric: {}", e)))?;
        
        let federation_errors = IntCounterVec::new(
            Opts::new(
                "norc_federation_errors_total",
                "Total number of federation errors",
            ),
            &["partner", "error_type"],
        )
        .map_err(|e| ServerError::Internal(format!("Failed to create metric: {}", e)))?;

        // Protocol metrics
        let handshakes_completed = IntCounter::new(
            "norc_handshakes_completed_total",
            "Total number of successfully completed handshakes",
        )
        .map_err(|e| ServerError::Internal(format!("Failed to create metric: {}", e)))?;
        
        let handshakes_failed = IntCounterVec::new(
            Opts::new("norc_handshakes_failed_total", "Total number of failed handshakes"),
            &["reason"],
        )
        .map_err(|e| ServerError::Internal(format!("Failed to create metric: {}", e)))?;
        
        let encryption_operations = IntCounterVec::new(
            Opts::new(
                "norc_encryption_operations_total",
                "Total number of encryption operations",
            ),
            &["operation"],
        )
        .map_err(|e| ServerError::Internal(format!("Failed to create metric: {}", e)))?;
        
        let signature_operations = IntCounterVec::new(
            Opts::new(
                "norc_signature_operations_total",
                "Total number of signature operations",
            ),
            &["operation"],
        )
        .map_err(|e| ServerError::Internal(format!("Failed to create metric: {}", e)))?;

        // System metrics
        let memory_usage_bytes = IntGauge::new(
            "norc_memory_usage_bytes",
            "Current memory usage in bytes",
        )
        .map_err(|e| ServerError::Internal(format!("Failed to create metric: {}", e)))?;
        
        let cpu_usage_percent = Gauge::new(
            "norc_cpu_usage_percent",
            "Current CPU usage percentage",
        )
        .map_err(|e| ServerError::Internal(format!("Failed to create metric: {}", e)))?;
        
        let goroutines_count = IntGauge::new(
            "norc_goroutines_count",
            "Number of active goroutines/tasks",
        )
        .map_err(|e| ServerError::Internal(format!("Failed to create metric: {}", e)))?;

        // Error metrics
        let errors_total = IntCounterVec::new(
            Opts::new("norc_errors_total", "Total number of errors"),
            &["error_type", "component"],
        )
        .map_err(|e| ServerError::Internal(format!("Failed to create metric: {}", e)))?;
        
        let panics_total = IntCounter::new(
            "norc_panics_total",
            "Total number of panics recovered",
        )
        .map_err(|e| ServerError::Internal(format!("Failed to create metric: {}", e)))?;

        // Register all metrics
        registry.register(Box::new(active_connections.clone()))?;
        registry.register(Box::new(total_connections.clone()))?;
        registry.register(Box::new(connection_duration.clone()))?;
        registry.register(Box::new(messages_received.clone()))?;
        registry.register(Box::new(messages_sent.clone()))?;
        registry.register(Box::new(message_size.clone()))?;
        registry.register(Box::new(message_processing_duration.clone()))?;
        registry.register(Box::new(federation_partners_connected.clone()))?;
        registry.register(Box::new(federation_messages_routed.clone()))?;
        registry.register(Box::new(federation_errors.clone()))?;
        registry.register(Box::new(handshakes_completed.clone()))?;
        registry.register(Box::new(handshakes_failed.clone()))?;
        registry.register(Box::new(encryption_operations.clone()))?;
        registry.register(Box::new(signature_operations.clone()))?;
        registry.register(Box::new(memory_usage_bytes.clone()))?;
        registry.register(Box::new(cpu_usage_percent.clone()))?;
        registry.register(Box::new(goroutines_count.clone()))?;
        registry.register(Box::new(errors_total.clone()))?;
        registry.register(Box::new(panics_total.clone()))?;

        Ok(Metrics {
            registry: Arc::new(registry),
            active_connections,
            total_connections,
            connection_duration,
            messages_received,
            messages_sent,
            message_size,
            message_processing_duration,
            federation_partners_connected,
            federation_messages_routed,
            federation_errors,
            handshakes_completed,
            handshakes_failed,
            encryption_operations,
            signature_operations,
            memory_usage_bytes,
            cpu_usage_percent,
            goroutines_count,
            errors_total,
            panics_total,
        })
    }

    /// Gather and encode metrics in Prometheus text format
    pub fn gather(&self) -> Result<String, ServerError> {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        encoder
            .encode(&metric_families, &mut buffer)
            .map_err(|e| ServerError::Internal(format!("Failed to encode metrics: {}", e)))?;
        String::from_utf8(buffer)
            .map_err(|e| ServerError::Internal(format!("Failed to convert metrics to string: {}", e)))
    }

    /// Start metrics HTTP server
    pub async fn serve(self, config: &ObservabilityConfig) -> Result<(), ServerError> {
        if !config.enable_metrics {
            tracing::info!("Metrics server disabled");
            return Ok(());
        }

        let addr = format!("{}:{}", config.metrics_address, config.metrics_port);
        let listener = TcpListener::bind(&addr)
            .await
            .map_err(|e| ServerError::Network(format!("Failed to bind metrics server: {}", e)))?;

        tracing::info!(address = %addr, "Metrics server listening");

        loop {
            let (mut socket, _) = listener
                .accept()
                .await
                .map_err(|e| ServerError::Network(format!("Failed to accept connection: {}", e)))?;

            let metrics = self.clone();

            tokio::spawn(async move {
                let mut buffer = [0; 4096];
                
                // Read HTTP request (simplified - just look for GET /metrics)
                if let Ok(n) = socket.read(&mut buffer).await {
                    let request = String::from_utf8_lossy(&buffer[..n]);
                    
                    if request.contains("GET /metrics") {
                        // Generate metrics
                        match metrics.gather() {
                            Ok(body) => {
                                let response = format!(
                                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\n\r\n{}",
                                    body.len(),
                                    body
                                );
                                let _ = socket.write_all(response.as_bytes()).await;
                            }
                            Err(e) => {
                                tracing::error!(error = %e, "Failed to gather metrics");
                                let response = "HTTP/1.1 500 Internal Server Error\r\n\r\n";
                                let _ = socket.write_all(response.as_bytes()).await;
                            }
                        }
                    } else if request.contains("GET /health") {
                        let response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nOK";
                        let _ = socket.write_all(response.as_bytes()).await;
                    } else {
                        let response = "HTTP/1.1 404 Not Found\r\n\r\n";
                        let _ = socket.write_all(response.as_bytes()).await;
                    }
                }
            });
        }
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new().expect("Failed to create default metrics")
    }
}
