//! Health Check System
//!
//! Implements liveness and readiness probes for monitoring and orchestration.
//! Complies with E-05 observability requirements.

use crate::error::ServerError;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Health status of a component
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthStatus {
    /// Component is healthy
    Healthy,
    /// Component is degraded but operational
    Degraded,
    /// Component is unhealthy
    Unhealthy,
}

/// Health check result for a component
#[derive(Debug, Clone)]
pub struct ComponentHealth {
    pub name: String,
    pub status: HealthStatus,
    pub message: Option<String>,
    
    #[allow(dead_code)]
    pub(crate) last_check: Instant,
    
    pub response_time_ms: Option<u64>,
}

/// Overall health check response
#[derive(Debug, Clone)]
pub struct HealthCheckResponse {
    pub status: HealthStatus,
    pub components: Vec<ComponentHealth>,
    pub uptime_seconds: u64,
    
    #[allow(dead_code)]
    pub(crate) timestamp: Instant,
}

/// Health checker for monitoring system components
#[derive(Clone)]
pub struct HealthChecker {
    components: Arc<RwLock<Vec<ComponentHealth>>>,
    start_time: Instant,
}

impl HealthChecker {
    /// Create new health checker
    pub fn new() -> Self {
        Self {
            components: Arc::new(RwLock::new(Vec::new())),
            start_time: Instant::now(),
        }
    }

    /// Register a component for health checking
    pub async fn register_component(&self, name: String) {
        let mut components = self.components.write().await;
        components.push(ComponentHealth {
            name,
            status: HealthStatus::Healthy,
            message: None,
            last_check: Instant::now(),
            response_time_ms: None,
        });
    }

    /// Update health status of a component
    pub async fn update_component(
        &self,
        name: &str,
        status: HealthStatus,
        message: Option<String>,
        response_time: Option<Duration>,
    ) {
        let mut components = self.components.write().await;
        if let Some(component) = components.iter_mut().find(|c| c.name == name) {
            component.status = status;
            component.message = message;
            component.last_check = Instant::now();
            component.response_time_ms = response_time.map(|d| d.as_millis() as u64);
        }
    }

    /// Get overall health status
    pub async fn get_health(&self) -> HealthCheckResponse {
        let components = self.components.read().await.clone();
        
        // Determine overall status
        let status = if components.iter().any(|c| c.status == HealthStatus::Unhealthy) {
            HealthStatus::Unhealthy
        } else if components.iter().any(|c| c.status == HealthStatus::Degraded) {
            HealthStatus::Degraded
        } else {
            HealthStatus::Healthy
        };

        HealthCheckResponse {
            status,
            components,
            uptime_seconds: self.start_time.elapsed().as_secs(),
            timestamp: Instant::now(),
        }
    }

    /// Check if system is ready (all components healthy or degraded)
    pub async fn is_ready(&self) -> bool {
        let components = self.components.read().await;
        !components.iter().any(|c| c.status == HealthStatus::Unhealthy)
    }

    /// Check if system is alive (at least some components are responsive)
    pub async fn is_alive(&self) -> bool {
        let components = self.components.read().await;
        
        // System is alive if at least one component is healthy or degraded
        // and was checked recently (within last 60 seconds)
        let now = Instant::now();
        components.iter().any(|c| {
            (c.status == HealthStatus::Healthy || c.status == HealthStatus::Degraded)
                && now.duration_since(c.last_check) < Duration::from_secs(60)
        })
    }

    /// Start background health monitoring
    pub fn start_monitoring(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            
            loop {
                interval.tick().await;
                
                // Perform health checks
                let components = self.components.read().await.clone();
                
                for component in components {
                    let start = Instant::now();
                    
                    // Perform component-specific health check
                    let (status, message) = match component.name.as_str() {
                        "transport" => check_transport_health().await,
                        "federation" => check_federation_health().await,
                        "database" => check_database_health().await,
                        "crypto" => check_crypto_health().await,
                        _ => (HealthStatus::Healthy, None),
                    };
                    
                    let elapsed = start.elapsed();
                    
                    self.update_component(
                        &component.name,
                        status,
                        message,
                        Some(elapsed),
                    )
                    .await;
                }
                
                let health = self.get_health().await;
                tracing::debug!(
                    status = ?health.status,
                    components = health.components.len(),
                    "Health check completed"
                );
            }
        })
    }
}

impl Default for HealthChecker {
    fn default() -> Self {
        Self::new()
    }
}

// Component-specific health checks

async fn check_transport_health() -> (HealthStatus, Option<String>) {
    // TODO: Implement actual transport health check
    // For now, assume healthy
    (HealthStatus::Healthy, None)
}

async fn check_federation_health() -> (HealthStatus, Option<String>) {
    // TODO: Implement actual federation health check
    // For now, assume healthy
    (HealthStatus::Healthy, None)
}

async fn check_database_health() -> (HealthStatus, Option<String>) {
    // TODO: Implement actual database health check
    // For now, assume healthy
    (HealthStatus::Healthy, None)
}

async fn check_crypto_health() -> (HealthStatus, Option<String>) {
    // TODO: Implement actual crypto health check
    // For now, assume healthy
    (HealthStatus::Healthy, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_health_checker_initialization() {
        let checker = HealthChecker::new();
        let health = checker.get_health().await;
        assert_eq!(health.status, HealthStatus::Healthy);
        assert_eq!(health.components.len(), 0);
    }

    #[tokio::test]
    async fn test_register_and_update_component() {
        let checker = HealthChecker::new();
        
        checker.register_component("test".to_string()).await;
        
        let health = checker.get_health().await;
        assert_eq!(health.components.len(), 1);
        assert_eq!(health.components[0].status, HealthStatus::Healthy);
        
        checker.update_component(
            "test",
            HealthStatus::Degraded,
            Some("Test degradation".to_string()),
            None,
        ).await;
        
        let health = checker.get_health().await;
        assert_eq!(health.status, HealthStatus::Degraded);
    }

    #[tokio::test]
    async fn test_overall_status_determination() {
        let checker = HealthChecker::new();
        
        checker.register_component("comp1".to_string()).await;
        checker.register_component("comp2".to_string()).await;
        
        // All healthy
        let health = checker.get_health().await;
        assert_eq!(health.status, HealthStatus::Healthy);
        
        // One degraded
        checker.update_component("comp1", HealthStatus::Degraded, None, None).await;
        let health = checker.get_health().await;
        assert_eq!(health.status, HealthStatus::Degraded);
        
        // One unhealthy
        checker.update_component("comp2", HealthStatus::Unhealthy, None, None).await;
        let health = checker.get_health().await;
        assert_eq!(health.status, HealthStatus::Unhealthy);
    }
}
