//! Security Metrics for Transport Layer
//!
//! Prometheus metrics collection for certificate validation, revocation checking,
//! and certificate rotation operations.
//!
//! Metrics exposed:
//! - Certificate validation attempts and failures
//! - Revocation check operations (OCSP/CRL)
//! - Certificate rotation events
//! - Certificate expiration gauges
//! - TLS handshake metrics

use prometheus::{
    Histogram, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge,
    IntGaugeVec, Opts, Registry,
};
use std::sync::Arc;

/// Security metrics collector for transport layer
#[derive(Clone)]
pub struct SecurityMetrics {
    registry: Arc<Registry>,
    
    // Certificate validation metrics
    pub cert_validations_total: IntCounterVec,
    pub cert_validation_failures_total: IntCounterVec,
    pub cert_validation_duration: HistogramVec,
    pub cert_chain_depth: HistogramVec,
    
    // Certificate expiration metrics
    pub cert_expiry_seconds: IntGaugeVec,
    pub cert_expired_total: IntCounter,
    pub cert_expiring_soon_total: IntGauge,
    
    // Certificate pinning metrics
    pub cert_pin_validations_total: IntCounterVec,
    pub cert_pin_failures_total: IntCounterVec,
    
    // Revocation checking metrics
    pub revocation_checks_total: IntCounterVec,
    pub revocation_check_failures_total: IntCounterVec,
    pub revocation_check_duration: HistogramVec,
    pub revocation_status_revoked: IntCounterVec,
    pub revocation_status_unknown: IntCounterVec,
    
    // OCSP-specific metrics
    pub ocsp_requests_total: IntCounter,
    pub ocsp_request_failures_total: IntCounterVec,
    pub ocsp_cache_hits_total: IntCounter,
    pub ocsp_cache_misses_total: IntCounter,
    pub ocsp_response_duration: Histogram,
    
    // CRL-specific metrics
    pub crl_downloads_total: IntCounter,
    pub crl_download_failures_total: IntCounterVec,
    pub crl_cache_hits_total: IntCounter,
    pub crl_cache_misses_total: IntCounter,
    pub crl_download_duration: Histogram,
    pub crl_download_bytes: Histogram,
    
    // Certificate rotation metrics
    pub cert_rotations_total: IntCounterVec,
    pub cert_rotation_failures_total: IntCounterVec,
    pub cert_rotation_duration: Histogram,
    pub cert_reload_total: IntCounter,
    pub cert_reload_failures_total: IntCounterVec,
    pub cert_age_seconds: IntGaugeVec,
    
    // TLS handshake metrics
    pub tls_handshakes_total: IntCounterVec,
    pub tls_handshake_failures_total: IntCounterVec,
    pub tls_handshake_duration: HistogramVec,
    pub mutual_tls_verifications_total: IntCounterVec,
}

impl SecurityMetrics {
    /// Create new security metrics collector
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let registry = Registry::new();
        
        // Certificate validation metrics
        let cert_validations_total = IntCounterVec::new(
            Opts::new(
                "norc_transport_cert_validations_total",
                "Total number of certificate validation attempts"
            ),
            &["cert_type", "organization_id"],
        )?;
        
        let cert_validation_failures_total = IntCounterVec::new(
            Opts::new(
                "norc_transport_cert_validation_failures_total",
                "Total number of certificate validation failures"
            ),
            &["reason", "cert_type"],
        )?;
        
        let cert_validation_duration = HistogramVec::new(
            HistogramOpts::new(
                "norc_transport_cert_validation_duration_seconds",
                "Duration of certificate validation operations"
            )
            .buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]),
            &["cert_type"],
        )?;
        
        let cert_chain_depth = HistogramVec::new(
            HistogramOpts::new(
                "norc_transport_cert_chain_depth",
                "Depth of certificate chains validated"
            )
            .buckets(vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0]),
            &["organization_id"],
        )?;
        
        // Certificate expiration metrics
        let cert_expiry_seconds = IntGaugeVec::new(
            Opts::new(
                "norc_transport_cert_expiry_seconds",
                "Seconds until certificate expiration"
            ),
            &["cert_type", "organization_id"],
        )?;
        
        let cert_expired_total = IntCounter::new(
            "norc_transport_cert_expired_total",
            "Total number of expired certificates encountered"
        )?;
        
        let cert_expiring_soon_total = IntGauge::new(
            "norc_transport_cert_expiring_soon_total",
            "Number of certificates expiring within 30 days"
        )?;
        
        // Certificate pinning metrics
        let cert_pin_validations_total = IntCounterVec::new(
            Opts::new(
                "norc_transport_cert_pin_validations_total",
                "Total number of certificate pin validations"
            ),
            &["pin_type"],
        )?;
        
        let cert_pin_failures_total = IntCounterVec::new(
            Opts::new(
                "norc_transport_cert_pin_failures_total",
                "Total number of certificate pin validation failures"
            ),
            &["reason"],
        )?;
        
        // Revocation checking metrics
        let revocation_checks_total = IntCounterVec::new(
            Opts::new(
                "norc_transport_revocation_checks_total",
                "Total number of revocation checks performed"
            ),
            &["method", "organization_id"],
        )?;
        
        let revocation_check_failures_total = IntCounterVec::new(
            Opts::new(
                "norc_transport_revocation_check_failures_total",
                "Total number of revocation check failures"
            ),
            &["method", "reason"],
        )?;
        
        let revocation_check_duration = HistogramVec::new(
            HistogramOpts::new(
                "norc_transport_revocation_check_duration_seconds",
                "Duration of revocation check operations"
            )
            .buckets(vec![0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0]),
            &["method"],
        )?;
        
        let revocation_status_revoked = IntCounterVec::new(
            Opts::new(
                "norc_transport_revocation_status_revoked_total",
                "Total number of revoked certificates detected"
            ),
            &["method", "organization_id"],
        )?;
        
        let revocation_status_unknown = IntCounterVec::new(
            Opts::new(
                "norc_transport_revocation_status_unknown_total",
                "Total number of certificates with unknown revocation status"
            ),
            &["method"],
        )?;
        
        // OCSP-specific metrics
        let ocsp_requests_total = IntCounter::new(
            "norc_transport_ocsp_requests_total",
            "Total number of OCSP requests sent"
        )?;
        
        let ocsp_request_failures_total = IntCounterVec::new(
            Opts::new(
                "norc_transport_ocsp_request_failures_total",
                "Total number of OCSP request failures"
            ),
            &["reason"],
        )?;
        
        let ocsp_cache_hits_total = IntCounter::new(
            "norc_transport_ocsp_cache_hits_total",
            "Total number of OCSP cache hits"
        )?;
        
        let ocsp_cache_misses_total = IntCounter::new(
            "norc_transport_ocsp_cache_misses_total",
            "Total number of OCSP cache misses"
        )?;
        
        let ocsp_response_duration = Histogram::with_opts(
            HistogramOpts::new(
                "norc_transport_ocsp_response_duration_seconds",
                "Duration of OCSP response retrieval"
            )
            .buckets(vec![0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0])
        )?;
        
        // CRL-specific metrics
        let crl_downloads_total = IntCounter::new(
            "norc_transport_crl_downloads_total",
            "Total number of CRL downloads"
        )?;
        
        let crl_download_failures_total = IntCounterVec::new(
            Opts::new(
                "norc_transport_crl_download_failures_total",
                "Total number of CRL download failures"
            ),
            &["reason"],
        )?;
        
        let crl_cache_hits_total = IntCounter::new(
            "norc_transport_crl_cache_hits_total",
            "Total number of CRL cache hits"
        )?;
        
        let crl_cache_misses_total = IntCounter::new(
            "norc_transport_crl_cache_misses_total",
            "Total number of CRL cache misses"
        )?;
        
        let crl_download_duration = Histogram::with_opts(
            HistogramOpts::new(
                "norc_transport_crl_download_duration_seconds",
                "Duration of CRL downloads"
            )
            .buckets(vec![0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0])
        )?;
        
        let crl_download_bytes = Histogram::with_opts(
            HistogramOpts::new(
                "norc_transport_crl_download_bytes",
                "Size of downloaded CRLs in bytes"
            )
            .buckets(vec![
                1024.0,      // 1 KB
                10240.0,     // 10 KB
                102400.0,    // 100 KB
                1048576.0,   // 1 MB
                5242880.0,   // 5 MB
                10485760.0,  // 10 MB
            ])
        )?;
        
        // Certificate rotation metrics
        let cert_rotations_total = IntCounterVec::new(
            Opts::new(
                "norc_transport_cert_rotations_total",
                "Total number of certificate rotations"
            ),
            &["trigger", "cert_type"],
        )?;
        
        let cert_rotation_failures_total = IntCounterVec::new(
            Opts::new(
                "norc_transport_cert_rotation_failures_total",
                "Total number of certificate rotation failures"
            ),
            &["reason", "cert_type"],
        )?;
        
        let cert_rotation_duration = Histogram::with_opts(
            HistogramOpts::new(
                "norc_transport_cert_rotation_duration_seconds",
                "Duration of certificate rotation operations"
            )
            .buckets(vec![0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0])
        )?;
        
        let cert_reload_total = IntCounter::new(
            "norc_transport_cert_reload_total",
            "Total number of certificate reloads from disk"
        )?;
        
        let cert_reload_failures_total = IntCounterVec::new(
            Opts::new(
                "norc_transport_cert_reload_failures_total",
                "Total number of certificate reload failures"
            ),
            &["reason"],
        )?;
        
        let cert_age_seconds = IntGaugeVec::new(
            Opts::new(
                "norc_transport_cert_age_seconds",
                "Age of currently loaded certificates in seconds"
            ),
            &["cert_type"],
        )?;
        
        // TLS handshake metrics
        let tls_handshakes_total = IntCounterVec::new(
            Opts::new(
                "norc_transport_tls_handshakes_total",
                "Total number of TLS handshakes"
            ),
            &["tls_version", "role"],
        )?;
        
        let tls_handshake_failures_total = IntCounterVec::new(
            Opts::new(
                "norc_transport_tls_handshake_failures_total",
                "Total number of TLS handshake failures"
            ),
            &["reason", "role"],
        )?;
        
        let tls_handshake_duration = HistogramVec::new(
            HistogramOpts::new(
                "norc_transport_tls_handshake_duration_seconds",
                "Duration of TLS handshake operations"
            )
            .buckets(vec![0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0]),
            &["role"],
        )?;
        
        let mutual_tls_verifications_total = IntCounterVec::new(
            Opts::new(
                "norc_transport_mutual_tls_verifications_total",
                "Total number of mutual TLS client certificate verifications"
            ),
            &["result"],
        )?;
        
        // Register all metrics
        registry.register(Box::new(cert_validations_total.clone()))?;
        registry.register(Box::new(cert_validation_failures_total.clone()))?;
        registry.register(Box::new(cert_validation_duration.clone()))?;
        registry.register(Box::new(cert_chain_depth.clone()))?;
        registry.register(Box::new(cert_expiry_seconds.clone()))?;
        registry.register(Box::new(cert_expired_total.clone()))?;
        registry.register(Box::new(cert_expiring_soon_total.clone()))?;
        registry.register(Box::new(cert_pin_validations_total.clone()))?;
        registry.register(Box::new(cert_pin_failures_total.clone()))?;
        registry.register(Box::new(revocation_checks_total.clone()))?;
        registry.register(Box::new(revocation_check_failures_total.clone()))?;
        registry.register(Box::new(revocation_check_duration.clone()))?;
        registry.register(Box::new(revocation_status_revoked.clone()))?;
        registry.register(Box::new(revocation_status_unknown.clone()))?;
        registry.register(Box::new(ocsp_requests_total.clone()))?;
        registry.register(Box::new(ocsp_request_failures_total.clone()))?;
        registry.register(Box::new(ocsp_cache_hits_total.clone()))?;
        registry.register(Box::new(ocsp_cache_misses_total.clone()))?;
        registry.register(Box::new(ocsp_response_duration.clone()))?;
        registry.register(Box::new(crl_downloads_total.clone()))?;
        registry.register(Box::new(crl_download_failures_total.clone()))?;
        registry.register(Box::new(crl_cache_hits_total.clone()))?;
        registry.register(Box::new(crl_cache_misses_total.clone()))?;
        registry.register(Box::new(crl_download_duration.clone()))?;
        registry.register(Box::new(crl_download_bytes.clone()))?;
        registry.register(Box::new(cert_rotations_total.clone()))?;
        registry.register(Box::new(cert_rotation_failures_total.clone()))?;
        registry.register(Box::new(cert_rotation_duration.clone()))?;
        registry.register(Box::new(cert_reload_total.clone()))?;
        registry.register(Box::new(cert_reload_failures_total.clone()))?;
        registry.register(Box::new(cert_age_seconds.clone()))?;
        registry.register(Box::new(tls_handshakes_total.clone()))?;
        registry.register(Box::new(tls_handshake_failures_total.clone()))?;
        registry.register(Box::new(tls_handshake_duration.clone()))?;
        registry.register(Box::new(mutual_tls_verifications_total.clone()))?;
        
        Ok(SecurityMetrics {
            registry: Arc::new(registry),
            cert_validations_total,
            cert_validation_failures_total,
            cert_validation_duration,
            cert_chain_depth,
            cert_expiry_seconds,
            cert_expired_total,
            cert_expiring_soon_total,
            cert_pin_validations_total,
            cert_pin_failures_total,
            revocation_checks_total,
            revocation_check_failures_total,
            revocation_check_duration,
            revocation_status_revoked,
            revocation_status_unknown,
            ocsp_requests_total,
            ocsp_request_failures_total,
            ocsp_cache_hits_total,
            ocsp_cache_misses_total,
            ocsp_response_duration,
            crl_downloads_total,
            crl_download_failures_total,
            crl_cache_hits_total,
            crl_cache_misses_total,
            crl_download_duration,
            crl_download_bytes,
            cert_rotations_total,
            cert_rotation_failures_total,
            cert_rotation_duration,
            cert_reload_total,
            cert_reload_failures_total,
            cert_age_seconds,
            tls_handshakes_total,
            tls_handshake_failures_total,
            tls_handshake_duration,
            mutual_tls_verifications_total,
        })
    }
    
    /// Get the Prometheus registry for this metrics collector
    pub fn registry(&self) -> &Registry {
        &self.registry
    }
}

impl Default for SecurityMetrics {
    fn default() -> Self {
        Self::new().expect("Failed to create default SecurityMetrics")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_security_metrics_creation() {
        let metrics = SecurityMetrics::new();
        assert!(metrics.is_ok(), "Should create security metrics");
    }
    
    #[test]
    fn test_cert_validation_metrics() {
        let metrics = SecurityMetrics::new().unwrap();
        
        // Record certificate validation
        metrics.cert_validations_total
            .with_label_values(&["server", "test.org"])
            .inc();
        
        assert_eq!(
            metrics.cert_validations_total
                .with_label_values(&["server", "test.org"])
                .get(),
            1
        );
    }
    
    #[test]
    fn test_revocation_check_metrics() {
        let metrics = SecurityMetrics::new().unwrap();
        
        // Record OCSP check
        metrics.revocation_checks_total
            .with_label_values(&["ocsp", "test.org"])
            .inc();
        
        metrics.ocsp_requests_total.inc();
        metrics.ocsp_cache_hits_total.inc();
        
        assert_eq!(
            metrics.revocation_checks_total
                .with_label_values(&["ocsp", "test.org"])
                .get(),
            1
        );
        assert_eq!(metrics.ocsp_requests_total.get(), 1);
        assert_eq!(metrics.ocsp_cache_hits_total.get(), 1);
    }
    
    #[test]
    fn test_rotation_metrics() {
        let metrics = SecurityMetrics::new().unwrap();
        
        // Record rotation
        metrics.cert_rotations_total
            .with_label_values(&["manual", "server"])
            .inc();
        
        metrics.cert_reload_total.inc();
        
        assert_eq!(
            metrics.cert_rotations_total
                .with_label_values(&["manual", "server"])
                .get(),
            1
        );
        assert_eq!(metrics.cert_reload_total.get(), 1);
    }
    
    #[test]
    fn test_tls_handshake_metrics() {
        let metrics = SecurityMetrics::new().unwrap();
        
        // Record TLS handshake
        metrics.tls_handshakes_total
            .with_label_values(&["1.3", "server"])
            .inc();
        
        metrics.mutual_tls_verifications_total
            .with_label_values(&["success"])
            .inc();
        
        assert_eq!(
            metrics.tls_handshakes_total
                .with_label_values(&["1.3", "server"])
                .get(),
            1
        );
    }
    
    #[test]
    fn test_histogram_metrics() {
        let metrics = SecurityMetrics::new().unwrap();
        
        // Record validation duration
        metrics.cert_validation_duration
            .with_label_values(&["server"])
            .observe(0.015);
        
        // Record revocation check duration
        metrics.revocation_check_duration
            .with_label_values(&["ocsp"])
            .observe(0.125);
        
        // No panic means success
    }
    
    #[test]
    fn test_gauge_metrics() {
        let metrics = SecurityMetrics::new().unwrap();
        
        // Set certificate expiry
        metrics.cert_expiry_seconds
            .with_label_values(&["server", "test.org"])
            .set(2592000); // 30 days
        
        // Set certificate age
        metrics.cert_age_seconds
            .with_label_values(&["server"])
            .set(86400); // 1 day
        
        assert_eq!(
            metrics.cert_expiry_seconds
                .with_label_values(&["server", "test.org"])
                .get(),
            2592000
        );
    }
    
    #[test]
    fn test_failure_metrics() {
        let metrics = SecurityMetrics::new().unwrap();
        
        // Record validation failure
        metrics.cert_validation_failures_total
            .with_label_values(&["expired", "server"])
            .inc();
        
        // Record revocation check failure
        metrics.revocation_check_failures_total
            .with_label_values(&["ocsp", "timeout"])
            .inc();
        
        // Record rotation failure
        metrics.cert_rotation_failures_total
            .with_label_values(&["file_not_found", "server"])
            .inc();
        
        assert_eq!(
            metrics.cert_validation_failures_total
                .with_label_values(&["expired", "server"])
                .get(),
            1
        );
    }
}
