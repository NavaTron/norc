//! Health Check Infrastructure
//!
//! Provides health check endpoints for monitoring certificate and security
//! service status. Includes liveness and readiness probes for orchestration
//! platforms like Kubernetes.

use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// Overall health status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    /// Service is healthy and operational
    Healthy,
    /// Service is degraded but operational
    Degraded,
    /// Service is unhealthy and may not function correctly
    Unhealthy,
}

impl std::fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HealthStatus::Healthy => write!(f, "healthy"),
            HealthStatus::Degraded => write!(f, "degraded"),
            HealthStatus::Unhealthy => write!(f, "unhealthy"),
        }
    }
}

/// Certificate health information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateHealth {
    /// Overall certificate health status
    pub status: HealthStatus,
    /// Certificate type (server, client, ca)
    pub cert_type: String,
    /// Certificate subject DN
    pub subject: String,
    /// Certificate serial number
    pub serial_number: String,
    /// Days until expiration (negative if expired)
    pub days_until_expiry: i64,
    /// Whether certificate is expired
    pub is_expired: bool,
    /// Whether certificate is expiring soon (within warning threshold)
    pub is_expiring_soon: bool,
    /// Whether certificate has been revoked
    pub is_revoked: bool,
    /// Last revocation check time
    pub last_revocation_check: Option<SystemTime>,
    /// Certificate fingerprint (SHA-256)
    pub fingerprint: Option<String>,
    /// Additional issues detected
    pub issues: Vec<String>,
}

impl CertificateHealth {
    /// Create a new certificate health check
    pub fn new(
        cert_type: impl Into<String>,
        subject: impl Into<String>,
        serial_number: impl Into<String>,
    ) -> Self {
        Self {
            status: HealthStatus::Healthy,
            cert_type: cert_type.into(),
            subject: subject.into(),
            serial_number: serial_number.into(),
            days_until_expiry: 0,
            is_expired: false,
            is_expiring_soon: false,
            is_revoked: false,
            last_revocation_check: None,
            fingerprint: None,
            issues: Vec::new(),
        }
    }

    /// Check certificate expiration and update health status
    pub fn check_expiration(&mut self, not_after: SystemTime, warning_days: u64) {
        let now = SystemTime::now();
        
        if let Ok(duration_until_expiry) = not_after.duration_since(now) {
            self.days_until_expiry = (duration_until_expiry.as_secs() / 86400) as i64;
            self.is_expired = false;
            
            if duration_until_expiry.as_secs() < warning_days * 86400 {
                self.is_expiring_soon = true;
                self.status = HealthStatus::Degraded;
                self.issues.push(format!(
                    "Certificate expires in {} days",
                    self.days_until_expiry
                ));
            }
        } else if let Ok(duration_since_expiry) = now.duration_since(not_after) {
            self.days_until_expiry = -((duration_since_expiry.as_secs() / 86400) as i64);
            self.is_expired = true;
            self.status = HealthStatus::Unhealthy;
            self.issues.push(format!(
                "Certificate expired {} days ago",
                -self.days_until_expiry
            ));
        }
    }

    /// Mark certificate as revoked
    pub fn mark_revoked(&mut self, reason: impl Into<String>) {
        self.is_revoked = true;
        self.status = HealthStatus::Unhealthy;
        self.issues.push(format!("Certificate revoked: {}", reason.into()));
    }

    /// Set last revocation check time
    pub fn set_last_revocation_check(&mut self, time: SystemTime) {
        self.last_revocation_check = Some(time);
    }

    /// Set certificate fingerprint
    pub fn set_fingerprint(&mut self, fingerprint: impl Into<String>) {
        self.fingerprint = Some(fingerprint.into());
    }

    /// Add a custom issue
    pub fn add_issue(&mut self, issue: impl Into<String>) {
        self.issues.push(issue.into());
        if self.status == HealthStatus::Healthy {
            self.status = HealthStatus::Degraded;
        }
    }
}

/// Rotation manager health information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationManagerHealth {
    /// Overall rotation manager status
    pub status: HealthStatus,
    /// Whether rotation manager is enabled
    pub enabled: bool,
    /// Whether auto-rotation is active
    pub auto_rotation_enabled: bool,
    /// Number of active certificate watchers
    pub active_watchers: usize,
    /// Number of registered rotation subscribers
    pub subscriber_count: usize,
    /// Last successful rotation time
    pub last_rotation: Option<SystemTime>,
    /// Last rotation attempt time
    pub last_rotation_attempt: Option<SystemTime>,
    /// Number of failed rotation attempts
    pub failed_rotations: u64,
    /// Current certificate expiration time
    pub current_cert_expiry: Option<SystemTime>,
    /// Days until current certificate expires
    pub days_until_expiry: Option<i64>,
    /// Issues detected with rotation manager
    pub issues: Vec<String>,
}

impl RotationManagerHealth {
    /// Create a new rotation manager health check
    pub fn new() -> Self {
        Self {
            status: HealthStatus::Healthy,
            enabled: false,
            auto_rotation_enabled: false,
            active_watchers: 0,
            subscriber_count: 0,
            last_rotation: None,
            last_rotation_attempt: None,
            failed_rotations: 0,
            current_cert_expiry: None,
            days_until_expiry: None,
            issues: Vec::new(),
        }
    }

    /// Set rotation manager enabled status
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Set auto-rotation enabled status
    pub fn set_auto_rotation(&mut self, enabled: bool) {
        self.auto_rotation_enabled = enabled;
    }

    /// Set active watcher count
    pub fn set_active_watchers(&mut self, count: usize) {
        self.active_watchers = count;
        
        if self.enabled && count == 0 {
            self.status = HealthStatus::Degraded;
            self.issues.push("No active certificate watchers".to_string());
        }
    }

    /// Set subscriber count
    pub fn set_subscriber_count(&mut self, count: usize) {
        self.subscriber_count = count;
    }

    /// Record successful rotation
    pub fn record_rotation(&mut self, time: SystemTime) {
        self.last_rotation = Some(time);
        self.last_rotation_attempt = Some(time);
        self.failed_rotations = 0;
    }

    /// Record failed rotation attempt
    pub fn record_failed_rotation(&mut self, time: SystemTime, error: impl Into<String>) {
        self.last_rotation_attempt = Some(time);
        self.failed_rotations += 1;
        
        if self.failed_rotations >= 3 {
            self.status = HealthStatus::Unhealthy;
            self.issues.push(format!(
                "{} consecutive rotation failures: {}",
                self.failed_rotations,
                error.into()
            ));
        } else {
            self.status = HealthStatus::Degraded;
            self.issues.push(format!("Rotation failed: {}", error.into()));
        }
    }

    /// Set current certificate expiration
    pub fn set_cert_expiry(&mut self, expiry: SystemTime, warning_days: u64) {
        self.current_cert_expiry = Some(expiry);
        
        let now = SystemTime::now();
        if let Ok(duration_until_expiry) = expiry.duration_since(now) {
            let days = (duration_until_expiry.as_secs() / 86400) as i64;
            self.days_until_expiry = Some(days);
            
            if duration_until_expiry.as_secs() < warning_days * 86400 {
                self.status = HealthStatus::Degraded;
                self.issues.push(format!(
                    "Certificate expires in {} days, rotation may be needed",
                    days
                ));
            }
        }
    }

    /// Add a custom issue
    pub fn add_issue(&mut self, issue: impl Into<String>) {
        self.issues.push(issue.into());
        if self.status == HealthStatus::Healthy {
            self.status = HealthStatus::Degraded;
        }
    }
}

impl Default for RotationManagerHealth {
    fn default() -> Self {
        Self::new()
    }
}

/// Revocation service health information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationServiceHealth {
    /// Overall revocation service status
    pub status: HealthStatus,
    /// Whether revocation checking is enabled
    pub enabled: bool,
    /// Whether OCSP checking is enabled
    pub ocsp_enabled: bool,
    /// Whether CRL checking is enabled
    pub crl_enabled: bool,
    /// OCSP cache hit rate (0.0 - 1.0)
    pub ocsp_cache_hit_rate: Option<f64>,
    /// CRL cache hit rate (0.0 - 1.0)
    pub crl_cache_hit_rate: Option<f64>,
    /// Last successful OCSP check
    pub last_ocsp_check: Option<SystemTime>,
    /// Last successful CRL check
    pub last_crl_check: Option<SystemTime>,
    /// Number of failed OCSP checks
    pub failed_ocsp_checks: u64,
    /// Number of failed CRL checks
    pub failed_crl_checks: u64,
    /// OCSP responder availability (0.0 - 1.0)
    pub ocsp_availability: Option<f64>,
    /// CRL download availability (0.0 - 1.0)
    pub crl_availability: Option<f64>,
    /// Issues detected with revocation service
    pub issues: Vec<String>,
}

impl RevocationServiceHealth {
    /// Create a new revocation service health check
    pub fn new() -> Self {
        Self {
            status: HealthStatus::Healthy,
            enabled: false,
            ocsp_enabled: false,
            crl_enabled: false,
            ocsp_cache_hit_rate: None,
            crl_cache_hit_rate: None,
            last_ocsp_check: None,
            last_crl_check: None,
            failed_ocsp_checks: 0,
            failed_crl_checks: 0,
            ocsp_availability: None,
            crl_availability: None,
            issues: Vec::new(),
        }
    }

    /// Set revocation checking enabled status
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Set OCSP enabled status
    pub fn set_ocsp_enabled(&mut self, enabled: bool) {
        self.ocsp_enabled = enabled;
    }

    /// Set CRL enabled status
    pub fn set_crl_enabled(&mut self, enabled: bool) {
        self.crl_enabled = enabled;
    }

    /// Set OCSP cache hit rate
    pub fn set_ocsp_cache_hit_rate(&mut self, rate: f64) {
        self.ocsp_cache_hit_rate = Some(rate.clamp(0.0, 1.0));
    }

    /// Set CRL cache hit rate
    pub fn set_crl_cache_hit_rate(&mut self, rate: f64) {
        self.crl_cache_hit_rate = Some(rate.clamp(0.0, 1.0));
    }

    /// Record successful OCSP check
    pub fn record_ocsp_check(&mut self, time: SystemTime) {
        self.last_ocsp_check = Some(time);
        self.failed_ocsp_checks = 0;
    }

    /// Record failed OCSP check
    pub fn record_failed_ocsp_check(&mut self, error: impl Into<String>) {
        self.failed_ocsp_checks += 1;
        
        if self.failed_ocsp_checks >= 5 {
            self.status = HealthStatus::Unhealthy;
            self.issues.push(format!(
                "{} consecutive OCSP check failures: {}",
                self.failed_ocsp_checks,
                error.into()
            ));
        } else if self.failed_ocsp_checks >= 3 {
            self.status = HealthStatus::Degraded;
            self.issues.push(format!("OCSP check issues: {}", error.into()));
        }
    }

    /// Record successful CRL check
    pub fn record_crl_check(&mut self, time: SystemTime) {
        self.last_crl_check = Some(time);
        self.failed_crl_checks = 0;
    }

    /// Record failed CRL check
    pub fn record_failed_crl_check(&mut self, error: impl Into<String>) {
        self.failed_crl_checks += 1;
        
        if self.failed_crl_checks >= 5 {
            self.status = HealthStatus::Unhealthy;
            self.issues.push(format!(
                "{} consecutive CRL check failures: {}",
                self.failed_crl_checks,
                error.into()
            ));
        } else if self.failed_crl_checks >= 3 {
            self.status = HealthStatus::Degraded;
            self.issues.push(format!("CRL check issues: {}", error.into()));
        }
    }

    /// Set OCSP responder availability
    pub fn set_ocsp_availability(&mut self, availability: f64) {
        let avail = availability.clamp(0.0, 1.0);
        self.ocsp_availability = Some(avail);
        
        if avail < 0.5 {
            self.status = HealthStatus::Unhealthy;
            self.issues.push(format!(
                "OCSP responder availability low: {:.1}%",
                avail * 100.0
            ));
        } else if avail < 0.8 {
            self.status = HealthStatus::Degraded;
            self.issues.push(format!(
                "OCSP responder availability degraded: {:.1}%",
                avail * 100.0
            ));
        }
    }

    /// Set CRL download availability
    pub fn set_crl_availability(&mut self, availability: f64) {
        let avail = availability.clamp(0.0, 1.0);
        self.crl_availability = Some(avail);
        
        if avail < 0.5 {
            self.status = HealthStatus::Unhealthy;
            self.issues.push(format!(
                "CRL download availability low: {:.1}%",
                avail * 100.0
            ));
        } else if avail < 0.8 {
            self.status = HealthStatus::Degraded;
            self.issues.push(format!(
                "CRL download availability degraded: {:.1}%",
                avail * 100.0
            ));
        }
    }

    /// Add a custom issue
    pub fn add_issue(&mut self, issue: impl Into<String>) {
        self.issues.push(issue.into());
        if self.status == HealthStatus::Healthy {
            self.status = HealthStatus::Degraded;
        }
    }
}

impl Default for RevocationServiceHealth {
    fn default() -> Self {
        Self::new()
    }
}

/// Overall system health report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemHealthReport {
    /// Overall system health status
    pub status: HealthStatus,
    /// Timestamp when health check was performed
    pub timestamp: SystemTime,
    /// Server certificates health
    pub server_certificates: Vec<CertificateHealth>,
    /// Client certificates health
    pub client_certificates: Vec<CertificateHealth>,
    /// CA certificates health
    pub ca_certificates: Vec<CertificateHealth>,
    /// Rotation manager health
    pub rotation_manager: RotationManagerHealth,
    /// Revocation service health
    pub revocation_service: RevocationServiceHealth,
    /// Overall system issues
    pub issues: Vec<String>,
}

impl SystemHealthReport {
    /// Create a new system health report
    pub fn new() -> Self {
        Self {
            status: HealthStatus::Healthy,
            timestamp: SystemTime::now(),
            server_certificates: Vec::new(),
            client_certificates: Vec::new(),
            ca_certificates: Vec::new(),
            rotation_manager: RotationManagerHealth::new(),
            revocation_service: RevocationServiceHealth::new(),
            issues: Vec::new(),
        }
    }

    /// Add a server certificate health check
    pub fn add_server_cert(&mut self, cert: CertificateHealth) {
        if cert.status != HealthStatus::Healthy {
            self.update_overall_status(cert.status);
        }
        self.server_certificates.push(cert);
    }

    /// Add a client certificate health check
    pub fn add_client_cert(&mut self, cert: CertificateHealth) {
        if cert.status != HealthStatus::Healthy {
            self.update_overall_status(cert.status);
        }
        self.client_certificates.push(cert);
    }

    /// Add a CA certificate health check
    pub fn add_ca_cert(&mut self, cert: CertificateHealth) {
        if cert.status != HealthStatus::Healthy {
            self.update_overall_status(cert.status);
        }
        self.ca_certificates.push(cert);
    }

    /// Set rotation manager health
    pub fn set_rotation_manager(&mut self, health: RotationManagerHealth) {
        if health.status != HealthStatus::Healthy {
            self.update_overall_status(health.status);
        }
        self.rotation_manager = health;
    }

    /// Set revocation service health
    pub fn set_revocation_service(&mut self, health: RevocationServiceHealth) {
        if health.status != HealthStatus::Healthy {
            self.update_overall_status(health.status);
        }
        self.revocation_service = health;
    }

    /// Add a system-level issue
    pub fn add_issue(&mut self, issue: impl Into<String>) {
        self.issues.push(issue.into());
        self.update_overall_status(HealthStatus::Degraded);
    }

    /// Update overall system status based on component status
    fn update_overall_status(&mut self, component_status: HealthStatus) {
        match (self.status, component_status) {
            (HealthStatus::Healthy, new_status) => self.status = new_status,
            (HealthStatus::Degraded, HealthStatus::Unhealthy) => {
                self.status = HealthStatus::Unhealthy
            }
            _ => {}
        }
    }

    /// Check if system is ready to serve traffic (readiness probe)
    pub fn is_ready(&self) -> bool {
        matches!(
            self.status,
            HealthStatus::Healthy | HealthStatus::Degraded
        )
    }

    /// Check if system is alive (liveness probe)
    pub fn is_alive(&self) -> bool {
        // Even unhealthy systems can be "alive" - they just need attention
        // Only return false if we detect a complete failure
        true
    }

    /// Get summary statistics
    pub fn summary(&self) -> HealthSummary {
        let total_certs = self.server_certificates.len()
            + self.client_certificates.len()
            + self.ca_certificates.len();

        let healthy_certs = self
            .server_certificates
            .iter()
            .chain(&self.client_certificates)
            .chain(&self.ca_certificates)
            .filter(|c| c.status == HealthStatus::Healthy)
            .count();

        let expired_certs = self
            .server_certificates
            .iter()
            .chain(&self.client_certificates)
            .chain(&self.ca_certificates)
            .filter(|c| c.is_expired)
            .count();

        let expiring_soon = self
            .server_certificates
            .iter()
            .chain(&self.client_certificates)
            .chain(&self.ca_certificates)
            .filter(|c| c.is_expiring_soon)
            .count();

        HealthSummary {
            status: self.status,
            total_certificates: total_certs,
            healthy_certificates: healthy_certs,
            expired_certificates: expired_certs,
            expiring_soon_certificates: expiring_soon,
            rotation_enabled: self.rotation_manager.enabled,
            revocation_enabled: self.revocation_service.enabled,
            total_issues: self.issues.len()
                + self.server_certificates.iter().map(|c| c.issues.len()).sum::<usize>()
                + self.client_certificates.iter().map(|c| c.issues.len()).sum::<usize>()
                + self.ca_certificates.iter().map(|c| c.issues.len()).sum::<usize>()
                + self.rotation_manager.issues.len()
                + self.revocation_service.issues.len(),
        }
    }
}

impl Default for SystemHealthReport {
    fn default() -> Self {
        Self::new()
    }
}

/// Health check summary statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthSummary {
    /// Overall status
    pub status: HealthStatus,
    /// Total number of certificates monitored
    pub total_certificates: usize,
    /// Number of healthy certificates
    pub healthy_certificates: usize,
    /// Number of expired certificates
    pub expired_certificates: usize,
    /// Number of certificates expiring soon
    pub expiring_soon_certificates: usize,
    /// Whether certificate rotation is enabled
    pub rotation_enabled: bool,
    /// Whether revocation checking is enabled
    pub revocation_enabled: bool,
    /// Total number of issues detected
    pub total_issues: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_health_status_display() {
        assert_eq!(HealthStatus::Healthy.to_string(), "healthy");
        assert_eq!(HealthStatus::Degraded.to_string(), "degraded");
        assert_eq!(HealthStatus::Unhealthy.to_string(), "unhealthy");
    }

    #[test]
    fn test_certificate_health_expiration() {
        let mut health = CertificateHealth::new("server", "CN=test.com", "123456");
        
        // Test expiring soon (5 days)
        let expiry = SystemTime::now() + Duration::from_secs(5 * 86400);
        health.check_expiration(expiry, 30);
        
        assert_eq!(health.status, HealthStatus::Degraded);
        assert!(health.is_expiring_soon);
        assert!(!health.is_expired);
        // Allow for minor timing differences in test execution
        assert!(health.days_until_expiry >= 4 && health.days_until_expiry <= 5);
        assert!(!health.issues.is_empty());
    }

    #[test]
    fn test_certificate_health_expired() {
        let mut health = CertificateHealth::new("server", "CN=test.com", "123456");
        
        // Test expired (10 days ago)
        let expiry = SystemTime::now() - Duration::from_secs(10 * 86400);
        health.check_expiration(expiry, 30);
        
        assert_eq!(health.status, HealthStatus::Unhealthy);
        assert!(health.is_expired);
        assert_eq!(health.days_until_expiry, -10);
        assert!(!health.issues.is_empty());
    }

    #[test]
    fn test_certificate_health_revoked() {
        let mut health = CertificateHealth::new("server", "CN=test.com", "123456");
        
        health.mark_revoked("Key compromise");
        
        assert_eq!(health.status, HealthStatus::Unhealthy);
        assert!(health.is_revoked);
        assert!(!health.issues.is_empty());
    }

    #[test]
    fn test_rotation_manager_health_failures() {
        let mut health = RotationManagerHealth::new();
        health.set_enabled(true);
        
        // First failure - degraded
        health.record_failed_rotation(SystemTime::now(), "Connection timeout");
        assert_eq!(health.status, HealthStatus::Degraded);
        assert_eq!(health.failed_rotations, 1);
        
        // Three failures - unhealthy
        health.record_failed_rotation(SystemTime::now(), "Connection timeout");
        health.record_failed_rotation(SystemTime::now(), "Connection timeout");
        assert_eq!(health.status, HealthStatus::Unhealthy);
        assert_eq!(health.failed_rotations, 3);
        
        // Successful rotation resets counter
        health.record_rotation(SystemTime::now());
        assert_eq!(health.failed_rotations, 0);
    }

    #[test]
    fn test_rotation_manager_health_no_watchers() {
        let mut health = RotationManagerHealth::new();
        health.set_enabled(true);
        health.set_active_watchers(0);
        
        assert_eq!(health.status, HealthStatus::Degraded);
        assert!(!health.issues.is_empty());
    }

    #[test]
    fn test_revocation_service_health_ocsp_failures() {
        let mut health = RevocationServiceHealth::new();
        health.set_enabled(true);
        health.set_ocsp_enabled(true);
        
        // 3 failures - degraded
        health.record_failed_ocsp_check("Timeout");
        health.record_failed_ocsp_check("Timeout");
        health.record_failed_ocsp_check("Timeout");
        assert_eq!(health.status, HealthStatus::Degraded);
        
        // 5 failures - unhealthy
        health.record_failed_ocsp_check("Timeout");
        health.record_failed_ocsp_check("Timeout");
        assert_eq!(health.status, HealthStatus::Unhealthy);
        assert_eq!(health.failed_ocsp_checks, 5);
    }

    #[test]
    fn test_revocation_service_health_availability() {
        let mut health = RevocationServiceHealth::new();
        
        // Good availability
        health.set_ocsp_availability(0.95);
        assert_eq!(health.status, HealthStatus::Healthy);
        
        // Degraded availability
        health = RevocationServiceHealth::new();
        health.set_ocsp_availability(0.7);
        assert_eq!(health.status, HealthStatus::Degraded);
        
        // Low availability
        health = RevocationServiceHealth::new();
        health.set_ocsp_availability(0.4);
        assert_eq!(health.status, HealthStatus::Unhealthy);
    }

    #[test]
    fn test_system_health_report_aggregation() {
        let mut report = SystemHealthReport::new();
        
        // Add healthy certificate
        let healthy_cert = CertificateHealth::new("server", "CN=healthy.com", "111");
        report.add_server_cert(healthy_cert);
        assert_eq!(report.status, HealthStatus::Healthy);
        
        // Add degraded certificate
        let mut degraded_cert = CertificateHealth::new("server", "CN=expiring.com", "222");
        let expiry = SystemTime::now() + Duration::from_secs(5 * 86400);
        degraded_cert.check_expiration(expiry, 30);
        report.add_server_cert(degraded_cert);
        assert_eq!(report.status, HealthStatus::Degraded);
        
        // Add unhealthy certificate
        let mut unhealthy_cert = CertificateHealth::new("server", "CN=expired.com", "333");
        let expiry = SystemTime::now() - Duration::from_secs(10 * 86400);
        unhealthy_cert.check_expiration(expiry, 30);
        report.add_server_cert(unhealthy_cert);
        assert_eq!(report.status, HealthStatus::Unhealthy);
    }

    #[test]
    fn test_system_health_report_readiness() {
        let mut report = SystemHealthReport::new();
        
        // Healthy and degraded systems are ready
        assert!(report.is_ready());
        
        report.status = HealthStatus::Degraded;
        assert!(report.is_ready());
        
        report.status = HealthStatus::Unhealthy;
        assert!(!report.is_ready());
    }

    #[test]
    fn test_system_health_report_liveness() {
        let report = SystemHealthReport::new();
        
        // System is always considered "alive" unless completely failed
        assert!(report.is_alive());
    }

    #[test]
    fn test_health_summary() {
        let mut report = SystemHealthReport::new();
        
        // Add various certificates
        let healthy_cert = CertificateHealth::new("server", "CN=healthy.com", "111");
        report.add_server_cert(healthy_cert);
        
        let mut expiring_cert = CertificateHealth::new("server", "CN=expiring.com", "222");
        let expiry = SystemTime::now() + Duration::from_secs(5 * 86400);
        expiring_cert.check_expiration(expiry, 30);
        report.add_server_cert(expiring_cert);
        
        let mut expired_cert = CertificateHealth::new("client", "CN=expired.com", "333");
        let expiry = SystemTime::now() - Duration::from_secs(10 * 86400);
        expired_cert.check_expiration(expiry, 30);
        report.add_client_cert(expired_cert);
        
        let summary = report.summary();
        
        assert_eq!(summary.total_certificates, 3);
        assert_eq!(summary.healthy_certificates, 1);
        assert_eq!(summary.expired_certificates, 1);
        assert_eq!(summary.expiring_soon_certificates, 1);
        assert!(summary.total_issues > 0);
    }
}
