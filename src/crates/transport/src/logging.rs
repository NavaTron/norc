//! Structured logging utilities for security operations
//!
//! Provides structured logging helpers for certificate validation, revocation checking,
//! and certificate rotation events with rich context fields.
//!
//! Uses the `tracing` crate for structured logging with support for:
//! - Field-based structured data
//! - Log levels (ERROR, WARN, INFO, DEBUG, TRACE)
//! - Context propagation
//! - Integration with observability systems

use std::time::Duration;
use tracing::{debug, error, info, warn, Level};

/// Log a certificate validation event
pub fn log_cert_validation(
    cert_type: &str,
    organization_id: &str,
    subject: &str,
    issuer: &str,
    success: bool,
    duration_ms: u64,
) {
    if success {
        info!(
            target: "norc_transport::cert_validation",
            cert_type = %cert_type,
            organization_id = %organization_id,
            subject = %subject,
            issuer = %issuer,
            duration_ms = %duration_ms,
            "Certificate validation succeeded"
        );
    } else {
        error!(
            target: "norc_transport::cert_validation",
            cert_type = %cert_type,
            organization_id = %organization_id,
            subject = %subject,
            issuer = %issuer,
            duration_ms = %duration_ms,
            "Certificate validation failed"
        );
    }
}

/// Log a certificate validation failure with reason
pub fn log_cert_validation_failure(
    cert_type: &str,
    organization_id: &str,
    subject: &str,
    reason: &str,
    details: Option<&str>,
) {
    error!(
        target: "norc_transport::cert_validation",
        cert_type = %cert_type,
        organization_id = %organization_id,
        subject = %subject,
        reason = %reason,
        details = ?details,
        "Certificate validation failed"
    );
}

/// Log certificate expiration warning
pub fn log_cert_expiration_warning(
    cert_type: &str,
    organization_id: &str,
    subject: &str,
    days_until_expiry: i64,
) {
    let level = if days_until_expiry <= 7 {
        Level::ERROR
    } else if days_until_expiry <= 30 {
        Level::WARN
    } else {
        Level::INFO
    };
    
    match level {
        Level::ERROR => error!(
            target: "norc_transport::cert_expiration",
            cert_type = %cert_type,
            organization_id = %organization_id,
            subject = %subject,
            days_until_expiry = %days_until_expiry,
            "Certificate expiring soon - URGENT"
        ),
        Level::WARN => warn!(
            target: "norc_transport::cert_expiration",
            cert_type = %cert_type,
            organization_id = %organization_id,
            subject = %subject,
            days_until_expiry = %days_until_expiry,
            "Certificate expiring soon"
        ),
        _ => info!(
            target: "norc_transport::cert_expiration",
            cert_type = %cert_type,
            organization_id = %organization_id,
            subject = %subject,
            days_until_expiry = %days_until_expiry,
            "Certificate expiration status"
        ),
    }
}

/// Log certificate pinning validation
pub fn log_cert_pinning(
    pin_type: &str,
    organization_id: &str,
    fingerprint: &str,
    matched: bool,
    pin_count: usize,
) {
    if matched {
        info!(
            target: "norc_transport::cert_pinning",
            pin_type = %pin_type,
            organization_id = %organization_id,
            fingerprint = %fingerprint,
            pin_count = %pin_count,
            "Certificate pin validation succeeded"
        );
    } else {
        error!(
            target: "norc_transport::cert_pinning",
            pin_type = %pin_type,
            organization_id = %organization_id,
            fingerprint = %fingerprint,
            pin_count = %pin_count,
            "Certificate pin validation failed - SECURITY ALERT"
        );
    }
}

/// Log revocation check event
pub fn log_revocation_check(
    method: &str,
    organization_id: &str,
    subject: &str,
    status: &str,
    duration_ms: u64,
    cached: bool,
) {
    info!(
        target: "norc_transport::revocation",
        method = %method,
        organization_id = %organization_id,
        subject = %subject,
        status = %status,
        duration_ms = %duration_ms,
        cached = %cached,
        "Revocation check completed"
    );
}

/// Log revocation check failure
pub fn log_revocation_check_failure(
    method: &str,
    organization_id: &str,
    subject: &str,
    reason: &str,
    url: Option<&str>,
) {
    error!(
        target: "norc_transport::revocation",
        method = %method,
        organization_id = %organization_id,
        subject = %subject,
        reason = %reason,
        url = ?url,
        "Revocation check failed"
    );
}

/// Log revoked certificate detection
pub fn log_certificate_revoked(
    method: &str,
    organization_id: &str,
    subject: &str,
    revocation_date: Option<&str>,
) {
    error!(
        target: "norc_transport::revocation",
        method = %method,
        organization_id = %organization_id,
        subject = %subject,
        revocation_date = ?revocation_date,
        "Certificate has been REVOKED - SECURITY ALERT"
    );
}

/// Log OCSP request
pub fn log_ocsp_request(
    url: &str,
    organization_id: &str,
    cached: bool,
) {
    if cached {
        debug!(
            target: "norc_transport::ocsp",
            url = %url,
            organization_id = %organization_id,
            "OCSP response served from cache"
        );
    } else {
        info!(
            target: "norc_transport::ocsp",
            url = %url,
            organization_id = %organization_id,
            "Sending OCSP request"
        );
    }
}

/// Log OCSP response
pub fn log_ocsp_response(
    url: &str,
    organization_id: &str,
    status: &str,
    duration_ms: u64,
    response_size: usize,
) {
    info!(
        target: "norc_transport::ocsp",
        url = %url,
        organization_id = %organization_id,
        status = %status,
        duration_ms = %duration_ms,
        response_size_bytes = %response_size,
        "OCSP response received"
    );
}

/// Log CRL download
pub fn log_crl_download(
    url: &str,
    cached: bool,
    size_bytes: Option<usize>,
    duration: Option<Duration>,
) {
    if cached {
        debug!(
            target: "norc_transport::crl",
            url = %url,
            "CRL served from cache"
        );
    } else {
        info!(
            target: "norc_transport::crl",
            url = %url,
            size_bytes = ?size_bytes,
            duration_ms = ?duration.map(|d| d.as_millis()),
            "CRL downloaded"
        );
    }
}

/// Log CRL download failure
pub fn log_crl_download_failure(
    url: &str,
    reason: &str,
    status_code: Option<u16>,
) {
    error!(
        target: "norc_transport::crl",
        url = %url,
        reason = %reason,
        status_code = ?status_code,
        "CRL download failed"
    );
}

/// Log certificate rotation event
pub fn log_cert_rotation(
    trigger: &str,
    cert_type: &str,
    cert_path: &str,
    key_path: &str,
    success: bool,
    duration_ms: u64,
) {
    if success {
        info!(
            target: "norc_transport::rotation",
            trigger = %trigger,
            cert_type = %cert_type,
            cert_path = %cert_path,
            key_path = %key_path,
            duration_ms = %duration_ms,
            "Certificate rotation completed successfully"
        );
    } else {
        error!(
            target: "norc_transport::rotation",
            trigger = %trigger,
            cert_type = %cert_type,
            cert_path = %cert_path,
            key_path = %key_path,
            duration_ms = %duration_ms,
            "Certificate rotation failed"
        );
    }
}

/// Log certificate rotation failure with details
pub fn log_cert_rotation_failure(
    trigger: &str,
    cert_type: &str,
    cert_path: &str,
    reason: &str,
    error: &str,
) {
    error!(
        target: "norc_transport::rotation",
        trigger = %trigger,
        cert_type = %cert_type,
        cert_path = %cert_path,
        reason = %reason,
        error = %error,
        "Certificate rotation failed"
    );
}

/// Log certificate reload from disk
pub fn log_cert_reload(
    cert_path: &str,
    key_path: &str,
    chain_len: usize,
    age_seconds: u64,
) {
    info!(
        target: "norc_transport::rotation",
        cert_path = %cert_path,
        key_path = %key_path,
        chain_len = %chain_len,
        age_seconds = %age_seconds,
        "Certificate reloaded from disk"
    );
}

/// Log certificate file change detection
pub fn log_cert_file_change_detected(
    cert_path: &str,
    modified_time: &str,
) {
    info!(
        target: "norc_transport::rotation",
        cert_path = %cert_path,
        modified_time = %modified_time,
        "Certificate file change detected"
    );
}

/// Log TLS handshake event
pub fn log_tls_handshake(
    role: &str,
    tls_version: &str,
    cipher_suite: Option<&str>,
    peer_organization: Option<&str>,
    success: bool,
    duration_ms: u64,
) {
    if success {
        info!(
            target: "norc_transport::tls_handshake",
            role = %role,
            tls_version = %tls_version,
            cipher_suite = ?cipher_suite,
            peer_organization = ?peer_organization,
            duration_ms = %duration_ms,
            "TLS handshake completed"
        );
    } else {
        error!(
            target: "norc_transport::tls_handshake",
            role = %role,
            tls_version = ?tls_version,
            duration_ms = %duration_ms,
            "TLS handshake failed"
        );
    }
}

/// Log TLS handshake failure with details
pub fn log_tls_handshake_failure(
    role: &str,
    reason: &str,
    alert: Option<&str>,
    peer_address: Option<&str>,
) {
    error!(
        target: "norc_transport::tls_handshake",
        role = %role,
        reason = %reason,
        alert = ?alert,
        peer_address = ?peer_address,
        "TLS handshake failed"
    );
}

/// Log mutual TLS client verification
pub fn log_mutual_tls_verification(
    client_organization: &str,
    client_subject: &str,
    success: bool,
    reason: Option<&str>,
) {
    if success {
        info!(
            target: "norc_transport::mutual_tls",
            client_organization = %client_organization,
            client_subject = %client_subject,
            "Mutual TLS client verification succeeded"
        );
    } else {
        warn!(
            target: "norc_transport::mutual_tls",
            client_organization = %client_organization,
            client_subject = %client_subject,
            reason = ?reason,
            "Mutual TLS client verification failed"
        );
    }
}

/// Log security event for audit trail
pub fn log_security_event(
    event_type: &str,
    severity: &str,
    description: &str,
    organization_id: Option<&str>,
    source_ip: Option<&str>,
) {
    let level = match severity {
        "critical" | "high" => Level::ERROR,
        "medium" => Level::WARN,
        _ => Level::INFO,
    };
    
    match level {
        Level::ERROR => error!(
            target: "norc_transport::security_event",
            event_type = %event_type,
            severity = %severity,
            description = %description,
            organization_id = ?organization_id,
            source_ip = ?source_ip,
            "Security event - requires attention"
        ),
        Level::WARN => warn!(
            target: "norc_transport::security_event",
            event_type = %event_type,
            severity = %severity,
            description = %description,
            organization_id = ?organization_id,
            source_ip = ?source_ip,
            "Security event"
        ),
        _ => info!(
            target: "norc_transport::security_event",
            event_type = %event_type,
            severity = %severity,
            description = %description,
            organization_id = ?organization_id,
            source_ip = ?source_ip,
            "Security event"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_log_cert_validation() {
        // Just ensure these don't panic
        log_cert_validation("server", "test.org", "CN=test", "CN=CA", true, 15);
        log_cert_validation("client", "test.org", "CN=client", "CN=CA", false, 25);
    }
    
    #[test]
    fn test_log_cert_validation_failure() {
        log_cert_validation_failure(
            "server",
            "test.org",
            "CN=test",
            "expired",
            Some("Certificate expired 5 days ago")
        );
    }
    
    #[test]
    fn test_log_cert_expiration_warning() {
        log_cert_expiration_warning("server", "test.org", "CN=test", 90);
        log_cert_expiration_warning("server", "test.org", "CN=test", 25);
        log_cert_expiration_warning("server", "test.org", "CN=test", 5);
    }
    
    #[test]
    fn test_log_cert_pinning() {
        log_cert_pinning("sha256", "test.org", "AA:BB:CC", true, 3);
        log_cert_pinning("sha256", "test.org", "DD:EE:FF", false, 3);
    }
    
    #[test]
    fn test_log_revocation_check() {
        log_revocation_check("ocsp", "test.org", "CN=test", "valid", 125, true);
        log_revocation_check("crl", "test.org", "CN=test", "valid", 450, false);
    }
    
    #[test]
    fn test_log_revocation_check_failure() {
        log_revocation_check_failure(
            "ocsp",
            "test.org",
            "CN=test",
            "timeout",
            Some("http://ocsp.example.com")
        );
    }
    
    #[test]
    fn test_log_certificate_revoked() {
        log_certificate_revoked("ocsp", "test.org", "CN=test", Some("2025-09-01"));
    }
    
    #[test]
    fn test_log_ocsp_request() {
        log_ocsp_request("http://ocsp.example.com", "test.org", false);
        log_ocsp_request("http://ocsp.example.com", "test.org", true);
    }
    
    #[test]
    fn test_log_ocsp_response() {
        log_ocsp_response("http://ocsp.example.com", "test.org", "good", 150, 1024);
    }
    
    #[test]
    fn test_log_crl_download() {
        log_crl_download("http://crl.example.com/ca.crl", false, Some(50000), Some(Duration::from_millis(500)));
        log_crl_download("http://crl.example.com/ca.crl", true, None, None);
    }
    
    #[test]
    fn test_log_crl_download_failure() {
        log_crl_download_failure("http://crl.example.com/ca.crl", "404 not found", Some(404));
    }
    
    #[test]
    fn test_log_cert_rotation() {
        log_cert_rotation("manual", "server", "/etc/certs/server.pem", "/etc/certs/server.key", true, 85);
        log_cert_rotation("expiring", "server", "/etc/certs/server.pem", "/etc/certs/server.key", false, 120);
    }
    
    #[test]
    fn test_log_cert_rotation_failure() {
        log_cert_rotation_failure(
            "auto",
            "server",
            "/etc/certs/server.pem",
            "file_not_found",
            "No such file or directory"
        );
    }
    
    #[test]
    fn test_log_cert_reload() {
        log_cert_reload("/etc/certs/server.pem", "/etc/certs/server.key", 2, 86400);
    }
    
    #[test]
    fn test_log_cert_file_change_detected() {
        log_cert_file_change_detected("/etc/certs/server.pem", "2025-10-02T10:30:00Z");
    }
    
    #[test]
    fn test_log_tls_handshake() {
        log_tls_handshake("server", "1.3", Some("TLS_AES_256_GCM_SHA384"), Some("client.org"), true, 45);
        log_tls_handshake("client", "1.3", None, None, false, 30);
    }
    
    #[test]
    fn test_log_tls_handshake_failure() {
        log_tls_handshake_failure("server", "certificate_unknown", Some("Alert(48)"), Some("192.168.1.100"));
    }
    
    #[test]
    fn test_log_mutual_tls_verification() {
        log_mutual_tls_verification("client.org", "CN=client", true, None);
        log_mutual_tls_verification("bad.org", "CN=attacker", false, Some("untrusted certificate"));
    }
    
    #[test]
    fn test_log_security_event() {
        log_security_event("cert_pinning_failure", "critical", "Pin mismatch detected", Some("test.org"), Some("192.168.1.100"));
        log_security_event("cert_expired", "high", "Certificate expired", Some("test.org"), None);
        log_security_event("rotation_success", "low", "Certificate rotated", Some("test.org"), None);
    }
}
