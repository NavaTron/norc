//! Distributed tracing utilities for security operations
//!
//! Provides tracing span helpers for certificate validation, revocation checking,
//! and certificate rotation with proper parent-child span relationships.
//!
//! Uses the `tracing` crate with OpenTelemetry-compatible spans for:
//! - Request flow tracking
//! - Performance analysis
//! - Distributed system correlation
//! - Debugging and troubleshooting

use tracing::{span, Level, Span};

/// Create a span for certificate validation
///
/// # Example
/// ```
/// use norc_transport::tracing_spans::*;
/// 
/// let span = span_cert_validation("server", "example.org", "CN=server.example.org");
/// let _guard = span.enter();
/// // ... perform validation ...
/// ```
pub fn span_cert_validation(cert_type: &str, organization_id: &str, subject: &str) -> Span {
    span!(
        Level::INFO,
        "cert_validation",
        cert_type = %cert_type,
        organization_id = %organization_id,
        subject = %subject,
        otel.kind = "internal"
    )
}

/// Create a span for certificate chain validation
pub fn span_cert_chain_validation(organization_id: &str, chain_length: usize) -> Span {
    span!(
        Level::INFO,
        "cert_chain_validation",
        organization_id = %organization_id,
        chain_length = %chain_length,
        otel.kind = "internal"
    )
}

/// Create a span for certificate expiration check
pub fn span_cert_expiration_check(cert_type: &str, organization_id: &str) -> Span {
    span!(
        Level::DEBUG,
        "cert_expiration_check",
        cert_type = %cert_type,
        organization_id = %organization_id,
        otel.kind = "internal"
    )
}

/// Create a span for certificate pinning validation
pub fn span_cert_pinning(pin_type: &str, organization_id: &str, pin_count: usize) -> Span {
    span!(
        Level::INFO,
        "cert_pinning",
        pin_type = %pin_type,
        organization_id = %organization_id,
        pin_count = %pin_count,
        otel.kind = "internal"
    )
}

/// Create a span for revocation checking (parent span)
pub fn span_revocation_check(organization_id: &str, subject: &str) -> Span {
    span!(
        Level::INFO,
        "revocation_check",
        organization_id = %organization_id,
        subject = %subject,
        otel.kind = "internal"
    )
}

/// Create a span for OCSP check (child of revocation_check)
pub fn span_ocsp_check(url: &str, organization_id: &str) -> Span {
    span!(
        Level::INFO,
        "ocsp_check",
        url = %url,
        organization_id = %organization_id,
        otel.kind = "client",
        otel.name = "OCSP Request"
    )
}

/// Create a span for OCSP request (network operation)
pub fn span_ocsp_request(url: &str) -> Span {
    span!(
        Level::DEBUG,
        "ocsp_request",
        url = %url,
        otel.kind = "client",
        http.method = "POST",
        http.url = %url
    )
}

/// Create a span for OCSP cache lookup
pub fn span_ocsp_cache_lookup(url: &str) -> Span {
    span!(
        Level::DEBUG,
        "ocsp_cache_lookup",
        url = %url,
        otel.kind = "internal"
    )
}

/// Create a span for CRL check (child of revocation_check)
pub fn span_crl_check(url: &str, organization_id: &str) -> Span {
    span!(
        Level::INFO,
        "crl_check",
        url = %url,
        organization_id = %organization_id,
        otel.kind = "client",
        otel.name = "CRL Download"
    )
}

/// Create a span for CRL download (network operation)
pub fn span_crl_download(url: &str) -> Span {
    span!(
        Level::DEBUG,
        "crl_download",
        url = %url,
        otel.kind = "client",
        http.method = "GET",
        http.url = %url
    )
}

/// Create a span for CRL cache lookup
pub fn span_crl_cache_lookup(url: &str) -> Span {
    span!(
        Level::DEBUG,
        "crl_cache_lookup",
        url = %url,
        otel.kind = "internal"
    )
}

/// Create a span for CRL parsing
pub fn span_crl_parse(size_bytes: usize) -> Span {
    span!(
        Level::DEBUG,
        "crl_parse",
        size_bytes = %size_bytes,
        otel.kind = "internal"
    )
}

/// Create a span for certificate rotation (parent span)
pub fn span_cert_rotation(trigger: &str, cert_type: &str) -> Span {
    span!(
        Level::INFO,
        "cert_rotation",
        trigger = %trigger,
        cert_type = %cert_type,
        otel.kind = "internal"
    )
}

/// Create a span for certificate reload from disk
pub fn span_cert_reload(cert_path: &str, key_path: &str) -> Span {
    span!(
        Level::INFO,
        "cert_reload",
        cert_path = %cert_path,
        key_path = %key_path,
        otel.kind = "internal"
    )
}

/// Create a span for certificate file load
pub fn span_cert_file_load(file_path: &str) -> Span {
    span!(
        Level::DEBUG,
        "cert_file_load",
        file_path = %file_path,
        otel.kind = "internal"
    )
}

/// Create a span for certificate parse
pub fn span_cert_parse(file_path: &str) -> Span {
    span!(
        Level::DEBUG,
        "cert_parse",
        file_path = %file_path,
        otel.kind = "internal"
    )
}

/// Create a span for rotation notification
pub fn span_rotation_notify(subscriber_count: usize) -> Span {
    span!(
        Level::DEBUG,
        "rotation_notify",
        subscriber_count = %subscriber_count,
        otel.kind = "internal"
    )
}

/// Create a span for TLS handshake (parent span)
pub fn span_tls_handshake(role: &str, tls_version: &str) -> Span {
    span!(
        Level::INFO,
        "tls_handshake",
        role = %role,
        tls_version = %tls_version,
        otel.kind = "internal"
    )
}

/// Create a span for TLS certificate verification
pub fn span_tls_cert_verification(peer_organization: Option<&str>) -> Span {
    span!(
        Level::INFO,
        "tls_cert_verification",
        peer_organization = ?peer_organization,
        otel.kind = "internal"
    )
}

/// Create a span for mutual TLS client verification
pub fn span_mutual_tls_verification(client_organization: &str) -> Span {
    span!(
        Level::INFO,
        "mutual_tls_verification",
        client_organization = %client_organization,
        otel.kind = "internal"
    )
}

/// Create a span for fingerprint computation
pub fn span_fingerprint_compute(algorithm: &str) -> Span {
    span!(
        Level::DEBUG,
        "fingerprint_compute",
        algorithm = %algorithm,
        otel.kind = "internal"
    )
}

/// Create a span for organization ID extraction
pub fn span_extract_org_id(subject: &str) -> Span {
    span!(
        Level::DEBUG,
        "extract_org_id",
        subject = %subject,
        otel.kind = "internal"
    )
}

/// Helper to record span success
pub fn record_success(span: &Span) {
    span.record("success", true);
    span.record("otel.status_code", "OK");
}

/// Helper to record span failure
pub fn record_failure(span: &Span, error: &str) {
    span.record("success", false);
    span.record("error", error);
    span.record("otel.status_code", "ERROR");
    span.record("otel.status_message", error);
}

/// Helper to record span duration
pub fn record_duration_ms(span: &Span, duration_ms: u64) {
    span.record("duration_ms", duration_ms);
}

/// Helper to record cache hit
pub fn record_cache_hit(span: &Span, hit: bool) {
    span.record("cache_hit", hit);
}

/// Helper to record HTTP status code
pub fn record_http_status(span: &Span, status_code: u16) {
    span.record("http.status_code", status_code);
}

/// Helper to record response size
pub fn record_response_size(span: &Span, size_bytes: usize) {
    span.record("response_size_bytes", size_bytes);
}

#[cfg(test)]
mod tests {
    use super::*;
    
    // Note: These tests verify that spans can be created without panicking.
    // Actual span metadata may not be available without a tracing subscriber.
    
    #[test]
    fn test_span_cert_validation() {
        let _span = span_cert_validation("server", "test.org", "CN=test");
        // Success if no panic
    }
    
    #[test]
    fn test_span_cert_chain_validation() {
        let _span = span_cert_chain_validation("test.org", 3);
        // Success if no panic
    }
    
    #[test]
    fn test_span_cert_expiration_check() {
        let _span = span_cert_expiration_check("server", "test.org");
        // Success if no panic
    }
    
    #[test]
    fn test_span_cert_pinning() {
        let _span = span_cert_pinning("sha256", "test.org", 3);
        // Success if no panic
    }
    
    #[test]
    fn test_span_revocation_check() {
        let _span = span_revocation_check("test.org", "CN=test");
        // Success if no panic
    }
    
    #[test]
    fn test_span_ocsp_check() {
        let _span = span_ocsp_check("http://ocsp.example.com", "test.org");
        // Success if no panic
    }
    
    #[test]
    fn test_span_ocsp_request() {
        let _span = span_ocsp_request("http://ocsp.example.com");
        // Success if no panic
    }
    
    #[test]
    fn test_span_ocsp_cache_lookup() {
        let _span = span_ocsp_cache_lookup("http://ocsp.example.com");
        // Success if no panic
    }
    
    #[test]
    fn test_span_crl_check() {
        let _span = span_crl_check("http://crl.example.com/ca.crl", "test.org");
        // Success if no panic
    }
    
    #[test]
    fn test_span_crl_download() {
        let _span = span_crl_download("http://crl.example.com/ca.crl");
        // Success if no panic
    }
    
    #[test]
    fn test_span_crl_cache_lookup() {
        let _span = span_crl_cache_lookup("http://crl.example.com/ca.crl");
        // Success if no panic
    }
    
    #[test]
    fn test_span_crl_parse() {
        let _span = span_crl_parse(50000);
        // Success if no panic
    }
    
    #[test]
    fn test_span_cert_rotation() {
        let _span = span_cert_rotation("manual", "server");
        // Success if no panic
    }
    
    #[test]
    fn test_span_cert_reload() {
        let _span = span_cert_reload("/etc/certs/server.pem", "/etc/certs/server.key");
        // Success if no panic
    }
    
    #[test]
    fn test_span_cert_file_load() {
        let _span = span_cert_file_load("/etc/certs/server.pem");
        // Success if no panic
    }
    
    #[test]
    fn test_span_cert_parse() {
        let _span = span_cert_parse("/etc/certs/server.pem");
        // Success if no panic
    }
    
    #[test]
    fn test_span_rotation_notify() {
        let _span = span_rotation_notify(5);
        // Success if no panic
    }
    
    #[test]
    fn test_span_tls_handshake() {
        let _span = span_tls_handshake("server", "1.3");
        // Success if no panic
    }
    
    #[test]
    fn test_span_tls_cert_verification() {
        let _span = span_tls_cert_verification(Some("client.org"));
        // Success if no panic
    }
    
    #[test]
    fn test_span_mutual_tls_verification() {
        let _span = span_mutual_tls_verification("client.org");
        // Success if no panic
    }
    
    #[test]
    fn test_span_fingerprint_compute() {
        let _span = span_fingerprint_compute("sha256");
        // Success if no panic
    }
    
    #[test]
    fn test_span_extract_org_id() {
        let _span = span_extract_org_id("CN=test,O=TestOrg");
        // Success if no panic
    }
    
    #[test]
    fn test_record_success() {
        let span = span_cert_validation("server", "test.org", "CN=test");
        let _guard = span.enter();
        record_success(&span);
        // Just verify it doesn't panic
    }
    
    #[test]
    fn test_record_failure() {
        let span = span_cert_validation("server", "test.org", "CN=test");
        let _guard = span.enter();
        record_failure(&span, "certificate expired");
        // Just verify it doesn't panic
    }
    
    #[test]
    fn test_record_duration_ms() {
        let span = span_cert_validation("server", "test.org", "CN=test");
        let _guard = span.enter();
        record_duration_ms(&span, 15);
        // Just verify it doesn't panic
    }
    
    #[test]
    fn test_record_cache_hit() {
        let span = span_ocsp_check("http://ocsp.example.com", "test.org");
        let _guard = span.enter();
        record_cache_hit(&span, true);
        // Just verify it doesn't panic
    }
    
    #[test]
    fn test_record_http_status() {
        let span = span_ocsp_request("http://ocsp.example.com");
        let _guard = span.enter();
        record_http_status(&span, 200);
        // Just verify it doesn't panic
    }
    
    #[test]
    fn test_record_response_size() {
        let span = span_crl_download("http://crl.example.com/ca.crl");
        let _guard = span.enter();
        record_response_size(&span, 50000);
        // Just verify it doesn't panic
    }
}
