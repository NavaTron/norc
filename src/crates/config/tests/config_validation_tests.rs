//! Configuration validation tests
//!
//! Tests configuration parsing, validation logic, default values,
//! error handling, and security utilities.
//!
//! Requirements: Validate configuration structures from config/src/server.rs

use norc_config::security::{
    format_fingerprint, parse_pin, validate_pinning_config, validate_tls_config,
};
use norc_config::server::{
    CertificatePinningConfig, OcspStaplingConfig, RevocationCheckConfig, SecurityConfig,
    TlsSecurityConfig,
};
use std::path::PathBuf;

// ============================================================================
// Default Value Tests
// ============================================================================

#[test]
fn test_tls_security_config_defaults() {
    let config = TlsSecurityConfig::default();

    assert!(
        config.require_mutual_tls,
        "Mutual TLS should be required by default"
    );
    assert!(
        config.trusted_ca_certs.is_empty(),
        "No trusted CAs by default"
    );
    assert_eq!(config.min_tls_version, "1.3", "Should default to TLS 1.3");
    assert!(
        config.allowed_cipher_suites.is_empty(),
        "Use secure defaults"
    );
    assert!(
        config.enable_session_resumption,
        "Session resumption enabled by default"
    );
    assert_eq!(
        config.session_ticket_rotation_secs, 86400,
        "24-hour ticket rotation"
    );
}

#[test]
fn test_certificate_pinning_config_defaults() {
    let config = CertificatePinningConfig::default();

    assert!(!config.enabled, "Pinning disabled by default");
    assert_eq!(config.mode, "strict", "Should default to strict mode");
    assert!(config.pins.is_empty(), "No pins by default");
    assert!(config.pin_cert_files.is_empty(), "No pin files by default");
    assert!(!config.enable_spki_pins, "SPKI pins disabled by default");
    assert!(config.spki_pins.is_empty(), "No SPKI pins by default");
    assert!(config.backup_pins.is_empty(), "No backup pins by default");
    assert_eq!(config.max_pin_age_days, 0, "No max pin age by default");
}

#[test]
fn test_revocation_check_config_defaults() {
    let config = RevocationCheckConfig::default();

    assert!(config.enable_ocsp, "OCSP enabled by default");
    assert!(config.enable_crl, "CRL enabled by default");
    assert_eq!(config.timeout_secs, 10, "10-second timeout");
    assert_eq!(
        config.max_crl_size_bytes,
        10 * 1024 * 1024,
        "10 MB max CRL size"
    );
    assert!(!config.fail_on_unknown, "Fail-open by default");
    assert_eq!(config.ocsp_cache_duration_secs, 3600, "1-hour OCSP cache");
    assert_eq!(config.crl_cache_duration_secs, 86400, "24-hour CRL cache");
}

#[test]
fn test_ocsp_stapling_config_defaults() {
    let config = OcspStaplingConfig::default();

    assert!(!config.enabled, "OCSP stapling disabled by default");
    assert!(config.responder_url.is_none(), "No responder URL override");
    assert_eq!(
        config.refresh_before_expiry_secs, 3600,
        "Refresh 1 hour before expiry"
    );
}

// ============================================================================
// Configuration Creation Tests
// ============================================================================

#[test]
fn test_create_tls_config_with_mutual_tls() {
    let config = TlsSecurityConfig {
        require_mutual_tls: true,
        trusted_ca_certs: vec![PathBuf::from("/etc/norc/ca.pem")],
        pinning: CertificatePinningConfig::default(),
        min_tls_version: "1.3".to_string(),
        allowed_cipher_suites: vec![],
        enable_session_resumption: true,
        session_ticket_rotation_secs: 86400,
    };

    assert!(config.require_mutual_tls);
    assert_eq!(config.trusted_ca_certs.len(), 1);
}

#[test]
fn test_create_pinning_config_enabled() {
    let config = CertificatePinningConfig {
        enabled: true,
        mode: "strict".to_string(),
        pins: vec!["sha256:ABCD1234".to_string()],
        pin_cert_files: vec![],
        enable_spki_pins: false,
        spki_pins: vec![],
        backup_pins: vec![],
        max_pin_age_days: 90,
    };

    assert!(config.enabled);
    assert_eq!(config.mode, "strict");
    assert_eq!(config.pins.len(), 1);
    assert_eq!(config.max_pin_age_days, 90);
}

#[test]
fn test_create_revocation_config_custom() {
    let config = RevocationCheckConfig {
        enable_ocsp: true,
        enable_crl: false,
        timeout_secs: 5,
        max_crl_size_bytes: 5 * 1024 * 1024,
        fail_on_unknown: true,
        ocsp_cache_duration_secs: 1800,
        crl_cache_duration_secs: 43200,
        ocsp_stapling: OcspStaplingConfig::default(),
    };

    assert!(config.enable_ocsp);
    assert!(!config.enable_crl);
    assert_eq!(config.timeout_secs, 5);
    assert!(config.fail_on_unknown);
}

// ============================================================================
// Pin Parsing Tests
// ============================================================================

#[test]
fn test_parse_pin_with_sha256_prefix() {
    let pin = "sha256:ABCD1234EFEF5678";
    let result = parse_pin(pin).expect("Should parse pin");

    assert_eq!(result, hex::decode("ABCD1234EFEF5678").unwrap());
}

#[test]
fn test_parse_pin_without_prefix() {
    let pin = "DEADBEEF";
    let result = parse_pin(pin).expect("Should parse pin");

    assert_eq!(result, hex::decode("DEADBEEF").unwrap());
}

#[test]
fn test_parse_pin_with_colons() {
    let pin = "AB:CD:EF:12:34";
    let result = parse_pin(pin).expect("Should parse pin with colons");

    assert_eq!(result, hex::decode("ABCDEF1234").unwrap());
}

#[test]
fn test_parse_pin_with_spaces() {
    let pin = "AB CD EF 12";
    let result = parse_pin(pin).expect("Should parse pin with spaces");

    assert_eq!(result, hex::decode("ABCDEF12").unwrap());
}

#[test]
fn test_parse_pin_invalid_hex() {
    let pin = "GHIJKLMN";
    let result = parse_pin(pin);

    assert!(result.is_err(), "Should fail with invalid hex");
}

#[test]
fn test_parse_pin_empty() {
    let pin = "";
    let result = parse_pin(pin);

    // Empty string is valid hex (empty vec)
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
}

// ============================================================================
// Fingerprint Formatting Tests
// ============================================================================

#[test]
fn test_format_fingerprint_basic() {
    let fingerprint = vec![0xAB, 0xCD, 0xEF, 0x12];
    let formatted = format_fingerprint(&fingerprint);

    assert_eq!(formatted, "AB:CD:EF:12");
}

#[test]
fn test_format_fingerprint_empty() {
    let fingerprint = vec![];
    let formatted = format_fingerprint(&fingerprint);

    assert_eq!(formatted, "");
}

#[test]
fn test_format_fingerprint_single_byte() {
    let fingerprint = vec![0xFF];
    let formatted = format_fingerprint(&fingerprint);

    assert_eq!(formatted, "FF");
}

#[test]
fn test_format_fingerprint_sha256_length() {
    // SHA-256 is 32 bytes = 64 hex chars + 31 colons
    let fingerprint = vec![0u8; 32];
    let formatted = format_fingerprint(&fingerprint);

    assert_eq!(formatted.len(), 32 * 2 + 31, "Should be 95 characters");
    assert_eq!(formatted.matches(':').count(), 31, "Should have 31 colons");
}

// ============================================================================
// TLS Config Validation Tests
// ============================================================================

#[test]
fn test_validate_tls_config_valid_13() {
    let config = TlsSecurityConfig {
        require_mutual_tls: true,
        trusted_ca_certs: vec![],
        pinning: CertificatePinningConfig::default(),
        min_tls_version: "1.3".to_string(),
        allowed_cipher_suites: vec![],
        enable_session_resumption: true,
        session_ticket_rotation_secs: 86400,
    };

    let result = validate_tls_config(&config);
    assert!(result.is_ok(), "TLS 1.3 should be valid");
}

#[test]
fn test_validate_tls_config_valid_12() {
    let config = TlsSecurityConfig {
        require_mutual_tls: true,
        trusted_ca_certs: vec![],
        pinning: CertificatePinningConfig::default(),
        min_tls_version: "1.2".to_string(),
        allowed_cipher_suites: vec![],
        enable_session_resumption: true,
        session_ticket_rotation_secs: 86400,
    };

    let result = validate_tls_config(&config);
    assert!(result.is_ok(), "TLS 1.2 should be valid");
}

#[test]
fn test_validate_tls_config_invalid_version() {
    let config = TlsSecurityConfig {
        require_mutual_tls: true,
        trusted_ca_certs: vec![],
        pinning: CertificatePinningConfig::default(),
        min_tls_version: "1.1".to_string(),
        allowed_cipher_suites: vec![],
        enable_session_resumption: true,
        session_ticket_rotation_secs: 86400,
    };

    let result = validate_tls_config(&config);
    assert!(result.is_err(), "TLS 1.1 should be invalid");
    assert!(result.unwrap_err().contains("Invalid TLS version"));
}

#[test]
fn test_validate_tls_config_invalid_version_string() {
    let config = TlsSecurityConfig {
        require_mutual_tls: true,
        trusted_ca_certs: vec![],
        pinning: CertificatePinningConfig::default(),
        min_tls_version: "2.0".to_string(),
        allowed_cipher_suites: vec![],
        enable_session_resumption: true,
        session_ticket_rotation_secs: 86400,
    };

    let result = validate_tls_config(&config);
    assert!(result.is_err(), "TLS 2.0 should be invalid");
}

// ============================================================================
// Pinning Config Validation Tests
// ============================================================================

#[test]
fn test_validate_pinning_config_disabled() {
    let config = CertificatePinningConfig {
        enabled: false,
        mode: "strict".to_string(),
        pins: vec![],
        pin_cert_files: vec![],
        enable_spki_pins: false,
        spki_pins: vec![],
        backup_pins: vec![],
        max_pin_age_days: 0,
    };

    let result = validate_pinning_config(&config);
    assert!(result.is_ok(), "Disabled pinning config should be valid");
}

#[test]
fn test_validate_pinning_config_enabled_with_pins() {
    let config = CertificatePinningConfig {
        enabled: true,
        mode: "strict".to_string(),
        pins: vec!["sha256:ABCD1234".to_string()],
        pin_cert_files: vec![],
        enable_spki_pins: false,
        spki_pins: vec![],
        backup_pins: vec![],
        max_pin_age_days: 0,
    };

    let result = validate_pinning_config(&config);
    assert!(result.is_ok(), "Enabled pinning with pins should be valid");
}

#[test]
fn test_validate_pinning_config_enabled_without_pins() {
    let config = CertificatePinningConfig {
        enabled: true,
        mode: "strict".to_string(),
        pins: vec![],
        pin_cert_files: vec![],
        enable_spki_pins: false,
        spki_pins: vec![],
        backup_pins: vec![],
        max_pin_age_days: 0,
    };

    let result = validate_pinning_config(&config);
    assert!(
        result.is_err(),
        "Enabled pinning without pins should be invalid"
    );
}

#[test]
fn test_validate_pinning_config_invalid_mode() {
    let config = CertificatePinningConfig {
        enabled: true,
        mode: "invalid".to_string(),
        pins: vec!["sha256:ABCD".to_string()],
        pin_cert_files: vec![],
        enable_spki_pins: false,
        spki_pins: vec![],
        backup_pins: vec![],
        max_pin_age_days: 0,
    };

    let result = validate_pinning_config(&config);
    assert!(result.is_err(), "Invalid pinning mode should be rejected");
    assert!(result.unwrap_err().contains("mode"));
}

#[test]
fn test_validate_pinning_config_relaxed_mode() {
    let config = CertificatePinningConfig {
        enabled: true,
        mode: "relaxed".to_string(),
        pins: vec!["sha256:ABCD".to_string()],
        pin_cert_files: vec![],
        enable_spki_pins: false,
        spki_pins: vec![],
        backup_pins: vec![],
        max_pin_age_days: 0,
    };

    let result = validate_pinning_config(&config);
    assert!(result.is_ok(), "Relaxed mode should be valid");
}

// ============================================================================
// Revocation Config Validation Tests
// ============================================================================

#[test]
fn test_revocation_config_both_disabled() {
    let config = RevocationCheckConfig {
        enable_ocsp: false,
        enable_crl: false,
        timeout_secs: 10,
        max_crl_size_bytes: 10 * 1024 * 1024,
        fail_on_unknown: false,
        ocsp_cache_duration_secs: 3600,
        crl_cache_duration_secs: 86400,
        ocsp_stapling: OcspStaplingConfig::default(),
    };

    // Both disabled is allowed (revocation checking off)
    assert!(!config.enable_ocsp);
    assert!(!config.enable_crl);
}

#[test]
fn test_revocation_config_ocsp_only() {
    let config = RevocationCheckConfig {
        enable_ocsp: true,
        enable_crl: false,
        timeout_secs: 10,
        max_crl_size_bytes: 10 * 1024 * 1024,
        fail_on_unknown: false,
        ocsp_cache_duration_secs: 3600,
        crl_cache_duration_secs: 86400,
        ocsp_stapling: OcspStaplingConfig::default(),
    };

    assert!(config.enable_ocsp);
    assert!(!config.enable_crl);
}

#[test]
fn test_revocation_config_crl_only() {
    let config = RevocationCheckConfig {
        enable_ocsp: false,
        enable_crl: true,
        timeout_secs: 10,
        max_crl_size_bytes: 10 * 1024 * 1024,
        fail_on_unknown: false,
        ocsp_cache_duration_secs: 3600,
        crl_cache_duration_secs: 86400,
        ocsp_stapling: OcspStaplingConfig::default(),
    };

    assert!(!config.enable_ocsp);
    assert!(config.enable_crl);
}

#[test]
fn test_revocation_config_reasonable_timeout() {
    let config = RevocationCheckConfig {
        enable_ocsp: true,
        enable_crl: true,
        timeout_secs: 1,
        max_crl_size_bytes: 10 * 1024 * 1024,
        fail_on_unknown: false,
        ocsp_cache_duration_secs: 3600,
        crl_cache_duration_secs: 86400,
        ocsp_stapling: OcspStaplingConfig::default(),
    };

    assert_eq!(config.timeout_secs, 1, "1-second timeout should be allowed");
}

#[test]
fn test_revocation_config_large_crl_size() {
    let config = RevocationCheckConfig {
        enable_ocsp: true,
        enable_crl: true,
        timeout_secs: 10,
        max_crl_size_bytes: 100 * 1024 * 1024, // 100 MB
        fail_on_unknown: false,
        ocsp_cache_duration_secs: 3600,
        crl_cache_duration_secs: 86400,
        ocsp_stapling: OcspStaplingConfig::default(),
    };

    assert_eq!(config.max_crl_size_bytes, 100 * 1024 * 1024);
}

// ============================================================================
// Security Config Tests
// ============================================================================

#[test]
fn test_security_config_creation() {
    let config = SecurityConfig {
        organization_id: "test.org".to_string(),
        default_trust_level: "Basic".to_string(),
        enable_pq_crypto: false,
        key_rotation_interval_secs: 3600,
        strict_cert_validation: true,
        enable_hsm: false,
        tls: TlsSecurityConfig::default(),
        revocation: RevocationCheckConfig::default(),
    };

    assert_eq!(config.organization_id, "test.org");
    assert_eq!(config.default_trust_level, "Basic");
    assert!(config.strict_cert_validation);
}

#[test]
fn test_security_config_with_pq_crypto() {
    let config = SecurityConfig {
        organization_id: "quantum.org".to_string(),
        default_trust_level: "Enhanced".to_string(),
        enable_pq_crypto: true,
        key_rotation_interval_secs: 1800,
        strict_cert_validation: true,
        enable_hsm: false,
        tls: TlsSecurityConfig::default(),
        revocation: RevocationCheckConfig::default(),
    };

    assert!(
        config.enable_pq_crypto,
        "Post-quantum crypto should be enabled"
    );
}

#[test]
fn test_security_config_with_hsm() {
    let config = SecurityConfig {
        organization_id: "secure.org".to_string(),
        default_trust_level: "Full".to_string(),
        enable_pq_crypto: false,
        key_rotation_interval_secs: 3600,
        strict_cert_validation: true,
        enable_hsm: true,
        tls: TlsSecurityConfig::default(),
        revocation: RevocationCheckConfig::default(),
    };

    assert!(config.enable_hsm, "HSM should be enabled");
}

// ============================================================================
// Edge Cases and Error Handling
// ============================================================================

#[test]
fn test_zero_timeout_revocation_config() {
    let config = RevocationCheckConfig {
        enable_ocsp: true,
        enable_crl: true,
        timeout_secs: 0,
        max_crl_size_bytes: 10 * 1024 * 1024,
        fail_on_unknown: false,
        ocsp_cache_duration_secs: 3600,
        crl_cache_duration_secs: 86400,
        ocsp_stapling: OcspStaplingConfig::default(),
    };

    // Zero timeout is allowed (might mean instant fail or no timeout)
    assert_eq!(config.timeout_secs, 0);
}

#[test]
fn test_zero_cache_duration() {
    let config = RevocationCheckConfig {
        enable_ocsp: true,
        enable_crl: true,
        timeout_secs: 10,
        max_crl_size_bytes: 10 * 1024 * 1024,
        fail_on_unknown: false,
        ocsp_cache_duration_secs: 0,
        crl_cache_duration_secs: 0,
        ocsp_stapling: OcspStaplingConfig::default(),
    };

    // Zero cache duration means no caching
    assert_eq!(config.ocsp_cache_duration_secs, 0);
    assert_eq!(config.crl_cache_duration_secs, 0);
}

#[test]
fn test_empty_trusted_ca_list() {
    let config = TlsSecurityConfig {
        require_mutual_tls: true,
        trusted_ca_certs: vec![],
        pinning: CertificatePinningConfig::default(),
        min_tls_version: "1.3".to_string(),
        allowed_cipher_suites: vec![],
        enable_session_resumption: true,
        session_ticket_rotation_secs: 86400,
    };

    // Empty CA list is allowed (might use system roots or no verification)
    assert!(config.trusted_ca_certs.is_empty());
}

#[test]
fn test_very_long_pin_list() {
    let mut pins = Vec::new();
    for i in 0..1000 {
        pins.push(format!("sha256:{:064x}", i));
    }

    let config = CertificatePinningConfig {
        enabled: true,
        mode: "strict".to_string(),
        pins,
        pin_cert_files: vec![],
        enable_spki_pins: false,
        spki_pins: vec![],
        backup_pins: vec![],
        max_pin_age_days: 0,
    };

    assert_eq!(config.pins.len(), 1000, "Should support many pins");
}

#[test]
fn test_backup_pins_without_primary() {
    let config = CertificatePinningConfig {
        enabled: true,
        mode: "strict".to_string(),
        pins: vec![],
        pin_cert_files: vec![],
        enable_spki_pins: false,
        spki_pins: vec![],
        backup_pins: vec!["sha256:BACKUP".to_string()],
        max_pin_age_days: 0,
    };

    // Backup pins without primary pins (should be caught by validation)
    assert!(config.pins.is_empty());
    assert!(!config.backup_pins.is_empty());
}
