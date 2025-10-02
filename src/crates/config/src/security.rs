//! Security configuration utilities
//! Helper functions for working with certificate pins and security settings

use crate::server::{CertificatePinningConfig, RevocationCheckConfig, TlsSecurityConfig};
use base64::{Engine as _, engine::general_purpose};
use std::fs;

/// Parse a pin string into a byte vector
///
/// Supports formats:
/// - "sha256:HEXSTRING" - SHA-256 fingerprint
/// - "HEXSTRING" - Raw hex string
pub fn parse_pin(pin: &str) -> Result<Vec<u8>, String> {
    let hex_str = if let Some(hex) = pin.strip_prefix("sha256:") {
        hex
    } else {
        pin
    };

    // Remove any colons or spaces
    let hex_clean = hex_str.replace([':', ' '], "");

    // Decode hex string
    hex::decode(&hex_clean).map_err(|e| format!("Invalid hex string: {}", e))
}

/// Load certificate pins from files
///
/// Reads certificate files and computes their SHA-256 fingerprints
pub fn load_pins_from_files(cert_files: &[std::path::PathBuf]) -> Result<Vec<Vec<u8>>, String> {
    let mut pins = Vec::new();

    for cert_file in cert_files {
        let cert_data = fs::read(cert_file)
            .map_err(|e| format!("Failed to read {}: {}", cert_file.display(), e))?;

        // Parse PEM or DER certificate
        let cert_der = if cert_data.starts_with(b"-----BEGIN") {
            parse_pem_cert(&cert_data)?
        } else {
            cert_data
        };

        // Compute SHA-256 fingerprint
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&cert_der);
        let fingerprint = hasher.finalize().to_vec();

        pins.push(fingerprint);
    }

    Ok(pins)
}

/// Parse a PEM certificate and return DER bytes
fn parse_pem_cert(pem_data: &[u8]) -> Result<Vec<u8>, String> {
    let pem_str =
        std::str::from_utf8(pem_data).map_err(|e| format!("Invalid UTF-8 in PEM file: {}", e))?;

    // Find certificate section
    if let Some(start) = pem_str.find("-----BEGIN CERTIFICATE-----") {
        if let Some(end) = pem_str[start..].find("-----END CERTIFICATE-----") {
            let b64_start = start + "-----BEGIN CERTIFICATE-----".len();
            let b64_end = start + end;
            let b64_data = &pem_str[b64_start..b64_end];

            // Decode base64
            let b64_clean = b64_data.replace(['\n', '\r', ' ', '\t'], "");
            return general_purpose::STANDARD
                .decode(&b64_clean)
                .map_err(|e| format!("Failed to decode base64: {}", e));
        }
    }

    Err("No certificate found in PEM data".to_string())
}

/// Format a fingerprint as a hex string with colons
pub fn format_fingerprint(fingerprint: &[u8]) -> String {
    fingerprint
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":")
}

/// Validate TLS security configuration
pub fn validate_tls_config(config: &TlsSecurityConfig) -> Result<(), String> {
    // Validate TLS version
    if config.min_tls_version != "1.2" && config.min_tls_version != "1.3" {
        return Err(format!("Invalid TLS version: {}", config.min_tls_version));
    }

    // Validate pinning configuration
    validate_pinning_config(&config.pinning)?;

    // Warn if mutual TLS is disabled
    if !config.require_mutual_tls {
        eprintln!("Warning: Mutual TLS is disabled - not recommended for production");
    }

    Ok(())
}

/// Validate certificate pinning configuration
pub fn validate_pinning_config(config: &CertificatePinningConfig) -> Result<(), String> {
    if !config.enabled {
        return Ok(());
    }

    // Validate pinning mode
    if config.mode != "strict" && config.mode != "relaxed" {
        return Err(format!("Invalid pinning mode: {}", config.mode));
    }

    // Check that at least one pin is configured
    if config.pins.is_empty() && config.pin_cert_files.is_empty() && config.spki_pins.is_empty() {
        return Err("Certificate pinning enabled but no pins configured".to_string());
    }

    // Validate pin format
    for pin in &config.pins {
        parse_pin(pin)?;
    }

    // Check that pinned cert files exist
    for cert_file in &config.pin_cert_files {
        if !cert_file.exists() {
            return Err(format!(
                "Pinned certificate file not found: {}",
                cert_file.display()
            ));
        }
    }

    Ok(())
}

/// Validate revocation check configuration
pub fn validate_revocation_config(config: &RevocationCheckConfig) -> Result<(), String> {
    if config.timeout_secs == 0 {
        return Err("Revocation timeout must be > 0".to_string());
    }

    if config.max_crl_size_bytes == 0 {
        return Err("Maximum CRL size must be > 0".to_string());
    }

    if !config.enable_ocsp && !config.enable_crl {
        eprintln!("Warning: Both OCSP and CRL checking are disabled");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_pin_with_prefix() {
        let pin = "sha256:AABBCCDD";
        let result = parse_pin(pin);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn test_parse_pin_without_prefix() {
        let pin = "AABBCCDD";
        let result = parse_pin(pin);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn test_parse_pin_with_colons() {
        let pin = "AA:BB:CC:DD";
        let result = parse_pin(pin);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn test_format_fingerprint() {
        let fingerprint = vec![0xAA, 0xBB, 0xCC, 0xDD];
        let formatted = format_fingerprint(&fingerprint);
        assert_eq!(formatted, "AA:BB:CC:DD");
    }

    #[test]
    fn test_validate_pinning_config_strict() {
        let config = CertificatePinningConfig {
            enabled: true,
            mode: "strict".to_string(),
            pins: vec!["sha256:AABBCCDD".to_string()],
            pin_cert_files: vec![],
            enable_spki_pins: false,
            spki_pins: vec![],
            backup_pins: vec![],
            max_pin_age_days: 0,
        };
        assert!(validate_pinning_config(&config).is_ok());
    }

    #[test]
    fn test_validate_pinning_config_no_pins() {
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
        assert!(validate_pinning_config(&config).is_err());
    }
}
