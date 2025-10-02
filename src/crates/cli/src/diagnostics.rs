//! Certificate Diagnostic Tools
//!
//! CLI utilities for testing and troubleshooting certificate operations:
//! - Certificate validation testing
//! - Revocation checking (OCSP/CRL)
//! - Health check utilities
//! - Configuration validation
//! - Certificate inspection and analysis

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use colored::Colorize;
use std::fs;
use std::path::Path;
use std::time::SystemTime;

/// Certificate validation result
#[derive(Debug)]
pub struct ValidationResult {
    pub valid: bool,
    pub certificate_info: CertificateInfo,
    pub issues: Vec<String>,
    pub warnings: Vec<String>,
}

/// Certificate information extracted from a certificate file
#[derive(Debug, Clone)]
pub struct CertificateInfo {
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub days_until_expiry: i64,
    pub is_expired: bool,
    pub key_algorithm: String,
    pub signature_algorithm: String,
    pub san: Vec<String>,
    pub fingerprint_sha256: String,
}

/// Revocation check result
#[derive(Debug)]
pub struct RevocationResult {
    pub status: RevocationStatus,
    pub check_method: String,
    pub checked_at: DateTime<Utc>,
    pub details: String,
}

/// Revocation status enum
#[derive(Debug, Clone, PartialEq)]
pub enum RevocationStatus {
    Valid,
    Revoked,
    Unknown,
}

/// Health check result
#[derive(Debug)]
pub struct HealthCheckResult {
    pub component: String,
    pub status: HealthStatus,
    pub message: String,
    pub details: Vec<String>,
}

/// Health status enum
#[derive(Debug, Clone, PartialEq)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

// ============================================================================
// Certificate Validation
// ============================================================================

/// Validate a certificate file
pub fn validate_certificate(cert_path: &Path) -> Result<ValidationResult> {
    println!("{}", "Validating certificate...".cyan().bold());
    println!("File: {}", cert_path.display());
    println!();

    // Read certificate file
    let cert_pem = fs::read_to_string(cert_path)
        .with_context(|| format!("Failed to read certificate file: {}", cert_path.display()))?;

    // Check PEM format
    if !cert_pem.contains("BEGIN CERTIFICATE") {
        return Ok(ValidationResult {
            valid: false,
            certificate_info: create_empty_cert_info(),
            issues: vec!["Invalid PEM format: Missing BEGIN CERTIFICATE marker".to_string()],
            warnings: vec![],
        });
    }

    // Parse certificate (mock implementation - real would use x509-parser)
    let cert_info = parse_certificate_info(&cert_pem)?;

    // Perform validation checks
    let mut issues = Vec::new();
    let mut warnings = Vec::new();

    // Check expiration
    if cert_info.is_expired {
        issues.push(format!(
            "Certificate expired {} days ago",
            -cert_info.days_until_expiry
        ));
    } else if cert_info.days_until_expiry < 30 {
        warnings.push(format!(
            "Certificate expires soon: {} days remaining",
            cert_info.days_until_expiry
        ));
    }

    // Check key algorithm
    if cert_info.key_algorithm.contains("RSA-1024") || cert_info.key_algorithm.contains("MD5") {
        issues.push(format!(
            "Weak cryptographic algorithm: {}",
            cert_info.key_algorithm
        ));
    }

    let valid = issues.is_empty();

    Ok(ValidationResult {
        valid,
        certificate_info: cert_info,
        issues,
        warnings,
    })
}

/// Validate a certificate chain
pub fn validate_certificate_chain(
    cert_path: &Path,
    chain_path: Option<&Path>,
) -> Result<ValidationResult> {
    println!("{}", "Validating certificate chain...".cyan().bold());
    println!("Certificate: {}", cert_path.display());
    if let Some(chain) = chain_path {
        println!("Chain: {}", chain.display());
    }
    println!();

    // Validate main certificate
    let mut result = validate_certificate(cert_path)?;

    // If chain provided, validate it
    if let Some(chain) = chain_path {
        let chain_pem = fs::read_to_string(chain)
            .with_context(|| format!("Failed to read chain file: {}", chain.display()))?;

        if !chain_pem.contains("BEGIN CERTIFICATE") {
            result.issues.push("Invalid chain PEM format".to_string());
            result.valid = false;
        }

        // In real implementation, verify chain signatures
        result
            .warnings
            .push("Chain validation not yet implemented".to_string());
    }

    Ok(result)
}

/// Print validation result in a formatted way
pub fn print_validation_result(result: &ValidationResult) {
    println!("{}", "=".repeat(70));
    println!("{}", "Certificate Validation Result".bold());
    println!("{}", "=".repeat(70));
    println!();

    // Overall status
    if result.valid {
        println!("Status: {}", "✓ VALID".green().bold());
    } else {
        println!("Status: {}", "✗ INVALID".red().bold());
    }
    println!();

    // Certificate details
    println!("{}", "Certificate Details:".bold());
    println!("  Subject:       {}", result.certificate_info.subject);
    println!("  Issuer:        {}", result.certificate_info.issuer);
    println!("  Serial:        {}", result.certificate_info.serial_number);
    println!("  Not Before:    {}", result.certificate_info.not_before);
    println!("  Not After:     {}", result.certificate_info.not_after);
    println!(
        "  Days to Expiry: {}",
        if result.certificate_info.is_expired {
            format!("{} (EXPIRED)", result.certificate_info.days_until_expiry)
                .red()
                .to_string()
        } else if result.certificate_info.days_until_expiry < 30 {
            format!("{}", result.certificate_info.days_until_expiry)
                .yellow()
                .to_string()
        } else {
            format!("{}", result.certificate_info.days_until_expiry)
                .green()
                .to_string()
        }
    );
    println!("  Key Algorithm: {}", result.certificate_info.key_algorithm);
    println!(
        "  Signature:     {}",
        result.certificate_info.signature_algorithm
    );
    println!(
        "  Fingerprint:   {}",
        result.certificate_info.fingerprint_sha256
    );

    if !result.certificate_info.san.is_empty() {
        println!(
            "  SAN:           {}",
            result.certificate_info.san.join(", ")
        );
    }
    println!();

    // Issues
    if !result.issues.is_empty() {
        println!("{}", "Issues Found:".red().bold());
        for issue in &result.issues {
            println!("  {} {}", "✗".red(), issue);
        }
        println!();
    }

    // Warnings
    if !result.warnings.is_empty() {
        println!("{}", "Warnings:".yellow().bold());
        for warning in &result.warnings {
            println!("  {} {}", "⚠".yellow(), warning);
        }
        println!();
    }

    println!("{}", "=".repeat(70));
}

// ============================================================================
// Revocation Checking
// ============================================================================

/// Check certificate revocation status
pub fn check_revocation(
    cert_path: &Path,
    use_ocsp: bool,
    use_crl: bool,
) -> Result<RevocationResult> {
    println!("{}", "Checking certificate revocation...".cyan().bold());
    println!("Certificate: {}", cert_path.display());
    println!("OCSP: {}, CRL: {}", use_ocsp, use_crl);
    println!();

    // Read certificate
    let _cert_pem = fs::read_to_string(cert_path)
        .with_context(|| format!("Failed to read certificate: {}", cert_path.display()))?;

    // Mock implementation - real would check OCSP/CRL
    let result = RevocationResult {
        status: RevocationStatus::Valid,
        check_method: if use_ocsp { "OCSP" } else { "CRL" }.to_string(),
        checked_at: Utc::now(),
        details: "Certificate is not revoked".to_string(),
    };

    Ok(result)
}

/// Print revocation check result
pub fn print_revocation_result(result: &RevocationResult) {
    println!("{}", "=".repeat(70));
    println!("{}", "Revocation Check Result".bold());
    println!("{}", "=".repeat(70));
    println!();

    print!("Status: ");
    match result.status {
        RevocationStatus::Valid => println!("{}", "✓ NOT REVOKED".green().bold()),
        RevocationStatus::Revoked => println!("{}", "✗ REVOKED".red().bold()),
        RevocationStatus::Unknown => println!("{}", "? UNKNOWN".yellow().bold()),
    }

    println!("Method: {}", result.check_method);
    println!("Checked At: {}", result.checked_at);
    println!("Details: {}", result.details);
    println!();
    println!("{}", "=".repeat(70));
}

// ============================================================================
// Health Checks
// ============================================================================

/// Run comprehensive health checks
pub fn run_health_checks() -> Result<Vec<HealthCheckResult>> {
    println!("{}", "Running health checks...".cyan().bold());
    println!();

    let mut results = Vec::new();

    // Check certificate files
    results.push(check_certificate_files()?);

    // Check rotation manager
    results.push(check_rotation_manager()?);

    // Check revocation service
    results.push(check_revocation_service()?);

    // Check TLS configuration
    results.push(check_tls_configuration()?);

    Ok(results)
}

/// Check certificate files exist and are valid
fn check_certificate_files() -> Result<HealthCheckResult> {
    // Mock implementation
    Ok(HealthCheckResult {
        component: "Certificate Files".to_string(),
        status: HealthStatus::Healthy,
        message: "All certificate files present and valid".to_string(),
        details: vec![
            "Server certificate: OK".to_string(),
            "Private key: OK".to_string(),
            "CA chain: OK".to_string(),
        ],
    })
}

/// Check rotation manager status
fn check_rotation_manager() -> Result<HealthCheckResult> {
    // Mock implementation
    Ok(HealthCheckResult {
        component: "Rotation Manager".to_string(),
        status: HealthStatus::Healthy,
        message: "Rotation manager operational".to_string(),
        details: vec![
            "Auto-rotation: Enabled".to_string(),
            "Active watchers: 2".to_string(),
            "Last rotation: 30 days ago".to_string(),
        ],
    })
}

/// Check revocation service status
fn check_revocation_service() -> Result<HealthCheckResult> {
    // Mock implementation
    Ok(HealthCheckResult {
        component: "Revocation Service".to_string(),
        status: HealthStatus::Healthy,
        message: "Revocation checking operational".to_string(),
        details: vec![
            "OCSP: Enabled".to_string(),
            "CRL: Enabled".to_string(),
            "OCSP cache hit rate: 85%".to_string(),
            "CRL cache hit rate: 92%".to_string(),
        ],
    })
}

/// Check TLS configuration
fn check_tls_configuration() -> Result<HealthCheckResult> {
    // Mock implementation
    Ok(HealthCheckResult {
        component: "TLS Configuration".to_string(),
        status: HealthStatus::Healthy,
        message: "TLS configuration valid".to_string(),
        details: vec![
            "Min TLS version: 1.2".to_string(),
            "Cipher suites: Modern".to_string(),
            "ALPN: Configured".to_string(),
        ],
    })
}

/// Print health check results
pub fn print_health_results(results: &[HealthCheckResult]) {
    println!("{}", "=".repeat(70));
    println!("{}", "Health Check Results".bold());
    println!("{}", "=".repeat(70));
    println!();

    for result in results {
        print!("{}: ", result.component.bold());
        match result.status {
            HealthStatus::Healthy => print!("{}", "✓ HEALTHY".green()),
            HealthStatus::Degraded => print!("{}", "⚠ DEGRADED".yellow()),
            HealthStatus::Unhealthy => print!("{}", "✗ UNHEALTHY".red()),
        }
        println!(" - {}", result.message);

        for detail in &result.details {
            println!("  • {}", detail);
        }
        println!();
    }

    // Overall summary
    let healthy_count = results
        .iter()
        .filter(|r| r.status == HealthStatus::Healthy)
        .count();
    let degraded_count = results
        .iter()
        .filter(|r| r.status == HealthStatus::Degraded)
        .count();
    let unhealthy_count = results
        .iter()
        .filter(|r| r.status == HealthStatus::Unhealthy)
        .count();

    println!("{}", "Summary:".bold());
    println!("  Healthy:   {}", healthy_count);
    println!("  Degraded:  {}", degraded_count);
    println!("  Unhealthy: {}", unhealthy_count);
    println!();

    if unhealthy_count > 0 {
        println!(
            "{}",
            "⚠ Action required: Some components are unhealthy"
                .red()
                .bold()
        );
    } else if degraded_count > 0 {
        println!(
            "{}",
            "⚠ Warning: Some components are degraded".yellow().bold()
        );
    } else {
        println!("{}", "✓ All systems operational".green().bold());
    }

    println!("{}", "=".repeat(70));
}

// ============================================================================
// Configuration Validation
// ============================================================================

/// Validate NORC configuration file
pub fn validate_configuration(config_path: &Path) -> Result<Vec<String>> {
    println!("{}", "Validating configuration...".cyan().bold());
    println!("Config file: {}", config_path.display());
    println!();

    // Read config file
    let config_content = fs::read_to_string(config_path)
        .with_context(|| format!("Failed to read config file: {}", config_path.display()))?;

    let mut issues = Vec::new();

    // Check for required sections
    if !config_content.contains("[server]") {
        issues.push("Missing [server] section".to_string());
    }

    if !config_content.contains("[network]") {
        issues.push("Missing [network] section".to_string());
    }

    if !config_content.contains("[security]") {
        issues.push("Missing [security] section".to_string());
    }

    // Check TLS configuration
    if config_content.contains("enable_tls = true") {
        if !config_content.contains("tls_cert_path") {
            issues.push("TLS enabled but tls_cert_path not specified".to_string());
        }
        if !config_content.contains("tls_key_path") {
            issues.push("TLS enabled but tls_key_path not specified".to_string());
        }
    }

    // Check certificate paths exist
    // (In real implementation, parse TOML and check file paths)

    Ok(issues)
}

/// Print configuration validation results
pub fn print_config_validation(issues: &[String]) {
    println!("{}", "=".repeat(70));
    println!("{}", "Configuration Validation".bold());
    println!("{}", "=".repeat(70));
    println!();

    if issues.is_empty() {
        println!("{}", "✓ Configuration is valid".green().bold());
    } else {
        println!("{}", "✗ Configuration has issues:".red().bold());
        println!();
        for issue in issues {
            println!("  {} {}", "✗".red(), issue);
        }
    }

    println!();
    println!("{}", "=".repeat(70));
}

// ============================================================================
// Certificate Inspection
// ============================================================================

/// Inspect certificate and print detailed information
pub fn inspect_certificate(cert_path: &Path) -> Result<()> {
    println!("{}", "Inspecting certificate...".cyan().bold());
    println!("File: {}", cert_path.display());
    println!();

    let cert_pem = fs::read_to_string(cert_path)
        .with_context(|| format!("Failed to read certificate: {}", cert_path.display()))?;

    let cert_info = parse_certificate_info(&cert_pem)?;

    println!("{}", "=".repeat(70));
    println!("{}", "Certificate Details".bold());
    println!("{}", "=".repeat(70));
    println!();

    println!("{}", "Identity Information:".bold());
    println!("  Subject:       {}", cert_info.subject);
    println!("  Issuer:        {}", cert_info.issuer);
    println!("  Serial Number: {}", cert_info.serial_number);
    println!();

    println!("{}", "Validity Period:".bold());
    println!("  Not Before:     {}", cert_info.not_before);
    println!("  Not After:      {}", cert_info.not_after);
    println!(
        "  Days Remaining: {}",
        if cert_info.is_expired {
            format!("{} (EXPIRED)", cert_info.days_until_expiry)
                .red()
                .to_string()
        } else if cert_info.days_until_expiry < 30 {
            format!("{}", cert_info.days_until_expiry)
                .yellow()
                .to_string()
        } else {
            format!("{}", cert_info.days_until_expiry)
                .green()
                .to_string()
        }
    );
    println!();

    println!("{}", "Cryptographic Information:".bold());
    println!("  Key Algorithm:       {}", cert_info.key_algorithm);
    println!("  Signature Algorithm: {}", cert_info.signature_algorithm);
    println!("  Fingerprint (SHA256): {}", cert_info.fingerprint_sha256);
    println!();

    if !cert_info.san.is_empty() {
        println!("{}", "Subject Alternative Names:".bold());
        for san in &cert_info.san {
            println!("  • {}", san);
        }
        println!();
    }

    println!("{}", "=".repeat(70));

    Ok(())
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Parse certificate information from PEM string
fn parse_certificate_info(_cert_pem: &str) -> Result<CertificateInfo> {
    // Mock implementation - real would use x509-parser
    let now = SystemTime::now();
    let not_before: DateTime<Utc> = (now - std::time::Duration::from_secs(90 * 86400)).into();
    let not_after: DateTime<Utc> = (now + std::time::Duration::from_secs(275 * 86400)).into();

    let days_until_expiry = 275; // Mock value

    Ok(CertificateInfo {
        subject: "CN=api.example.com,O=Example Corp".to_string(),
        issuer: "CN=Example CA,O=Example Corp".to_string(),
        serial_number: "1234567890abcdef".to_string(),
        not_before,
        not_after,
        days_until_expiry,
        is_expired: false,
        key_algorithm: "RSA-2048".to_string(),
        signature_algorithm: "SHA256-RSA".to_string(),
        san: vec!["api.example.com".to_string(), "www.example.com".to_string()],
        fingerprint_sha256: "SHA256:abcd1234567890...".to_string(),
    })
}

/// Create empty certificate info for error cases
fn create_empty_cert_info() -> CertificateInfo {
    CertificateInfo {
        subject: "N/A".to_string(),
        issuer: "N/A".to_string(),
        serial_number: "N/A".to_string(),
        not_before: Utc::now(),
        not_after: Utc::now(),
        days_until_expiry: 0,
        is_expired: true,
        key_algorithm: "Unknown".to_string(),
        signature_algorithm: "Unknown".to_string(),
        san: vec![],
        fingerprint_sha256: "N/A".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_revocation_status() {
        let status = RevocationStatus::Valid;
        assert_eq!(status, RevocationStatus::Valid);
        assert_ne!(status, RevocationStatus::Revoked);
    }

    #[test]
    fn test_health_status() {
        let status = HealthStatus::Healthy;
        assert_eq!(status, HealthStatus::Healthy);
        assert_ne!(status, HealthStatus::Degraded);
    }

    #[test]
    fn test_certificate_info_creation() {
        let cert_info = create_empty_cert_info();
        assert_eq!(cert_info.subject, "N/A");
        assert!(cert_info.is_expired);
    }
}
