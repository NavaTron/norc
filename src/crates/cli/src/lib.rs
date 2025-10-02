//! NORC CLI
//!
//! Command line interface utilities and service management for NORC applications.

pub mod diagnostics;
pub mod service;

pub use diagnostics::{
    CertificateInfo, HealthCheckResult, HealthStatus, RevocationResult, RevocationStatus,
    ValidationResult, check_revocation, inspect_certificate, print_config_validation,
    print_health_results, print_revocation_result, print_validation_result, run_health_checks,
    validate_certificate, validate_certificate_chain, validate_configuration,
};
pub use service::{
    ServiceConfig, ServiceManager, ServiceStatus, check_privileges, get_service_manager,
};
