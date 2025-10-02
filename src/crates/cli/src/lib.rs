//! NORC CLI
//!
//! Command line interface utilities and service management for NORC applications.

pub mod service;
pub mod diagnostics;

pub use service::{ServiceConfig, ServiceManager, ServiceStatus, get_service_manager, check_privileges};
pub use diagnostics::{
    validate_certificate, validate_certificate_chain, check_revocation, run_health_checks,
    validate_configuration, inspect_certificate, print_validation_result, print_revocation_result,
    print_health_results, print_config_validation, ValidationResult, RevocationResult,
    HealthCheckResult, HealthStatus, RevocationStatus, CertificateInfo,
};

