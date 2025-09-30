//! NORC CLI
//!
//! Command line interface utilities and service management for NORC applications.

pub mod service;

pub use service::{ServiceConfig, ServiceManager, ServiceStatus, get_service_manager, check_privileges};

