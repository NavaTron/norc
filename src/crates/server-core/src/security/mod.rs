//! Security hardening features per SERVER_REQUIREMENTS E-04
//!
//! This module provides comprehensive security features including:
//! - Rate limiting with token bucket algorithm
//! - Circuit breakers for federation partners
//! - Input validation and sanitization
//! - Privilege separation helpers

pub mod rate_limiter;
pub mod circuit_breaker;
pub mod validator;
pub mod privileges;

pub use rate_limiter::{RateLimiter, RateLimiterConfig};
pub use circuit_breaker::{CircuitBreaker, CircuitBreakerConfig, CircuitState};
pub use validator::{MessageValidator, ValidationError};
pub use privileges::drop_privileges;
