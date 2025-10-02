//! Circuit Breaker Pattern
//!
//! Implements circuit breaker for federation partners per E-04 requirements.
//! Prevents cascading failures by temporarily blocking requests to failing partners.

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Circuit breaker state
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CircuitState {
    /// Normal operation, requests allowed
    Closed,

    /// Failure threshold exceeded, requests blocked
    Open,

    /// Testing if service recovered, limited requests allowed
    HalfOpen,
}

/// Circuit breaker configuration
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Failure threshold before opening circuit
    pub failure_threshold: u32,

    /// Success threshold to close circuit from half-open
    pub success_threshold: u32,

    /// Time to wait before attempting half-open
    pub timeout: Duration,

    /// Window duration for counting failures
    pub window_duration: Duration,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,                     // 5 failures to open
            success_threshold: 2,                     // 2 successes to close
            timeout: Duration::from_secs(60),         // 60s before half-open
            window_duration: Duration::from_secs(30), // 30s failure window
        }
    }
}

/// Circuit breaker implementation
pub struct CircuitBreaker {
    config: CircuitBreakerConfig,
    state: Arc<RwLock<CircuitBreakerState>>,
}

#[derive(Debug)]
struct CircuitBreakerState {
    /// Current state
    state: CircuitState,

    /// Failure count in current window
    failure_count: u32,

    /// Success count (used in half-open state)
    success_count: u32,

    /// Last state change time
    last_state_change: Instant,

    /// Window start time for failure counting
    window_start: Instant,
}

impl CircuitBreaker {
    /// Create a new circuit breaker
    pub fn new(config: CircuitBreakerConfig) -> Self {
        let now = Instant::now();
        Self {
            config,
            state: Arc::new(RwLock::new(CircuitBreakerState {
                state: CircuitState::Closed,
                failure_count: 0,
                success_count: 0,
                last_state_change: now,
                window_start: now,
            })),
        }
    }

    /// Create with default configuration
    pub fn with_defaults() -> Self {
        Self::new(CircuitBreakerConfig::default())
    }

    /// Check if request is allowed
    pub async fn is_request_allowed(&self) -> bool {
        let mut state = self.state.write().await;

        match state.state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                // Check if timeout elapsed to move to half-open
                let elapsed = Instant::now().duration_since(state.last_state_change);
                if elapsed >= self.config.timeout {
                    state.state = CircuitState::HalfOpen;
                    state.success_count = 0;
                    state.last_state_change = Instant::now();
                    true
                } else {
                    false
                }
            }
            CircuitState::HalfOpen => {
                // Allow limited requests in half-open state
                true
            }
        }
    }

    /// Record successful operation
    pub async fn record_success(&self) {
        let mut state = self.state.write().await;

        match state.state {
            CircuitState::Closed => {
                // Reset failure count on success
                if state.failure_count > 0 {
                    state.failure_count = 0;
                    state.window_start = Instant::now();
                }
            }
            CircuitState::HalfOpen => {
                state.success_count += 1;

                // Close circuit if success threshold reached
                if state.success_count >= self.config.success_threshold {
                    state.state = CircuitState::Closed;
                    state.failure_count = 0;
                    state.success_count = 0;
                    state.last_state_change = Instant::now();
                    state.window_start = Instant::now();
                    tracing::info!("Circuit breaker closed after successful recovery");
                }
            }
            CircuitState::Open => {
                // Shouldn't happen, but reset if it does
            }
        }
    }

    /// Record failed operation
    pub async fn record_failure(&self) {
        let mut state = self.state.write().await;

        let now = Instant::now();

        // Reset window if expired
        if now.duration_since(state.window_start) > self.config.window_duration {
            state.failure_count = 0;
            state.window_start = now;
        }

        match state.state {
            CircuitState::Closed => {
                state.failure_count += 1;

                // Open circuit if failure threshold exceeded
                if state.failure_count >= self.config.failure_threshold {
                    state.state = CircuitState::Open;
                    state.last_state_change = now;
                    tracing::warn!(
                        "Circuit breaker opened after {} failures",
                        state.failure_count
                    );
                }
            }
            CircuitState::HalfOpen => {
                // Go back to open on any failure in half-open
                state.state = CircuitState::Open;
                state.failure_count += 1;
                state.success_count = 0;
                state.last_state_change = now;
                tracing::warn!("Circuit breaker re-opened after failure in half-open state");
            }
            CircuitState::Open => {
                // Already open, increment counter
                state.failure_count += 1;
            }
        }
    }

    /// Get current state
    pub async fn get_state(&self) -> CircuitState {
        let state = self.state.read().await;
        state.state.clone()
    }

    /// Get failure count
    pub async fn get_failure_count(&self) -> u32 {
        let state = self.state.read().await;
        state.failure_count
    }

    /// Reset circuit breaker to closed state
    pub async fn reset(&self) {
        let mut state = self.state.write().await;
        let now = Instant::now();

        state.state = CircuitState::Closed;
        state.failure_count = 0;
        state.success_count = 0;
        state.last_state_change = now;
        state.window_start = now;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_circuit_breaker_opens_on_failures() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            success_threshold: 2,
            timeout: Duration::from_secs(1),
            window_duration: Duration::from_secs(10),
        };
        let cb = CircuitBreaker::new(config);

        assert_eq!(cb.get_state().await, CircuitState::Closed);
        assert!(cb.is_request_allowed().await);

        // Record failures
        cb.record_failure().await;
        cb.record_failure().await;
        cb.record_failure().await;

        // Circuit should be open
        assert_eq!(cb.get_state().await, CircuitState::Open);
        assert!(!cb.is_request_allowed().await);
    }

    #[tokio::test]
    async fn test_circuit_breaker_half_open_after_timeout() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            success_threshold: 2,
            timeout: Duration::from_millis(100),
            window_duration: Duration::from_secs(10),
        };
        let cb = CircuitBreaker::new(config);

        // Open the circuit
        cb.record_failure().await;
        cb.record_failure().await;
        assert_eq!(cb.get_state().await, CircuitState::Open);

        // Wait for timeout
        sleep(Duration::from_millis(150)).await;

        // Should move to half-open and allow request
        assert!(cb.is_request_allowed().await);
        assert_eq!(cb.get_state().await, CircuitState::HalfOpen);
    }

    #[tokio::test]
    async fn test_circuit_breaker_closes_on_success() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            success_threshold: 2,
            timeout: Duration::from_millis(100),
            window_duration: Duration::from_secs(10),
        };
        let cb = CircuitBreaker::new(config);

        // Open the circuit
        cb.record_failure().await;
        cb.record_failure().await;
        assert_eq!(cb.get_state().await, CircuitState::Open);

        // Wait for timeout
        sleep(Duration::from_millis(150)).await;
        assert!(cb.is_request_allowed().await);

        // Record successes in half-open state
        cb.record_success().await;
        cb.record_success().await;

        // Should close circuit
        assert_eq!(cb.get_state().await, CircuitState::Closed);
        assert!(cb.is_request_allowed().await);
    }

    #[tokio::test]
    async fn test_circuit_breaker_reopens_on_half_open_failure() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            success_threshold: 2,
            timeout: Duration::from_millis(100),
            window_duration: Duration::from_secs(10),
        };
        let cb = CircuitBreaker::new(config);

        // Open the circuit
        cb.record_failure().await;
        cb.record_failure().await;

        // Wait for half-open
        sleep(Duration::from_millis(150)).await;
        assert!(cb.is_request_allowed().await);
        assert_eq!(cb.get_state().await, CircuitState::HalfOpen);

        // Fail in half-open state
        cb.record_failure().await;

        // Should go back to open
        assert_eq!(cb.get_state().await, CircuitState::Open);
        assert!(!cb.is_request_allowed().await);
    }
}
