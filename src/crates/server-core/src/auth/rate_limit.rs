//! Rate limiting for authentication
//!
//! Implements T-S-F-04.02.01.04: Account lockout and rate limiting

use crate::ServerError;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tracing::{info, warn};

/// Rate limit configuration
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum attempts per window
    pub max_attempts: u32,
    /// Time window in seconds
    pub window_secs: u64,
    /// Lockout duration in seconds after exceeding limit
    pub lockout_duration_secs: u64,
    /// Enable progressive backoff
    pub progressive_backoff: bool,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            window_secs: 60,
            lockout_duration_secs: 300, // 5 minutes
            progressive_backoff: true,
        }
    }
}

/// Rate limit state for a client
#[derive(Debug, Clone)]
struct RateLimitState {
    /// Number of attempts in current window
    attempts: u32,
    /// Window start time
    window_start: Instant,
    /// Lockout until time (if locked out)
    locked_until: Option<Instant>,
    /// Number of consecutive lockouts
    lockout_count: u32,
}

impl RateLimitState {
    fn new() -> Self {
        Self {
            attempts: 0,
            window_start: Instant::now(),
            locked_until: None,
            lockout_count: 0,
        }
    }

    fn reset_window(&mut self) {
        self.attempts = 0;
        self.window_start = Instant::now();
    }

    fn is_locked_out(&self) -> bool {
        if let Some(locked_until) = self.locked_until {
            Instant::now() < locked_until
        } else {
            false
        }
    }

    fn remaining_lockout(&self) -> Option<Duration> {
        if let Some(locked_until) = self.locked_until {
            let now = Instant::now();
            if now < locked_until {
                Some(locked_until.duration_since(now))
            } else {
                None
            }
        } else {
            None
        }
    }
}

/// Rate limiter
pub struct RateLimiter {
    config: RateLimitConfig,
    states: HashMap<String, RateLimitState>,
    /// Last cleanup time
    last_cleanup: Instant,
}

impl RateLimiter {
    /// Create a new rate limiter
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            states: HashMap::new(),
            last_cleanup: Instant::now(),
        }
    }

    /// Check rate limit for a client
    pub fn check_rate_limit(&mut self, client_id: &str) -> Result<(), ServerError> {
        // Periodic cleanup of old states
        self.cleanup_if_needed();

        let state = self
            .states
            .entry(client_id.to_string())
            .or_insert_with(RateLimitState::new);

        // Check if locked out
        if state.is_locked_out() {
            let remaining = state.remaining_lockout().unwrap();
            warn!(
                "Rate limit: client {} is locked out for {:?}",
                client_id, remaining
            );
            return Err(ServerError::RateLimitExceeded(format!(
                "Too many authentication attempts. Locked out for {} seconds",
                remaining.as_secs()
            )));
        }

        // Check if window has expired
        let window_duration = Duration::from_secs(self.config.window_secs);
        let elapsed = state.window_start.elapsed();
        
        if elapsed > window_duration {
            // Reset window
            state.reset_window();
        }

        // Increment attempt counter
        state.attempts += 1;

        // Check if limit exceeded
        if state.attempts > self.config.max_attempts {
            // Calculate lockout duration with progressive backoff
            let lockout_duration = if self.config.progressive_backoff {
                let multiplier = 2_u32.pow(state.lockout_count.min(5));
                Duration::from_secs(self.config.lockout_duration_secs * multiplier as u64)
            } else {
                Duration::from_secs(self.config.lockout_duration_secs)
            };

            state.locked_until = Some(Instant::now() + lockout_duration);
            state.lockout_count += 1;

            warn!(
                "Rate limit exceeded for client {}: {} attempts in {:?}, locked out for {:?}",
                client_id, state.attempts, elapsed, lockout_duration
            );

            return Err(ServerError::RateLimitExceeded(format!(
                "Too many authentication attempts. Locked out for {} seconds",
                lockout_duration.as_secs()
            )));
        }

        Ok(())
    }

    /// Record successful authentication (resets rate limit for client)
    pub fn record_success(&mut self, client_id: &str) {
        if let Some(state) = self.states.get_mut(client_id) {
            state.reset_window();
            state.locked_until = None;
            state.lockout_count = 0;
            info!("Rate limit reset for client {} after successful auth", client_id);
        }
    }

    /// Manually unlock a client (admin operation)
    pub fn unlock(&mut self, client_id: &str) {
        if let Some(state) = self.states.get_mut(client_id) {
            state.locked_until = None;
            state.lockout_count = 0;
            state.reset_window();
            info!("Manually unlocked client {}", client_id);
        }
    }

    /// Get remaining attempts for a client
    pub fn remaining_attempts(&self, client_id: &str) -> u32 {
        if let Some(state) = self.states.get(client_id) {
            if state.is_locked_out() {
                0
            } else {
                self.config.max_attempts.saturating_sub(state.attempts)
            }
        } else {
            self.config.max_attempts
        }
    }

    /// Cleanup old states
    fn cleanup_if_needed(&mut self) {
        const CLEANUP_INTERVAL: Duration = Duration::from_secs(300); // 5 minutes

        if self.last_cleanup.elapsed() < CLEANUP_INTERVAL {
            return;
        }

        let cleanup_threshold = Duration::from_secs(self.config.window_secs * 2);
        let now = Instant::now();

        self.states.retain(|client_id, state| {
            // Keep if locked out
            if state.is_locked_out() {
                return true;
            }

            // Keep if recently active
            let age = now.duration_since(state.window_start);
            if age < cleanup_threshold {
                return true;
            }

            // Remove old inactive states
            info!("Cleaning up rate limit state for client {}", client_id);
            false
        });

        self.last_cleanup = now;
    }

    /// Get current state count (for monitoring)
    pub fn state_count(&self) -> usize {
        self.states.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limit_basic() {
        let config = RateLimitConfig {
            max_attempts: 3,
            window_secs: 60,
            lockout_duration_secs: 10,
            progressive_backoff: false,
        };
        let mut limiter = RateLimiter::new(config);

        // First 3 attempts should succeed
        assert!(limiter.check_rate_limit("client1").is_ok());
        assert!(limiter.check_rate_limit("client1").is_ok());
        assert!(limiter.check_rate_limit("client1").is_ok());

        // 4th attempt should fail
        assert!(limiter.check_rate_limit("client1").is_err());
    }

    #[test]
    fn test_rate_limit_reset_on_success() {
        let config = RateLimitConfig {
            max_attempts: 3,
            window_secs: 60,
            lockout_duration_secs: 10,
            progressive_backoff: false,
        };
        let mut limiter = RateLimiter::new(config);

        // Use 2 attempts
        assert!(limiter.check_rate_limit("client1").is_ok());
        assert!(limiter.check_rate_limit("client1").is_ok());

        // Record success - should reset
        limiter.record_success("client1");

        // Should have full attempts again
        assert_eq!(limiter.remaining_attempts("client1"), 3);
    }

    #[test]
    fn test_rate_limit_per_client() {
        let config = RateLimitConfig::default();
        let mut limiter = RateLimiter::new(config);

        // Exhaust limit for client1
        for _ in 0..6 {
            let _ = limiter.check_rate_limit("client1");
        }

        // client2 should still have attempts
        assert!(limiter.check_rate_limit("client2").is_ok());
    }

    #[test]
    fn test_manual_unlock() {
        let config = RateLimitConfig {
            max_attempts: 2,
            window_secs: 60,
            lockout_duration_secs: 10,
            progressive_backoff: false,
        };
        let mut limiter = RateLimiter::new(config);

        // Trigger lockout
        let _ = limiter.check_rate_limit("client1");
        let _ = limiter.check_rate_limit("client1");
        assert!(limiter.check_rate_limit("client1").is_err());

        // Manual unlock
        limiter.unlock("client1");

        // Should work again
        assert!(limiter.check_rate_limit("client1").is_ok());
    }
}
