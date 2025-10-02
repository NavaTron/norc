//! Token Bucket Rate Limiter
//!
//! Implements token bucket algorithm for rate limiting per SERVER_REQUIREMENTS F-01.04.01.01
//! Default: 100 messages/second per connection

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Rate limiter configuration
#[derive(Debug, Clone)]
pub struct RateLimiterConfig {
    /// Maximum tokens (burst capacity)
    pub max_tokens: u32,

    /// Refill rate (tokens per second)
    pub refill_rate: u32,

    /// Refill interval
    pub refill_interval: Duration,
}

impl Default for RateLimiterConfig {
    fn default() -> Self {
        Self {
            max_tokens: 100,  // 100 message burst
            refill_rate: 100, // 100 messages/second
            refill_interval: Duration::from_secs(1),
        }
    }
}

/// Token bucket state for a single entity (connection, IP, etc.)
#[derive(Debug, Clone)]
struct TokenBucket {
    /// Current number of tokens
    tokens: f64,

    /// Maximum tokens
    max_tokens: u32,

    /// Last refill time
    last_refill: Instant,

    /// Refill rate (tokens per second)
    refill_rate: u32,
}

impl TokenBucket {
    fn new(config: &RateLimiterConfig) -> Self {
        Self {
            tokens: config.max_tokens as f64,
            max_tokens: config.max_tokens,
            last_refill: Instant::now(),
            refill_rate: config.refill_rate,
        }
    }

    /// Refill tokens based on elapsed time
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill);
        let elapsed_secs = elapsed.as_secs_f64();

        // Calculate tokens to add
        let tokens_to_add = elapsed_secs * self.refill_rate as f64;

        // Add tokens up to max
        self.tokens = (self.tokens + tokens_to_add).min(self.max_tokens as f64);
        self.last_refill = now;
    }

    /// Try to consume tokens
    fn try_consume(&mut self, tokens: u32) -> bool {
        self.refill();

        if self.tokens >= tokens as f64 {
            self.tokens -= tokens as f64;
            true
        } else {
            false
        }
    }

    /// Get remaining tokens
    fn available_tokens(&mut self) -> u32 {
        self.refill();
        self.tokens.floor() as u32
    }
}

/// Token bucket rate limiter
pub struct RateLimiter {
    config: RateLimiterConfig,
    buckets: Arc<RwLock<HashMap<String, TokenBucket>>>,
}

impl RateLimiter {
    /// Create a new rate limiter
    pub fn new(config: RateLimiterConfig) -> Self {
        Self {
            config,
            buckets: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create with default configuration (100 msg/sec)
    pub fn with_defaults() -> Self {
        Self::new(RateLimiterConfig::default())
    }

    /// Check if request is allowed for given key (connection ID, IP, etc.)
    pub async fn check_rate_limit(&self, key: &str) -> bool {
        self.check_rate_limit_with_tokens(key, 1).await
    }

    /// Check rate limit with specific token cost
    pub async fn check_rate_limit_with_tokens(&self, key: &str, tokens: u32) -> bool {
        let mut buckets = self.buckets.write().await;

        let bucket = buckets
            .entry(key.to_string())
            .or_insert_with(|| TokenBucket::new(&self.config));

        bucket.try_consume(tokens)
    }

    /// Get available tokens for a key
    pub async fn available_tokens(&self, key: &str) -> u32 {
        let mut buckets = self.buckets.write().await;

        let bucket = buckets
            .entry(key.to_string())
            .or_insert_with(|| TokenBucket::new(&self.config));

        bucket.available_tokens()
    }

    /// Remove bucket for a key (cleanup on disconnect)
    pub async fn remove(&self, key: &str) {
        let mut buckets = self.buckets.write().await;
        buckets.remove(key);
    }

    /// Get number of tracked buckets
    pub async fn bucket_count(&self) -> usize {
        let buckets = self.buckets.read().await;
        buckets.len()
    }

    /// Clear all buckets (for testing)
    pub async fn clear(&self) {
        let mut buckets = self.buckets.write().await;
        buckets.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_rate_limit_allows_within_limit() {
        let config = RateLimiterConfig {
            max_tokens: 10,
            refill_rate: 10,
            refill_interval: Duration::from_secs(1),
        };
        let limiter = RateLimiter::new(config);

        // First 10 requests should succeed
        for _ in 0..10 {
            assert!(limiter.check_rate_limit("conn1").await);
        }

        // 11th request should fail (no tokens left)
        assert!(!limiter.check_rate_limit("conn1").await);
    }

    #[tokio::test]
    async fn test_rate_limit_refills_over_time() {
        let config = RateLimiterConfig {
            max_tokens: 5,
            refill_rate: 10, // 10 tokens per second
            refill_interval: Duration::from_secs(1),
        };
        let limiter = RateLimiter::new(config);

        // Consume all tokens
        for _ in 0..5 {
            assert!(limiter.check_rate_limit("conn1").await);
        }
        assert!(!limiter.check_rate_limit("conn1").await);

        // Wait for refill (0.5 seconds = 5 tokens at 10/sec rate)
        sleep(Duration::from_millis(500)).await;

        // Should have ~5 tokens available
        let available = limiter.available_tokens("conn1").await;
        assert!(
            available >= 4 && available <= 5,
            "Expected ~5 tokens, got {}",
            available
        );
    }

    #[tokio::test]
    async fn test_rate_limit_per_connection() {
        let limiter = RateLimiter::with_defaults();

        // Different connections have independent limits
        assert!(limiter.check_rate_limit("conn1").await);
        assert!(limiter.check_rate_limit("conn2").await);

        assert_eq!(limiter.bucket_count().await, 2);
    }

    #[tokio::test]
    async fn test_remove_bucket() {
        let limiter = RateLimiter::with_defaults();

        limiter.check_rate_limit("conn1").await;
        assert_eq!(limiter.bucket_count().await, 1);

        limiter.remove("conn1").await;
        assert_eq!(limiter.bucket_count().await, 0);
    }
}
