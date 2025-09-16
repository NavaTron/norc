//! Rate limiting primitives for the NavaTron transport layer
//!
//! Provides lightweight, allocation-conscious token bucket and moving window
//! counters for protecting server resources against abusive clients. These are
//! scaffolds (not yet wired) to be integrated into connection acceptance and
//! per-session message dispatch pipelines.
//!
//! Design goals:
//! - Lock-free fast path for single-threaded usage (atomic counters)
//! - Deterministic refill using monotonic time (no background task required)
//! - Configurable burst capacity and sustained rate
//! - Extensible classification (per-IP, per-user, per-session) via caller-held keys
//!
//! Future work:
//! - Sliding window for adaptive penalties
//! - Global leaky bucket for aggregate shaping
//! - Integration with metrics (expose saturation, drops)

use std::time::{Duration, Instant};
use std::sync::atomic::{AtomicU64, Ordering};
use std::fmt;

/// Simple token bucket rate limiter (single-producer orientation)
#[derive(Debug)]
pub struct TokenBucket {
    capacity: u64,
    refill_per_sec: u64,
    tokens: AtomicU64,
    // Last refill instant in monotonic nanos (to avoid Instant serialization issues)
    last_refill_ns: AtomicU64,
}

impl TokenBucket {
    /// Create a new token bucket
    pub fn new(capacity: u64, refill_per_sec: u64) -> Self {
        let now = monotonic_ns();
        Self {
            capacity,
            refill_per_sec,
            tokens: AtomicU64::new(capacity),
            last_refill_ns: AtomicU64::new(now),
        }
    }

    /// Try to consume `n` tokens, returning true if successful.
    pub fn try_consume(&self, n: u64) -> bool {
        self.refill_if_needed();
        loop {
            let current = self.tokens.load(Ordering::Relaxed);
            if current < n { return false; }
            let new = current - n;
            if self.tokens.compare_exchange(current, new, Ordering::SeqCst, Ordering::Relaxed).is_ok() {
                return true;
            }
        }
    }

    /// Peek current token count after lazy refill.
    pub fn tokens(&self) -> u64 { self.refill_if_needed(); self.tokens.load(Ordering::Relaxed) }

    fn refill_if_needed(&self) {
        let now = monotonic_ns();
        let last = self.last_refill_ns.load(Ordering::Relaxed);
        if now <= last { return; }
        let elapsed_ns = now - last;
        if self.refill_per_sec == 0 { return; }
        let ns_per_token = 1_000_000_000u64 / self.refill_per_sec.max(1);
        let to_add = elapsed_ns / ns_per_token;
        if to_add == 0 { return; }
        let new_last = last + to_add * ns_per_token;
        if self.last_refill_ns.compare_exchange(last, new_last, Ordering::SeqCst, Ordering::Relaxed).is_ok() {
            // Apply refill
            self.tokens.fetch_update(Ordering::SeqCst, Ordering::Relaxed, |current| {
                let updated = (current.saturating_add(to_add)).min(self.capacity);
                Some(updated)
            }).ok();
        }
    }
}

/// Moving window counter (fixed-size window segmented) - placeholder
#[derive(Debug)]
pub struct MovingWindowCounter {
    window: Duration,
    _resolution: Duration,
    _count: AtomicU64,
}

impl MovingWindowCounter {
    /// Create a new moving window counter (scaffold)
    pub fn new(window: Duration, resolution: Duration) -> Self {
        Self { window, _resolution: resolution, _count: AtomicU64::new(0) }
    }

    /// Record an event (placeholder)
    pub fn record(&self) { self._count.fetch_add(1, Ordering::Relaxed); }

    /// Approximate count (placeholder)
    pub fn approximate(&self) -> u64 { self._count.load(Ordering::Relaxed) }
}

fn monotonic_ns() -> u64 { Instant::now().elapsed().as_nanos() as u64 }

impl fmt::Display for TokenBucket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TokenBucket(capacity={}, tokens={}, refill_per_sec={})", self.capacity, self.tokens(), self.refill_per_sec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;    

    #[test]
    fn test_token_bucket_basic() {
        let bucket = TokenBucket::new(10, 10); // 10 tokens per second
        assert!(bucket.try_consume(5));
        assert!(bucket.tokens() <= 5);
    }

    #[test]
    fn test_token_bucket_refill() {
        let bucket = TokenBucket::new(2, 2); // 2 tokens/sec
        assert!(bucket.try_consume(2));
        assert!(!bucket.try_consume(1));
        thread::sleep(Duration::from_millis(600));
        assert!(bucket.try_consume(1));
    }
}
