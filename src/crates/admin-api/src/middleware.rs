//! Middleware for Admin API
//!
//! Implements security controls including authentication, rate limiting,
//! audit logging, and request validation per T-S-F-08.02.01.05

use crate::{
    auth::{ApiKeyStore, AuthContext},
    ApiError,
};
use axum::{
    extract::{Request, State},
    http::HeaderMap,
    middleware::Next,
    response::Response,
};
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use tracing::{info, warn};
use uuid::Uuid;

/// Rate limiter using token bucket algorithm
pub struct RateLimiter {
    buckets: Arc<RwLock<HashMap<String, TokenBucket>>>,
    capacity: u32,
    refill_rate: u32,
}

struct TokenBucket {
    tokens: u32,
    last_refill: Instant,
}

impl RateLimiter {
    pub fn new(capacity: u32, refill_rate_per_minute: u32) -> Self {
        Self {
            buckets: Arc::new(RwLock::new(HashMap::new())),
            capacity,
            refill_rate: refill_rate_per_minute,
        }
    }

    pub async fn check_rate_limit(&self, key: &str) -> bool {
        let mut buckets = self.buckets.write().await;

        let bucket = buckets
            .entry(key.to_string())
            .or_insert_with(|| TokenBucket {
                tokens: self.capacity,
                last_refill: Instant::now(),
            });

        // Refill tokens based on time elapsed
        let now = Instant::now();
        let elapsed = now.duration_since(bucket.last_refill);
        let refill_amount = (elapsed.as_secs_f64() / 60.0 * self.refill_rate as f64) as u32;

        if refill_amount > 0 {
            bucket.tokens = (bucket.tokens + refill_amount).min(self.capacity);
            bucket.last_refill = now;
        }

        // Check if we have tokens available
        if bucket.tokens > 0 {
            bucket.tokens -= 1;
            true
        } else {
            false
        }
    }
}

/// Authentication middleware
pub async fn auth_middleware(
    State(key_store): State<Arc<ApiKeyStore>>,
    headers: HeaderMap,
    mut req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    // Extract API key from Authorization header
    let auth_header = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::Unauthorized("Missing Authorization header".to_string()))?;

    // Check for "Bearer <token>" format
    let api_key = if let Some(key) = auth_header.strip_prefix("Bearer ") {
        key
    } else {
        return Err(ApiError::Unauthorized(
            "Invalid Authorization header format. Use: Bearer <api-key>".to_string(),
        ));
    };

    // Verify API key
    let verified_key = key_store.verify_key(api_key).await?;

    // Extract client IP
    let client_ip = headers
        .get("X-Forwarded-For")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    // Create auth context
    let auth_context = AuthContext {
        api_key: verified_key.clone(),
        request_id: Uuid::new_v4(),
        client_ip: client_ip.clone(),
        timestamp: Utc::now(),
    };

    // Log authentication
    info!(
        request_id = %auth_context.request_id,
        api_key_id = %verified_key.id,
        api_key_name = %verified_key.name,
        client_ip = %client_ip,
        "API request authenticated"
    );

    // Insert auth context into request extensions
    req.extensions_mut().insert(auth_context);

    Ok(next.run(req).await)
}

/// Rate limiting middleware
pub async fn rate_limit_middleware(
    State(rate_limiter): State<Arc<RateLimiter>>,
    req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    // Extract auth context (should be set by auth middleware)
    let auth_context = req
        .extensions()
        .get::<AuthContext>()
        .ok_or_else(|| ApiError::Internal("Auth context not found".to_string()))?;

    let rate_limit_key = format!("api_key_{}", auth_context.api_key.id);

    if !rate_limiter.check_rate_limit(&rate_limit_key).await {
        warn!(
            api_key_id = %auth_context.api_key.id,
            client_ip = %auth_context.client_ip,
            "Rate limit exceeded"
        );
        return Err(ApiError::RateLimitExceeded);
    }

    Ok(next.run(req).await)
}

/// Audit logging middleware
pub async fn audit_middleware(req: Request, next: Next) -> Response {
    let method = req.method().clone();
    let uri = req.uri().clone();

    // Extract auth context if available
    let auth_context = req.extensions().get::<AuthContext>().cloned();

    let start = Instant::now();
    let response = next.run(req).await;
    let duration = start.elapsed();

    // Log the request
    if let Some(ctx) = auth_context {
        info!(
            request_id = %ctx.request_id,
            method = %method,
            uri = %uri,
            api_key_id = %ctx.api_key.id,
            client_ip = %ctx.client_ip,
            status = %response.status(),
            duration_ms = %duration.as_millis(),
            "Admin API request completed"
        );
    } else {
        warn!(
            method = %method,
            uri = %uri,
            status = %response.status(),
            duration_ms = %duration.as_millis(),
            "Unauthenticated request"
        );
    }

    response
}

/// Security headers middleware
pub async fn security_headers_middleware(req: Request, next: Next) -> Response {
    let mut response = next.run(req).await;

    let headers = response.headers_mut();

    // Add security headers
    headers.insert("X-Content-Type-Options", "nosniff".parse().unwrap());
    headers.insert("X-Frame-Options", "DENY".parse().unwrap());
    headers.insert("X-XSS-Protection", "1; mode=block".parse().unwrap());
    headers.insert(
        "Strict-Transport-Security",
        "max-age=31536000; includeSubDomains".parse().unwrap(),
    );
    headers.insert(
        "Content-Security-Policy",
        "default-src 'none'; frame-ancestors 'none'"
            .parse()
            .unwrap(),
    );
    headers.insert("Referrer-Policy", "no-referrer".parse().unwrap());

    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rate_limiter() {
        let limiter = RateLimiter::new(5, 60);

        // First 5 requests should succeed
        for _ in 0..5 {
            assert!(limiter.check_rate_limit("test").await);
        }

        // 6th request should fail
        assert!(!limiter.check_rate_limit("test").await);
    }
}
