//! Error types for the Admin API

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use thiserror::Error;

/// Result type for API operations
pub type ApiResult<T> = Result<T, ApiError>;

/// API error types
#[derive(Debug, Error)]
pub enum ApiError {
    #[error("Authentication failed: {0}")]
    Unauthorized(String),

    #[error("Permission denied: {0}")]
    Forbidden(String),

    #[error("Resource not found: {0}")]
    NotFound(String),

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("Internal server error: {0}")]
    Internal(String),

    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Persistence error: {0}")]
    Persistence(#[from] norc_persistence::error::PersistenceError),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Configuration error: {0}")]
    Configuration(String),
}

/// Error response structure
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error_type) = match &self {
            ApiError::Unauthorized(_) => (StatusCode::UNAUTHORIZED, "unauthorized"),
            ApiError::Forbidden(_) => (StatusCode::FORBIDDEN, "forbidden"),
            ApiError::NotFound(_) => (StatusCode::NOT_FOUND, "not_found"),
            ApiError::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request"),
            ApiError::Conflict(_) => (StatusCode::CONFLICT, "conflict"),
            ApiError::RateLimitExceeded => (StatusCode::TOO_MANY_REQUESTS, "rate_limit_exceeded"),
            ApiError::Internal(_) | ApiError::Database(_) | ApiError::Persistence(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
            }
            ApiError::Validation(_) => (StatusCode::BAD_REQUEST, "validation_error"),
            ApiError::Configuration(_) => (StatusCode::BAD_REQUEST, "configuration_error"),
        };

        let error_response = ErrorResponse {
            error: error_type.to_string(),
            message: self.to_string(),
            details: None,
        };

        (status, Json(error_response)).into_response()
    }
}
