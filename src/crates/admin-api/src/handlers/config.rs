//! Configuration management handlers

use crate::{auth::AuthContext, models::*, rbac::Permission, AdminApiState, ApiResult, ApiError};
use axum::{extract::State, Extension, Json};
use chrono::Utc;
use norc_config::ServerConfig;
use serde_json::{json, Value};

/// Get current configuration (sanitized - secrets removed)
pub async fn get_config(
    State(_state): State<AdminApiState>,
    Extension(auth): Extension<AuthContext>,
) -> ApiResult<Json<Value>> {
    auth.require_permission(Permission::ConfigRead)?;
    
    // TODO: Get actual configuration from ServerCore when available
    // For now, return a mock sanitized configuration structure
    
    let config = json!({
        "organization_id": "example-org",
        "network": {
            "bind_address": "0.0.0.0",
            "bind_port": 8883,
            "federation_address": "0.0.0.0",
            "federation_port": 8884,
            "enable_tls": true,
            "enable_websocket": true,
            "enable_quic": false,
            // Note: tls_cert_path and tls_key_path intentionally omitted for security
        },
        "security": {
            "organization_id": "example-org",
            "default_trust_level": "authenticated",
            "enable_pq_crypto": false,
            "key_rotation_interval_secs": 86400,
            "strict_cert_validation": true,
            "enable_hsm": false,
        },
        "observability": {
            "log_level": "info",
            "log_format": "json",
            "enable_metrics": true,
            "metrics_port": 9090,
            "enable_tracing": false,
            "tracing_sample_rate": 1.0,
        },
        "federation": {
            "enable_federation": true,
            "max_partners": 100,
            "sync_interval_secs": 300,
        },
        "limits": {
            "max_connections": 10000,
            "max_message_size_bytes": 16777216,
            "rate_limit_per_connection": 100,
            "connection_timeout_secs": 300,
        },
        "daemon": {
            "auto_restart": true,
            "max_restart_attempts": 3,
            "restart_cooldown_secs": 60,
        },
        "storage": {
            "data_dir": "/var/lib/norc",
            "max_db_size_mb": 10240,
        },
    });
    
    Ok(Json(config))
}

/// Update configuration
pub async fn update_config(
    State(_state): State<AdminApiState>,
    Extension(auth): Extension<AuthContext>,
    Json(request): Json<ConfigUpdateRequest>,
) -> ApiResult<Json<ConfigResponse>> {
    auth.require_permission(Permission::ConfigUpdate)?;
    
    // Validate the configuration section and key
    validate_config_update(&request.section, &request.key, &request.value)?;
    
    // TODO: Apply configuration update to ServerCore when available
    // For now, return success response with mock data
    
    Ok(Json(ConfigResponse {
        section: request.section,
        key: request.key,
        value: request.value,
        version: 1,
        updated_at: Utc::now(),
        updated_by: auth.api_key.id.to_string(),
    }))
}

/// Validate configuration
pub async fn validate_config(
    State(_state): State<AdminApiState>,
    Extension(auth): Extension<AuthContext>,
    Json(config): Json<Value>,
) -> ApiResult<Json<ConfigValidationResponse>> {
    auth.require_permission(Permission::ConfigValidate)?;
    
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    
    // Try to deserialize into ServerConfig to validate structure
    match serde_json::from_value::<ServerConfig>(config.clone()) {
        Ok(server_config) => {
            // Perform additional validation
            if let Err(e) = server_config.validate() {
                errors.push(format!("Configuration validation failed: {}", e));
            }
            
            // Check for warnings
            if server_config.security.enable_pq_crypto {
                warnings.push("Post-quantum cryptography is experimental".to_string());
            }
            
            if !server_config.network.enable_tls {
                warnings.push("TLS is disabled - connections will not be encrypted".to_string());
            }
            
            if server_config.limits.max_connections > 50000 {
                warnings.push("Very high connection limit may impact performance".to_string());
            }
        }
        Err(e) => {
            errors.push(format!("Invalid configuration structure: {}", e));
        }
    }
    
    let valid = errors.is_empty();
    
    Ok(Json(ConfigValidationResponse {
        valid,
        errors,
        warnings,
    }))
}

/// Validate individual config update
fn validate_config_update(section: &str, key: &str, value: &Value) -> Result<(), ApiError> {
    match section {
        "network" => validate_network_config(key, value)?,
        "security" => validate_security_config(key, value)?,
        "observability" => validate_observability_config(key, value)?,
        "federation" => validate_federation_config(key, value)?,
        "limits" => validate_limits_config(key, value)?,
        _ => {
            return Err(ApiError::BadRequest(format!(
                "Unknown configuration section: {}",
                section
            )));
        }
    }
    Ok(())
}

fn validate_network_config(key: &str, value: &Value) -> Result<(), ApiError> {
    match key {
        "bind_port" | "federation_port" => {
            if let Some(port) = value.as_u64() {
                if port == 0 || port > 65535 {
                    return Err(ApiError::BadRequest("Port must be between 1 and 65535".to_string()));
                }
            } else {
                return Err(ApiError::BadRequest("Port must be a number".to_string()));
            }
        }
        "enable_tls" | "enable_websocket" | "enable_quic" => {
            if !value.is_boolean() {
                return Err(ApiError::BadRequest("Value must be a boolean".to_string()));
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_security_config(key: &str, value: &Value) -> Result<(), ApiError> {
    match key {
        "key_rotation_interval_secs" => {
            if let Some(secs) = value.as_u64() {
                if secs < 3600 {
                    return Err(ApiError::BadRequest(
                        "Key rotation interval must be at least 1 hour".to_string(),
                    ));
                }
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_observability_config(key: &str, value: &Value) -> Result<(), ApiError> {
    match key {
        "log_level" => {
            if let Some(level) = value.as_str() {
                if !["error", "warn", "info", "debug", "trace"].contains(&level) {
                    return Err(ApiError::BadRequest(
                        "Invalid log level. Must be: error, warn, info, debug, or trace".to_string(),
                    ));
                }
            }
        }
        "log_format" => {
            if let Some(format) = value.as_str() {
                if !["json", "pretty", "compact"].contains(&format) {
                    return Err(ApiError::BadRequest(
                        "Invalid log format. Must be: json, pretty, or compact".to_string(),
                    ));
                }
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_federation_config(key: &str, value: &Value) -> Result<(), ApiError> {
    match key {
        "max_partners" => {
            if let Some(max) = value.as_u64() {
                if max == 0 || max > 10000 {
                    return Err(ApiError::BadRequest(
                        "max_partners must be between 1 and 10000".to_string(),
                    ));
                }
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_limits_config(key: &str, value: &Value) -> Result<(), ApiError> {
    match key {
        "max_connections" => {
            if let Some(max) = value.as_u64() {
                if max == 0 {
                    return Err(ApiError::BadRequest(
                        "max_connections must be greater than 0".to_string(),
                    ));
                }
            }
        }
        "max_message_size_bytes" => {
            if let Some(size) = value.as_u64() {
                if size > 100_000_000 {
                    // 100 MB limit
                    return Err(ApiError::BadRequest(
                        "max_message_size_bytes cannot exceed 100MB".to_string(),
                    ));
                }
            }
        }
        _ => {}
    }
    Ok(())
}
