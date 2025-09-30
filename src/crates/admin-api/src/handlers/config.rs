//! Configuration management handlers

use crate::{auth::AuthContext, models::*, rbac::Permission, AdminApiState, ApiResult, ApiError};
use axum::{extract::State, Extension, Json};
use chrono::Utc;
use norc_config::ServerConfig;
use serde_json::{json, Value};

/// Get current configuration (sanitized - secrets removed)
pub async fn get_config(
    State(state): State<AdminApiState>,
    Extension(auth): Extension<AuthContext>,
) -> ApiResult<Json<Value>> {
    auth.require_permission(Permission::ConfigRead)?;
    
    // Get actual configuration from state (with sensitive fields removed)
    let cfg = &state.server_config;
    
    let config = json!({
        "organization_id": cfg.security.organization_id,
        "network": {
            "bind_address": cfg.network.bind_address,
            "bind_port": cfg.network.bind_port,
            "federation_address": cfg.network.federation_address,
            "federation_port": cfg.network.federation_port,
            "enable_tls": cfg.network.enable_tls,
            "enable_websocket": cfg.network.enable_websocket,
            "enable_quic": cfg.network.enable_quic,
            // Note: tls_cert_path and tls_key_path intentionally omitted for security
        },
        "security": {
            "organization_id": cfg.security.organization_id,
            "default_trust_level": format!("{:?}", cfg.security.default_trust_level),
            "enable_pq_crypto": cfg.security.enable_pq_crypto,
            "key_rotation_interval_secs": cfg.security.key_rotation_interval_secs,
            "strict_cert_validation": cfg.security.strict_cert_validation,
            "enable_hsm": cfg.security.enable_hsm,
        },
        "observability": {
            "log_level": cfg.observability.log_level,
            "log_format": cfg.observability.log_format,
            "enable_metrics": cfg.observability.enable_metrics,
            "metrics_port": cfg.observability.metrics_port,
            "enable_tracing": cfg.observability.enable_tracing,
            "tracing_sample_rate": cfg.observability.tracing_sample_rate,
        },
        "federation": {
            "enable_federation": cfg.federation.enable_federation,
            "discovery_method": &cfg.federation.discovery_method,
            "partner_count": cfg.federation.partners.len(),
        },
        "limits": {
            "max_connections": cfg.limits.max_connections,
            "max_message_size": cfg.limits.max_message_size,
            "rate_limit_per_connection": cfg.limits.rate_limit_per_connection,
            "max_memory_per_connection": cfg.limits.max_memory_per_connection,
            "worker_threads": cfg.limits.worker_threads,
        },
        "daemon": {
            "daemonize": cfg.daemon.daemonize,
            "auto_restart": cfg.daemon.auto_restart,
            "max_restarts": cfg.daemon.max_restarts,
            "restart_cooldown_secs": cfg.daemon.restart_cooldown_secs,
        },
        "storage": {
            "data_dir": cfg.storage.data_dir.display().to_string(),
            "enable_persistence": cfg.storage.enable_persistence,
            "snapshot_interval_secs": cfg.storage.snapshot_interval_secs,
            "max_snapshots": cfg.storage.max_snapshots,
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
