# NORC Admin API

RESTful administrative API for NORC server management with enterprise-grade security.

## Features

- 🔐 **Secure Authentication** - API keys with SHA-256 hashing, optional mTLS
- 👥 **Role-Based Access Control** - 5 roles, 23 fine-grained permissions
- 🛡️ **Security Hardening** - Rate limiting, audit logging, secure headers
- 📊 **Comprehensive Management** - Users, devices, config, federation, monitoring
- 📝 **Full Audit Trail** - All administrative actions logged with correlation IDs
- ⚡ **High Performance** - Async/await, efficient middleware stack

## Quick Start

### Basic Usage

```rust
use norc_admin_api::{AdminApiConfig, AdminApiState, build_router};
use norc_persistence::Database;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize database
    let database = Arc::new(Database::new(db_config).await?);
    
    // Configure admin API
    let config = AdminApiConfig {
        bind_address: "127.0.0.1:8443".to_string(),
        enable_mtls: true,
        rate_limit_per_minute: 100,
        ..Default::default()
    };
    
    // Create API state
    let state = AdminApiState { database, config: config.clone() };
    
    // Build router
    let app = build_router(state);
    
    // Start server
    let listener = tokio::net::TcpListener::bind(&config.bind_address).await?;
    axum::serve(listener, app).await?;
    
    Ok(())
}
```

### Creating an API Key

```rust
use norc_admin_api::auth::ApiKey;
use norc_admin_api::rbac::Role;

let (api_key, raw_key) = ApiKey::new(
    "Production Admin".to_string(),
    vec![Role::SuperAdmin],
    Some("org1".to_string()),
);

println!("API Key: {}", raw_key); // Save this securely!
```

### Making Authenticated Requests

```bash
# List users
curl -H "Authorization: Bearer norc_<your-api-key>" \
  https://admin.norc.example.com/api/v1/users

# Create user
curl -X POST https://admin.norc.example.com/api/v1/users \
  -H "Authorization: Bearer norc_<your-api-key>" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john.doe",
    "email": "john@example.com",
    "organization_id": "org1"
  }'
```

## API Endpoints

### Health & Status
- `GET /health` - Health check (public)
- `GET /ready` - Readiness probe (public)

### User Management
- `GET /api/v1/users` - List users
- `POST /api/v1/users` - Create user
- `GET /api/v1/users/:id` - Get user
- `PUT /api/v1/users/:id` - Update user
- `DELETE /api/v1/users/:id` - Delete user

### Device Management
- `GET /api/v1/devices` - List devices
- `POST /api/v1/devices` - Register device
- `DELETE /api/v1/devices/:id` - Revoke device

### Configuration
- `GET /api/v1/config` - Get config
- `PUT /api/v1/config` - Update config
- `POST /api/v1/config/validate` - Validate config

### Monitoring
- `GET /api/v1/server/status` - Server status
- `GET /api/v1/metrics` - Performance metrics

### Federation
- `GET /api/v1/federation/partners` - List partners
- `POST /api/v1/federation/partners` - Add partner
- `DELETE /api/v1/federation/partners/:id` - Remove partner

### Audit Logs
- `GET /api/v1/audit/logs` - Query logs
- `GET /api/v1/audit/export` - Export logs

### API Keys
- `GET /api/v1/api-keys` - List keys
- `POST /api/v1/api-keys` - Create key
- `POST /api/v1/api-keys/:id/revoke` - Revoke key
- `DELETE /api/v1/api-keys/:id` - Delete key

## RBAC Roles

| Role | Description | Permissions |
|------|-------------|-------------|
| SuperAdmin | Full system access | All (24 permissions) |
| OrgAdmin | User/device management | User*, Device*, Config.Read, Metrics.Read |
| Auditor | Read-only audit access | *. Read, Audit.Export, Compliance.Report |
| Operator | Server operations | Server.*, Metrics.*, Logs.Read |
| FederationManager | Federation management | Federation.*, Config.Read, Metrics.Read |

## Security Features

### Authentication
- API key authentication with SHA-256 hashing
- Constant-time comparison (timing attack prevention)
- Optional mutual TLS (mTLS)
- Session expiration and timeout

### Authorization
- Role-based access control (RBAC)
- 23 fine-grained permissions
- Per-request permission checks
- No privilege inheritance

### Rate Limiting
- Token bucket algorithm
- Per-API-key limits
- Configurable refill rate (default: 100/min)
- HTTP 429 responses with retry headers

### Audit Logging
- All requests logged with UUIDs
- Client IP, API key, duration tracking
- Resource change logging
- Tamper-evident audit trail (planned)

### Security Headers
```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Strict-Transport-Security: max-age=31536000
Content-Security-Policy: default-src 'none'
```

## Configuration

```toml
[admin_api]
# Network
bind_address = "127.0.0.1:8443"

# Authentication
enable_mtls = true
client_ca_path = "/etc/norc/client-ca.pem"
api_keys_path = "/etc/norc/api-keys.json"
session_timeout_secs = 3600

# Rate Limiting
rate_limit_per_minute = 100

# CORS (development only)
enable_cors = false
```

## Error Responses

```json
{
  "error": "unauthorized",
  "message": "Invalid API key",
  "details": null
}
```

**Status Codes**:
- `200` - Success
- `400` - Bad Request (validation error)
- `401` - Unauthorized (authentication failed)
- `403` - Forbidden (insufficient permissions)
- `404` - Not Found
- `409` - Conflict
- `429` - Too Many Requests (rate limited)
- `500` - Internal Server Error

## Testing

```bash
# Run unit tests
cargo test -p norc-admin-api

# Run with coverage
cargo tarpaulin -p norc-admin-api
```

## Documentation

- [Security Hardening Guide](../../ADMIN_API_SECURITY.md)
- [Implementation Summary](../../ADMIN_API_IMPLEMENTATION.md)
- [Server Requirements](../../SERVER_REQUIREMENTS.md) - Epic E-08

## Compliance

Implements:
- NIST 800-53 controls: AC-2, AC-3, AC-7, AU-2, AU-3, AU-9, IA-5, SC-8, SC-13
- OWASP API Security Top 10 mitigations
- SERVER_REQUIREMENTS Epic E-04 (Security Hardening)
- SERVER_REQUIREMENTS Epic E-08 (Admin Interfaces)

## License

Apache-2.0 © 2025 NavaTron Holding B.V.
