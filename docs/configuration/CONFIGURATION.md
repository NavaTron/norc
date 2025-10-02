# NORC Configuration Reference

Complete reference for NORC server and client configuration files.

## Table of Contents

1. [Configuration File Locations](#configuration-file-locations)
2. [Server Configuration](#server-configuration)
3. [Client Configuration](#client-configuration)
4. [Environment Variables](#environment-variables)
5. [Configuration Examples](#configuration-examples)
6. [Configuration Validation](#configuration-validation)

---

## Configuration File Locations

### Default Paths

**Linux**:
- Server: `/etc/norc/config.toml`
- Client: `~/.config/norc/client.toml`
- System-wide: `/etc/norc/`

**macOS**:
- Server: `/usr/local/etc/norc/config.toml`
- Client: `~/Library/Application Support/norc/client.toml`
- System-wide: `/usr/local/etc/norc/`

**Windows**:
- Server: `C:\ProgramData\NORC\config.toml`
- Client: `%APPDATA%\NORC\client.toml`
- System-wide: `C:\ProgramData\NORC\`

### Custom Configuration Path

```bash
# Specify custom configuration file
norc-server --config /path/to/custom-config.toml
norc-client --config /path/to/client-config.toml
```

---

## Server Configuration

### Complete Configuration Template

```toml
# /etc/norc/config.toml - NORC Server Configuration

#═══════════════════════════════════════════════════════════════════════════════
# SERVER CONFIGURATION
#═══════════════════════════════════════════════════════════════════════════════

[server]
# Server bind address
# Default: "0.0.0.0" (all interfaces)
address = "0.0.0.0"

# HTTP port (non-TLS)
# Default: 8080
# Set to 0 to disable HTTP
port = 8080

# HTTPS port (TLS/mTLS)
# Default: 8443
tls_port = 8443

# Server identifier (unique across deployment)
# Used for distributed tracing and metrics
# Default: hostname
server_id = "server-01"

# Organization name
# Used in server certificates and identity
# Default: none (required)
organization = "example.com"

# Maximum concurrent connections
# Default: 10000
max_connections = 10000

# Connection timeout (seconds)
# Default: 300 (5 minutes)
connection_timeout_seconds = 300

# Idle connection timeout (seconds)
# Default: 600 (10 minutes)
idle_timeout_seconds = 600

# TCP keep-alive
# Default: true
enable_keepalive = true

# Keep-alive interval (seconds)
# Default: 60
keepalive_interval_seconds = 60

# Number of worker threads
# Default: number of CPU cores
# Set to 0 for automatic detection
worker_threads = 0

# Maximum blocking threads for IO operations
# Default: 512
max_blocking_threads = 512

# Request timeout (seconds)
# Default: 30
request_timeout_seconds = 30

# Graceful shutdown timeout (seconds)
# Default: 30
shutdown_timeout_seconds = 30

#═══════════════════════════════════════════════════════════════════════════════
# TLS CONFIGURATION
#═══════════════════════════════════════════════════════════════════════════════

[tls]
# Enable TLS
# Default: true
enabled = true

# Server certificate path (PEM format)
# Required if TLS is enabled
cert_path = "/etc/norc/certs/server.pem"

# Server private key path (PEM format)
# Required if TLS is enabled
key_path = "/etc/norc/certs/server-key.pem"

# CA certificate path for client verification (PEM format)
# Required if require_client_cert is true
ca_cert_path = "/etc/norc/certs/ca.pem"

# Additional trusted CA certificates directory
# All .pem files in this directory will be loaded
# Optional
ca_certs_dir = "/etc/norc/certs/trusted-cas/"

# Require client certificates (mTLS)
# Default: true
require_client_cert = true

# Verify client certificates against CA
# Default: true
verify_client_cert = true

# Client certificate verification depth
# Default: 2
verify_depth = 2

# Minimum TLS version
# Options: "TLSv1.2", "TLSv1.3"
# Default: "TLSv1.2"
min_tls_version = "TLSv1.2"

# Maximum TLS version
# Options: "TLSv1.2", "TLSv1.3"
# Default: "TLSv1.3"
max_tls_version = "TLSv1.3"

# Cipher suites (TLS 1.2)
# Default: secure defaults
cipher_suites_tls12 = [
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
]

# Cipher suites (TLS 1.3)
# Default: secure defaults
cipher_suites_tls13 = [
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_GCM_SHA256",
    "TLS_CHACHA20_POLY1305_SHA256",
]

# Enable OCSP stapling
# Default: false
enable_ocsp_stapling = false

# OCSP staple cache TTL (hours)
# Default: 24
ocsp_staple_cache_ttl_hours = 24

# Session resumption
# Default: true
enable_session_resumption = true

# Session ticket keys
# Hex-encoded 48-byte keys for session ticket encryption
# Leave empty to generate random keys on startup
session_ticket_keys = []

# Session cache size
# Default: 1024
session_cache_size = 1024

# Enable hardware acceleration (AES-NI)
# Default: true
enable_hardware_acceleration = true

#═══════════════════════════════════════════════════════════════════════════════
# SECURITY CONFIGURATION
#═══════════════════════════════════════════════════════════════════════════════

[security]
# Enable certificate pinning
# Default: false
enable_pinning = false

# Pinned certificate fingerprints (SHA256)
# Only connections with these certificates are allowed
# Format: "SHA256:ab:cd:ef:..."
pinned_fingerprints = []

# Enable OCSP revocation checking
# Default: true
enable_ocsp = true

# Enable CRL revocation checking
# Default: true
enable_crl = true

# OCSP request timeout (seconds)
# Default: 5
ocsp_timeout_seconds = 5

# OCSP responder URL override
# Leave empty to use AIA extension from certificate
# Optional
ocsp_responder_url = ""

# CRL download timeout (seconds)
# Default: 30
crl_timeout_seconds = 30

# CRL cache directory
# Default: "/var/lib/norc/crl-cache"
crl_cache_dir = "/var/lib/norc/crl-cache"

# CRL cache TTL (hours)
# Default: 24
crl_cache_ttl_hours = 24

# Certificate validation cache TTL (seconds)
# Cache successful validation results
# Default: 300 (5 minutes)
# Set to 0 to disable caching
validation_cache_ttl_seconds = 300

# Allowed client IP addresses/ranges (CIDR notation)
# Leave empty to allow all
# Optional
allowed_ips = []

# Denied client IP addresses/ranges (CIDR notation)
# Takes precedence over allowed_ips
# Optional
denied_ips = []

# Enable audit logging
# Default: true
enable_audit_logging = true

# Audit log path
# Default: "/var/log/norc/audit.log"
audit_log_path = "/var/log/norc/audit.log"

#═══════════════════════════════════════════════════════════════════════════════
# DATABASE CONFIGURATION
#═══════════════════════════════════════════════════════════════════════════════

[database]
# Database type
# Options: "sqlite", "postgresql"
# Default: "sqlite"
type = "sqlite"

# SQLite database path
# Required if type = "sqlite"
path = "/var/lib/norc/norc.db"

# PostgreSQL connection URL
# Required if type = "postgresql"
# Format: "postgresql://user:password@host:port/database"
# url = "postgresql://norc:password@localhost:5432/norc"

# Maximum number of connections in pool
# Default: 10
max_connections = 10

# Minimum number of connections in pool
# Default: 2
min_connections = 2

# Connection timeout (seconds)
# Default: 30
connection_timeout_seconds = 30

# Connection lifetime (seconds)
# Connections are closed and reopened after this time
# Default: 3600 (1 hour)
# Set to 0 to disable
connection_lifetime_seconds = 3600

# Connection idle timeout (seconds)
# Idle connections are closed after this time
# Default: 600 (10 minutes)
connection_idle_timeout_seconds = 600

# SQLite busy timeout (milliseconds)
# How long to wait for database lock
# Default: 5000 (5 seconds)
# Only applies to SQLite
busy_timeout_ms = 5000

# SQLite journal mode
# Options: "DELETE", "WAL", "MEMORY"
# Default: "WAL" (recommended for concurrency)
# Only applies to SQLite
journal_mode = "WAL"

# SQLite synchronous mode
# Options: "OFF", "NORMAL", "FULL"
# Default: "NORMAL"
# Only applies to SQLite
synchronous = "NORMAL"

# Enable foreign keys
# Default: true
# Only applies to SQLite
foreign_keys = true

# Enable query logging
# Default: false
log_queries = false

# Slow query threshold (milliseconds)
# Log queries slower than this threshold
# Default: 1000 (1 second)
slow_query_threshold_ms = 1000

#═══════════════════════════════════════════════════════════════════════════════
# LOGGING CONFIGURATION
#═══════════════════════════════════════════════════════════════════════════════

[logging]
# Log level
# Options: "trace", "debug", "info", "warn", "error"
# Default: "info"
level = "info"

# Log format
# Options: "json", "pretty", "compact"
# Default: "json"
format = "json"

# Log output destination
# Options: "stdout", "stderr", file path
# Default: "/var/log/norc/norc.log"
output = "/var/log/norc/norc.log"

# Enable log rotation
# Default: true
rotation = true

# Maximum log file size (MB)
# Default: 100
max_size_mb = 100

# Maximum number of rotated log files
# Default: 10
max_files = 10

# Log file compression
# Default: true
compress = true

# Include timestamps in logs
# Default: true
timestamps = true

# Include source location (file:line)
# Default: false (performance impact)
source_location = false

# Include thread ID
# Default: false
thread_id = false

# Include request ID in logs
# Default: true
request_id = true

# Include span context (OpenTelemetry)
# Default: true
span_context = true

#═══════════════════════════════════════════════════════════════════════════════
# METRICS CONFIGURATION
#═══════════════════════════════════════════════════════════════════════════════

[metrics]
# Enable Prometheus metrics
# Default: true
enabled = true

# Metrics HTTP server port
# Default: 9090
port = 9090

# Metrics HTTP server address
# Default: "0.0.0.0"
address = "0.0.0.0"

# Metrics endpoint path
# Default: "/metrics"
path = "/metrics"

# Include histogram buckets for latency
# Default: true
histograms = true

# Histogram buckets (seconds)
# Default: [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
histogram_buckets = [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]

# Metrics update interval (seconds)
# Default: 10
update_interval_seconds = 10

#═══════════════════════════════════════════════════════════════════════════════
# TRACING CONFIGURATION
#═══════════════════════════════════════════════════════════════════════════════

[tracing]
# Enable distributed tracing (OpenTelemetry)
# Default: false
enabled = false

# Tracing exporter
# Options: "otlp", "jaeger", "zipkin"
# Default: "otlp"
exporter = "otlp"

# OTLP exporter endpoint
# Default: "http://localhost:4317"
otlp_endpoint = "http://localhost:4317"

# Jaeger exporter endpoint
# Default: "http://localhost:14268/api/traces"
jaeger_endpoint = "http://localhost:14268/api/traces"

# Zipkin exporter endpoint
# Default: "http://localhost:9411/api/v2/spans"
zipkin_endpoint = "http://localhost:9411/api/v2/spans"

# Sampling rate (0.0 to 1.0)
# Default: 0.1 (10%)
sampling_rate = 0.1

# Service name for traces
# Default: "norc-server"
service_name = "norc-server"

# Service namespace
# Optional
service_namespace = "production"

# Service version
# Optional (defaults to NORC version)
service_version = "0.1.0"

#═══════════════════════════════════════════════════════════════════════════════
# ADMIN API CONFIGURATION
#═══════════════════════════════════════════════════════════════════════════════

[admin_api]
# Enable Admin API
# Default: true
enabled = true

# Admin API port
# Default: 8443 (same as TLS port)
port = 8443

# Admin API path prefix
# Default: "/api/v1"
path_prefix = "/api/v1"

# Require authentication
# Default: true
require_auth = true

# Authentication method
# Options: "mtls", "token", "both"
# Default: "mtls"
auth_method = "mtls"

# API tokens (for token-based auth)
# Format: ["token1", "token2", ...]
# Tokens should be cryptographically secure random strings
# Optional
api_tokens = []

# API token header name
# Default: "X-API-Token"
token_header = "X-API-Token"

# Rate limiting
# Default: true
rate_limiting = true

# Rate limit: requests per hour (per client)
# Default: 1000
rate_limit_requests_per_hour = 1000

# Rate limit: certificate operations per hour
# Default: 100
rate_limit_cert_ops_per_hour = 100

# Rate limit: certificate rotations per hour
# Default: 10
rate_limit_rotations_per_hour = 10

# Enable CORS
# Default: false
enable_cors = false

# CORS allowed origins
# Default: ["*"]
cors_allowed_origins = ["*"]

# Request body size limit (bytes)
# Default: 1048576 (1 MB)
max_request_body_size = 1048576

#═══════════════════════════════════════════════════════════════════════════════
# CERTIFICATE ROTATION CONFIGURATION
#═══════════════════════════════════════════════════════════════════════════════

[rotation]
# Enable automatic certificate reload
# Watch for certificate file changes
# Default: true
auto_reload = true

# Certificate check interval (seconds)
# How often to check for certificate changes
# Default: 300 (5 minutes)
check_interval_seconds = 300

# Reload cooldown (seconds)
# Minimum time between reloads
# Default: 10
reload_cooldown_seconds = 10

# Enable graceful rotation
# Keep old certificates valid during rotation
# Default: true
graceful_rotation = true

# Grace period for old certificates (seconds)
# How long to accept old certificates after rotation
# Default: 300 (5 minutes)
grace_period_seconds = 300

# Certificate expiration warning threshold (days)
# Log warning when certificate expires within this many days
# Default: 30
expiration_warning_days = 30

# Enable automatic certificate renewal
# Automatically renew certificates using ACME (Let's Encrypt)
# Default: false
auto_renewal = false

# ACME directory URL
# Default: "https://acme-v02.api.letsencrypt.org/directory"
acme_directory_url = "https://acme-v02.api.letsencrypt.org/directory"

# ACME account email
# Required if auto_renewal is true
# acme_account_email = "admin@example.com"

# ACME challenge type
# Options: "http-01", "tls-alpn-01", "dns-01"
# Default: "http-01"
acme_challenge_type = "http-01"

#═══════════════════════════════════════════════════════════════════════════════
# BACKUP CONFIGURATION
#═══════════════════════════════════════════════════════════════════════════════

[backup]
# Enable automatic backups
# Default: false
enabled = false

# Backup directory
# Default: "/var/backups/norc"
directory = "/var/backups/norc"

# Backup interval (hours)
# Default: 24
interval_hours = 24

# Number of backups to retain
# Default: 7
retention_count = 7

# Compress backups
# Default: true
compress = true

# Include certificates in backup
# Default: false (security risk)
include_certificates = false

#═══════════════════════════════════════════════════════════════════════════════
# DAEMON CONFIGURATION (Linux/Unix)
#═══════════════════════════════════════════════════════════════════════════════

[daemon]
# Run as daemon (background process)
# Default: false (use systemd/launchd instead)
daemonize = false

# PID file path
# Default: "/var/run/norc/norc.pid"
pid_file = "/var/run/norc/norc.pid"

# Run as specific user
# Default: current user
# user = "norc"

# Run as specific group
# Default: current group
# group = "norc"

# Working directory
# Default: current directory
# working_directory = "/var/lib/norc"

# Umask for file creation
# Default: 0o022
umask = 0o022

#═══════════════════════════════════════════════════════════════════════════════
# EXPERIMENTAL FEATURES
#═══════════════════════════════════════════════════════════════════════════════

[experimental]
# Enable QUIC transport protocol
# Default: false
enable_quic = false

# QUIC port
# Default: 8443
quic_port = 8443

# Enable HTTP/3
# Default: false
enable_http3 = false

# Enable certificate transparency
# Default: false
enable_cert_transparency = false

# Certificate transparency log URLs
ct_log_urls = [
    "https://ct.googleapis.com/logs/argon2024/",
]
```

---

## Client Configuration

### Complete Client Configuration Template

```toml
# ~/.config/norc/client.toml - NORC Client Configuration

#═══════════════════════════════════════════════════════════════════════════════
# CLIENT CONFIGURATION
#═══════════════════════════════════════════════════════════════════════════════

[client]
# Server URL
# Required
server_url = "https://server.example.com:8443"

# Client identifier
# Default: hostname
client_id = "client-01"

# Connection timeout (seconds)
# Default: 30
connection_timeout_seconds = 30

# Request timeout (seconds)
# Default: 30
request_timeout_seconds = 30

# Retry attempts
# Default: 3
retry_attempts = 3

# Retry delay (seconds)
# Default: 1
retry_delay_seconds = 1

# Enable connection pooling
# Default: true
connection_pooling = true

# Maximum idle connections
# Default: 10
max_idle_connections = 10

# Idle connection timeout (seconds)
# Default: 600 (10 minutes)
idle_timeout_seconds = 600

#═══════════════════════════════════════════════════════════════════════════════
# TLS CONFIGURATION
#═══════════════════════════════════════════════════════════════════════════════

[tls]
# Enable TLS
# Default: true
enabled = true

# Client certificate path (PEM format)
# Required for mTLS
cert_path = "/etc/norc/certs/client.pem"

# Client private key path (PEM format)
# Required for mTLS
key_path = "/etc/norc/certs/client-key.pem"

# CA certificate path for server verification (PEM format)
# Required
ca_cert_path = "/etc/norc/certs/ca.pem"

# Verify server certificate
# Default: true
verify_server = true

# Server name for SNI and certificate verification
# Optional (uses hostname from server_url by default)
# server_name = "server.example.com"

# Accept invalid certificates (INSECURE - development only)
# Default: false
accept_invalid_certs = false

# Accept invalid hostnames (INSECURE - development only)
# Default: false
accept_invalid_hostnames = false

# Minimum TLS version
# Options: "TLSv1.2", "TLSv1.3"
# Default: "TLSv1.2"
min_tls_version = "TLSv1.2"

#═══════════════════════════════════════════════════════════════════════════════
# LOGGING CONFIGURATION
#═══════════════════════════════════════════════════════════════════════════════

[logging]
# Log level
# Options: "trace", "debug", "info", "warn", "error"
# Default: "info"
level = "info"

# Log format
# Options: "json", "pretty", "compact"
# Default: "pretty"
format = "pretty"

# Log output destination
# Options: "stdout", "stderr", file path
# Default: "stdout"
output = "stdout"

#═══════════════════════════════════════════════════════════════════════════════
# CLI CONFIGURATION
#═══════════════════════════════════════════════════════════════════════════════

[cli]
# Output format
# Options: "json", "yaml", "table", "plain"
# Default: "table"
output_format = "table"

# Enable colored output
# Default: true
colored_output = true

# Pager for long output
# Default: system pager (less/more)
# Set to empty string to disable
pager = ""

# Default page size for paginated output
# Default: 50
page_size = 50

#═══════════════════════════════════════════════════════════════════════════════
# TUI CONFIGURATION
#═══════════════════════════════════════════════════════════════════════════════

[tui]
# TUI theme
# Options: "dark", "light"
# Default: "dark"
theme = "dark"

# Update interval (milliseconds)
# Default: 1000 (1 second)
update_interval_ms = 1000

# Enable mouse support
# Default: true
mouse_support = true

# Show timestamps
# Default: true
show_timestamps = true
```

---

## Environment Variables

Environment variables override configuration file settings.

### Server Environment Variables

```bash
# Server configuration
export NORC_SERVER_ADDRESS="0.0.0.0"
export NORC_SERVER_PORT="8080"
export NORC_SERVER_TLS_PORT="8443"
export NORC_SERVER_ID="server-01"
export NORC_SERVER_ORGANIZATION="example.com"

# TLS configuration
export NORC_TLS_ENABLED="true"
export NORC_TLS_CERT_PATH="/etc/norc/certs/server.pem"
export NORC_TLS_KEY_PATH="/etc/norc/certs/server-key.pem"
export NORC_TLS_CA_CERT_PATH="/etc/norc/certs/ca.pem"
export NORC_TLS_REQUIRE_CLIENT_CERT="true"
export NORC_TLS_VERIFY_CLIENT_CERT="true"

# Security configuration
export NORC_SECURITY_ENABLE_OCSP="true"
export NORC_SECURITY_ENABLE_CRL="true"
export NORC_SECURITY_OCSP_TIMEOUT_SECONDS="5"

# Database configuration
export NORC_DATABASE_TYPE="sqlite"
export NORC_DATABASE_PATH="/var/lib/norc/norc.db"
# Or for PostgreSQL:
export NORC_DATABASE_URL="postgresql://user:password@localhost:5432/norc"

# Logging configuration
export NORC_LOG_LEVEL="info"
export NORC_LOG_FORMAT="json"
export NORC_LOG_OUTPUT="/var/log/norc/norc.log"

# Metrics configuration
export NORC_METRICS_ENABLED="true"
export NORC_METRICS_PORT="9090"

# Admin API configuration
export NORC_ADMIN_API_ENABLED="true"
export NORC_ADMIN_API_PORT="8443"
export NORC_ADMIN_API_REQUIRE_AUTH="true"

# Rust logging (more granular)
export RUST_LOG="norc=info,norc_server_core=debug"
export RUST_BACKTRACE="1"  # Enable backtraces on panic
```

### Client Environment Variables

```bash
# Client configuration
export NORC_CLIENT_SERVER_URL="https://server.example.com:8443"
export NORC_CLIENT_ID="client-01"

# TLS configuration
export NORC_CLIENT_CERT_PATH="/etc/norc/certs/client.pem"
export NORC_CLIENT_KEY_PATH="/etc/norc/certs/client-key.pem"
export NORC_CLIENT_CA_CERT_PATH="/etc/norc/certs/ca.pem"

# Logging
export NORC_LOG_LEVEL="info"
export RUST_LOG="norc_client=info"
```

---

## Configuration Examples

### Development Configuration

```toml
# Development server configuration
[server]
address = "127.0.0.1"
port = 8080
tls_port = 8443
server_id = "dev-server"
organization = "dev.local"

[tls]
enabled = true
cert_path = "./certs/server.pem"
key_path = "./certs/server-key.pem"
ca_cert_path = "./certs/ca.pem"
require_client_cert = true

[security]
enable_ocsp = false
enable_crl = false

[database]
type = "sqlite"
path = "./data/norc-dev.db"

[logging]
level = "debug"
format = "pretty"
output = "stdout"

[metrics]
enabled = true
port = 9090
```

### Production Configuration

```toml
# Production server configuration
[server]
address = "0.0.0.0"
port = 8080
tls_port = 8443
server_id = "prod-server-01"
organization = "example.com"
max_connections = 10000
worker_threads = 8

[tls]
enabled = true
cert_path = "/etc/norc/certs/server.pem"
key_path = "/etc/norc/certs/server-key.pem"
ca_cert_path = "/etc/norc/certs/ca.pem"
require_client_cert = true
verify_client_cert = true
min_tls_version = "TLSv1.3"

[security]
enable_ocsp = true
enable_crl = true
enable_audit_logging = true
validation_cache_ttl_seconds = 300

[database]
type = "postgresql"
url = "postgresql://norc:${DATABASE_PASSWORD}@db.example.com:5432/norc"
max_connections = 20
min_connections = 5

[logging]
level = "info"
format = "json"
output = "/var/log/norc/norc.log"
rotation = true
max_size_mb = 100
max_files = 30

[metrics]
enabled = true
port = 9090
histograms = true

[tracing]
enabled = true
exporter = "otlp"
otlp_endpoint = "http://tempo.example.com:4317"
sampling_rate = 0.1

[admin_api]
enabled = true
port = 8443
require_auth = true
rate_limiting = true
rate_limit_requests_per_hour = 1000

[rotation]
auto_reload = true
check_interval_seconds = 300
graceful_rotation = true
expiration_warning_days = 30

[backup]
enabled = true
directory = "/var/backups/norc"
interval_hours = 24
retention_count = 7
compress = true
```

### High Availability Configuration

```toml
# HA server configuration
[server]
address = "0.0.0.0"
port = 8080
tls_port = 8443
server_id = "ha-server-01"  # Unique per instance
organization = "example.com"
max_connections = 15000

[tls]
enabled = true
cert_path = "/etc/norc/certs/server.pem"
key_path = "/etc/norc/certs/server-key.pem"
ca_cert_path = "/etc/norc/certs/ca.pem"
require_client_cert = true

[database]
type = "postgresql"
url = "postgresql://norc:password@pg-cluster.example.com:5432/norc"
max_connections = 30
min_connections = 10
connection_lifetime_seconds = 1800

[logging]
level = "info"
format = "json"
output = "/var/log/norc/norc.log"
rotation = true

[metrics]
enabled = true
port = 9090

[admin_api]
enabled = true
rate_limiting = true

[rotation]
auto_reload = true
graceful_rotation = true
grace_period_seconds = 600
```

---

## Configuration Validation

### Validate Configuration File

```bash
# Validate server configuration
norc-diag config --file /etc/norc/config.toml

# Validate and show parsed configuration
norc-diag config --file /etc/norc/config.toml --show

# Validate and fix common issues
norc-diag config --file /etc/norc/config.toml --fix

# Validate specific section
norc-diag config --file /etc/norc/config.toml --section tls
```

### Common Validation Issues

**Issue: Missing Required Fields**
```
ERROR: Missing required field 'server.organization'
```
Solution: Add required field to configuration

**Issue: Invalid Value**
```
ERROR: Invalid value for 'tls.min_tls_version': must be one of ["TLSv1.2", "TLSv1.3"]
```
Solution: Use valid value from allowed options

**Issue: File Not Found**
```
ERROR: Certificate file not found: /etc/norc/certs/server.pem
```
Solution: Verify file path and permissions

**Issue: Conflicting Settings**
```
WARN: 'tls.require_client_cert' is true but 'tls.ca_cert_path' is not set
```
Solution: Provide CA certificate path or disable client cert requirement

---

## Configuration Best Practices

### Security Best Practices

1. **Use Strong TLS Configuration**:
```toml
[tls]
min_tls_version = "TLSv1.3"
require_client_cert = true
verify_client_cert = true
```

2. **Enable Revocation Checking**:
```toml
[security]
enable_ocsp = true
enable_crl = true
validation_cache_ttl_seconds = 300
```

3. **Enable Audit Logging**:
```toml
[security]
enable_audit_logging = true
audit_log_path = "/var/log/norc/audit.log"
```

4. **Restrict Access**:
```toml
[security]
allowed_ips = ["192.168.1.0/24", "10.0.0.0/8"]
```

### Performance Best Practices

1. **Tune Worker Threads**:
```toml
[server]
worker_threads = 8  # Match CPU cores
max_blocking_threads = 512
```

2. **Optimize Database Connections**:
```toml
[database]
max_connections = 20
connection_lifetime_seconds = 3600
journal_mode = "WAL"  # SQLite only
```

3. **Enable Connection Pooling**:
```toml
[server]
max_connections = 10000
connection_timeout_seconds = 300
enable_keepalive = true
```

### Reliability Best Practices

1. **Enable Backups**:
```toml
[backup]
enabled = true
interval_hours = 24
retention_count = 7
```

2. **Configure Graceful Rotation**:
```toml
[rotation]
graceful_rotation = true
grace_period_seconds = 300
expiration_warning_days = 30
```

3. **Enable Health Checks**:
```toml
[server]
# Health endpoint available at /health
enable_keepalive = true
```

### Monitoring Best Practices

1. **Enable Metrics**:
```toml
[metrics]
enabled = true
port = 9090
histograms = true
```

2. **Configure Structured Logging**:
```toml
[logging]
level = "info"
format = "json"
rotation = true
```

3. **Enable Distributed Tracing**:
```toml
[tracing]
enabled = true
exporter = "otlp"
sampling_rate = 0.1
```

---

*Last Updated: 2025-01-02*  
*NORC Configuration Reference v1.0*
