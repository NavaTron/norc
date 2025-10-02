# NORC Deployment Guide

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation Methods](#installation-methods)
3. [Configuration](#configuration)
4. [Certificate Setup](#certificate-setup)
5. [Starting the Server](#starting-the-server)
6. [Verification](#verification)
7. [Production Deployment](#production-deployment)
8. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### System Requirements

**Minimum**:
- CPU: 2 cores
- RAM: 2GB
- Disk: 10GB
- OS: Linux (Ubuntu 20.04+, RHEL 8+), macOS 12+, Windows Server 2019+

**Recommended (Production)**:
- CPU: 4+ cores
- RAM: 8GB+
- Disk: 50GB+ SSD
- OS: Linux (Ubuntu 22.04 LTS, RHEL 9)

### Software Dependencies

- Rust 1.90.0+ (for building from source)
- SQLite 3.35+ or PostgreSQL 13+
- OpenSSL 1.1.1+ or 3.0+

---

## Installation Methods

### Method 1: Pre-built Binaries (Recommended)

Download the latest release for your platform:

```bash
# Linux x86_64
wget https://github.com/NavaTron/norc/releases/latest/download/norc-v0.1.0-x86_64-unknown-linux-gnu.tar.gz
tar xzf norc-v0.1.0-x86_64-unknown-linux-gnu.tar.gz
sudo mv norc-server norc-client norc-diag /usr/local/bin/

# macOS (Apple Silicon)
wget https://github.com/NavaTron/norc/releases/latest/download/norc-v0.1.0-aarch64-apple-darwin.tar.gz
tar xzf norc-v0.1.0-aarch64-apple-darwin.tar.gz
sudo mv norc-server norc-client norc-diag /usr/local/bin/

# Windows
# Download norc-v0.1.0-x86_64-pc-windows-msvc.zip
# Extract to C:\Program Files\NORC\
```

### Method 2: Build from Source

```bash
# Clone repository
git clone https://github.com/NavaTron/norc.git
cd norc

# Build release binaries
cargo build --release

# Install binaries
sudo cp target/release/norc-server /usr/local/bin/
sudo cp target/release/norc-client /usr/local/bin/
sudo cp target/release/norc-diag /usr/local/bin/
```

### Method 3: Docker Container

```bash
# Pull from GitHub Container Registry
docker pull ghcr.io/navatron/norc:latest-server

# Or build locally
docker-compose build norc-server
```

### Method 4: Package Manager

```bash
# Homebrew (macOS/Linux)
brew tap navatron/tap
brew install norc

# APT (Debian/Ubuntu)
curl -fsSL https://packages.navatron.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/navatron.gpg
echo "deb [signed-by=/usr/share/keyrings/navatron.gpg] https://packages.navatron.com/apt stable main" | sudo tee /etc/apt/sources.list.d/navatron.list
sudo apt update
sudo apt install norc

# YUM/DNF (RHEL/CentOS/Fedora)
sudo dnf config-manager --add-repo https://packages.navatron.com/rpm/navatron.repo
sudo dnf install norc
```

---

## Configuration

### Generate Default Configuration

```bash
norc-server generate-config --output /etc/norc/config.toml
```

### Configuration File Structure

```toml
# /etc/norc/config.toml

[server]
# Server bind address
address = "0.0.0.0"
port = 8080
tls_port = 8443

# Server identity
server_id = "server-01"
organization = "example.com"

[tls]
# TLS configuration
enabled = true
cert_path = "/etc/norc/certs/server.pem"
key_path = "/etc/norc/certs/server-key.pem"
ca_cert_path = "/etc/norc/certs/ca.pem"

# mTLS configuration
require_client_cert = true
verify_client_cert = true

[security]
# Certificate pinning
enable_pinning = true
pinned_fingerprints = [
    "SHA256:ab:cd:ef:12:34:56:78:90:ab:cd:ef:12:34:56:78:90",
]

# Revocation checking
enable_ocsp = true
enable_crl = true
ocsp_timeout_seconds = 5
crl_cache_ttl_hours = 24

[database]
# Database configuration
type = "sqlite"
path = "/var/lib/norc/norc.db"
max_connections = 10

# For PostgreSQL:
# type = "postgresql"
# url = "postgresql://user:pass@localhost/norc"

[logging]
# Logging configuration
level = "info"
format = "json"
output = "/var/log/norc/norc.log"

# Log rotation
rotation = true
max_size_mb = 100
max_files = 10

[metrics]
# Prometheus metrics
enabled = true
port = 9090
path = "/metrics"

[admin_api]
# Admin API configuration
enabled = true
port = 8443
require_auth = true

[daemon]
# Daemon configuration (Linux/Unix)
daemonize = false
pid_file = "/var/run/norc/norc.pid"
user = "norc"
group = "norc"

[rotation]
# Certificate rotation
auto_reload = true
check_interval_seconds = 300
reload_cooldown_seconds = 10
```

### Environment Variables

Override configuration with environment variables:

```bash
# Server configuration
export NORC_SERVER_ADDRESS="0.0.0.0"
export NORC_SERVER_PORT="8080"
export NORC_SERVER_TLS_PORT="8443"

# TLS configuration
export NORC_TLS_CERT_PATH="/etc/norc/certs/server.pem"
export NORC_TLS_KEY_PATH="/etc/norc/certs/server-key.pem"
export NORC_TLS_CA_CERT_PATH="/etc/norc/certs/ca.pem"

# Database
export NORC_DATABASE_URL="sqlite:///var/lib/norc/norc.db"

# Logging
export NORC_LOG_LEVEL="info"
export RUST_LOG="norc=debug"
```

---

## Certificate Setup

### Certificate Requirements

- **Format**: PEM-encoded X.509 certificates
- **Key Algorithm**: RSA 2048-bit or ECDSA P-256
- **Signature**: SHA256withRSA or better
- **Validity**: Minimum 30 days remaining

### Generate Self-Signed Certificates (Development)

```bash
# Create certificate directory
sudo mkdir -p /etc/norc/certs
cd /etc/norc/certs

# Generate CA certificate
openssl req -x509 -newkey rsa:4096 -keyout ca-key.pem -out ca.pem \
    -days 3650 -nodes \
    -subj "/C=US/ST=California/L=San Francisco/O=NORC Dev/CN=NORC Dev CA"

# Generate server certificate
openssl req -newkey rsa:2048 -keyout server-key.pem -out server-csr.pem \
    -nodes \
    -subj "/C=US/ST=California/L=San Francisco/O=NORC Dev/CN=localhost"

# Sign server certificate
openssl x509 -req -in server-csr.pem -CA ca.pem -CAkey ca-key.pem \
    -CAcreateserial -out server.pem -days 365 \
    -extfile <(cat <<EOF
subjectAltName = DNS:localhost,DNS:server.local,IP:127.0.0.1
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
EOF
)

# Generate client certificate
openssl req -newkey rsa:2048 -keyout client-key.pem -out client-csr.pem \
    -nodes \
    -subj "/C=US/ST=California/L=San Francisco/O=NORC Dev/CN=client-01"

openssl x509 -req -in client-csr.pem -CA ca.pem -CAkey ca-key.pem \
    -CAcreateserial -out client.pem -days 365 \
    -extfile <(cat <<EOF
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EOF
)

# Set permissions
sudo chmod 600 *-key.pem
sudo chmod 644 *.pem
sudo chown -R norc:norc /etc/norc/certs
```

### Use Production CA (Let's Encrypt, Internal CA)

```bash
# For Let's Encrypt with certbot
sudo certbot certonly --standalone -d server.example.com

# Link certificates
sudo ln -s /etc/letsencrypt/live/server.example.com/fullchain.pem /etc/norc/certs/server.pem
sudo ln -s /etc/letsencrypt/live/server.example.com/privkey.pem /etc/norc/certs/server-key.pem

# For internal CA, copy issued certificates
sudo cp /path/to/server-cert.pem /etc/norc/certs/server.pem
sudo cp /path/to/server-key.pem /etc/norc/certs/server-key.pem
sudo cp /path/to/ca-chain.pem /etc/norc/certs/ca.pem
```

### Validate Certificates

```bash
# Check certificate
norc-diag inspect --cert /etc/norc/certs/server.pem

# Validate certificate chain
norc-diag validate --cert /etc/norc/certs/server.pem --chain /etc/norc/certs/ca.pem

# Check revocation status
norc-diag revocation --cert /etc/norc/certs/server.pem
```

---

## Starting the Server

### Create System User

```bash
# Linux
sudo useradd --system --no-create-home --shell /bin/false norc

# Create directories
sudo mkdir -p /var/lib/norc /var/log/norc /var/run/norc
sudo chown -R norc:norc /var/lib/norc /var/log/norc /var/run/norc
```

### Systemd Service (Linux)

Create `/etc/systemd/system/norc.service`:

```ini
[Unit]
Description=NORC Server
Documentation=https://github.com/NavaTron/norc
After=network.target

[Service]
Type=simple
User=norc
Group=norc
ExecStart=/usr/local/bin/norc-server --config /etc/norc/config.toml
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=10

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/norc /var/log/norc /var/run/norc
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=norc

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable norc
sudo systemctl start norc
sudo systemctl status norc
```

### Launchd (macOS)

Create `/Library/LaunchDaemons/com.navatron.norc.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.navatron.norc</string>
    
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/norc-server</string>
        <string>--config</string>
        <string>/usr/local/etc/norc/config.toml</string>
    </array>
    
    <key>RunAtLoad</key>
    <true/>
    
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    
    <key>StandardOutPath</key>
    <string>/usr/local/var/log/norc/stdout.log</string>
    
    <key>StandardErrorPath</key>
    <string>/usr/local/var/log/norc/stderr.log</string>
</dict>
</plist>
```

Load and start:

```bash
sudo launchctl load /Library/LaunchDaemons/com.navatron.norc.plist
sudo launchctl start com.navatron.norc
```

### Docker Compose

```yaml
# docker-compose.yml
version: '3.8'

services:
  norc-server:
    image: ghcr.io/navatron/norc:latest-server
    container_name: norc-server
    ports:
      - "8080:8080"
      - "8443:8443"
      - "9090:9090"
    volumes:
      - ./config:/etc/norc:ro
      - norc-data:/var/lib/norc
      - norc-logs:/var/log/norc
    environment:
      - RUST_LOG=info
      - NORC_DATABASE_URL=sqlite:///var/lib/norc/norc.db
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "norc-diag", "health"]
      interval: 30s
      timeout: 3s
      retries: 3

volumes:
  norc-data:
  norc-logs:
```

Start with Docker Compose:

```bash
docker-compose up -d
docker-compose logs -f norc-server
```

### Kubernetes

```yaml
# norc-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: norc-server
  labels:
    app: norc
spec:
  replicas: 3
  selector:
    matchLabels:
      app: norc
  template:
    metadata:
      labels:
        app: norc
    spec:
      containers:
      - name: norc-server
        image: ghcr.io/navatron/norc:latest-server
        ports:
        - containerPort: 8080
          name: http
        - containerPort: 8443
          name: https
        - containerPort: 9090
          name: metrics
        env:
        - name: RUST_LOG
          value: "info"
        - name: NORC_DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: norc-secrets
              key: database-url
        volumeMounts:
        - name: config
          mountPath: /etc/norc
          readOnly: true
        - name: certs
          mountPath: /etc/norc/certs
          readOnly: true
        - name: data
          mountPath: /var/lib/norc
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "1000m"
        livenessProbe:
          exec:
            command:
            - norc-diag
            - health
          initialDelaySeconds: 30
          periodSeconds: 30
        readinessProbe:
          exec:
            command:
            - norc-diag
            - health
          initialDelaySeconds: 10
          periodSeconds: 10
      volumes:
      - name: config
        configMap:
          name: norc-config
      - name: certs
        secret:
          secretName: norc-certs
      - name: data
        persistentVolumeClaim:
          claimName: norc-data-pvc

---
apiVersion: v1
kind: Service
metadata:
  name: norc-server
spec:
  selector:
    app: norc
  ports:
  - name: http
    port: 8080
    targetPort: 8080
  - name: https
    port: 8443
    targetPort: 8443
  - name: metrics
    port: 9090
    targetPort: 9090
  type: LoadBalancer
```

Deploy to Kubernetes:

```bash
kubectl apply -f norc-deployment.yaml
kubectl get pods -l app=norc
kubectl logs -f deployment/norc-server
```

---

## Verification

### Check Server Status

```bash
# Check if server is running
sudo systemctl status norc

# Check logs
sudo journalctl -u norc -f

# Check metrics
curl http://localhost:9090/metrics

# Run diagnostics
norc-diag health
```

### Test Connection

```bash
# Test HTTP endpoint
curl http://localhost:8080/health

# Test HTTPS with mTLS
curl --cert /etc/norc/certs/client.pem \
     --key /etc/norc/certs/client-key.pem \
     --cacert /etc/norc/certs/ca.pem \
     https://localhost:8443/api/v1/certificates

# Test with client binary
norc-client --config /etc/norc/client-config.toml connect
```

### Verify Certificates

```bash
# Check server certificate
openssl s_client -connect localhost:8443 -showcerts

# Validate certificate chain
norc-diag validate --cert /etc/norc/certs/server.pem

# Check revocation status
norc-diag revocation --cert /etc/norc/certs/server.pem
```

---

## Production Deployment

### Load Balancer Configuration

#### Nginx

```nginx
upstream norc_backend {
    least_conn;
    server 10.0.1.10:8443 max_fails=3 fail_timeout=30s;
    server 10.0.1.11:8443 max_fails=3 fail_timeout=30s;
    server 10.0.1.12:8443 max_fails=3 fail_timeout=30s;
}

server {
    listen 443 ssl http2;
    server_name norc.example.com;
    
    # TLS configuration
    ssl_certificate /etc/nginx/certs/server.pem;
    ssl_certificate_key /etc/nginx/certs/server-key.pem;
    ssl_client_certificate /etc/nginx/certs/ca.pem;
    ssl_verify_client on;
    ssl_verify_depth 2;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers on;
    
    # Pass client certificate to backend
    proxy_set_header X-SSL-Client-Cert $ssl_client_cert;
    proxy_set_header X-SSL-Client-Verify $ssl_client_verify;
    
    location / {
        proxy_pass https://norc_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Health checks
        proxy_next_upstream error timeout http_500 http_502 http_503;
    }
}
```

### Monitoring Setup

```bash
# Prometheus scrape configuration
cat >> /etc/prometheus/prometheus.yml <<EOF
scrape_configs:
  - job_name: 'norc'
    static_configs:
      - targets:
        - 'norc-server-1:9090'
        - 'norc-server-2:9090'
        - 'norc-server-3:9090'
    scrape_interval: 15s
    metrics_path: /metrics
EOF

sudo systemctl reload prometheus
```

### Backup Configuration

```bash
#!/bin/bash
# /usr/local/bin/norc-backup.sh

BACKUP_DIR="/var/backups/norc"
DATE=$(date +%Y%m%d_%H%M%S)

# Backup database
sqlite3 /var/lib/norc/norc.db ".backup $BACKUP_DIR/norc_$DATE.db"

# Backup certificates
tar -czf $BACKUP_DIR/certs_$DATE.tar.gz /etc/norc/certs/

# Backup configuration
cp /etc/norc/config.toml $BACKUP_DIR/config_$DATE.toml

# Keep only last 30 days
find $BACKUP_DIR -type f -mtime +30 -delete

echo "Backup completed: $DATE"
```

Add to cron:

```bash
# Run daily at 2 AM
0 2 * * * /usr/local/bin/norc-backup.sh
```

---

## Troubleshooting

### Server Won't Start

```bash
# Check logs
sudo journalctl -u norc -n 100 --no-pager

# Validate configuration
norc-diag config --file /etc/norc/config.toml

# Check certificate permissions
ls -la /etc/norc/certs/

# Verify port availability
sudo netstat -tlnp | grep -E '8080|8443'
```

### Certificate Issues

```bash
# Validate certificate
norc-diag validate --cert /etc/norc/certs/server.pem

# Check expiration
norc-diag inspect --cert /etc/norc/certs/server.pem

# Test TLS connection
openssl s_client -connect localhost:8443 -showcerts -CAfile /etc/norc/certs/ca.pem
```

### Performance Issues

```bash
# Check metrics
curl http://localhost:9090/metrics | grep -E 'norc_requests|norc_connections'

# Monitor resource usage
top -p $(pgrep norc-server)

# Check database performance
sqlite3 /var/lib/norc/norc.db "PRAGMA integrity_check"
```

See [Troubleshooting Guide](../troubleshooting/TROUBLESHOOTING.md) for detailed solutions.

---

*Last Updated: 2025-10-02*  
*NORC Deployment Guide v1.0*
