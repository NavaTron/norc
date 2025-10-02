# NORC Troubleshooting Guide

## Table of Contents

1. [Diagnostic Tools](#diagnostic-tools)
2. [Common Issues](#common-issues)
3. [Certificate Problems](#certificate-problems)
4. [Connection Issues](#connection-issues)
5. [Performance Troubleshooting](#performance-troubleshooting)
6. [Database Issues](#database-issues)
7. [Log Analysis](#log-analysis)
8. [Security Issues](#security-issues)

---

## Diagnostic Tools

NORC includes the `norc-diag` diagnostic tool with comprehensive troubleshooting capabilities.

### Available Diagnostic Commands

```bash
# Check overall system health
norc-diag health

# Inspect certificate details
norc-diag inspect --cert /path/to/cert.pem

# Validate certificate chain
norc-diag validate --cert /path/to/cert.pem --chain /path/to/ca.pem

# Check revocation status (OCSP/CRL)
norc-diag revocation --cert /path/to/cert.pem

# Test connectivity to server
norc-diag connect --server https://server.example.com:8443

# Validate configuration file
norc-diag config --file /etc/norc/config.toml
```

### Running Comprehensive Diagnostics

```bash
# Run all diagnostic checks
norc-diag health --verbose --json > diag-report.json

# Check specific component
norc-diag health --component certificates
norc-diag health --component database
norc-diag health --component network
```

---

## Common Issues

### Issue: Server Fails to Start

**Symptoms**:
- Server exits immediately after starting
- `systemctl status norc` shows "failed" state
- Error in logs: "Address already in use"

**Diagnosis**:

```bash
# Check if port is already in use
sudo netstat -tlnp | grep -E '8080|8443'

# Check systemd status
sudo systemctl status norc

# View recent logs
sudo journalctl -u norc -n 50 --no-pager

# Validate configuration
norc-diag config --file /etc/norc/config.toml
```

**Solutions**:

1. **Port Conflict**:
```bash
# Identify process using the port
sudo lsof -i :8443

# Kill conflicting process
sudo kill -9 <PID>

# Or change NORC port in config
vim /etc/norc/config.toml
# [server]
# tls_port = 9443
```

2. **Permission Denied**:
```bash
# Check file permissions
ls -la /etc/norc/config.toml
ls -la /etc/norc/certs/

# Fix permissions
sudo chown -R norc:norc /etc/norc/
sudo chmod 640 /etc/norc/config.toml
sudo chmod 600 /etc/norc/certs/*-key.pem
```

3. **Invalid Configuration**:
```bash
# Validate and fix configuration
norc-diag config --file /etc/norc/config.toml --fix

# Check for syntax errors
cat /etc/norc/config.toml | grep -v '^#' | grep -v '^$'
```

### Issue: High Memory Usage

**Symptoms**:
- Server consumes excessive memory (>2GB)
- OOM killer terminates server
- Slow response times

**Diagnosis**:

```bash
# Check memory usage
ps aux | grep norc-server

# Monitor memory over time
watch -n 1 'ps aux | grep norc-server'

# Check metrics
curl http://localhost:9090/metrics | grep memory
```

**Solutions**:

1. **Reduce Connection Pool Size**:
```toml
# /etc/norc/config.toml
[database]
max_connections = 5  # Reduce from 10
```

2. **Enable Connection Limits**:
```toml
[server]
max_connections = 1000  # Set limit
connection_timeout_seconds = 30
```

3. **Optimize Database**:
```bash
# Vacuum SQLite database
sqlite3 /var/lib/norc/norc.db "VACUUM;"

# Analyze query performance
sqlite3 /var/lib/norc/norc.db "ANALYZE;"
```

### Issue: Service Crashes Frequently

**Symptoms**:
- Server restarts repeatedly
- Segmentation faults in logs
- Core dumps generated

**Diagnosis**:

```bash
# Check crash logs
sudo journalctl -u norc --since "1 hour ago" | grep -i "core\|segfault\|panic"

# Check for core dumps
ls -lh /var/lib/systemd/coredump/

# Run with debug logging
sudo systemctl stop norc
sudo RUST_LOG=debug /usr/local/bin/norc-server --config /etc/norc/config.toml
```

**Solutions**:

1. **Update to Latest Version**:
```bash
# Check current version
norc-server --version

# Download latest release
wget https://github.com/NavaTron/norc/releases/latest/download/norc-v0.1.0-x86_64-unknown-linux-gnu.tar.gz
sudo systemctl stop norc
sudo mv norc-server /usr/local/bin/norc-server
sudo systemctl start norc
```

2. **Check Resource Limits**:
```bash
# Increase file descriptor limits
sudo vim /etc/systemd/system/norc.service
# Add under [Service]
# LimitNOFILE=65536

sudo systemctl daemon-reload
sudo systemctl restart norc
```

3. **Enable Crash Reporting**:
```bash
# Enable core dumps
ulimit -c unlimited
echo "/var/crash/core.%e.%p" | sudo tee /proc/sys/kernel/core_pattern
```

---

## Certificate Problems

### Issue: Certificate Validation Fails

**Symptoms**:
- Error: "Certificate validation failed"
- Client cannot connect to server
- "Untrusted certificate" errors

**Diagnosis**:

```bash
# Inspect certificate
norc-diag inspect --cert /etc/norc/certs/server.pem

# Validate certificate chain
norc-diag validate --cert /etc/norc/certs/server.pem --chain /etc/norc/certs/ca.pem

# Check certificate expiration
openssl x509 -in /etc/norc/certs/server.pem -noout -dates

# Verify certificate purpose
openssl x509 -in /etc/norc/certs/server.pem -noout -purpose
```

**Solutions**:

1. **Certificate Expired**:
```bash
# Check expiration date
norc-diag inspect --cert /etc/norc/certs/server.pem | grep "Expiration"

# Renew certificate with Let's Encrypt
sudo certbot renew

# Or regenerate self-signed certificate
openssl req -x509 -newkey rsa:2048 -keyout server-key.pem -out server.pem -days 365 -nodes
```

2. **Wrong CA Certificate**:
```bash
# Verify CA chain
openssl verify -CAfile /etc/norc/certs/ca.pem /etc/norc/certs/server.pem

# Download correct CA certificate
wget https://example.com/ca.pem -O /etc/norc/certs/ca.pem
```

3. **Missing Subject Alternative Name (SAN)**:
```bash
# Check SAN
openssl x509 -in /etc/norc/certs/server.pem -noout -ext subjectAltName

# Regenerate certificate with SAN
openssl req -newkey rsa:2048 -keyout server-key.pem -out server-csr.pem -nodes
openssl x509 -req -in server-csr.pem -CA ca.pem -CAkey ca-key.pem \
    -out server.pem -days 365 -extfile <(echo "subjectAltName=DNS:server.example.com,IP:192.168.1.10")
```

### Issue: OCSP/CRL Revocation Check Fails

**Symptoms**:
- Error: "Failed to check revocation status"
- Slow certificate validation
- Warnings about OCSP timeout

**Diagnosis**:

```bash
# Check revocation status
norc-diag revocation --cert /etc/norc/certs/server.pem

# Test OCSP responder manually
openssl ocsp -issuer /etc/norc/certs/ca.pem \
    -cert /etc/norc/certs/server.pem \
    -url http://ocsp.example.com \
    -VAfile /etc/norc/certs/ca.pem

# Check CRL download
wget -O - http://crl.example.com/ca.crl | openssl crl -inform DER -text
```

**Solutions**:

1. **Increase OCSP Timeout**:
```toml
# /etc/norc/config.toml
[security]
ocsp_timeout_seconds = 10  # Increase from 5
```

2. **Disable Revocation Checking (Not Recommended)**:
```toml
[security]
enable_ocsp = false
enable_crl = false
```

3. **Use CRL Fallback**:
```toml
[security]
enable_ocsp = true
enable_crl = true  # Fallback to CRL if OCSP fails
crl_cache_ttl_hours = 24
```

4. **Configure OCSP Stapling**:
```toml
[tls]
enable_ocsp_stapling = true
ocsp_staple_cache_ttl_hours = 24
```

### Issue: Certificate Rotation Fails

**Symptoms**:
- Error: "Certificate rotation failed"
- Old certificate still in use after rotation
- Clients disconnect during rotation

**Diagnosis**:

```bash
# Check rotation logs
sudo journalctl -u norc | grep -i rotation

# Verify new certificate
norc-diag inspect --cert /etc/norc/certs/new-server.pem

# Check rotation configuration
grep -A 10 '\[rotation\]' /etc/norc/config.toml
```

**Solutions**:

1. **Enable Graceful Rotation**:
```bash
# Use Admin API for graceful rotation
curl --cert /etc/norc/certs/admin-client.pem \
     --key /etc/norc/certs/admin-client-key.pem \
     --cacert /etc/norc/certs/ca.pem \
     -X POST https://localhost:8443/api/v1/certificates/rotate \
     -H "Content-Type: application/json" \
     -d '{
       "certificates": [
         {
           "old_fingerprint": "SHA256:ab:cd:ef...",
           "new_certificate": "-----BEGIN CERTIFICATE-----\n...",
           "certificate_chain": ["-----BEGIN CERTIFICATE-----\n..."]
         }
       ],
       "graceful": true,
       "grace_period_seconds": 300
     }'
```

2. **Fix File Permissions**:
```bash
# Ensure new certificate is readable
sudo chown norc:norc /etc/norc/certs/new-server.pem
sudo chmod 644 /etc/norc/certs/new-server.pem
sudo chmod 600 /etc/norc/certs/new-server-key.pem
```

3. **Enable Auto-Reload**:
```toml
[rotation]
auto_reload = true
check_interval_seconds = 300
reload_cooldown_seconds = 10
```

---

## Connection Issues

### Issue: Client Cannot Connect to Server

**Symptoms**:
- Error: "Connection refused"
- Error: "Connection timeout"
- Client hangs during connection

**Diagnosis**:

```bash
# Test connectivity
norc-diag connect --server https://server.example.com:8443

# Check if server is listening
sudo netstat -tlnp | grep 8443

# Test TLS handshake
openssl s_client -connect server.example.com:8443 -showcerts

# Check firewall rules
sudo iptables -L -n | grep 8443
sudo firewall-cmd --list-all
```

**Solutions**:

1. **Server Not Running**:
```bash
# Start server
sudo systemctl start norc
sudo systemctl status norc
```

2. **Firewall Blocking Connection**:
```bash
# Allow port through firewall (iptables)
sudo iptables -A INPUT -p tcp --dport 8443 -j ACCEPT
sudo iptables-save

# Allow port through firewall (firewalld)
sudo firewall-cmd --permanent --add-port=8443/tcp
sudo firewall-cmd --reload

# Allow port through firewall (ufw)
sudo ufw allow 8443/tcp
```

3. **Wrong Server Address**:
```bash
# Verify server configuration
grep -E 'address|port' /etc/norc/config.toml

# Check DNS resolution
nslookup server.example.com
dig server.example.com

# Try IP address instead
norc-diag connect --server https://192.168.1.10:8443
```

### Issue: mTLS Authentication Fails

**Symptoms**:
- Error: "Client certificate required"
- Error: "Certificate verification failed"
- HTTP 401 Unauthorized

**Diagnosis**:

```bash
# Test mTLS connection
curl --cert /etc/norc/certs/client.pem \
     --key /etc/norc/certs/client-key.pem \
     --cacert /etc/norc/certs/ca.pem \
     -v https://server.example.com:8443/api/v1/certificates

# Validate client certificate
norc-diag validate --cert /etc/norc/certs/client.pem --chain /etc/norc/certs/ca.pem

# Check certificate purpose
openssl x509 -in /etc/norc/certs/client.pem -noout -purpose | grep "SSL client"
```

**Solutions**:

1. **Client Certificate Not Provided**:
```bash
# Ensure client certificate is configured
cat ~/.norc/client-config.toml
# [tls]
# cert_path = "/etc/norc/certs/client.pem"
# key_path = "/etc/norc/certs/client-key.pem"
```

2. **Client Certificate Not Trusted**:
```bash
# Verify client certificate is signed by trusted CA
openssl verify -CAfile /etc/norc/certs/ca.pem /etc/norc/certs/client.pem

# Add client certificate to server's trust store
sudo cp /etc/norc/certs/client-ca.pem /etc/norc/certs/trusted-clients/
```

3. **Client Certificate Expired**:
```bash
# Check expiration
norc-diag inspect --cert /etc/norc/certs/client.pem | grep Expiration

# Renew client certificate
openssl req -newkey rsa:2048 -keyout client-key.pem -out client-csr.pem -nodes
openssl x509 -req -in client-csr.pem -CA ca.pem -CAkey ca-key.pem -out client.pem -days 365
```

### Issue: Connection Drops/Timeouts

**Symptoms**:
- Connections drop after period of inactivity
- Error: "Connection reset by peer"
- Intermittent connection failures

**Diagnosis**:

```bash
# Check connection timeout settings
grep timeout /etc/norc/config.toml

# Monitor connections
watch -n 1 'ss -tn | grep :8443'

# Check for network issues
ping -c 10 server.example.com
traceroute server.example.com
```

**Solutions**:

1. **Increase Timeout Values**:
```toml
[server]
connection_timeout_seconds = 300  # 5 minutes
idle_timeout_seconds = 600  # 10 minutes
```

2. **Enable Keep-Alive**:
```toml
[server]
enable_keepalive = true
keepalive_interval_seconds = 60
```

3. **Check Network Path MTU**:
```bash
# Test MTU
ping -M do -s 1472 server.example.com

# Adjust MTU if needed
sudo ip link set dev eth0 mtu 1500
```

---

## Performance Troubleshooting

### Issue: High Latency

**Symptoms**:
- Requests take >1 second to complete
- Slow response times
- Timeout errors

**Diagnosis**:

```bash
# Check metrics
curl http://localhost:9090/metrics | grep -E 'latency|duration'

# Measure request time
time curl --cert /etc/norc/certs/client.pem \
          --key /etc/norc/certs/client-key.pem \
          --cacert /etc/norc/certs/ca.pem \
          https://server.example.com:8443/api/v1/certificates

# Check database performance
sqlite3 /var/lib/norc/norc.db "EXPLAIN QUERY PLAN SELECT * FROM certificates WHERE status = 'active'"
```

**Solutions**:

1. **Optimize Database Queries**:
```bash
# Add indexes
sqlite3 /var/lib/norc/norc.db "CREATE INDEX idx_status ON certificates(status)"
sqlite3 /var/lib/norc/norc.db "CREATE INDEX idx_fingerprint ON certificates(fingerprint)"

# Vacuum database
sqlite3 /var/lib/norc/norc.db "VACUUM"
```

2. **Increase Worker Threads**:
```toml
[server]
worker_threads = 4  # Match CPU cores
max_blocking_threads = 512
```

3. **Enable Connection Pooling**:
```toml
[database]
max_connections = 20
min_connections = 5
connection_timeout_seconds = 30
```

### Issue: High CPU Usage

**Symptoms**:
- CPU usage >80%
- Server becomes unresponsive
- Request queue builds up

**Diagnosis**:

```bash
# Monitor CPU usage
top -p $(pgrep norc-server)

# Profile CPU usage
sudo perf top -p $(pgrep norc-server)

# Check metrics
curl http://localhost:9090/metrics | grep cpu
```

**Solutions**:

1. **Reduce Cryptographic Operations**:
```toml
[security]
# Cache certificate validation results
validation_cache_ttl_seconds = 300
```

2. **Optimize TLS Configuration**:
```toml
[tls]
# Use hardware acceleration
enable_hardware_acceleration = true

# Prefer faster cipher suites
cipher_suites = ["TLS_AES_128_GCM_SHA256"]
```

3. **Rate Limiting**:
```toml
[server]
rate_limit_requests_per_minute = 1000
rate_limit_burst = 100
```

### Issue: Memory Leaks

**Symptoms**:
- Memory usage grows continuously
- Server eventually crashes with OOM
- RSS memory >2GB

**Diagnosis**:

```bash
# Monitor memory over time
while true; do
    date
    ps aux | grep norc-server | grep -v grep
    sleep 60
done | tee memory-usage.log

# Check for leaked connections
ss -tn | grep :8443 | wc -l

# Profile memory allocation
sudo valgrind --leak-check=full /usr/local/bin/norc-server --config /etc/norc/config.toml
```

**Solutions**:

1. **Limit Connection Pool**:
```toml
[database]
max_connections = 10
connection_lifetime_seconds = 3600
```

2. **Enable Periodic Cleanup**:
```toml
[server]
cleanup_interval_seconds = 300
max_idle_connections = 100
```

3. **Restart Periodically** (temporary solution):
```bash
# Add timer to restart daily
sudo systemctl edit norc.service
# [Service]
# Restart=always
# RuntimeMaxSec=86400  # 24 hours
```

---

## Database Issues

### Issue: Database Corruption

**Symptoms**:
- Error: "database disk image is malformed"
- Query failures
- Server crashes on startup

**Diagnosis**:

```bash
# Check database integrity
sqlite3 /var/lib/norc/norc.db "PRAGMA integrity_check"

# Check for corruption
sqlite3 /var/lib/norc/norc.db "PRAGMA quick_check"

# Verify database schema
sqlite3 /var/lib/norc/norc.db ".schema"
```

**Solutions**:

1. **Repair Database**:
```bash
# Export and reimport
sqlite3 /var/lib/norc/norc.db ".dump" > dump.sql
mv /var/lib/norc/norc.db /var/lib/norc/norc.db.corrupt
sqlite3 /var/lib/norc/norc.db < dump.sql
```

2. **Restore from Backup**:
```bash
# Stop server
sudo systemctl stop norc

# Restore backup
sudo cp /var/backups/norc/norc_20250102_020000.db /var/lib/norc/norc.db
sudo chown norc:norc /var/lib/norc/norc.db

# Start server
sudo systemctl start norc
```

3. **Migrate to PostgreSQL** (for production):
```bash
# Export from SQLite
sqlite3 /var/lib/norc/norc.db ".dump" > dump.sql

# Convert to PostgreSQL format
sed 's/AUTOINCREMENT/SERIAL/g' dump.sql > dump_pg.sql

# Import to PostgreSQL
psql -U norc -d norc < dump_pg.sql

# Update configuration
vim /etc/norc/config.toml
# [database]
# type = "postgresql"
# url = "postgresql://norc:password@localhost/norc"
```

### Issue: Database Lock Errors

**Symptoms**:
- Error: "database is locked"
- Write operations fail
- Timeouts on queries

**Diagnosis**:

```bash
# Check for locked database
lsof /var/lib/norc/norc.db

# Check for long-running transactions
sqlite3 /var/lib/norc/norc.db "PRAGMA busy_timeout"

# Monitor lock contention
strace -p $(pgrep norc-server) 2>&1 | grep SQLITE_BUSY
```

**Solutions**:

1. **Increase Busy Timeout**:
```toml
[database]
busy_timeout_ms = 5000  # 5 seconds
```

2. **Enable WAL Mode**:
```bash
# Enable Write-Ahead Logging
sqlite3 /var/lib/norc/norc.db "PRAGMA journal_mode=WAL"
sqlite3 /var/lib/norc/norc.db "PRAGMA synchronous=NORMAL"
```

3. **Reduce Concurrent Writes**:
```toml
[database]
max_connections = 5  # Reduce connection pool
```

### Issue: Migration Failures

**Symptoms**:
- Error: "migration failed"
- Schema version mismatch
- Server won't start after upgrade

**Diagnosis**:

```bash
# Check migration status
sqlite3 /var/lib/norc/norc.db "SELECT * FROM _sqlx_migrations"

# Verify schema version
sqlite3 /var/lib/norc/norc.db "PRAGMA user_version"

# Check for partial migration
sqlite3 /var/lib/norc/norc.db ".tables"
```

**Solutions**:

1. **Retry Migration**:
```bash
# Stop server
sudo systemctl stop norc

# Run migrations manually
norc-server migrate --database-url sqlite:///var/lib/norc/norc.db

# Start server
sudo systemctl start norc
```

2. **Rollback and Retry**:
```bash
# Restore pre-migration backup
sudo cp /var/backups/norc/norc_pre_migration.db /var/lib/norc/norc.db

# Run upgrade again
norc-server --config /etc/norc/config.toml migrate
```

3. **Manual Schema Fix**:
```bash
# Apply specific migration
sqlite3 /var/lib/norc/norc.db < /usr/share/norc/migrations/0001_initial.sql
```

---

## Log Analysis

### Analyzing Server Logs

```bash
# View real-time logs
sudo journalctl -u norc -f

# Filter by log level
sudo journalctl -u norc -p err  # Errors only
sudo journalctl -u norc -p warning  # Warnings and above

# Search for specific errors
sudo journalctl -u norc | grep -i "certificate"
sudo journalctl -u norc | grep -i "connection"

# Export logs for analysis
sudo journalctl -u norc --since "2025-01-01" --until "2025-01-02" > norc-logs.txt
```

### Common Log Patterns

**Certificate Expiration Warning**:
```
WARN certificate expires in 7 days: fingerprint=SHA256:ab:cd:ef...
```
Solution: Renew certificate before expiration

**OCSP Timeout**:
```
ERROR OCSP check timeout: url=http://ocsp.example.com, duration=5.2s
```
Solution: Increase OCSP timeout or disable OCSP

**Connection Refused**:
```
ERROR connection failed: kind=ConnectionRefused, address=192.168.1.10:8443
```
Solution: Check server is running and firewall rules

**Database Lock**:
```
ERROR database operation failed: kind=Busy, message="database is locked"
```
Solution: Enable WAL mode or reduce concurrent writes

### Log Aggregation

**With Promtail/Loki**:

```yaml
# promtail-config.yaml
scrape_configs:
  - job_name: norc
    static_configs:
      - targets:
          - localhost
        labels:
          job: norc
          __path__: /var/log/norc/*.log
    pipeline_stages:
      - json:
          expressions:
            level: level
            message: message
            timestamp: timestamp
```

**With Fluentd**:

```conf
# fluentd.conf
<source>
  @type tail
  path /var/log/norc/norc.log
  pos_file /var/log/td-agent/norc.log.pos
  tag norc
  <parse>
    @type json
  </parse>
</source>

<match norc>
  @type elasticsearch
  host elasticsearch.example.com
  port 9200
  index_name norc
</match>
```

---

## Security Issues

### Issue: Unauthorized Access Attempts

**Symptoms**:
- Multiple failed authentication attempts
- Suspicious IP addresses in logs
- Rate limiting triggered

**Diagnosis**:

```bash
# Check access logs
sudo journalctl -u norc | grep "authentication failed"

# Identify suspicious IPs
sudo journalctl -u norc | grep "401\|403" | awk '{print $NF}' | sort | uniq -c | sort -rn

# Check rate limiting
curl http://localhost:9090/metrics | grep rate_limit
```

**Solutions**:

1. **Enable IP Allowlist**:
```toml
[security]
allowed_ips = ["192.168.1.0/24", "10.0.0.0/8"]
```

2. **Implement Fail2Ban**:
```bash
# Install fail2ban
sudo apt install fail2ban

# Create filter
sudo cat > /etc/fail2ban/filter.d/norc.conf <<EOF
[Definition]
failregex = authentication failed.*client_ip=<HOST>
ignoreregex =
EOF

# Create jail
sudo cat > /etc/fail2ban/jail.d/norc.conf <<EOF
[norc]
enabled = true
filter = norc
logpath = /var/log/norc/norc.log
maxretry = 5
bantime = 3600
findtime = 600
EOF

sudo systemctl restart fail2ban
```

3. **Rotate Certificates**:
```bash
# Rotate compromised certificates
curl --cert /etc/norc/certs/admin-client.pem \
     --key /etc/norc/certs/admin-client-key.pem \
     --cacert /etc/norc/certs/ca.pem \
     -X POST https://localhost:8443/api/v1/certificates/rotate \
     -H "Content-Type: application/json" \
     -d '{"certificates": [...]}'
```

### Issue: TLS Protocol Downgrade

**Symptoms**:
- Weak cipher suites negotiated
- Old TLS versions in use
- Security scanner warnings

**Diagnosis**:

```bash
# Test TLS configuration
testssl.sh --full server.example.com:8443

# Check supported cipher suites
nmap --script ssl-enum-ciphers -p 8443 server.example.com

# Verify TLS version
openssl s_client -connect server.example.com:8443 -tls1_2
openssl s_client -connect server.example.com:8443 -tls1_3
```

**Solutions**:

1. **Enforce Strong TLS**:
```toml
[tls]
min_tls_version = "TLSv1.3"
cipher_suites = [
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_GCM_SHA256",
    "TLS_CHACHA20_POLY1305_SHA256"
]
```

2. **Disable Weak Ciphers**:
```toml
[tls]
disabled_cipher_suites = [
    "TLS_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_256_CBC_SHA"
]
```

---

## Getting Help

### Collect Diagnostic Information

```bash
# Generate diagnostic report
norc-diag health --verbose --json > diag-report.json

# Include system information
uname -a >> diag-report.txt
cat /etc/os-release >> diag-report.txt

# Include configuration (sanitized)
cat /etc/norc/config.toml | sed 's/password = .*/password = REDACTED/' >> diag-report.txt

# Include recent logs
sudo journalctl -u norc -n 500 --no-pager >> diag-report.txt
```

### Submit Issue

1. Check [GitHub Issues](https://github.com/NavaTron/norc/issues)
2. Search for existing issues
3. Create new issue with:
   - NORC version (`norc-server --version`)
   - OS and version
   - Configuration (sanitized)
   - Diagnostic report
   - Steps to reproduce
   - Expected vs actual behavior

### Community Support

- GitHub Discussions: https://github.com/NavaTron/norc/discussions
- Discord: https://discord.gg/norc
- Email: support@navatron.com

---

*Last Updated: 2025-01-02*  
*NORC Troubleshooting Guide v1.0*
