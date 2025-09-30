# NORC Server

A production-ready daemon server for the NavaTron Open Real-time Communication (NORC) protocol.

## Features

- **Production-Ready Daemon**: Proper backgrounding, PID file management, and signal handling
- **Graceful Shutdown**: Responds to SIGTERM, SIGINT, and other signals for clean shutdown
- **Auto-Restart**: Automatic crash detection and restart with configurable limits
- **Cross-Platform**: Supports Linux, macOS, and Windows (x64 + ARM64)
- **Structured Logging**: JSON, pretty, and compact log formats with rotation
- **Flexible Configuration**: TOML configuration files with CLI overrides
- **TLS Support**: Built-in TLS/SSL encryption with configurable security settings

## Installation

Build from source:

```bash
cargo build --release --bin norc-server
```

The binary will be available at `target/release/norc-server`.

## Quick Start

1. **Generate a default configuration file:**
   ```bash
   ./norc-server --generate-config
   ```

2. **Edit the configuration** (`config.toml`) as needed.

3. **Start the server:**
   ```bash
   ./norc-server
   ```

4. **Run as daemon:**
   ```bash
   ./norc-server --daemon
   ```

## Configuration

The server uses TOML configuration files. See the `examples/` directory for sample configurations:

- `config.toml` - Default configuration with comments
- `config-production.toml` - Production-ready settings
- `config-development.toml` - Development-friendly settings

### Configuration Sections

#### Network
- `bind_address`: IP address to bind to
- `port`: Port number for NORC protocol
- `max_connections`: Maximum concurrent connections
- `connection_timeout_secs`: Connection timeout
- `ipv6_enabled`: Enable IPv6 support

#### TLS
- `enabled`: Enable/disable TLS encryption
- `cert_file`: Path to certificate file (PEM format)
- `key_file`: Path to private key file (PEM format)
- `ca_file`: Path to CA certificate for client verification
- `require_client_certs`: Require client certificates
- `min_version`: Minimum TLS version (1.2 or 1.3)

#### Logging
- `level`: Log level (trace, debug, info, warn, error)
- `format`: Log format (json, pretty, compact)
- `file`: Log file path (stdout if not specified)
- `rotation`: Enable log file rotation
- `max_size_mb`: Maximum log file size before rotation
- `max_files`: Number of rotated files to keep

#### Storage
- `data_dir`: Directory for persistent data
- `max_disk_usage_mb`: Maximum disk usage limit
- `compression_enabled`: Enable data compression
- `backup_interval_hours`: Automatic backup interval
- `backup_retention`: Number of backups to keep

#### Daemon
- `pid_file`: Path to PID file
- `user`: User to run as (Unix only)
- `group`: Group to run as (Unix only)
- `working_dir`: Working directory
- `auto_restart`: Enable automatic restart on crash
- `max_restarts`: Maximum restart attempts
- `restart_cooldown_secs`: Cooldown between restarts

## Command Line Usage

### Basic Commands

```bash
# Start server with default config
./norc-server

# Start with custom config file
./norc-server -c /path/to/config.toml

# Start as daemon (background process)
./norc-server --daemon

# Override settings via CLI
./norc-server --port 9443 --log-level debug
```

### Subcommands

```bash
# Generate default configuration
./norc-server generate-config

# Start server
./norc-server start

# Stop server gracefully
./norc-server stop

# Force stop server
./norc-server stop --force

# Restart server
./norc-server restart

# Check server status
./norc-server status

# Reload configuration
./norc-server reload

# Validate configuration file
./norc-server validate-config config.toml
```

### CLI Options

- `-c, --config <FILE>`: Configuration file path (default: config.toml)
- `-l, --log-level <LEVEL>`: Override log level (trace, debug, info, warn, error)
- `-b, --bind <ADDRESS>`: Override bind address
- `-p, --port <PORT>`: Override port number
- `-d, --daemon`: Run as daemon (background process)
- `--generate-config`: Generate default configuration file

## Service Management

### systemd (Linux)

Create `/etc/systemd/system/norc-server.service`:

```ini
[Unit]
Description=NORC Server
After=network.target

[Service]
Type=forking
User=norc-server
Group=norc-server
ExecStart=/usr/local/bin/norc-server --config /etc/norc-server/config.toml --daemon
ExecReload=/bin/kill -HUP $MAINPID
PIDFile=/var/run/norc-server.pid
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable norc-server
sudo systemctl start norc-server
```

### launchd (macOS)

Create `/Library/LaunchDaemons/com.navatron.norc-server.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.navatron.norc-server</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/norc-server</string>
        <string>--config</string>
        <string>/usr/local/etc/norc-server/config.toml</string>
        <string>--daemon</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
```

Load and start:
```bash
sudo launchctl load /Library/LaunchDaemons/com.navatron.norc-server.plist
```

### Windows Service

Windows service support is planned for future releases. Currently, the server can run as a console application or be managed using tools like NSSM.

## Signal Handling

The server responds to the following signals:

- **SIGTERM**: Graceful shutdown
- **SIGINT** (Ctrl+C): Graceful shutdown  
- **SIGQUIT**: Quick shutdown
- **SIGHUP**: Reload configuration (Unix only)

## Logging

The server supports three log formats:

### JSON Format
Structured JSON logs suitable for log aggregation systems:
```json
{"timestamp":"2024-01-01T12:00:00.000Z","level":"INFO","target":"norc_server","message":"Server started"}
```

### Pretty Format
Human-readable format for development:
```
2024-01-01T12:00:00.000Z  INFO norc_server: Server started
```

### Compact Format
Minimal format for production:
```
INFO Server started
```

## Security Considerations

1. **TLS Configuration**: Always use TLS in production with strong certificates
2. **User Privileges**: Run the server as a dedicated non-root user
3. **File Permissions**: Protect configuration files and private keys
4. **Network Access**: Use firewalls to restrict access to the server port
5. **Log Security**: Ensure log files are properly secured and rotated

## Troubleshooting

### Common Issues

**Server won't start:**
- Check configuration file syntax with `validate-config`
- Verify port is not already in use
- Check file permissions on data directory and log files

**High memory usage:**
- Reduce `max_connections` in configuration
- Enable `compression_enabled` for storage
- Check for log file rotation issues

**Connection issues:**
- Verify `bind_address` and `port` settings
- Check firewall rules
- Validate TLS certificate configuration

### Debug Mode

Run with debug logging to troubleshoot issues:
```bash
./norc-server --log-level debug
```

## Performance Tuning

### High Load Scenarios

For high-traffic deployments:

1. Increase `max_connections` based on your hardware
2. Use a dedicated data partition with fast storage
3. Enable `compression_enabled` to reduce disk usage
4. Increase log rotation settings for busy systems
5. Consider running multiple instances behind a load balancer

### Resource Limits

The server is designed to be resource-efficient:
- Memory usage scales with concurrent connections
- Disk usage is limited by `max_disk_usage_mb` setting
- CPU usage is minimal when idle

## Development

This server currently implements only the daemon infrastructure. The NORC protocol logic will be added in future releases.

## License

Licensed under the Apache License, Version 2.0. See LICENSE file for details.