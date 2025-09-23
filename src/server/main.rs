//! NORC Server Main Entry Point
//!
//! This is the main entry point for the NORC server daemon process.
//! It handles command-line arguments, configuration loading, logging setup,
//! and daemon process management.

use std::process;
use clap::{Arg, Command};
use tracing::{error, info, warn};

use norc_server_core::{Daemon, DaemonConfig, ServerConfig};
use norc_config::{ConfigLoader, ServerConfiguration};

#[tokio::main]
async fn main() {
    // Parse command line arguments
    let matches = Command::new("norc-server")
        .version(env!("CARGO_PKG_VERSION"))
        .author("NavaTron Holding B.V.")
        .about("NavaTron Open Real-time Communication Server")
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("FILE")
                .help("Configuration file path")
        )
        .arg(
            Arg::new("daemon")
                .short('d')
                .long("daemon")
                .action(clap::ArgAction::SetTrue)
                .help("Run as daemon (background process)")
        )
        .arg(
            Arg::new("pid-file")
                .short('p')
                .long("pid-file")
                .value_name("FILE")
                .help("PID file path")
        )
        .arg(
            Arg::new("log-level")
                .short('l')
                .long("log-level")
                .value_name("LEVEL")
                .help("Log level (trace, debug, info, warn, error)")
                .default_value("info")
        )
        .arg(
            Arg::new("bind-address")
                .short('b')
                .long("bind")
                .value_name("ADDRESS")
                .help("Bind address (e.g., 0.0.0.0:4242)")
        )
        .get_matches();

    // Load configuration
    let config = match load_configuration(&matches) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Configuration error: {}", e);
            process::exit(1);
        }
    };

    // Setup logging
    if let Err(e) = setup_logging(&config, matches.get_one::<String>("log-level").unwrap()) {
        eprintln!("Logging setup error: {}", e);
        process::exit(1);
    }

    info!("Starting NORC server v{}", env!("CARGO_PKG_VERSION"));
    info!("Configuration loaded successfully");

    // Create daemon configuration
    let daemon_config = create_daemon_config(&config, &matches);

    // Create and start daemon
    let mut daemon = Daemon::new(daemon_config);
    
    match daemon.start().await {
        Ok(_) => {
            info!("NORC server shutdown complete");
        }
        Err(e) => {
            error!("Server error: {}", e);
            process::exit(1);
        }
    }
}

/// Load configuration from file or environment
fn load_configuration(matches: &clap::ArgMatches) -> Result<ServerConfiguration, Box<dyn std::error::Error>> {
    let config = if let Some(config_file) = matches.get_one::<String>("config") {
        // Load from specified file
        ConfigLoader::from_file(config_file)?
    } else {
        // Load with default search paths and environment fallback
        ConfigLoader::load()?
    };

    info!("Loaded configuration from file and environment");
    Ok(config)
}

/// Setup logging based on configuration and command line arguments
fn setup_logging(
    config: &ServerConfiguration, 
    log_level: &str
) -> Result<(), Box<dyn std::error::Error>> {
    use tracing_subscriber::{fmt, EnvFilter};
    use tracing_appender::rolling::{RollingFileAppender, Rotation};

    // Determine log level (CLI overrides config)
    let level = log_level;

    // Create environment filter
    let env_filter = EnvFilter::try_new(level)
        .unwrap_or_else(|_| EnvFilter::new("info"));

    // Setup subscriber based on configuration
    match config.logging.file_path.as_ref() {
        Some(file_path) => {
            // Log to file with optional rotation
            if config.logging.rotation {
                let file_appender = RollingFileAppender::new(
                    Rotation::DAILY,
                    std::path::Path::new(file_path).parent().unwrap_or(std::path::Path::new(".")),
                    std::path::Path::new(file_path).file_name().unwrap_or(std::ffi::OsStr::new("norc-server.log"))
                );
                
                let subscriber = fmt::Subscriber::builder()
                    .with_env_filter(env_filter)
                    .with_writer(file_appender)
                    .with_ansi(false);

                match config.logging.format.as_str() {
                    "json" => {
                        tracing::subscriber::set_global_default(subscriber.json().finish())?;
                    }
                    "compact" => {
                        tracing::subscriber::set_global_default(subscriber.compact().finish())?;
                    }
                    _ => {
                        tracing::subscriber::set_global_default(subscriber.pretty().finish())?;
                    }
                }
            } else {
                // Simple file logging without rotation
                let file = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(file_path)?;
                
                let subscriber = fmt::Subscriber::builder()
                    .with_env_filter(env_filter)
                    .with_writer(file)
                    .with_ansi(false);

                match config.logging.format.as_str() {
                    "json" => {
                        tracing::subscriber::set_global_default(subscriber.json().finish())?;
                    }
                    "compact" => {
                        tracing::subscriber::set_global_default(subscriber.compact().finish())?;
                    }
                    _ => {
                        tracing::subscriber::set_global_default(subscriber.pretty().finish())?;
                    }
                }
            }
        }
        None => {
            // Log to stdout
            let subscriber = fmt::Subscriber::builder()
                .with_env_filter(env_filter);

            match config.logging.format.as_str() {
                "json" => {
                    tracing::subscriber::set_global_default(subscriber.json().finish())?;
                }
                "compact" => {
                    tracing::subscriber::set_global_default(subscriber.compact().finish())?;
                }
                _ => {
                    tracing::subscriber::set_global_default(subscriber.pretty().finish())?;
                }
            }
        }
    }

    info!("Logging initialized with level: {}", level);
    Ok(())
}

/// Create daemon configuration from server config and CLI arguments
fn create_daemon_config(config: &ServerConfiguration, matches: &clap::ArgMatches) -> DaemonConfig {
    // Create server configuration
    let server_config = ServerConfig {
        bind_address: if let Some(bind_addr) = matches.get_one::<String>("bind-address") {
            bind_addr.parse().unwrap_or_else(|e| {
                warn!("Invalid bind address '{}': {}. Using config default.", bind_addr, e);
                config.bind_address().unwrap_or_else(|_| "0.0.0.0:4242".parse().unwrap())
            })
        } else {
            config.bind_address().unwrap_or_else(|_| "0.0.0.0:4242".parse().unwrap())
        },
        max_connections: config.performance.max_connections,
        connection_timeout: config.network.connection_timeout,
        enable_tls: config.security.enable_tls,
        tls_cert_path: config.security.tls_cert_path.clone(),
        tls_key_path: config.security.tls_key_path.clone(),
        server_name: config.security.server_name.clone(),
    };

    // Create daemon configuration
    DaemonConfig {
        server: server_config,
        pid_file: matches.get_one::<String>("pid-file")
            .map(|s| s.clone())
            .or_else(|| config.daemon.pid_file.clone()),
        daemon_user: config.daemon.user.clone(),
        daemon_group: config.daemon.group.clone(),
        daemonize: matches.get_flag("daemon") || config.daemon.daemonize,
    }
}
