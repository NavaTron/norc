//! NORC Server Main Entry Point
//!
//! This is the main entry point for the NORC server daemon process.
//! It handles command-line arguments, configuration loading, logging setup,
//! and daemon process management.

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use norc_config::{ConfigValidator, NorcConfig};
use norc_server_core::{default_dev_config, NorcServer, ServerHandle};
use std::path::PathBuf;
use std::process;
use std::sync::Arc;
use tokio::signal;
use tracing::{error, info, warn};

/// NORC Server - NavaTron Open Real-time Communication Server
#[derive(Parser)]
#[command(name = "norc-server")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "NORC Protocol Server Implementation")]
#[command(long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
    
    /// Configuration file path
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,
    
    /// Enable development mode (relaxed security, debug logging)
    #[arg(long)]
    dev: bool,
    
    /// Foreground mode (don't daemonize)
    #[arg(short, long)]
    foreground: bool,
    
    /// Validate configuration and exit
    #[arg(long)]
    validate_config: bool,
    
    /// Log level override (error, warn, info, debug, trace)
    #[arg(long)]
    log_level: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the server
    Start(StartArgs),
    /// Stop the server
    Stop(StopArgs),
    /// Restart the server
    Restart(RestartArgs),
    /// Check server status
    Status(StatusArgs),
    /// Validate configuration
    Validate(ValidateArgs),
    /// Generate default configuration
    GenerateConfig(GenerateConfigArgs),
}

#[derive(Args)]
struct StartArgs {
    /// Force start even if already running
    #[arg(long)]
    force: bool,
}

#[derive(Args)]
struct StopArgs {
    /// Force stop (SIGKILL instead of SIGTERM)
    #[arg(long)]
    force: bool,
    
    /// Timeout for graceful shutdown in seconds
    #[arg(long, default_value = "30")]
    timeout: u64,
}

#[derive(Args)]
struct RestartArgs {
    /// Force restart
    #[arg(long)]
    force: bool,
}

#[derive(Args)]
struct StatusArgs {
    /// Show detailed status information
    #[arg(long)]
    detailed: bool,
}

#[derive(Args)]
struct ValidateArgs {
    /// Show detailed validation information
    #[arg(long)]
    detailed: bool,
}

#[derive(Args)]
struct GenerateConfigArgs {
    /// Output file path
    #[arg(short, long)]
    output: Option<PathBuf>,
    
    /// Generate development configuration
    #[arg(long)]
    dev: bool,
    
    /// Overwrite existing file
    #[arg(long)]
    force: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    
    // Handle configuration-only commands first
    if cli.validate_config {
        return validate_config_only(&cli).await;
    }
    
    match &cli.command {
        Some(Commands::Validate(args)) => return validate_config_command(&cli, args).await,
        Some(Commands::GenerateConfig(args)) => return generate_config_command(args).await,
        _ => {}
    }
    
    // Load configuration
    let config = load_configuration(&cli).await?;
    
    // Setup logging
    setup_logging(&config, &cli)?;
    
    info!("NORC Server v{} starting", env!("CARGO_PKG_VERSION"));
    info!("Protocol version: {}", norc_server_core::PROTOCOL_VERSION);
    
    // Handle daemon commands
    match &cli.command {
        Some(Commands::Start(args)) => start_server(config, &cli, args).await,
        Some(Commands::Stop(args)) => stop_server(&config, args).await,
        Some(Commands::Restart(args)) => restart_server(config, &cli, args).await,
        Some(Commands::Status(args)) => show_status(&config, args).await,
        None => start_server(config, &cli, &StartArgs { force: false }).await,
        _ => unreachable!(), // Handled above
    }
}

/// Load configuration from file or use defaults
async fn load_configuration(cli: &Cli) -> Result<NorcConfig> {
    let config = if let Some(config_path) = &cli.config {
        info!("Loading configuration from {}", config_path.display());
        NorcConfig::load_from_file(config_path)
            .with_context(|| format!("Failed to load configuration from {}", config_path.display()))?
    } else if cli.dev {
        info!("Using development configuration");
        default_dev_config()
    } else {
        // Try default locations
        let default_paths = [
            "/etc/norc/norc.toml",
            "~/.config/norc/norc.toml",
            "./norc.toml",
        ];
        
        let mut config = None;
        for path_str in &default_paths {
            let path = PathBuf::from(path_str);
            if path.exists() {
                info!("Found configuration at {}", path.display());
                config = Some(NorcConfig::load_from_file(&path)
                    .with_context(|| format!("Failed to load configuration from {}", path.display()))?);
                break;
            }
        }
        
        config.unwrap_or_else(|| {
            warn!("No configuration file found, using defaults");
            NorcConfig::default()
        })
    };
    
    // Apply CLI overrides
    let mut config = config;
    
    if cli.foreground {
        config.server.process.daemonize = false;
    }
    
    if let Some(log_level) = &cli.log_level {
        config.server.logging.level = log_level.clone();
    }
    
    if cli.dev {
        config.server.logging.format = norc_config::server::LogFormat::Pretty;
        config.security.auth.device.allow_self_signed = true;
    }
    
    Ok(config)
}

/// Setup logging based on configuration
fn setup_logging(config: &NorcConfig, cli: &Cli) -> Result<()> {
    use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
    
    let log_level = &config.server.logging.level;
    let filter = EnvFilter::try_new(log_level)
        .or_else(|_| EnvFilter::try_new("info"))
        .context("Failed to create log filter")?;
    
    let fmt_layer = match config.server.logging.format {
        norc_config::server::LogFormat::Json => {
            fmt::layer().json().boxed()
        }
        norc_config::server::LogFormat::Pretty => {
            fmt::layer().pretty().boxed()
        }
        norc_config::server::LogFormat::Plain => {
            fmt::layer().boxed()
        }
    };
    
    let subscriber = tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer);
    
    subscriber.init();
    
    Ok(())
}

/// Start the server
async fn start_server(mut config: NorcConfig, cli: &Cli, args: &StartArgs) -> Result<()> {
    // Check if already running
    if !args.force && is_server_running(&config)? {
        error!("Server is already running. Use --force to override.");
        process::exit(1);
    }
    
    // Daemonize if requested
    if config.server.process.daemonize && !cli.foreground {
        daemonize(&config)?;
    }
    
    // Create PID file
    if let Some(pid_file) = &config.server.process.pid_file {
        create_pid_file(pid_file)?;
    }
    
    // Start the server
    info!("Starting NORC server on {}", config.server.socket_addr());
    
    let server = NorcServer::new(config.clone()).await?;
    let handle = server.start().await?;
    
    // Setup signal handlers
    let handle_clone = handle.clone();
    tokio::spawn(async move {
        if let Err(e) = setup_signal_handlers(handle_clone).await {
            error!("Signal handler error: {}", e);
        }
    });
    
    // Configuration reload handler
    let config_clone = Arc::new(tokio::sync::Mutex::new(config));
    let handle_clone = handle.clone();
    tokio::spawn(async move {
        if let Err(e) = config_reload_handler(config_clone, handle_clone).await {
            error!("Configuration reload error: {}", e);
        }
    });
    
    // Wait for server to complete
    match handle.wait().await {
        Ok(_) => {
            info!("Server stopped gracefully");
            Ok(())
        }
        Err(e) => {
            error!("Server error: {}", e);
            Err(e.into())
        }
    }
}

/// Stop the server
async fn stop_server(config: &NorcConfig, args: &StopArgs) -> Result<()> {
    info!("Stopping NORC server...");
    
    if !is_server_running(config)? {
        warn!("Server is not running");
        return Ok(());
    }
    
    // Read PID and send signal
    if let Some(pid_file) = &config.server.process.pid_file {
        let pid = read_pid_file(pid_file)?;
        
        if args.force {
            kill_process(pid, libc::SIGKILL)?;
            info!("Server force-stopped");
        } else {
            kill_process(pid, libc::SIGTERM)?;
            
            // Wait for graceful shutdown
            let timeout = std::time::Duration::from_secs(args.timeout);
            if wait_for_process_exit(pid, timeout) {
                info!("Server stopped gracefully");
            } else {
                warn!("Server did not stop within timeout, force killing");
                kill_process(pid, libc::SIGKILL)?;
            }
        }
        
        // Remove PID file
        let _ = std::fs::remove_file(pid_file);
    }
    
    Ok(())
}

/// Restart the server
async fn restart_server(config: NorcConfig, cli: &Cli, args: &RestartArgs) -> Result<()> {
    info!("Restarting NORC server...");
    
    // Stop first
    let stop_args = StopArgs {
        force: args.force,
        timeout: 30,
    };
    stop_server(&config, &stop_args).await?;
    
    // Small delay
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    
    // Start again
    let start_args = StartArgs {
        force: args.force,
    };
    start_server(config, cli, &start_args).await
}

/// Show server status
async fn show_status(config: &NorcConfig, args: &StatusArgs) -> Result<()> {
    if is_server_running(config)? {
        println!("NORC Server: RUNNING");
        
        if args.detailed {
            if let Some(pid_file) = &config.server.process.pid_file {
                if let Ok(pid) = read_pid_file(pid_file) {
                    println!("PID: {}", pid);
                }
            }
            println!("Bind Address: {}", config.server.socket_addr());
            println!("Config File: {:?}", config.metadata.file_path);
        }
    } else {
        println!("NORC Server: NOT RUNNING");
        process::exit(1);
    }
    
    Ok(())
}

/// Validate configuration only
async fn validate_config_only(cli: &Cli) -> Result<()> {
    let config = load_configuration(cli).await?;
    
    match ConfigValidator::validate(&config) {
        Ok(_) => {
            println!("Configuration is valid");
            Ok(())
        }
        Err(e) => {
            eprintln!("Configuration validation failed: {}", e);
            process::exit(1);
        }
    }
}

/// Validate configuration command
async fn validate_config_command(cli: &Cli, args: &ValidateArgs) -> Result<()> {
    let config = load_configuration(cli).await?;
    
    match ConfigValidator::validate(&config) {
        Ok(_) => {
            println!("✓ Configuration is valid");
            
            if args.detailed {
                println!("\nConfiguration summary:");
                println!("  Server: {}", config.server.socket_addr());
                println!("  Max Connections: {}", config.server.max_connections);
                println!("  TLS Cert: {}", config.security.tls.cert_file.display());
                println!("  Log Level: {}", config.server.logging.level);
            }
            Ok(())
        }
        Err(e) => {
            eprintln!("✗ Configuration validation failed: {}", e);
            process::exit(1);
        }
    }
}

/// Generate configuration file
async fn generate_config_command(args: &GenerateConfigArgs) -> Result<()> {
    let config = if args.dev {
        default_dev_config()
    } else {
        NorcConfig::default()
    };
    
    let output_path = args.output.as_ref()
        .map(|p| p.clone())
        .unwrap_or_else(|| PathBuf::from("norc.toml"));
    
    if output_path.exists() && !args.force {
        eprintln!("File {} already exists. Use --force to overwrite.", output_path.display());
        process::exit(1);
    }
    
    config.save_to_file(&output_path)
        .with_context(|| format!("Failed to write configuration to {}", output_path.display()))?;
    
    println!("Configuration written to {}", output_path.display());
    Ok(())
}

/// Setup signal handlers for graceful shutdown
async fn setup_signal_handlers(handle: ServerHandle) -> Result<()> {
    let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())?;
    let mut sigint = signal::unix::signal(signal::unix::SignalKind::interrupt())?;
    let mut sighup = signal::unix::signal(signal::unix::SignalKind::hangup())?;
    
    loop {
        tokio::select! {
            _ = sigterm.recv() => {
                info!("Received SIGTERM, shutting down gracefully");
                handle.shutdown().await?;
                break;
            }
            _ = sigint.recv() => {
                info!("Received SIGINT, shutting down gracefully");
                handle.shutdown().await?;
                break;
            }
            _ = sighup.recv() => {
                info!("Received SIGHUP, reloading configuration");
                if let Err(e) = handle.reload_config().await {
                    error!("Failed to reload configuration: {}", e);
                }
            }
        }
    }
    
    Ok(())
}

/// Configuration reload handler
async fn config_reload_handler(
    config: Arc<tokio::sync::Mutex<NorcConfig>>,
    handle: ServerHandle,
) -> Result<()> {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
    
    loop {
        interval.tick().await;
        
        let mut config_guard = config.lock().await;
        if let Ok(changed) = config_guard.reload_if_changed() {
            if changed {
                info!("Configuration file changed, applying updates");
                drop(config_guard);
                
                if let Err(e) = handle.reload_config().await {
                    error!("Failed to apply configuration changes: {}", e);
                }
            }
        }
    }
}

// Platform-specific helper functions

/// Check if server is running
fn is_server_running(config: &NorcConfig) -> Result<bool> {
    if let Some(pid_file) = &config.server.process.pid_file {
        if !pid_file.exists() {
            return Ok(false);
        }
        
        let pid = read_pid_file(pid_file)?;
        Ok(is_process_running(pid))
    } else {
        // Without PID file, we can't reliably check
        Ok(false)
    }
}

/// Read PID from PID file
fn read_pid_file(path: &PathBuf) -> Result<i32> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read PID file {}", path.display()))?;
    
    content.trim().parse::<i32>()
        .with_context(|| format!("Invalid PID in file {}", path.display()))
}

/// Create PID file
fn create_pid_file(path: &PathBuf) -> Result<()> {
    let pid = process::id();
    
    // Create parent directory if needed
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create PID file directory {}", parent.display()))?;
    }
    
    std::fs::write(path, pid.to_string())
        .with_context(|| format!("Failed to write PID file {}", path.display()))?;
    
    Ok(())
}

/// Check if process is running
fn is_process_running(pid: i32) -> bool {
    unsafe {
        libc::kill(pid, 0) == 0
    }
}

/// Kill process with signal
fn kill_process(pid: i32, signal: i32) -> Result<()> {
    unsafe {
        if libc::kill(pid, signal) != 0 {
            let errno = *libc::__errno_location();
            return Err(anyhow::anyhow!("Failed to kill process {}: errno {}", pid, errno));
        }
    }
    Ok(())
}

/// Wait for process to exit
fn wait_for_process_exit(pid: i32, timeout: std::time::Duration) -> bool {
    let start = std::time::Instant::now();
    
    while start.elapsed() < timeout {
        if !is_process_running(pid) {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    
    false
}

/// Daemonize the process
fn daemonize(config: &NorcConfig) -> Result<()> {
    // Fork and exit parent
    unsafe {
        let pid = libc::fork();
        if pid < 0 {
            return Err(anyhow::anyhow!("Failed to fork"));
        }
        if pid > 0 {
            // Parent process exits
            process::exit(0);
        }
    }
    
    // Create new session
    unsafe {
        if libc::setsid() < 0 {
            return Err(anyhow::anyhow!("Failed to create new session"));
        }
    }
    
    // Change working directory if configured
    if let Some(work_dir) = &config.server.process.working_directory {
        std::env::set_current_dir(work_dir)
            .with_context(|| format!("Failed to change working directory to {}", work_dir.display()))?;
    }
    
    // Redirect stdout/stderr to log files or /dev/null
    // This would typically be handled by the logging system
    
    Ok(())
}
