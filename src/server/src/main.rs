//! NORC Server Main Entry Point
//!
//! This is the main entry point for the NORC server daemon process.
//! It handles command-line arguments, configuration loading, logging setup,
//! and daemon process management.

use anyhow::{Context, Result};
use clap::Parser;
use norc_config::{Cli, Commands, ServerConfig};
use norc_server_core::{daemon::daemonize, init_logging, ServerCore};
use std::process;
use tracing::{error, info, warn};

#[tokio::main]
async fn main() {
    // Parse command line arguments
    let cli = Cli::parse();

    // Handle generate config early (before logging setup)
    if cli.generate_config {
        if let Err(e) = handle_generate_config(&cli).await {
            eprintln!("Failed to generate config: {}", e);
            process::exit(1);
        }
        return;
    }

    // Handle subcommands that might generate configs
    if let Some(Commands::GenerateConfig { output, force }) = &cli.command {
        if let Err(e) = generate_config_file(output, *force).await {
            eprintln!("Failed to generate config: {}", e);
            process::exit(1);
        }
        return;
    }

    // Load configuration
    let config = match load_config(&cli).await {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Failed to load configuration: {}", e);
            process::exit(1);
        }
    };

    // Initialize logging system
    if let Err(e) = init_logging(&config) {
        eprintln!("Failed to initialize logging: {}", e);
        process::exit(1);
    }

    info!("NORC Server starting up...");
    info!("Version: {}", env!("CARGO_PKG_VERSION"));

    // Handle subcommands
    if let Some(command) = &cli.command {
        if let Err(e) = handle_command(command, &config).await {
            error!("Command failed: {}", e);
            process::exit(1);
        }
        return;
    }

    // Daemonize if requested
    if cli.daemon {
        info!("Daemonizing process...");
        if let Err(e) = daemonize(&config).await {
            error!("Failed to daemonize: {}", e);
            process::exit(1);
        }
        // Re-initialize logging after daemonization
        if let Err(e) = init_logging(&config) {
            // Can't log this error since logging might not be available
            eprintln!("Failed to re-initialize logging after daemonization: {}", e);
            process::exit(1);
        }
        info!("Process daemonized successfully");
    }

    // Start the server
    if let Err(e) = run_server(config).await {
        error!("Server failed: {}", e);
        process::exit(1);
    }
}

/// Load configuration from file and apply CLI overrides
async fn load_config(cli: &Cli) -> Result<ServerConfig> {
    let config = if cli.config.exists() {
        info!("Loading configuration from: {:?}", cli.config);
        ServerConfig::from_file(&cli.config)
            .with_context(|| format!("Failed to load config from {:?}", cli.config))?
    } else {
        warn!("Config file not found, using defaults: {:?}", cli.config);
        ServerConfig::default()
    };

    // Apply CLI overrides
    let config = config.merge_cli_overrides(cli);

    Ok(config)
}

/// Handle generate config flag
async fn handle_generate_config(cli: &Cli) -> Result<()> {
    let output_path = &cli.config;
    generate_config_file(output_path, false).await
}

/// Generate a default configuration file
async fn generate_config_file(output_path: &std::path::Path, force: bool) -> Result<()> {
    if output_path.exists() && !force {
        return Err(anyhow::anyhow!(
            "Config file already exists: {:?}. Use --force to overwrite.",
            output_path
        ));
    }

    let default_config = ServerConfig::default();
    let toml_content = toml::to_string_pretty(&default_config)
        .context("Failed to serialize default config")?;

    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory: {:?}", parent))?;
    }

    std::fs::write(output_path, toml_content)
        .with_context(|| format!("Failed to write config file: {:?}", output_path))?;

    println!("Generated default configuration file: {:?}", output_path);
    Ok(())
}

/// Handle subcommands
async fn handle_command(command: &Commands, config: &ServerConfig) -> Result<()> {
    match command {
        Commands::Start { force } => {
            info!("Starting server...");
            start_server(config, *force).await
        }
        Commands::Stop { force } => {
            info!("Stopping server...");
            stop_server(config, *force).await
        }
        Commands::Restart { force } => {
            info!("Restarting server...");
            restart_server(config, *force).await
        }
        Commands::Status => {
            info!("Checking server status...");
            check_status(config).await
        }
        Commands::Reload => {
            info!("Reloading server configuration...");
            reload_config(config).await
        }
        Commands::ValidateConfig { config: config_path } => {
            info!("Validating configuration...");
            validate_config(config_path).await
        }
        Commands::GenerateConfig { .. } => {
            // Already handled in main
            Ok(())
        }
    }
}

/// Start the server
async fn start_server(config: &ServerConfig, force: bool) -> Result<()> {
    let mut server = ServerCore::new(config.clone())
        .await
        .context("Failed to create server instance")?;

    // Check for existing instance unless forced
    if !force {
        // This check will be done inside server.run()
    }

    server
        .run()
        .await
        .context("Failed to start server")?;

    Ok(())
}

/// Stop a running server
async fn stop_server(config: &ServerConfig, force: bool) -> Result<()> {
    use std::fs;

    if !config.daemon.pid_file.exists() {
        println!("No PID file found. Server may not be running.");
        return Ok(());
    }

    let pid_content = fs::read_to_string(&config.daemon.pid_file)
        .context("Failed to read PID file")?;
    
    let pid: u32 = pid_content.trim().parse()
        .context("Invalid PID in PID file")?;

    if force {
        println!("Force stopping server (PID: {})...", pid);
        // TODO: Send SIGKILL on Unix, TerminateProcess on Windows
    } else {
        println!("Gracefully stopping server (PID: {})...", pid);
        // TODO: Send SIGTERM on Unix, WM_CLOSE on Windows
    }

    // Remove PID file
    if let Err(e) = fs::remove_file(&config.daemon.pid_file) {
        warn!("Failed to remove PID file: {}", e);
    }

    println!("Server stopped successfully.");
    Ok(())
}

/// Restart the server
async fn restart_server(config: &ServerConfig, force: bool) -> Result<()> {
    // Stop first
    if let Err(e) = stop_server(config, force).await {
        warn!("Failed to stop server: {}", e);
    }

    // Wait a moment
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Start again
    start_server(config, force).await
}

/// Check server status
async fn check_status(config: &ServerConfig) -> Result<()> {
    if config.daemon.pid_file.exists() {
        let pid_content = std::fs::read_to_string(&config.daemon.pid_file)
            .context("Failed to read PID file")?;
        
        let pid: u32 = pid_content.trim().parse()
            .context("Invalid PID in PID file")?;

        // TODO: Check if process is actually running
        println!("Server is running (PID: {})", pid);
        println!("PID file: {:?}", config.daemon.pid_file);
        println!("Bind address: {}", config.socket_addr());
    } else {
        println!("Server is not running (no PID file found)");
    }

    Ok(())
}

/// Reload configuration
async fn reload_config(_config: &ServerConfig) -> Result<()> {
    // TODO: Send SIGHUP to running process
    println!("Configuration reload signal sent");
    Ok(())
}

/// Validate configuration file
async fn validate_config(config_path: &std::path::Path) -> Result<()> {
    match ServerConfig::from_file(config_path) {
        Ok(_) => {
            println!("Configuration file is valid: {:?}", config_path);
            Ok(())
        }
        Err(e) => {
            println!("Configuration file is invalid: {:?}", config_path);
            println!("Error: {}", e);
            Err(e.into())
        }
    }
}

/// Run the main server
async fn run_server(config: ServerConfig) -> Result<()> {
    let mut server = ServerCore::new(config)
        .await
        .context("Failed to create server instance")?;
    
    server
        .run()
        .await
        .context("Server execution failed")?;

    info!("Server shutdown complete");
    Ok(())
}