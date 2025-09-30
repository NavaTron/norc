//! Command-line interface definitions

use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// NORC Server CLI
#[derive(Parser, Debug)]
#[command(name = "norc-server")]
#[command(about = "NavaTron Open Real-time Communication Server")]
#[command(version)]
pub struct Cli {
    /// Path to configuration file
    #[arg(short, long, default_value = "config.toml")]
    pub config: PathBuf,

    /// Log level override (trace, debug, info, warn, error)
    #[arg(short, long)]
    pub log_level: Option<String>,

    /// Bind address override
    #[arg(short, long)]
    pub bind: Option<String>,

    /// Port override
    #[arg(short, long)]
    pub port: Option<u16>,

    /// Run as daemon (background process)
    #[arg(short, long)]
    pub daemon: bool,

    /// Generate default configuration file
    #[arg(long)]
    pub generate_config: bool,

    /// Subcommands
    #[command(subcommand)]
    pub command: Option<Commands>,
}

/// Available subcommands
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Start the server
    Start {
        /// Force start even if PID file exists
        #[arg(long)]
        force: bool,
    },
    /// Stop a running server
    Stop {
        /// Force stop (kill instead of graceful shutdown)
        #[arg(long)]
        force: bool,
    },
    /// Restart the server
    Restart {
        /// Force restart
        #[arg(long)]
        force: bool,
    },
    /// Check server status
    Status,
    /// Reload configuration
    Reload,
    /// Generate configuration file
    GenerateConfig {
        /// Output path for config file
        #[arg(short, long, default_value = "config.toml")]
        output: PathBuf,
        /// Overwrite existing file
        #[arg(long)]
        force: bool,
    },
    /// Validate configuration file
    ValidateConfig {
        /// Path to config file to validate
        #[arg(default_value = "config.toml")]
        config: PathBuf,
    },
}