//! NORC Certificate Diagnostic Tool
//!
//! CLI tool for testing and troubleshooting certificate operations

use anyhow::Result;
use clap::{Parser, Subcommand};
use norc_cli::{
    check_revocation, inspect_certificate, print_config_validation, print_health_results,
    print_revocation_result, print_validation_result, run_health_checks, validate_certificate,
    validate_certificate_chain, validate_configuration,
};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "norc-diag")]
#[command(about = "NORC Certificate Diagnostic Tool", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Validate a certificate file
    Validate {
        /// Path to certificate file (PEM format)
        #[arg(short, long)]
        cert: PathBuf,
        
        /// Path to certificate chain file (optional)
        #[arg(short = 'C', long)]
        chain: Option<PathBuf>,
    },
    
    /// Check certificate revocation status
    Revocation {
        /// Path to certificate file
        #[arg(short, long)]
        cert: PathBuf,
        
        /// Use OCSP for revocation checking
        #[arg(long, default_value_t = true)]
        ocsp: bool,
        
        /// Use CRL for revocation checking
        #[arg(long, default_value_t = false)]
        crl: bool,
    },
    
    /// Run health checks on certificate infrastructure
    Health,
    
    /// Validate NORC configuration file
    Config {
        /// Path to configuration file
        #[arg(short, long, default_value = "/etc/norc/config.toml")]
        file: PathBuf,
    },
    
    /// Inspect and display certificate details
    Inspect {
        /// Path to certificate file
        #[arg(short, long)]
        cert: PathBuf,
    },
    
    /// Run all diagnostic checks
    All {
        /// Path to certificate file
        #[arg(short, long)]
        cert: PathBuf,
        
        /// Path to configuration file
        #[arg(short = 'C', long, default_value = "/etc/norc/config.toml")]
        config: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Validate { cert, chain } => {
            let result = if let Some(chain_path) = chain {
                validate_certificate_chain(&cert, Some(&chain_path))?
            } else {
                validate_certificate(&cert)?
            };
            print_validation_result(&result);
        }
        
        Commands::Revocation { cert, ocsp, crl } => {
            let result = check_revocation(&cert, ocsp, crl)?;
            print_revocation_result(&result);
        }
        
        Commands::Health => {
            let results = run_health_checks()?;
            print_health_results(&results);
        }
        
        Commands::Config { file } => {
            let issues = validate_configuration(&file)?;
            print_config_validation(&issues);
        }
        
        Commands::Inspect { cert } => {
            inspect_certificate(&cert)?;
        }
        
        Commands::All { cert, config } => {
            println!("Running comprehensive diagnostics...\n");
            
            // 1. Certificate validation
            println!("1. Certificate Validation");
            println!("{}", "─".repeat(70));
            let validation_result = validate_certificate(&cert)?;
            print_validation_result(&validation_result);
            println!();
            
            // 2. Revocation check
            println!("2. Revocation Check");
            println!("{}", "─".repeat(70));
            let revocation_result = check_revocation(&cert, true, false)?;
            print_revocation_result(&revocation_result);
            println!();
            
            // 3. Health checks
            println!("3. System Health Checks");
            println!("{}", "─".repeat(70));
            let health_results = run_health_checks()?;
            print_health_results(&health_results);
            println!();
            
            // 4. Configuration validation
            println!("4. Configuration Validation");
            println!("{}", "─".repeat(70));
            let config_issues = validate_configuration(&config)?;
            print_config_validation(&config_issues);
            
            println!();
            println!("Comprehensive diagnostics complete!");
        }
    }
    
    Ok(())
}
