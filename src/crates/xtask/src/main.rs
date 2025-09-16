//! NavaTron xtask automation binary
//!
//! Provides reproducible developer workflows decoupled from user-facing crates.
//! Inspired by the community 'xtask' pattern.
//!
//! Commands:
//! - ci: run fmt, clippy (deny warnings), tests, cargo-deny, (optional) cargo-audit
//! - lint: run clippy + format check
//! - audit: run cargo-deny + cargo-audit (if installed)
//! - coverage: produce coverage report with cargo-llvm-cov (if installed)
//! - bench: run criterion benches (once added)

#![forbid(unsafe_code)]

use std::{process::Command, path::PathBuf};
use clap::{Parser, Subcommand};
use anyhow::{Result, anyhow};
use tracing::{info, error};

#[derive(Debug, Parser)]
#[command(name="xtask", about="NavaTron developer automation")] 
pub struct XtaskCli {
    #[command(subcommand)]
    pub command: XtaskCommand,

    /// Increase verbosity (-v, -vv)
    #[arg(short = 'v', action = clap::ArgAction::Count)]
    pub verbose: u8,
}

#[derive(Debug, Subcommand)]
pub enum XtaskCommand {
    /// Run full CI pipeline (format, clippy, test)
    Ci,
    /// Run clippy & format check only
    Lint,
    /// Security auditing (cargo-deny + optional cargo-audit)
    Audit,
    /// Generate coverage report (placeholder)
    Coverage,
    /// Run benchmarks (placeholder)
    Bench,
}

fn main() -> Result<()> {
    init_tracing();
    let cli = XtaskCli::parse();
    match cli.command {
        XtaskCommand::Ci => ci_pipeline(),
        XtaskCommand::Lint => lint_only(),
        XtaskCommand::Audit => audit(),
        XtaskCommand::Coverage => coverage(),
        XtaskCommand::Bench => bench(),
    }
}

fn init_tracing() {
    use tracing_subscriber::{fmt, EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::registry().with(filter).with(fmt::layer()).init();
}

fn ci_pipeline() -> Result<()> {
    info!(step = "fmt");
    run("cargo", &["fmt", "--", "--check"], None)?;
    info!(step = "clippy");
    run("cargo", &["clippy", "--all-targets", "--all-features", "--", "-D", "warnings"], None)?;
    info!(step = "test");
    run("cargo", &["test", "--all"], None)?;
    info!(step = "deny");
    if let Err(e) = run("cargo", &["deny", "check"], None) { error!(error=?e, "cargo-deny failed"); return Err(e); }
    info!(step = "audit(optional)");
    let _ = run_optional("cargo", &["audit"], None);
    info!("ci pipeline complete");
    Ok(())
}

fn lint_only() -> Result<()> {
    run("cargo", &["fmt", "--", "--check"], None)?;
    run("cargo", &["clippy", "--all-targets", "--all-features", "--", "-D", "warnings"], None)?;
    Ok(())
}

fn audit() -> Result<()> {
    info!(step = "cargo-deny");
    run("cargo", &["deny", "check"], None)?;
    info!(step = "cargo-audit(optional)");
    let _ = run_optional("cargo", &["audit"], None);
    Ok(())
}

fn coverage() -> Result<()> {
    info!(step = "llvm-cov");
    // Typical invocation: cargo llvm-cov --workspace --html
    let _ = run_optional("cargo", &["llvm-cov", "--workspace", "--fail-under-lines", "70"], None)?;
    Ok(())
}

fn bench() -> Result<()> {
    info!(step = "bench" );
    let _ = run_optional("cargo", &["bench"], None)?; // Will succeed once benches exist
    Ok(())
}

fn run(cmd: &str, args: &[&str], cwd: Option<&PathBuf>) -> Result<()> {
    info!(command=%cmd, ?args, "run");
    let mut command = Command::new(cmd);
    command.args(args);
    if let Some(dir) = cwd { command.current_dir(dir); }
    let status = command.status().map_err(|e| anyhow!("spawn {cmd}: {e}"))?;
    if !status.success() { return Err(anyhow!("command {cmd} failed with status {status}")); }
    Ok(())
}

fn run_optional(cmd: &str, args: &[&str], cwd: Option<&PathBuf>) -> Result<()> {
    match run(cmd, args, cwd) {
        Ok(_) => Ok(()),
        Err(e) => {
            info!(command=%cmd, ?args, "optional step skipped or failed");
            Err(e)
        }
    }
}
