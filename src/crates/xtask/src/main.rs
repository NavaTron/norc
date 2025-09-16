//! NavaTron xtask automation binary
//!
//! Provides reproducible developer workflows decoupled from user-facing crates.
//! Inspired by the community 'xtask' pattern.
//!
//! Commands (initial):
//! - ci: run fmt, clippy (deny warnings), tests
//! - lint: run clippy + format check
//! - audit: (placeholder) security audits (cargo-audit / cargo-deny future)
//! - coverage: (placeholder) produce coverage report
//! - bench: (placeholder) run criterion benches

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
    /// Security auditing (placeholder)
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
    info!("step=fmt");
    run("cargo", &["fmt", "--", "--check"], None)?;
    info!("step=clippy");
    run("cargo", &["clippy", "--all-targets", "--all-features", "--", "-D", "warnings"], None)?;
    info!("step=test");
    run("cargo", &["test", "--all"], None)?;
    info!("ci pipeline complete");
    Ok(())
}

fn lint_only() -> Result<()> {
    run("cargo", &["fmt", "--", "--check"], None)?;
    run("cargo", &["clippy", "--all-targets", "--all-features", "--", "-D", "warnings"], None)?;
    Ok(())
}

fn audit() -> Result<()> {
    info!("audit placeholder - integrate cargo-audit / cargo-deny later");
    Ok(())
}

fn coverage() -> Result<()> {
    info!("coverage placeholder - integrate cargo-llvm-cov later");
    Ok(())
}

fn bench() -> Result<()> {
    info!("bench placeholder - integrate criterion benches later");
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
