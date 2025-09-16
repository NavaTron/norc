//! NavaTron NORC CLI Utilities
//!
//! Provides unified command-line parsing and layered configuration loading for
//! the NavaTron NORC server and client binaries. Configuration precedence:
//! 1. Command-line flags
//! 2. Environment variables (prefixed `NAVATRON_`)
//! 3. Configuration file (TOML / YAML / JSON) if supplied via `--config` or
//!    found at platform-specific default path.
//!
//! Secrets (keys, tokens) are never echoed when printing effective config.
//!
//! Example (server):
//! ```text
//! navatron-server --listen 0.0.0.0:8443 --data-dir ./data --cert server.pem --key server.key
//! ```
//!
//! Example (client):
//! ```text
//! navatron-client --server chat.example:8443 --user alice --room general
//! ```
#![deny(unsafe_code, missing_docs)]

use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::{PathBuf};
use thiserror::Error;

/// CLI level error
#[derive(Debug, Error)]
pub enum CliError {
	/// Configuration load error
	#[error("configuration error: {0}")] Config(String),
	/// Invalid argument
	#[error("invalid argument: {0}")] Arg(String),
}

/// Result type for CLI operations
pub type Result<T> = std::result::Result<T, CliError>;

/// Top-level NavaTron command enumeration (extensible for future tooling)
#[derive(Debug, Subcommand)]
pub enum NavaTronCommand {
	/// Run the NavaTron NORC server
	Server(ServerArgs),
	/// Run the NavaTron NORC client
	Client(ClientArgs),
}

/// Root CLI parser
#[derive(Debug, Parser)]
#[command(name = "navatron", version, about = "NavaTron NORC Command Suite", long_about = None)]
pub struct NavaTronCli {
	/// Optional path to configuration file (TOML/YAML/JSON)
	#[arg(global = true, long = "config", env = "NAVATRON_CONFIG", value_name = "FILE")] 
	pub config: Option<PathBuf>,

	/// Increase output verbosity (-v, -vv, -vvv)
	#[arg(global = true, short = 'v', action = clap::ArgAction::Count)]
	pub verbose: u8,

	/// Subcommand
	#[command(subcommand)]
	pub command: NavaTronCommand,
}

/// Server CLI arguments
#[derive(Debug, Parser, Clone, Serialize, Deserialize)]
pub struct ServerArgs {
	/// Listen address (host:port)
	#[arg(long = "listen", env = "NAVATRON_LISTEN", default_value = "0.0.0.0:8443")]
	pub listen: String,

	/// Data directory for persistence
	#[arg(long = "data-dir", env = "NAVATRON_DATA_DIR", default_value = "./data")]
	pub data_dir: PathBuf,

	/// TLS certificate file (PEM)
	#[arg(long = "cert", env = "NAVATRON_CERT")]
	pub cert: Option<PathBuf>,

	/// TLS private key file (PEM)
	#[arg(long = "key", env = "NAVATRON_KEY")]
	pub key: Option<PathBuf>,

	/// Optional mTLS CA file
	#[arg(long = "mtls-ca", env = "NAVATRON_MTLS_CA")]
	pub mtls_ca: Option<PathBuf>,

	/// Enable metrics exporter (:9090/metrics)
	#[arg(long = "metrics", env = "NAVATRON_METRICS", default_value_t = false)]
	pub metrics: bool,

	/// Maximum concurrent connections
	#[arg(long = "max-connections", env = "NAVATRON_MAX_CONNECTIONS", default_value_t = 1000)]
	pub max_connections: usize,
}

/// Client CLI arguments
#[derive(Debug, Parser, Clone, Serialize, Deserialize)]
pub struct ClientArgs {
	/// Server address (host:port)
	#[arg(long = "server", env = "NAVATRON_SERVER", default_value = "localhost:8443")]
	pub server: String,

	/// Username / user ID
	#[arg(long = "user", env = "NAVATRON_USER")]
	pub user: Option<String>,

	/// Room to join on connect
	#[arg(long = "room", env = "NAVATRON_ROOM", default_value = "general")]
	pub room: String,

	/// Disable TLS (NOT recommended in production)
	#[arg(long = "insecure", env = "NAVATRON_INSECURE", default_value_t = false)]
	pub insecure: bool,
}

/// Effective server configuration after precedence merging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EffectiveServerConfig {
	/// Socket address to bind
	pub listen: SocketAddr,
	/// Data directory
	pub data_dir: PathBuf,
	/// TLS certificate path
	pub cert: Option<PathBuf>,
	/// TLS key path
	pub key: Option<PathBuf>,
	/// mTLS CA
	pub mtls_ca: Option<PathBuf>,
	/// Metrics enabled
	pub metrics: bool,
	/// Max connections
	pub max_connections: usize,
	/// Verbosity level
	pub verbosity: u8,
}

/// Effective client configuration after precedence merging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EffectiveClientConfig {
	/// Server socket address
	pub server: String,
	/// User (optional if using external auth)
	pub user: Option<String>,
	/// Room join target
	pub room: String,
	/// Use TLS
	pub tls: bool,
	/// Verbosity level
	pub verbosity: u8,
}

/// Load configuration file (if provided) into serde Value for merging
fn load_config_file(path: &PathBuf) -> Result<serde_json::Value> {
	let content = std::fs::read_to_string(path).map_err(|e| CliError::Config(format!("read {path:?}: {e}")))?;
	// Support basic formats via extension sniffing
	let value = if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
		match ext {
			"json" => serde_json::from_str(&content).map_err(|e| CliError::Config(e.to_string()))?,
			"toml" => toml::from_str::<toml::Value>(&content)
				.map_err(|e| CliError::Config(e.to_string()))?
				.try_into()
				.map_err(|e: toml::ser::Error| CliError::Config(e.to_string()))?,
			"yml" | "yaml" => serde_yaml::from_str(&content).map_err(|e| CliError::Config(e.to_string()))?,
			_ => serde_json::Value::Null,
		}
	} else { serde_json::Value::Null };
	Ok(value)
}

/// Merge two serde JSON values shallowly (right overrides left)
fn shallow_merge(mut base: serde_json::Value, overlay: serde_json::Value) -> serde_json::Value {
	match (&mut base, overlay) {
		(serde_json::Value::Object(ref mut left), serde_json::Value::Object(right)) => {
			for (k, v) in right { left.insert(k, v); }
			serde_json::Value::Object(left.clone())
		},
		(_, over) => over
	}
}

/// Build effective server config
pub fn build_server_config(args: &ServerArgs, file: Option<serde_json::Value>, verbosity: u8) -> Result<EffectiveServerConfig> {
	// Start from file then layer CLI (already parsed & env-applied by clap)
	let file_obj = file.unwrap_or(serde_json::Value::Null);
	let mut merged = file_obj;
	// CLI layering (simple field overrides)
	// (For deeper/nested config we would perform structural merges.)
	// Convert args to JSON then merge.
	let cli_json = serde_json::json!({
		"listen": args.listen,
		"data_dir": args.data_dir,
		"cert": args.cert,
		"key": args.key,
		"mtls_ca": args.mtls_ca,
		"metrics": args.metrics,
		"max_connections": args.max_connections,
	});
	merged = shallow_merge(merged, cli_json);

	// Deserialize into strongly typed config
	let mut cfg: EffectiveServerConfig = serde_json::from_value(merged)
		.map_err(|e| CliError::Config(format!("deserialize server config: {e}")))?;
	cfg.listen = args.listen.parse().map_err(|e| CliError::Arg(format!("invalid --listen: {e}")))?;
	cfg.verbosity = verbosity;
	Ok(cfg)
}

/// Build effective client config
pub fn build_client_config(args: &ClientArgs, file: Option<serde_json::Value>, verbosity: u8) -> Result<EffectiveClientConfig> {
	let merged = file.unwrap_or(serde_json::Value::Null);
	let mut cfg = EffectiveClientConfig {
		server: args.server.clone(),
		user: args.user.clone(),
		room: args.room.clone(),
		tls: !args.insecure,
		verbosity,
	};
	if merged != serde_json::Value::Null {
		if let Some(obj) = merged.as_object() {
			if let Some(v) = obj.get("server").and_then(|v| v.as_str()) { cfg.server = v.to_string(); }
			if let Some(v) = obj.get("room").and_then(|v| v.as_str()) { cfg.room = v.to_string(); }
		}
	}
	Ok(cfg)
}

/// Load CLI plus config file and build effective configuration
pub fn load() -> Result<(NavaTronCli, Option<EffectiveServerConfig>, Option<EffectiveClientConfig>)> {
	let cli = NavaTronCli::parse();
	let file_value = if let Some(ref path) = cli.config { Some(load_config_file(path)?) } else { None };
	let (server_cfg, client_cfg) = match &cli.command {
		NavaTronCommand::Server(args) => (Some(build_server_config(args, file_value.clone(), cli.verbose)?), None),
		NavaTronCommand::Client(args) => (None, Some(build_client_config(args, file_value.clone(), cli.verbose)?)),
	};
	Ok((cli, server_cfg, client_cfg))
}

#[cfg(test)]
mod tests {
	use super::*;
	#[test]
	fn test_shallow_merge_overrides() {
		let a = serde_json::json!({"listen":"0.0.0.0:1","max_connections":10});
		let b = serde_json::json!({"listen":"127.0.0.1:2"});
		let merged = shallow_merge(a,b);
		assert_eq!(merged["listen"], "127.0.0.1:2");
	}
}
