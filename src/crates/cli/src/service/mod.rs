//! Service management for NORC across different platforms
//!
//! Provides platform-specific service installation, management, and lifecycle control.

#[cfg(target_os = "macos")]
pub mod launchd;
#[cfg(target_os = "linux")]
pub mod systemd;
#[cfg(target_os = "windows")]
pub mod windows;

use anyhow::Result;
use std::path::PathBuf;

/// Service configuration
#[derive(Debug, Clone)]
pub struct ServiceConfig {
    /// Service name
    pub name: String,

    /// Service display name
    pub display_name: String,

    /// Service description
    pub description: String,

    /// Path to the executable
    pub executable_path: PathBuf,

    /// Working directory
    pub working_directory: PathBuf,

    /// Configuration file path
    pub config_path: Option<PathBuf>,

    /// User to run as (Unix only)
    pub user: Option<String>,

    /// Group to run as (Unix only)
    pub group: Option<String>,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            name: "norc".to_string(),
            display_name: "NORC Server".to_string(),
            description: "NavaTron Open Real-time Communication Server".to_string(),
            executable_path: PathBuf::from("/usr/local/bin/norc-server"),
            working_directory: PathBuf::from("/var/lib/norc"),
            config_path: Some(PathBuf::from("/etc/norc/config.toml")),
            user: Some("norc".to_string()),
            group: Some("norc".to_string()),
        }
    }
}

/// Platform-specific service manager
pub trait ServiceManager {
    /// Install the service
    fn install(&self, config: &ServiceConfig) -> Result<()>;

    /// Uninstall the service
    fn uninstall(&self, service_name: &str) -> Result<()>;

    /// Start the service
    fn start(&self, service_name: &str) -> Result<()>;

    /// Stop the service
    fn stop(&self, service_name: &str) -> Result<()>;

    /// Restart the service
    fn restart(&self, service_name: &str) -> Result<()>;

    /// Get service status
    fn status(&self, service_name: &str) -> Result<ServiceStatus>;

    /// Enable service to start on boot
    fn enable(&self, service_name: &str) -> Result<()>;

    /// Disable service from starting on boot
    fn disable(&self, service_name: &str) -> Result<()>;
}

/// Service status
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceStatus {
    Running,
    Stopped,
    Failed,
    Unknown,
}

impl std::fmt::Display for ServiceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceStatus::Running => write!(f, "running"),
            ServiceStatus::Stopped => write!(f, "stopped"),
            ServiceStatus::Failed => write!(f, "failed"),
            ServiceStatus::Unknown => write!(f, "unknown"),
        }
    }
}

/// Get the appropriate service manager for the current platform
pub fn get_service_manager() -> Result<Box<dyn ServiceManager>> {
    cfg_if::cfg_if! {
        if #[cfg(target_os = "linux")] {
            Ok(Box::new(crate::service::systemd::SystemdManager::new()?))
        } else if #[cfg(target_os = "macos")] {
            Ok(Box::new(crate::service::launchd::LaunchdManager::new()?))
        } else if #[cfg(target_os = "windows")] {
            Ok(Box::new(crate::service::windows::WindowsServiceManager::new()?))
        } else {
            anyhow::bail!("Unsupported platform for service management")
        }
    }
}

/// Check if running with sufficient privileges for service management
pub fn check_privileges() -> Result<()> {
    cfg_if::cfg_if! {
        if #[cfg(unix)] {
            // Check if running as root by trying to access system directories
            let test_path = std::path::Path::new("/etc/systemd/system");
            if !test_path.exists() {
                // Not Linux with systemd, check macOS
                let test_path = std::path::Path::new("/Library/LaunchDaemons");
                if !test_path.exists() || !test_path.metadata()?.permissions().readonly() {
                    // Can't determine privileges, assume OK
                    return Ok(());
                }
            }

            // Simple heuristic: try to check if we can write to system directories
            // In practice, systemctl/launchctl will fail with proper error messages
            // if privileges are insufficient
            println!("Note: Service management typically requires root/sudo privileges");
        } else if #[cfg(windows)] {
            // Windows privilege check would go here
            // For now, just succeed
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_config_default() {
        let config = ServiceConfig::default();
        assert_eq!(config.name, "norc");
        assert_eq!(config.display_name, "NORC Server");
    }

    #[test]
    fn test_service_status_display() {
        assert_eq!(ServiceStatus::Running.to_string(), "running");
        assert_eq!(ServiceStatus::Stopped.to_string(), "stopped");
        assert_eq!(ServiceStatus::Failed.to_string(), "failed");
        assert_eq!(ServiceStatus::Unknown.to_string(), "unknown");
    }
}
