//! systemd service manager implementation for Linux

use super::{ServiceConfig, ServiceManager, ServiceStatus};
use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const SYSTEMD_SYSTEM_DIR: &str = "/etc/systemd/system";
const SERVICE_TEMPLATE: &str = include_str!("../../../packaging/systemd/norc.service");

pub struct SystemdManager {
    system_dir: PathBuf,
}

impl SystemdManager {
    pub fn new() -> Result<Self> {
        Ok(Self {
            system_dir: PathBuf::from(SYSTEMD_SYSTEM_DIR),
        })
    }

    fn service_file_path(&self, service_name: &str) -> PathBuf {
        self.system_dir.join(format!("{}.service", service_name))
    }

    fn run_systemctl(&self, args: &[&str]) -> Result<String> {
        let output = Command::new("systemctl")
            .args(args)
            .output()
            .context("Failed to execute systemctl")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("systemctl failed: {}", stderr);
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    fn generate_service_file(&self, config: &ServiceConfig) -> String {
        // For now, use a simple template replacement
        // In production, you might want to use a proper templating engine
        let mut content = String::from(
            r#"[Unit]
Description={{DESCRIPTION}}
Documentation=https://github.com/NavaTron/norc
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
User={{USER}}
Group={{GROUP}}
ExecStart={{EXECUTABLE}}
WorkingDirectory={{WORKDIR}}
Restart=always
RestartSec=10
Environment="NORC_CONFIG={{CONFIG}}"
Environment="NORC_LOG_LEVEL=info"
Environment="RUST_BACKTRACE=1"
KillMode=mixed
KillSignal=SIGTERM
TimeoutStopSec=30
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths={{WORKDIR}} /var/log/norc
LimitNOFILE=65536
LimitNPROC=4096
StandardOutput=journal
StandardError=journal
SyslogIdentifier={{NAME}}

[Install]
WantedBy=multi-user.target
"#,
        );

        content = content.replace("{{DESCRIPTION}}", &config.description);
        content = content.replace("{{USER}}", config.user.as_deref().unwrap_or("norc"));
        content = content.replace("{{GROUP}}", config.group.as_deref().unwrap_or("norc"));
        content = content.replace(
            "{{EXECUTABLE}}",
            &config.executable_path.display().to_string(),
        );
        content = content.replace(
            "{{WORKDIR}}",
            &config.working_directory.display().to_string(),
        );
        content = content.replace(
            "{{CONFIG}}",
            &config
                .config_path
                .as_ref()
                .unwrap_or(&PathBuf::from("/etc/norc/config.toml"))
                .display()
                .to_string(),
        );
        content = content.replace("{{NAME}}", &config.name);

        content
    }
}

impl ServiceManager for SystemdManager {
    fn install(&self, config: &ServiceConfig) -> Result<()> {
        println!("Installing {} service with systemd...", config.name);

        // Generate service file content
        let service_content = self.generate_service_file(config);

        // Write service file
        let service_path = self.service_file_path(&config.name);
        fs::write(&service_path, service_content)
            .with_context(|| format!("Failed to write service file to {:?}", service_path))?;

        println!("✓ Service file created: {:?}", service_path);

        // Reload systemd daemon
        self.run_systemctl(&["daemon-reload"])
            .context("Failed to reload systemd daemon")?;

        println!("✓ systemd daemon reloaded");
        println!("\nService installed successfully!");
        println!("To enable and start the service:");
        println!("  sudo systemctl enable {}", config.name);
        println!("  sudo systemctl start {}", config.name);

        Ok(())
    }

    fn uninstall(&self, service_name: &str) -> Result<()> {
        println!("Uninstalling {} service...", service_name);

        // Stop service if running
        let _ = self.stop(service_name);

        // Disable service
        let _ = self.disable(service_name);

        // Remove service file
        let service_path = self.service_file_path(service_name);
        if service_path.exists() {
            fs::remove_file(&service_path)
                .with_context(|| format!("Failed to remove service file {:?}", service_path))?;
            println!("✓ Service file removed: {:?}", service_path);
        }

        // Reload systemd daemon
        self.run_systemctl(&["daemon-reload"])
            .context("Failed to reload systemd daemon")?;

        println!("✓ Service uninstalled successfully");

        Ok(())
    }

    fn start(&self, service_name: &str) -> Result<()> {
        println!("Starting {} service...", service_name);
        self.run_systemctl(&["start", service_name])?;
        println!("✓ Service started");
        Ok(())
    }

    fn stop(&self, service_name: &str) -> Result<()> {
        println!("Stopping {} service...", service_name);
        self.run_systemctl(&["stop", service_name])?;
        println!("✓ Service stopped");
        Ok(())
    }

    fn restart(&self, service_name: &str) -> Result<()> {
        println!("Restarting {} service...", service_name);
        self.run_systemctl(&["restart", service_name])?;
        println!("✓ Service restarted");
        Ok(())
    }

    fn status(&self, service_name: &str) -> Result<ServiceStatus> {
        let output = self.run_systemctl(&["is-active", service_name])?;

        let status = match output.trim() {
            "active" => ServiceStatus::Running,
            "inactive" => ServiceStatus::Stopped,
            "failed" => ServiceStatus::Failed,
            _ => ServiceStatus::Unknown,
        };

        Ok(status)
    }

    fn enable(&self, service_name: &str) -> Result<()> {
        println!("Enabling {} service...", service_name);
        self.run_systemctl(&["enable", service_name])?;
        println!("✓ Service enabled (will start on boot)");
        Ok(())
    }

    fn disable(&self, service_name: &str) -> Result<()> {
        println!("Disabling {} service...", service_name);
        self.run_systemctl(&["disable", service_name])?;
        println!("✓ Service disabled");
        Ok(())
    }
}
