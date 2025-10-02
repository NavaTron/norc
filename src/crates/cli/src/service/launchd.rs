//! launchd service manager implementation for macOS

use super::{ServiceConfig, ServiceManager, ServiceStatus};
use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;
use std::process::Command;

const LAUNCHD_DAEMON_DIR: &str = "/Library/LaunchDaemons";

pub struct LaunchdManager {
    daemon_dir: PathBuf,
}

impl LaunchdManager {
    pub fn new() -> Result<Self> {
        Ok(Self {
            daemon_dir: PathBuf::from(LAUNCHD_DAEMON_DIR),
        })
    }

    fn plist_path(&self, service_name: &str) -> PathBuf {
        self.daemon_dir
            .join(format!("com.navatron.{}.plist", service_name))
    }

    fn run_launchctl(&self, args: &[&str]) -> Result<String> {
        let output = Command::new("launchctl")
            .args(args)
            .output()
            .context("Failed to execute launchctl")?;

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    fn generate_plist(&self, config: &ServiceConfig) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.navatron.{name}</string>
    
    <key>Disabled</key>
    <false/>
    
    <key>ProgramArguments</key>
    <array>
        <string>{executable}</string>
    </array>
    
    <key>WorkingDirectory</key>
    <string>{workdir}</string>
    
    <key>UserName</key>
    <string>{user}</string>
    <key>GroupName</key>
    <string>{group}</string>
    
    <key>EnvironmentVariables</key>
    <dict>
        <key>NORC_CONFIG</key>
        <string>{config}</string>
        <key>NORC_LOG_LEVEL</key>
        <string>info</string>
        <key>RUST_BACKTRACE</key>
        <string>1</string>
    </dict>
    
    <key>RunAtLoad</key>
    <true/>
    
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
        <key>Crashed</key>
        <true/>
    </dict>
    
    <key>ThrottleInterval</key>
    <integer>10</integer>
    
    <key>StandardOutPath</key>
    <string>/usr/local/var/log/norc/stdout.log</string>
    
    <key>StandardErrorPath</key>
    <string>/usr/local/var/log/norc/stderr.log</string>
    
    <key>ExitTimeOut</key>
    <integer>30</integer>
    
    <key>SoftResourceLimits</key>
    <dict>
        <key>NumberOfFiles</key>
        <integer>65536</integer>
        <key>NumberOfProcesses</key>
        <integer>4096</integer>
    </dict>
    
    <key>HardResourceLimits</key>
    <dict>
        <key>NumberOfFiles</key>
        <integer>65536</integer>
        <key>NumberOfProcesses</key>
        <integer>4096</integer>
    </dict>
</dict>
</plist>
"#,
            name = config.name,
            executable = config.executable_path.display(),
            workdir = config.working_directory.display(),
            user = config.user.as_deref().unwrap_or("_norc"),
            group = config.group.as_deref().unwrap_or("_norc"),
            config = config
                .config_path
                .as_ref()
                .unwrap_or(&PathBuf::from("/usr/local/etc/norc/config.toml"))
                .display(),
        )
    }

    fn label(&self, service_name: &str) -> String {
        format!("com.navatron.{}", service_name)
    }
}

impl ServiceManager for LaunchdManager {
    fn install(&self, config: &ServiceConfig) -> Result<()> {
        println!("Installing {} service with launchd...", config.name);

        // Generate plist content
        let plist_content = self.generate_plist(config);

        // Write plist file
        let plist_path = self.plist_path(&config.name);
        fs::write(&plist_path, plist_content)
            .with_context(|| format!("Failed to write plist file to {:?}", plist_path))?;

        // Set proper permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&plist_path)?.permissions();
            perms.set_mode(0o644);
            fs::set_permissions(&plist_path, perms)?;
        }

        println!("✓ Plist file created: {:?}", plist_path);

        // Load the service
        let label = self.label(&config.name);
        self.run_launchctl(&["load", plist_path.to_str().unwrap()])
            .context("Failed to load service")?;

        println!("✓ Service loaded");
        println!("\nService installed successfully!");
        println!("To start the service:");
        println!("  sudo launchctl start {}", label);

        Ok(())
    }

    fn uninstall(&self, service_name: &str) -> Result<()> {
        println!("Uninstalling {} service...", service_name);

        // Stop service if running
        let _ = self.stop(service_name);

        // Unload the service
        let plist_path = self.plist_path(service_name);
        if plist_path.exists() {
            let _ = self.run_launchctl(&["unload", plist_path.to_str().unwrap()]);

            // Remove plist file
            fs::remove_file(&plist_path)
                .with_context(|| format!("Failed to remove plist file {:?}", plist_path))?;
            println!("✓ Plist file removed: {:?}", plist_path);
        }

        println!("✓ Service uninstalled successfully");

        Ok(())
    }

    fn start(&self, service_name: &str) -> Result<()> {
        println!("Starting {} service...", service_name);
        let label = self.label(service_name);
        self.run_launchctl(&["start", &label])?;
        println!("✓ Service started");
        Ok(())
    }

    fn stop(&self, service_name: &str) -> Result<()> {
        println!("Stopping {} service...", service_name);
        let label = self.label(service_name);
        self.run_launchctl(&["stop", &label])?;
        println!("✓ Service stopped");
        Ok(())
    }

    fn restart(&self, service_name: &str) -> Result<()> {
        println!("Restarting {} service...", service_name);
        let label = self.label(service_name);
        self.run_launchctl(&["kickstart", "-k", &label])?;
        println!("✓ Service restarted");
        Ok(())
    }

    fn status(&self, service_name: &str) -> Result<ServiceStatus> {
        let label = self.label(service_name);
        let output = self.run_launchctl(&["list", &label])?;

        // Parse launchctl output to determine status
        if output.contains(&label) {
            // Check if it contains error indicators
            if output.contains("could not find") {
                Ok(ServiceStatus::Stopped)
            } else {
                Ok(ServiceStatus::Running)
            }
        } else {
            Ok(ServiceStatus::Unknown)
        }
    }

    fn enable(&self, service_name: &str) -> Result<()> {
        // On macOS, services are enabled by default when loaded
        println!("Service {} is enabled (loaded in launchd)", service_name);
        Ok(())
    }

    fn disable(&self, service_name: &str) -> Result<()> {
        // Disabling means unloading on macOS
        let plist_path = self.plist_path(service_name);
        if plist_path.exists() {
            self.run_launchctl(&["unload", plist_path.to_str().unwrap()])?;
            println!("✓ Service disabled (unloaded from launchd)");
        }
        Ok(())
    }
}
