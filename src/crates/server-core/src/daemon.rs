//! Daemon process management
//!
//! Handles daemon lifecycle, process monitoring, and auto-restart functionality.

use crate::ServerError;
use norc_config::ServerConfig;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

/// Daemon process manager
pub struct DaemonManager {
    config: Arc<ServerConfig>,
    state: Arc<RwLock<DaemonState>>,
    restart_count: Arc<RwLock<u32>>,
    last_restart: Arc<RwLock<Option<Instant>>>,
}

/// Daemon state
#[derive(Debug, Clone, PartialEq)]
pub enum DaemonState {
    Stopped,
    Starting,
    Running,
    Stopping,
    Crashed,
    RestartCooldown,
}

impl DaemonManager {
    /// Create a new daemon manager
    pub async fn new(config: Arc<ServerConfig>) -> Result<Self, ServerError> {
        let manager = Self {
            config,
            state: Arc::new(RwLock::new(DaemonState::Stopped)),
            restart_count: Arc::new(RwLock::new(0)),
            last_restart: Arc::new(RwLock::new(None)),
        };

        // Write PID file
        if let Err(e) = manager.write_pid_file().await {
            warn!("Failed to write PID file: {}", e);
        }

        Ok(manager)
    }

    /// Get current daemon state
    pub async fn state(&self) -> DaemonState {
        self.state.read().await.clone()
    }

    /// Start daemon monitoring
    pub async fn start_monitoring(&self) -> Result<(), ServerError> {
        if !self.config.daemon.auto_restart {
            return Ok(());
        }

        let state = self.state.clone();
        let restart_count = self.restart_count.clone();
        let last_restart = self.last_restart.clone();
        let config = self.config.clone();

        tokio::spawn(async move {
            loop {
                let current_state = { state.read().await.clone() };

                match current_state {
                    DaemonState::Crashed => {
                        let can_restart = {
                            let count = *restart_count.read().await;
                            let last = *last_restart.read().await;

                            // Check if we've exceeded max restarts
                            if count >= config.daemon.max_restarts {
                                error!(
                                    "Maximum restart attempts ({}) exceeded",
                                    config.daemon.max_restarts
                                );
                                false
                            } else if let Some(last_time) = last {
                                // Check cooldown period
                                let elapsed = last_time.elapsed();
                                let cooldown =
                                    Duration::from_secs(config.daemon.restart_cooldown_secs);

                                if elapsed < cooldown {
                                    let remaining = cooldown - elapsed;
                                    info!(
                                        "Restart cooldown active, waiting {}s",
                                        remaining.as_secs()
                                    );
                                    {
                                        let mut s = state.write().await;
                                        *s = DaemonState::RestartCooldown;
                                    }
                                    tokio::time::sleep(remaining).await;
                                }
                                true
                            } else {
                                true
                            }
                        };

                        if can_restart {
                            info!("Attempting to restart daemon...");

                            {
                                let mut count = restart_count.write().await;
                                *count += 1;
                            }

                            {
                                let mut last = last_restart.write().await;
                                *last = Some(Instant::now());
                            }

                            {
                                let mut s = state.write().await;
                                *s = DaemonState::Starting;
                            }

                            // Simulate restart success for now
                            // TODO: Implement actual process restart logic
                            tokio::time::sleep(Duration::from_secs(2)).await;

                            {
                                let mut s = state.write().await;
                                *s = DaemonState::Running;
                            }

                            info!("Daemon restart successful");
                        } else {
                            break;
                        }
                    }
                    DaemonState::Stopping => {
                        break;
                    }
                    _ => {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
            }
        });

        Ok(())
    }

    /// Stop the daemon manager
    pub async fn stop(&mut self) -> Result<(), ServerError> {
        {
            let mut state = self.state.write().await;
            *state = DaemonState::Stopping;
        }

        // Clean up PID file
        if let Err(e) = self.remove_pid_file().await {
            warn!("Failed to remove PID file: {}", e);
        }

        {
            let mut state = self.state.write().await;
            *state = DaemonState::Stopped;
        }

        Ok(())
    }

    /// Simulate a crash (for testing)
    pub async fn simulate_crash(&self) {
        {
            let mut state = self.state.write().await;
            *state = DaemonState::Crashed;
        }
        warn!("Daemon process crashed");
    }

    /// Write PID file
    async fn write_pid_file(&self) -> Result<(), std::io::Error> {
        let pid = std::process::id();
        let pid_content = pid.to_string();

        if let Some(parent) = self.config.daemon.pid_file.parent() {
            std::fs::create_dir_all(parent)?;
        }

        std::fs::write(&self.config.daemon.pid_file, pid_content)?;
        info!("PID file written: {:?}", self.config.daemon.pid_file);
        Ok(())
    }

    /// Remove PID file
    async fn remove_pid_file(&self) -> Result<(), std::io::Error> {
        if self.config.daemon.pid_file.exists() {
            std::fs::remove_file(&self.config.daemon.pid_file)?;
            info!("PID file removed: {:?}", self.config.daemon.pid_file);
        }
        Ok(())
    }

    /// Check if another instance is running
    pub async fn check_running_instance(&self) -> Result<bool, ServerError> {
        if !self.config.daemon.pid_file.exists() {
            return Ok(false);
        }

        let pid_content = std::fs::read_to_string(&self.config.daemon.pid_file)
            .map_err(|e| ServerError::Io(e))?;

        let pid: u32 = pid_content
            .trim()
            .parse()
            .map_err(|_| ServerError::Daemon("Invalid PID in PID file".to_string()))?;

        // Check if process is still running
        let is_running = is_process_running(pid);

        if !is_running {
            // Stale PID file, remove it
            let _ = std::fs::remove_file(&self.config.daemon.pid_file);
        }

        Ok(is_running)
    }
}

/// Check if a process with the given PID is running
#[cfg(unix)]
fn is_process_running(pid: u32) -> bool {
    use nix::sys::signal::{Signal, kill};
    use nix::unistd::Pid;

    match kill(Pid::from_raw(pid as i32), Signal::SIGCONT) {
        Ok(_) => true,
        Err(nix::errno::Errno::ESRCH) => false, // No such process
        Err(_) => true, // Process exists but we can't signal it (probably permission denied)
    }
}

#[cfg(windows)]
fn is_process_running(pid: u32) -> bool {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION};

    unsafe {
        let handle: HANDLE = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid);
        if handle.is_invalid() {
            false
        } else {
            let _ = CloseHandle(handle);
            true
        }
    }
}

/// Daemonize the current process (Unix only)
#[cfg(unix)]
pub async fn daemonize(config: &ServerConfig) -> Result<(), ServerError> {
    use nix::unistd::{ForkResult, fork, setsid};
    use std::os::unix::io::AsRawFd;

    // First fork
    match unsafe { fork() } {
        Ok(ForkResult::Parent { .. }) => {
            // Parent process exits
            std::process::exit(0);
        }
        Ok(ForkResult::Child) => {
            // Child continues
        }
        Err(e) => {
            return Err(ServerError::Daemon(format!("First fork failed: {}", e)));
        }
    }

    // Create new session
    setsid().map_err(|e| ServerError::Daemon(format!("setsid failed: {}", e)))?;

    // Second fork to ensure we're not a session leader
    match unsafe { fork() } {
        Ok(ForkResult::Parent { .. }) => {
            // Parent process exits
            std::process::exit(0);
        }
        Ok(ForkResult::Child) => {
            // Child continues
        }
        Err(e) => {
            return Err(ServerError::Daemon(format!("Second fork failed: {}", e)));
        }
    }

    // Change working directory
    if let Some(working_dir) = &config.daemon.working_dir {
        std::env::set_current_dir(working_dir).map_err(|e| {
            ServerError::Daemon(format!("Failed to change working directory: {}", e))
        })?;
    }

    // Redirect stdin, stdout, stderr to /dev/null
    let dev_null = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")
        .map_err(|e| ServerError::Daemon(format!("Failed to open /dev/null: {}", e)))?;

    let fd = dev_null.as_raw_fd();

    unsafe {
        libc::dup2(fd, libc::STDIN_FILENO);
        libc::dup2(fd, libc::STDOUT_FILENO);
        libc::dup2(fd, libc::STDERR_FILENO);
    }

    info!("Process daemonized successfully");
    Ok(())
}

/// Windows service simulation (placeholder)
#[cfg(windows)]
pub async fn daemonize(_config: &ServerConfig) -> Result<(), ServerError> {
    // On Windows, this would typically involve creating a Windows service
    // For now, we'll just run in the background
    info!("Running as background process (Windows service mode not fully implemented)");
    Ok(())
}
