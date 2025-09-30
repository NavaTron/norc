//! Signal handling for graceful shutdown
//!
//! Provides cross-platform signal handling for daemon processes.

use crate::ServerError;
use tokio::sync::broadcast;
use tracing::{info, warn};

/// Signal types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Signal {
    Terminate,
    Interrupt,
    Reload,
    Quit,
}

/// Signal handler manager
pub struct SignalHandler {
    shutdown_tx: broadcast::Sender<Signal>,
    _shutdown_rx: broadcast::Receiver<Signal>,
}

impl SignalHandler {
    /// Create a new signal handler
    pub fn new() -> Self {
        let (shutdown_tx, shutdown_rx) = broadcast::channel(16);
        
        Self {
            shutdown_tx,
            _shutdown_rx: shutdown_rx,
        }
    }

    /// Get a receiver for shutdown signals
    pub fn subscribe(&self) -> broadcast::Receiver<Signal> {
        self.shutdown_tx.subscribe()
    }

    /// Install signal handlers and start monitoring
    pub async fn install(&self) -> Result<(), ServerError> {
        let tx = self.shutdown_tx.clone();
        
        // Handle Ctrl+C (SIGINT)
        let tx_clone = tx.clone();
        ctrlc::set_handler(move || {
            info!("Received interrupt signal (Ctrl+C)");
            let _ = tx_clone.send(Signal::Interrupt);
        })
        .map_err(|e| ServerError::Signal(format!("Failed to set Ctrl+C handler: {}", e)))?;

        // Handle other signals on Unix systems
        #[cfg(unix)]
        {
            self.install_unix_signals(tx).await?;
        }

        info!("Signal handlers installed");
        Ok(())
    }

    /// Install Unix-specific signal handlers
    #[cfg(unix)]
    async fn install_unix_signals(&self, _tx: broadcast::Sender<Signal>) -> Result<(), ServerError> {
        use nix::sys::signal::{self, SigHandler, Signal as NixSignal};
        
        // SIGTERM handler
        extern "C" fn handle_sigterm(_: i32) {
            // Note: This is called from a signal handler context
            // We should only do async-signal-safe operations here
        }
        
        unsafe {
            signal::signal(NixSignal::SIGTERM, SigHandler::Handler(handle_sigterm))
                .map_err(|e| ServerError::Signal(format!("Failed to set SIGTERM handler: {}", e)))?;
        }

        // SIGQUIT handler
        extern "C" fn handle_sigquit(_: i32) {
            // Note: Same limitations as above
        }
        
        unsafe {
            signal::signal(NixSignal::SIGQUIT, SigHandler::Handler(handle_sigquit))
                .map_err(|e| ServerError::Signal(format!("Failed to set SIGQUIT handler: {}", e)))?;
        }

        // SIGHUP handler (reload configuration)
        extern "C" fn handle_sighup(_: i32) {
            // Note: Same limitations as above
        }
        
        unsafe {
            signal::signal(NixSignal::SIGHUP, SigHandler::Handler(handle_sighup))
                .map_err(|e| ServerError::Signal(format!("Failed to set SIGHUP handler: {}", e)))?;
        }

        info!("Unix signal handlers installed");
        Ok(())
    }

    /// Send a signal manually (for testing)
    pub fn send_signal(&self, signal: Signal) -> Result<(), ServerError> {
        self.shutdown_tx
            .send(signal)
            .map_err(|e| ServerError::Signal(format!("Failed to send signal: {}", e)))?;
        Ok(())
    }
}

impl Default for SignalHandler {
    fn default() -> Self {
        Self::new()
    }
}

/// Wait for shutdown signals
pub async fn wait_for_shutdown() -> Signal {
    let handler = SignalHandler::new();
    
    if let Err(e) = handler.install().await {
        warn!("Failed to install signal handlers: {}", e);
        // Fallback to basic Ctrl+C handling
        tokio::signal::ctrl_c().await.expect("Failed to listen for ctrl_c");
        return Signal::Interrupt;
    }

    let mut rx = handler.subscribe();
    
    match rx.recv().await {
        Ok(signal) => {
            info!("Received shutdown signal: {:?}", signal);
            signal
        }
        Err(e) => {
            warn!("Error receiving shutdown signal: {}", e);
            Signal::Terminate
        }
    }
}