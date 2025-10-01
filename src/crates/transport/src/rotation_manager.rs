//! Certificate and key rotation management
//! Implements SERVER_REQUIREMENTS T-S-F-04.01.02.03 (Automatic key rotation)
//! Implements T-S-F-01.02.01.04 (Hot configuration reload)

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use thiserror::Error;
use tokio::fs;
use tokio::sync::{RwLock, watch};
use tokio::time::interval;
use tracing::{debug, error, info, warn};

use crate::tls_config::{load_certs, load_private_key, TlsConfigError};

/// Certificate rotation error
#[derive(Debug, Error)]
pub enum RotationError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("TLS configuration error: {0}")]
    TlsConfig(#[from] TlsConfigError),
    
    #[error("Invalid rotation schedule: {0}")]
    InvalidSchedule(String),
    
    #[error("Certificate validation error: {0}")]
    ValidationError(String),
}

/// Certificate and key material
#[derive(Debug)]
pub struct CertificateBundle {
    /// Certificate chain
    pub certs: Vec<CertificateDer<'static>>,
    /// Private key (wrapped in Arc as PrivateKeyDer doesn't implement Clone for security)
    pub key: Arc<PrivateKeyDer<'static>>,
    /// Certificate file path
    pub cert_path: PathBuf,
    /// Key file path
    pub key_path: PathBuf,
    /// When this bundle was loaded
    pub loaded_at: SystemTime,
}

impl CertificateBundle {
    /// Load a certificate bundle from disk
    pub async fn load(cert_path: impl AsRef<Path>, key_path: impl AsRef<Path>) -> Result<Self, RotationError> {
        let cert_path = cert_path.as_ref().to_path_buf();
        let key_path = key_path.as_ref().to_path_buf();
        
        // Load certificates and key
        let certs = load_certs(&cert_path)?;
        let key = Arc::new(load_private_key(&key_path)?);
        
        info!(
            "Loaded certificate bundle: cert={:?}, key={:?}, chain_len={}",
            cert_path,
            key_path,
            certs.len()
        );
        
        Ok(Self {
            certs,
            key,
            cert_path,
            key_path,
            loaded_at: SystemTime::now(),
        })
    }
    
    /// Reload the certificate bundle from disk
    pub async fn reload(&mut self) -> Result<(), RotationError> {
        let new_bundle = Self::load(&self.cert_path, &self.key_path).await?;
        
        self.certs = new_bundle.certs;
        self.key = new_bundle.key;
        self.loaded_at = new_bundle.loaded_at;
        
        info!("Reloaded certificate bundle from disk");
        Ok(())
    }
    
    /// Get the age of this certificate bundle
    pub fn age(&self) -> Duration {
        SystemTime::now()
            .duration_since(self.loaded_at)
            .unwrap_or(Duration::ZERO)
    }
}

/// Configuration for certificate rotation
#[derive(Debug, Clone)]
pub struct RotationConfig {
    /// Check for certificate changes at this interval
    pub check_interval: Duration,
    /// Automatically reload certificates when they change
    pub auto_reload: bool,
    /// Minimum time between reloads to prevent thrashing
    pub reload_cooldown: Duration,
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self {
            check_interval: Duration::from_secs(300), // Check every 5 minutes
            auto_reload: true,
            reload_cooldown: Duration::from_secs(10), // Wait 10s between reloads
        }
    }
}

/// Certificate rotation manager
/// 
/// Monitors certificate files for changes and automatically reloads them.
/// Notifies listeners when certificates are rotated.
pub struct CertificateRotationManager {
    /// Current certificate bundle (shared)
    bundle: Arc<RwLock<Arc<CertificateBundle>>>,
    /// Rotation configuration
    config: RotationConfig,
    /// Channel for notifying about certificate changes
    tx: watch::Sender<Arc<CertificateBundle>>,
    /// Last reload time
    last_reload: Arc<RwLock<SystemTime>>,
}

impl CertificateRotationManager {
    /// Create a new certificate rotation manager
    pub async fn new(
        cert_path: impl AsRef<Path>,
        key_path: impl AsRef<Path>,
        config: RotationConfig,
    ) -> Result<Self, RotationError> {
        let bundle = CertificateBundle::load(cert_path, key_path).await?;
        let bundle_arc = Arc::new(bundle);
        
        let (tx, _) = watch::channel(bundle_arc.clone());
        let bundle = Arc::new(RwLock::new(bundle_arc));
        
        Ok(Self {
            bundle,
            config,
            tx,
            last_reload: Arc::new(RwLock::new(SystemTime::now())),
        })
    }
    
    /// Get a receiver for certificate change notifications
    pub fn subscribe(&self) -> watch::Receiver<Arc<CertificateBundle>> {
        self.tx.subscribe()
    }
    
    /// Get the current certificate bundle
    pub async fn current_bundle(&self) -> Arc<CertificateBundle> {
        let bundle = self.bundle.read().await;
        bundle.clone()
    }
    
    /// Manually trigger a certificate reload
    pub async fn reload(&self) -> Result<(), RotationError> {
        // Check cooldown period
        let last_reload = *self.last_reload.read().await;
        let since_last_reload = SystemTime::now()
            .duration_since(last_reload)
            .unwrap_or(Duration::MAX);
        
        if since_last_reload < self.config.reload_cooldown {
            warn!(
                "Reload requested but cooldown period not elapsed ({}s remaining)",
                (self.config.reload_cooldown - since_last_reload).as_secs()
            );
            return Ok(());
        }
        
        info!("Manually reloading certificates");
        
        // Load new bundle from disk
        let current_bundle = self.bundle.read().await;
        let new_bundle = CertificateBundle::load(&current_bundle.cert_path, &current_bundle.key_path).await?;
        let new_bundle_arc = Arc::new(new_bundle);
        drop(current_bundle);
        
        // Update the shared bundle
        *self.bundle.write().await = new_bundle_arc.clone();
        
        // Update last reload time
        *self.last_reload.write().await = SystemTime::now();
        
        // Notify subscribers
        self.tx.send(new_bundle_arc).ok();
        
        info!("Certificate reload completed successfully");
        Ok(())
    }
    
    /// Start the automatic rotation background task
    /// 
    /// This task monitors certificate files for changes and automatically reloads them.
    pub async fn start_rotation_task(self: Arc<Self>) {
        if !self.config.auto_reload {
            info!("Automatic certificate rotation is disabled");
            return;
        }
        
        info!(
            "Starting certificate rotation task (check interval: {}s)",
            self.config.check_interval.as_secs()
        );
        
        let mut check_timer = interval(self.config.check_interval);
        
        loop {
            check_timer.tick().await;
            
            if let Err(e) = self.check_and_reload().await {
                error!("Certificate rotation check failed: {}", e);
            }
        }
    }
    
    /// Check if certificates have changed and reload if necessary
    async fn check_and_reload(&self) -> Result<(), RotationError> {
        let bundle = self.bundle.read().await;
        let cert_path = &bundle.cert_path;
        let key_path = &bundle.key_path;
        
        // Check if files have been modified since we last loaded them
        let cert_modified = self.get_file_modified_time(cert_path).await?;
        let key_modified = self.get_file_modified_time(key_path).await?;
        
        let bundle_age = bundle.age();
        drop(bundle); // Release read lock
        
        // Check if either file is newer than our current bundle
        let cert_changed = cert_modified
            .duration_since(SystemTime::now() - bundle_age)
            .is_ok();
        let key_changed = key_modified
            .duration_since(SystemTime::now() - bundle_age)
            .is_ok();
        
        if cert_changed || key_changed {
            info!(
                "Certificate files have changed (cert={}, key={}), reloading",
                cert_changed, key_changed
            );
            self.reload().await?;
        } else {
            debug!("Certificate files unchanged");
        }
        
        Ok(())
    }
    
    /// Get the last modified time of a file
    async fn get_file_modified_time(&self, path: &Path) -> Result<SystemTime, RotationError> {
        let metadata = fs::metadata(path).await?;
        let modified = metadata
            .modified()
            .map_err(|e| RotationError::Io(e))?;
        Ok(modified)
    }
}

/// Builder for certificate rotation manager
pub struct RotationManagerBuilder {
    cert_path: Option<PathBuf>,
    key_path: Option<PathBuf>,
    config: RotationConfig,
}

impl RotationManagerBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            cert_path: None,
            key_path: None,
            config: RotationConfig::default(),
        }
    }
    
    /// Set the certificate path
    pub fn cert_path(mut self, path: impl AsRef<Path>) -> Self {
        self.cert_path = Some(path.as_ref().to_path_buf());
        self
    }
    
    /// Set the private key path
    pub fn key_path(mut self, path: impl AsRef<Path>) -> Self {
        self.key_path = Some(path.as_ref().to_path_buf());
        self
    }
    
    /// Set the rotation configuration
    pub fn config(mut self, config: RotationConfig) -> Self {
        self.config = config;
        self
    }
    
    /// Set the check interval
    pub fn check_interval(mut self, interval: Duration) -> Self {
        self.config.check_interval = interval;
        self
    }
    
    /// Enable or disable auto-reload
    pub fn auto_reload(mut self, enabled: bool) -> Self {
        self.config.auto_reload = enabled;
        self
    }
    
    /// Set the reload cooldown period
    pub fn reload_cooldown(mut self, cooldown: Duration) -> Self {
        self.config.reload_cooldown = cooldown;
        self
    }
    
    /// Build the rotation manager
    pub async fn build(self) -> Result<Arc<CertificateRotationManager>, RotationError> {
        let cert_path = self.cert_path.ok_or_else(|| {
            RotationError::InvalidSchedule("Certificate path not set".to_string())
        })?;
        
        let key_path = self.key_path.ok_or_else(|| {
            RotationError::InvalidSchedule("Key path not set".to_string())
        })?;
        
        let manager = CertificateRotationManager::new(cert_path, key_path, self.config).await?;
        Ok(Arc::new(manager))
    }
}

impl Default for RotationManagerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rotation_config_default() {
        let config = RotationConfig::default();
        assert_eq!(config.check_interval, Duration::from_secs(300));
        assert!(config.auto_reload);
        assert_eq!(config.reload_cooldown, Duration::from_secs(10));
    }

    #[tokio::test]
    async fn test_builder() {
        let builder = RotationManagerBuilder::new()
            .cert_path("/tmp/cert.pem")
            .key_path("/tmp/key.pem")
            .check_interval(Duration::from_secs(60))
            .auto_reload(false);
        
        // Builder should be constructed without errors
        assert!(builder.cert_path.is_some());
        assert!(builder.key_path.is_some());
    }
}
