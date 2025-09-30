//! Windows Service Manager implementation
//!
//! Note: Full Windows service implementation requires significant work
//! with the Windows Service API. This is a placeholder for future implementation.

use super::{ServiceConfig, ServiceManager, ServiceStatus};
use anyhow::Result;

pub struct WindowsServiceManager;

impl WindowsServiceManager {
    pub fn new() -> Result<Self> {
        Ok(Self)
    }
}

impl ServiceManager for WindowsServiceManager {
    fn install(&self, _config: &ServiceConfig) -> Result<()> {
        anyhow::bail!("Windows service installation not yet implemented")
    }
    
    fn uninstall(&self, _service_name: &str) -> Result<()> {
        anyhow::bail!("Windows service uninstallation not yet implemented")
    }
    
    fn start(&self, _service_name: &str) -> Result<()> {
        anyhow::bail!("Windows service start not yet implemented")
    }
    
    fn stop(&self, _service_name: &str) -> Result<()> {
        anyhow::bail!("Windows service stop not yet implemented")
    }
    
    fn restart(&self, _service_name: &str) -> Result<()> {
        anyhow::bail!("Windows service restart not yet implemented")
    }
    
    fn status(&self, _service_name: &str) -> Result<ServiceStatus> {
        anyhow::bail!("Windows service status not yet implemented")
    }
    
    fn enable(&self, _service_name: &str) -> Result<()> {
        anyhow::bail!("Windows service enable not yet implemented")
    }
    
    fn disable(&self, _service_name: &str) -> Result<()> {
        anyhow::bail!("Windows service disable not yet implemented")
    }
}
