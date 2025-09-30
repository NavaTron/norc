//! Privilege Separation Helpers
//!
//! Provides utilities for dropping privileges after binding to privileged ports
//! per E-04 security requirements.

use crate::ServerError;

/// Drop privileges to a non-root user (Unix only)
#[cfg(unix)]
pub fn drop_privileges(user: &str, group: &str) -> Result<(), ServerError> {
    use nix::unistd::{setgid, setuid, Gid, Group, Uid, User};
    
    // Get user and group IDs
    let user_info = User::from_name(user)
        .map_err(|e| ServerError::Security(format!("Failed to get user info: {}", e)))?
        .ok_or_else(|| ServerError::Security(format!("User not found: {}", user)))?;
    
    let group_info = Group::from_name(group)
        .map_err(|e| ServerError::Security(format!("Failed to get group info: {}", e)))?
        .ok_or_else(|| ServerError::Security(format!("Group not found: {}", group)))?;
    
    let uid = Uid::from_raw(user_info.uid.as_raw());
    let gid = Gid::from_raw(group_info.gid.as_raw());
    
    // Drop group privileges first
    setgid(gid).map_err(|e| ServerError::Security(format!("Failed to set GID: {}", e)))?;
    
    // Drop user privileges
    setuid(uid).map_err(|e| ServerError::Security(format!("Failed to set UID: {}", e)))?;
    
    tracing::info!("Dropped privileges to user: {}, group: {}", user, group);
    
    Ok(())
}

/// Windows version (no-op, Windows uses different security model)
#[cfg(windows)]
pub fn drop_privileges(_user: &str, _group: &str) -> Result<(), ServerError> {
    tracing::warn!("Privilege dropping not implemented on Windows");
    Ok(())
}

/// Check if running as root/administrator
#[cfg(unix)]
pub fn is_privileged() -> bool {
    use nix::unistd::Uid;
    Uid::effective().is_root()
}

/// Check if running as administrator (Windows)
#[cfg(windows)]
pub fn is_privileged() -> bool {
    // Simplified check - real implementation would use Windows APIs
    false
}

/// Get current effective user ID (Unix)
#[cfg(unix)]
pub fn get_effective_uid() -> u32 {
    use nix::unistd::Uid;
    Uid::effective().as_raw()
}

/// Get current effective user ID (Windows - returns 0)
#[cfg(windows)]
pub fn get_effective_uid() -> u32 {
    0
}

/// Set resource limits (Unix)
#[cfg(unix)]
pub fn set_resource_limits(
    max_open_files: u64,
    max_memory_mb: u64,
) -> Result<(), ServerError> {
    use nix::sys::resource::{setrlimit, Resource};
    
    // Set maximum number of open files
    setrlimit(Resource::RLIMIT_NOFILE, max_open_files, max_open_files)
        .map_err(|e| ServerError::Security(format!("Failed to set file limit: {}", e)))?;
    
    // Set maximum memory (address space)
    let max_memory_bytes = max_memory_mb * 1024 * 1024;
    setrlimit(Resource::RLIMIT_AS, max_memory_bytes, max_memory_bytes)
        .map_err(|e| ServerError::Security(format!("Failed to set memory limit: {}", e)))?;
    
    tracing::info!(
        "Set resource limits: {} max files, {} MB max memory",
        max_open_files,
        max_memory_mb
    );
    
    Ok(())
}

/// Set resource limits (Windows - no-op)
#[cfg(windows)]
pub fn set_resource_limits(
    _max_open_files: u64,
    _max_memory_mb: u64,
) -> Result<(), ServerError> {
    tracing::warn!("Resource limits not implemented on Windows");
    Ok(())
}

/// Enable secure memory options (prevent swapping sensitive data)
#[cfg(unix)]
pub fn enable_secure_memory() -> Result<(), ServerError> {
    use nix::sys::mman::{mlockall, MlockAllFlags};
    
    // Lock all current and future pages in memory
    mlockall(MlockAllFlags::MCL_CURRENT | MlockAllFlags::MCL_FUTURE)
        .map_err(|e| ServerError::Security(format!("Failed to lock memory: {}", e)))?;
    
    tracing::info!("Enabled secure memory (mlockall)");
    
    Ok(())
}

/// Enable secure memory (Windows - no-op)
#[cfg(windows)]
pub fn enable_secure_memory() -> Result<(), ServerError> {
    tracing::warn!("Secure memory not implemented on Windows");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_effective_uid() {
        let _uid = get_effective_uid();
        // UID is retrieved successfully if this doesn't panic
    }
    
    #[test]
    fn test_is_privileged() {
        // Just check it doesn't panic
        let _is_root = is_privileged();
    }
    
    // Note: Actual privilege dropping tests require running as root
    // and are not suitable for unit tests
}
