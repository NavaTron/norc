//! Role-Based Access Control (RBAC) implementation
//!
//! Implements T-S-F-08.02.01.04: RBAC for fine-grained access control

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Administrative roles
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Role {
    /// Super administrator - full access to all operations
    SuperAdmin,
    
    /// Organization administrator - manage users and devices within organization
    OrgAdmin,
    
    /// Auditor - read-only access to audit logs and compliance reports
    Auditor,
    
    /// Operator - server operations and monitoring (no user management)
    Operator,
    
    /// Federation manager - manage federation partnerships
    FederationManager,
}

/// Fine-grained permissions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Permission {
    // User management
    UserCreate,
    UserRead,
    UserUpdate,
    UserDelete,
    UserBulkOps,
    
    // Device management
    DeviceRegister,
    DeviceRead,
    DeviceRevoke,
    DeviceBulkOps,
    
    // Configuration management
    ConfigRead,
    ConfigUpdate,
    ConfigRollback,
    ConfigValidate,
    
    // Server operations
    ServerStart,
    ServerStop,
    ServerReload,
    ServerStatus,
    
    // Monitoring
    MetricsRead,
    HealthCheck,
    LogsRead,
    
    // Federation
    FederationCreate,
    FederationRead,
    FederationUpdate,
    FederationDelete,
    
    // Audit
    AuditRead,
    AuditExport,
    ComplianceReport,
    
    // API key management
    ApiKeyCreate,
    ApiKeyRead,
    ApiKeyRevoke,
    
    // Connection management
    ConnectionsRead,
    ConnectionsManage,
    
    // Session management
    SessionsRead,
    SessionsManage,
}

impl Role {
    /// Get all permissions for this role
    pub fn permissions(&self) -> HashSet<Permission> {
        use Permission::*;
        
        match self {
            Role::SuperAdmin => {
                // SuperAdmin has all permissions
                vec![
                    UserCreate, UserRead, UserUpdate, UserDelete, UserBulkOps,
                    DeviceRegister, DeviceRead, DeviceRevoke, DeviceBulkOps,
                    ConfigRead, ConfigUpdate, ConfigRollback, ConfigValidate,
                    ServerStart, ServerStop, ServerReload, ServerStatus,
                    MetricsRead, HealthCheck, LogsRead,
                    FederationCreate, FederationRead, FederationUpdate, FederationDelete,
                    AuditRead, AuditExport, ComplianceReport,
                    ApiKeyCreate, ApiKeyRead, ApiKeyRevoke,
                    ConnectionsRead, ConnectionsManage,
                    SessionsRead, SessionsManage,
                ].into_iter().collect()
            }
            
            Role::OrgAdmin => {
                // OrgAdmin can manage users and devices
                vec![
                    UserCreate, UserRead, UserUpdate, UserDelete, UserBulkOps,
                    DeviceRegister, DeviceRead, DeviceRevoke, DeviceBulkOps,
                    ConfigRead,
                    MetricsRead, HealthCheck,
                    AuditRead,
                ].into_iter().collect()
            }
            
            Role::Auditor => {
                // Auditor has read-only access to audit and compliance
                vec![
                    UserRead,
                    DeviceRead,
                    ConfigRead,
                    MetricsRead, HealthCheck, LogsRead,
                    FederationRead,
                    AuditRead, AuditExport, ComplianceReport,
                ].into_iter().collect()
            }
            
            Role::Operator => {
                // Operator manages server operations
                vec![
                    ServerStart, ServerStop, ServerReload, ServerStatus,
                    MetricsRead, HealthCheck, LogsRead,
                    ConfigRead,
                    AuditRead,
                    ConnectionsRead, ConnectionsManage,
                    SessionsRead, SessionsManage,
                ].into_iter().collect()
            }
            
            Role::FederationManager => {
                // FederationManager manages federation partnerships
                vec![
                    FederationCreate, FederationRead, FederationUpdate, FederationDelete,
                    ConfigRead,
                    MetricsRead, HealthCheck,
                    AuditRead,
                ].into_iter().collect()
            }
        }
    }
    
    /// Check if role has a specific permission
    pub fn has_permission(&self, permission: Permission) -> bool {
        self.permissions().contains(&permission)
    }
}

/// Check if a set of roles has a specific permission
pub fn has_permission(roles: &[Role], permission: Permission) -> bool {
    roles.iter().any(|role| role.has_permission(permission))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_super_admin_has_all_permissions() {
        let role = Role::SuperAdmin;
        assert!(role.has_permission(Permission::UserCreate));
        assert!(role.has_permission(Permission::ServerStop));
        assert!(role.has_permission(Permission::AuditExport));
    }

    #[test]
    fn test_auditor_read_only() {
        let role = Role::Auditor;
        assert!(role.has_permission(Permission::AuditRead));
        assert!(role.has_permission(Permission::UserRead));
        assert!(!role.has_permission(Permission::UserCreate));
        assert!(!role.has_permission(Permission::ServerStop));
    }

    #[test]
    fn test_operator_no_user_management() {
        let role = Role::Operator;
        assert!(role.has_permission(Permission::ServerStatus));
        assert!(role.has_permission(Permission::MetricsRead));
        assert!(!role.has_permission(Permission::UserCreate));
    }
}
