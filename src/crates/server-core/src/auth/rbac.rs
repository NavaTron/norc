//! Role-Based Access Control (RBAC)
//!
//! Implements authorization and permission checking

use crate::ServerError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Permissions for various operations
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Permission {
    // Message permissions
    MessageSend,
    MessageReceive,
    MessageDelete,
    
    // User management
    UserCreate,
    UserRead,
    UserUpdate,
    UserDelete,
    
    // Device management
    DeviceRegister,
    DeviceRevoke,
    DeviceList,
    
    // Federation management
    FederationCreate,
    FederationUpdate,
    FederationDelete,
    FederationList,
    
    // Admin operations
    ConfigRead,
    ConfigWrite,
    ConfigReload,
    
    // Monitoring
    MetricsRead,
    LogsRead,
    HealthCheck,
    
    // System administration
    SystemShutdown,
    SystemRestart,
    SystemBackup,
}

/// User roles with associated permissions
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Role {
    /// Regular user - can send/receive messages
    User,
    
    /// Device administrator - can manage devices
    DeviceAdmin,
    
    /// Organization administrator - can manage users and devices
    OrgAdmin,
    
    /// Federation administrator - can manage federation
    FederationAdmin,
    
    /// System administrator - full access
    SystemAdmin,
    
    /// Federation partner with trust level
    FederationPartner(super::federation_auth::TrustLevel),
    
    /// Custom role with specific permissions
    Custom(String, Vec<Permission>),
}

impl Role {
    /// Get permissions for this role
    pub fn permissions(&self) -> Vec<Permission> {
        match self {
            Role::User => vec![
                Permission::MessageSend,
                Permission::MessageReceive,
                Permission::HealthCheck,
            ],
            
            Role::DeviceAdmin => vec![
                Permission::MessageSend,
                Permission::MessageReceive,
                Permission::DeviceRegister,
                Permission::DeviceRevoke,
                Permission::DeviceList,
                Permission::HealthCheck,
            ],
            
            Role::OrgAdmin => vec![
                Permission::MessageSend,
                Permission::MessageReceive,
                Permission::UserCreate,
                Permission::UserRead,
                Permission::UserUpdate,
                Permission::UserDelete,
                Permission::DeviceRegister,
                Permission::DeviceRevoke,
                Permission::DeviceList,
                Permission::ConfigRead,
                Permission::MetricsRead,
                Permission::LogsRead,
                Permission::HealthCheck,
            ],
            
            Role::FederationAdmin => vec![
                Permission::MessageSend,
                Permission::MessageReceive,
                Permission::FederationCreate,
                Permission::FederationUpdate,
                Permission::FederationDelete,
                Permission::FederationList,
                Permission::ConfigRead,
                Permission::MetricsRead,
                Permission::HealthCheck,
            ],
            
            Role::SystemAdmin => {
                // System admins have all permissions
                vec![
                    Permission::MessageSend,
                    Permission::MessageReceive,
                    Permission::MessageDelete,
                    Permission::UserCreate,
                    Permission::UserRead,
                    Permission::UserUpdate,
                    Permission::UserDelete,
                    Permission::DeviceRegister,
                    Permission::DeviceRevoke,
                    Permission::DeviceList,
                    Permission::FederationCreate,
                    Permission::FederationUpdate,
                    Permission::FederationDelete,
                    Permission::FederationList,
                    Permission::ConfigRead,
                    Permission::ConfigWrite,
                    Permission::ConfigReload,
                    Permission::MetricsRead,
                    Permission::LogsRead,
                    Permission::HealthCheck,
                    Permission::SystemShutdown,
                    Permission::SystemRestart,
                    Permission::SystemBackup,
                ]
            },
            
            Role::FederationPartner(trust_level) => {
                use super::federation_auth::TrustLevel;
                match trust_level {
                    TrustLevel::None => vec![],
                    TrustLevel::Basic => vec![
                        Permission::MessageSend,
                        Permission::MessageReceive,
                    ],
                    TrustLevel::Standard => vec![
                        Permission::MessageSend,
                        Permission::MessageReceive,
                        Permission::HealthCheck,
                    ],
                    TrustLevel::Enhanced => vec![
                        Permission::MessageSend,
                        Permission::MessageReceive,
                        Permission::FederationList,
                        Permission::HealthCheck,
                        Permission::MetricsRead,
                    ],
                    TrustLevel::Full => vec![
                        Permission::MessageSend,
                        Permission::MessageReceive,
                        Permission::MessageDelete,
                        Permission::FederationList,
                        Permission::HealthCheck,
                        Permission::MetricsRead,
                        Permission::LogsRead,
                    ],
                }
            },
            
            Role::Custom(_, permissions) => permissions.clone(),
        }
    }
}

/// Access control manager
pub struct AccessControl {
    /// Custom role definitions
    custom_roles: HashMap<String, Vec<Permission>>,
}

impl AccessControl {
    /// Create a new access control manager
    pub fn new() -> Self {
        Self {
            custom_roles: HashMap::new(),
        }
    }

    /// Get permissions for a role
    pub fn get_permissions(&self, role: &Role) -> Result<Vec<Permission>, ServerError> {
        Ok(role.permissions())
    }

    /// Check if a role has a specific permission
    pub fn has_permission(&self, role: &Role, permission: &Permission) -> bool {
        role.permissions().contains(permission)
    }

    /// Require a specific permission for a role
    pub fn require_permission(&self, role: &Role, permission: &Permission) -> Result<(), ServerError> {
        if self.has_permission(role, permission) {
            Ok(())
        } else {
            Err(ServerError::Unauthorized(format!(
                "Role {:?} does not have permission {:?}",
                role, permission
            )))
        }
    }

    /// Define a custom role
    pub fn define_custom_role(&mut self, name: String, permissions: Vec<Permission>) {
        self.custom_roles.insert(name, permissions);
    }

    /// Get a custom role
    pub fn get_custom_role(&self, name: &str) -> Option<Role> {
        self.custom_roles
            .get(name)
            .map(|perms| Role::Custom(name.to_string(), perms.clone()))
    }

    /// Remove a custom role
    pub fn remove_custom_role(&mut self, name: &str) -> Option<Vec<Permission>> {
        self.custom_roles.remove(name)
    }
}

impl Default for AccessControl {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_role_permissions() {
        let role = Role::User;
        let permissions = role.permissions();
        
        assert!(permissions.contains(&Permission::MessageSend));
        assert!(permissions.contains(&Permission::MessageReceive));
        assert!(!permissions.contains(&Permission::UserCreate));
    }

    #[test]
    fn test_system_admin_permissions() {
        let role = Role::SystemAdmin;
        let permissions = role.permissions();
        
        // System admin should have all permissions
        assert!(permissions.contains(&Permission::MessageSend));
        assert!(permissions.contains(&Permission::UserCreate));
        assert!(permissions.contains(&Permission::SystemShutdown));
        assert!(permissions.contains(&Permission::ConfigWrite));
    }

    #[test]
    fn test_federation_partner_permissions() {
        use super::super::federation_auth::TrustLevel;
        
        let basic_role = Role::FederationPartner(TrustLevel::Basic);
        let basic_perms = basic_role.permissions();
        assert!(basic_perms.contains(&Permission::MessageSend));
        assert!(!basic_perms.contains(&Permission::MetricsRead));
        
        let enhanced_role = Role::FederationPartner(TrustLevel::Enhanced);
        let enhanced_perms = enhanced_role.permissions();
        assert!(enhanced_perms.contains(&Permission::MetricsRead));
    }

    #[test]
    fn test_access_control() {
        let ac = AccessControl::new();
        
        assert!(ac.has_permission(&Role::SystemAdmin, &Permission::ConfigWrite));
        assert!(!ac.has_permission(&Role::User, &Permission::ConfigWrite));
        
        assert!(ac.require_permission(&Role::SystemAdmin, &Permission::ConfigWrite).is_ok());
        assert!(ac.require_permission(&Role::User, &Permission::ConfigWrite).is_err());
    }

    #[test]
    fn test_custom_roles() {
        let mut ac = AccessControl::new();
        
        ac.define_custom_role(
            "Moderator".to_string(),
            vec![Permission::MessageDelete, Permission::UserRead],
        );
        
        let moderator = ac.get_custom_role("Moderator").unwrap();
        assert!(ac.has_permission(&moderator, &Permission::MessageDelete));
        assert!(!ac.has_permission(&moderator, &Permission::UserCreate));
    }
}
