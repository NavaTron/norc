//! Trust level management and verification

use serde::{Deserialize, Serialize};
use std::fmt;

/// Trust level hierarchy as defined in PROTOCOL_REQUIREMENTS.md
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum TrustLevel {
    /// No established trust relationship; communication prohibited
    Untrusted = 0,
    /// Domain verification sufficient; standard business relationships
    Basic = 1,
    /// Organizational verification required; enhanced assurance relationships
    Verified = 2,
    /// Government/enterprise PKI required; security-cleared environments
    Classified = 3,
    /// NATO-level security clearance; international security cooperation
    Nato = 4,
}

impl TrustLevel {
    /// Get the minimum key size in bits required for this trust level
    pub const fn min_key_bits(&self) -> u16 {
        match self {
            TrustLevel::Untrusted => 0,
            TrustLevel::Basic => 2048,
            TrustLevel::Verified => 3072,
            TrustLevel::Classified => 4096,
            TrustLevel::Nato => 4096,
        }
    }

    /// Check if this trust level requires post-quantum cryptography
    pub const fn requires_pq_crypto(&self) -> bool {
        matches!(self, TrustLevel::Classified | TrustLevel::Nato)
    }

    /// Check if this trust level requires hardware security module (HSM)
    pub const fn requires_hsm(&self) -> bool {
        matches!(self, TrustLevel::Classified | TrustLevel::Nato)
    }

    /// Get the audit log retention period in days
    pub const fn audit_retention_days(&self) -> u32 {
        match self {
            TrustLevel::Untrusted => 0,
            TrustLevel::Basic => 90,
            TrustLevel::Verified => 365,
            TrustLevel::Classified => 2555, // 7 years
            TrustLevel::Nato => 3650,       // 10 years
        }
    }

    /// Check if communication is allowed between two trust levels
    pub fn allows_communication_with(&self, other: &TrustLevel) -> bool {
        // Untrusted never allows communication
        if *self == TrustLevel::Untrusted || *other == TrustLevel::Untrusted {
            return false;
        }

        // Communication is allowed if both sides meet the minimum trust level
        // which is the maximum of the two levels
        true
    }

    /// Get the effective trust level for communication between two levels
    /// Returns the more restrictive (higher) trust level
    pub fn effective_level(&self, other: &TrustLevel) -> TrustLevel {
        if *self > *other { *self } else { *other }
    }

    /// Parse a trust level from a string
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "untrusted" => Some(TrustLevel::Untrusted),
            "basic" => Some(TrustLevel::Basic),
            "verified" => Some(TrustLevel::Verified),
            "classified" => Some(TrustLevel::Classified),
            "nato" => Some(TrustLevel::Nato),
            _ => None,
        }
    }
}

impl fmt::Display for TrustLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TrustLevel::Untrusted => write!(f, "Untrusted"),
            TrustLevel::Basic => write!(f, "Basic"),
            TrustLevel::Verified => write!(f, "Verified"),
            TrustLevel::Classified => write!(f, "Classified"),
            TrustLevel::Nato => write!(f, "NATO"),
        }
    }
}

impl Default for TrustLevel {
    fn default() -> Self {
        TrustLevel::Basic
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trust_level_ordering() {
        assert!(TrustLevel::Basic < TrustLevel::Verified);
        assert!(TrustLevel::Verified < TrustLevel::Classified);
        assert!(TrustLevel::Classified < TrustLevel::Nato);
    }

    #[test]
    fn test_trust_level_requirements() {
        assert_eq!(TrustLevel::Basic.min_key_bits(), 2048);
        assert_eq!(TrustLevel::Nato.min_key_bits(), 4096);

        assert!(!TrustLevel::Basic.requires_pq_crypto());
        assert!(TrustLevel::Classified.requires_pq_crypto());

        assert!(!TrustLevel::Basic.requires_hsm());
        assert!(TrustLevel::Nato.requires_hsm());
    }

    #[test]
    fn test_trust_level_communication() {
        assert!(!TrustLevel::Untrusted.allows_communication_with(&TrustLevel::Basic));
        assert!(TrustLevel::Basic.allows_communication_with(&TrustLevel::Verified));

        assert_eq!(
            TrustLevel::Basic.effective_level(&TrustLevel::Classified),
            TrustLevel::Classified
        );
    }

    #[test]
    fn test_trust_level_parsing() {
        assert_eq!(TrustLevel::parse("basic"), Some(TrustLevel::Basic));
        assert_eq!(TrustLevel::parse("NATO"), Some(TrustLevel::Nato));
        assert_eq!(TrustLevel::parse("invalid"), None);
    }
}
