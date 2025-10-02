//! Protocol version management with Adjacent-Major Compatibility (AMC)

use crate::error::{ProtocolError, Result};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Protocol version number
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ProtocolVersion {
    /// Major version number
    pub major: u8,
    /// Minor version number
    pub minor: u8,
    /// Patch version number
    pub patch: u8,
}

impl ProtocolVersion {
    /// Current protocol version (1.0.0)
    pub const CURRENT: Self = Self {
        major: 1,
        minor: 0,
        patch: 0,
    };

    /// Create a new protocol version
    pub const fn new(major: u8, minor: u8, patch: u8) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Check if this version is compatible with another using Adjacent-Major Compatibility (AMC)
    ///
    /// AMC permits interoperability across exactly one major version gap (N ↔ N+1)
    /// but prohibits compatibility across two or more major version gaps
    pub fn is_compatible_with(&self, other: &Self) -> bool {
        // Same major version is always compatible
        if self.major == other.major {
            return true;
        }

        // Adjacent major versions are compatible (N ↔ N+1)
        let major_diff = if self.major > other.major {
            self.major - other.major
        } else {
            other.major - self.major
        };

        major_diff == 1
    }

    /// Negotiate the highest compatible version between two versions
    pub fn negotiate(&self, other: &Self) -> Result<Self> {
        if !self.is_compatible_with(other) {
            return Err(ProtocolError::InvalidVersion(format!(
                "Incompatible versions: {} and {}",
                self, other
            )));
        }

        // Return the lower of the two major versions with the highest minor/patch
        Ok(if self.major < other.major {
            *self
        } else if other.major < self.major {
            *other
        } else {
            // Same major version, choose the minimum (most conservative)
            if self < other { *self } else { *other }
        })
    }

    /// Parse a version string in the format "major.minor.patch"
    pub fn parse(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 3 {
            return Err(ProtocolError::InvalidVersion(format!(
                "Invalid version format: {}",
                s
            )));
        }

        let major = parts[0].parse::<u8>().map_err(|_| {
            ProtocolError::InvalidVersion(format!("Invalid major version: {}", parts[0]))
        })?;

        let minor = parts[1].parse::<u8>().map_err(|_| {
            ProtocolError::InvalidVersion(format!("Invalid minor version: {}", parts[1]))
        })?;

        let patch = parts[2].parse::<u8>().map_err(|_| {
            ProtocolError::InvalidVersion(format!("Invalid patch version: {}", parts[2]))
        })?;

        Ok(Self::new(major, minor, patch))
    }
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_compatibility() {
        let v1_0_0 = ProtocolVersion::new(1, 0, 0);
        let v1_1_0 = ProtocolVersion::new(1, 1, 0);
        let v2_0_0 = ProtocolVersion::new(2, 0, 0);
        let v3_0_0 = ProtocolVersion::new(3, 0, 0);

        // Same major version
        assert!(v1_0_0.is_compatible_with(&v1_1_0));

        // Adjacent major versions
        assert!(v1_0_0.is_compatible_with(&v2_0_0));
        assert!(v2_0_0.is_compatible_with(&v1_0_0));

        // Non-adjacent major versions
        assert!(!v1_0_0.is_compatible_with(&v3_0_0));
        assert!(!v3_0_0.is_compatible_with(&v1_0_0));
    }

    #[test]
    fn test_version_negotiation() {
        let v1_0_0 = ProtocolVersion::new(1, 0, 0);
        let v2_0_0 = ProtocolVersion::new(2, 0, 0);

        // Adjacent versions negotiate to the lower major version
        assert_eq!(v1_0_0.negotiate(&v2_0_0).unwrap(), v1_0_0);
        assert_eq!(v2_0_0.negotiate(&v1_0_0).unwrap(), v1_0_0);
    }

    #[test]
    fn test_version_parsing() {
        assert_eq!(
            ProtocolVersion::parse("1.0.0").unwrap(),
            ProtocolVersion::new(1, 0, 0)
        );
        assert!(ProtocolVersion::parse("invalid").is_err());
    }
}
