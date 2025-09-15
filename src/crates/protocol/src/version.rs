//! NORC protocol version handling and Adjacent-Major Compatibility (AMC)

use crate::error::{NorcError, Result};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt;
use std::str::FromStr;

/// NORC protocol version with major.minor format
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Version {
    /// Major version number
    pub major: u8,
    /// Minor version number  
    pub minor: u8,
}

impl Version {
    /// Create a new version
    ///
    /// # Examples
    ///
    /// ```
    /// # use navatron_protocol::Version;
    /// let version = Version::new(2, 0)?;
    /// assert_eq!(version.major, 2);
    /// assert_eq!(version.minor, 0);
    /// # Ok::<(), navatron_protocol::NorcError>(())
    /// ```
    pub fn new(major: u8, minor: u8) -> Result<Self> {
        if major == 0 {
            return Err(NorcError::version("Major version cannot be 0"));
        }
        Ok(Self { major, minor })
    }

    /// NORC protocol version 1.0
    pub const V1_0: Self = Self { major: 1, minor: 0 };
    /// NORC protocol version 1.1  
    pub const V1_1: Self = Self { major: 1, minor: 1 };
    /// NORC protocol version 2.0
    pub const V2_0: Self = Self { major: 2, minor: 0 };

    /// Current protocol version (latest stable)
    pub const CURRENT: Self = Self::V2_0;

    /// Check if two versions are compatible under Adjacent-Major Compatibility (AMC)
    ///
    /// AMC allows interoperability across one major version gap (N ↔ N+1)
    ///
    /// # Examples
    ///
    /// ```
    /// # use navatron_protocol::Version;
    /// assert!(Version::V1_0.is_compatible_with(Version::V2_0)); // 1.x ↔ 2.x ✅
    /// assert!(Version::V2_0.is_compatible_with(Version::V1_1)); // 2.x ↔ 1.x ✅  
    /// assert!(!Version::V1_0.is_compatible_with(Version { major: 3, minor: 0 })); // 1.x ↔ 3.x ❌
    /// ```
    pub fn is_compatible_with(self, other: Version) -> bool {
        let major_diff = if self.major > other.major {
            self.major - other.major
        } else {
            other.major - self.major
        };
        major_diff <= 1
    }

    /// Check if this version supports a specific feature
    pub fn supports_feature(self, feature: VersionFeature) -> bool {
        match feature {
            VersionFeature::BasicMessaging => true, // All versions
            VersionFeature::HashChaining => self >= Self::V1_1,
            VersionFeature::PostQuantumHybrid => self >= Self::V2_0,
            VersionFeature::AdvancedRatcheting => self >= Self::V2_0,
            VersionFeature::FederationV2 => self >= Self::V2_0,
        }
    }

    /// Get the canonical wire format for this version
    pub fn wire_format(self) -> [u8; 2] {
        [self.major, self.minor]
    }

    /// Parse version from wire format
    pub fn from_wire(bytes: [u8; 2]) -> Result<Self> {
        Self::new(bytes[0], bytes[1])
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

impl FromStr for Version {
    type Err = NorcError;

    fn from_str(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 2 {
            return Err(NorcError::version(format!(
                "Invalid version format: {s}, expected major.minor"
            )));
        }

        let major = parts[0]
            .parse::<u8>()
            .map_err(|_| NorcError::version(format!("Invalid major version: {}", parts[0])))?;
        let minor = parts[1]
            .parse::<u8>()
            .map_err(|_| NorcError::version(format!("Invalid minor version: {}", parts[1])))?;

        Self::new(major, minor)
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.major.cmp(&other.major) {
            Ordering::Equal => self.minor.cmp(&other.minor),
            other => other,
        }
    }
}

/// Protocol features that depend on version
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionFeature {
    /// Basic messaging support (all versions)
    BasicMessaging,
    /// Message hash chaining (1.1+)
    HashChaining,
    /// Post-quantum hybrid cryptography (2.0+)
    PostQuantumHybrid,
    /// Advanced ratcheting (2.0+)
    AdvancedRatcheting,
    /// Federation protocol v2 (2.0+)
    FederationV2,
}

/// Version negotiation helper
#[derive(Debug, Clone)]
pub struct VersionNegotiation {
    /// Versions supported by local implementation
    pub supported: Vec<Version>,
    /// Preferred version (highest supported)
    pub preferred: Version,
}

impl VersionNegotiation {
    /// Create new version negotiation with supported versions
    ///
    /// # Examples
    ///
    /// ```
    /// # use navatron_protocol::{Version, VersionNegotiation};
    /// let negotiation = VersionNegotiation::new(vec![
    ///     Version::V1_0,
    ///     Version::V1_1, 
    ///     Version::V2_0,
    /// ])?;
    /// assert_eq!(negotiation.preferred, Version::V2_0);
    /// # Ok::<(), navatron_protocol::NorcError>(())
    /// ```
    pub fn new(mut supported: Vec<Version>) -> Result<Self> {
        if supported.is_empty() {
            return Err(NorcError::version("No supported versions provided"));
        }

        // Sort versions in ascending order
        supported.sort();
        let preferred = *supported
            .last()
            .ok_or_else(|| NorcError::version("Internal error: no versions after sort"))?;

        Ok(Self {
            supported,
            preferred,
        })
    }

    /// Negotiate the best version with a remote peer
    ///
    /// Returns the highest mutually compatible version according to AMC rules
    ///
    /// # Examples
    ///
    /// ```
    /// # use navatron_protocol::{Version, VersionNegotiation};
    /// let local = VersionNegotiation::new(vec![Version::V1_0, Version::V2_0])?;
    /// let remote = vec![Version::V1_1, Version::V2_0];
    /// 
    /// let negotiated = local.negotiate(&remote)?;
    /// assert_eq!(negotiated, Version::V2_0); // Highest mutual version
    /// # Ok::<(), navatron_protocol::NorcError>(())
    /// ```
    pub fn negotiate(&self, remote_versions: &[Version]) -> Result<Version> {
        // First try to find exact matches, preferring highest version
        let mut exact_matches: Vec<Version> = self
            .supported
            .iter()
            .filter(|v| remote_versions.contains(v))
            .copied()
            .collect();

        if !exact_matches.is_empty() {
            exact_matches.sort();
            return Ok(*exact_matches.last().unwrap());
        }

        // If no exact matches, try AMC compatibility
        let mut compatible: Vec<Version> = Vec::new();

        for local_version in &self.supported {
            for remote_version in remote_versions {
                if local_version.is_compatible_with(*remote_version) {
                    // Use the higher version when compatible
                    compatible.push((*local_version).max(*remote_version));
                }
            }
        }

        if compatible.is_empty() {
            return Err(NorcError::version(format!(
                "No compatible versions found. Local: {:?}, Remote: {:?}",
                self.supported, remote_versions
            )));
        }

        compatible.sort();
        compatible.dedup();
        Ok(*compatible.last().unwrap())
    }

    /// Check if a version is supported
    pub fn supports(&self, version: Version) -> bool {
        self.supported.contains(&version)
    }

    /// Get compatibility mode info if negotiated version differs from preferred
    pub fn compatibility_mode(&self, negotiated: Version) -> Option<String> {
        if negotiated == self.preferred {
            None
        } else {
            Some(format!(
                "Using compatibility mode: negotiated {} instead of preferred {}",
                negotiated, self.preferred
            ))
        }
    }
}

impl Default for VersionNegotiation {
    fn default() -> Self {
        Self::new(vec![Version::V1_0, Version::V1_1, Version::V2_0])
            .expect("Default version negotiation should be valid")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_creation() {
        let v = Version::new(2, 0).unwrap();
        assert_eq!(v.major, 2);
        assert_eq!(v.minor, 0);

        assert!(Version::new(0, 1).is_err()); // Major version cannot be 0
    }

    #[test]
    fn test_version_parsing() {
        assert_eq!("2.0".parse::<Version>().unwrap(), Version::V2_0);
        assert_eq!("1.1".parse::<Version>().unwrap(), Version::V1_1);

        assert!("2".parse::<Version>().is_err()); // Missing minor
        assert!("2.0.1".parse::<Version>().is_err()); // Too many parts
        assert!("invalid".parse::<Version>().is_err()); // Non-numeric
    }

    #[test]
    fn test_version_display() {
        assert_eq!(Version::V2_0.to_string(), "2.0");
        assert_eq!(Version::V1_1.to_string(), "1.1");
    }

    #[test]
    fn test_version_ordering() {
        assert!(Version::V1_0 < Version::V1_1);
        assert!(Version::V1_1 < Version::V2_0);
        assert!(Version::V2_0 > Version::V1_0);
    }

    #[test]
    fn test_amc_compatibility() {
        // Adjacent major versions are compatible
        assert!(Version::V1_0.is_compatible_with(Version::V2_0));
        assert!(Version::V2_0.is_compatible_with(Version::V1_1));

        // Same major versions are compatible
        assert!(Version::V1_0.is_compatible_with(Version::V1_1));

        // Non-adjacent major versions are not compatible
        let v3_0 = Version::new(3, 0).unwrap();
        assert!(!Version::V1_0.is_compatible_with(v3_0));
    }

    #[test]
    fn test_version_features() {
        assert!(Version::V1_0.supports_feature(VersionFeature::BasicMessaging));
        assert!(!Version::V1_0.supports_feature(VersionFeature::HashChaining));
        assert!(Version::V1_1.supports_feature(VersionFeature::HashChaining));
        assert!(Version::V2_0.supports_feature(VersionFeature::PostQuantumHybrid));
    }

    #[test]
    fn test_wire_format() {
        let v = Version::V2_0;
        let wire = v.wire_format();
        assert_eq!(wire, [2, 0]);

        let parsed = Version::from_wire(wire).unwrap();
        assert_eq!(parsed, v);
    }

    #[test]
    fn test_version_negotiation() {
        let negotiation = VersionNegotiation::new(vec![Version::V1_0, Version::V2_0]).unwrap();
        assert_eq!(negotiation.preferred, Version::V2_0);

        // Exact match
        let result = negotiation.negotiate(&[Version::V1_0, Version::V2_0]).unwrap();
        assert_eq!(result, Version::V2_0); // Highest mutual

        // AMC compatibility
        let result = negotiation.negotiate(&[Version::V1_1]).unwrap();
        assert_eq!(result, Version::V2_0); // Compatible via AMC, use higher

        // No compatibility - major diff > 1 from all supported versions
        let v4_0 = Version::new(4, 0).unwrap();
        let v5_0 = Version::new(5, 0).unwrap();
        assert!(negotiation.negotiate(&[v4_0, v5_0]).is_err());
    }

    #[test]
    fn test_compatibility_mode() {
        let negotiation = VersionNegotiation::default();
        assert!(negotiation.compatibility_mode(Version::V2_0).is_none());
        assert!(negotiation.compatibility_mode(Version::V1_0).is_some());
    }
}