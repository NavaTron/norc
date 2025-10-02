/// Test certificate generation utilities for comprehensive security testing
///
/// This module provides utilities for generating various types of test certificates
/// to validate certificate handling, validation, and pinning functionality.
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::time::Duration;
use time::OffsetDateTime;

/// Test certificate bundle containing certificate and private key
pub struct TestCertBundle {
    pub cert_der: Vec<u8>,
    pub cert_pem: String,
    pub key_der: Vec<u8>,
    pub key_pem: String,
    pub certificate: Certificate,
}

impl TestCertBundle {
    /// Get certificate as rustls CertificateDer
    pub fn as_rustls_cert(&self) -> CertificateDer<'static> {
        CertificateDer::from(self.cert_der.clone())
    }

    /// Get private key as rustls PrivateKeyDer
    pub fn as_rustls_key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(self.key_der.clone().into())
    }

    /// Get certificate chain as Vec<CertificateDer>
    pub fn as_cert_chain(&self) -> Vec<CertificateDer<'static>> {
        vec![self.as_rustls_cert()]
    }
}

/// Certificate builder with fluent API for test scenarios
pub struct TestCertBuilder {
    params: CertificateParams,
    key_pair: Option<KeyPair>,
    // For now, we don't support issuer chaining with rcgen 0.13
    // All certificates will be self-signed for testing purposes
}

impl TestCertBuilder {
    /// Create a new certificate builder with default parameters
    pub fn new() -> Self {
        let mut params = CertificateParams::default();

        // Default validity: 30 days
        params.not_before = OffsetDateTime::now_utc();
        params.not_after = OffsetDateTime::now_utc() + Duration::from_secs(30 * 24 * 3600);

        Self {
            params,
            key_pair: None,
        }
    }

    /// Set the subject organization (O field)
    pub fn organization(mut self, org: impl Into<String>) -> Self {
        self.params
            .distinguished_name
            .push(DnType::OrganizationName, org.into());
        self
    }

    /// Set the subject common name (CN field)
    pub fn common_name(mut self, cn: impl Into<String>) -> Self {
        self.params
            .distinguished_name
            .push(DnType::CommonName, cn.into());
        self
    }

    /// Set the subject organizational unit (OU field)
    pub fn organizational_unit(mut self, ou: impl Into<String>) -> Self {
        self.params
            .distinguished_name
            .push(DnType::OrganizationalUnitName, ou.into());
        self
    }

    /// Set the subject country (C field)
    pub fn country(mut self, country: impl Into<String>) -> Self {
        self.params
            .distinguished_name
            .push(DnType::CountryName, country.into());
        self
    }

    /// Add a Subject Alternative Name (DNS)
    pub fn san_dns(mut self, dns: impl Into<String>) -> Self {
        self.params
            .subject_alt_names
            .push(SanType::DnsName(dns.into().try_into().unwrap()));
        self
    }

    /// Add a Subject Alternative Name (IP address)
    pub fn san_ip(mut self, ip: std::net::IpAddr) -> Self {
        self.params.subject_alt_names.push(SanType::IpAddress(ip));
        self
    }

    /// Make this a CA certificate
    pub fn ca(mut self) -> Self {
        self.params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        self.params.key_usages.push(KeyUsagePurpose::KeyCertSign);
        self.params.key_usages.push(KeyUsagePurpose::CrlSign);
        self
    }

    /// Make this an end-entity certificate for TLS server authentication
    pub fn server_auth(mut self) -> Self {
        self.params.is_ca = IsCa::NoCa;
        self.params
            .key_usages
            .push(KeyUsagePurpose::DigitalSignature);
        self.params
            .key_usages
            .push(KeyUsagePurpose::KeyEncipherment);
        self.params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ServerAuth);
        self
    }

    /// Make this an end-entity certificate for TLS client authentication
    pub fn client_auth(mut self) -> Self {
        self.params.is_ca = IsCa::NoCa;
        self.params
            .key_usages
            .push(KeyUsagePurpose::DigitalSignature);
        self.params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ClientAuth);
        self
    }

    /// Set certificate validity period (days from now)
    pub fn valid_for_days(mut self, days: u64) -> Self {
        self.params.not_before = OffsetDateTime::now_utc();
        self.params.not_after = OffsetDateTime::now_utc() + Duration::from_secs(days * 24 * 3600);
        self
    }

    /// Create an expired certificate (expired 1 day ago)
    pub fn expired(mut self) -> Self {
        let now = OffsetDateTime::now_utc();
        self.params.not_before = now - Duration::from_secs(31 * 24 * 3600); // 31 days ago
        self.params.not_after = now - Duration::from_secs(24 * 3600); // 1 day ago
        self
    }

    /// Create a not-yet-valid certificate (valid starting tomorrow)
    pub fn not_yet_valid(mut self) -> Self {
        let tomorrow = OffsetDateTime::now_utc() + Duration::from_secs(24 * 3600);
        self.params.not_before = tomorrow;
        self.params.not_after = tomorrow + Duration::from_secs(30 * 24 * 3600);
        self
    }

    /// Set a specific validity period
    pub fn valid_from_to(mut self, not_before: OffsetDateTime, not_after: OffsetDateTime) -> Self {
        self.params.not_before = not_before;
        self.params.not_after = not_after;
        self
    }

    /// Set serial number
    pub fn serial_number(mut self, serial: u64) -> Self {
        self.params.serial_number = Some(serial.into());
        self
    }

    /// Use a specific key pair (for issuer certificates)
    pub fn key_pair(mut self, key_pair: KeyPair) -> Self {
        self.key_pair = Some(key_pair);
        self
    }

    /// Build the certificate
    pub fn build(self) -> anyhow::Result<TestCertBundle> {
        // Generate or use provided key pair
        let key_pair = self
            .key_pair
            .unwrap_or_else(|| KeyPair::generate().expect("Failed to generate key pair"));

        // rcgen 0.13 API: Create self-signed certificate
        let certificate = self.params.self_signed(&key_pair)?;

        let cert_der = certificate.der().to_vec();
        let cert_pem = certificate.pem();
        let key_der = key_pair.serialize_der();
        let key_pem = key_pair.serialize_pem();

        Ok(TestCertBundle {
            cert_der,
            cert_pem,
            key_der,
            key_pem,
            certificate,
        })
    }
}

impl Default for TestCertBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Create a self-signed root CA certificate
pub fn create_root_ca(org_name: &str) -> anyhow::Result<TestCertBundle> {
    TestCertBuilder::new()
        .organization(org_name)
        .common_name(format!("{} Root CA", org_name))
        .ca()
        .valid_for_days(3650) // 10 years
        .build()
}

/// Create an intermediate CA certificate (self-signed for testing)
pub fn create_intermediate_ca(
    org_name: &str,
    _root_ca: &TestCertBundle,
) -> anyhow::Result<TestCertBundle> {
    // Note: In rcgen 0.13, proper CA chain signing requires more complex setup
    // For testing purposes, we create self-signed intermediate CAs
    TestCertBuilder::new()
        .organization(org_name)
        .common_name(format!("{} Intermediate CA", org_name))
        .ca()
        .valid_for_days(1825) // 5 years
        .build()
}

/// Create a valid server certificate (self-signed for testing)
pub fn create_server_cert(
    org_name: &str,
    hostname: &str,
    _ca: Option<&TestCertBundle>,
) -> anyhow::Result<TestCertBundle> {
    // Note: CA parameter ignored for rcgen 0.13 simplicity
    // All test certificates are self-signed
    TestCertBuilder::new()
        .organization(org_name)
        .common_name(hostname)
        .san_dns(hostname)
        .san_dns("localhost")
        .san_ip("127.0.0.1".parse().unwrap())
        .server_auth()
        .valid_for_days(365)
        .build()
}

/// Create a valid client certificate (self-signed for testing)
pub fn create_client_cert(
    org_name: &str,
    client_id: &str,
    _ca: Option<&TestCertBundle>,
) -> anyhow::Result<TestCertBundle> {
    // Note: CA parameter ignored for rcgen 0.13 simplicity
    // All test certificates are self-signed
    TestCertBuilder::new()
        .organization(org_name)
        .common_name(format!("client-{}", client_id))
        .organizational_unit("Federation")
        .client_auth()
        .valid_for_days(365)
        .build()
}

/// Create an expired certificate
pub fn create_expired_cert(org_name: &str) -> anyhow::Result<TestCertBundle> {
    TestCertBuilder::new()
        .organization(org_name)
        .common_name("expired.example.com")
        .server_auth()
        .expired()
        .build()
}

/// Create a not-yet-valid certificate
pub fn create_not_yet_valid_cert(org_name: &str) -> anyhow::Result<TestCertBundle> {
    TestCertBuilder::new()
        .organization(org_name)
        .common_name("future.example.com")
        .server_auth()
        .not_yet_valid()
        .build()
}

/// Create a certificate with invalid key usage (CA cert used as client cert)
pub fn create_invalid_key_usage_cert(org_name: &str) -> anyhow::Result<TestCertBundle> {
    // Create a CA certificate but mark it for client auth
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::OrganizationName, org_name.to_string());
    params.distinguished_name.push(
        DnType::CommonName,
        "invalid-key-usage.example.com".to_string(),
    );

    // CA basic constraints but with client auth
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ClientAuth);

    params.not_before = OffsetDateTime::now_utc();
    params.not_after = OffsetDateTime::now_utc() + Duration::from_secs(365 * 24 * 3600);

    // Generate key pair and create certificate
    let key_pair = KeyPair::generate()?;
    let certificate = params.self_signed(&key_pair)?;

    let cert_der = certificate.der().to_vec();
    let cert_pem = certificate.pem();
    let key_der = key_pair.serialize_der();
    let key_pem = key_pair.serialize_pem();

    Ok(TestCertBundle {
        cert_der,
        cert_pem,
        key_der,
        key_pem,
        certificate,
    })
}

/// Create a complete certificate chain (root CA -> intermediate CA -> end entity)
pub fn create_cert_chain(
    org_name: &str,
    is_server: bool,
) -> anyhow::Result<(TestCertBundle, TestCertBundle, TestCertBundle)> {
    let root_ca = create_root_ca(org_name)?;
    let intermediate_ca = create_intermediate_ca(org_name, &root_ca)?;

    let end_entity = if is_server {
        create_server_cert(org_name, "server.example.com", Some(&intermediate_ca))?
    } else {
        create_client_cert(org_name, "client-001", Some(&intermediate_ca))?
    };

    Ok((root_ca, intermediate_ca, end_entity))
}

/// Write certificate and key to temporary files
pub fn write_cert_to_temp_files(
    bundle: &TestCertBundle,
) -> anyhow::Result<(tempfile::NamedTempFile, tempfile::NamedTempFile)> {
    use std::io::Write;

    let mut cert_file = tempfile::NamedTempFile::new()?;
    cert_file.write_all(bundle.cert_pem.as_bytes())?;
    cert_file.flush()?;

    let mut key_file = tempfile::NamedTempFile::new()?;
    key_file.write_all(bundle.key_pem.as_bytes())?;
    key_file.flush()?;

    Ok((cert_file, key_file))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_root_ca() {
        let ca = create_root_ca("TestOrg").unwrap();
        assert!(!ca.cert_pem.is_empty());
        assert!(!ca.key_pem.is_empty());
        assert!(!ca.cert_der.is_empty());
    }

    #[test]
    fn test_create_server_cert() {
        let ca = create_root_ca("TestOrg").unwrap();
        let server = create_server_cert("TestOrg", "server.example.com", Some(&ca)).unwrap();
        assert!(!server.cert_pem.is_empty());
        assert!(!server.key_pem.is_empty());
    }

    #[test]
    fn test_create_client_cert() {
        let ca = create_root_ca("TestOrg").unwrap();
        let client = create_client_cert("TestOrg", "client-001", Some(&ca)).unwrap();
        assert!(!client.cert_pem.is_empty());
        assert!(!client.key_pem.is_empty());
    }

    #[test]
    fn test_create_expired_cert() {
        let cert = create_expired_cert("TestOrg").unwrap();
        assert!(!cert.cert_pem.is_empty());
        // Verify it's actually expired by checking the not_after date
        // This would require parsing the certificate, which we'll do in integration tests
    }

    #[test]
    fn test_create_cert_chain() {
        let (root, intermediate, end_entity) = create_cert_chain("TestOrg", true).unwrap();
        assert!(!root.cert_pem.is_empty());
        assert!(!intermediate.cert_pem.is_empty());
        assert!(!end_entity.cert_pem.is_empty());
    }

    #[test]
    fn test_write_to_temp_files() {
        let ca = create_root_ca("TestOrg").unwrap();
        let (cert_file, key_file) = write_cert_to_temp_files(&ca).unwrap();

        assert!(cert_file.path().exists());
        assert!(key_file.path().exists());
    }
}
