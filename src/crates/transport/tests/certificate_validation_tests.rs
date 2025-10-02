/// Integration tests for certificate validation functionality
///
/// This test suite validates:
/// - Organization ID extraction from certificates
/// - Certificate fingerprint computation
/// - Certificate pinning validation
/// - Mutual TLS configuration
mod common;

use common::*;
use norc_transport::{
    compute_certificate_fingerprint, extract_organization_id, verify_certificate_pin,
};
use rustls::pki_types::CertificateDer;
use sha2::{Digest, Sha256};

#[test]
fn test_extract_organization_id_from_valid_cert() {
    // Create a certificate with organization name
    let cert_bundle =
        create_client_cert("ACME-Corp", "client-001", None).expect("Failed to create client cert");

    let org_id = extract_organization_id(&cert_bundle.as_rustls_cert())
        .expect("Failed to extract organization ID");

    assert_eq!(org_id, "ACME-Corp");
}

#[test]
fn test_extract_organization_id_fallback_to_cn() {
    // Create a certificate with only CN, no O field
    let cert_bundle = TestCertBuilder::new()
        .common_name("client.example.com")
        .client_auth()
        .build()
        .expect("Failed to create cert");

    let org_id = extract_organization_id(&cert_bundle.as_rustls_cert())
        .expect("Failed to extract organization ID");

    // Should fall back to CN
    assert_eq!(org_id, "client.example.com");
}

#[test]
fn test_extract_organization_id_from_multiple_orgs() {
    // Test with multiple O fields - should return one of them
    let mut params = rcgen::CertificateParams::default();
    params
        .distinguished_name
        .push(rcgen::DnType::OrganizationName, "FirstOrg".to_string());
    params
        .distinguished_name
        .push(rcgen::DnType::OrganizationName, "SecondOrg".to_string());
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "test.example.com".to_string());

    let key_pair = rcgen::KeyPair::generate().expect("Failed to generate key pair");
    let certificate = params
        .self_signed(&key_pair)
        .expect("Failed to create certificate");

    let cert_der = certificate.der().to_vec();
    let cert = CertificateDer::from(cert_der);

    let org_id = extract_organization_id(&cert).expect("Failed to extract organization ID");

    // Should extract one of the organizations (order not guaranteed)
    assert!(
        org_id == "FirstOrg" || org_id == "SecondOrg",
        "Expected FirstOrg or SecondOrg, got: {}",
        org_id
    );
}

#[test]
fn test_extract_organization_id_no_org_or_cn() {
    // Create a certificate with neither O nor CN
    // Note: rcgen may auto-generate some fields, so this test checks
    // that extraction doesn't panic even with minimal certificates
    let mut params = rcgen::CertificateParams::default();
    params
        .distinguished_name
        .push(rcgen::DnType::CountryName, "US".to_string());

    let key_pair = rcgen::KeyPair::generate().expect("Failed to generate key pair");
    let certificate = params
        .self_signed(&key_pair)
        .expect("Failed to create certificate");

    let cert_der = certificate.der().to_vec();
    let cert = CertificateDer::from(cert_der);

    // Should either fail or extract a valid ID (rcgen might auto-generate)
    let result = extract_organization_id(&cert);
    // Just verify it doesn't panic - result can be Ok or Err depending on rcgen behavior
    let _ = result;
}

#[test]
fn test_compute_certificate_fingerprint() {
    let cert_bundle =
        create_client_cert("TestOrg", "client-001", None).expect("Failed to create client cert");

    let fingerprint = compute_certificate_fingerprint(&cert_bundle.as_rustls_cert())
        .expect("Failed to compute fingerprint");

    // Verify it's a SHA-256 hash (32 bytes)
    assert_eq!(fingerprint.len(), 32);

    // Verify it matches manual SHA-256 computation
    let mut hasher = Sha256::new();
    hasher.update(&cert_bundle.cert_der);
    let expected = hasher.finalize().to_vec();

    assert_eq!(fingerprint, expected);
}

#[test]
fn test_compute_fingerprint_consistency() {
    // Same certificate should always produce the same fingerprint
    let cert_bundle = create_server_cert("TestOrg", "server.example.com", None)
        .expect("Failed to create server cert");

    let fingerprint1 = compute_certificate_fingerprint(&cert_bundle.as_rustls_cert())
        .expect("Failed to compute fingerprint 1");
    let fingerprint2 = compute_certificate_fingerprint(&cert_bundle.as_rustls_cert())
        .expect("Failed to compute fingerprint 2");

    assert_eq!(fingerprint1, fingerprint2);
}

#[test]
fn test_compute_fingerprint_different_certs() {
    // Different certificates should produce different fingerprints
    let cert1 = create_client_cert("Org1", "client-001", None).expect("Failed to create cert 1");
    let cert2 = create_client_cert("Org2", "client-002", None).expect("Failed to create cert 2");

    let fingerprint1 = compute_certificate_fingerprint(&cert1.as_rustls_cert())
        .expect("Failed to compute fingerprint 1");
    let fingerprint2 = compute_certificate_fingerprint(&cert2.as_rustls_cert())
        .expect("Failed to compute fingerprint 2");

    assert_ne!(fingerprint1, fingerprint2);
}

#[test]
fn test_verify_certificate_pin_valid() {
    let cert_bundle =
        create_client_cert("TestOrg", "client-001", None).expect("Failed to create client cert");

    let fingerprint = compute_certificate_fingerprint(&cert_bundle.as_rustls_cert())
        .expect("Failed to compute fingerprint");

    // Verify with correct pin
    let pins = vec![fingerprint.clone()];
    let result = verify_certificate_pin(&cert_bundle.as_rustls_cert(), &pins);

    assert!(
        result.is_ok(),
        "Should verify successfully with correct pin"
    );
}

#[test]
fn test_verify_certificate_pin_invalid() {
    let cert_bundle =
        create_client_cert("TestOrg", "client-001", None).expect("Failed to create client cert");

    // Create a wrong pin
    let wrong_pin = vec![0u8; 32];
    let pins = vec![wrong_pin];

    let result = verify_certificate_pin(&cert_bundle.as_rustls_cert(), &pins);

    assert!(result.is_err(), "Should fail with incorrect pin");
}

#[test]
fn test_verify_certificate_pin_multiple_pins() {
    let cert_bundle =
        create_client_cert("TestOrg", "client-001", None).expect("Failed to create client cert");

    let fingerprint = compute_certificate_fingerprint(&cert_bundle.as_rustls_cert())
        .expect("Failed to compute fingerprint");

    // Create multiple pins, correct one in the middle
    let pins = vec![
        vec![0u8; 32],       // Wrong
        fingerprint.clone(), // Correct
        vec![1u8; 32],       // Wrong
    ];

    let result = verify_certificate_pin(&cert_bundle.as_rustls_cert(), &pins);

    assert!(
        result.is_ok(),
        "Should verify successfully when correct pin is among multiple pins"
    );
}

#[test]
fn test_verify_certificate_pin_empty_pins() {
    let cert_bundle =
        create_client_cert("TestOrg", "client-001", None).expect("Failed to create client cert");

    let pins = vec![];
    let result = verify_certificate_pin(&cert_bundle.as_rustls_cert(), &pins);

    assert!(result.is_err(), "Should fail when pin list is empty");
}

#[test]
fn test_certificate_chain_validation() {
    // Create a complete certificate chain
    let (root_ca, intermediate_ca, end_entity) =
        create_cert_chain("TestOrg", false).expect("Failed to create cert chain");

    // Each certificate should have a valid fingerprint
    let root_fp = compute_certificate_fingerprint(&root_ca.as_rustls_cert())
        .expect("Failed to compute root fingerprint");
    let intermediate_fp = compute_certificate_fingerprint(&intermediate_ca.as_rustls_cert())
        .expect("Failed to compute intermediate fingerprint");
    let end_entity_fp = compute_certificate_fingerprint(&end_entity.as_rustls_cert())
        .expect("Failed to compute end entity fingerprint");

    // All fingerprints should be different
    assert_ne!(root_fp, intermediate_fp);
    assert_ne!(root_fp, end_entity_fp);
    assert_ne!(intermediate_fp, end_entity_fp);

    // Each certificate should have a valid organization ID
    let root_org =
        extract_organization_id(&root_ca.as_rustls_cert()).expect("Failed to extract root org");
    let intermediate_org = extract_organization_id(&intermediate_ca.as_rustls_cert())
        .expect("Failed to extract intermediate org");
    let end_entity_org = extract_organization_id(&end_entity.as_rustls_cert())
        .expect("Failed to extract end entity org");

    // All should have the same organization
    assert_eq!(root_org, "TestOrg");
    assert_eq!(intermediate_org, "TestOrg");
    assert_eq!(end_entity_org, "TestOrg");
}

#[test]
fn test_pinning_with_cert_rotation() {
    // Simulate certificate rotation scenario
    let old_cert =
        create_client_cert("TestOrg", "client-001", None).expect("Failed to create old cert");
    let new_cert =
        create_client_cert("TestOrg", "client-001", None).expect("Failed to create new cert");

    let old_pin = compute_certificate_fingerprint(&old_cert.as_rustls_cert())
        .expect("Failed to compute old fingerprint");
    let new_pin = compute_certificate_fingerprint(&new_cert.as_rustls_cert())
        .expect("Failed to compute new fingerprint");

    // During rotation period, both pins should be valid
    let pins = vec![old_pin.clone(), new_pin.clone()];

    let result_old = verify_certificate_pin(&old_cert.as_rustls_cert(), &pins);
    let result_new = verify_certificate_pin(&new_cert.as_rustls_cert(), &pins);

    assert!(
        result_old.is_ok(),
        "Old certificate should verify with both pins"
    );
    assert!(
        result_new.is_ok(),
        "New certificate should verify with both pins"
    );

    // After rotation, only new pin should be valid
    let pins_post_rotation = vec![new_pin.clone()];

    let result_old_post = verify_certificate_pin(&old_cert.as_rustls_cert(), &pins_post_rotation);
    let result_new_post = verify_certificate_pin(&new_cert.as_rustls_cert(), &pins_post_rotation);

    assert!(
        result_old_post.is_err(),
        "Old certificate should fail with only new pin"
    );
    assert!(
        result_new_post.is_ok(),
        "New certificate should verify with new pin"
    );
}

#[test]
fn test_organization_id_extraction_edge_cases() {
    // Test with special characters in organization name
    let special_chars = vec![
        "Test Org With Spaces",
        "Test-Org-With-Dashes",
        "Test_Org_With_Underscores",
        "Test.Org.With.Dots",
        "TestOrg123",
        "123TestOrg",
    ];

    for org_name in special_chars {
        let cert = create_client_cert(org_name, "client-001", None)
            .expect(&format!("Failed to create cert for org: {}", org_name));

        let extracted_org = extract_organization_id(&cert.as_rustls_cert())
            .expect(&format!("Failed to extract org ID for: {}", org_name));

        assert_eq!(extracted_org, org_name, "Organization name mismatch");
    }
}

#[test]
fn test_fingerprint_hex_encoding() {
    let cert = create_client_cert("TestOrg", "client-001", None).expect("Failed to create cert");

    let fingerprint = compute_certificate_fingerprint(&cert.as_rustls_cert())
        .expect("Failed to compute fingerprint");

    // Convert to hex string
    let hex_fingerprint = hex::encode(&fingerprint);

    // Should be 64 hex characters (32 bytes * 2)
    assert_eq!(hex_fingerprint.len(), 64);

    // Should only contain valid hex characters
    assert!(hex_fingerprint.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_certificate_with_no_extensions() {
    // Create a minimal certificate with no extensions
    let mut params = rcgen::CertificateParams::default();
    params
        .distinguished_name
        .push(rcgen::DnType::OrganizationName, "MinimalOrg".to_string());
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "minimal.example.com".to_string());

    let key_pair = rcgen::KeyPair::generate().expect("Failed to generate key pair");
    let certificate = params
        .self_signed(&key_pair)
        .expect("Failed to create certificate");

    let cert_der = certificate.der().to_vec();
    let cert = CertificateDer::from(cert_der);

    // Should still be able to extract organization ID
    let org_id = extract_organization_id(&cert)
        .expect("Failed to extract organization ID from minimal cert");
    assert_eq!(org_id, "MinimalOrg");

    // Should still be able to compute fingerprint
    let fingerprint = compute_certificate_fingerprint(&cert)
        .expect("Failed to compute fingerprint for minimal cert");
    assert_eq!(fingerprint.len(), 32);
}
