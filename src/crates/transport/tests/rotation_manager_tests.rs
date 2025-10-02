//! Comprehensive test suite for CertificateRotationManager
//! Tests file modification detection, automatic reload, manual reload,
//! cooldown periods, watch channel notifications, concurrent access,
//! error recovery, and thread safety.
//!
//! Requirements: T-S-F-04.01.02.03 (Automatic key rotation)

use norc_transport::rotation_manager::{CertificateBundle, RotationConfig, RotationManagerBuilder};
use std::sync::Arc;
use std::time::Duration;
use tokio::fs;
use tokio::time::{sleep, timeout};

mod common;
use common::test_certs::{create_server_cert, write_cert_to_temp_files};

// ============================================================================
// Test Helper Functions
// ============================================================================

/// Create a temporary certificate and key file
async fn create_temp_cert_files() -> (String, String) {
    let cert_bundle = create_server_cert("TestOrg", "test.example.com", None)
        .expect("Failed to create test certificate");

    let (cert_file, key_file) =
        write_cert_to_temp_files(&cert_bundle).expect("Failed to write cert to temp files");

    // Convert NamedTempFile to path strings and leak to keep files alive
    let cert_path = cert_file.path().to_str().unwrap().to_string();
    let key_path = key_file.path().to_str().unwrap().to_string();

    // Keep files alive by leaking
    std::mem::forget(cert_file);
    std::mem::forget(key_file);

    (cert_path, key_path)
}

/// Write new certificate content to files (simulating rotation)
async fn rotate_cert_files(cert_path: &str, key_path: &str) {
    let new_cert_bundle = create_server_cert("RotatedOrg", "rotated.example.com", None)
        .expect("Failed to create rotated certificate");

    // Write new certificate
    fs::write(cert_path, &new_cert_bundle.cert_pem)
        .await
        .expect("Failed to write rotated cert");

    // Write new key
    fs::write(key_path, &new_cert_bundle.key_pem)
        .await
        .expect("Failed to write rotated key");

    // Give filesystem time to update metadata
    sleep(Duration::from_millis(100)).await;
}

// ============================================================================
// Configuration Tests
// ============================================================================

#[tokio::test]
async fn test_rotation_config_default() {
    let config = RotationConfig::default();

    assert_eq!(config.check_interval, Duration::from_secs(300));
    assert!(config.auto_reload);
    assert_eq!(config.reload_cooldown, Duration::from_secs(10));
}

#[tokio::test]
async fn test_rotation_config_custom() {
    let config = RotationConfig {
        check_interval: Duration::from_secs(60),
        auto_reload: false,
        reload_cooldown: Duration::from_secs(5),
    };

    assert_eq!(config.check_interval, Duration::from_secs(60));
    assert!(!config.auto_reload);
    assert_eq!(config.reload_cooldown, Duration::from_secs(5));
}

// ============================================================================
// CertificateBundle Tests
// ============================================================================

#[tokio::test]
async fn test_certificate_bundle_load() {
    let (cert_path, key_path) = create_temp_cert_files().await;

    let bundle = CertificateBundle::load(&cert_path, &key_path)
        .await
        .expect("Failed to load certificate bundle");

    assert!(
        !bundle.certs.is_empty(),
        "Certificate chain should not be empty"
    );
    assert_eq!(bundle.cert_path.to_str().unwrap(), cert_path);
    assert_eq!(bundle.key_path.to_str().unwrap(), key_path);

    // Bundle age should be very small (just loaded)
    assert!(bundle.age() < Duration::from_secs(1));
}

#[tokio::test]
async fn test_certificate_bundle_reload() {
    let (cert_path, key_path) = create_temp_cert_files().await;

    let mut bundle = CertificateBundle::load(&cert_path, &key_path)
        .await
        .expect("Failed to load certificate bundle");

    let original_loaded_at = bundle.loaded_at;

    // Wait a bit and then reload
    sleep(Duration::from_millis(100)).await;

    // Rotate the certificates
    rotate_cert_files(&cert_path, &key_path).await;

    bundle.reload().await.expect("Failed to reload bundle");

    // loaded_at should be updated
    assert!(
        bundle.loaded_at > original_loaded_at,
        "loaded_at should be updated after reload"
    );
    assert!(
        bundle.age() < Duration::from_secs(1),
        "Bundle age should be small after reload"
    );
}

#[tokio::test]
async fn test_certificate_bundle_age() {
    let (cert_path, key_path) = create_temp_cert_files().await;

    let bundle = CertificateBundle::load(&cert_path, &key_path)
        .await
        .expect("Failed to load certificate bundle");

    // Age should be very small initially
    let initial_age = bundle.age();
    assert!(initial_age < Duration::from_secs(1));

    // Wait a bit
    sleep(Duration::from_millis(200)).await;

    // Age should have increased
    let new_age = bundle.age();
    assert!(
        new_age > initial_age,
        "Bundle age should increase over time"
    );
    assert!(
        new_age >= Duration::from_millis(200),
        "Age should reflect elapsed time"
    );
}

// ============================================================================
// Builder Tests
// ============================================================================

#[tokio::test]
async fn test_builder_basic() {
    let (cert_path, key_path) = create_temp_cert_files().await;

    let manager = RotationManagerBuilder::new()
        .cert_path(&cert_path)
        .key_path(&key_path)
        .build()
        .await
        .expect("Failed to build rotation manager");

    let bundle = manager.current_bundle().await;
    assert!(!bundle.certs.is_empty());
}

#[tokio::test]
async fn test_builder_with_custom_config() {
    let (cert_path, key_path) = create_temp_cert_files().await;

    let config = RotationConfig {
        check_interval: Duration::from_secs(30),
        auto_reload: false,
        reload_cooldown: Duration::from_secs(5),
    };

    let manager = RotationManagerBuilder::new()
        .cert_path(&cert_path)
        .key_path(&key_path)
        .config(config.clone())
        .build()
        .await
        .expect("Failed to build rotation manager");

    // Manager built successfully with custom config
    let bundle = manager.current_bundle().await;
    assert!(!bundle.certs.is_empty());
}

#[tokio::test]
async fn test_builder_fluent_api() {
    let (cert_path, key_path) = create_temp_cert_files().await;

    let manager = RotationManagerBuilder::new()
        .cert_path(&cert_path)
        .key_path(&key_path)
        .check_interval(Duration::from_secs(45))
        .auto_reload(false)
        .reload_cooldown(Duration::from_secs(3))
        .build()
        .await
        .expect("Failed to build rotation manager");

    // Manager built successfully with fluent API
    let bundle = manager.current_bundle().await;
    assert!(!bundle.certs.is_empty());
}

#[tokio::test]
async fn test_builder_missing_cert_path() {
    let (_cert_path, key_path) = create_temp_cert_files().await;

    let result = RotationManagerBuilder::new()
        .key_path(&key_path)
        .build()
        .await;

    assert!(result.is_err(), "Builder should fail without cert_path");
    let err_msg = result.err().unwrap().to_string();
    assert!(
        err_msg.contains("Certificate path"),
        "Error should mention certificate path: {}",
        err_msg
    );
}

#[tokio::test]
async fn test_builder_missing_key_path() {
    let (cert_path, _key_path) = create_temp_cert_files().await;

    let result = RotationManagerBuilder::new()
        .cert_path(&cert_path)
        .build()
        .await;

    assert!(result.is_err(), "Builder should fail without key_path");
    let err_msg = result.err().unwrap().to_string();
    assert!(
        err_msg.contains("Key path"),
        "Error should mention key path: {}",
        err_msg
    );
}

// ============================================================================
// Manual Reload Tests
// ============================================================================

#[tokio::test]
async fn test_manual_reload_basic() {
    let (cert_path, key_path) = create_temp_cert_files().await;

    let manager = RotationManagerBuilder::new()
        .cert_path(&cert_path)
        .key_path(&key_path)
        .reload_cooldown(Duration::from_millis(100))
        .build()
        .await
        .expect("Failed to build rotation manager");

    let original_bundle = manager.current_bundle().await;
    let original_loaded_at = original_bundle.loaded_at;

    // Rotate certificates
    sleep(Duration::from_millis(150)).await;
    rotate_cert_files(&cert_path, &key_path).await;

    // Manual reload
    manager.reload().await.expect("Failed to reload");

    let new_bundle = manager.current_bundle().await;
    assert!(
        new_bundle.loaded_at > original_loaded_at,
        "Bundle should be reloaded"
    );
}

#[tokio::test]
async fn test_manual_reload_cooldown_enforcement() {
    let (cert_path, key_path) = create_temp_cert_files().await;

    let manager = RotationManagerBuilder::new()
        .cert_path(&cert_path)
        .key_path(&key_path)
        .reload_cooldown(Duration::from_secs(2))
        .build()
        .await
        .expect("Failed to build rotation manager");

    // First reload should succeed
    manager.reload().await.expect("First reload should succeed");

    let bundle_after_first = manager.current_bundle().await;
    let loaded_at_after_first = bundle_after_first.loaded_at;

    // Immediate second reload should be blocked by cooldown
    manager
        .reload()
        .await
        .expect("Second reload should not error");

    let bundle_after_second = manager.current_bundle().await;
    assert_eq!(
        bundle_after_second.loaded_at, loaded_at_after_first,
        "Bundle should not be reloaded during cooldown period"
    );

    // Wait for cooldown to expire
    sleep(Duration::from_millis(2100)).await;

    // Third reload should succeed
    rotate_cert_files(&cert_path, &key_path).await;
    manager.reload().await.expect("Third reload should succeed");

    let bundle_after_third = manager.current_bundle().await;
    assert!(
        bundle_after_third.loaded_at > loaded_at_after_first,
        "Bundle should be reloaded after cooldown expires"
    );
}

#[tokio::test]
async fn test_manual_reload_multiple_times() {
    let (cert_path, key_path) = create_temp_cert_files().await;

    let manager = RotationManagerBuilder::new()
        .cert_path(&cert_path)
        .key_path(&key_path)
        .reload_cooldown(Duration::from_millis(100))
        .build()
        .await
        .expect("Failed to build rotation manager");

    let mut previous_loaded_at = manager.current_bundle().await.loaded_at;

    // Perform multiple reloads
    for _ in 0..3 {
        sleep(Duration::from_millis(150)).await;
        rotate_cert_files(&cert_path, &key_path).await;

        manager.reload().await.expect("Reload should succeed");

        let current_loaded_at = manager.current_bundle().await.loaded_at;
        assert!(
            current_loaded_at > previous_loaded_at,
            "Each reload should update loaded_at"
        );
        previous_loaded_at = current_loaded_at;
    }
}

// ============================================================================
// Watch Channel Notification Tests
// ============================================================================

#[tokio::test]
async fn test_subscribe_receives_notifications() {
    let (cert_path, key_path) = create_temp_cert_files().await;

    let manager = RotationManagerBuilder::new()
        .cert_path(&cert_path)
        .key_path(&key_path)
        .reload_cooldown(Duration::from_millis(100))
        .build()
        .await
        .expect("Failed to build rotation manager");

    let mut rx = manager.subscribe();

    // Get initial value
    let initial_bundle = rx.borrow().clone();
    let initial_loaded_at = initial_bundle.loaded_at;

    // Trigger reload
    sleep(Duration::from_millis(150)).await;
    rotate_cert_files(&cert_path, &key_path).await;
    manager.reload().await.expect("Reload should succeed");

    // Wait for notification
    timeout(Duration::from_secs(1), rx.changed())
        .await
        .expect("Should receive notification within timeout")
        .expect("Channel should not be closed");

    let new_bundle = rx.borrow().clone();
    assert!(
        new_bundle.loaded_at > initial_loaded_at,
        "Notification should contain updated bundle"
    );
}

#[tokio::test]
async fn test_multiple_subscribers() {
    let (cert_path, key_path) = create_temp_cert_files().await;

    let manager = RotationManagerBuilder::new()
        .cert_path(&cert_path)
        .key_path(&key_path)
        .reload_cooldown(Duration::from_millis(100))
        .build()
        .await
        .expect("Failed to build rotation manager");

    let mut rx1 = manager.subscribe();
    let mut rx2 = manager.subscribe();
    let mut rx3 = manager.subscribe();

    // Trigger reload
    sleep(Duration::from_millis(150)).await;
    rotate_cert_files(&cert_path, &key_path).await;
    manager.reload().await.expect("Reload should succeed");

    // All subscribers should receive notification
    timeout(Duration::from_secs(1), rx1.changed())
        .await
        .expect("rx1 should receive notification")
        .expect("Channel should not be closed");

    timeout(Duration::from_secs(1), rx2.changed())
        .await
        .expect("rx2 should receive notification")
        .expect("Channel should not be closed");

    timeout(Duration::from_secs(1), rx3.changed())
        .await
        .expect("rx3 should receive notification")
        .expect("Channel should not be closed");
}

// ============================================================================
// Concurrent Access Tests
// ============================================================================

#[tokio::test]
async fn test_concurrent_bundle_access() {
    let (cert_path, key_path) = create_temp_cert_files().await;

    let manager = RotationManagerBuilder::new()
        .cert_path(&cert_path)
        .key_path(&key_path)
        .build()
        .await
        .expect("Failed to build rotation manager");

    let manager = Arc::new(manager);

    // Spawn multiple tasks that access the bundle concurrently
    let mut handles = vec![];
    for _ in 0..10 {
        let mgr = manager.clone();
        let handle = tokio::spawn(async move {
            for _ in 0..5 {
                let bundle = mgr.current_bundle().await;
                assert!(!bundle.certs.is_empty());
                sleep(Duration::from_millis(10)).await;
            }
        });
        handles.push(handle);
    }

    // Wait for all tasks to complete
    for handle in handles {
        handle.await.expect("Task should complete successfully");
    }
}

#[tokio::test]
async fn test_concurrent_reload_and_access() {
    let (cert_path, key_path) = create_temp_cert_files().await;

    let manager = RotationManagerBuilder::new()
        .cert_path(&cert_path)
        .key_path(&key_path)
        .reload_cooldown(Duration::from_millis(50))
        .build()
        .await
        .expect("Failed to build rotation manager");

    let manager = Arc::new(manager);

    // Spawn reader tasks
    let mut handles = vec![];
    for _ in 0..5 {
        let mgr = manager.clone();
        let handle = tokio::spawn(async move {
            for _ in 0..10 {
                let bundle = mgr.current_bundle().await;
                assert!(!bundle.certs.is_empty());
                sleep(Duration::from_millis(20)).await;
            }
        });
        handles.push(handle);
    }

    // Spawn reload task
    let mgr = manager.clone();
    let cert_path_clone = cert_path.clone();
    let key_path_clone = key_path.clone();
    let reload_handle = tokio::spawn(async move {
        for _ in 0..3 {
            sleep(Duration::from_millis(100)).await;
            rotate_cert_files(&cert_path_clone, &key_path_clone).await;
            mgr.reload().await.ok(); // Ignore cooldown errors
        }
    });
    handles.push(reload_handle);

    // Wait for all tasks to complete
    for handle in handles {
        handle.await.expect("Task should complete successfully");
    }
}

// ============================================================================
// Error Handling Tests
// ============================================================================

#[tokio::test]
async fn test_load_nonexistent_cert_file() {
    let result = CertificateBundle::load("/nonexistent/cert.pem", "/nonexistent/key.pem").await;

    assert!(result.is_err(), "Loading nonexistent files should fail");
}

#[tokio::test]
async fn test_reload_after_file_deletion() {
    let (cert_path, key_path) = create_temp_cert_files().await;

    let manager = RotationManagerBuilder::new()
        .cert_path(&cert_path)
        .key_path(&key_path)
        .reload_cooldown(Duration::from_millis(100))
        .build()
        .await
        .expect("Failed to build rotation manager");

    // Delete certificate file
    fs::remove_file(&cert_path)
        .await
        .expect("Failed to delete cert file");

    sleep(Duration::from_millis(150)).await;

    // Reload should fail
    let result = manager.reload().await;
    assert!(
        result.is_err(),
        "Reload should fail when cert file is deleted"
    );
}

#[tokio::test]
async fn test_reload_with_invalid_cert_content() {
    let (cert_path, key_path) = create_temp_cert_files().await;

    let manager = RotationManagerBuilder::new()
        .cert_path(&cert_path)
        .key_path(&key_path)
        .reload_cooldown(Duration::from_millis(100))
        .build()
        .await
        .expect("Failed to build rotation manager");

    // Write invalid content to cert file
    sleep(Duration::from_millis(150)).await;
    fs::write(&cert_path, b"invalid certificate content")
        .await
        .expect("Failed to write invalid content");

    // Reload should fail
    let result = manager.reload().await;
    assert!(
        result.is_err(),
        "Reload should fail with invalid cert content"
    );
}

// ============================================================================
// Current Bundle Tests
// ============================================================================

#[tokio::test]
async fn test_current_bundle_returns_latest() {
    let (cert_path, key_path) = create_temp_cert_files().await;

    let manager = RotationManagerBuilder::new()
        .cert_path(&cert_path)
        .key_path(&key_path)
        .reload_cooldown(Duration::from_millis(100))
        .build()
        .await
        .expect("Failed to build rotation manager");

    let bundle1 = manager.current_bundle().await;
    let loaded_at1 = bundle1.loaded_at;

    // Reload
    sleep(Duration::from_millis(150)).await;
    rotate_cert_files(&cert_path, &key_path).await;
    manager.reload().await.expect("Reload should succeed");

    let bundle2 = manager.current_bundle().await;
    let loaded_at2 = bundle2.loaded_at;

    assert!(
        loaded_at2 > loaded_at1,
        "current_bundle should return the latest bundle"
    );
}

#[tokio::test]
async fn test_current_bundle_concurrent_calls() {
    let (cert_path, key_path) = create_temp_cert_files().await;

    let manager = RotationManagerBuilder::new()
        .cert_path(&cert_path)
        .key_path(&key_path)
        .build()
        .await
        .expect("Failed to build rotation manager");

    let manager = Arc::new(manager);

    // Call current_bundle from multiple tasks simultaneously
    let handles: Vec<_> = (0..20)
        .map(|_| {
            let mgr = manager.clone();
            tokio::spawn(async move { mgr.current_bundle().await })
        })
        .collect();

    // All should succeed and return valid bundles
    for handle in handles {
        let bundle = handle.await.expect("Task should complete");
        assert!(!bundle.certs.is_empty());
    }
}

// ============================================================================
// Thread Safety Tests
// ============================================================================

#[tokio::test]
async fn test_thread_safety_with_std_threads() {
    let (cert_path, key_path) = create_temp_cert_files().await;

    let manager = RotationManagerBuilder::new()
        .cert_path(&cert_path)
        .key_path(&key_path)
        .reload_cooldown(Duration::from_millis(100))
        .build()
        .await
        .expect("Failed to build rotation manager");

    let manager = Arc::new(manager);

    // Spawn multiple OS threads
    let mut handles = vec![];
    for i in 0..5 {
        let mgr = manager.clone();
        let handle = std::thread::spawn(move || {
            let runtime = tokio::runtime::Runtime::new().unwrap();
            runtime.block_on(async move {
                for _ in 0..10 {
                    let bundle = mgr.current_bundle().await;
                    assert!(
                        !bundle.certs.is_empty(),
                        "Thread {} should get valid bundle",
                        i
                    );
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            });
        });
        handles.push(handle);
    }

    // Wait for all threads
    for handle in handles {
        handle.join().expect("Thread should complete successfully");
    }
}

#[tokio::test]
async fn test_no_data_races_with_reload() {
    let (cert_path, key_path) = create_temp_cert_files().await;

    let manager = RotationManagerBuilder::new()
        .cert_path(&cert_path)
        .key_path(&key_path)
        .reload_cooldown(Duration::from_millis(50))
        .build()
        .await
        .expect("Failed to build rotation manager");

    let manager = Arc::new(manager);

    // Reader threads
    let mut handles = vec![];
    for _ in 0..10 {
        let mgr = manager.clone();
        let handle = tokio::spawn(async move {
            for _ in 0..20 {
                let bundle = mgr.current_bundle().await;
                let age = bundle.age();
                // Verify bundle is consistent
                assert!(!bundle.certs.is_empty());
                assert!(age < Duration::from_secs(10)); // Reasonable age
            }
        });
        handles.push(handle);
    }

    // Reloader threads
    for _ in 0..3 {
        let mgr = manager.clone();
        let cp = cert_path.clone();
        let kp = key_path.clone();
        let handle = tokio::spawn(async move {
            for _ in 0..5 {
                sleep(Duration::from_millis(100)).await;
                rotate_cert_files(&cp, &kp).await;
                mgr.reload().await.ok();
            }
        });
        handles.push(handle);
    }

    // Wait for all
    for handle in handles {
        handle.await.expect("Task should complete without panics");
    }
}
