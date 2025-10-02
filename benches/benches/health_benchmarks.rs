use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use norc_transport::health::{ComponentHealth, HealthCheck, HealthStatus};
use std::time::Duration;

/// Benchmark health check creation and evaluation
fn bench_health_check_creation(c: &mut Criterion) {
    c.bench_function("health_check_creation", |b| {
        b.iter(|| {
            let health = HealthCheck::new(
                black_box("test_component"),
                black_box(HealthStatus::Healthy),
            );
            black_box(health);
        });
    });
}

/// Benchmark component health status checks
fn bench_component_health(c: &mut Criterion) {
    let mut group = c.benchmark_group("component_health");

    for size in [10, 50, 100, 500].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            let components: Vec<ComponentHealth> = (0..size)
                .map(|i| ComponentHealth {
                    component: format!("component_{}", i),
                    status: HealthStatus::Healthy,
                    message: format!("Component {} is healthy", i),
                    details: None,
                })
                .collect();

            b.iter(|| {
                let total_healthy = components
                    .iter()
                    .filter(|c| matches!(c.status, HealthStatus::Healthy))
                    .count();
                black_box(total_healthy);
            });
        });
    }

    group.finish();
}

/// Benchmark health status transitions
fn bench_health_status_transition(c: &mut Criterion) {
    c.bench_function("health_status_transition", |b| {
        let mut health = HealthCheck::new("component", HealthStatus::Healthy);

        b.iter(|| {
            health.status = black_box(HealthStatus::Degraded);
            health.status = black_box(HealthStatus::Healthy);
            black_box(&health);
        });
    });
}

/// Benchmark concurrent health checks
fn bench_concurrent_health_checks(c: &mut Criterion) {
    c.bench_function("concurrent_health_checks", |b| {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let counter = Arc::new(AtomicUsize::new(0));

        b.iter(|| {
            let handles: Vec<_> = (0..10)
                .map(|_| {
                    let counter = counter.clone();
                    std::thread::spawn(move || {
                        let health = HealthCheck::new("component", HealthStatus::Healthy);
                        counter.fetch_add(1, Ordering::Relaxed);
                        black_box(health);
                    })
                })
                .collect();

            for handle in handles {
                handle.join().unwrap();
            }
        });
    });
}

criterion_group!(
    benches,
    bench_health_check_creation,
    bench_component_health,
    bench_health_status_transition,
    bench_concurrent_health_checks,
);
criterion_main!(benches);
