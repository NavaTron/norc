use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};

/// Benchmark certificate validation operations
fn bench_certificate_validation(c: &mut Criterion) {
    c.bench_function("certificate_validation", |b| {
        // Mock certificate data
        let cert_data = black_box(vec![0u8; 2048]);

        b.iter(|| {
            // Simulate certificate validation
            let result = cert_data
                .iter()
                .fold(0u32, |acc, &byte| acc.wrapping_add(byte as u32));
            black_box(result);
        });
    });
}

/// Benchmark certificate chain validation with varying chain lengths
fn bench_certificate_chain_validation(c: &mut Criterion) {
    let mut group = c.benchmark_group("certificate_chain");

    for chain_length in [1, 3, 5, 10].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(chain_length),
            chain_length,
            |b, &length| {
                let chains: Vec<Vec<u8>> = (0..length).map(|_| vec![0u8; 2048]).collect();

                b.iter(|| {
                    for chain in &chains {
                        let result = chain
                            .iter()
                            .fold(0u32, |acc, &byte| acc.wrapping_add(byte as u32));
                        black_box(result);
                    }
                });
            },
        );
    }

    group.finish();
}

/// Benchmark revocation checking (OCSP simulation)
fn bench_revocation_check_ocsp(c: &mut Criterion) {
    c.bench_function("revocation_check_ocsp", |b| {
        b.iter(|| {
            // Simulate OCSP request/response parsing
            let request = black_box(vec![0u8; 128]);
            let response = black_box(vec![1u8; 256]);

            let request_hash = request
                .iter()
                .fold(0u32, |acc, &b| acc.wrapping_add(b as u32));
            let response_hash = response
                .iter()
                .fold(0u32, |acc, &b| acc.wrapping_add(b as u32));

            black_box(request_hash ^ response_hash);
        });
    });
}

/// Benchmark revocation checking (CRL simulation)
fn bench_revocation_check_crl(c: &mut Criterion) {
    let mut group = c.benchmark_group("revocation_check_crl");

    for crl_size in [100, 500, 1000, 5000].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(crl_size),
            crl_size,
            |b, &size| {
                // Simulate CRL with list of revoked serial numbers
                let crl: Vec<u64> = (0..size).map(|i| i as u64).collect();
                let target_serial = black_box(size as u64 / 2);

                b.iter(|| {
                    let found = crl.binary_search(&target_serial).is_ok();
                    black_box(found);
                });
            },
        );
    }

    group.finish();
}

/// Benchmark certificate fingerprint calculation
fn bench_fingerprint_calculation(c: &mut Criterion) {
    c.bench_function("fingerprint_calculation", |b| {
        let cert_data = black_box(vec![0u8; 2048]);

        b.iter(|| {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};

            let mut hasher = DefaultHasher::new();
            cert_data.hash(&mut hasher);
            let fingerprint = hasher.finish();
            black_box(fingerprint);
        });
    });
}

criterion_group!(
    benches,
    bench_certificate_validation,
    bench_certificate_chain_validation,
    bench_revocation_check_ocsp,
    bench_revocation_check_crl,
    bench_fingerprint_calculation,
);
criterion_main!(benches);
