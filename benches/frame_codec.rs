use criterion::{criterion_group, criterion_main, Criterion, black_box};
use navatron_protocol::messages::{NorcMessage, Message, MessageType};
use navatron_protocol::{Version};
use std::collections::HashMap;

fn bench_frame_encode(c: &mut Criterion) {
    let version = Version::new(1,0).unwrap();
    let msg = NorcMessage::new(
        version,
        MessageType::Error,
        1,
        [0u8;32],
        Message::Error(navatron_protocol::messages::ErrorMessage{
            error_code: 1,
            error_category: "bench".into(),
            message: "benchmark".into(),
            retry_after_secs: None,
            details: HashMap::new(),
        })
    );
    c.bench_function("encode_message", |b| {
        b.iter(|| {
            let encoded = msg.encode().unwrap();
            black_box(encoded);
        });
    });
}

criterion_group!(codec, bench_frame_encode);
criterion_main!(codec);
