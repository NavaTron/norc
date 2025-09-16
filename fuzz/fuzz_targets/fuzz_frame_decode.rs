#![no_main]
use libfuzzer_sys::fuzz_target;
use navatron_protocol::wire::WireFormat;

fuzz_target!(|data: &[u8]| {
    // Attempt to decode arbitrary bytes as a frame sequence.
    // TODO: integrate proper frame decoder once implemented.
    let _ = WireFormat::decode(data);
});
