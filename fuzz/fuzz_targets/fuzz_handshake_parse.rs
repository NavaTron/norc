#![no_main]
use libfuzzer_sys::fuzz_target;
use navatron_protocol::handshake::*;

fuzz_target!(|data: &[u8]| {
    // Simplistic: treat arbitrary data as potential handshake message payloads
    // Future: parse structured enums once binary layout is finalized.
    if data.len() > 4 { let _ = HandshakeState::try_from(data[0] % 3); }
});
