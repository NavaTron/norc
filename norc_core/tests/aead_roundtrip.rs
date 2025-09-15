use norc_core::{derive_session_keys, SessionKeys, aead_encrypt, aead_decrypt, AeadDirection};

#[test]
fn aead_roundtrip_basic() {
    let ms = [7u8;32];
    let th = [3u8;32];
    let keys = derive_session_keys(&ms, &th);
    let plaintext = b"hello world";
    let ct = aead_encrypt(AeadDirection::ClientToServer, &keys, 1, plaintext, b"aad").expect("encrypt");
    let pt = aead_decrypt(AeadDirection::ClientToServer, &keys, 1, &ct, b"aad").expect("decrypt");
    assert_eq!(pt, plaintext);
}
