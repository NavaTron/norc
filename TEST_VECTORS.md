# NORC Test Vectors
Version: 0.1 Draft
Status: Draft (some cryptographic outputs reference authoritative RFC test vectors)

These vectors exercise: version negotiation, transcript hashing, AAD construction, key derivation & wrapping, message encryption ordering & hash chaining, file manifest protection, device revocation, time synchronization, and replay protection logic.

Sections using well-known primitives (Ed25519 / X25519 / ChaCha20-Poly1305) cite RFC test vectors to avoid transcription errors. Implementers MUST verify against authoritative sources.

Notation:
- hex: lowercase, no 0x prefix
- uuid: canonical lowercase hex (no braces)
- b64url: standard base64url without padding
- || : concatenation
- B3(x): BLAKE3-256 digest of x (hex) (leftmost 32 bytes)
- HKDF-B3(salt, ikm, info, L): HKDF using BLAKE3 as extract/expand hash

## 1. Version Negotiation (AMC)
Input:
- Client supported (ordered preference): ["2.0","1.2","1.1","1.0"]
- Server supported (ordered preference): ["1.2","1.1"]
Expected:
- Highest exact mutual: 1.2
- Negotiated: 1.2
- Downgrade: not detected (1.2 is max mutual)

Input:
- Client: ["2.0","1.2"]
- Server: ["1.0"] (AMC adjacent major: 1.x ↔ 2.x OK)
Expected:
- No exact mutual version string
- Compatible via AMC: choose 2.0? No (server lacks); choose 1.0? Yes, but only if client lists 1.0. Since not listed negotiation fails → {error, no_compatible_version} (client must offer 1.0 to bridge).

Input:
- Client: ["3.0","2.1","2.0"]
- Server: ["1.2","2.0"]
Expected:
- Mutual exact: 2.0
- Negotiated: 2.0
- Chain bridging 3.0↔1.2 blocked (non-adjacent).

## 2. Canonical Serialization Example
Message (JSON debug form before encryption):
```
{
  "type":"auth_request",
  "user_id":"alice@example.org",
  "device_id":"550e8400-e29b-41d4-a716-446655440000",
  "timestamp":1734900000
}
```
Canonical rules: keys sorted (already), numbers base10, no extra whitespace, UTF-8 bytes used directly. Binary variant would follow fixed field order: type, user_id, device_id, timestamp.

## 3. Transcript Hash (Handshake)
Handshake messages (canonical JSON, UTF-8):
1. client_hello: `{"type":"connection_request","client_versions":["1.2","2.0"],"preferred_version":"2.0","capabilities":["messaging","e2ee"]}`
2. server_hello: `{"type":"connection_accepted","negotiated_version":"2.0","server_capabilities":["messaging","e2ee"],"compatibility_mode":false}`
Concatenate (no delimiter). Label: `norc-c-handshake-v1`.
Transcript input: `norc-c-handshake-v1||client_hello||server_hello`.
`transcript_hash = B3(transcript_input)` (compute with implementation; include in AAD; value will depend on BLAKE3—verify with official library).

## 4. AAD Construction Example
Fields:
- proto_major = 2
- proto_minor = 0
- message_type = 0x10 (MSG_MESSAGE_SEND)
- sequence_number = 0000000000000005 (hex)
- message_id = 4d3c2b1a09080706ffeeddccbbaa9988 (UUID bytes) (example)
- ciphertext_length = 00000120 (288 decimal) (big-endian 32-bit)
- prev_message_hash = 32 zero bytes (first in chain) -> 00...00
- transcript_hash = (from section 3) e.g. `TH` placeholder
AAD bytes layout (hex, with TH truncated 32 bytes):
```
02 00 10 00 00 00 00 00 00 00 00 05 4d 3c 2b 1a 09 08 07 06 ff ee dd cc bb aa 99 88 00 00 01 20 00..00 (32) TH(32)
```

## 5. X25519 Key Agreement (Referenced)
Use RFC 7748 test vector:
- Scalar a: a5465cddf38bf3f12fb64cdd5f5d236d0e6f12a52af0a25a27e4b6d1233fa176
- Public key b: e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d1e9bf (concatenated; ensure 32 bytes)
Shared secret (per RFC 7748): c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552
This becomes part of ikm = shared_secret || optional_pq_secret.

## 6. Ed25519 Signature (Referenced)
RFC 8032 test case 1:
- Private: 9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
- Public:  d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
- Message: (empty)
- Signature: e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b

## 7. ChaCha20-Poly1305 Content Encryption (Mapped)
From RFC 8439 Section 2.8.2. Map to NORC fields:
- content_key (32 bytes): 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
- nonce (12 bytes): 000000000000004a00000000 (map to our per-message nonce)
- AAD (example early NORC adaptation) = first 16 bytes of our AAD structure for illustrative mapping (NOT normative) 0200100000000000000000054d3c2b1a
- Plaintext: "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
- Ciphertext+Tag (RFC): 6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d1ae10b594f09e26a7e902ecbd0600691

Implementers MUST recompute using full NORC AAD (Section 6.10 master spec) instead of truncated illustration.

## 8. HKDF-BLAKE3 Master Secret Derivation (Illustrative)
Inputs:
- shared_secret (X25519) = c3da55...8552 (32 bytes)
- optional_pq_secret = (empty for classical suite)
- salt = client_nonce || server_nonce = (12 bytes each concatenated) `6c69656e74636c6e6f6e6365` + `7372766e6f6e63656c69656e74` (ASCII examples) → 24 bytes
- info = negotiated_version || cipher_suite || transcript_hash
  - negotiated_version = "2.0"
  - cipher_suite id (0001) hex: 0001
  - transcript_hash (32 bytes) = TH
Concatenate info: 322e300001TH
Result: master_secret = HKDF-B3(salt, shared_secret, info, 32)
(Compute with BLAKE3-based HKDF; supply hex output when implementation available.)

## 9. Content Key Wrapping
Given:
- content_key = b74f3d0d9a2ebddc14c9e4acd1f2b3a2f1e0d9c8b7a697887766554433221100
- device_id = "alice-device-1"
- message_id = 4d3c2b1a09080706ffeeddccbbaa9988
- ephemeral X25519 key pair & recipient pub produce shared_secret = 11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff
wrap_key = HKDF-B3( salt=B3(content_key)[0..31], ikm=shared_secret, info="norc:wrap:v1"||"2.0"||device_id, 32 )
nonce = first_12_bytes( B3(device_id||message_id) )
wrapped_content_key = AEAD_Seal(wrap_key, nonce, aad=AAD_meta, plaintext=content_key)
(Outputs dependent on BLAKE3 & AEAD implementation.)

## 10. Hash Chain Example
Message 1 ciphertext canonical hash:
- hash1 = B3(ciphertext1) = H1
Message 2 includes prev_message_hash = H1; its own hash2 = B3(ciphertext2) = H2
Replay of message 1 with sequence_number=1 again is rejected (duplicate) even if hash matches.

## 11. Replay Detection Window
Window size = 1024
Accepted so far: sequence 100..120 (current highest=120)
Receiving sequence 119 (duplicate) → reject
Receiving sequence 100 (outside window once head advances beyond 112) → reject
Receiving sequence 121 → accept; bitmap shifts
Receiving sequence 125 before 121..124 present → accept (gap); mark missing 122..124 (optionally request retransmit extension); chain validation fails later if prev_message_hash mismatch.

## 12. File Manifest Encryption
Manifest JSON (pre-encryption canonical):
```
{"file_id":"f-01","filename":"design.pdf","mime":"application/pdf","orig_size":1048576,"sha256":"<hex>","classification":"unclassified"}
```
Pad to 512 bytes (power-of-two bucket after encryption). AEAD encrypt with content_key separate from chunk keys; server sees only file_id and padded length.

## 13. Device Revocation Message
Canonical JSON:
```
{"type":"device_revoke","user_id":"alice@example.org","device_id":"550e8400-e29b-41d4-a716-446655440000","reason":"compromised","effective":1734905000}
```
Signature = Ed25519(user_master_priv, canonical_bytes)
Include revocation in hash-chained audit log (prev_log_hash).

## 14. Time Sync Message
Canonical JSON:
```
{"type":"time_sync","server_time":1734900123,"uncertainty_ms":35,"server_id":"srv1.example.org"}
```
Signature over canonical bytes; client adjusts logical offset if |local - server_time| ≤ (uncertainty_ms + policy_margin).

## 15. Hybrid PQ Suite Placeholder
When suite 0101 selected:
- Collect X25519 shared_secret_X
- Kyber768 encapsulation: ciphertext_K, shared_secret_K (use official Kyber test set) 
- Combined secret = shared_secret_X || shared_secret_K
All subsequent HKDF & wrap steps identical. (Concrete Kyber values omitted until standardized library integrated.)

## 16. Audit Log Hash Chain
Entry i canonical bytes hash_i = B3(hash_{i-1} || canonical_i)
Daily root = hash_last; publish root & retain proofs (siblings) for transparency audit.

## 17. Implementation Checklist
- [ ] Verify version negotiation matches vectors (Section 1)
- [ ] Implement canonical serialization & confirm deterministic bytes (Section 2)
- [ ] Compute transcript hash & store in session state (Section 3)
- [ ] Construct AAD exactly as Section 4, verify length (Section 4)
- [ ] Validate X25519 & Ed25519 primitives match RFC vectors (Sections 5,6)
- [ ] Map ChaCha20-Poly1305 encryption to NORC AAD (Section 7)
- [ ] Implement HKDF-BLAKE3 & verify deterministic output (Section 8)
- [ ] Exercise content key wrapping path (Section 9)
- [ ] Enforce sequence & prev hash checks (Section 10)
- [ ] Execute replay window tests (Section 11)
- [ ] Encrypt file manifests & remove plaintext filename logging (Section 12)
- [ ] Sign & propagate device revocations (Section 13)
- [ ] Process & verify time sync messages (Section 14)
- [ ] Add hybrid suite once PQ libs present (Section 15)
- [ ] Hash-chain audit log (Section 16)

## 18. Generating Missing Cryptographic Outputs
Use reference implementations:
- Ed25519: RFC 8032 test harness
- X25519: RFC 7748 reference
- BLAKE3: Official implementation (https://github.com/BLAKE3-team/BLAKE3)
- ChaCha20-Poly1305: RFC 8439 test code
- Kyber (optional): PQClean / liboqs (when adopted)

## 19. Disclaimer
Some vector outputs referencing BLAKE3, HKDF-B3, and wrapping steps are intentionally left symbolic (e.g., TH, H1) to be filled by deterministic computation in your implementation. This avoids accidental divergence due to manual hashing mistakes. Replace placeholders with concrete hex in a fork-specific finalized test vector file when computed.

---
Document Hash (B3) after finalization: compute & publish.
