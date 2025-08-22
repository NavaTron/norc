# NORC Security & Threat Model

Version: 1.0 (Aligned with Protocol Specification 1.0 + Security Enhancements Draft)
Status: Draft

---
## 1. Scope
This document consolidates the NORC protocol suite security objectives, threat analysis, cryptographic design rationale, and forward-compatible enhancement roadmap. It is normative where explicitly stated (MUST / SHOULD) and informational otherwise.

## 2. Assets
| Asset | Description | Desired Properties |
|-------|-------------|--------------------|
| Message Content | End-to-end encrypted payloads | Confidentiality, Integrity, FS, PQ-FS (opt) |
| Metadata Minimization | Absence of plaintext filenames, minimized routing data | Unlinkability (best-effort), Non-exfiltration |
| Device Keys | Long-term identity (Ed25519) | AuthN, Non-forgeability, Controlled lifecycle |
| Session Keys | Ephemeral conversation/call keys | Forward secrecy, Replay resistance |
| Trust Certificates | Inter-server trust assertions | Authenticity, Revocability, Auditability |
| Audit Logs | Security & compliance events | Integrity, Non-repudiation (opt), Minimal exposure |
| Version/Cipher Negotiation | Handshake parameters | Downgrade resistance |
| Presence Privacy | User availability granularity | Controlled disclosure, Anti-enumeration |
| File Metadata | Filenames, MIME types, size | Confidentiality, Padding |

## 3. Adversaries & Capabilities
| Adversary | Capabilities | Examples |
|-----------|-------------|----------|
| Network Attacker | Packet capture, injection, reordering, delay | MITM, Replay, Downgrade |
| Malicious Federation Server | Access to relayed ciphertext, timing, limited routing metadata | Content correlation, Replay attempts |
| Compromised Device | Legitimate keys, message visibility for owner | Malicious insider |
| Log/Audit Insider | Read server logs/audit DB | Metadata mining |
| Future Quantum Adversary | Record today, break ECDH/Sig later | Harvest-now, decrypt-later |

## 4. Security Goals
MUST: Confidentiality, Integrity, Forward Secrecy, Replay Protection, Downgrade Resistance, Key Lifecycle Control, Minimal Metadata Leakage, Authentic Revocation, Audit Integrity.
SHOULD: PQ Hybrid Support, Traffic Shaping, Supply Chain Attestation, Ordering Detection.
MAY: Deniability (disabled when compliance mode active), Advanced Anonymity.

## 5. Cryptographic Stack Rationale
| Primitive | Choice | Reason |
|----------|-------|--------|
| Signatures | Ed25519 | Fast, small, widely reviewed |
| KEM/ECDH | X25519 (+ Kyber hybrid optional) | Modern DH, constant-time, PQ extension path |
| AEAD | ChaCha20-Poly1305 (AES-256-GCM FIPS alt) | High performance on software, well studied |
| Hash/KDF | BLAKE3 (SHA-256 FIPS alt) | Speed, tree hashing, extensibility |
| HKDF | HKDF-BLAKE3 | Simplified context separation |

## 6. Handshake & Transcript Binding
All negotiation messages are canonically serialized; transcript hash binds ordered messages + advertised version/cipher lists. Master secret derived via HKDF-BLAKE3 over (ECDH || optional PQ secret). Enforces highest mutual version & suite (AMC). Downgrade attempt => abort.

## 7. Replay & Ordering Defense
- Per-session sequence_number, random offset
- Sliding window (≥1024)
- prev_message_hash chain (BLAKE3-256)
- Federation relay cache (TTL >=10m, ≤24h)
- Timestamp skew bound (≤300s clients, ≤60s federation) unless chain continuity proves legitimacy

## 8. AEAD AAD Schema
```
struct AAD_v1 {
  uint8  proto_major;
  uint8  proto_minor;
  uint8  message_type;
  uint64 sequence_number;
  uint128 message_id;
  uint32 ciphertext_length;
  bytes32 prev_message_hash;
  bytes32 transcript_hash;
}
```
Mismatch => discard silently + increment local error counters.

## 9. Key Lifecycle
Creation local; rotation ≤180d; revocation via signed device_revoke; overlap window for dual addressing. Escrow optional (passphrase wrapped). Session keys ephemeral; per-message content keys random & wrapped per recipient.

## 10. Algorithm Agility
Cipher suite registry; negotiation selects highest mutual; transcript binds lists. Hybrid PQ suites concatenate classical + PQ shared secrets before HKDF.

## 11. Privacy & Metadata Minimization
Encrypted file manifest conceals filenames/MIME/true size; padding to power-of-two buckets ≤64KB; batched ACKs; random presence jitter 0–3s; generic errors prevent enumeration.

## 12. Rate Limiting (Baseline)
Messages 60/min (burst 120); key lookups 30/min; registrations 3/hour; federation 1000 msgs/min & 100MB/5min/remote. Exceed → ERR_RATE_LIMIT (retry_after).

## 13. Time Sync
Signed time_sync messages supply server time & uncertainty; never adjust system clock—store offset; rely on authenticated NTP/Roughtime server side.

## 14. Audit Integrity
Hash chain (Merkle-like) over canonical entries; daily root hash publication recommended. No plaintext message content; user IDs HMAC pseudonymized.

## 15. Supply Chain Attestation
Build attestation & SBOM hashes optionally advertised; clients enforce policy where mandated (e.g., gov/defense deployments).

## 16. Threat Mitigations Matrix
| Threat | Mitigation |
|--------|-----------|
| Network replay | Sequence numbers + sliding window + timestamps + hash chain |
| Downgrade | Transcript binding + highest mutual enforcement |
| Key compromise (device) | Rotation policy + revocation broadcast |
| Metadata leakage (file) | Encrypted manifest + padding |
| Harvest-now, decrypt-later | Optional Kyber hybrid suites |
| Log tampering | Hash-chained audit log roots |

## 17. Residual Risks
- Traffic analysis (size/timing patterns) partially mitigated only
- Compromised endpoints can exfiltrate plaintext before encryption
- Federation trust misconfiguration could broaden metadata exposure
- PQ algorithms future cryptanalysis risk (monitor standards updates)

## 18. Migration Guidance
1. Enable optional tracking of sequence numbers & prev_message_hash (tolerate absence)
2. Adopt encrypted file manifests; cease logging filenames
3. Implement transcript hashing before rolling out stricter downgrade aborts
4. Introduce hybrid suites behind feature flag; monitor performance
5. Begin publishing daily audit log root hashes

## 19. Future Work
- Group messaging tree-based key management (MLS-like) integration
- Full PQ signature agility (Dilithium/Falcon) once standardized
- Adaptive padding strategies (cover traffic)
- Automated policy-driven trust revalidation

---
Document Hash (BLAKE3): TBD (compute post-publication)
