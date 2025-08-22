# NORC Security & Threat Model (Academic Revision)

Version: 1.1 (Aligned with Protocol Specification 1.1)  
Status: Draft for Peer Review

This revision introduces formal mapping to academic and standards references ([1]–[14] in `REFERENCES.md`), clarifies Key Compromise Impersonation (KCI) and Unknown Key Share (UKS) resistance, and adds guidance for optional Post‑Compromise Security (PCS) via a symmetric ratchet. Hybrid post‑quantum key establishment rationale is updated per NIST PQC selections ([5][13]).

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
All negotiation messages are canonically serialized; transcript hash `th` binds their ordered, byte‑exact encodings (cf. TLS 1.3 transcript binding [4][12]). Master secret derived via HKDF-BLAKE3 over classical ECDH (X25519) concatenated with optional PQ KEM secret (Kyber) ([5][13]). Highest mutual version & suite enforcement yields downgrade resistance. Any attempt to alter ordering or remove higher precedence options MUST abort.

## 7. Replay & Ordering Defense
- Per‑session `sequence_number` (random 24‑bit offset start)
- Sliding window (≥1024; ≥4096 for federation as of v1.1 enhancement)
- `prev_message_hash` chain (BLAKE3-256) forming linear hash chain
- Federation relay cache (TTL ≥10m, ≤24h)
- Timestamp skew bound (≤300s clients, ≤60s federation) unless hash chain continuity justifies acceptance

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
Cipher suite registry; negotiation selects highest mutual; transcript binds ordered lists. Hybrid PQ suites concatenate classical + PQ shared secrets before HKDF (ordering fixed: classical || PQ). Domain separation labels `norc:*` REQUIRED for all HKDF contexts (new normative requirement v1.1) ([3][4]).

## 11. Privacy & Metadata Minimization
Encrypted file manifest conceals filenames/MIME/true size; padding to power‑of‑two buckets ≤64KB. Optional adaptive padding (probabilistic multiplier set) further reduces deterministic size leakage ([6]). Batched ACKs; random presence jitter 0–3s; generic errors prevent enumeration.

## 12. Rate Limiting (Baseline)
Messages 60/min (burst 120); key lookups 30/min; registrations 3/hour; federation 1000 msgs/min & 100MB/5min/remote. Exceed → ERR_RATE_LIMIT (retry_after).

## 13. Time Sync
Signed time_sync messages supply server time & uncertainty; never adjust system clock—store offset; rely on authenticated NTP/Roughtime server side.

## 14. Audit Integrity
Hash chain (Merkle-like) over canonical entries; daily root hash publication recommended. No plaintext message content; user IDs HMAC pseudonymized.

## 15. Supply Chain Attestation
Build attestation & SBOM hashes optionally advertised; clients enforce policy where mandated (e.g., gov/defense deployments).

## 16. Threat Mitigations Matrix (Updated v1.1)
| Threat | Primary Mitigation | References |
|--------|--------------------|------------|
| Network replay | Sequence window + hash chain + relay cache | [3][4] |
| Downgrade | Transcript binding + ordered list hash | [4][12] |
| Key compromise (device) | Rotation + revocation + optional PCS ratchet | [1][7] |
| KCI attack | Identity + ephemeral binding in transcript | [7][8] |
| UKS attack | Explicit peer identity in canonical forms | [8][9] |
| Metadata leakage (files) | Encrypted manifest + length padding | Section 11 |
| Harvest-now, decrypt-later | Hybrid KEM (Kyber) concatenation | [5][13] |
| Log tampering | Hash-chained audit roots + optional publication | [14] |
| Traffic analysis (size) | Power-of-two + adaptive probabilistic padding | [6] |

## 17. Residual Risks
- Traffic analysis (size/timing patterns) partially mitigated only
- Compromised endpoints can exfiltrate plaintext before encryption
- Federation trust misconfiguration could broaden metadata exposure
- PQ algorithms future cryptanalysis risk (monitor standards updates)

## 18. Migration Guidance (1.0 → 1.1)
1. Enforce domain separation labels for all HKDF invocations (`norc:*`).
2. Increase federation replay window to ≥4096 entries.
3. Integrate hybrid PQ suites (classical || PQ) with strict abort on PQ failure (no silent downgrade).
4. Optional: Deploy PCS ratchet for high classification conversations.
5. Adopt adaptive padding strategy once performance overhead assessed.
6. Begin daily publication of audit root hashes (transparency).

## 19. Future Work
- Group messaging tree-based key management (MLS-like) integration
- Full PQ signature agility (Dilithium/Falcon) once standardized
- Adaptive padding strategies (cover traffic)
- Automated policy-driven trust revalidation

---
Document Hash (BLAKE3): TBD (compute post‑publication)
