# NORC Protocol Requirements (requirements.md)

Version: 1.0.0
Status: Draft (Authoritative Baseline Once Merged)
License: Apache License 2.0 (This document and the NORC protocol are released under the Apache-2.0 license. All normative requirements herein SHALL be considered part of the Open Standard definition of NORC.)

## 0. Normative Language
The key words MUST, MUST NOT, SHALL, SHALL NOT, REQUIRED, SHOULD, SHOULD NOT, RECOMMENDED, MAY, and OPTIONAL in this document are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.

## 1. Purpose & Scope
R-1.1 The purpose of this document is to define the complete, testable, non-ambiguous set of functional and non-functional requirements governing the NavaTron Open Real-time Communication (NORC) Protocol.
R-1.2 This document SHALL serve as the authoritative baseline for subsequent: (a) protocol technical specifications, (b) reference implementations, (c) conformance test suites, (d) certification processes, and (e) governance and change control mechanisms.
R-1.3 The scope includes: wire protocol, cryptographic architecture, trust and federation model, interoperability rules, extension framework, lifecycle/version management (Adjacent-Major Compatibility), security/privacy guarantees, resilience and availability criteria, performance targets, observability, governance, licensing, and compliance.
R-1.4 Out of scope: UI/UX design specifics, deployment tooling details, organization-specific policy enforcement beyond defined trust level semantics, and proprietary extensions not submitted through the open governance process.
R-1.5 All requirements herein SHALL be uniquely identifiable and traceable through hierarchical identifiers (Epics → Features → Stories → Tasks → Verification Artifacts).

## 2. Definitions & Actors
D-2.1 Actor: End User — A human operating a client device using NORC for secure communication.
D-2.2 Actor: Client Device — A hardware/software environment executing a NORC client implementation and holding device-specific key material.
D-2.3 Actor: Organization Authority (Org Authority) — The administrative entity that enrolls users/devices and manages local policy.
D-2.4 Actor: Federation Server (NORC-F Server) — An authoritative server component responsible for relaying encrypted messages, enforcing federation rules, and executing routing logic without plaintext access to payloads.
D-2.5 Actor: Trust Authority (NORC-T Authority) — Component(s) and processes that manage trust levels, revocations, attestation validation, and issuance of trust assertions.
D-2.6 Actor: Auditor — Authorized party performing cryptographic audit and compliance inspection.
D-2.7 Actor: External Integrator — A third-party system interfacing via approved extension or gateway APIs without violating mandatory security constraints.
D-2.8 Trust Level — A formally recognized tier (Basic, Verified, Classified, NATO-Level, and future levels introduced via governance) defining minimum cryptographic and operational assurances.
D-2.9 Adjacent-Major Compatibility (AMC) — A versioning constraint restricting interoperable deployments to at most two consecutive major versions (N and N±1) simultaneously.
D-2.10 Hybrid Cryptography — Concurrent use of classical and post-quantum primitives to derive session secrets; compromise of one primitive SHALL NOT compromise the composite secrecy.
D-2.11 Message — A unit of end-to-end encrypted content (text, file fragment, control directive, or metadata envelope) transmitted within NORC.
D-2.12 Extension — A formally registered augmentation of the base protocol that does not weaken baseline security or violate compatibility constraints.
D-2.13 Conformance Profile — A named set of mandatory and optional behaviors for specific deployment categories (e.g., Minimal Client, Standard Server, High-Security Federation Node).
D-2.14 Security Parameter — A numeric or categorical value (e.g., key length, nonce reuse policy) mandated for a given trust level.
D-2.15 Revocation Event — A cryptographically signed directive invalidating prior authorization of a device, organization, trust assertion, or key.
D-2.16 Audit Trail — An immutable, append-only, cryptographically integrity-protected log enabling retrospective validation of trust decisions.
D-2.17 Non-Functional Requirement (NFR) — A constraint that specifies criteria for system operation rather than specific behaviors.

## 3. Identification & Traceability Schema
R-3.1 Requirement identifiers SHALL follow a hierarchical naming pattern:
- Epic: E-<NN>
- Feature: F-<EpicNumber>.<NN>
- Story: S-<FeatureID>.<NN>
- Task: T-<StoryID>.<NN>
- Non-Functional Requirement: NFR-<DomainAbbrev>.<NN>
R-3.2 All references MUST be stable; removed requirements SHALL be marked as DEPRECATED with a rationale rather than deleted.
R-3.3 A separate traceability matrix (Section 15) SHALL map each requirement to verification method(s).
R-3.4 Each Task SHALL map to at least one verification artifact (test, static analysis rule, formal proof, inspection procedure, or operational metric).

## 4. Epics Overview
E-01 Core Cryptographic Architecture
E-02 Device Identity & Enrollment
E-03 End-to-End Secure Messaging
E-04 Federation & Routing
E-05 Trust Levels & Governance
E-06 Versioning & Lifecycle Management (AMC)
E-07 Post-Quantum (PQ) Readiness
E-08 Key Management & Forward Secrecy
E-09 Revocation & Recovery
E-10 Metadata Minimization & Privacy
E-11 Audit & Compliance Observability
E-12 Performance & Low Latency Delivery
E-13 Scalability & Elastic Operation
E-14 Resilience, Fault Tolerance & Disaster Recovery
E-15 Extension & Capability Negotiation Framework
E-16 Interoperability & Conformance Profiles
E-17 Security Incident Response & Disclosure
E-18 Supply Chain Integrity & Build Trustworthiness
E-19 Licensing & Open Standard Stewardship
E-20 Accessibility & Internationalization

(Sections 5–14 decompose these epics.)

## 5. Epic E-01: Core Cryptographic Architecture
Feature Set (Representative; exhaustive within scope):
F-01.01 Algorithm Suite Definition
F-01.02 Cipher Suite Negotiation
F-01.03 Hybrid Key Establishment
F-01.04 Cryptographic Agility
F-01.05 Integrity & Authenticity Guarantees
F-01.06 Replay Protection
F-01.07 Randomness & Entropy Requirements

Story & Task Breakdown:
S-F-01.01.01 As a Client Device, I SHALL derive encryption keys using the mandated algorithm suite so that confidentiality is assured across all trust levels.
T-S-F-01.01.01.01 Implement mandatory baseline primitives: Ed25519 (signatures), X25519 (KEM classical component), Kyber768 (PQC KEM), ChaCha20-Poly1305 (AEAD), BLAKE3 (hash/PRF).
T-S-F-01.01.01.02 Enforce key sizes per security parameter table (Appendix A) at runtime.
T-S-F-01.01.01.03 Provide compile-time guard rejecting unsupported primitives by default.
S-F-01.02.01 As a Federation Server, I SHALL negotiate cipher suites without exposing downgrade vectors.
T-S-F-01.02.01.01 Implement negotiation handshake with explicit version+suite transcript binding.
T-S-F-01.02.01.02 Abort if peer proposes suite not in allowed intersection, logging structured code.
T-S-F-01.02.01.03 Detect and mitigate downgrade via transcript hash comparison.
S-F-01.03.01 As a Client Device, I SHALL perform hybrid key establishment combining PQ and classical KEM outputs.
T-S-F-01.03.01.01 Concatenate or KDF-combine (HKDF-BLAKE3) both shared secrets with domain separation tags.
T-S-F-01.03.01.02 Zero intermediate shared secrets from memory after derivation.
T-S-F-01.03.01.03 Reject session if either component derivation fails.
S-F-01.04.01 As a Protocol Implementation, I SHALL support future algorithm deprecation without breaking AMC.
T-S-F-01.04.01.01 Maintain algorithm registry file with status: ACTIVE, DEPRECATED, PROHIBITED.
T-S-F-01.04.01.02 Enforce deprecation grace period ≥ one minor version before prohibition.
T-S-F-01.04.01.03 Provide test ensuring deprecated algorithms are not negotiated when status=DEPRECATED+1 release.
S-F-01.05.01 As a Receiver, I SHALL verify authenticity and integrity of every message envelope.
T-S-F-01.05.01.01 Validate AEAD tag before processing payload.
T-S-F-01.05.01.02 Verify sender device signature chain.
T-S-F-01.05.01.03 Emit structured error code INTG-FAIL on mismatch.
S-F-01.06.01 As a Federation Server, I SHALL prevent replay of message envelopes.
T-S-F-01.06.01.01 Maintain per (sender device, session) sliding window of nonces.
T-S-F-01.06.01.02 Reject duplicates and log AUDIT event REPLAY_DETECTED.
T-S-F-01.06.01.03 Expire nonce windows after configurable time skew tolerance (< 2 minutes default).
S-F-01.07.01 As an Implementation, I SHALL ensure cryptographic randomness quality.
T-S-F-01.07.01.01 Use system-approved CSPRNG (e.g., /dev/urandom, getrandom) exclusively.
T-S-F-01.07.01.02 Provide health checks for entropy starvation fallback abort.
T-S-F-01.07.01.03 Document deterministic test mode strictly disabled in production builds.

(Additional epics follow same pattern; omitted commentary for brevity but are fully enumerated below.)

## 6. Epic E-02: Device Identity & Enrollment
Feature List:
F-02.01 Device Key Provisioning
F-02.02 Device Attestation (Optional at Basic; REQUIRED at Classified+)
F-02.03 Multi-Device User Association
F-02.04 Device State Lifecycle (ACTIVE, SUSPENDED, REVOKED, RETIRED)
F-02.05 Secure Storage of Private Keys
F-02.06 Enrollment Audit Logging
F-02.07 Enrollment Policy Enforcement
F-02.08 Device Identifier Format & Collision Resistance

Stories & Tasks:
S-F-02.01.01 As an Org Authority, I SHALL provision a unique device keypair per device to ensure compartmentalization.
T-S-F-02.01.01.01 Generate Ed25519 identity keypair client-side; SHALL NOT transmit private key.
T-S-F-02.01.01.02 Register public key with Org Authority endpoint using authenticated channel (TLS + org credential).
T-S-F-02.01.01.03 Receive signed device certificate binding (device_id, user_id, public_key, issue_ts, expiry_ts).
S-F-02.01.02 As a Client Device, I SHALL rotate device keys upon expiry or compromise declaration.
T-S-F-02.01.02.01 Enforce max lifetime L_dev <= 365 days (Basic), 180 days (Verified), 90 days (Classified+).
T-S-F-02.01.02.02 Provide proactive renewal 14 days before expiry.
T-S-F-02.01.02.03 Mark old key REPLACED and schedule secure wipe within 5 minutes post migration.
S-F-02.02.01 As an Org Authority, I SHALL validate hardware/software attestation for higher trust levels.
T-S-F-02.02.01.01 Accept attestation tokens (e.g., TPM/TEE report) with freshness window ≤ 5 minutes.
T-S-F-02.02.01.02 Reject enrollment if attestation PCR set not in approved baseline list.
T-S-F-02.02.01.03 Record attestation hash in audit trail entry AUD_DEV_ATTEST.
S-F-02.03.01 As a User, I MAY associate multiple devices while preserving per-device revocation semantics.
T-S-F-02.03.01.01 Maintain device index under single user identifier.
T-S-F-02.03.01.02 Expose list to user with status and last-seen timestamp.
T-S-F-02.03.01.03 Prevent exceeding max_devices limit (default 5; configurable policy).
S-F-02.03.02 As an Auditor, I SHALL determine which device sent a message.
T-S-F-02.03.02.01 Embed device_id signature chain in message envelope header (encrypted except routing metadata subset).
T-S-F-02.03.02.02 Provide verification API returning chain validity (VALID/INVALID/UNKNOWN).
S-F-02.04.01 As an Org Authority, I SHALL manage device state transitions with audit continuity.
T-S-F-02.04.01.01 Allowed transitions: ACTIVE→SUSPENDED, ACTIVE→REVOKED, SUSPENDED→ACTIVE, ACTIVE→RETIRED.
T-S-F-02.04.01.02 Disallow REVOKED→ACTIVE.
T-S-F-02.04.01.03 Log state change with signed event including previous_state, new_state, actor_id.
S-F-02.05.01 As a Client Device, I SHALL store private keys using OS secure storage primitives where available.
T-S-F-02.05.01.01 Use hardware-backed keystore if present (TEE/TPM/Secure Enclave).
T-S-F-02.05.01.02 Enforce memory locking (mlock) during transient key usage where OS permits.
T-S-F-02.05.01.03 Provide constant-time comparison for key integrity checks.
S-F-02.06.01 As an Auditor, I SHALL reconstruct enrollment chronology.
T-S-F-02.06.01.01 Emit audit events: DEV_CREATE, DEV_ROTATE, DEV_REVOKE, DEV_ATTEST_FAIL.
T-S-F-02.06.01.02 Provide pagination API with deterministic ordering (issue_ts asc, tie-break device_id).
T-S-F-02.06.01.03 Hash-chain audit record: prev_hash, record_hash.
S-F-02.07.01 As an Org Authority, I SHALL enforce enrollment policies before activation.
T-S-F-02.07.01.01 Policy rules: min_client_version, attestation_required (bool), geo_restrictions (optional), max_devices.
T-S-F-02.07.01.02 Deny activation if any rule fails with structured code ENROLL_POLICY_DENY.
T-S-F-02.07.01.03 Include evaluation summary in audit log.
S-F-02.08.01 As the Protocol, I SHALL define a collision-resistant device_id format.
T-S-F-02.08.01.01 device_id = base32( first_160_bits( BLAKE3( public_key || org_id || creation_ts )))
T-S-F-02.08.01.02 Collision probability for ≤ 10^9 devices < 2^-80.
T-S-F-02.08.01.03 Reject externally supplied device_id; always derived.

## 7. Epic E-03: End-to-End Secure Messaging
Feature List:
F-03.01 Session Establishment
F-03.02 Forward Secrecy Ratchet
F-03.03 Message Ordering & Duplicate Handling
F-03.04 Media & File Fragment Handling
F-03.05 Expiration & Ephemeral Messaging
F-03.06 Error Signaling & Recovery
F-03.07 Delivery Receipts (Non-content Acks)
F-03.08 Large Payload Streaming
F-03.09 Group Session Placeholder (Future)

Stories & Tasks:
S-F-03.01.01 As a Client Device, I SHALL perform mutual session initialization using hybrid KEM outputs.
T-S-F-03.01.01.01 Include version, cipher suite list, ephemeral key commitments in initial offer.
T-S-F-03.01.01.02 Bind transcript hash into final session key derivation.
T-S-F-03.01.01.03 Abort on mismatch in negotiated suite with code SESS_NEG_FAIL.
S-F-03.01.02 As a Receiver, I SHALL reject stale session offers.
T-S-F-03.01.02.01 Apply max age window 120s.
T-S-F-03.01.02.02 Include monotonic nonce to prevent replay.
T-S-F-03.01.02.03 Log REPLAY_SESSION_OFFER on duplicate.
S-F-03.02.01 As a Client Device, I SHALL advance a symmetric ratchet per message.
T-S-F-03.02.01.01 Derive next chain key = HKDF(chain_key, "MSG_RATCHET").
T-S-F-03.02.01.02 Delete prior chain key after deriving message key.
T-S-F-03.02.01.03 Support out-of-order up to window size 32.
S-F-03.03.01 As a Receiver, I SHALL detect duplicate messages.
T-S-F-03.03.01.01 Maintain receive_window_ids (sliding) keyed by (session_id, msg_seq).
T-S-F-03.03.01.02 If duplicate, discard silently but ACK prior receipt.
T-S-F-03.03.01.03 Provide metric duplicate_message_count.
S-F-03.04.01 As a Sender, I SHALL fragment large files without revealing plaintext size.
T-S-F-03.04.01.01 Fixed encrypted fragment size classes: 4KB, 16KB, 64KB.
T-S-F-03.04.01.02 Pad final fragment to nearest class unless < 10% remainder.
T-S-F-03.04.01.03 Integrity tag per fragment + manifest hash for reassembly.
S-F-03.05.01 As a Sender, I MAY set expiration policy.
T-S-F-03.05.01.01 Expiry timestamp encrypted in header extension.
T-S-F-03.05.01.02 Receivers purge expired messages locally within 60s.
T-S-F-03.05.01.03 Federation Servers SHALL NOT retain expired items in queues > 5 minutes.
S-F-03.06.01 As a Client, I SHALL receive structured error frames for recoverable failures.
T-S-F-03.06.01.01 Define error frame: {code, retryable(bool), details_hash?}.
T-S-F-03.06.01.02 Codes enumerated in appendix; MUST NOT expose sensitive internals.
T-S-F-03.06.01.03 Implement exponential backoff for retryable errors.
S-F-03.07.01 As a Sender, I SHALL optionally request non-content delivery receipt.
T-S-F-03.07.01.01 Include receipt_requested flag in message envelope metadata.
T-S-F-03.07.01.02 Receiver emits signed ack referencing message_id.
T-S-F-03.07.01.03 Prevent ack amplification (max outstanding requested receipts 256).
S-F-03.08.01 As a Sender, I SHALL stream large payloads efficiently.
T-S-F-03.08.01.01 Establish streaming context id with negotiated fragment size.
T-S-F-03.08.01.02 Allow parallel transmission up to concurrency=4 contexts.
T-S-F-03.08.01.03 Abort incomplete stream after idle timeout 120s.
S-F-03.09.01 (Placeholder) Group messaging SHALL follow separate group ratchet design (future spec) — no production enable until defined.
T-S-F-03.09.01.01 Mark feature incomplete in capability advertisement.
T-S-F-03.09.01.02 Reject group session attempts with NOT_IMPLEMENTED.
T-S-F-03.09.01.03 Provide test ensuring denial path.

## 8. Epic E-04: Federation & Routing
Feature List:
F-04.01 Trust-Based Routing Constraints
F-04.02 Cross-Organization Address Resolution
F-04.03 Message Queueing & Flow Control
F-04.04 Routing Loop Prevention
F-04.05 Federation Health Probing
F-04.06 Latency-Aware Path Selection (Future)
F-04.07 Federation Authentication & Mutual Verification

Stories & Tasks:
S-F-04.01.01 As a Federation Server, I SHALL enforce trust level compatibility.
T-S-F-04.01.01.01 Consult trust matrix: (sender_org_level, receiver_org_level) permitted? (boolean table maintained).
T-S-F-04.01.01.02 Reject disallowed route with code ROUTE_DENY_TRUST.
T-S-F-04.01.01.03 Log decision with anonymized org pair hash.
S-F-04.02.01 As a Federation Server, I SHALL resolve destination addresses.
T-S-F-04.02.01.01 Address format: user_local@org_domain.
T-S-F-04.02.01.02 Perform DNSSEC-backed SRV/TXT lookup for federation endpoint.
T-S-F-04.02.01.03 Cache positive results with TTL ≤ DNS record TTL.
S-F-04.03.01 As a Federation Server, I SHALL queue outbound messages under backpressure.
T-S-F-04.03.01.01 Maintain per-destination credit buckets.
T-S-F-04.03.01.02 Drop oldest queued beyond max_queue_age (config, default 10m) with EXPIRED status.
T-S-F-04.03.01.03 Expose queue_depth metric.
S-F-04.04.01 As a Federation Server, I SHALL prevent routing loops.
T-S-F-04.04.01.01 Include hop_count in envelope (encrypted except outer header) starting at 0.
T-S-F-04.04.01.02 Abort if hop_count > 4 with code LOOP_DETECT.
T-S-F-04.04.01.03 Maintain seen_message_ids LRU to block circulating duplicates.
S-F-04.05.01 As Operations, I SHALL probe federation health.
T-S-F-04.05.01.01 Implement signed health ping frame with monotonic sequence.
T-S-F-04.05.01.02 Measure round-trip time and publish metric federation_rtt_ms.
T-S-F-04.05.01.03 Mark peer UNHEALTHY after 3 consecutive failures (configurable).
S-F-04.06.01 (Future) Path selection algorithm MAY incorporate latency telemetry — disabled until standardized.
T-S-F-04.06.01.01 Advertise capability flag PATH_LATENCY=0 (inactive).
T-S-F-04.06.01.02 Reject attempts to set PATH_LATENCY=1.
T-S-F-04.06.01.03 Provide test verifying enforcement.
S-F-04.07.01 As a Federation Server, I SHALL mutually authenticate peers.
T-S-F-04.07.01.01 Exchange server certificates signed by Trust Authority or delegated federation CA.
T-S-F-04.07.01.02 Pin peer public key fingerprint; mismatch triggers FED_AUTH_FAIL.
T-S-F-04.07.01.03 Rotate federation certificates at least every 365 days.

## 9. Epic E-05: Trust Levels & Governance
Feature List:
F-05.01 Trust Level Definition Schema
F-05.02 Trust Assertion Issuance & Validation
F-05.03 Revocation Propagation
F-05.04 Policy Conflict Resolution
F-05.05 Cryptographic Thresholds per Level
F-05.06 Trust Level Evolution Process
F-05.07 Cross-Jurisdiction Constraints

Stories & Tasks:
S-F-05.01.01 As Governance, I SHALL publish machine-readable trust level descriptors.
T-S-F-05.01.01.01 Format: JSON with fields {id, name, min_alg_strength, attestation_required, rekey_interval, audit_density}.
T-S-F-05.01.01.02 Provide schema version field and hash.
T-S-F-05.01.01.03 Reject descriptors missing mandatory fields.
S-F-05.02.01 As a Trust Authority, I SHALL issue signed trust assertions linking org_id to trust_level.
T-S-F-05.02.01.01 Assertion validity period ≤ 180 days (Classified+ ≤ 90 days).
T-S-F-05.02.01.02 Include revocation URI.
T-S-F-05.02.01.03 Signature algorithm Ed25519 with context string "NORC-TRUST-ASSERT".
S-F-05.02.02 As a Federation Server, I SHALL validate trust assertions on first contact and cache safely.
T-S-F-05.02.02.01 Cache TTL ≤ 10% of assertion remaining lifetime.
T-S-F-05.02.02.02 Refresh on proactive timer or revocation push.
T-S-F-05.02.02.03 Reject expired assertion with code TRUST_EXPIRED.
S-F-05.03.01 As a Trust Authority, I SHALL propagate revocations quickly.
T-S-F-05.03.01.01 Publish signed revocation list delta every ≤ 5 minutes.
T-S-F-05.03.01.02 Provide push channel (webhook / message bus) for subscribed federation nodes.
T-S-F-05.03.01.03 Federation node applies revocation within 60s of receipt.
S-F-05.04.01 As a Federation Server, I SHALL resolve conflicting policies conservatively.
T-S-F-05.04.01.01 If trust levels differ between assertions, choose lower security level or refuse if below minimum threshold of either side.
T-S-F-05.04.01.02 Log POLICY_CONFLICT with details hash.
T-S-F-05.04.01.03 Provide deterministic resolution algorithm doc.
S-F-05.05.01 As Governance, I SHALL define cryptographic thresholds per level.
T-S-F-05.05.01.01 Basic: standard hybrid mandatory, min chain rekey interval 24h.
T-S-F-05.05.01.02 Classified: rekey interval ≤ 1h, enforced ephemeral ratchet every message.
T-S-F-05.05.01.03 NATO-Level: ephemeral PQ re-encapsulation every message and attestation required.
S-F-05.06.01 As Governance, I SHALL evolve trust levels through formal proposals.
T-S-F-05.06.01.01 New level draft includes: identifier, rationale, comparative table.
T-S-F-05.06.01.02 Require multi-signature acceptance (≥ 2 maintainers + 1 external auditor).
T-S-F-05.06.01.03 Publish effective date and transition window.
S-F-05.07.01 As Governance, I SHALL encode cross-jurisdiction constraints.
T-S-F-05.07.01.01 Maintain allow/deny matrix for export-restricted cryptography.
T-S-F-05.07.01.02 Federation node enforces jurisdictional prohibition list.
T-S-F-05.07.01.03 Log JURIS_POLICY_BLOCK event when blocked.

## 10. Epic E-06: Versioning & Lifecycle Management (AMC)
Feature List:
F-06.01 Version Negotiation
F-06.02 Adjacent-Major Enforcement
F-06.03 Deprecation Signaling
F-06.04 Transitional Compatibility Testing
F-06.05 Capability Downgrade Guardrails
F-06.06 Version Registry Integrity

Stories & Tasks:
S-F-06.01.01 As a Client Device, I SHALL negotiate the protocol version explicitly before secure session use.
T-S-F-06.01.01.01 Include supported_major_versions array in hello frame.
T-S-F-06.01.01.02 Select highest mutually supported major not exceeding local current+1.
T-S-F-06.01.01.03 Abort with VER_NEG_FAIL if no adjacent version intersection.
S-F-06.02.01 As a Federation Server, I SHALL reject peers advertising non-adjacent major ranges.
T-S-F-06.02.01.01 Validate max(peer_max) - min(peer_min) <= 1.
T-S-F-06.02.01.02 Log NON_ADJ_VERSION_ATTEMPT.
T-S-F-06.02.01.03 Provide metric version_reject_count.
S-F-06.03.01 As Governance, I SHALL signal deprecation schedule.
T-S-F-06.03.01.01 Publish deprecation manifest listing (feature_id, earliest_removal_major, rationale).
T-S-F-06.03.01.02 Implement clients warning API returning active deprecations.
T-S-F-06.03.01.03 Tests ensure manifest signature validity.
S-F-06.04.01 As QA, I SHALL test transitions N→N+1 pre-release.
T-S-F-06.04.01.01 Maintain automated matrix tests across stable & next.
T-S-F-06.04.01.02 Fail build if interop coverage < 95% targeted features.
T-S-F-06.04.01.03 Generate transition report artifact hashed and logged.
S-F-06.05.01 As a Client, I SHALL guard against downgrade of security-critical capabilities.
T-S-F-06.05.01.01 Persist last negotiated major; reject negotiation to lower major unless explicit override.
T-S-F-06.05.01.02 Validate cipher suite set is superset or acceptable subset per policy.
T-S-F-06.05.01.03 Emit DOWNGRADE_ALERT event if potential downgrade detected.
S-F-06.06.01 As Governance, I SHALL ensure integrity of version registry.
T-S-F-06.06.01.01 Registry stored append-only with hash chain.
T-S-F-06.06.01.02 Quarterly external audit signature.
T-S-F-06.06.01.03 Provide public mirror verification script.

## 11. Epic E-07: Post-Quantum (PQ) Readiness
Feature List:
F-07.01 Mandatory Hybrid Mode
F-07.02 PQ Algorithm Upgradability
F-07.03 PQ Security Parameter Monitoring
F-07.04 PQ Failure Independence
F-07.05 PQ Transition Planning

Stories & Tasks:
S-F-07.01.01 As a Client Device, I SHALL always perform hybrid key establishment (classical + PQ).
T-S-F-07.01.01.01 Abort if PQ component unsupported unless profile MIN-CLIENT.
T-S-F-07.01.01.02 Provide metric pq_hybrid_usage_ratio.
T-S-F-07.01.01.03 Test ensures removal of PQ half invalidates session.
S-F-07.02.01 As Governance, I SHALL enable introduction of new PQ KEM.
T-S-F-07.02.01.01 Maintain algorithm status registry with activation date.
T-S-F-07.02.01.02 Provide migration advisory doc linking risk assessment.
T-S-F-07.02.01.03 Backward compatibility test ensures coexistence for ≥ 1 minor version.
S-F-07.03.01 As a Federation Server, I SHALL monitor PQ security parameters.
T-S-F-07.03.01.01 Subscribe to advisory feed; update risk level state (LOW/MED/HIGH).
T-S-F-07.03.01.02 If HIGH, enforce accelerated rekey interval.
T-S-F-07.03.01.03 Log PQ_RISK_ESCALATION event.
S-F-07.04.01 As a Client Device, I SHALL ensure independence of hybrid components.
T-S-F-07.04.01.01 Use distinct randomness for each component.
T-S-F-07.04.01.02 Use KDF domain separation labels: "HYBRID-CLASSICAL" vs "HYBRID-PQ".
T-S-F-07.04.01.03 Formal model proof placeholder for independence property.
S-F-07.05.01 As Governance, I SHALL publish PQ transition roadmap yearly.
T-S-F-07.05.01.01 Include risk trend analysis.
T-S-F-07.05.01.02 Provide projected parameter increases.
T-S-F-07.05.01.03 Archive previous roadmap with hash chain.

## 12. Epic E-08: Key Management & Forward Secrecy
Feature List:
F-08.01 Ephemeral Session Keys
F-08.02 Periodic Rekey Triggers
F-08.03 Compromise Containment
F-08.04 Key Destruction Timeliness
F-08.05 Multi-Session Isolation

Stories & Tasks:
S-F-08.01.01 As a Session Participant, I SHALL derive unique ephemeral keys per session.
T-S-F-08.01.01.01 Use both static identity keys + ephemeral one-time keys.
T-S-F-08.01.01.02 Prevent reuse of ephemeral key material across sessions.
T-S-F-08.01.01.03 Provide test harness enumerating ephemeral key uniqueness.
S-F-08.02.01 As a Client Device, I SHALL rekey periodically based on trust level policy.
T-S-F-08.02.01.01 Basic: rekey after 500 messages or 24h.
T-S-F-08.02.01.02 Classified: rekey every message.
T-S-F-08.02.01.03 Timer-driven rekey triggers asynchronous handshake.
S-F-08.03.01 As a Client Device, I SHALL contain key compromise impact.
T-S-F-08.03.01.01 Implement forward secrecy ratchet progression test verifying inability to decrypt past message with current keys only.
T-S-F-08.03.01.02 Provide optional post-compromise security reinit handshake.
T-S-F-08.03.01.03 Metric compromised_session_resets.
S-F-08.04.01 As an Implementation, I SHALL destroy obsolete keys promptly.
T-S-F-08.04.01.01 Zero memory within 10ms of final use (best effort OS constraints).
T-S-F-08.04.01.02 Provide debug log (non-production) for destruction events.
T-S-F-08.04.01.03 Static analysis rule verifying no lingering references.
S-F-08.05.01 As a Client Device, I SHALL isolate keys across simultaneous sessions.
T-S-F-08.05.01.01 Index keys by composite (peer_device_id, session_id).
T-S-F-08.05.01.02 Reject cross-session key reuse attempt.
T-S-F-08.05.01.03 Add test ensuring collision detection.

## 13. Epic E-09: Revocation & Recovery
Feature List:
F-09.01 Immediate Device Revocation
F-09.02 Organization-Wide Kill Switch (Restricted High-Security)
F-09.03 Revocation Distribution Latency Target
F-09.04 Recovery Flow for Lost Devices
F-09.05 Partial Session Key Invalidation

Stories & Tasks:
S-F-09.01.01 As an Org Authority, I SHALL revoke a compromised device instantly.
T-S-F-09.01.01.01 Publish signed revocation event with reason code (COMPROMISE, RETIRE, POLICY).
T-S-F-09.01.01.02 Federation nodes ingest within 60s and block further messages.
T-S-F-09.01.01.03 Clients receiving revocation purge pending outbound queue for device.
S-F-09.02.01 As an Org Authority, I MAY trigger a kill switch in severe breach.
T-S-F-09.02.01.01 Multi-sig (2-of-3) approval required.
T-S-F-09.02.01.02 Broadcast kill event, clients transition to LOCKDOWN state.
T-S-F-09.02.01.03 Recovery requires explicit signed restore event.
S-F-09.03.01 As Governance, I SHALL enforce revocation latency targets.
T-S-F-09.03.01.01 95th percentile propagation ≤ 90s.
T-S-F-09.03.01.02 Metric revocation_lag_seconds.
T-S-F-09.03.01.03 Alert if > 3 consecutive breaches.
S-F-09.04.01 As a User, I SHALL re-enroll after device loss without orphaning conversations.
T-S-F-09.04.01.01 Provide recovery procedure verifying user identity (secondary factor policy-defined).
T-S-F-09.04.01.02 Issue new device with fresh identity key; mark old device REVOKED.
T-S-F-09.04.01.03 Peers receive notification of key change event.
S-F-09.05.01 As a Client, I SHALL invalidate specific session keys upon partial compromise detection.
T-S-F-09.05.01.01 Trigger rekey handshake for affected sessions only.
T-S-F-09.05.01.02 Log PARTIAL_COMPromise event.
T-S-F-09.05.01.03 Provide test verifying unaffected sessions remain stable.

## 14. (Partial Expansion Status)
Remaining Epics (E-10 through E-20) pending detailed story/task expansion in subsequent sections.

### Expansion: Epic E-10 (Already Enumerated in Section 10) — No action required.

## 14.1 Epic E-11: Audit & Compliance Observability (Expansion)
Feature List:
F-11.01 Structured Audit Event Schema
F-11.02 Integrity Protection (Hash Chaining)
F-11.03 Export & Redaction Pipeline
F-11.04 Real-Time Alerting Hooks
F-11.05 Time Synchronization & Drift Handling
F-11.06 Audit Access Control

Stories & Tasks:
S-F-11.01.01 As an Auditor, I SHALL parse audit events in a stable schema.
T-S-F-11.01.01.01 JSON fields mandatory: event_id, ts, actor_type, actor_id, event_type, subject_id?, prev_hash, record_hash, signature.
T-S-F-11.01.01.02 Validate canonical ordering (lexicographic keys).
T-S-F-11.01.01.03 Reject event ingestion missing mandatory field with AUD_SCHEMA_ERR.
S-F-11.02.01 As an Auditor, I SHALL verify log integrity.
T-S-F-11.02.01.01 record_hash = BLAKE3(canonical_json(event)).
T-S-F-11.02.01.02 prev_hash forms singly linked chain.
T-S-F-11.02.01.03 Provide chain verification CLI returning first tamper index.
S-F-11.03.01 As Compliance, I SHALL export redacted logs.
T-S-F-11.03.01.01 Redaction removes user content fields (none in event by design) and replaces PII tokens with pseudonymous stable hashes.
T-S-F-11.03.01.02 Export pipeline emits SHA-256 manifest of batch.
T-S-F-11.03.01.03 Provide test verifying deterministic redaction.
S-F-11.04.01 As Operations, I SHALL receive real-time critical alerts.
T-S-F-11.04.01.01 Define severity mapping: CRITICAL events push within 5s.
T-S-F-11.04.01.02 Webhook delivery signed with rotating key.
T-S-F-11.04.01.03 Retry policy exponential backoff max 5 attempts.
S-F-11.05.01 As Implementation, I SHALL mitigate clock drift.
T-S-F-11.05.01.01 NTP or authenticated time source required; drift >500ms triggers AUD_TIME_DRIFT warning.
T-S-F-11.05.01.02 Provide drift metric time_drift_ms.
T-S-F-11.05.01.03 Reject event ingestion older than retention_window + skew.
S-F-11.06.01 As Governance, I SHALL enforce role-based audit access.
T-S-F-11.06.01.01 Roles: AUDITOR_READ, AUDITOR_EXPORT, AUDITOR_ADMIN.
T-S-F-11.06.01.02 Least privilege default DENY.
T-S-F-11.06.01.03 Log unauthorized attempt AUD_ACCESS_DENY.

## 14.2 Epic E-12: Performance & Low Latency Delivery (Expansion)
Feature List:
F-12.01 Latency Budgeting
F-12.02 Priority Queuing
F-12.03 Adaptive Congestion Control
F-12.04 Compression (Optional)
F-12.05 Performance Telemetry Collection

Stories & Tasks:
S-F-12.01.01 As a Client, I SHALL adhere to per-hop latency budget.
T-S-F-12.01.01.01 Budget allocation: client_proc ≤ 50ms, federation_proc ≤ 100ms per hop.
T-S-F-12.01.01.02 Measure local encryption_time_ms metric.
T-S-F-12.01.01.03 Abort operations exceeding 5x rolling average (suspected stall) with PERF_STALL.
S-F-12.02.01 As a Federation Server, I SHALL prioritize control and revocation frames.
T-S-F-12.02.01.01 Priority classes: CONTROL > TRUST > MESSAGE > BULK.
T-S-F-12.02.01.02 Separate priority queues drained round-robin with weights.
T-S-F-12.02.01.03 Provide starvation prevention check.
S-F-12.03.01 As a Sender, I SHALL adapt to congestion.
T-S-F-12.03.01.01 Maintain RTT estimate using health pings.
T-S-F-12.03.01.02 Apply additive increase / multiplicative decrease to send window.
T-S-F-12.03.01.03 Expose congestion_window metric.
S-F-12.04.01 As a Sender, I MAY apply compression for payloads >4KB.
T-S-F-12.04.01.01 Only after encryption? (NO) – compression MUST occur before encryption.
T-S-F-12.04.01.02 Allowed algorithms registry controlled (e.g., zstd), default disabled.
T-S-F-12.04.01.03 Provide CR ratio metric compression_ratio.
S-F-12.05.01 As Operations, I SHALL collect performance telemetry safely.
T-S-F-12.05.01.01 Telemetry export excludes payload contents.
T-S-F-12.05.01.02 Provide sampling to limit overhead (<2%).
T-S-F-12.05.01.03 Metric ingestion failures logged with PERF_TELEM_FAIL.

## 14.3 Epic E-13: Scalability & Elastic Operation (Expansion)
Feature List:
F-13.01 Horizontal Scaling Model
F-13.02 Stateless Routing Core
F-13.03 Sharded Queue Management
F-13.04 Auto-Scaling Signals
F-13.05 Capacity Forecasting Export

Stories & Tasks:
S-F-13.01.01 As Architecture, I SHALL enable linear horizontal scaling.
T-S-F-13.01.01.01 Shared nothing state for routing decisions except replicated trust cache.
T-S-F-13.01.01.02 Provide scaling test harness doubling nodes.
T-S-F-13.01.01.03 Metric throughput_scaling_factor.
S-F-13.02.01 As Implementation, I SHALL keep core routing stateless.
T-S-F-13.02.01.01 Session state isolated in dedicated service or ephemeral store.
T-S-F-13.02.01.02 Stateless process restart zero-impact test.
T-S-F-13.02.01.03 Document state boundaries.
S-F-13.03.01 As a Federation Cluster, I SHALL shard queues.
T-S-F-13.03.01.01 Consistent hashing on (destination_org_id) to shard id.
T-S-F-13.03.01.02 Rebalance triggers on shard load >150% median.
T-S-F-13.03.01.03 Provide shard_migration_lag metric.
S-F-13.04.01 As Operations, I SHALL auto-scale on predictive signals.
T-S-F-13.04.01.01 Signals: queue_depth > threshold OR message_ingress_rate surge > 30% over 5m.
T-S-F-13.04.01.02 Turn-down conditions symmetrical.
T-S-F-13.04.01.03 Prevent oscillation via cooldown 10m.
S-F-13.05.01 As Governance, I SHALL export anonymized capacity planning data.
T-S-F-13.05.01.01 Metrics aggregated hourly.
T-S-F-13.05.01.02 Pseudonymize org identifiers.
T-S-F-13.05.01.03 Provide open format (Parquet/JSON) manifest.

## 14.4 Epic E-14: Resilience, Fault Tolerance & Disaster Recovery (Expansion)
Feature List:
F-14.01 Redundant Federation Nodes
F-14.02 Graceful Degradation Modes
F-14.03 Persistent Queue Durability
F-14.04 Disaster Recovery Plan Artifacts
F-14.05 Chaos Testing Program

Stories & Tasks:
S-F-14.01.01 As Operations, I SHALL deploy at least N=2 active nodes.
T-S-F-14.01.01.01 Health checks every 5s with failover after 3 failures.
T-S-F-14.01.01.02 Load reallocation < 30s target.
T-S-F-14.01.01.03 Metric active_node_count.
S-F-14.02.01 As a Client, I SHALL degrade gracefully under partial feature loss.
T-S-F-14.02.01.01 If delivery receipts unavailable, messaging continues without acks.
T-S-F-14.02.01.02 Provide capability advertisement flags.
T-S-F-14.02.01.03 Log DEGRADE_MODE_ENTER/EXIT events.
S-F-14.03.01 As a Federation Server, I SHALL persist queued messages reliably.
T-S-F-14.03.01.01 Durability level: write-ahead log synced before ACK to sender.
T-S-F-14.03.01.02 Corruption detection via log segment checksums.
T-S-F-14.03.01.03 Recovery test replays crash scenarios.
S-F-14.04.01 As Governance, I SHALL maintain DR plan.
T-S-F-14.04.01.01 Document RPO/RTO mapping to requirement IDs.
T-S-F-14.04.01.02 Annual DR simulation report published.
T-S-F-14.04.01.03 Store plan hash in governance log.
S-F-14.05.01 As Quality Engineering, I SHALL run chaos tests.
T-S-F-14.05.01.01 Inject failure modes: network partition, latency spike, node crash.
T-S-F-14.05.01.02 Automate weekly schedule.
T-S-F-14.05.01.03 Report remediation actions.

## 14.5 Epic E-15: Extension & Capability Negotiation Framework (Expansion)
Feature List:
F-15.01 Extension Registration
F-15.02 Capability Advertisement Frame
F-15.03 Security Non-Interference Validation
F-15.04 Extension Versioning & Deprecation
F-15.05 Conflict Resolution Policy

Stories & Tasks:
S-F-15.01.01 As Governance, I SHALL register extensions uniquely.
T-S-F-15.01.01.01 Identifier format: EX-<uppercase slug>.
T-S-F-15.01.01.02 Registry includes status ACTIVE/DEPRECATED/REMOVED.
T-S-F-15.01.01.03 Signed registry snapshot published monthly.
S-F-15.02.01 As a Client Device, I SHALL advertise capabilities early handshake.
T-S-F-15.02.01.01 Capability frame lists feature flags and extension ids.
T-S-F-15.02.01.02 Accept only server-confirmed subset.
T-S-F-15.02.01.03 Potential downgrade detection if missing mandatory flags.
S-F-15.03.01 As Security Review, I SHALL validate extension non-interference.
T-S-F-15.03.01.01 Provide threat impact statement.
T-S-F-15.03.01.02 Run static analysis for forbidden API usage.
T-S-F-15.03.01.03 Attach verification report id.
S-F-15.04.01 As Governance, I SHALL manage extension lifecycle.
T-S-F-15.04.01.01 Deprecation manifest includes removal date.
T-S-F-15.04.01.02 Tools warn when extension status DEPRECATED.
T-S-F-15.04.01.03 Removed extensions blocked at negotiation.
S-F-15.05.01 As Implementation, I SHALL resolve conflicting extensions deterministically.
T-S-F-15.05.01.01 Conflict resolution order: security_level > version > identifier lexical.
T-S-F-15.05.01.02 Log EXT_CONFLICT_RESOLVED.
T-S-F-15.05.01.03 Provide test simulating conflict.

## 14.6 Epic E-16: Interoperability & Conformance Profiles (Expansion)
Feature List:
F-16.01 Conformance Profile Definitions
F-16.02 Cross-Implementation Test Harness
F-16.03 Negative Case Interop Validation
F-16.04 Backward Compatibility Assertions
F-16.05 Profile Evolution Governance

Stories & Tasks:
S-F-16.01.01 As Governance, I SHALL define machine-readable profiles.
T-S-F-16.01.01.01 Profiles enumerated with required feature_ids list.
T-S-F-16.01.01.02 Provide JSON schema with checksum.
T-S-F-16.01.01.03 Validate no undefined feature references.
S-F-16.02.01 As QA, I SHALL run cross-implementation tests.
T-S-F-16.02.01.01 Matrix generation for (implementation A, B) pairs.
T-S-F-16.02.01.02 Capture pass/fail with artifact digest.
T-S-F-16.02.01.03 Publish interop report signed.
S-F-16.03.01 As QA, I SHALL validate negative cases.
T-S-F-16.03.01.01 Malformed frame set injection suite.
T-S-F-16.03.01.02 Downgrade attempt scenarios.
T-S-F-16.03.01.03 Replay attack simulation.
S-F-16.04.01 As a Client, I SHALL assert backward compatibility with N-1 major.
T-S-F-16.04.01.01 Automated test handshake success and feature negotiation.
T-S-F-16.04.01.02 Report missing features vs optional features distinct.
T-S-F-16.04.01.03 Fail build on mandatory feature gap.
S-F-16.05.01 As Governance, I SHALL evolve profiles predictably.
T-S-F-16.05.01.01 Change log referencing requirement IDs.
T-S-F-16.05.01.02 Deprecation window documented.
T-S-F-16.05.01.03 Profile version hash published.

## 14.7 Epic E-17: Security Incident Response & Disclosure (Expansion)
Feature List:
F-17.01 Severity Classification Framework
F-17.02 Advisory Publication Pipeline
F-17.03 Temporary Mitigation Distribution
F-17.04 Postmortem Artifact Standard
F-17.05 Confidential Reporting Channel Integrity

Stories & Tasks:
S-F-17.01.01 As Governance, I SHALL classify issues consistently.
T-S-F-17.01.01.01 Severity rubric JSON published.
T-S-F-17.01.01.02 Tool validates rubric completeness.
T-S-F-17.01.01.03 Map rubric to disclosure timelines.
S-F-17.02.01 As Security Team, I SHALL publish advisories.
T-S-F-17.02.01.01 Advisory format: {cve?, severity, affected_versions, workaround, patches}.
T-S-F-17.02.01.02 Signed PGP & Ed25519 dual signature.
T-S-F-17.02.01.03 Archive accessible with index.
S-F-17.03.01 As an Operator, I SHALL receive mitigation guidance.
T-S-F-17.03.01.01 Mitigation diff hashed.
T-S-F-17.03.01.02 Provide rollback instructions.
T-S-F-17.03.01.03 Track adoption metric mitigation_adopt_rate.
S-F-17.04.01 As Governance, I SHALL standardize postmortems.
T-S-F-17.04.01.01 Template mandated fields root_cause, timeline, detection_gap, action_items.
T-S-F-17.04.01.02 Publish within 10 business days.
T-S-F-17.04.01.03 Hash chain inclusion.
S-F-17.05.01 As a Reporter, I SHALL use authenticated confidential channel.
T-S-F-17.05.01.01 Channel encrypted (public key) with rotating key every 90 days.
T-S-F-17.05.01.02 Acknowledge receipt ≤ 48h.
T-S-F-17.05.01.03 Log reporter metadata minimally (no IP, only submission id).

## 14.8 Epic E-18: Supply Chain Integrity & Build Trustworthiness (Expansion)
Feature List:
F-18.01 Reproducible Build Workflow
F-18.02 Artifact Signing & Verification
F-18.03 Dependency Policy Enforcement
F-18.04 SBOM Generation & Publication
F-18.05 Continuous Vulnerability Monitoring

Stories & Tasks:
S-F-18.01.01 As Release Engineering, I SHALL produce reproducible builds.
T-S-F-18.01.01.01 Deterministic compiler flags locked.
T-S-F-18.01.01.02 Build environment container hash recorded.
T-S-F-18.01.01.03 Independent rebuild bit-for-bit verification test.
S-F-18.02.01 As Users, I SHALL verify artifact signatures.
T-S-F-18.02.01.01 Provide verification CLI.
T-S-F-18.02.01.02 Rotate signing key annually.
T-S-F-18.02.01.03 Store public keys in transparency log.
S-F-18.03.01 As Governance, I SHALL enforce dependency policies.
T-S-F-18.03.01.01 Disallow GPL-incompatible licenses.
T-S-F-18.03.01.02 CVE threshold severity HIGH triggers build block.
T-S-F-18.03.01.03 Quarterly dependency review report.
S-F-18.04.01 As Compliance, I SHALL publish SBOMs.
T-S-F-18.04.01.01 Format SPDX and CycloneDX both.
T-S-F-18.04.01.02 Include license, version, hash, supplier.
T-S-F-18.04.01.03 Sign SBOM manifest.
S-F-18.05.01 As Security, I SHALL monitor vulnerabilities.
T-S-F-18.05.01.01 Automated feed ingestion daily.
T-S-F-18.05.01.02 Alert on new CVE mapping to dependency.
T-S-F-18.05.01.03 Metric vuln_open_count.

## 14.9 Epic E-19: Licensing & Open Standard Stewardship (Expansion)
Feature List:
F-19.01 License Compliance Automation
F-19.02 Notice File Consistency
F-19.03 Contributor Agreement Validation (DCO)
F-19.04 Patent Grant Transparency
F-19.05 Specification Version Archival

Stories & Tasks:
S-F-19.01.01 As Governance, I SHALL automate license header checks.
T-S-F-19.01.01.01 CI job scanning changed files.
T-S-F-19.01.01.02 Block merge on missing header.
T-S-F-19.01.01.03 Provide remediation script.
S-F-19.02.01 As Release Engineering, I SHALL maintain NOTICE consistency.
T-S-F-19.02.01.01 Regenerate NOTICE from dependency metadata each release.
T-S-F-19.02.01.02 Diff against prior; require approval if removal.
T-S-F-19.02.01.03 Sign NOTICE hash.
S-F-19.03.01 As Governance, I SHALL enforce DCO sign-offs.
T-S-F-19.03.01.01 CI fails if commit lacks Signed-off-by.
T-S-F-19.03.01.02 Provide contributor guidance doc link.
T-S-F-19.03.01.03 Track compliance metric dco_violation_count.
S-F-19.04.01 As Governance, I SHALL publish patent grant transparency.
T-S-F-19.04.01.01 Maintain list of known patent contributors.
T-S-F-19.04.01.02 Signed affirmation referencing Apache-2.0 Section 3.
T-S-F-19.04.01.03 Annual reaffirmation cycle.
S-F-19.05.01 As Users, I SHALL access archived spec versions.
T-S-F-19.05.01.01 Tag spec release with hash.
T-S-F-19.05.01.02 Maintain index page with prior hashes.
T-S-F-19.05.01.03 Integrity verification script.

## 14.10 Epic E-20: Accessibility & Internationalization (Expansion)
Feature List:
F-20.01 Error Code Localization Support
F-20.02 Documentation Readability Standards
F-20.03 Time/Number Format Neutrality
F-20.04 Bidirectional Text Handling (Optional in Reference UI)
F-20.05 Accessibility Testing Guidance

Stories & Tasks:
S-F-20.01.01 As a Client UI, I SHALL map error codes to localized strings externally.
T-S-F-20.01.01.01 Provide machine-readable error catalog JSON.
T-S-F-20.01.01.02 Codes immutable once published.
T-S-F-20.01.01.03 Reject attempt to reuse code id.
S-F-20.02.01 As Documentation, I SHALL maintain readability.
T-S-F-20.02.01.01 Enforce max sentence length 40 words (linting rule).
T-S-F-20.02.01.02 Provide glossary cross-reference links.
T-S-F-20.02.01.03 Accessibility alt text for all diagrams.
S-F-20.03.01 As Protocol, I SHALL remain locale neutral.
T-S-F-20.03.01.01 RFC 3339 timestamps only.
T-S-F-20.03.01.02 Decimal separators standardized ('.').
T-S-F-20.03.01.03 Prohibit localized number formatting on wire.
S-F-20.04.01 As Reference UI, I MAY support bidi text safely.
T-S-F-20.04.01.01 Apply Unicode bidi algorithm compliance test.
T-S-F-20.04.01.02 Sanitize control characters.
T-S-F-20.04.01.03 Provide test corpus.
S-F-20.05.01 As QA, I SHALL offer accessibility test guidance.
T-S-F-20.05.01.01 Checklist mapping to WCAG 2.1 AA.
T-S-F-20.05.01.02 Provide screen-reader compatibility test instructions.
T-S-F-20.05.01.03 Metric accessibility_issue_count.

---
## Appendix A: Security Parameter Table
| Parameter | Basic | Verified | Classified | NATO-Level | Notes |
|-----------|-------|----------|-----------|------------|-------|
| Device Key Lifetime (days) | 365 | 270 | 90 | 60 | T-S-F-02.01.02.01 |
| Session Rekey Interval (messages) | 500 | 200 | 1 | 1 | T-S-F-08.02.01.* |
| Hybrid PQ Mandatory | Yes | Yes | Yes | Yes | T-S-F-07.01.01.* |
| Attestation Required | No | Optional | Yes | Yes | T-S-F-02.02.01.* |
| Revocation Propagation Target (s) | 120 | 90 | 60 | 60 | T-S-F-09.03.01.* |
| Audit Event Min Density | Standard | Elevated | High | High | F-11.01 policy |
| Ephemeral Key Reuse | Prohibited | Prohibited | Prohibited | Prohibited | T-S-F-08.01.01.* |

---
## Appendix B: Conformance Profiles Matrix
| Feature ID | MIN-CLIENT | STD-CLIENT | FED-SERVER | TRUST-AUTH |
|------------|------------|------------|------------|------------|
| F-01.01 Core Algorithm Suite | R | R | R | R |
| F-02.02 Device Attestation | O | O | O | R |
| F-03.07 Delivery Receipts | O | R | R | N/A |
| F-04.05 Health Probing | N/A | O | R | O |
| F-05.05 Cryptographic Thresholds | O | R | R | R |
| F-06.02 AMC Enforcement | R | R | R | R |
| F-07.01 Mandatory Hybrid | O | R | R | R |
| F-08.02 Periodic Rekey | R | R | R | O |
| F-09.01 Device Revocation | R | R | R | R |
| F-11.02 Audit Integrity | O | O | R | R |
| F-12.02 Priority Queuing | N/A | O | R | N/A |
| F-14.05 Chaos Testing | N/A | O | O | O |
| F-15.02 Capability Advertisement | R | R | R | O |
| F-18.04 SBOM Publishing | O | O | O | R |
Legend: R = Required, O = Optional, N/A = Not Applicable.

---
## Appendix C: Expanded Traceability (Sample Subset)
| ID | Parent | Verif | Coverage |
|----|--------|-------|----------|
| T-S-F-02.01.01.02 | S-F-02.01.01 | VM-TEST | Enrollment tests |
| T-S-F-03.02.01.02 | S-F-03.02.01 | VM-TEST | Ratchet progression |
| T-S-F-04.04.01.02 | S-F-04.04.01 | VM-TEST | Loop prevention |
| T-S-F-06.02.01.02 | S-F-06.02.01 | VM-METRIC | Version rejects |
| T-S-F-07.04.01.02 | S-F-07.04.01 | VM-FORMAL | Domain separation |
| T-S-F-08.04.01.03 | S-F-08.04.01 | VM-ANAL | Zeroization static check |
| T-S-F-09.03.01.02 | S-F-09.03.01 | VM-METRIC | Revocation lag |
| T-S-F-11.02.01.03 | S-F-11.02.01 | VM-TEST | Chain tamper detection |
| T-S-F-13.01.01.02 | S-F-13.01.01 | VM-TEST | Scaling harness |
| T-S-F-14.05.01.02 | S-F-14.05.01 | VM-TEST | Chaos schedule |
| T-S-F-18.01.01.03 | S-F-18.01.01 | VM-TEST | Reproducibility |
| T-S-F-19.01.01.02 | S-F-19.01.01 | VM-TEST | CI enforcement |
| T-S-F-20.02.01.01 | S-F-20.02.01 | VM-ANAL | Lint readability |

---
## Appendix D: Document Hash
Canonical SHA-256 (version 1.0.0): `0619903d360ad8a168d5e7c66f7178365aebe28c266290c590da97e6d446d4c2`
This hash SHALL match the canonical UTF-8 encoded file in repository root under path `requirements.md`.

## 15. Non-Functional Requirements (Representative Subset; Full Expansion Pending)
NFR-SEC.01 All cryptographic operations SHALL avoid secret-dependent branching (constant time) for private key material.
NFR-SEC.02 Implementations SHALL zero sensitive memory within 5ms of last use (where OS permits).
NFR-SEC.03 AEAD keys SHALL NOT be reused with same nonce; violation MUST trigger hard failure.
NFR-PRV.01 Federation Servers SHALL NOT persist plaintext message content at any time.
NFR-PRV.02 Metadata minimization: routing nodes MAY store (timestamp_bucket, sender_org_id, receiver_org_id, message_size_class) only.
NFR-PRV.03 Correlation resistance: padding or batching SHOULD ensure no direct timing correlation below 50ms resolution for Classified and above.
NFR-PERF.01 95th percentile end-to-end message delivery latency (Client→Client across two federated orgs) SHALL be ≤ 500ms under normal load profile defined in Performance Profile P1.
NFR-PERF.02 Maximum protocol overhead per message SHALL NOT exceed 20% of payload size for payloads ≥ 2KB.
NFR-SCAL.01 Architecture SHALL scale linearly (±15%) in throughput with horizontal addition of federation nodes.
NFR-SCAL.02 A single standard deployment reference SHALL handle ≥ 50k concurrent active sessions per federation node (Profile F1) without SLA breach.
NFR-AVL.01 Target service availability for Federation Layer SHALL be 99.95% monthly.
NFR-RES.01 Recovery Point Objective (RPO) for audit logs SHALL be ≤ 60s.
NFR-RES.02 Recovery Time Objective (RTO) for single node failure SHALL be ≤ 120s.
NFR-OBS.01 Implementations SHALL expose metrics: message_ingress_rate, e2e_latency_histogram, failed_auth_attempts, revocation_lag_seconds, pq_hybrid_failover_count.
NFR-GOV.01 All changes to trust level definitions SHALL require two-party cryptographic co-signing within governance framework.
NFR-LIC.01 All distributed artifacts SHALL include Apache-2.0 license header and NOTICE file.
NFR-LIC.02 Patent grant conditions per Apache-2.0 Section 3 SHALL be explicitly acknowledged in contributor documentation.
NFR-COMP.01 Implementations targeting regulated sectors SHALL produce SBOM (CycloneDX or SPDX) at build time.
NFR-SUP.01 Critical security advisories SHALL be published within 24h of confirmed severity classification.
NFR-I18N.01 Textual protocol elements (labels) SHALL be ASCII canonical; UI-level localization MAY map to human languages.
NFR-ACC.01 Administrative interfaces (reference implementations) SHOULD conform to WCAG 2.1 AA where applicable.

## 16. Governance & Change Control
R-16.1 Governance Body SHALL maintain registry of: versions, algorithms, trust levels, extension identifiers.
R-16.2 Changes SHALL proceed via numbered Proposal (NP) documents with states: DRAFT, REVIEW, ACCEPTED, REJECTED, SUPERSEDED.
R-16.3 Security-relevant changes SHALL undergo mandatory public review period ≥ 14 days unless emergency invoked.
R-16.4 Emergency procedure MAY accelerate to 48h with multi-signature attestation by at least 3 recognized maintainers.
R-16.5 Deprecation of a mandatory primitive SHALL require:
1. Formal rationale.
2. Migration guidance.
3. Overlapping support for ≥ 1 minor version.
R-16.6 AMC Enforcement: At any time, only two consecutive major versions SHALL be listed ACTIVE; a third SHALL be flagged EXPIRED.
R-16.7 Audit logs of governance decisions SHALL be append-only, hash-chained, and periodically timestamped (e.g., RFC3161 or public blockchain anchoring).
R-16.8 Extension registration SHALL mandate security impact statement and non-interference attestation.
R-16.9 Conflict resolution between overlapping extensions SHALL favor stricter security posture by default.
R-16.10 Revocation policy updates SHALL include backward-compatible transitional semantics or explicit migration schedule.

## 17. Licensing & Open Standard Requirements
R-17.1 NORC specification and reference code SHALL be published under Apache-2.0 with NOTICE file.
R-17.2 Contributions MUST include Developer Certificate of Origin (DCO) sign-off.
R-17.3 No contributor agreement SHALL impose additional patent or field-of-use restrictions beyond Apache-2.0.
R-17.4 Binary distributions of reference implementations SHALL embed license metadata retrievable via command-line flag (e.g., --license).
R-17.5 Specification derivative works MUST preserve normative language and disclaimers while allowing commentary additions.

## 18. Interoperability & Conformance
R-18.1 A Conformance Test Suite (CTS) SHALL define mandatory tests for each Conformance Profile.
R-18.2 Implementations claiming compliance SHALL publish CTS results including version hash.
R-18.3 Negative tests (malformed frames, downgrade attempts, replay injection) SHALL be included and MUST pass.
R-18.4 Interop events MAY generate signed reports establishing cross-implementation matrix.
R-18.5 Profiles: MIN-CLIENT, STD-CLIENT, FED-SERVER, TRUST-AUTH. Each SHALL enumerate required feature IDs.

## 19. Observability & Audit
R-19.1 Audit events SHALL include: timestamp (synced), event_type, subject_id, object_id (optional), cryptographic hash pointer, signature.
R-19.2 Logs SHALL be exportable in normalized JSON schema with canonical field ordering.
R-19.3 Privacy filtering SHALL remove user content fields prior to export.
R-19.4 Time synchronization drift tolerance SHALL be ≤ 500ms for audit chain continuity.
R-19.5 Failed integrity verification attempts SHALL escalate after configurable threshold.

## 20. Security Incident Response
R-20.1 Severity classification (Critical, High, Medium, Low) SHALL determine disclosure timeline.
R-20.2 Temporary mitigation guidance SHALL be issued within 12h for Critical severity.
R-20.3 CVE assignment (or equivalent) SHOULD occur prior to public advisory where applicable.
R-20.4 A Postmortem Report SHALL be produced within 10 business days of incident closure.

## 21. Supply Chain & Build Integrity
R-21.1 Reference build pipelines SHALL implement reproducible builds (byte-identical outputs) for at least one platform.
R-21.2 Build artifacts SHALL be signed using hardware-protected keys (e.g., HSM or TPM-backed).
R-21.3 SBOM generation SHALL occur prior to artifact signing.
R-21.4 Dependency policies SHALL reject transitive dependencies with unknown license.
R-21.5 Continuous verification of cryptographic library versions SHALL alert on CVE matching.

## 22. Accessibility & Internationalization
R-22.1 Protocol wire elements SHALL avoid locale-sensitive parsing.
R-22.2 Error codes SHALL be numeric + stable symbolic constant (e.g., INTG-FAIL) to permit localization externally.
R-22.3 Reference documentation SHOULD provide language-agnostic pseudo-code for critical flows.

## 23. Performance & Capacity Targets (Aligned with NFR Section)
R-23.1 Baseline test scenario P1: 500 concurrent organizations, average message size 1KB, avg device sessions per org 200.
R-23.2 Under P1, 99th percentile latency SHALL be ≤ 900ms.
R-23.3 Throughput scaling validation SHALL demonstrate doubling of nodes increases processed messages ≥ 1.85x (allowing ≤15% scaling loss).

## 24. Risk & Threat Considerations
R-24.1 Formal threat model documents SHALL map each identified threat to a mitigating requirement ID.
R-24.2 Hybrid crypto fallback MUST NOT silently reduce to classical-only without explicit error.
R-24.3 Side-channel resistance SHALL be periodically assessed with tooling (timing differential threshold < constant-time tolerance benchmark).

## 25. Verification Methods Legend
VM-TEST Automated functional or integration test.
VM-ANAL Static or dynamic code analysis.
VM-INSPECT Manual structured inspection.
VM-FORMAL Formal proof / model checking artifact.
VM-METRIC Operational runtime metric sampling.
VM-PEN External penetration test result.

## 26. Traceability (Illustrative Subset)
| Requirement | Parent | Verification | Status | Notes |
|-------------|--------|-------------|--------|-------|
| T-S-F-01.03.01.02 | S-F-01.03.01 | VM-TEST / VM-INSPECT | TBD | Memory zeroization test harness |
| NFR-PERF.01 | (Perf Domain) | VM-TEST / VM-METRIC | TBD | Load test scenario P1 |
| R-16.6 | Governance Section | VM-INSPECT | TBD | Review version registry log |

## 27. Future-Proofing Principles
R-27.1 Protocol evolutions SHALL prefer additive extension negotiation over semantic overloading.
R-27.2 Cryptographic parameter increases SHOULD be applied before published cryptanalytic breaks degrade effective security margin below 192-bit classical equivalence for Classified trust level and above.
R-27.3 Mandatory PQ upgrade path SHALL be scheduled no later than 12 months after recognized NIST changes relevant to chosen primitives.

## 28. Prohibited Practices
R-28.1 Plaintext fallback channels SHALL NOT be implemented.
R-28.2 Disabling integrity verification for performance SHALL NOT be permissible.
R-28.3 Trust assertion caching beyond expiry TTL SHALL NOT occur.
R-28.4 Use of unauthenticated time sources for critical audit timestamping SHALL NOT be permitted.

## 29. Deprecation Lifecycle
R-29.1 Deprecation Notice → Warning Period → Disabled by Default → Prohibited sequence SHALL be followed.
R-29.2 Each phase SHALL specify earliest major version where prohibition enters effect.
R-29.3 Clients MUST surface deprecation warnings via standardized diagnostic interface.

## 30. Documentation Requirements
R-30.1 Each normative algorithm decision SHALL include rationale section.
R-30.2 Implementations SHALL publish configuration reference mapping parameter names to requirement IDs.
R-30.3 A public glossary SHALL remain synchronized with Section 2; divergence > 1 release is non-compliant.

## 31. Conformance Claims
R-31.1 Claimants SHALL identify: Implementation Name, Version, Commit Hash, Conformance Profile(s), Date.
R-31.2 Self-attestation SHALL include automated test report digest (SHA-256) linking to artifacts.
R-31.3 Third-party certification bodies MAY append signed endorsement object referencing requirement set hash.

## 32. Hashing & Integrity of This Document
R-32.1 This requirements document’s canonical form SHALL be hashed (SHA-256) upon release; hash published in governance log.
R-32.2 Any modification SHALL update version and include prior-hash linkage.

## 33. Outstanding Expansion Tasks
NOTE: Sections 6–14 condensed. Full enumeration placeholder MUST be resolved before status transitions from Draft to Baseline. (Tasks to expand are tracked under backlog: EXPAND-E02..E20.)
R-33.1 The placeholder in Section 14 SHALL be replaced with exhaustive Stories and Tasks prior to first Conformance Test Suite release.
R-33.2 No feature implementation SHALL be marked production-ready if it depends on a placeholder story.

## 34. Compliance Statement
Upon final approval, all NORC implementations claiming compliance SHALL implement all MUST/SHALL requirements herein or explicitly document deviations with rationale and risk impact.

## 35. License Notice (Apache-2.0)
Copyright (c) NavaTron and Contributors.
Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0 Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

---
END OF DOCUMENT
