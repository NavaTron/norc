# NORC Protocol Specification
## NavaTron Open Real-time Communication Protocol - Technical Specification

**Document Version:** 1.0  
**Effective Date:** September 22, 2025  
**Document Type:** Normative Technical Specification  
**Legal Framework:** Apache-2.0 License  
**Classification:** Open Standard  

---

## Abstract

The NavaTron Open Real-time Communication (NORC) Protocol is a federated, secure real-time communication protocol designed for organizations requiring robust security guarantees and practical cross-organizational collaboration capabilities. NORC employs a three-layer architecture comprising client communication (NORC-C), server federation (NORC-F), and trust management (NORC-T). This specification defines the complete protocol behavior, message formats, cryptographic requirements, and interoperability constraints necessary for implementing conforming NORC systems.

## Table of Contents

1. [Introduction](#1-introduction)
2. [Terminology and Definitions](#2-terminology-and-definitions)
3. [Protocol Overview](#3-protocol-overview)
4. [Data Structures and Message Formats](#4-data-structures-and-message-formats)
5. [State Machines and Interactions](#5-state-machines-and-interactions)
6. [Error Handling](#6-error-handling)
7. [Security Considerations](#7-security-considerations)
8. [Privacy Considerations](#8-privacy-considerations)
9. [Performance and Scalability](#9-performance-and-scalability)
10. [Interoperability and Versioning](#10-interoperability-and-versioning)
11. [Conformance Requirements](#11-conformance-requirements)
12. [Extensions and Future Work](#12-extensions-and-future-work)
13. [Licensing and Governance](#13-licensing-and-governance)

---

## 1. Introduction

### 1.1 Purpose and Scope

This document specifies the NavaTron Open Real-time Communication (NORC) Protocol, a comprehensive solution for secure, federated real-time communication between organizations. The protocol addresses the fundamental tension between security and collaboration by providing graduated trust levels and mandatory end-to-end encryption while enabling practical cross-organizational communication.

The NORC protocol is designed to be:

- **Security-first**: All communication is end-to-end encrypted by default with no optional security modes
- **Federation-capable**: Organizations can establish selective trust relationships across administrative boundaries
- **Quantum-resistant**: Hybrid classical/post-quantum cryptography protects against current and future threats
- **Complexity-bounded**: Adjacent-Major Compatibility (AMC) prevents unbounded legacy accumulation
- **Standards-compliant**: Suitable for adoption as an international communication standard

### 1.2 Design Principles

NORC is built upon four fundamental design principles:

1. **Mandatory Security**: Security properties are enforced by the protocol itself, not left to implementation choices
2. **Selective Trust**: Organizations can establish graduated trust relationships with cryptographic verification
3. **Bounded Evolution**: Version compatibility is limited to prevent complexity explosion while ensuring interoperability
4. **Cryptographic Transparency**: All security-relevant decisions are auditable and verifiable

### 1.3 Intended Audience

This specification is intended for:

- Protocol implementers developing NORC-compliant software
- Security architects evaluating the protocol for organizational adoption
- Standards bodies considering NORC for standardization
- Auditors conducting security and compliance assessments
- Researchers analyzing secure communication protocols

---

## 2. Terminology and Definitions

### 2.1 Protocol Actors

**End User**: A human entity operating a client device for secure communication purposes.

**Client Device**: A hardware/software platform executing a NORC client implementation with device-specific cryptographic key material.

**Organization Authority**: The administrative entity responsible for user/device enrollment and local policy management within an organization.

**Federation Server**: An authoritative server component responsible for message relay, federation rule enforcement, and routing logic without plaintext access to message content.

**Trust Authority**: The component(s) and processes responsible for trust level management, revocation handling, attestation validation, and trust assertion issuance.

**Auditor**: An authorized party performing cryptographic audits and compliance inspections.

**External Integrator**: A third-party system interfacing via approved extension or gateway APIs without violating mandatory security constraints.

### 2.2 Technical Definitions

**Adjacent-Major Compatibility (AMC)**: A versioning constraint permitting interoperability across exactly one major version gap (N ↔ N+1) but prohibiting compatibility across two or more major version gaps.

**Trust Level**: A hierarchical security classification defining the strength of cryptographic verification and operational constraints between federation partners.

**Device Identity**: A unique cryptographic identity bound to a specific client device, comprising public/private key pairs and associated certificates.

**Session Key**: An ephemeral cryptographic key used for a specific communication session with automatic rotation and forward secrecy properties.

**Federation Link**: A persistent, mutually authenticated communication channel between two federation servers.

**Trust Certificate**: A cryptographically signed assertion establishing trust relationships and permitted operations between federation servers.

**Message Envelope**: The encrypted outer structure containing routing information and encrypted payload data.

**Conversation Context**: The cryptographic and operational state associated with a specific communication thread between devices.

**Transcript Hash**: A BLAKE3 hash over canonical handshake messages used for downgrade resistance and transcript binding.

**Hash Chain**: A sequence linkage mechanism using `prev_message_hash` to enforce message ordering and detect tampering.

**Canonical Serialization**: Deterministic and injective encoding ensuring identical binary representation across implementations.

**Domain Separation Label**: Mandatory HKDF context labels beginning with "norc:" to prevent cross-protocol key derivation attacks.

### 2.3 Trust Level Hierarchy

The protocol supports the following trust levels in ascending order of security requirements:

1. **Untrusted**: No established trust relationship; communication prohibited
2. **Basic**: Domain verification sufficient; standard business relationships
3. **Verified**: Organizational verification required; enhanced assurance relationships
4. **Classified**: Government/enterprise PKI required; security-cleared environments
5. **NATO**: NATO-level security clearance; international security cooperation

Each trust level imposes progressively stricter requirements for certificate authority validation, key algorithm and strength requirements, background verification procedures, compliance standard adherence, and audit trail granularity.

### 2.4 Normative Language

This specification uses the key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" as defined in RFC 2119 and RFC 8174.

---

## 3. Protocol Overview

### 3.1 Architecture Layers

NORC employs a three-layer architecture with clear separation of concerns:

#### 3.1.1 NORC-C (Client Layer)

The client layer handles:
- Device registration and authentication
- End-to-end message encryption and decryption
- User interface and application logic
- Local key management and storage
- Presence and status management

#### 3.1.2 NORC-F (Federation Layer)

The federation layer handles:
- Encrypted message routing between organizations
- Trust relationship enforcement
- Load balancing and performance optimization
- Federation discovery and health monitoring
- Audit trail generation for routing decisions

#### 3.1.3 NORC-T (Trust Layer)

The trust layer handles:
- Trust certificate issuance and management
- Trust level verification and enforcement
- Revocation and emergency response
- Compliance policy enforcement
- Cryptographic audit trail maintenance

### 3.2 Communication Flows

#### 3.2.1 Intra-Organization Communication

```
[Device A] ──encrypted──> [Federation Server] ──encrypted──> [Device B]
    │                           │                               │
    └─── E2E encrypted payload ─┴─── routing metadata only ─────┘
```

#### 3.2.2 Inter-Organization Communication

```
[Device A] ──> [Fed Server A] ──trust-verified──> [Fed Server B] ──> [Device B]
   Org 1           Org 1                              Org 2          Org 2
    │                 │                                 │              │
    └── E2E encrypted payload (servers cannot decrypt) ─┴──────────────┘
```

### 3.3 Message Processing Pipeline

1. **Message Creation**: Client encrypts payload with session keys
2. **Envelope Construction**: Client creates message envelope with routing metadata
3. **Server Routing**: Federation server validates trust and routes envelope
4. **Delivery**: Target federation server delivers envelope to recipient client
5. **Decryption**: Recipient client decrypts and processes message

### 3.4 Formal Handshake and Key Schedule

#### 3.4.1 Handshake Transcript

Let a client device be `C` and server `S`. Identity key pairs (Ed25519) are `(IKc_pk, IKc_sk)` and `(IKs_pk, IKs_sk)`. Ephemeral X25519 pairs `(EKc_pk, EKc_sk)`, `(EKs_pk, EKs_sk)` are freshly generated per session.

**Message Sequence**:
1. `ClientHello`: versions list `V_c`, capability list `Cap_c` (ordered), nonce `Nc`, `EKc_pk`, optional `PQc_pk`
2. `ServerHello`: selection `v* = max(V_c ∩ V_s)` under AMC, ordered `Cap_s`, nonce `Ns`, `EKs_pk`, optional `PQs_pk`
3. Transcript hash: `th = BLAKE3(canonical(ClientHello) || canonical(ServerHello))`
4. Shared secret derivation:
   - Classical: `ss_ecdh = X25519(EKc_sk, EKs_pk)`
   - Hybrid (if negotiated): `ss = ss_ecdh || ss_pq` else `ss = ss_ecdh`
5. Master secret: `ms = HKDF-BLAKE3(Nc || Ns, ss, "norc:ms:v1" || th, 32)`
6. Directional traffic keys:
   - `k_c2s = HKDF-BLAKE3(ms, 0, "norc:tk:c2s:v1", 32)`
   - `k_s2c = HKDF-BLAKE3(ms, 0, "norc:tk:s2c:v1", 32)`

#### 3.4.2 Domain Separation

All HKDF invocations MUST use labels beginning with `"norc:"` to prevent cross-protocol collisions. Unrecognized labels MUST cause connection abort.

### 3.5 Trust Establishment Flow

1. **Certificate Request**: Organization requests trust certificate from authority
2. **Verification**: Trust authority validates organization credentials for target trust level
3. **Certificate Issuance**: Trust authority issues cryptographically signed certificate
4. **Federation Configuration**: Organizations configure federation servers with trust certificates
5. **Trust Enforcement**: All inter-organization communication validated against trust certificates

---

## 4. Data Structures and Message Formats

### 4.1 Message Format Overview

All NORC messages use canonical binary encoding with the following general structure:

```
NORC Message := Version || Type || Length || Payload || Signature
```

### 4.2 Core Data Types

#### 4.2.1 Primitive Types

```
uint8   := 8-bit unsigned integer
uint16  := 16-bit unsigned integer (big-endian)
uint32  := 32-bit unsigned integer (big-endian)
uint64  := 64-bit unsigned integer (big-endian)
bytes   := length-prefixed byte array (uint32 length + data)
string  := UTF-8 encoded length-prefixed byte array
```

#### 4.2.2 Cryptographic Types

```
PublicKey    := bytes[32]     // Ed25519 public key
PrivateKey   := bytes[64]     // Ed25519 private key (32-byte secret + 32-byte public)
Signature    := bytes[64]     // Ed25519 signature
Hash         := bytes[32]     // BLAKE3 hash
SymmetricKey := bytes[32]     // ChaCha20 key
Nonce        := bytes[12]     // ChaCha20-Poly1305 nonce
MAC          := bytes[16]     // Poly1305 authentication tag
```

#### 4.2.3 Identity Types

```
DeviceID  := Hash             // BLAKE3 hash of device public key
UserID    := string           // Organization-local user identifier
OrgID     := string           // DNS-based organization identifier
ConvID    := Hash             // Conversation identifier
MessageID := Hash             // Unique message identifier
```

### 4.3 Protocol Messages

#### 4.3.1 Message Header

All NORC messages begin with a common header:

```
MessageHeader := {
    version:     uint8,          // Protocol version number
    layer:       uint8,          // Protocol layer (C=1, F=2, T=3)
    message_type: uint8,         // Message type within layer
    flags:       uint8,          // Message flags
    length:      uint32,         // Total message length including header
    timestamp:   uint64,         // Unix timestamp in milliseconds
    message_id:  MessageID,      // Unique message identifier
}
```

#### 4.3.2 Client Layer Messages (NORC-C)

**Device Registration Message**:
```
DeviceRegistration := {
    header:           MessageHeader,
    device_public_key: PublicKey,
    user_id:          UserID,
    device_info:      string,        // Device description/model
    capabilities:     uint32,        // Supported feature flags
    signature:        Signature,     // Self-signed with device private key
}
```

**Encrypted Message**:
```
EncryptedMessage := {
    header:       MessageHeader,
    sender_id:    DeviceID,
    recipient_id: DeviceID,
    conversation: ConvID,
    sequence:     uint64,            // Message sequence number
    encrypted_payload: bytes,        // ChaCha20-Poly1305 encrypted content
    signature:    Signature,         // Ed25519 signature
}
```

**Presence Update**:
```
PresenceUpdate := {
    header:    MessageHeader,
    device_id: DeviceID,
    status:    uint8,               // 0=offline, 1=online, 2=away, 3=busy
    message:   string,              // Optional status message
    timestamp: uint64,              // Last activity timestamp
    signature: Signature,
}
```

#### 4.3.3 Federation Layer Messages (NORC-F)

**Federation Handshake**:
```
FederationHandshake := {
    header:              MessageHeader,
    sender_org:          OrgID,
    recipient_org:       OrgID,
    supported_versions:  []uint8,
    trust_certificate:   bytes,
    server_public_key:   PublicKey,
    challenge:           bytes[32],
    signature:           Signature,
}
```

**Route Message**:
```
RouteMessage := {
    header:        MessageHeader,
    source_org:    OrgID,
    dest_org:      OrgID,
    envelope:      bytes,           // Encrypted message envelope
    routing_hints: []string,        // Optional routing optimization hints
    ttl:           uint8,           // Time-to-live hop count
    signature:     Signature,
}
```

#### 4.3.4 Trust Layer Messages (NORC-T)

**Trust Certificate**:
```
TrustCertificate := {
    header:         MessageHeader,
    issuer:         OrgID,
    subject:        OrgID,
    trust_level:    uint8,
    valid_from:     uint64,         // Unix timestamp
    valid_until:    uint64,         // Unix timestamp
    permitted_ops:  uint32,         // Bitmask of allowed operations
    extensions:     []Extension,    // Additional certificate data
    signature:      Signature,      // Signed by issuer
}
```

**Trust Revocation**:
```
TrustRevocation := {
    header:           MessageHeader,
    issuer:           OrgID,
    revoked_subject:  OrgID,
    revocation_time:  uint64,
    reason:           uint8,        // Revocation reason code
    signature:        Signature,
}
```

#### 4.3.5 Cryptographic Coverage of Message Fields (Req: T-S-F-01.03.01.11/12, T-S-F-02.05.01.13)

This subsection defines, for each core message category, which fields are covered by digital signatures and which are protected (confidentiality + integrity) inside AEAD payloads. Implementers MUST NOT diverge; adding fields to the signature base without an extension risks interoperability failure.

| Message Type | Signed (Ed25519) Fields | AEAD Confidential Fields | Notes |
|--------------|-------------------------|--------------------------|-------|
| DeviceRegistration | Entire structure except `signature` (canonical encoding) | None (all public) | Self-signed bootstrap identity |
| EncryptedMessage | Header, sender_id, recipient_id, conversation, sequence, ciphertext length metadata | `encrypted_payload` (full) | Payload includes inner plaintext length & padding marker |
| PresenceUpdate | All top-level fields except `signature` | None | Presence content intentionally plaintext to routing scope |
| RouteMessage (Federation) | header, source_org, dest_org, envelope hash, ttl | `envelope` (opaque to federation) | Envelope integrity enforced end-to-end by inner signature |
| TrustCertificate | All fields except `signature` | Extensions MAY embed AEAD sub-blobs | Certificate is published artifact |
| TrustRevocation | All fields except `signature` | None | Fast verification prioritized |

Signature Canonicalization:
1. Fields are serialized in the order defined in their structure, without optional-field reordering.
2. Length fields (if present) are included exactly as encoded.
3. Implementations MUST reject messages where the serialized bytes used for signature verification differ from re-serialization of parsed structures (prevents malleability via alternate encodings).

AEAD Associated Data (AAD) (Req: T-S-F-01.03.01.12):
* MUST include: protocol version, message_type, conversation (if applicable), sequence (if present), and a 32-byte transcript/context hash (`th` if from handshake or chain hash for message sequences) – exact layout: `AAD = version || message_type || context_fields || th`.
* Any deviation in AAD composition MUST result in decryption failure; AAD composition MUST be documented in implementation conformance notes (Req: T-S-F-01.03.01.12).

Rationale: Explicit partitioning prevents ambiguity (e.g., header-only vs full-structure signing) and simplifies formal analysis (transcript binding & downgrade prevention rely on deterministic coverage).

### 4.4 Encrypted Payload Formats

#### 4.4.1 Message Content

```
MessageContent := {
    content_type: uint8,            // MIME-style content type
    metadata:     []KeyValue,       // Encrypted metadata pairs
    body:         bytes,            // Encrypted message body
}
```

#### 4.4.2 File Transfer

```
FileTransfer := {
    file_id:      Hash,
    file_name:    string,           // Encrypted filename
    file_size:    uint64,
    mime_type:    string,           // Encrypted MIME type
    chunk_size:   uint32,
    total_chunks: uint32,
    chunk_data:   bytes,            // Encrypted file chunk
    chunk_hash:   Hash,             // BLAKE3 hash of decrypted chunk
}
```

### 4.5 Binary Wire Format

NORC messages use the following binary format:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
├─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┤
│  Ver  │   Type    │            Length (ciphertext)            │
├─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┤
│                          Message ID (128)                     │
├─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┤
│                      Sequence Number (64)                     │
├─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┤
│                   Prev Message Hash (256 bits)                │
├─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┤
│                         Ciphertext …                          │
└───────────────────────────────────────────────────────────────┘
```

### 4.6 Message Type Registry

**NORC-C Message Types**:
- `0x00` - Connection Request (version negotiation)
- `0x01` - Connection Accepted (version confirmation)
- `0x02` - Device Register
- `0x03` - Authentication Request
- `0x04` - Authentication Response
- `0x05` - Device Revocation
- `0x10` - Message Send
- `0x11` - Message Acknowledgment
- `0x20` - Presence Update
- `0x30` - Key Request
- `0x31` - Key Response
- `0x32` - Session Key Exchange
- `0x33` - Time Synchronization
- `0x40` - File Manifest

**NORC-F Message Types**:
- `0x70` - Federation Hello
- `0x71` - Federation Hello Response
- `0x80` - Message Relay
- `0x81` - Delivery Acknowledgment
- `0x90` - Server Discovery
- `0x91` - Server Information

**NORC-T Message Types**:
- `0x9F` - Trust Capabilities
- `0xA0` - Trust Request
- `0xA1` - Trust Challenge
- `0xA2` - Trust Response
- `0xA3` - Trust Revocation

### 4.7 Serialization Rules

1. **Canonical Encoding**: All messages MUST use deterministic canonical encoding
2. **Field Ordering**: Structure fields MUST appear in the order specified
3. **Padding**: Variable-length fields MUST be padded to hide true lengths where required
4. **Reserved Fields**: All reserved fields MUST be set to zero
5. **Extension Points**: Unknown fields MUST be ignored for forward compatibility
6. **Big-Endian**: Multi-byte integers MUST use big-endian byte ordering
7. **UTF-8**: Text fields MUST use UTF-8 encoding without BOM

### 4.8 Size Limits and Padding Strategy

#### 4.8.1 Message Size Constraints
1. **Interactive Message Payload**: Encrypted payload size (ciphertext, excluding transport framing) MUST NOT exceed 4 MiB. Larger content MUST use `FileTransfer` chunking.
2. **File Chunk Size**: `chunk_size` MUST be ≤ 1 MiB (recommended default 256 KiB) to limit retransmission cost.
3. **Header Size**: Core header (pre-payload fields) MUST NOT exceed 512 bytes.
4. **Aggregate Burst**: Implementations SHOULD apply flow control if a single device submits > 10 MiB of unacknowledged ciphertext within a 5 second window.

#### 4.8.2 Padding Buckets
1. **Bucket Set**: Default interactive padding buckets: {1KB, 2KB, 4KB, 8KB, 16KB, 32KB, 64KB, 128KB, 256KB}.
2. **Selection Rule**: Ciphertext length after padding MUST be the smallest bucket ≥ (plaintext_length + AEAD overhead + length_field).
3. **Randomized Overshoot (Optional)**: Implementations MAY add one additional random bucket step (≤ 1 level higher) for traffic analysis resistance; MUST record flag internally (not transmitted).
4. **Removal**: Padding MUST be unambiguously removed via explicit encoded plaintext length field inside the protected payload.

#### 4.8.3 Timing Obfuscation
1. **Send Jitter**: Implementations SHOULD introduce randomized delay (0–30ms) for non-urgent interactive messages to reduce temporal correlation.
2. **Batching Window**: Federation servers MAY batch up to 5ms worth of outbound messages per destination without violating latency targets.

#### 4.8.4 Interoperability
1. **Capability Advertisement**: Supported padding bucket profiles MUST be advertised in capability lists; negotiation selects intersection.
2. **Fallback**: If no common bucket profile exists, parties fall back to unpadded (minimum length) mode only for Basic trust level; higher trust levels MUST abort.

#### 4.8.5 Security Considerations
Padding MUST avoid deterministic timing signals; size normalization reduces passive traffic analysis while preserving performance. Excessive padding SHOULD be configurable to balance cost vs privacy.

---

## 5. State Machines and Interactions

### 5.1 Device Lifecycle State Machine

```
┌─────────────┐    register     ┌─────────────┐    activate    ┌─────────────┐
│ Unregistered├────────────────>│ Registered  ├───────────────>│   Active    │
└─────────────┘                 └─────────────┘                └──────┬──────┘
                                                                      │
                                                               suspend│
                                                                      ▼
┌─────────────┐    revoke       ┌─────────────┐    resume     ┌─────────────┐
│   Revoked   │<────────────────┤  Suspended  │<──────────────┤  Suspended  │
└─────────────┘                 └─────────────┘               └─────────────┘
```

#### 5.1.1 State Descriptions

- **Unregistered**: Device has no valid cryptographic identity
- **Registered**: Device has valid identity but is not authorized for communication
- **Active**: Device is fully operational and can send/receive messages
- **Suspended**: Device is temporarily disabled but retains cryptographic identity
- **Revoked**: Device identity has been permanently revoked and cannot be restored

#### 5.1.2 State Transitions

**Registration**:
1. Device generates Ed25519 key pair
2. Device constructs DeviceRegistration message
3. Organization Authority validates and approves registration
4. Device transitions to Registered state

**Activation**:
1. Organization Authority authorizes device for communication
2. Device receives activation confirmation
3. Device transitions to Active state

**Suspension**:
1. Administrative action or security policy triggers suspension
2. Device loses communication privileges but retains identity
3. Device may resume from suspension

**Revocation**:
1. Security incident or administrative action triggers revocation
2. Device identity is permanently invalidated
3. All cryptographic material must be destroyed
4. New registration required for device reactivation

### 5.2 Federation Link State Machine

```
┌─────────────┐    establish    ┌─────────────┐    verify     ┌─────────────┐
│ Disconnected├────────────────>│ Connecting  ├──────────────>│ Connected   │
└─────────────┘                 └─────────────┘               └──────┬──────┘
      ▲                                                              │
      │                                                       failure│
      │          ┌─────────────┐    timeout      ┌─────────────┐     │
      └──────────┤   Failed    │<────────────────┤  Degraded   │<────┘
                 └─────────────┘                 └─────────────┘
```

#### 5.2.1 State Descriptions

- **Disconnected**: No active federation link exists
- **Connecting**: Handshake and trust verification in progress
- **Connected**: Full operational federation link established
- **Degraded**: Operational but experiencing performance or reliability issues
- **Failed**: Federation link has failed and requires manual intervention

#### 5.2.2 Federation Handshake Protocol

1. **Initial Contact**: Initiating server sends FederationHandshake with trust certificate
2. **Trust Verification**: Receiving server validates trust certificate and trust level compatibility
3. **Challenge-Response**: Mutual authentication using cryptographic challenges
4. **Key Agreement**: Establish secure communication channel for federation messages
5. **Health Monitoring**: Begin continuous link health monitoring

### 5.3 Message Processing State Machine

```
┌─────────────┐    receive      ┌─────────────┐    validate   ┌─────────────┐
│   Pending   │<────────────────┤   Received  ├──────────────>│  Validated  │
└─────────────┘                 └─────────────┘               └──────┬──────┘
      │                                 │                            │
      │invalid                          │                            │route
      ▼                                 ▼                            ▼
┌─────────────┐                 ┌─────────────┐              ┌─────────────┐
│  Rejected   │                 │   Failed    │              │  Delivered  │
└─────────────┘                 └─────────────┘              └─────────────┘
```

#### 5.3.1 Message Validation Process

1. **Format Validation**: Verify message structure and encoding
2. **Signature Verification**: Validate cryptographic signatures
3. **Trust Verification**: Confirm sender trust level authorization
4. **Freshness Check**: Verify message timestamps and replay protection
5. **Content Validation**: Decrypt and validate payload (client only)

### 5.4 Trust Relationship Management

#### 5.4.1 Trust Establishment

1. **Certificate Request**: Organization submits trust certificate request
2. **Verification Process**: Trust authority validates organizational credentials
3. **Certificate Issuance**: Cryptographically signed trust certificate generated
4. **Distribution**: Certificate distributed to federation infrastructure
5. **Activation**: Trust relationship becomes operational

#### 5.4.2 Trust Revocation

1. **Revocation Decision**: Security incident or policy change triggers revocation
2. **Revocation Certificate**: Cryptographically signed revocation generated
3. **Emergency Distribution**: Revocation distributed within 300 seconds
4. **Connection Termination**: All active connections immediately terminated
5. **Audit Trail**: Complete revocation process recorded in audit logs

##### 5.4.2.1 Revocation Distribution Protocol

To satisfy the 300-second federation-wide revocation propagation requirement, federation servers MUST implement:

1. **Primary Push Channel**: A persistent authenticated channel (e.g., mTLS WebSocket or HTTP/2 stream) subscribed to revocation events from trusted peers.
2. **Fallback Polling**: Polling of peer revocation endpoints at an interval ≤ 60 seconds when the push channel is unavailable.
3. **Revocation Event Format**:
```
RevocationEvent := {
    revocation_id: Hash,              // Unique identifier (BLAKE3)
    sequence_number: uint64,          // Monotonic per issuer
    issuer: OrgID,
    revoked_subject: OrgID,
    reason_code: uint8,
    issued_at: uint64,                // Unix ms
    signature: Signature              // Issuer Ed25519 signature
}
```
4. **Acknowledgment**: Receiving servers MUST ack with `revocation_id`, local receipt timestamp, and signature.
5. **Propagation Timing**: Servers MUST measure `(receipt_time - issued_at)` and log warning if > 300,000 ms.
6. **Idempotency**: Duplicate `revocation_id` events MUST NOT trigger repeated disconnect logic.
7. **Enforcement Point**: Upon receipt, servers MUST immediately terminate active sessions and reject new handshakes involving the revoked subject.
8. **Failure Handling**: If a peer fails to acknowledge within 300 seconds, an audit log entry with severity=ERROR MUST be generated.
9. **Replay Protection**: Lower `sequence_number` than latest observed for an issuer MUST be discarded (audit severity=INFO).
10. **Clock Skew**: If `issued_at` is > 300 seconds in the future relative to local time, event is quarantined and retried after time sync.

Security considerations: Revocation messages rely on authenticity (signature) and freshness (sequence_number + issued_at). Compromise of a federation server cannot retroactively suppress revocations already disseminated.

---

## 6. Error Handling

### 6.1 Error Classification

NORC errors are classified into the following categories:

#### 6.1.1 Protocol Errors (1xx)

- **100 - Protocol Version Mismatch**: Incompatible protocol versions
- **101 - Message Format Error**: Malformed message structure
- **102 - Unsupported Feature**: Requested feature not implemented
- **103 - Sequence Error**: Message out of sequence or duplicate

#### 6.1.2 Authentication Errors (2xx)

- **200 - Authentication Failed**: Invalid credentials or signature verification failed
- **201 - Device Not Registered**: Device identity not recognized
- **202 - Device Revoked**: Device access has been revoked
- **203 - Session Expired**: Authentication session has expired

#### 6.1.3 Authorization Errors (3xx)

- **300 - Insufficient Trust Level**: Operation requires higher trust level
- **301 - Trust Relationship Missing**: No trust relationship exists
- **302 - Trust Certificate Invalid**: Trust certificate validation failed
- **303 - Operation Not Permitted**: Requested operation not allowed

#### 6.1.4 Routing Errors (4xx)

- **400 - Destination Unreachable**: Cannot route to destination organization
- **401 - Federation Link Down**: Required federation link unavailable
- **402 - Message Too Large**: Message exceeds size limits
- **403 - TTL Exceeded**: Message hop count exceeded maximum

#### 6.1.5 Server Errors (5xx)

- **500 - Internal Server Error**: Unexpected server failure
- **501 - Service Unavailable**: Server temporarily unavailable
- **502 - Resource Exhausted**: Server resource limits exceeded
- **503 - Maintenance Mode**: Server undergoing maintenance

### 6.2 Error Response Format

```
ErrorResponse := {
    header:       MessageHeader,
    error_code:   uint16,           // Error code from classifications above
    error_msg:    string,           // Human-readable error description
    retry_after:  uint32,           // Suggested retry delay in seconds (optional)
    details:      []KeyValue,       // Additional error context
    timestamp:    uint64,           // Error occurrence timestamp
}
```

### 6.3 Error Handling Procedures

#### 6.3.1 Client Error Handling

1. **Retry Logic**: Implement exponential backoff for transient errors
2. **User Notification**: Provide clear error messages for user-actionable errors
3. **Fallback Behavior**: Graceful degradation when possible
4. **Error Reporting**: Log errors for debugging and support

#### 6.3.2 Server Error Handling

1. **Error Propagation**: Forward appropriate errors to clients
2. **Recovery Procedures**: Automatic recovery for transient failures
3. **Circuit Breaking**: Prevent cascade failures through rate limiting
4. **Monitoring Integration**: Alert administrators of critical errors

#### 6.3.3 Federation Error Handling

1. **Link Failure Recovery**: Automatic retry with alternative routes
2. **Trust Errors**: Immediate connection termination for trust violations
3. **Load Balancing**: Redirect traffic from failed servers
4. **Audit Logging**: Record all error conditions for analysis

### 6.4 Graceful Degradation

#### 6.4.1 Partial Connectivity

When full federation connectivity is unavailable:
1. Queue messages for delayed delivery
2. Provide store-and-forward capability
3. Maintain local communication functionality
4. Notify users of degraded service

#### 6.4.2 Trust Level Downgrades

When higher trust levels become unavailable:
1. Maintain communication at lower trust levels
2. Clearly indicate degraded security status
3. Provide upgrade path when trust is restored
4. Log all trust level changes

---

## 7. Security Considerations

### 7.1 Cryptographic Requirements

#### 7.1.1 Mandatory Algorithms

All NORC implementations MUST support the following cryptographic algorithms:

**Digital Signatures**: Ed25519
- Key size: 256 bits
- Signature size: 512 bits
- Security level: 128 bits classical, quantum-vulnerable

**Key Agreement**: X25519 (mandatory) + Kyber768 (post-quantum hybrid)
- Classical: Curve25519 elliptic curve Diffie-Hellman
- Post-quantum: Kyber768 lattice-based key encapsulation
- Combined security: Secure if either algorithm remains unbroken

**Symmetric Encryption**: ChaCha20-Poly1305
- Key size: 256 bits
- Nonce size: 96 bits
- Authentication tag: 128 bits
- Provides authenticated encryption with associated data (AEAD)

**Hash Functions**: BLAKE3
- Output size: 256 bits (configurable)
- Security level: 128 bits
- Performance: Optimized for modern CPU architectures

**Key Derivation**: HKDF-BLAKE3
- Extract-and-expand paradigm
- Domain separation through labels
- Suitable for deriving multiple keys from shared secrets

#### 7.1.2 Security Levels by Trust Level

The table below expresses target effective security strength (classical) and additional posture requirements. "256-bit" here denotes a symmetric security goal (e.g., 256-bit AEAD keys / resistance horizon for long‑term archival) rather than implying that all asymmetric primitives already provide 256-bit classical strength.

| Trust Level | Target Symmetric Strength | Required Algorithms (Minimum) | Additional Requirements |
|-------------|---------------------------|-------------------------------|-------------------------|
| Basic | ≥128-bit | Ed25519, X25519, ChaCha20-Poly1305 (or AES-256-GCM), BLAKE3 (or SHA-256) | Hybrid PQ OPTIONAL (opportunistic) |
| Verified | ≥128-bit + Hybrid | + Kyber768 (ML-KEM-768) hybrid with X25519 | Hybrid MANDATORY; downgrade prohibited |
| Classified | ≥256-bit retention goal | Verified set + FIPS 140-2/140-3 validated modules | HSM / hardware isolation RECOMMENDED |
| NATO | ≥256-bit retention goal | Classified set | Jurisdiction / CNSA 2.0 / national profile extensions (via capability flags) |

#### 7.1.3 Algorithm Agility and Alternatives (Req: T-S-F-02.05.01.10/13)

NORC defines a mandatory baseline while permitting controlled substitution:

| Primitive Category | Mandatory Baseline | Approved Alternatives (Negotiated) | Notes |
|--------------------|--------------------|------------------------------------|-------|
| Digital Signatures | Ed25519 | Ed448 (future), PQ (Dilithium/Falcon – roadmap) | PQ signatures introduced via extension once standardized |
| Key Agreement | X25519 (+ Kyber768 hybrid for Verified+) | X25519-only (Basic fallback); Future PQ KEM variants | Verified+ MUST use hybrid; downgrade prohibited |
| Symmetric AEAD | ChaCha20-Poly1305 | AES-256-GCM (FIPS / HW acceleration) | Both sides advertise support flags |
| Hash / KDF | BLAKE3 / HKDF-BLAKE3 | SHA-256 / HKDF-SHA-256 (FIPS) | Domain separation labels MUST start with "norc:" |

Algorithm negotiation rules:
1. Peers exchange ordered capability lists during initial handshake (ClientHello / ServerHello).
2. Strongest mutually supported tuple selected; MUST prefer hybrid over classical-only when trust level ≥ Verified.
3. If both parties support both ChaCha20-Poly1305 and AES-256-GCM, selection order is implementation-defined but MUST be deterministic (e.g., lexicographic priority list) and transcript-bound.
4. Attempts to force a weaker suite when a stronger mutually supported suite exists MUST abort with a downgrade error.
5. PQ signature adoption WILL occur under an extension flag `ext.pq_sig.v1` with separate interoperability test vectors.
6. Unsupported alternative algorithms MUST be ignored without side effects.
 7. Deterministic Preference Ordering: Implementations MUST apply the following ordered comparison when constructing the final suite to ensure both sides derive the same “best” set (Req: T-S-F-02.05.01.10):
     a. Hybrid vs Classical: Hybrid (X25519+Kyber768) > Classical-only.
     b. AEAD Strength: ChaCha20-Poly1305 vs AES-256-GCM – if both available, choose the one appearing first in the initiator’s advertised preference list; responder MUST mirror.
     c. Hash/KDF: BLAKE3 preferred over SHA-256 unless in declared FIPS mode; if FIPS mode is active for either side, SHA-256 MUST be selected.
     d. Signature: (During PQ transition phase) Dual-sign (Ed25519+PQ) > Ed25519-only.
     e. Tie-break: Lexicographic comparison of the canonical capability tuple string.
 8. Transcript Binding: The chosen capability tuple string (e.g., `ALGSET:v1|sig=ed25519|kem=x25519+mlkem768|aead=chacha20poly1305|hash=blake3`) MUST be concatenated into the handshake transcript hash prior to master secret derivation (Req: T-S-F-02.05.01.13).
 9. Ambiguity Handling: If both parties compute different preferred tuples locally, the responder MUST send an abort with a DOW N GRADE_DETECTED alert (implementation detail) and no application data SHALL flow.

#### 7.1.4 HKDF-BLAKE3 Construction (Non-FIPS Mode) (Req: T-S-F-02.05.01.11)

NORC uses HKDF semantics. In non-FIPS mode an instantiation with BLAKE3 is permitted for performance. Because RFC 5869 specifies HKDF over HMAC, this document defines a compatible extract/expand interface using BLAKE3's keyed mode.

Definitions:
```
HKDF-BLAKE3-Extract(salt, IKM) = BLAKE3(key=salt_or_zero(salt), data=IKM)
    where salt_or_zero(salt) = salt if provided else 32 bytes of 0x00

HKDF-BLAKE3-Expand(PRK, info, L):
    N = ceil(L / 32)
    T(0) = empty
    For i in 1..N:
        T(i) = BLAKE3(key=PRK, data=T(i-1) || info || uint8(i))
    return first L bytes of T(1) || T(2) || ... || T(N)
```

Usage:
1. The label (info) MUST begin with "norc:" and SHOULD include a version token (e.g., `norc:ms:v1`).
2. Salt MUST be present for master secret derivation (concatenated nonces) but MAY be omitted (replaced by zeros) for subsequent traffic key expansions when PRK already has high entropy.
3. Output length L MUST NOT exceed 255 * 32 bytes (HKDF bound).

FIPS Mode:
* When operating in FIPS-constrained environments implementations MUST substitute HKDF-HMAC-SHA-256 for HKDF-BLAKE3 (Req: T-S-F-02.05.01.11/12). Capability negotiation MUST include an indicator (e.g., `cap.fips.hkdf.hmacsha256`). Mixed HKDF variants in one transcript MUST abort (Req: T-S-F-02.05.01.11).
* Mixed mode (one side FIPS HKDF, one side BLAKE3) is NOT permitted; absence of a common HKDF capability MUST abort the handshake.

Security Considerations:
* PRK confidentiality relies on BLAKE3 keyed mode PRF strength (assumed ≥128-bit). If future cryptanalysis weakens keyed BLAKE3, FIPS/HMAC instantiation SHOULD be preferred globally.
* Labels provide domain separation across distinct derivation contexts (handshake vs per-direction traffic keys vs key wrapping).

### 7.2 Key Management

#### 7.2.1 Key Generation

1. **Entropy Requirements**: All keys MUST be generated using cryptographically secure random number generators
2. **Key Independence**: Each device MUST generate independent key pairs
3. **Seed Diversity**: Key generation MUST use diverse entropy sources
4. **Hardware Support**: Hardware random number generators SHOULD be used when available

#### 7.2.2 Key Storage

1. **Device Keys**: Private keys MUST be stored in secure device storage
2. **Key Encryption**: Stored keys MUST be encrypted with device-specific keys
3. **Hardware Security**: Hardware security modules SHOULD be used for high-trust deployments
4. **Key Backup**: Secure key backup and recovery procedures MUST be defined

#### 7.2.3 Key Rotation

1. **Session Keys**: MUST be rotated automatically with configurable intervals
2. **Device Keys**: SHOULD be rotated periodically (recommended: annually)
3. **Federation Keys**: MUST be rotated when trust relationships change
4. **Emergency Rotation**: Immediate key rotation MUST be supported for security incidents

### 7.3 Forward Secrecy

#### 7.3.1 Session Key Management

1. **Ephemeral Keys**: Each conversation MUST use ephemeral session keys
2. **Key Derivation**: Session keys MUST be derived from fresh Diffie-Hellman exchanges
3. **Key Deletion**: Previous session keys MUST be securely erased after rotation
4. **Compromise Isolation**: Session key compromise MUST NOT affect other sessions

#### 7.3.2 Message Key Rotation

1. **Automatic Rotation**: Message keys MUST rotate after configurable message counts or time intervals
2. **Bidirectional Independence**: Send and receive keys MUST be independently managed
3. **Out-of-Order Protection**: The protocol MUST handle out-of-order message delivery
4. **Gap Recovery**: Missing messages MUST NOT prevent key advancement

#### 7.3.3 Periodic Re-Handshake (Long-Lived Sessions) (Req: T-S-F-02.03.01.05/06/07)

To reduce exposure window from latent key compromise, long-lived logical conversations SHOULD perform a fresh authenticated handshake (full ephemeral + transcript binding) at conservative intervals:

1. **Time Threshold**: Implementations SHOULD re-handshake after 60 minutes of continuous session activity.
2. **Message Threshold**: Implementations SHOULD re-handshake after 10,000 application messages (whichever comes first) within a conversation.
3. **Staggering**: Re-handshakes MUST randomize scheduling ±10% jitter to avoid synchronized load spikes.
4. **Fail-Open vs Fail-Safe**: If a scheduled re-handshake fails due to transient network issues, existing keys MAY be used for up to an additional 10 minutes before forcing termination.
5. **Auditability**: Each successful re-handshake MUST log prior session identifier, new session identifier, trigger cause (time/message), and negotiated algorithm tuple.
6. **Security Justification**: Periodic renewal narrows forensic uncertainty and limits the useful lifetime of any compromised traffic keys below the maximum retention assumptions (supports forward secrecy plus partial post‑compromise recovery).

### 7.4 Post-Quantum Cryptography

#### 7.4.1 Hybrid Approach

1. **Scope of Mandate**: For trust levels Verified, Classified, and NATO the key agreement MUST use a hybrid classical + post‑quantum KEM (currently X25519 + Kyber768). Basic level MAY negotiate hybrid; if both Basic peers advertise hybrid capability it SHOULD be selected. Any attempt to negotiate non‑hybrid when both peers (and the trust level policy) require hybrid MUST abort the handshake with a downgrade error.
2. **Independent Security**: Combined construction MUST preserve confidentiality if either the classical or the post‑quantum component remains secure.
3. **Algorithm Agility**: The protocol MUST support transitioning to successor post‑quantum KEMs (e.g., new ML-KEM parameter sets) via capability flags without violating AMC.
4. **Implementation Timeline**: Hybrid is MANDATORY immediately for Verified+ (Verified / Classified / NATO). Basic remains classical baseline with opportunistic hybrid.
5. **Standardization Status Note**: Kyber768 (standardized as ML-KEM-768) was selected in the NIST PQC process (Draft FIPS 203 as of 2025). Implementers MUST track final FIPS publication. If parameter/layout changes occur between draft and final, the draft variant MUST be advertised under a distinct capability identifier (e.g., `pq_kem.kyber768.draft`) separate from the finalized (`pq_kem.mlkem768.fips`) to avoid silent interoperability or security ambiguities.
6. **Capability Labeling**: Hybrid support MUST be explicitly advertised (e.g., `cap.hybrid.kem.v1`) and transcript-bound; absence of this label at Basic trust level permits classical-only fallback, but absence at Verified+ MUST terminate negotiation.

#### 7.4.2 Quantum-Safe Migration

1. **Gradual Transition**: Organizations MAY transition incrementally to post-quantum algorithms
2. **Backwards Compatibility**: Hybrid mode MUST maintain compatibility with classical-only implementations
3. **Algorithm Negotiation**: Clients and servers MUST negotiate the strongest mutually supported algorithm combination
4. **Future Algorithms**: The protocol MUST support adding new post-quantum algorithms without breaking changes

### 7.4.3 Key Wrapping and Derivation

Per-message key wrapping procedure:

1. Generate 256-bit `content_key` using cryptographically secure RNG
2. For each recipient device: ephemeral X25519 (or hybrid X25519+Kyber) → shared secret
3. `wrap_key = HKDF-BLAKE3(shared_secret, salt=BLAKE3(content_key)[0..31], info="norc:wrap:v1"||version||device_id, 32)`
4. `wrapped_content_key = ChaCha20-Poly1305-seal(wrap_key, nonce=first_96_bits(BLAKE3(device_id||message_id)), aad=AAD_meta, plaintext=content_key)`
5. Store `encrypted_keys[device_id] = wrapped_content_key`

For session establishment, replace `message_id` with `session_id` and use label `"norc:session:v1"`.


### 7.10 Time Synchronization

Servers MUST provide authenticated time synchronization:

```
TimeSync := {
    server_time:      uint64,       // Current server time (microseconds)
    uncertainty:      uint32,       // Time uncertainty in microseconds
    signature:        Signature,    // Ed25519 signature of time data
    ntp_stratum:      uint8,        // NTP stratum level (optional)
}
```

**Time Tolerance**:
- Authentication operations: ≤5 seconds skew
- Federation message delay: ≤60 seconds tolerance
- Servers SHOULD use authenticated NTP or Roughtime

### 7.11 Audit Trail Integrity

Audit log entries MUST be cryptographically chained:

```
entry_hash = BLAKE3(prev_hash || canonical_entry)
```

**Audit Requirements**:
- Daily root hash MAY be published for transparency
- No plaintext message content or private keys in logs
- User IDs MUST be HMAC-pseudonymized for privacy
- Chain integrity MUST be verifiable by auditors

### 7.12 Rate Limiting
**Per Device**:
- Messages: 60/minute (burst 120)
- Key lookups: 30/minute
- Registrations: 3/hour

**Federation Ingress (per remote server)**:
- Messages: 1000/minute
- Data: 100 MB per 5 minutes

Exceeding limits results in `ERR_RATE_LIMIT` with `retry_after` field.

### 7.13 Attack Resistance

#### 7.13.1 Replay Attack Prevention

1. **Message Uniqueness**: All messages MUST include unique identifiers and timestamps
2. **Sequence Numbers**: Conversation messages MUST use monotonically increasing sequence numbers
3. **Freshness Windows**: Servers MUST reject messages outside acceptable time windows
4. **Duplicate Detection**: Servers MUST detect and reject duplicate messages

#### 7.13.2 Man-in-the-Middle Prevention

1. **Mutual Authentication**: All communication channels MUST use mutual authentication
2. **Certificate Pinning**: Trust relationships MUST be established through out-of-band certificate verification
3. **Key Verification**: Device keys SHOULD be verified through out-of-band channels
4. **Trust Anchors**: Trust certificates MUST be anchored to well-known trust authorities

#### 7.13.3 Downgrade Attack Prevention

1. **Version Negotiation**: Protocol version negotiation MUST be cryptographically protected
2. **Algorithm Selection**: Cryptographic algorithm selection MUST prevent downgrade attacks
3. **Trust Level Enforcement**: Trust level requirements MUST NOT be bypassable
4. **Capability Advertisement**: Feature capabilities MUST be authenticated


### 7.13.4 Replay Protection (Consolidated)

Layered replay protection mechanisms:

1. **Session Level**: 64-bit sequence numbers starting from random 24-bit offset.
2. **Message Level**: Receiver sliding bitmap window (≥1024 entries) rejects duplicates.
3. **Federation Level**: Relay cache of `{origin_server, message_id}` with TTL ≤ 24h.
4. **Handshake Level**: 96-bit nonces + transcript hashing prevent negotiation replay.
5. **Timestamp Level**: Reject if `|local_time - message_time| > 300s`.

### 7.13.5 Message Ordering and Hash Chaining

Each encrypted message (except the first in a chain) MUST include:

* `sequence_number`: Monotonically increasing per conversation
* `prev_message_hash`: BLAKE3-256 hash of previous accepted message's canonical ciphertext
* Optional `chain_depth`: For rapid consistency verification

Gap Handling: MAY request retransmission.
Hash Mismatch: MUST discard message and flag integrity alert.

### 7.10 Metadata Protection

#### 7.10.1 Content Metadata

1. **Filename Encryption**: File names MUST be encrypted in file manifest structures
2. **MIME Type Protection**: Content types MUST be encrypted with message content
3. **Size Obfuscation**: Message sizes SHOULD be padded to reduce correlation opportunities
4. **Timing Randomization**: Message timing SHOULD be randomized within operational constraints

#### 7.10.2 Communication Metadata

1. **Routing Minimization**: Federation servers MUST have minimal access to routing metadata
2. **Traffic Analysis Resistance**: The protocol SHOULD resist traffic analysis where feasible
3. **Presence Privacy**: Presence information MUST be filtered based on trust relationships
4. **Audit Trail Protection**: Audit logs MUST protect sensitive metadata while enabling compliance

### 7.11 Canonical Serialization Rules

1. **Deterministic Encoding**: All messages MUST use deterministic canonical encoding
2. **Field Ordering**: Structure fields MUST appear in specification order
3. **Absent Fields**: Optional fields not present MUST be omitted entirely
4. **Binary Encoding**: Big-endian byte order for multi-byte integers
5. **String Encoding**: UTF-8 without BOM for all text fields
6. **Padding**: Cryptographic padding MUST use specified algorithms only

---

## 8. Privacy Considerations

### 8.1 Data Minimization

#### 8.1.1 Server Data Access

1. **Plaintext Prohibition**: Federation servers MUST NOT have access to message plaintext
2. **Metadata Minimization**: Servers MUST only access metadata necessary for routing and trust enforcement
3. **Audit Data Limitation**: Audit logs MUST NOT contain unnecessary personal information
4. **Retention Policies**: Data retention MUST be limited to operational and compliance requirements

#### 8.1.2 Cross-Organization Data Sharing

1. **Explicit Consent**: Cross-organization communication MUST require explicit user consent
2. **Purpose Limitation**: Data sharing MUST be limited to specified purposes
3. **Trust Level Alignment**: Data sensitivity MUST align with established trust levels
4. **Revocation Rights**: Users MUST be able to revoke consent and request data deletion

### 8.2 User Control

#### 8.2.1 Privacy Settings

1. **Granular Controls**: Users MUST have granular control over privacy settings
2. **Presence Management**: Users MUST control presence visibility per organization and trust level
3. **Data Sharing Preferences**: Users MUST be able to configure data sharing preferences
4. **Opt-Out Capabilities**: Users MUST be able to opt out of non-essential data processing

#### 8.2.2 Transparency

1. **Data Processing Disclosure**: Organizations MUST disclose all data processing activities
2. **Trust Relationship Visibility**: Users MUST be informed of active trust relationships
3. **Audit Access**: Users SHOULD have access to audit logs of their communications
4. **Policy Changes**: Users MUST be notified of privacy policy changes

### 8.3 Regulatory Compliance

#### 8.3.1 GDPR Compliance

1. **Lawful Basis**: Data processing MUST have appropriate lawful basis under GDPR
2. **Data Subject Rights**: The protocol MUST support data subject rights including access, rectification, and erasure
3. **Privacy by Design**: Privacy protection MUST be built into the protocol design
4. **Data Protection Impact Assessment**: High-risk deployments MUST conduct DPIAs

#### 8.3.2 Sectoral Privacy Requirements

1. **HIPAA**: Healthcare deployments MUST comply with HIPAA privacy and security requirements
2. **FERPA**: Educational deployments MUST protect student privacy per FERPA requirements
3. **Financial Privacy**: Financial services deployments MUST comply with applicable financial privacy regulations
4. **Government Privacy**: Government deployments MUST comply with jurisdiction-specific privacy requirements

### 8.4 Cross-Border Data Transfers

#### 8.4.1 Data Localization

1. **Geographic Restrictions**: Organizations MAY enforce geographic restrictions on data processing
2. **Local Storage**: Organizations MAY require data to be stored within specific jurisdictions
3. **Transit Restrictions**: Organizations MAY restrict data transit through specific countries
4. **Sovereignty Requirements**: Government deployments MUST comply with data sovereignty requirements

#### 8.4.2 International Frameworks

1. **Adequacy Decisions**: Cross-border transfers SHOULD leverage adequacy decisions where available
2. **Standard Contractual Clauses**: Transfers MAY use standard contractual clauses as appropriate
3. **Binding Corporate Rules**: Multi-national organizations MAY use binding corporate rules
4. **Certification Schemes**: Organizations MAY participate in relevant certification schemes

---

## 9. Performance and Scalability

### 9.1 Latency Requirements

#### 9.1.1 Message Delivery Latency

1. **End-to-End Target**: 95% of messages MUST be delivered within 500ms under normal conditions
2. **Intra-Organization**: Local messages SHOULD be delivered within 100ms
3. **Inter-Organization**: Federation adds maximum 100ms latency per hop
4. **Cryptographic Overhead**: Encryption/decryption MUST NOT add more than 50ms

#### 9.1.2 Connection Establishment

1. **Device Authentication**: MUST complete within 2 seconds
2. **Federation Handshake**: MUST complete within 5 seconds
3. **Trust Verification**: MUST complete within 3 seconds
4. **Session Key Agreement**: MUST complete within 1 second

### 9.2 Throughput Requirements

#### 9.2.1 Server Capacity

1. **Concurrent Connections**: Servers MUST support minimum 10,000 concurrent client connections
2. **Message Throughput**: Servers MUST support minimum 100,000 messages per minute
3. **Federation Throughput**: Federation links MUST support minimum 1,000 messages per minute per remote server
4. **File Transfer**: Large file transfers MUST support streaming with minimum 10 MB/s throughput

#### 9.2.2 Client Performance

1. **Message Processing**: Clients MUST process incoming messages within 100ms
2. **Encryption Performance**: Message encryption MUST complete within 10ms for typical messages
3. **Key Operations**: Key agreement operations MUST complete within 500ms
4. **UI Responsiveness**: User interface MUST remain responsive during cryptographic operations

### 9.3 Scalability Architecture

#### 9.3.1 Horizontal Scaling

1. **Stateless Design**: Federation servers SHOULD be designed for stateless horizontal scaling
2. **Load Balancing**: Multiple federation servers MUST support load balancing and failover
3. **Database Scaling**: Persistent storage MUST support horizontal scaling approaches
4. **Cache Distribution**: Distributed caching SHOULD be used for performance optimization

#### 9.3.2 Federation Scaling

1. **Mesh Architecture**: Federation SHOULD support mesh architectures for large deployments
2. **Routing Optimization**: Federation routing MUST support optimization for common communication patterns
3. **Regional Deployment**: Organizations SHOULD support regional server deployment for global scaling
4. **Traffic Shaping**: Federation links SHOULD support traffic shaping and prioritization

### 9.4 Resource Utilization

#### 9.4.1 Memory Management

1. **Linear Scaling**: Memory usage MUST scale linearly with active connections
2. **Connection Limits**: Configurable per-connection memory limits MUST be enforced
3. **Garbage Collection**: Memory management MUST not cause significant processing delays
4. **Resource Monitoring**: Real-time memory usage monitoring MUST be available

#### 9.4.2 CPU Utilization

1. **Normal Load**: CPU utilization MUST remain below 80% under normal load conditions
2. **Cryptographic Optimization**: Cryptographic operations MUST be optimized for target hardware
3. **Parallel Processing**: CPU-intensive operations SHOULD utilize parallel processing where possible
4. **Performance Monitoring**: Real-time CPU usage monitoring MUST be available

#### 9.4.3 Network Utilization

1. **Bandwidth Efficiency**: Protocol overhead MUST be minimized while maintaining security
2. **Compression**: Message compression SHOULD be used where beneficial
3. **Batching**: Message batching SHOULD be used to improve network efficiency
4. **Quality of Service**: QoS mechanisms SHOULD be supported for prioritizing critical traffic

### 9.5 Performance Monitoring

#### 9.5.1 Metrics Collection

1. **Latency Metrics**: End-to-end and component-level latency MUST be continuously measured
2. **Throughput Metrics**: Message and data throughput MUST be continuously measured
3. **Error Rates**: Error rates and failure modes MUST be tracked and analyzed
4. **Resource Metrics**: CPU, memory, and network utilization MUST be monitored

#### 9.5.2 Performance Alerting

1. **Threshold Monitoring**: Configurable performance thresholds MUST trigger alerts
2. **Trend Analysis**: Performance trend analysis SHOULD identify degradation before failure
3. **Capacity Planning**: Performance data MUST support capacity planning activities
4. **SLA Monitoring**: Service level agreement compliance MUST be continuously monitored

---

## 10. Interoperability and Versioning

### 10.1 Adjacent-Major Compatibility (AMC)

#### 10.1.1 Version Numbering

NORC uses semantic versioning (MAJOR.MINOR.PATCH) with special compatibility rules:

1. **MAJOR**: Introduces breaking changes, AMC applies
2. **MINOR**: Adds features while maintaining backward compatibility within major version
3. **PATCH**: Bug fixes and security updates, no feature changes

#### 10.1.2 AMC Implementation

1. **Compatibility Window**: Implementations MUST support exactly one major version gap (N ↔ N+1)
2. **Version Negotiation**: Clients and servers MUST negotiate the highest mutually supported version
3. **Feature Detection**: Implementations MUST gracefully handle unknown features
4. **Migration Timeline**: Major version transitions MUST provide 12-month overlap periods

#### 10.1.3 Version Negotiation Protocol

```
1. Client sends supported version range [min_version, max_version]
2. Server responds with selected version within AMC constraints
3. If no compatible version exists, connection is rejected
4. Both parties use selected version for all subsequent communication
```

### 10.2 Feature Negotiation

#### 10.2.1 Capability Advertisement

1. **Feature Flags**: Implementations MUST advertise supported features through feature flags
2. **Extension Registry**: Optional extensions MUST be registered in a central registry
3. **Graceful Degradation**: Implementations MUST gracefully handle unsupported features
4. **Feature Discovery**: Clients MUST be able to discover server capabilities

#### 10.2.2 Extension Mechanism

1. **Namespace Isolation**: Extensions MUST use namespaced identifiers to prevent conflicts
2. **Optional Behavior**: Extensions MUST NOT be required for basic protocol compliance
3. **Security Review**: Security-relevant extensions MUST undergo security review
4. **Interoperability Testing**: Extensions MUST be tested for interoperability impact

### 10.3 Implementation Requirements

#### 10.3.1 Conformance Levels

**Level 1 - Basic Conformance**:
- All mandatory protocol features
- Basic trust level support
- Standard cryptographic algorithms
- AMC version support

**Level 2 - Enhanced Conformance**:
- Post-quantum cryptography support
- Advanced trust levels (Verified, Classified)
- Performance optimization features
- Enhanced audit capabilities

**Level 3 - Full Conformance**:
- All optional features
- NATO trust level support
- Full extension framework
- Advanced federation features

#### 10.3.2 Interoperability Testing

1. **Test Vectors**: Standard test vectors MUST be provided for all protocol operations
2. **Conformance Suite**: Automated conformance testing MUST be available
3. **Interoperability Events**: Regular interoperability testing events SHOULD be conducted
4. **Certification Program**: Optional certification program MAY be established

### 10.4 Migration and Transition

#### 10.4.1 Version Migration

1. **Backward Compatibility**: New versions MUST maintain backward compatibility within AMC constraints
2. **Migration Tools**: Automated migration tools SHOULD be provided for major version transitions
3. **Gradual Rollout**: Version upgrades SHOULD support gradual rollout and rollback
4. **Emergency Updates**: Critical security updates MUST support rapid deployment

#### 10.4.2 Deployment Coordination

1. **Federation Coordination**: Multi-organization deployments MUST coordinate version transitions
2. **Testing Environment**: Separate testing environments MUST be maintained for version validation
3. **Rollback Procedures**: Rollback procedures MUST be tested and documented
4. **Communication Plan**: Version transition communication plans MUST be established

---

## 11. Conformance Requirements

### 11.1 Implementation Conformance

#### 11.1.1 Mandatory Features

All NORC implementations claiming conformance MUST implement:

1. **Protocol Layers**: All three protocol layers (NORC-C, NORC-F, NORC-T)
2. **Cryptographic Algorithms**: Ed25519, X25519, ChaCha20-Poly1305, BLAKE3
3. **Message Formats**: All core message types and data structures
4. **Security Features**: End-to-end encryption, device authentication, forward secrecy
5. **Trust Management**: Basic trust level support and certificate validation
6. **Version Support**: AMC-compliant version negotiation
7. **Error Handling**: Standard error codes and recovery procedures

#### 11.1.2 Optional Features

Implementations MAY optionally implement:

1. **Post-Quantum Cryptography**: Kyber768 hybrid key agreement
2. **Advanced Trust Levels**: Classified and NATO trust levels
3. **Performance Optimizations**: Batching, compression, caching
4. **Monitoring Integration**: Advanced monitoring and alerting
5. **Extension Framework**: Support for protocol extensions
6. **High Availability**: Clustering and failover capabilities

#### 11.1.3 Prohibited Behaviors

Conforming implementations MUST NOT:

1. **Bypass Security**: Implement optional security or plaintext fallbacks
2. **Break AMC**: Support version combinations outside AMC constraints
3. **Expose Plaintext**: Allow servers to access encrypted message content
4. **Violate Trust**: Allow communication outside established trust relationships
5. **Compromise Forward Secrecy**: Retain session keys after rotation
6. **Modify Standard Messages**: Alter standard message formats without proper extensions

### 11.2 Testing and Validation

#### 11.2.1 Conformance Testing

1. **Test Suite**: A comprehensive test suite MUST validate all mandatory features
2. **Interoperability Tests**: Cross-implementation testing MUST verify compatibility
3. **Security Tests**: Security properties MUST be validated through automated testing
4. **Performance Tests**: Performance requirements MUST be validated under realistic conditions
5. **Stress Tests**: Implementations MUST be tested under high load and failure conditions

#### 11.2.2 Test Vectors

1. **Cryptographic Vectors**: Standard test vectors MUST be provided for all cryptographic operations
2. **Message Vectors**: Example messages MUST be provided for all message types
3. **Protocol Flows**: Complete protocol interaction examples MUST be documented
4. **Error Scenarios**: Test cases MUST cover all error conditions and recovery procedures

#### 11.2.3 Security Validation

1. **Formal Verification**: Security properties SHOULD be formally verified where feasible
2. **Penetration Testing**: Implementations SHOULD undergo penetration testing
3. **Code Review**: Security-critical code SHOULD undergo independent security review
4. **Vulnerability Assessment**: Regular vulnerability assessments SHOULD be conducted

### 11.3 Certification and Compliance

#### 11.3.1 Conformance Certification

1. **Self-Declaration**: Implementers MAY self-declare conformance based on testing results
2. **Third-Party Validation**: Independent third-party validation MAY be sought
3. **Certification Marks**: Conformance certification marks MAY be used with proper authorization
4. **Compliance Matrix**: Detailed compliance matrices MUST be maintained and published

#### 11.3.2 Ongoing Compliance

1. **Version Updates**: Conformance MUST be maintained across supported protocol versions
2. **Security Updates**: Security patches MUST maintain conformance while addressing vulnerabilities
3. **Regression Testing**: Ongoing regression testing MUST verify continued conformance
4. **Audit Trail**: Compliance activities MUST be documented for audit purposes

### 11.4 Non-Conformance Handling

#### 11.4.1 Compatibility Issues

1. **Issue Reporting**: Non-conformance issues MUST be reported to relevant authorities
2. **Interoperability Problems**: Compatibility issues MUST be investigated and resolved
3. **Security Violations**: Security non-conformance MUST be treated as critical issues
4. **Update Requirements**: Non-conforming implementations MUST be updated or discontinued

#### 11.4.2 Dispute Resolution

1. **Technical Disputes**: Technical interpretation disputes SHOULD be resolved through community consensus
2. **Conformance Disputes**: Conformance disputes MAY be escalated to governance bodies
3. **Appeal Process**: A formal appeal process SHOULD be established for certification decisions
4. **Documentation**: All dispute resolution activities MUST be documented

---

## 11.5 Implementation Guidelines

### 11.5.1 Reference Architecture

The logical supervision layout (language-agnostic) can be mapped to Rust async tasks:

```rust
// Conceptual task hierarchy (Tokio based)
struct NorcRuntime {
    connection_mgr: tokio::task::JoinHandle<()>,
    federation_mgr: tokio::task::JoinHandle<()>,
    trust_mgr: tokio::task::JoinHandle<()>,
    message_router: tokio::task::JoinHandle<()>,
    message_store: tokio::task::JoinHandle<()>,
    crypto_mgr: tokio::task::JoinHandle<()>,
}

fn start_runtime() -> NorcRuntime {
    use tokio::task::spawn;
    let connection_mgr = spawn(async { /* accept & supervise connections */ });
    let federation_mgr = spawn(async { /* maintain inter-server links */ });
    let trust_mgr = spawn(async { /* refresh certs, handle revocations */ });
    let message_router = spawn(async { /* distribute envelopes */ });
    let message_store = spawn(async { /* persist & index */ });
    let crypto_mgr = spawn(async { /* key rotation, PQ KEM cache */ });
    NorcRuntime { connection_mgr, federation_mgr, trust_mgr, message_router, message_store, crypto_mgr }
}
```

### 11.5.2 Message Processing Patterns

Leverage match + concurrent channels for efficient routing:

```rust
use dashmap::DashMap;
use tokio::sync::mpsc::UnboundedSender;

#[derive(Clone, Default)]
pub struct ConversationDirectory {
    inner: DashMap<ConversationId, Vec<UnboundedSender<Vec<u8>>>>,
}

impl ConversationDirectory {
    pub fn route(&self, conv: &ConversationId, msg: Vec<u8>) -> Result<(), &'static str> {
        if let Some(chans) = self.inner.get(conv) {
            for tx in chans.iter() { let _ = tx.send(msg.clone()); }
            Ok(())
        } else { Err("conversation_not_found") }
    }
}
```

### 11.5.3 Binary Protocol Efficiency

```rust
// Efficient binary slice parsing (simplified; add signature & MAC validation in production)
pub fn parse_frame_mut(input: &mut &[u8]) -> Option<NorcFrame> {
    const HEADER: usize = 1+1+4; // version + type + length
    if input.len() < HEADER + 64 { return None; }
    let version = input[0];
    let msg_type = input[1];
    let length = u32::from_be_bytes(input[2..6].try_into().ok()?);
    let need = HEADER + length as usize + 64;
    if input.len() < need { return None; }
    let payload = &input[6..6+length as usize];
    let mut sig = [0u8;64];
    sig.copy_from_slice(&input[6+length as usize .. need]);
    let frame = NorcFrame { version, msg_type, length, payload, signature: sig };
    *input = &input[need..];
    Some(frame)
}
```

### 11.5.4 Performance Optimizations

- Use ETS tables for session and key management
- Implement per-connection message queue limits
- Leverage Erlang distribution for clustering
- Use binary protocols to minimize memory usage
- Implement circuit breakers for federation links

### 11.5.5 Memory Management

- Zero ephemeral secrets immediately after use
- Use constant-time comparisons for authentication tags
- Lock memory pages for long-term keys where supported
- Implement secure key destruction procedures

---

## 11.5 Implementation Guidelines

### 11.5.1 Reference Architecture

NORC is optimized for Erlang/OTP but remains language-agnostic. The recommended supervision tree:

```
norc_server_sup
├── norc_connection_sup (simple_one_for_one)
│   └── norc_connection_worker (per WebSocket)
├── norc_federation_sup
│   ├── norc_federation_manager
│   └── norc_trust_manager
├── norc_message_sup
│   ├── norc_message_router
│   └── norc_message_store
└── norc_crypto_sup
    ├── norc_key_manager
    └── norc_session_manager
```

### 11.5.2 Message Processing Patterns

Leverage pattern matching for efficient routing:


### 11.5.3 Binary Protocol Efficiency

```text
[Replaced by Rust parsing example above]
```

### 11.5.4 Performance Optimizations

- Use ETS tables for session and key management
- Implement per-connection message queue limits
- Leverage Erlang distribution for clustering
- Use binary protocols to minimize memory usage
- Implement circuit breakers for federation links

### 11.5.5 Memory Management

- Zero ephemeral secrets immediately after use
- Use constant-time comparisons for authentication tags
- Lock memory pages for long-term keys where supported
- Implement secure key destruction procedures

### 11.5.6 Version Negotiation Implementation

```rust
pub fn adjacent_major_compatible(v1: u16, v2: u16) -> bool {
    let maj1 = v1 >> 8; // high byte major
    let maj2 = v2 >> 8;
    (maj1 as i16 - maj2 as i16).abs() <= 1
}

pub fn negotiate_version(client: &[u16], server: &[u16]) -> Result<u16, &'static str> {
    for &v in client { if server.contains(&v) { return Ok(v); } }
    // fallback: any adjacent-major compatible
    for &v in client { if server.iter().any(|&sv| adjacent_major_compatible(v, sv)) { return Ok(v); } }
    Err("no_compatible_version")
}
```

---

## 12. Extensions and Future Work

### 12.1 Extension Framework

#### 12.1.1 Extension Architecture

NORC supports protocol extensions through a structured framework:

1. **Extension Points**: Clearly defined extension points in message formats and protocol flows
2. **Namespace Management**: Extensions MUST use globally unique namespace identifiers
3. **Capability Negotiation**: Extensions MUST be negotiated during connection establishment
4. **Graceful Degradation**: Unknown extensions MUST be gracefully ignored
5. **Security Review**: Security-relevant extensions MUST undergo security review

#### 12.1.2 Extension Types

**Message Extensions**:
- Additional message types for specialized functionality
- Extended metadata fields in existing messages
- Optional message processing behaviors

**Cryptographic Extensions**:
- Additional cryptographic algorithms
- Extended key management procedures
- Specialized security features

**Federation Extensions**:
- Advanced routing algorithms
- Quality of service features
- Performance optimization mechanisms

**Trust Extensions**:
- Specialized trust verification procedures
- Additional trust levels or categories
- Enhanced audit and compliance features

#### 12.1.3 Extension Development Process

1. **Proposal Phase**: Extension proposals MUST include technical specification and security analysis
2. **Community Review**: Proposals SHOULD undergo public review and comment
3. **Implementation Phase**: Reference implementations MUST be developed and tested
4. **Adoption Phase**: Extensions become available for general implementation
5. **Standardization**: Successful extensions MAY be incorporated into future protocol versions

#### 12.1.4 Extension Governance Workflow

1. **Namespace Registration**: Extension authors request a namespace (e.g., `ext.acme.analytics`) via a signed pull request adding an entry to the public extension registry file.
2. **Security Review Intake**: Extensions affecting cryptography, trust, or metadata minimization MUST include a security analysis (threats, mitigations, downgrade risks) for review by the Cryptography and Privacy working groups.
3. **Capability Flag Assignment**: Each approved extension receives a canonical capability flag (e.g., `X-EXT-ANALYTICS-V1`). Flags are immutable once published.
4. **Versioning Model**: Backward-compatible changes increment minor version; breaking changes require a new capability flag (e.g., `X-EXT-ANALYTICS-V2`).
5. **Interoperability Testing**: At least two independent implementations MUST pass published test vectors before extension status changes from EXPERIMENTAL to STABLE.
6. **Lifecycle States**: EXPERIMENTAL → STABLE → DEPRECATED → WITHDRAWN. Deprecation requires 12-month notice; withdrawal requires security justification.
7. **Revocation of Extensions**: Security-critical flaws allow emergency reclassification to WITHDRAWN; federation servers MAY reject withdrawn capability flags.
8. **Registry Integrity**: Registry file commits MUST be signed; hash of the current registry MAY be included in periodic transparency log entries.
9. **Discovery**: Implementations retrieve signed registry snapshots; stale snapshot (>30 days) MUST raise an operational warning.
10. **Compliance Mapping**: Extensions impacting compliance MUST document control alignment (e.g., NIST, GDPR) in their specification entry.

### 12.2 Identified Future Work

#### 12.2.1 Advanced Cryptography

1. **Quantum-Safe Signatures**: Integration of post-quantum signature algorithms
2. **Homomorphic Encryption**: Support for privacy-preserving computation
3. **Zero-Knowledge Proofs**: Identity verification without information disclosure
4. **Secure Multi-Party Computation**: Collaborative computation without data sharing

##### 12.2.1.1 Post-Quantum Signature Roadmap

| Milestone | Target Window | Deliverables | Exit Criteria |
|-----------|---------------|--------------|---------------|
| Evaluation | Q1–Q2 2026 | Benchmark Dilithium / Falcon / SPHINCS+; side-channel review | Selection report published; extension draft `ext.pq_sig.v1` |
| Experimental Extension | Q3 2026 | Draft capability flag; test vectors; dual-sign mode (Ed25519 + PQ) | Two independent implementations pass conformance |
| Hybrid Deployment | Q4 2026 | Optional dual-sign for Verified+ trust; audit logging of PQ adoption | ≥30% of federation test network using hybrid signatures |
| Transition Guidance | Q1 2027 | Migration playbook; risk assessment for deprecating single-classical mode at higher trust | Governance approval of deprecation timeline |
| Mandatory at Classified/NATO | Earliest Q4 2027 (subject to maturity) | Update Requirements: PQ signature mandatory for Classified/NATO | Formal amendment ratified |

All PQ signature work proceeds under extension governance (Section 12.1.4) and MUST include side-channel and fault-injection analysis prior to promotion.

#### 12.2.2 Enhanced Federation

1. **Mesh Routing**: Advanced routing algorithms for large federation networks
2. **Content Distribution**: Efficient distribution of large content across federation
3. **Publish-Subscribe**: Event-driven communication patterns
4. **Federated Search**: Privacy-preserving search across organizations

#### 12.2.3 Emerging Technologies

1. **IoT Integration**: Support for Internet of Things device communication
2. **Blockchain Integration**: Distributed trust management using blockchain technology
3. **AI/ML Integration**: Machine learning for threat detection and performance optimization
4. **Edge Computing**: Optimization for edge computing environments

### 12.3 Research Areas

#### 12.3.1 Security Research

1. **Post-Quantum Transition**: Research on quantum-safe migration strategies
2. **Privacy-Preserving Analytics**: Analysis of communication patterns without privacy violations
3. **Advanced Threat Detection**: Detection of sophisticated attacks and insider threats
4. **Quantum Key Distribution**: Integration with quantum communication technologies

#### 12.3.2 Performance Research

1. **Ultra-Low Latency**: Optimization for real-time applications requiring microsecond latency
2. **Massive Scale**: Support for millions of concurrent users and organizations
3. **Resource Efficiency**: Optimization for resource-constrained environments
4. **Network Optimization**: Advanced techniques for optimizing network utilization

#### 12.3.3 Usability Research

1. **Transparency**: Making security transparent to end users
2. **Key Management**: Simplified key management for non-technical users
3. **Cross-Platform Consistency**: Consistent user experience across platforms
4. **Accessibility**: Support for users with disabilities

### 12.4 Evolution Strategy

#### 12.4.1 Roadmap Planning

1. **Community Input**: Protocol evolution SHOULD incorporate community feedback and requirements
2. **Research Integration**: Academic and industry research SHOULD inform protocol development
3. **Market Needs**: Real-world deployment experience SHOULD guide feature prioritization
4. **Security Landscape**: Evolving threat landscape SHOULD drive security enhancements

#### 12.4.2 Backward Compatibility

1. **AMC Preservation**: Future versions MUST maintain AMC principles
2. **Migration Path**: Clear migration paths MUST be provided for deprecated features
3. **Legacy Support**: Reasonable legacy support SHOULD be provided during transitions
4. **Breaking Changes**: Breaking changes MUST be carefully justified and communicated

---

## 13. Licensing and Governance

### 13.1 Open Standard Declaration

NORC is declared as an open standard protocol under the following principles:

1. **Open Specification**: The complete protocol specification is publicly available
2. **Royalty-Free**: No licensing fees or royalties are required for implementation
3. **Patent Freedom**: The protocol is free from essential patents or uses FRAND licensing
4. **Implementation Freedom**: Any party may implement the protocol without permission
5. **Non-Discrimination**: The protocol is available to all implementers without discrimination

### 13.2 Apache 2.0 License

#### 13.2.1 License Terms

This specification and all reference implementations are licensed under the Apache License, Version 2.0:

1. **Permissions**: Use, modification, distribution, patent use, private use
2. **Conditions**: License and copyright notice, state changes
3. **Limitations**: Trademark use, liability, warranty
4. **Patent Grant**: Express grant of patent rights from contributors

#### 13.2.2 Attribution Requirements

All implementations and derivative works MUST:

1. **Preserve Copyright**: Include original copyright notices
2. **License Notice**: Include copy of Apache 2.0 license
3. **Attribution**: Credit NavaTron Holding B.V. as protocol originator
4. **Change Documentation**: Document any modifications to the protocol

### 13.3 Governance Structure

#### 13.3.1 NavaTron

NavaTron Holding B.V. serves as the governance body for NORC with responsibilities including:

1. **Specification Maintenance**: Authoritative maintenance of protocol specifications
2. **Version Management**: Management of protocol versioning and compatibility
3. **Compliance Certification**: Definition of conformance requirements and certification
4. **Dispute Resolution**: Resolution of technical and conformance disputes
5. **Community Coordination**: Coordination of community contributions and feedback

#### 13.3.2 Technical Working Groups

Specialized working groups may be established for:

1. **Cryptography**: Cryptographic algorithm selection and security analysis
2. **Performance**: Performance optimization and scalability improvements
3. **Extensions**: Review and standardization of protocol extensions
4. **Compliance**: Regulatory compliance and audit requirements
5. **Interoperability**: Cross-implementation compatibility and testing

#### 13.3.3 Decision Making Process

1. **Consensus Building**: Technical decisions SHOULD be made through community consensus
2. **Expert Review**: Complex technical decisions SHOULD involve expert review
3. **Public Comment**: Significant changes SHOULD undergo public comment periods
4. **Final Authority**: NavaTron Holding B.V. retains final authority for specification changes
5. **Appeal Process**: A formal appeal process exists for disputed decisions

### 13.4 Intellectual Property

#### 13.4.1 Patent Policy

1. **Patent Commitment**: Contributors MUST provide patent commitments for essential patents
2. **Defensive Patent Use**: Patents related to NORC SHOULD only be used defensively
3. **FRAND Licensing**: Essential patents not covered by Apache 2.0 MUST use FRAND terms
4. **Patent Disclosure**: Known essential patents MUST be disclosed to the community

#### 13.4.2 Trademark Policy

1. **Protocol Name**: "NORC" and "NavaTron" are trademarks of the NavaTron Holding B.V.
2. **Conformance Marks**: Certification marks may be used only with proper authorization
3. **Fair Use**: Reasonable fair use of trademarks is permitted for descriptive purposes
4. **Commercial Use**: Commercial use of trademarks requires separate licensing agreements

### 13.5 Community Participation

#### 13.5.1 Contribution Process

1. **Open Participation**: Protocol development is open to community participation
2. **Contribution Agreement**: Contributors MUST agree to license terms for contributions
3. **Code of Conduct**: Community participants MUST adhere to established code of conduct
4. **Technical Merit**: Contributions are evaluated based on technical merit and alignment with protocol goals

#### 13.5.2 Communication Channels

1. **Public Forums**: Technical discussions occur in public forums and mailing lists
2. **Issue Tracking**: Protocol issues and enhancement requests use public issue tracking
3. **Regular Meetings**: Regular community meetings are held for coordination and discussion
4. **Documentation**: All decisions and rationale are documented for transparency

---

## Conclusion

## Conclusion

The NavaTron Open Real-time Communication (NORC) Protocol represents a comprehensive and mature approach to secure, federated communication designed for organizations that cannot compromise on security. This specification incorporates lessons learned from contemporary secure protocols while addressing their fundamental limitations.

### Key Innovations

**Security-First Design**: NORC mandates end-to-end encryption with no optional security modes, formal security objectives, and comprehensive attack resistance mechanisms including replay protection, hash chaining, and authenticated time synchronization.

**Graduated Trust Model**: The five-level hierarchical trust system enables organizations to establish appropriate security relationships ranging from basic business partnerships to NATO-level security cooperation, with cryptographic enforcement at every level.

**Bounded Complexity**: Adjacent-Major Compatibility (AMC) prevents the complexity explosion that has plagued other protocols while ensuring smooth migration paths and interoperability.

**Quantum-Ready Architecture**: Hybrid classical/post-quantum cryptography with formal key wrapping procedures protects against both current and future threats, with clear migration strategies as quantum computers emerge.

**Implementation Excellence**: Comprehensive implementation guidelines, formal notation, binary protocol specifications, and reference architecture patterns ensure consistent, high-quality implementations across platforms.

### Technical Rigor

This specification provides the complete technical foundation needed for building production-grade NORC systems:

- **Formal Cryptographic Procedures**: Step-by-step key derivation, AEAD structures, and domain separation
- **Comprehensive State Machines**: Device lifecycle, federation links, and message processing with clear error handling
- **Performance Engineering**: Specific latency and throughput requirements with implementation optimizations
- **Audit and Compliance**: Cryptographically chained audit trails and regulatory compliance frameworks
- **Standards-Grade Documentation**: RFC-quality specification suitable for international standardization

### Future Outlook

NORC is designed to be the communication protocol organizations will rely on through 2040 and beyond. The protocol's formal foundation, bounded complexity, and extensibility framework ensure it can evolve with changing security requirements while maintaining the clarity and rigor essential for secure implementations.

Implementers are encouraged to participate in the open development process and contribute to the continued evolution of the protocol. The combination of academic rigor, practical engineering, and real-world deployment experience embedded in this specification provides a solid foundation for the next generation of organizational communication systems.

For the latest version of this specification, reference implementations, and additional resources, visit: https://github.com/NavaTron/norc

---

## Appendix A: Padding Profile Registry (Normative) (Req: T-S-F-01.03.01.10/12)

Padding profiles define standardized bucket sets and selection semantics to promote interoperability and predictable privacy characteristics. Implementations advertise supported profile IDs during capability exchange.

| Profile ID | Description | Buckets (bytes) | Notes |
|------------|-------------|-----------------|-------|
| PAD-PROFILE-1 | Baseline Interactive | 1024,2048,4096,8192,16384,32768,65536,131072,262144 | Default; MUST be supported by all Verified+ implementations |
| PAD-PROFILE-2 | Compact Mobile | 512,1024,2048,4096,8192,16384,32768,65536 | MAY be used by mobile devices; not RECOMMENDED for high-sensitivity traffic |
| PAD-PROFILE-3 | High Privacy | 1024..262144 (power-of-two) + randomized overshoot up to +2 buckets | Increased bandwidth overhead; SHOULD require administrative opt-in |
| PAD-PROFILE-4 | Minimal (Fallback) | None (no padding) | ONLY permitted at Basic trust level when no other profile intersects; MUST NOT be offered at Verified+ |

Rules:
1. Intersection Selection: Highest privacy profile (numerically lowest row that is present in both sets with larger bucket cardinality) wins unless policy forbids.
2. Overshoot Extension: Random overshoot (≤1 bucket unless profile explicitly allows more) is defined within each profile; PAD-PROFILE-3 allows +2.
3. Negotiation Transcript Binding: Chosen profile ID MUST be included in the capability tuple string hashed into the transcript (see §7.1.3 rule 8).
4. Future Profiles: New profiles MUST start at ID >= 100 to avoid collision with initial reserved set.
5. Registry Governance: Additions require documented privacy & performance analysis; withdrawn profiles MUST remain reserved (not reassigned).

Security Considerations (Req: T-S-F-01.03.01.11/12/13): Standardizing sets reduces fingerprinting across implementations while enabling explicit trade-off selection. Minimal profile prevents connection failure but intentionally sacrifices size obfuscation—administrators SHOULD monitor its usage. Negotiated profile ID MUST appear in capability tuple (Req: T-S-F-02.05.01.13).

## Appendix B: FIPS Mode Profile (Normative) (Req: T-S-F-02.05.01.12)

This appendix defines the mandatory substitutions and operational constraints when operating in a FIPS 140-2 / 140-3 validated boundary or equivalent compliance mode.

### B.1 Capability Signaling
Implementations entering FIPS mode MUST advertise capability flag `cap.fips.v1`. Absence implies standard (non-FIPS) mode. All cryptographic negotiation decisions MUST treat the presence of any party advertising `cap.fips.v1` as globally enabling FIPS constraints.

### B.2 Algorithm Set
| Category | Standard Baseline | FIPS Mode Requirement | Notes | (Req: T-S-F-02.05.01.12)
|----------|-------------------|------------------------|-------|
| AEAD | ChaCha20-Poly1305 or AES-256-GCM | AES-256-GCM (FIPS validated module) | ChaCha20-Poly1305 MAY NOT be selected in FIPS mode |
| Hash | BLAKE3 (preferred) / SHA-256 | SHA-256 (FIPS 180-4) | BLAKE3 disallowed for HKDF; MAY be used only for non-security debug metrics if clearly segregated |
| KDF | HKDF-BLAKE3 | HKDF-HMAC-SHA-256 | HKDF per RFC 5869 within validated module |
| Signatures | Ed25519 | Ed25519 (if within validated boundary) OR ECDSA P-256 | If Ed25519 unavailable, use ECDSA P-256 with deterministic RFC 6979 nonce |
| KEM Hybrid | X25519 + Kyber768 | X25519 + Kyber768 (pending FIPS PQC finalization) | If Kyber not cleared, fall back to X25519-only with audit WARNING |

### B.3 HKDF-HMAC-SHA-256 Usage (Req: T-S-F-02.05.01.11/12)
When substituting HKDF-HMAC-SHA-256, transcript binding labels remain identical. The capability tuple MUST reflect `hkdf=hmacsha256` and be transcript-bound.

### B.4 Prohibited Constructions
1. BLAKE3 for key derivation or hashing security-critical transcripts.
2. ChaCha20-Poly1305 for payload encryption.
3. Non-validated crypto acceleration paths (e.g., custom SIMD) inside the FIPS boundary.

### B.5 Transitional Operation
If both peers are FIPS mode capable but one lacks PQ KEM validation, negotiation MAY select classical-only for that session; an audit event with severity=INFO MUST record the reason (`pq_unavailable_fips`).

### B.6 Audit Requirements (Req: T-S-F-02.05.01.12)
FIPS mode sessions MUST log: capability tuple, module certificate identifier, and any fallback decisions (e.g., classical-only).

### B.7 Security Considerations (Req: T-S-F-02.05.01.12)
FIPS mode may reduce algorithm diversity (loss of ChaCha20-Poly1305 & BLAKE3) but improves regulatory acceptance. Operators SHOULD evaluate performance impact (AES-GCM on hardware acceleration vs ChaCha20 on software-only platforms) during deployment planning.

---

**License Notice:** This requirements specification is licensed under the Apache License, Version 2.0. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

**Copyright Notice:** Copyright 2025 NavaTron Holding B.V. Licensed under the Apache License, Version 2.0.