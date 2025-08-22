# NORC Protocol Specification
## NavaTron Open Real-time Communication Protocol

**Version:** 1.0  
**Date:** August 22, 2025  
**Status:** Draft

---

## Table of Contents

1. [Introduction](#introduction)
2. [Architecture Overview](#architecture-overview)
3. [NORC-C: Client-Server Protocol](#norc-c-client-server-protocol)
4. [NORC-F: Server-Server Federation Protocol](#norc-f-server-server-federation-protocol)
5. [NORC-T: Trust Establishment Protocol](#norc-t-trust-establishment-protocol)
6. [Security Considerations](#security-considerations)
7. [Implementation Guidelines](#implementation-guidelines)
8. [Message Formats](#message-formats)
9. [Error Handling](#error-handling)
10. [Compliance and Extensions](#compliance-and-extensions)

---

## 1. Introduction

The NavaTron Open Real-time Communication (NORC) Protocol is a security-first, federated communication protocol designed for real-time messaging, voice, and media transmission. NORC prioritizes end-to-end encryption, metadata minimization, and trusted federation suitable for government, enterprise, and critical communication scenarios.

### 1.0 Glossary (Quick Reference)
| Term | Meaning |
|------|---------|
| AMC | Adjacent-Major Compatibility rule (N ↔ N+1 allowed) |
| Capability | Feature flag verbally advertised during negotiation (e.g. `voice`) |
| Conversation | Logical messaging context (1:1, group, channel) |
| Device | Individual client endpoint with its own key pair |
| Federation | Server ↔ Server communication layer (NORC-F) |
| Manifest | Encrypted metadata object describing a file prior to upload |
| Transcript Hash | BLAKE3 hash over canonical handshake messages used for downgrade resistance |
| Hash Chain | Sequence linkage using `prev_message_hash` to enforce ordering |
| Hybrid Suite | Cipher suite combining classical + PQ primitives |
| Sequence Window | Receiver bitmap used to detect replayed sequence numbers |

### 1.0.1 Why NORC Exists (Problem Statement)
Existing real‑time protocols either (a) emphasize openness at the cost of strong metadata reduction or (b) emphasize zero‑knowledge but lack robust federation trust governance. NORC explicitly combines: (1) strong cryptography and forward secrecy, (2) explicit trust establishment with revocation and auditability, (3) deterministic version migration (AMC) limiting long‑tail compatibility complexity, (4) optimization for high‑concurrency Erlang/OTP but retaining language neutrality.

### 1.0.2 Reading Order Suggestion
1. Skim Section 1 (principles & AMC)  
2. Read your layer of interest (3–5)  
3. Jump to Security (6) for threat & design rationale  
4. Consult Implementation (7) + Message Formats (8) for concrete encoding  
5. Use Test Vectors & Security Model documents for validation.

### 1.1 Design Principles

- **Security by Design**: End-to-end encryption is mandatory, not optional
- **Federation with Trust**: Servers can federate only through explicit trust relationships
- **Metadata Minimization**: Servers relay encrypted content without visibility
- **Device-Level Security**: Each device maintains its own cryptographic identity
- **Forward Secrecy**: Session keys are ephemeral and regularly rotated
- **Compliance Ready**: Built-in support for classification levels and audit trails

### 1.2 Version Compatibility

NORC follows **Adjacent-Major Compatibility (AMC)** versioning:

- **Rule**: Implementations may interoperate across one major version gap (N ↔ N+1)
- **Examples**:
  - Version 1.x ↔ 2.x ✅ **Compatible**
  - Version 1.x ↔ 3.x ❌ **Not Compatible**
  - Version 2.x ↔ 3.x ✅ **Compatible**
- **Rationale**: Provides migration path while preventing complexity of supporting too many legacy versions
- **Implementation**: Servers MUST negotiate the highest mutually supported version within AMC constraints

### 1.3 Protocol Layers

- **NORC-C**: Client ↔ Server communication
- **NORC-F**: Server ↔ Server federation
- **NORC-T**: Trust establishment and management

---

## 2. Architecture Overview

```
┌─────────────┐         ┌─────────────┐         ┌─────────────┐
│   Client    │◄───────►│   Server    │◄───────►│   Server    │
│   Device    │  NORC-C │     A       │  NORC-F │     B       │
└─────────────┘         └─────────────┘         └─────────────┘
                               │                         │
                               │         NORC-T          │
                               │   Trust Establishment   │
                               └─────────────────────────┘
```

### 2.1 Communication Flow

1. Clients connect to their home server using NORC-C
2. Servers establish trust relationships using NORC-T
3. Federated communication occurs via NORC-F
4. All content is end-to-end encrypted between client devices

### 2.2 Field Naming & Conventions
| Pattern | Meaning | Example |
|---------|---------|---------|
| `*_id` | Stable UUID v4 (unless noted) | `message_id` |
| `*_timestamp` / `timestamp` | Unix epoch seconds (millis/micros when suffixed) | `timestamp` (micros in NORC-C messages) |
| `*_hash` | BLAKE3-256 unless otherwise stated | `prev_message_hash` |
| `*_public_key` | Raw 32‑byte public key (Ed25519/X25519) | `ephemeral_public_key` |
| `classification` | Policy enum defining handling rules | `secret` |
| `capabilities` | Flat list of atoms (no nested structures) | `[voice, files]` |
| `expires_at` | Future timestamp hinting rotation/cleanup | session key expiry |

Consistency of naming reduces translation logic between versions and simplifies code generation.

### 2.3 Typical End‑to‑End Scenario (Narrative)
1. Device registers → obtains server public key & (optionally) device certificate.
2. User authenticates → session established; version selected via AMC.
3. Client fetches recipient device keys (key_request / key_response).
4. Message prepared: content key generated, per‑device wrapping.
5. AEAD encryption with AAD (sequence & previous hash where available) → send.
6. Federation forwards (if remote users) validating trust & relay replay cache.
7. Recipient device unwraps content key → decrypts → verifies hash chain.
8. Read receipt or ack returns (batched where feasible).
9. Periodic: session key rotation, device key rotation, time sync, trust revalidation.

---

## 3. NORC-C: Client-Server Protocol

### 3.1 Transport Layer

NORC-C operates over WebSocket connections with TLS 1.3 mandatory. The WebSocket subprotocol identifier is `norc-c-v1`.

#### 3.1.1 Version Negotiation

Clients and servers MUST implement version negotiation following AMC rules:

```erlang
%% Connection handshake with version negotiation
#{
    type => connection_request,
    client_versions => [<<"1.0">>, <<"1.1">>, <<"2.0">>], % Supported versions
    preferred_version => <<"2.0">>,                        % Client preference
    capabilities => [messaging, voice, video, files]
}

%% Server response with negotiated version
#{
    type => connection_accepted,
    negotiated_version => <<"2.0">>,                       % Highest mutual version
    server_capabilities => [federation, voice, video, files, e2ee],
    compatibility_mode => false                            % true if using AMC fallback
}
```

**Connection URI Format:**
```
wss://server.domain.tld:port/norc-c?version=2.0
```

### 3.2 Authentication and Registration

#### 3.2.1 Device Registration

Each device generates a unique key pair and registers with the server:

```erlang
%% Registration Message
#{
    type => device_register,
    device_id => binary(),           % UUID v4
    public_key => binary(),          % Ed25519 public key (32 bytes)
    device_info => #{
        name => binary(),            % Human-readable device name
        type => atom(),              % phone | desktop | server | etc
        capabilities => [atom()]     % [messaging, voice, video, files]
    },
    proof_of_work => binary()        % Optional anti-spam mechanism
}
```

#### 3.2.2 User Authentication

Users authenticate using their existing device credentials:

```erlang
%% Authentication Message  
#{
    type => auth_request,
    user_id => binary(),             % User identifier
    device_id => binary(),           % Device UUID
    timestamp => integer(),          % Unix timestamp
    signature => binary()           % Ed25519 signature of challenge
}
```

### 3.3 Message Types

#### 3.3.1 Real-time Messaging

```erlang
%% Message Send
#{
    type => message_send,
    message_id => binary(),          % UUID v4
    conversation_id => binary(),     % Conversation/room UUID
    recipients => [binary()],        % List of recipient user IDs
    encrypted_content => #{
        device_id() => binary()      % Per-device encrypted payloads
    },
    metadata => #{
        timestamp => integer(),
        message_type => atom(),      % text | file | voice | video
        classification => atom()     % unclassified | restricted | etc
    }
}
```

#### 3.3.2 Presence and Status

```erlang
%% Presence Update
#{
    type => presence_update,
    status => atom(),                % online | away | busy | offline
    status_message => binary(),      % Optional custom status
    capabilities => [atom()],        % Current device capabilities
    last_seen => integer()          % Unix timestamp
}
```

### 3.4 Key Management

#### 3.4.1 Key Exchange

```erlang
%% Public Key Request
#{
    type => key_request,
    user_ids => [binary()],          % Users to get keys for
    device_filter => [binary()]      % Optional device ID filter
}

%% Public Key Response
#{
    type => key_response,
    keys => #{
        binary() => #{               % user_id =>
            binary() => #{           % device_id =>
                public_key => binary(),
                key_algorithm => ed25519,
                expires_at => integer(),
                verified => boolean()
            }
        }
    }
}
```

#### 3.4.2 Session Key Establishment

For forward secrecy, NORC uses X25519 key exchange for ephemeral session keys:

```erlang
%% Session Key Exchange
#{
    type => session_key_exchange,
    session_id => binary(),          % Session UUID
    ephemeral_public_key => binary(), % X25519 public key
    target_device => binary(),       % Target device ID
    expires_at => integer()          % Session expiry timestamp
}
```

---

## 4. NORC-F: Server-Server Federation Protocol

### 4.1 Transport Layer

NORC-F uses mutual TLS (mTLS) over TCP with HTTP/2 framing for efficiency. Default port is 8843.

#### 4.1.1 Version Negotiation for Federation

Federation connections MUST negotiate compatible versions using AMC:

```erlang
%% Federation handshake with version compatibility check
#{
    type => federation_hello,
    server_id => <<"alice.example.org">>,
    protocol_versions => #{
        norc_f => [<<"1.0">>, <<"1.2">>, <<"2.0">>],      % NORC-F versions
        norc_t => [<<"1.0">>, <<"1.1">>]                  % NORC-T versions
    },
    capabilities => [federation, voice_relay, file_storage]
}

%% Response with negotiated versions
#{
    type => federation_hello_response,
    server_id => <<"bob.example.org">>,
    negotiated_versions => #{
        norc_f => <<"2.0">>,
        norc_t => <<"1.1">>
    },
    compatibility_warnings => [
        <<"NORC-F 2.0 -> 1.0 compatibility mode active">>,
        <<"Some advanced features may be unavailable">>
    ]
}
```

### 4.2 Server Identity

Each server has a unique server identity and maintains a certificate:

```erlang
%% Server Identity
#{
    server_id => binary(),           % Unique server identifier (domain)
    public_key => binary(),          % Ed25519 server public key
    certificate => #{
        issuer => binary(),          % Certificate authority
        subject => binary(),         % Server domain
        valid_from => integer(),     % Unix timestamp
        valid_until => integer(),    % Unix timestamp
        signature => binary()        % CA signature
    }
}
```

### 4.3 Message Routing

#### 4.3.1 Message Relay

```erlang
%% Federated Message Relay
#{
    type => message_relay,
    message_id => binary(),
    origin_server => binary(),       % Originating server ID
    target_users => [binary()],      % Target user IDs on this server
    encrypted_payloads => #{
        binary() => binary()         % device_id => encrypted_content
    },
    metadata => #{
        timestamp => integer(),
        hop_count => integer(),      % TTL mechanism
        route_signature => binary()  % Route integrity signature
    }
}
```

#### 4.3.2 Delivery Confirmation

```erlang
%% Delivery Acknowledgment
#{
    type => delivery_ack,
    message_id => binary(),
    delivered_to => [binary()],      % Successfully delivered device IDs
    failed_devices => [binary()],    % Failed delivery device IDs
    timestamp => integer()
}
```

### 4.4 Federation Discovery

```erlang
%% Server Discovery Request
#{
    type => server_discovery,
    query_server => binary(),        % Server domain to discover
    requesting_server => binary(),   % This server's ID
    timestamp => integer(),
    signature => binary()           % Request signature
}

%% Server Discovery Response
#{
    type => server_info,
    server_id => binary(),
    endpoints => [#{
        protocol => norc_f,
        address => binary(),         % IP or hostname
        port => integer(),
        tls_fingerprint => binary()
    }],
    trust_anchors => [binary()],     % Trusted CA fingerprints
    federation_policy => #{
        auto_accept => boolean(),
        require_verification => boolean(),
        max_message_size => integer()
    }
}
```

---

## 5. NORC-T: Trust Establishment Protocol

### 5.1 Trust Models

NORC-T supports multiple trust establishment models:

- **Direct Trust**: Servers exchange keys directly
- **Certificate Authority**: Third-party CA validation
- **Web of Trust**: Peer validation network
- **Government PKI**: Integration with existing government PKI

### 5.2 Trust Establishment Flow

#### 5.2.1 Trust Initiation

```erlang
%% Trust Request
#{
    type => trust_request,
    requesting_server => binary(),   % Server requesting trust
    requested_server => binary(),    % Target server
    trust_level => atom(),          % basic | verified | classified
    certificate_chain => [binary()], % X.509 certificate chain
    proof_of_control => binary(),    % Domain ownership proof
    contact_info => #{
        admin_email => binary(),
        organization => binary(),
        country => binary()
    }
}
```

#### 5.2.2 Trust Validation

```erlang
%% Trust Challenge
#{
    type => trust_challenge,
    challenge_id => binary(),
    challenge_data => binary(),      % Random challenge to sign
    validation_method => atom(),     % dns | email | manual | ca
    expires_at => integer()
}

%% Trust Response
#{
    type => trust_response,
    challenge_id => binary(),
    signature => binary(),           % Signed challenge
    additional_proofs => [binary()]  % Additional validation data
}
```

### 5.3 Trust Revocation

```erlang
%% Trust Revocation
#{
    type => trust_revoke,
    revoked_server => binary(),
    reason => atom(),                % compromised | policy | request
    effective_date => integer(),
    signature => binary(),
    revocation_proof => binary()     % Optional proof of authority
}
```

### 5.4 Trust Levels

- **Basic**: Minimal verification, suitable for public instances
- **Verified**: Domain and organization verification required  
- **Classified**: Government/enterprise PKI integration required
- **NATO**: NATO UNCLASSIFIED or higher security requirements

---

## 6. Security Considerations

### 6.1 Cryptographic Requirements

- **Asymmetric**: Ed25519 for signatures, X25519 for key exchange
- **Symmetric**: ChaCha20-Poly1305 for content encryption
- **Hashing**: BLAKE3 for integrity and key derivation
- **Random**: Cryptographically secure random number generation

### 6.2 Forward Secrecy

Session keys MUST be rotated according to this schedule:
- **Text messages**: Every 1000 messages or 24 hours
- **Voice calls**: Every 30 seconds
- **Video calls**: Every 30 seconds  
- **File transfers**: Per file

### 6.3 Metadata Protection

Servers MUST NOT log:
- Message content (encrypted)
- Participant lists for encrypted rooms
- Call duration details
- File contents or names

Servers MAY log (with retention limits):
- Connection timestamps
- Message delivery status
- Aggregate usage statistics
- Security audit events

### 6.4 Classification Handling

Messages can be tagged with classification levels:

```erlang
%% Classification Levels
-type classification() :: unclassified 
                       | official_use_only
                       | confidential  
                       | secret
                       | top_secret
                       | nato_restricted
                       | nato_confidential
                       | nato_secret.
```

Servers MUST enforce appropriate handling based on classification.

### 6.5 Threat Model

**Primary Assets**: Encrypted message payloads, minimized metadata, device long‑term keys, ephemeral session keys, trust certificates, federation routing integrity, user presence privacy, file metadata, version/cipher negotiation integrity, audit log integrity.

**Actors**:
- Legitimate clients/devices (honest) & honest‑but‑curious servers
- Malicious external network attacker (passive + active MITM)
- Compromised / malicious federation server
- Insider with limited log/audit access
- Future quantum adversary (harvest‑now, decrypt‑later)

**Assumptions**:
- TLS 1.3 (mTLS where applicable) protects transport until NORC layered keys established
- Ed25519 / X25519 / ChaCha20‑Poly1305 / BLAKE3 remain secure; secure RNG available
- Time skew bounded (≤5s client↔server, ≤60s inter‑server) or compensated via signed time sync

**Security Goals (MUST)**:
1. Confidentiality & integrity of end‑to‑end payloads
2. Forward secrecy (session & per‑message) and hybrid PQ option
3. Replay detection at client, session & federation layers
4. Downgrade resistance (version & cipher suites)
5. Minimal metadata exposure (no plaintext filenames, limited presence granularity)
6. Authentic revocation (device & trust)
7. Audit integrity without leaking plaintext

**Non‑Goals (MAY)**: Full traffic analysis resistance, anonymity from the home server, perfect plausible deniability in compliance/audit modes.

### 6.6 Replay Protection

Layered controls:
1. Per‑session 64‑bit `sequence_number` starting at random 24‑bit offset
2. Receiver sliding bitmap window (≥1024) rejects duplicates/out‑of‑window
3. Federation relay cache of `{origin_server, message_id}` & `{origin_server, sequence_number}` with TTL = max(message_TTL, 600s) capped at 24h
4. Handshake nonces (96‑bit) + transcript hashing (6.8) prevent replays of negotiation
5. Timestamp freshness: reject if |local_time − message_time| > 300s unless offline‑delivery extension permits (bounded ≤24h with hash chain continuity)

### 6.7 Ordering & Hash Chaining

Each encrypted message (except the first in a chain) includes:
- `sequence_number`
- `prev_message_hash` = BLAKE3‑256(canonical ciphertext of previous accepted message)
- Optional `chain_depth` for rapid consistency verification

Gap ⇒ MAY request retransmit; hash mismatch ⇒ MUST discard & flag integrity alert (no explicit protocol error to attacker).

### 6.8 Downgrade Resistance & Transcript Binding

Negotiation transcripts hash all ordered canonical handshake structures:
```
transcript_hash = BLAKE3( label || concat( canonical(handshake_msg_i) ) )
```
Key derivation:
```
master_secret = HKDF-BLAKE3( ikm = ecdh_secret || optional_pq_secret,
                                                         salt = client_nonce || server_nonce,
                                                         info = negotiated_version || cipher_suite || transcript_hash )
```
Abort if negotiated version < max(mutual_compatible_versions) (AMC) or chosen cipher suite not highest mutually preferred.

### 6.9 Canonical Serialization

Used for signatures / hashes:
- JSON debug: UTF‑8, sorted keys, no extraneous whitespace, base64url (no padding) for binary
- Binary: fixed field order; absent optional fields omitted; big‑endian length prefixes
`canonical_message` = exact serialized form pre‑encryption (excluding transport framing).

### 6.10 AEAD Additional Authenticated Data (AAD)

Structure (binary, fixed order):
```
struct AAD_v1 {
    uint8  proto_major;
    uint8  proto_minor;
    uint8  message_type;      // registry code
    uint64 sequence_number;   // 0 if not yet sequenced
    uint128 message_id;       // UUID bits
    uint32 ciphertext_length; // bytes
    bytes32 prev_message_hash;// zeroes for first message
    bytes32 transcript_hash;  // zeroes for non-handshake
}
```
AEAD verification failure ⇒ silent discard + local error counter.

### 6.11 Key Wrapping & Derivation

Per message:
1. Generate 256‑bit `content_key`
2. For each recipient device: ephemeral X25519 (or hybrid X25519+Kyber) → shared secret
3. `wrap_key = HKDF-BLAKE3(shared_secret, salt=BLAKE3(content_key)[0..31], info="norc:wrap:v1"||version||device_id, 32)`
4. `wrapped_content_key = ChaCha20-Poly1305(seal, wrap_key, nonce=first_96_bits(BLAKE3(device_id||message_id)), aad=AAD_meta, plaintext=content_key)`
5. Store `encrypted_keys[device_id] = wrapped_content_key`

Session establishment replaces `message_id` with `session_id` & label `"norc:session:v1"`.

### 6.12 Device Key Lifecycle

Rotation ≥ every 180 days or on compromise; overlap window permits dual addressing. Revocation via signed `device_revoke` including reason & effective timestamp. Pre‑rotate ≥7 days before expiry. Optional escrow MUST be passphrase‑wrapped (Argon2id) and never silently imported.

### 6.13 Algorithm Agility & Cipher Suites

```
Suite | Sig        | KEM/ECDH            | AEAD                | Hash/KDF
------+------------+---------------------+---------------------+---------
0001  | Ed25519    | X25519              | ChaCha20-Poly1305   | BLAKE3
0002  | ECDSA P-256| X25519              | AES-256-GCM         | SHA-256
0101  | Ed25519    | X25519 + Kyber768   | ChaCha20-Poly1305   | BLAKE3
```
Highest mutually supported (respecting AMC) selected; transcript binds advertisement order.

### 6.14 Post‑Quantum Hybrid (Optional)

Hybrid suites concatenate classical & PQ shared secrets before HKDF. PQ public key & ciphertext accompany handshake; failure to validate PQ part falls back only if policy allows.

### 6.15 Privacy Padding & Traffic Shaping

Ciphertexts padded to next power‑of‑two bucket (≤64KB). Presence updates MAY be delayed randomly (0–3s). Low‑priority ACKs MAY batch ≤100ms. Errors use generic messages to prevent enumeration.

### 6.16 Rate Limiting (Baseline)

Per device defaults (MAY tighten): messages 60/min (burst 120), key lookups 30/min, registrations 3/hour. Federation ingress per remote: 1000 msgs/min & 100 MB/5 min. Exceed ⇒ `ERR_RATE_LIMIT` with `retry_after`.

### 6.17 Time Synchronization

Signed `time_sync` gives server time & uncertainty. Acceptable skew: auth ≤5s; federation delay tolerance ≤60s. Servers SHOULD use authenticated NTP or Roughtime.

### 6.18 Logging & Audit Integrity

Audit log entries chained: `entry_hash = BLAKE3(prev_hash || canonical_entry)`. Daily root hash MAY be published (transparency). No plaintext message content or private keys; user IDs HMAC‑pseudonymized.

### 6.19 Supply Chain Integrity

Servers SHOULD advertise build attestation (e.g., Sigstore) hash; clients MAY enforce policy.

### 6.20 File Metadata Confidentiality

File manifests (filenames, MIME types, original length) encrypted as a `file_manifest` message (Section 8) before upload; server only sees padded chunk sizes & ID.

### 6.21 Security Property Summary

| Property | Mechanism |
|----------|-----------|
| Replay Protection | Sequence numbers + sliding window + relay cache |
| Ordering Integrity | Hash chain (`prev_message_hash`) |
| Downgrade Resistance | Transcript hash + highest mutual enforcement |
| Forward Secrecy | Ephemeral X25519 (optional PQ hybrid) |
| Confidentiality | AEAD (ChaCha20-Poly1305 / AES-GCM) |
| Metadata Minimization | Encrypted manifest + padding + batching |
| Algorithm Agility | Cipher suite negotiation registry |
| Key Lifecycle | Rotation & signed revocation messages |
| Supply Chain Integrity | Build attestations |
| Audit Integrity | Merkle-like hash chaining |

---

## 7. Implementation Guidelines

### 7.1 Adjacent-Major Compatibility Implementation

#### 7.1.1 Version Negotiation Algorithm

```erlang
%% AMC compatibility: adjacent major versions (|Δ| ≤ 1)
-spec is_compatible(binary(), binary()) -> boolean().
is_compatible(V1, V2) ->
    {Maj1, _} = parse_version(V1),
    {Maj2, _} = parse_version(V2),
    abs(Maj1 - Maj2) =< 1.

%% Negotiate highest non-downgraded version; return chosen + original lists for transcript binding
-spec negotiate_version([binary()], [binary()]) -> {ok, binary(), [binary()], [binary()]} | {error, term()}.
negotiate_version(ClientPref, ServerPref) ->
    Exact = [V || V <- ClientPref, lists:member(V, ServerPref)],
    case Exact of
        [BestExact | _] -> {ok, BestExact, ClientPref, ServerPref};
        [] ->
            Compat = [V || V <- ClientPref,
                           lists:any(fun(SV) -> is_compatible(V, SV) end, ServerPref)],
            case Compat of
                [] -> {error, no_compatible_version};
                _  ->
                    Highest = lists:last(lists:sort(Compat)),
                    {ok, Highest, ClientPref, ServerPref}
            end
    end.

parse_version(<<"v", Rest/binary>>) -> parse_version(Rest);
parse_version(VersionBin) ->
    case binary:split(VersionBin, <<".">>, [global]) of
        [Maj, Min] -> {binary_to_integer(Maj), binary_to_integer(Min)};
        [Maj, Min | _] -> {binary_to_integer(Maj), binary_to_integer(Min)}
    end.
```

#### 7.1.2 Compatibility Mode Handling

When operating across major version boundaries, implementations MUST:

1. **Feature Detection**: Query available capabilities after version negotiation
2. **Graceful Degradation**: Disable features not supported by both versions
3. **Compatibility Warnings**: Log when operating in compatibility mode
4. **Message Translation**: Transform messages between version formats when needed

```erlang
%% Compatibility mode message handling
handle_message_with_compatibility(Message, NegotiatedVersion, LocalVersion) ->
    case {major_version(NegotiatedVersion), major_version(LocalVersion)} of
        {Same, Same} -> 
            %% Same major version - no translation needed
            handle_message_native(Message);
        {Remote, Local} when abs(Remote - Local) =:= 1 ->
            %% Adjacent major versions - apply compatibility translation
            TranslatedMessage = translate_message(Message, NegotiatedVersion, LocalVersion),
            handle_message_native(TranslatedMessage);
        _ ->
            %% Should never happen if negotiation worked correctly
            {error, incompatible_versions}
    end.
```

#### 7.1.3 Migration Strategy

Organizations upgrading NORC implementations should follow this pattern:

1. **Phase 1**: Deploy new version alongside old version
2. **Phase 2**: Gradually migrate clients/servers using AMC compatibility
3. **Phase 3**: Once all systems are on version N+1, optionally upgrade to N+2
4. **Phase 4**: Deprecate version N support after full migration

### 7.2 Erlang/OTP Optimizations

The protocol is designed to leverage Erlang/OTP strengths:

#### 7.1.1 Process Architecture

```erlang
%% Recommended supervision tree
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

#### 7.1.2 Message Passing Patterns

Use Erlang's pattern matching for efficient message routing:

```erlang
%% Message routing based on pattern matching
route_message(#{type := message_send, conversation_id := ConvId} = Msg) ->
    case ets:lookup(conversations, ConvId) of
        [{ConvId, Participants}] ->
            [gen_server:cast(Pid, {deliver, Msg}) || Pid <- Participants];
        [] ->
            {error, conversation_not_found}
    end.
```

#### 7.1.3 Binary Protocol Efficiency

Use Erlang's binary pattern matching for efficient parsing:

```erlang
%% Efficient binary message parsing
parse_norc_message(<<Type:8, Length:32, Payload:Length/binary, Rest/binary>>) ->
    Message = decode_message(Type, Payload),
    {Message, Rest}.
```

### 7.2 Scalability Considerations

- Use ETS tables for session management
- Implement message queue limits per connection
- Use binary protocols to minimize memory usage
- Leverage Erlang's distribution for clustering

### 7.3 Error Recovery

- Implement exponential backoff for federation connections
- Use supervision trees for fault tolerance
- Graceful degradation when federation links fail
- Message queuing during temporary outages

---

## 8. Message Formats

### 8.1 Binary Wire Format (v2)

Includes sequencing & hash chaining fields:

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

### 8.2 JSON Alternative

For easier debugging and non-Erlang implementations, NORC also supports JSON over WebSocket with the subprotocol `norc-c-json-v1`.

### 8.3 Message Type Registry

```erlang
%% NORC-C Message Types (Version-aware)
-define(MSG_CONNECTION_REQUEST,     16#00).  % Version negotiation
-define(MSG_CONNECTION_ACCEPTED,    16#01).  % Version confirmation
-define(MSG_DEVICE_REGISTER,        16#02).  % Renamed from 16#01
-define(MSG_AUTH_REQUEST,           16#03).  % Renamed from 16#02
-define(MSG_AUTH_RESPONSE,          16#04).  % Renamed from 16#03
-define(MSG_DEVICE_REVOKE,          16#05).  % Device key revocation
-define(MSG_MESSAGE_SEND,           16#10).
-define(MSG_MESSAGE_ACK,            16#11).
-define(MSG_PRESENCE_UPDATE,        16#20).
-define(MSG_KEY_REQUEST,            16#30).
-define(MSG_KEY_RESPONSE,           16#31).
-define(MSG_SESSION_KEY_EXCHANGE,   16#32).
-define(MSG_TIME_SYNC,              16#33).  % Signed time synchronization
-define(MSG_FILE_MANIFEST,          16#40).  % Encrypted file metadata manifest

%% NORC-F Message Types (Version-aware)
-define(MSG_FEDERATION_HELLO,       16#70).  % New: Version negotiation
-define(MSG_FEDERATION_HELLO_RESP,  16#71).  % New: Version response
-define(MSG_MESSAGE_RELAY,          16#80).
-define(MSG_DELIVERY_ACK,           16#81).
-define(MSG_SERVER_DISCOVERY,       16#90).
-define(MSG_SERVER_INFO,            16#91).

%% NORC-T Message Types (Version-aware)
-define(MSG_TRUST_CAPABILITY,       16#9F).  % New: Version capabilities
-define(MSG_TRUST_REQUEST,          16#A0).
-define(MSG_TRUST_CHALLENGE,        16#A1).
-define(MSG_TRUST_RESPONSE,         16#A2).
-define(MSG_TRUST_REVOKE,           16#A3).

%% Version Compatibility Matrix
-define(VERSION_COMPATIBILITY, #{
    <<"1.0">> => [<<"1.0">>, <<"1.1">>, <<"1.2">>, <<"2.0">>],  % AMC: can talk to 2.x
    <<"1.1">> => [<<"1.0">>, <<"1.1">>, <<"1.2">>, <<"2.0">>],
    <<"1.2">> => [<<"1.0">>, <<"1.1">>, <<"1.2">>, <<"2.0">>],
    <<"2.0">> => [<<"1.0">>, <<"1.1">>, <<"1.2">>, <<"2.0">>, <<"2.1">>, <<"3.0">>], % AMC: 1.x and 3.x
    <<"2.1">> => [<<"1.0">>, <<"1.1">>, <<"1.2">>, <<"2.0">>, <<"2.1">>, <<"3.0">>],
    <<"3.0">> => [<<"2.0">>, <<"2.1">>, <<"3.0">>, <<"3.1">>, <<"4.0">>]  % AMC: 2.x and 4.x
}).
```

---

## 9. Error Handling

### 9.1 Error Categories

```erlang
%% Error Response Format
#{
    type => error,
    error_code => integer(),
    error_category => atom(),
    message => binary(),
    retry_after => integer(),      % Optional retry delay
    details => map()              % Additional error context
}

%% Error Categories
-define(ERR_AUTHENTICATION,     1000).
-define(ERR_AUTHORIZATION,      2000).  
-define(ERR_PROTOCOL,           3000).
-define(ERR_CRYPTO,            4000).
-define(ERR_FEDERATION,        5000).
-define(ERR_RATE_LIMIT,        6000).
-define(ERR_SERVER_ERROR,      9000).
```

### 9.2 Recovery Mechanisms

- **Connection Loss**: Automatic reconnection with exponential backoff
- **Message Delivery**: Store-and-forward with TTL
- **Federation Failure**: Route around failed servers when possible
- **Key Rotation**: Graceful handling of expired keys

---

## 10. Compliance and Extensions

### 10.1 Audit Requirements

For compliance environments, NORC supports:

- **Message Audit Trails**: Cryptographic proof of message delivery
- **Key Escrow**: Optional key recovery for authorized entities
- **Compliance Reporting**: Automated generation of security reports
- **Data Retention**: Configurable retention policies per classification

### 10.2 Extension Mechanism

NORC supports protocol extensions through:

```erlang
%% Extension Message
#{
    type => extension,
    extension_id => binary(),       % Unique extension identifier
    extension_version => binary(),  % Extension version
    extension_data => binary()     % Extension-specific payload
}
```

### 10.3 Future Considerations

- **Post-Quantum Cryptography**: Migration path for quantum-resistant algorithms
- **Group Messaging**: Optimized protocols for large group communications
- **Media Streaming**: Enhanced support for real-time media
- **IoT Integration**: Lightweight variants for constrained devices

---

## Conclusion

The NORC Protocol Specification provides a comprehensive framework for secure, federated real-time communication. Its design leverages Erlang/OTP strengths while remaining technology-independent for broader adoption.

For implementation questions or protocol extensions, please refer to the NORC community resources or submit protocol improvement proposals through the official channels.

---

**Document Version**: 1.0  
**Last Updated**: August 22, 2025  
**Next Review**: November 22, 2025
