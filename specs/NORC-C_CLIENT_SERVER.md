# NORC-C: Client-Server Protocol Specification
## Version 1.1 (Academic Alignment Draft)

This document aligns the client‑server layer with the academic restructuring of the master NORC Specification v1.1. Section numbering herein is local; security properties and formal handshake model are defined centrally (master spec Section 3). References `[1]–[14]` are cataloged in `REFERENCES.md`.

---

## 1. Overview

NORC-C defines the communication protocol between client devices and NORC servers. It handles device registration, user authentication, real-time messaging, presence, and key management.

### 1.1 Quick Glossary
| Term | Meaning |
|------|---------|
| Session | Authenticated logical connection (WebSocket) after version & auth |
| Device Registration | One-time association of device key with user account |
| Content Key | Random per-message (or small burst) symmetric key |
| Wrapped Key | Content key encrypted per recipient device using ephemeral X25519 |
| Sequence Number | Monotonic per-session counter for replay/order defense |
| Prev Message Hash | BLAKE3-256 of prior ciphertext enabling chain integrity |

### 1.2 Recommended Reading Order
1. Transport & Version Negotiation (Section 2)  
2. Registration & Authentication (Sections 3–4)  
3. Messaging & Key Management (Sections 5–6)  
4. Presence / Conversations / Calls / Files (7–10)  
5. Error Handling & Implementation Notes (11–12)  
6. Appendix A for forward security features.

### 1.3 Typical Client Message Send Flow
1. Ensure session active (else reconnect & negotiate version)  
2. Fetch / cache recipient device keys (key_request) if stale (>24h or rotated)  
3. Generate content key; encrypt plaintext; wrap key per device  
4. Assign `sequence_number` & `prev_message_hash` (if feature negotiated)  
5. Build AAD & perform AEAD encryption  
6. Transmit `message_send`; await ack / apply retry policy  
7. On ack, update delivery metrics & optional UI state.

**Version Compatibility**: NORC-C follows Adjacent-Major Compatibility (AMC):
- Version 1.x ↔ 2.x ✅ Compatible
- Version 1.x ↔ 3.x ❌ Not Compatible  
- Version 2.x ↔ 3.x ✅ Compatible

## 2. Transport and Connection

### 2.1 WebSocket Connection

- **Protocol**: WebSocket over TLS 1.3 (WSS)
- **Subprotocol**: `norc-c-v{major}.{minor}` (e.g., `norc-c-v1.0`, `norc-c-v2.0`)
- **URI Format**: `wss://server.domain.tld[:port]/norc-c?version={version}`
- **Default Port**: 443 (HTTPS) or 8843 (dedicated)
- **Version Negotiation**: Required for all connections

#### 2.1.1 Version Negotiation Process

```erlang
%% Step 1: Client connection request with supported versions
GET /norc-c HTTP/1.1
Host: server.example.org
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Protocol: norc-c-v1.0, norc-c-v1.1, norc-c-v2.0
Sec-WebSocket-Extensions: permessage-deflate
NORC-Client-Versions: 1.0,1.1,2.0
NORC-Preferred-Version: 2.0

%% Step 2: Server response with negotiated version
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
Sec-WebSocket-Protocol: norc-c-v2.0
NORC-Negotiated-Version: 2.0
NORC-Compatibility-Mode: false

%% Step 3: First WebSocket message confirms version
#{
    type => version_confirmation,
    negotiated_version => <<"2.0">>,
    server_capabilities => [messaging, voice, video, e2ee, federation],
    client_must_support => [messaging, e2ee],
    compatibility_features => [],  % Empty if same major version
    session_id => <<"session-uuid">>
}
```

### 2.2 Connection Lifecycle

```erlang
%% Connection States
-type connection_state() :: connecting 
                          | authenticating 
                          | authenticated 
                          | error 
                          | closed.
```

#### 2.2.1 Connection Establishment

1. Client initiates WSS connection
2. Server responds with capabilities and challenge
3. Client authenticates with device credentials
4. Connection enters authenticated state

#### 2.2.2 Keepalive Mechanism

```erlang
%% Ping message (every 30 seconds)
#{type => ping, timestamp => integer()}

%% Pong response
#{type => pong, timestamp => integer()}
```

## 3. Device Registration

### 3.1 Device Identity

Each device maintains a unique cryptographic identity:

```erlang
-record(device_identity, {
    device_id :: binary(),           % UUID v4 (36 bytes as string)
    private_key :: binary(),         % Ed25519 private key (32 bytes)
    public_key :: binary(),          % Ed25519 public key (32 bytes)  
    creation_time :: integer(),      % Unix timestamp
    device_info :: device_info()
}).

-record(device_info, {
    name :: binary(),                % Human readable name
    type :: device_type(),           % Device category
    capabilities :: [capability()],  % Supported features
    platform :: platform_info()     % Platform details
}).

-type device_type() :: smartphone | tablet | desktop | server | iot | unknown.
-type capability() :: messaging | voice | video | files | screen_share.
```

### 3.2 Registration Process

```erlang
%% Step 1: Registration Request
#{
    type => device_register,
    device_id => <<"550e8400-e29b-41d4-a716-446655440000">>,
    public_key => <<Ed25519PublicKey:32/binary>>,
    device_info => #{
        name => <<"Alice's iPhone">>,
        type => smartphone,
        capabilities => [messaging, voice, video],
        platform => #{
            os => ios,
            version => <<"17.5">>,
            app_version => <<"1.0.0">>
        }
    },
    proof_of_work => <<ProofBytes:32/binary>>  % Optional anti-spam
}

%% Step 2: Server Challenge
#{
    type => registration_challenge,
    challenge => <<RandomChallenge:32/binary>>,
    difficulty => 4,                 % Proof-of-work difficulty
    expires_at => UnixTimestamp
}

%% Step 3: Challenge Response  
#{
    type => registration_response,
    challenge => <<RandomChallenge:32/binary>>,
    signature => <<Ed25519Signature:64/binary>>,
    proof_solution => <<ProofSolution/binary>>
}

%% Step 4: Registration Confirmation
#{
    type => registration_success,
    device_id => <<"550e8400-e29b-41d4-a716-446655440000">>,
    server_public_key => <<ServerPubKey:32/binary>>,
    device_certificate => <<DeviceCert/binary>>
}
```

## 4. Authentication

### 4.1 Challenge-Response Authentication

```erlang
%% Authentication Request
#{
    type => auth_request,
    user_id => <<"alice@example.org">>,
    device_id => <<"550e8400-e29b-41d4-a716-446655440000">>,
    timestamp => UnixTimestamp,
    client_version => <<"1.0.0">>
}

%% Server Challenge
#{
    type => auth_challenge,
    challenge => <<RandomChallenge:32/binary>>,
    server_timestamp => UnixTimestamp,
    expires_at => UnixTimestamp
}

%% Challenge Response
#{
    type => auth_response,
    challenge => <<RandomChallenge:32/binary>>,
    signature => <<Ed25519Signature:64/binary>>,
    timestamp => UnixTimestamp
}

%% Authentication Result
#{
    type => auth_success,
    session_id => <<"session-uuid">>,
    user_info => #{
        user_id => <<"alice@example.org">>,
        display_name => <<"Alice Smith">>,
        avatar_url => <<"https://cdn.example.org/avatar/alice.jpg">>,
        permissions => [send_messages, make_calls, create_rooms]
    },
    server_capabilities => [federation, voice, video, files, e2ee]
}
```

### 4.2 Session Management

```erlang
-record(session, {
    session_id :: binary(),
    user_id :: binary(),
    device_id :: binary(),
    created_at :: integer(),
    expires_at :: integer(),
    permissions :: [permission()],
    rate_limits :: rate_limits()
}).

-type permission() :: send_messages | make_calls | create_rooms | admin.

-record(rate_limits, {
    messages_per_minute :: integer(),
    calls_per_hour :: integer(),
    files_per_day :: integer()
}).
```

## 5. Real-time Messaging

### 5.1 Message Structure

```erlang
-record(norc_message, {
    message_id :: binary(),          % UUID v4
    conversation_id :: binary(),     % Room/chat UUID  
    sender_user_id :: binary(),      % Sender user ID
    sender_device_id :: binary(),    % Sender device ID
    timestamp :: integer(),          % Unix timestamp microseconds
    message_type :: message_type(),  % Content type
    encrypted_content :: #{binary() => binary()}, % device_id => encrypted_payload
    metadata :: message_metadata(),
    classification :: classification()
}).

-type message_type() :: text | image | video | audio | file | system | call_invite.

-record(message_metadata, {
    reply_to :: binary(),           % Message ID being replied to
    thread_id :: binary(),          % Thread/conversation thread
    mentions :: [binary()],         % Mentioned user IDs
    expires_at :: integer(),        % Self-destructing message TTL
    edit_of :: binary()             % Original message ID if edit
}).
```

### 5.2 Message Encryption

#### 5.2.1 Content Encryption Process

1. **Generate ephemeral key**: `ephemeral_key = random(32)`
2. **Encrypt content**: `ciphertext = ChaCha20Poly1305.encrypt(plaintext, ephemeral_key, nonce)`
3. **For each recipient device**:
   - `encrypted_key = X25519.encrypt(ephemeral_key, recipient_public_key)`
   - Store as `device_id => encrypted_key`

```erlang
%% Encrypted message payload structure
#{
    nonce => <<Nonce:12/binary>>,
    ciphertext => <<EncryptedContent/binary>>,
    encrypted_keys => #{
        <<"device-1-uuid">> => <<EncryptedKey1:32/binary>>,
        <<"device-2-uuid">> => <<EncryptedKey2:32/binary>>
    },
    key_algorithm => x25519,
    content_algorithm => chacha20_poly1305
}
```

### 5.3 Message Sending

```erlang
%% Send Message
#{
    type => message_send,
    message_id => <<"msg-uuid">>,
    conversation_id => <<"room-uuid">>,
    recipients => [<<"alice@example.org">>, <<"bob@example.org">>],
    message_type => text,
    encrypted_content => #{
        <<"alice-device-1">> => <<EncryptedPayload1/binary>>,
        <<"alice-device-2">> => <<EncryptedPayload2/binary>>,
        <<"bob-device-1">> => <<EncryptedPayload3/binary>>
    },
    metadata => #{
        timestamp => UnixTimestampMicros,
        classification => unclassified,
        expires_at => null,
        reply_to => null
    }
}

%% Message Acknowledgment
#{
    type => message_ack,
    message_id => <<"msg-uuid">>,
    status => delivered,             % sent | delivered | read | failed
    timestamp => UnixTimestampMicros,
    error_code => null
}
```

### 5.4 Message Reception

```erlang
%% Receive Message
#{
    type => message_received,
    message_id => <<"msg-uuid">>,
    conversation_id => <<"room-uuid">>,
    sender_user_id => <<"alice@example.org">>,
    sender_device_id => <<"alice-device-1">>,
    timestamp => UnixTimestampMicros,
    message_type => text,
    encrypted_content => <<EncryptedPayload/binary>>,
    metadata => #{
        classification => unclassified,
        reply_to => <<"parent-msg-uuid">>,
        mentions => [<<"bob@example.org">>]
    }
}

%% Read Receipt
#{
    type => read_receipt,
    message_id => <<"msg-uuid">>,
    conversation_id => <<"room-uuid">>,
    read_by_device => <<"bob-device-1">>,
    timestamp => UnixTimestampMicros
}
```

## 6. Key Management

### 6.1 Public Key Distribution

```erlang
%% Key Request
#{
    type => key_request,
    request_id => <<"req-uuid">>,
    user_ids => [<<"alice@example.org">>, <<"bob@example.org">>],
    device_filter => all,           % all | active | specific([DeviceId])
    include_revoked => false
}

%% Key Response
#{
    type => key_response,
    request_id => <<"req-uuid">>,
    keys => #{
        <<"alice@example.org">> => #{
            <<"alice-device-1">> => #{
                public_key => <<PubKey:32/binary>>,
                key_algorithm => ed25519,
                created_at => UnixTimestamp,
                expires_at => UnixTimestamp,
                verified => true,
                revoked => false
            },
            <<"alice-device-2">> => #{...}
        },
        <<"bob@example.org">> => #{...}
    },
    timestamp => UnixTimestamp
}
```

### 6.2 Session Key Management

```erlang
%% Session Key Exchange Initiation
#{
    type => session_key_init,
    session_id => <<"session-uuid">>,
    conversation_id => <<"room-uuid">>,
    ephemeral_public_key => <<X25519PubKey:32/binary>>,
    target_devices => [<<"alice-device-1">>, <<"bob-device-1">>],
    expires_at => UnixTimestamp
}

%% Session Key Accept
#{
    type => session_key_accept,
    session_id => <<"session-uuid">>,
    ephemeral_public_key => <<X25519PubKey:32/binary>>,
    device_id => <<"alice-device-1">>,
    signature => <<Ed25519Signature:64/binary>>
}

%% Session Key Rotation
#{
    type => session_key_rotate,
    old_session_id => <<"old-session-uuid">>,
    new_session_id => <<"new-session-uuid">>,
    ephemeral_public_key => <<X25519PubKey:32/binary>>,
    rotation_reason => scheduled    % scheduled | compromised | expired
}
```

## 7. Presence and Status

### 7.1 Presence Updates

```erlang
-type presence_status() :: online | away | busy | invisible | offline.

%% Presence Update
#{
    type => presence_update,
    user_id => <<"alice@example.org">>,
    device_id => <<"alice-device-1">>,
    status => online,
    status_message => <<"Working on NORC protocol">>,
    capabilities => [messaging, voice, video],
    last_seen => UnixTimestamp,
    idle_since => UnixTimestamp     % null if not idle
}

%% Presence Subscription
#{
    type => presence_subscribe,
    user_ids => [<<"bob@example.org">>, <<"charlie@example.org">>],
    subscribe => true               % true = subscribe, false = unsubscribe
}

%% Presence Notification
#{
    type => presence_notification,
    user_id => <<"bob@example.org">>,
    device_id => <<"bob-device-1">>,
    status => away,
    status_message => <<"In a meeting">>,
    timestamp => UnixTimestamp
}
```

## 8. Conversation Management

### 8.1 Conversation Types

```erlang
-type conversation_type() :: direct | group | channel | broadcast.

-record(conversation, {
    conversation_id :: binary(),
    type :: conversation_type(),
    name :: binary(),
    description :: binary(),
    created_by :: binary(),
    created_at :: integer(),
    participants :: [participant()],
    settings :: conversation_settings()
}).

-record(participant, {
    user_id :: binary(),
    role :: participant_role(),
    joined_at :: integer(),
    permissions :: [conversation_permission()]
}).

-type participant_role() :: owner | admin | moderator | member | observer.
-type conversation_permission() :: send_messages | add_members | remove_members | 
                                   change_settings | delete_messages.
```

### 8.2 Conversation Operations

```erlang
%% Create Conversation
#{
    type => conversation_create,
    conversation_id => <<"room-uuid">>,
    conversation_type => group,
    name => <<"NORC Development">>,
    description => <<"Discussion about NORC protocol development">>,
    participants => [
        #{user_id => <<"alice@example.org">>, role => owner},
        #{user_id => <<"bob@example.org">>, role => member}
    ],
    settings => #{
        is_public => false,
        history_visible => true,
        message_ttl => null,
        max_members => 100
    }
}

%% Join Conversation
#{
    type => conversation_join,
    conversation_id => <<"room-uuid">>,
    user_id => <<"charlie@example.org">>,
    invite_code => <<"invite-uuid">>    % Optional
}

%% Leave Conversation
#{
    type => conversation_leave,
    conversation_id => <<"room-uuid">>,
    user_id => <<"bob@example.org">>,
    reason => <<"No longer needed">>
}
```

## 9. Voice and Video Calls

### 9.1 Call Signaling

```erlang
%% Call Invitation
#{
    type => call_invite,
    call_id => <<"call-uuid">>,
    caller_user_id => <<"alice@example.org">>,
    caller_device_id => <<"alice-device-1">>,
    participants => [<<"bob@example.org">>],
    call_type => audio,              % audio | video | screen_share
    sdp_offer => <<SDPOffer/binary>>,
    ice_candidates => [<<ICECandidate/binary>>],
    expires_at => UnixTimestamp
}

%% Call Response
#{
    type => call_response,
    call_id => <<"call-uuid">>,
    response => accept,              % accept | reject | busy
    callee_device_id => <<"bob-device-1">>,
    sdp_answer => <<SDPAnswer/binary>>,
    ice_candidates => [<<ICECandidate/binary>>]
}

%% Call Update (ICE candidates, media changes)
#{
    type => call_update,
    call_id => <<"call-uuid">>,
    device_id => <<"alice-device-1">>,
    ice_candidate => <<ICECandidate/binary>>,
    media_change => #{
        video => enabled,
        screen_share => disabled
    }
}

%% Call Termination
#{
    type => call_end,
    call_id => <<"call-uuid">>,
    ended_by => <<"alice-device-1">>,
    reason => normal,               % normal | busy | failed | network_error
    duration => 1234,               % Call duration in seconds
    timestamp => UnixTimestamp
}
```

## 10. File Transfer

### 10.1 File Upload Process

```erlang
%% File Upload Request
#{
    type => file_upload_request,
    file_id => <<"file-uuid">>,
    conversation_id => <<"room-uuid">>,
    filename => <<"document.pdf">>,
    file_size => 1048576,           % Bytes
    mime_type => <<"application/pdf">>,
    classification => unclassified,
    chunk_size => 65536,            % 64KB chunks
    total_chunks => 16,
    file_hash => <<SHA256Hash:32/binary>>
}

%% File Upload Chunk
#{
    type => file_chunk,
    file_id => <<"file-uuid">>,
    chunk_index => 0,
    chunk_data => <<EncryptedChunkData/binary>>,
    chunk_hash => <<ChunkSHA256:32/binary>>
}

%% File Upload Complete
#{
    type => file_upload_complete,
    file_id => <<"file-uuid">>,
    download_url => <<"https://files.example.org/file-uuid">>,
    expires_at => UnixTimestamp
}
```

## 11. Error Handling

### 11.1 Error Response Format

```erlang
%% Error Response
#{
    type => error,
    error_code => 4001,
    error_category => authentication,
    message => <<"Invalid device signature">>,
    details => #{
        field => signature,
        expected_algorithm => ed25519,
        received_algorithm => unknown
    },
    retry_after => 60,              % Seconds (for rate limiting)
    timestamp => UnixTimestamp
}
```

### 11.2 Error Codes

```erlang
%% Authentication Errors (1000-1999)
-define(ERR_AUTH_INVALID_DEVICE,      1001).
-define(ERR_AUTH_INVALID_SIGNATURE,   1002).
-define(ERR_AUTH_DEVICE_REVOKED,      1003).
-define(ERR_AUTH_SESSION_EXPIRED,     1004).

%% Message Errors (2000-2999)  
-define(ERR_MSG_INVALID_RECIPIENT,    2001).
-define(ERR_MSG_ENCRYPTION_FAILED,    2002).
-define(ERR_MSG_TOO_LARGE,           2003).
-define(ERR_MSG_CONVERSATION_NOT_FOUND, 2004).

%% Key Management Errors (3000-3999)
-define(ERR_KEY_NOT_FOUND,           3001).
-define(ERR_KEY_EXPIRED,             3002).
-define(ERR_KEY_REVOKED,             3003).
-define(ERR_KEY_ALGORITHM_UNSUPPORTED, 3004).

%% Rate Limiting (6000-6999)
-define(ERR_RATE_LIMIT_MESSAGES,     6001).
-define(ERR_RATE_LIMIT_CALLS,        6002).
-define(ERR_RATE_LIMIT_FILES,        6003).
```

## 12. Implementation Notes

### 12.1 Erlang-Specific Optimizations

```erlang
%% Use pattern matching for efficient message routing
handle_message(#{type := message_send} = Msg, State) ->
    route_message(Msg, State);
handle_message(#{type := presence_update} = Msg, State) ->
    update_presence(Msg, State);
handle_message(#{type := call_invite} = Msg, State) ->
    handle_call_invite(Msg, State).

%% Use ETS for fast key lookups
-record(device_key, {
    device_id :: binary(),
    user_id :: binary(), 
    public_key :: binary(),
    expires_at :: integer()
}).

init_key_store() ->
    ets:new(device_keys, [named_table, {keypos, #device_key.device_id}]).

lookup_device_key(DeviceId) ->
    case ets:lookup(device_keys, DeviceId) of
        [#device_key{} = Key] -> {ok, Key};
        [] -> {error, not_found}
    end.
```

### 12.2 Binary Message Optimization

```erlang
%% Efficient binary encoding for Erlang
encode_message(#{type := Type, message_id := MsgId, data := Data}) ->
    TypeByte = message_type_to_byte(Type),
    DataBin = term_to_binary(Data, [compressed]),
    <<1:8, TypeByte:8, (byte_size(MsgId)):16, MsgId/binary, 
      (byte_size(DataBin)):32, DataBin/binary>>.

decode_message(<<1:8, TypeByte:8, MsgIdLen:16, MsgId:MsgIdLen/binary,
                 DataLen:32, DataBin:DataLen/binary>>) ->
    Type = byte_to_message_type(TypeByte),
    Data = binary_to_term(DataBin),
    #{type => Type, message_id => MsgId, data => Data}.
```

---

This specification defines the complete NORC-C protocol for client-server communication, optimized for Erlang/OTP implementations while remaining language-agnostic.

---
### Appendix A: Security Enhancements (v1.1 Draft Forward Compatibility)

The following fields / message types are introduced for forward security & integrity improvements (see master spec Sections 6.6–6.13):

- `sequence_number` (uint64) and `prev_message_hash` (BLAKE3-256) will be added to encrypted message envelopes to enforce ordering and replay protection. Implementations MAY begin tracking these now (tolerating absence) to ease migration.
- New message types:
    - `device_revoke` (MSG_DEVICE_REVOKE / 0x05): Announces device key revocation with reason & effective time.
    - `time_sync` (MSG_TIME_SYNC / 0x33): Signed server time & uncertainty window for skew mitigation.
    - `file_manifest` (MSG_FILE_MANIFEST / 0x40): Encrypted filename, MIME type, original size, classification, and hash prior to chunk upload (replacing plaintext filename exposure).
- AEAD AAD MUST (once v1.1 active) include protocol version, message type, sequence number, message ID, length, prev hash, and transcript hash (handshakes) exactly as defined in master spec 6.10.
- Clients SHOULD start padding ciphertext to power‑of‑two buckets (≤64KB) to reduce size leakage.

Backward Compatibility: These additions are designed under Adjacent‑Major Compatibility (AMC). A v1.0 client MUST ignore unknown message types and absent ordering fields; a v1.1 client MUST accept unsequenced messages from v1.0 peers during transition while logging `compatibility_mode`.

Security Recommendation: Early adopters SHOULD enable optional tracking; reject duplicate `message_id` within a sliding window even before `sequence_number` rollout.
