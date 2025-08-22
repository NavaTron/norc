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

---

## 7. Implementation Guidelines

### 7.1 Adjacent-Major Compatibility Implementation

#### 7.1.1 Version Negotiation Algorithm

```erlang
%% Version compatibility checking
-spec is_compatible(Version1 :: binary(), Version2 :: binary()) -> boolean().
is_compatible(V1, V2) ->
    {Major1, Minor1} = parse_version(V1),
    {Major2, Minor2} = parse_version(V2),
    
    %% AMC Rule: Adjacent major versions are compatible
    abs(Major1 - Major2) =< 1.

%% Find highest compatible version
negotiate_version(ClientVersions, ServerVersions) ->
    Compatible = [V || V1 <- ClientVersions, 
                      V2 <- ServerVersions, 
                      is_compatible(V1, V2), V <- [V1, V2]],
    case Compatible of
        [] -> {error, no_compatible_version};
        Versions -> 
            Highest = lists:max(Versions),
            {ok, Highest}
    end.

%% Version parsing helper
parse_version(<<"v", Rest/binary>>) -> parse_version(Rest);
parse_version(VersionBin) ->
    [MajorBin, MinorBin | _] = binary:split(VersionBin, <<".">>, [global]),
    {binary_to_integer(MajorBin), binary_to_integer(MinorBin)}.
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

### 8.1 Binary Wire Format

NORC messages use a compact binary format optimized for Erlang:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
├─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┤
│     Version     │     Type      │           Length              │
├─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┤
│                          Message ID                             │
├─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┤
│                                                                 │
├─                         Payload                               ─┤
│                                                                 │
└─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┘
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
-define(MSG_MESSAGE_SEND,           16#10).
-define(MSG_MESSAGE_ACK,            16#11).
-define(MSG_PRESENCE_UPDATE,        16#20).
-define(MSG_KEY_REQUEST,            16#30).
-define(MSG_KEY_RESPONSE,           16#31).
-define(MSG_SESSION_KEY_EXCHANGE,   16#32).

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
