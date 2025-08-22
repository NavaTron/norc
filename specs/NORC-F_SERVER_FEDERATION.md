# NORC-F: Server-Server Federation Protocol Specification
## Version 1.1 (Academic Alignment Draft)

Aligned with master NORC Specification v1.1. Formal security objectives, replay / ordering definitions, and hybrid PQ guidance are inherited from Sections 3 and 7 of the master spec. Local section numbers remain unchanged for backward reference. Citations `[1]–[14]` in `REFERENCES.md`.

---

## 1. Overview

NORC-F defines the federation protocol between NORC servers, enabling secure message routing, user discovery, and inter-server trust management across organizational boundaries.

### 1.1 Quick Glossary
| Term | Meaning |
|------|---------|
| Federation Link | Persistent mTLS + HTTP/2 channel between two servers |
| Relay Cache | Structure tracking seen `(origin_server, message_id)` for replay defense |
| Route Path | Ordered list of servers a federated payload traversed |
| Hop Count / TTL | Anti-loop / anti-flood counters limiting propagation |
| Trust Level | NORC-T evaluated assurance tier gating capabilities |

### 1.2 Typical Federation Relay Flow
1. Establish mTLS connection & ALPN selects highest AMC-compatible version.  
2. Exchange handshake capabilities + trust status (NORC-T integration).  
3. For outbound message: group recipients by destination server(s); build `message_relay` with per-device encrypted payloads.  
4. Update `route_path`, increment `hop_count`, validate TTL.  
5. Destination validates replay via relay cache + hash chain (future).  
6. Destination delivers to local user devices; sends `relay_ack` summarizing success/failure.  
7. Rate limiting & QoS adjust prioritization queues.

### 1.3 Trust Integration Mapping
| NORC-F Phase | NORC-T Dependency | Purpose |
|--------------|------------------|---------|
| Handshake | trust_status / certificates | Verify baseline trust & permissions |
| Message Relay | trust_level | Enforce max size / classification policy |
| Presence Federation | permissions list | Filter allowed presence propagation |
| Archive Sync | trust_certificate.conditions | Check audit / compliance authorization |
| Revocation Handling | trust_revoke | Immediately disable routes & purge caches |

**Version Compatibility**: NORC-F follows Adjacent-Major Compatibility (AMC):
- Version 1.x ↔ 2.x ✅ Compatible
- Version 1.x ↔ 3.x ❌ Not Compatible  
- Version 2.x ↔ 3.x ✅ Compatible

## 2. Transport Layer

### 2.1 Connection Requirements

- **Protocol**: HTTP/2 over mutual TLS (mTLS) 1.3
- **Default Port**: 8843
- **Certificate Requirements**: Valid X.509 certificates for server identity
- **Connection Pooling**: Persistent connections with multiplexing
- **Compression**: HPACK header compression, optional gzip for large payloads
- **Version Negotiation**: Mandatory using ALPN extension

#### 2.1.1 Federation Version Negotiation

Federation connections use ALPN (Application-Layer Protocol Negotiation) for version selection:

```erlang
%% TLS ALPN negotiation with version support
ALPN_PROTOCOLS = [
    "norc-f/2.0",    % Preferred version
    "norc-f/1.2",    % Fallback compatible versions
    "norc-f/1.1",
    "norc-f/1.0"
].

%% Post-connection handshake message
#{
    type => federation_handshake,
    requesting_server => <<"alice.example.org">>,
    target_server => <<"bob.example.org">>,
    protocol_version => <<"2.0">>,
    supported_versions => [<<"1.0">>, <<"1.1">>, <<"1.2">>, <<"2.0">>],
    capabilities => [federation, voice_relay, file_storage],
    compatibility_requirements => #{
        min_trust_level => basic,
        required_features => [message_relay],
        optional_features => [voice_relay, presence_federation]
    }
}

%% Handshake response with version confirmation
#{
    type => federation_handshake_response,
    responding_server => <<"bob.example.org">>,
    accepted_version => <<"2.0">>,
    compatibility_mode => false,     % true if AMC fallback active
    shared_capabilities => [federation, message_relay, presence_federation],
    version_warnings => [],          % Warnings if compatibility mode
    connection_id => <<"conn-uuid">>
}
```

### 2.2 Server Identity

```erlang
-record(server_identity, {
    server_id :: binary(),           % Fully qualified domain name
    public_key :: binary(),          % Ed25519 server public key  
    certificate :: x509_certificate(),
    federation_endpoints :: [endpoint()],
    capabilities :: [server_capability()],
    trust_level :: trust_level()
}).

-record(endpoint, {
    protocol :: norc_f,
    address :: inet:ip_address() | binary(), % IP or hostname
    port :: inet:port_number(),
    tls_fingerprint :: binary()      % SHA-256 of certificate
}).

-type server_capability() :: federation | voice_relay | file_storage | 
                             message_archive | compliance_logging.
-type trust_level() :: untrusted | basic | verified | classified | nato.
```

### 2.3 Connection Lifecycle

```erlang
%% Connection states for federation links
-type federation_state() :: connecting 
                          | tls_handshake 
                          | authenticating 
                          | trusted 
                          | active 
                          | error 
                          | suspended.
```

## 3. Server Discovery

### 3.1 DNS-based Discovery

NORC servers publish federation endpoints via DNS SRV records:

```dns
_norc-federation._tcp.example.org. 3600 IN SRV 10 5 8843 norc1.example.org.
_norc-federation._tcp.example.org. 3600 IN SRV 20 5 8843 norc2.example.org.
```

Additional TXT records provide metadata:
```dns
_norc-federation._tcp.example.org. 3600 IN TXT "version=1.0" "capabilities=federation,voice_relay"
```

### 3.2 Server Discovery Protocol

```erlang
%% Discovery Request
#{
    type => server_discovery,
    request_id => <<"req-uuid">>,
    query_server => <<"target.example.org">>,
    requesting_server => <<"source.example.org">>,
    discovery_method => dns,         % dns | direct | registry
    timestamp => UnixTimestamp,
    signature => <<Ed25519Signature:64/binary>>
}

%% Discovery Response
#{
    type => server_info,
    request_id => <<"req-uuid">>,
    server_id => <<"target.example.org">>,
    federation_endpoints => [
        #{protocol => norc_f, address => <<"198.51.100.10">>, port => 8843,
          tls_fingerprint => <<SHA256:32/binary>>}
    ],
    capabilities => [federation, voice_relay, file_storage],
    trust_anchors => [<<CACertFingerprint:32/binary>>],
    federation_policy => #{
        auto_accept => false,
        require_verification => true,
        max_message_size => 16777216,   % 16MB
        rate_limits => #{
            messages_per_second => 1000,
            bandwidth_mbps => 100
        }
    },
    server_version => <<"1.0.0">>,
    timestamp => UnixTimestamp,
    signature => <<Ed25519Signature:64/binary>>
}
```

## 4. Trust Establishment Integration

### 4.1 Trust Verification

Before message routing, servers must establish trust via NORC-T protocol:

```erlang
%% Trust Status Check
#{
    type => trust_status,
    target_server => <<"example.org">>,
    requesting_server => <<"source.org">>,
    trust_level_required => basic    % basic | verified | classified
}

%% Trust Status Response  
#{
    type => trust_status_response,
    target_server => <<"example.org">>,
    trust_established => true,
    trust_level => verified,
    established_at => UnixTimestamp,
    expires_at => UnixTimestamp,
    certificate_chain => [<<Cert1/binary>>, <<Cert2/binary>>]
}
```

## 5. Message Routing

### 5.1 Federated Message Structure

```erlang
-record(federated_message, {
    message_id :: binary(),          % Original message UUID
    federation_id :: binary(),       % Federation-specific UUID
    origin_server :: binary(),       % Originating server FQDN
    target_server :: binary(),       % Destination server FQDN
    target_users :: [binary()],      % Target user IDs
    route_path :: [binary()],        % Server routing path
    encrypted_payloads :: #{binary() => binary()}, % device_id => payload
    metadata :: federation_metadata(),
    classification :: classification(),
    signature :: binary()           % Origin server signature
}).

-record(federation_metadata, {
    original_timestamp :: integer(), % Original send time
    federation_timestamp :: integer(), % Federation relay time
    hop_count :: integer(),          % Number of server hops
    ttl :: integer(),               % Time to live (seconds)
    priority :: priority_level(),    % Message priority
    delivery_requirements :: [delivery_requirement()]
}).

-type priority_level() :: low | normal | high | urgent.
-type delivery_requirement() :: acknowledge | encrypt_transport | no_archive.
```

### 5.2 Message Relay

```erlang
%% Message Relay Request
#{
    type => message_relay,
    federation_id => <<"fed-msg-uuid">>,
    message_id => <<"original-msg-uuid">>,
    origin_server => <<"alice.example.org">>,
    target_server => <<"bob.example.org">>,
    target_users => [<<"bob@bob.example.org">>, <<"charlie@bob.example.org">>],
    route_path => [<<"alice.example.org">>],
    encrypted_payloads => #{
        <<"bob-device-1">> => <<EncryptedPayload1/binary>>,
        <<"bob-device-2">> => <<EncryptedPayload2/binary>>,
        <<"charlie-device-1">> => <<EncryptedPayload3/binary>>
    },
    metadata => #{
        original_timestamp => UnixTimestampMicros,
        federation_timestamp => UnixTimestampMicros,
        hop_count => 1,
        ttl => 86400,               % 24 hours
        priority => normal,
        delivery_requirements => [acknowledge]
    },
    classification => unclassified,
    route_signature => <<Ed25519Signature:64/binary>>
}

%% Message Relay Acknowledgment
#{
    type => relay_ack,
    federation_id => <<"fed-msg-uuid">>,
    message_id => <<"original-msg-uuid">>,
    target_server => <<"bob.example.org">>,
    status => delivered,            % delivered | partial | failed
    delivered_to => [
        #{user_id => <<"bob@bob.example.org">>, 
          device_ids => [<<"bob-device-1">>, <<"bob-device-2">>],
          timestamp => UnixTimestampMicros}
    ],
    failed_deliveries => [
        #{user_id => <<"charlie@bob.example.org">>,
          device_ids => [<<"charlie-device-1">>],
          error_code => user_not_found,
          timestamp => UnixTimestampMicros}
    ],
    timestamp => UnixTimestampMicros
}
```

### 5.3 Multi-hop Routing

For complex federation topologies, messages may traverse multiple servers:

```erlang
%% Extended route path tracking
route_path => [
    <<"alice.example.org">>,        % Origin
    <<"relay.federation.org">>,     % Intermediate
    <<"bob.example.org">>          % Destination
],

%% Hop limit to prevent routing loops
hop_count => 2,
max_hops => 10
```

## 6. User Discovery

### 6.1 User Lookup

```erlang
%% User Discovery Request
#{
    type => user_lookup,
    request_id => <<"lookup-uuid">>,
    requesting_server => <<"alice.example.org">>,
    target_server => <<"bob.example.org">>,
    user_queries => [
        <<"bob@bob.example.org">>,
        <<"charlie@bob.example.org">>
    ],
    lookup_type => basic,           % basic | detailed | presence
    requester_user => <<"alice@alice.example.org">>
}

%% User Discovery Response
#{
    type => user_lookup_response,
    request_id => <<"lookup-uuid">>,
    results => [
        #{
            user_id => <<"bob@bob.example.org">>,
            exists => true,
            public_profile => #{
                display_name => <<"Bob Smith">>,
                avatar_url => <<"https://cdn.bob.example.org/avatar.jpg">>
            },
            devices => [
                #{device_id => <<"bob-device-1">>, 
                  public_key => <<PubKey1:32/binary>>,
                  last_seen => UnixTimestamp,
                  capabilities => [messaging, voice, video]}
            ],
            federation_allowed => true
        },
        #{
            user_id => <<"charlie@bob.example.org">>,
            exists => false,
            error => user_not_found
        }
    ],
    timestamp => UnixTimestamp
}
```

### 6.2 Presence Federation

```erlang
%% Federated Presence Update
#{
    type => presence_federation,
    user_id => <<"bob@bob.example.org">>,
    device_id => <<"bob-device-1">>,
    origin_server => <<"bob.example.org">>,
    target_servers => [<<"alice.example.org">>],
    presence_data => #{
        status => away,
        status_message => <<"In a meeting">>,
        last_seen => UnixTimestamp,
        capabilities => [messaging]
    },
    subscribers => [<<"alice@alice.example.org">>],  % Who should receive this
    timestamp => UnixTimestamp
}
```

## 7. Server-to-Server Authentication

### 7.1 mTLS Certificate Requirements

```erlang
%% Server certificate validation
-record(server_certificate, {
    subject :: binary(),             % CN=server.example.org
    issuer :: binary(),             % CA that issued the cert
    serial_number :: binary(),
    not_before :: integer(),
    not_after :: integer(),
    public_key :: binary(),
    key_usage :: [key_usage()],     % [digital_signature, key_agreement]
    extensions :: [extension()]     % SAN, etc.
}).

-type key_usage() :: digital_signature | key_agreement | key_cert_sign.
```

### 7.2 Request Authentication

Each federation request includes cryptographic proof of origin:

```erlang
%% Request signature structure
SigningData = <<
    RequestType/binary,
    RequestingServer/binary, 
    TargetServer/binary,
    Timestamp:64,
    RequestBodyHash/binary
>>,
Signature = ed25519:sign(SigningData, ServerPrivateKey).
```

## 8. Rate Limiting and QoS

### 8.1 Federation Rate Limits

```erlang
-record(federation_limits, {
    messages_per_second :: integer(),    % Per-server message limit
    bandwidth_mbps :: integer(),         % Bandwidth limit
    concurrent_connections :: integer(), % Connection pool size
    burst_capacity :: integer(),         % Burst message allowance
    priority_weights :: #{priority_level() => float()} % QoS weights
}).

%% Rate limit exceeded response
#{
    type => rate_limit_exceeded,
    request_id => <<"req-uuid">>,
    limit_type => messages_per_second,
    current_rate => 1500,
    limit => 1000,
    retry_after => 60,               % Seconds
    timestamp => UnixTimestamp
}
```

### 8.2 Quality of Service

```erlang
%% QoS-aware message routing
prioritize_message(Msg = #{metadata := #{priority := urgent}}) ->
    {high_priority_queue, Msg};
prioritize_message(Msg = #{metadata := #{priority := normal}}) ->
    {normal_priority_queue, Msg};
prioritize_message(Msg) ->
    {low_priority_queue, Msg}.
```

## 9. Message Archive and Compliance

### 9.1 Archive Synchronization

```erlang
%% Archive Sync Request (for compliance)
#{
    type => archive_sync,
    requesting_server => <<"alice.example.org">>,
    target_server => <<"bob.example.org">>,
    sync_period => #{
        start_time => UnixTimestamp,
        end_time => UnixTimestamp
    },
    user_filter => [<<"bob@bob.example.org">>],
    message_types => [text, file],
    classification_levels => [unclassified, official_use_only],
    audit_id => <<"audit-uuid">>
}

%% Archive Sync Response  
#{
    type => archive_sync_response,
    audit_id => <<"audit-uuid">>,
    message_count => 1524,
    messages => [
        #{
            message_id => <<"msg-uuid-1">>,
            timestamp => UnixTimestamp,
            participants => [<<"alice@alice.example.org">>, <<"bob@bob.example.org">>],
            message_hash => <<SHA256:32/binary>>,
            classification => unclassified,
            archived_at => UnixTimestamp
        }
        % ... additional message metadata
    ],
    sync_status => complete,         % complete | partial | failed
    next_page_token => null
}
```

## 10. Voice and Media Relay

### 10.1 Voice Call Federation

```erlang
%% Federated Call Invite
#{
    type => call_invite_federation,
    call_id => <<"call-uuid">>,
    origin_server => <<"alice.example.org">>,
    target_server => <<"bob.example.org">>,
    caller => <<"alice@alice.example.org">>,
    callees => [<<"bob@bob.example.org">>],
    call_type => audio,              % audio | video | conference
    media_relay_required => true,    % Whether media relay is needed
    sdp_offer => <<SDPOffer/binary>>,
    ice_candidates => [<<ICECandidate/binary>>],
    call_metadata => #{
        classification => unclassified,
        max_duration => 3600,        % 1 hour limit
        recording_allowed => false
    }
}

%% Media Relay Endpoint
#{
    type => media_relay_info,
    call_id => <<"call-uuid">>,
    relay_server => <<"relay.federation.org">>,
    relay_endpoints => [
        #{protocol => rtp, address => <<"203.0.113.5">>, port => 50000},
        #{protocol => rtcp, address => <<"203.0.113.5">>, port => 50001}
    ],
    encryption_key => <<MediaKey:32/binary>>,
    relay_expires_at => UnixTimestamp
}
```

## 11. Error Handling

### 11.1 Federation-Specific Errors

```erlang
%% Federation Error Response
#{
    type => federation_error,
    request_id => <<"req-uuid">>,
    error_code => 5001,
    error_category => trust,
    message => <<"Server not in trust network">>,
    details => #{
        required_trust_level => verified,
        current_trust_level => basic,
        trust_expires_at => UnixTimestamp
    },
    resolution_hint => <<"Contact administrator to upgrade trust level">>,
    timestamp => UnixTimestamp
}
```

### 11.2 Error Codes

```erlang
%% Federation Trust Errors (5000-5199)
-define(ERR_FED_SERVER_NOT_TRUSTED,   5001).
-define(ERR_FED_TRUST_EXPIRED,        5002).
-define(ERR_FED_TRUST_REVOKED,        5003).
-define(ERR_FED_INSUFFICIENT_TRUST,   5004).

%% Routing Errors (5200-5399)
-define(ERR_FED_NO_ROUTE,            5201).
-define(ERR_FED_TTL_EXPIRED,         5202).
-define(ERR_FED_LOOP_DETECTED,       5203).
-define(ERR_FED_USER_NOT_FOUND,      5204).

%% Rate Limiting (5400-5599)
-define(ERR_FED_RATE_EXCEEDED,       5401).
-define(ERR_FED_BANDWIDTH_EXCEEDED,  5402).
-define(ERR_FED_QUOTA_EXCEEDED,      5403).

%% Protocol Errors (5600-5799)
-define(ERR_FED_PROTOCOL_VERSION,    5601).
-define(ERR_FED_MESSAGE_TOO_LARGE,   5602).
-define(ERR_FED_CAPABILITY_MISSING,  5603).
```

## 12. Load Balancing and High Availability

### 12.1 Server Clustering

```erlang
%% Cluster Member Discovery
#{
    type => cluster_member_info,
    server_id => <<"node1.example.org">>,
    cluster_id => <<"example-cluster">>,
    cluster_members => [
        #{server_id => <<"node1.example.org">>, weight => 100, active => true},
        #{server_id => <<"node2.example.org">>, weight => 100, active => true},
        #{server_id => <<"node3.example.org">>, weight => 50, active => false}
    ],
    load_balancing_policy => round_robin, % round_robin | least_connections | weighted
    failover_priority => [
        <<"node1.example.org">>,
        <<"node2.example.org">>,
        <<"node3.example.org">>
    ]
}
```

### 12.2 Health Monitoring

```erlang
%% Health Check Request
#{
    type => health_check,
    requesting_server => <<"monitor.example.org">>,
    target_server => <<"node1.example.org">>,
    check_level => detailed,         % basic | detailed | comprehensive
    timestamp => UnixTimestamp
}

%% Health Check Response
#{
    type => health_status,
    server_id => <<"node1.example.org">>,
    status => healthy,               % healthy | degraded | unhealthy
    load_metrics => #{
        cpu_percent => 45.2,
        memory_percent => 67.8,
        active_connections => 1523,
        messages_per_second => 890
    },
    federation_status => #{
        trusted_servers => 15,
        active_connections => 8,
        pending_messages => 0
    },
    capabilities_status => [
        #{capability => federation, status => operational},
        #{capability => voice_relay, status => operational},
        #{capability => file_storage, status => degraded}
    ],
    timestamp => UnixTimestamp
}
```

## 13. Implementation Guidelines

### 13.1 Erlang/OTP Architecture

```erlang
%% Recommended supervision structure for federation
norc_federation_sup
├── norc_federation_manager        % Manages federation state
├── norc_trust_manager            % Handles trust relationships  
├── norc_route_manager            % Message routing logic
├── norc_discovery_sup            % Server discovery processes
│   └── norc_dns_resolver         % DNS-based discovery
├── norc_connection_sup           % Federation connections
│   └── norc_federation_conn      % Per-server connection (simple_one_for_one)
└── norc_relay_sup               % Message relay workers
    └── norc_message_relay        % Message routing worker
```

### 13.2 Connection Pool Management

```erlang
%% Federation connection pool
-record(federation_pool, {
    target_server :: binary(),
    connections :: [pid()],
    max_connections :: integer(),
    active_connections :: integer(),
    connection_timeout :: integer(),
    retry_policy :: retry_policy()
}).

%% Connection pool worker
start_federation_connection(TargetServer) ->
    ConnectionOpts = #{
        server_id => TargetServer,
        ssl_opts => get_mtls_options(),
        reconnect_delay => 5000,
        max_retries => 3
    },
    {ok, Pid} = norc_federation_conn:start_link(ConnectionOpts),
    Pid.
```

### 13.3 Message Routing Optimization

```erlang
%% Efficient message routing with pattern matching
route_federated_message(#{target_server := TargetServer} = Msg) ->
    case get_federation_connection(TargetServer) of
        {ok, ConnectionPid} ->
            gen_server:cast(ConnectionPid, {relay_message, Msg});
        {error, not_connected} ->
            queue_for_retry(Msg),
            establish_connection(TargetServer);
        {error, not_trusted} ->
            {error, federation_not_allowed}
    end.

%% Use ETS for fast server lookup
init_server_registry() ->
    ets:new(federation_servers, [named_table, {read_concurrency, true}]).

lookup_server_info(ServerId) ->
    case ets:lookup(federation_servers, ServerId) of
        [{ServerId, ServerInfo}] -> {ok, ServerInfo};
        [] -> {error, server_not_found}
    end.
```

### 13.4 Binary Protocol Optimization

```erlang
%% Efficient federation message encoding
encode_federation_message(Msg = #{type := message_relay}) ->
    Header = <<1:8, 16#80:8>>,      % Version 1, Type message_relay
    Body = term_to_binary(Msg, [compressed]),
    <<Header/binary, (byte_size(Body)):32, Body/binary>>.

%% Streaming decode for large messages  
decode_federation_stream(<<1:8, Type:8, Len:32, Body:Len/binary, Rest/binary>>) ->
    case Type of
        16#80 -> % message_relay
            Message = binary_to_term(Body),
            {message_relay, Message, Rest};
        _ ->
            {unknown_message_type, Type, Rest}
    end;
decode_federation_stream(Partial) ->
    {need_more_data, Partial}.
```

---

This specification defines the complete NORC-F protocol for server-to-server federation, enabling secure and efficient communication across organizational boundaries while maintaining the security and privacy principles of the NORC protocol suite.

---
### Appendix A: Security & Ordering Enhancements (v1.1 Draft Guidance)

Federation implementations SHOULD prepare for the following forward-compatible features (master spec Sections 6.6–6.21):

1. **Replay & Ordering**: Track per incoming federation link `{origin_server, sequence_number}` sliding window (≥4096) and maintain `prev_message_hash` chain for each conversation. If chain mismatch occurs, mark message for quarantine & request retransmit (future extension) rather than propagating.
2. **Transcript Binding**: Include ordered ALPN list & capability advertisement in negotiated transcript hash prior to key derivation to detect downgrade attempts.
3. **Time Sync**: Accept `time_sync` messages from trusted peers; adjust logical offset only—never system clock. Reject messages with timestamp skew >60s unless accompanied by valid hash chain continuity.
4. **Encrypted File Manifests**: A `file_manifest` payload precedes relay of file chunks; servers treat it as opaque metadata and MUST NOT log plaintext filenames post‑migration.
5. **Device Revocation Propagation**: Relay `device_revoke` events promptly; cache revocation state with expiry to prevent stale device key usage.
6. **Hybrid PQ Suites**: If negotiated suite includes PQ component, ensure both classical & PQ public artifacts are present or abort with `ERR_CRYPTO`.

Transition: v1.0 peers ignore unknown message types; federation gateways SHOULD down‑convert (strip sequence/hash fields) only if absolutely required and MUST set `compatibility_mode = true` in logs.
