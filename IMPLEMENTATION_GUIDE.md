# NORC Implementation Guide
## Technology-Independent Implementation Guidelines

---

## 1. Overview

This guide provides technology-independent implementation guidance for the NORC protocol suite, with specific optimizations for Erlang/OTP systems. The protocols are designed to work efficiently across different programming languages and platforms while leveraging Erlang's strengths in concurrent, fault-tolerant systems.

## 2. Architecture Recommendations

### 2.1 Layered Architecture

```
┌─────────────────────────────────────────────────────┐
│                Application Layer                    │
├─────────────────────────────────────────────────────┤
│  NORC-C    │    NORC-F     │     NORC-T           │
│ (Client)   │ (Federation)  │    (Trust)           │
├─────────────────────────────────────────────────────┤
│              Protocol Common Layer                  │
├─────────────────────────────────────────────────────┤
│               Cryptography Layer                    │
├─────────────────────────────────────────────────────┤
│                Transport Layer                      │
│          (WebSocket/TLS, HTTP/2/mTLS)              │
└─────────────────────────────────────────────────────┘
```

### 2.2 Component Separation

**Core Components:**
- **Protocol Handlers**: Handle specific NORC-C, NORC-F, NORC-T messages
- **Crypto Engine**: Manages all cryptographic operations
- **Trust Manager**: Handles trust relationships and validation
- **Message Router**: Routes messages between components and external systems
- **Storage Layer**: Persistent storage for keys, messages, trust relationships
- **Federation Gateway**: Manages inter-server communication

### 2.3 Erlang/OTP Supervision Strategy

```erlang
%% Top-level NORC application supervisor
norc_app_sup
├── norc_crypto_sup                 % Cryptographic services
│   ├── norc_key_manager
│   ├── norc_session_manager
│   └── norc_crypto_worker_sup (simple_one_for_one)
├── norc_protocol_sup              % Protocol handlers
│   ├── norc_c_handler_sup
│   │   └── norc_c_connection (simple_one_for_one)
│   ├── norc_f_handler_sup
│   │   └── norc_f_connection (simple_one_for_one)
│   └── norc_t_handler
├── norc_federation_sup            % Federation services
│   ├── norc_federation_manager
│   ├── norc_trust_manager
│   └── norc_discovery_service
├── norc_storage_sup              % Storage services
│   ├── norc_message_store
│   ├── norc_user_store
│   └── norc_trust_store
└── norc_router_sup               % Message routing
    ├── norc_message_router
    └── norc_presence_manager
```

## 3. Message Processing Pipeline

### 3.1 Inbound Message Processing

```erlang
%% Generic message processing pipeline (technology-independent pseudocode)
process_inbound_message(RawMessage, ConnectionContext) ->
    pipeline([
        fun parse_message/1,
        fun validate_format/1,
        fun authenticate_sender/1,
        fun decrypt_if_needed/1,
        fun route_message/1,
        fun send_acknowledgment/1
    ], {RawMessage, ConnectionContext}).

%% Erlang-specific implementation with pattern matching
handle_message(#{type := message_send} = Msg, State) ->
    case validate_message_send(Msg, State) of
        {ok, ValidMsg} ->
            route_message_send(ValidMsg, State),
            {reply, {ok, delivered}, State};
        {error, Reason} ->
            {reply, {error, Reason}, State}
    end;
handle_message(#{type := presence_update} = Msg, State) ->
    update_presence(Msg, State),
    broadcast_presence_change(Msg, State),
    {noreply, State}.
```

### 3.2 Outbound Message Processing

```erlang
%% Outbound message pipeline
send_message(Message, Recipients, Context) ->
    pipeline([
        fun validate_recipients/1,
        fun encrypt_content/1,
        fun sign_message/1,
        fun determine_routes/1,
        fun transmit_message/1,
        fun track_delivery/1
    ], {Message, Recipients, Context}).
```

## 4. Cryptographic Implementation

### 4.1 Key Management

```erlang
%% Technology-independent key management interface
-behavior(key_manager).

%% Callbacks that must be implemented
-callback generate_keypair() -> {PublicKey, PrivateKey}.
-callback sign(Message, PrivateKey) -> Signature.
-callback verify(Message, Signature, PublicKey) -> boolean().
-callback encrypt(Plaintext, PublicKey) -> Ciphertext.
-callback decrypt(Ciphertext, PrivateKey) -> Plaintext | error.

%% Erlang implementation using standard crypto libraries
-module(norc_crypto_ed25519).
-behavior(key_manager).

generate_keypair() ->
    {PublicKey, PrivateKey} = crypto:generate_key(eddsa, ed25519),
    {PublicKey, PrivateKey}.

sign(Message, PrivateKey) ->
    crypto:sign(eddsa, sha512, Message, [PrivateKey, ed25519]).

verify(Message, Signature, PublicKey) ->
    crypto:verify(eddsa, sha512, Message, Signature, [PublicKey, ed25519]).
```

### 4.2 Session Key Management

```erlang
%% Session key rotation policy
-record(session_policy, {
    rotation_interval :: integer(),     % Seconds between rotations
    max_messages :: integer(),          % Max messages per session key
    max_bytes :: integer(),            % Max bytes encrypted per key
    forward_secrecy :: boolean()       % Enable forward secrecy
}).

%% Session key rotation implementation
maybe_rotate_session_key(SessionId, MessageCount, ByteCount) ->
    Policy = get_session_policy(),
    ShouldRotate = 
        MessageCount >= Policy#session_policy.max_messages orelse
        ByteCount >= Policy#session_policy.max_bytes orelse
        is_rotation_time_due(SessionId),
    
    case ShouldRotate of
        true -> rotate_session_key(SessionId);
        false -> ok
    end.
```

## 5. Federation Implementation

### 5.1 Connection Management

```erlang
%% Federation connection pool
-record(federation_pool, {
    target_server :: binary(),
    connections :: [pid()],
    max_connections :: integer(),
    load_balancing :: round_robin | least_connections | weighted
}).

%% Connection establishment
establish_federation_connection(TargetServer) ->
    TrustStatus = norc_trust_manager:check_trust(TargetServer),
    case TrustStatus of
        {ok, trusted} ->
            SSLOpts = get_mtls_options(TargetServer),
            case ssl:connect(get_server_address(TargetServer), 8843, SSLOpts) of
                {ok, Socket} ->
                    Pid = spawn_link(fun() -> 
                        federation_connection_loop(Socket, TargetServer) 
                    end),
                    {ok, Pid};
                {error, Reason} ->
                    {error, {connection_failed, Reason}}
            end;
        {error, not_trusted} ->
            {error, trust_not_established}
    end.
```

### 5.2 Message Routing

```erlang
%% Efficient message routing with ETS lookups
init_routing_table() ->
    ets:new(user_routes, [named_table, {read_concurrency, true}]),
    ets:new(server_routes, [named_table, {read_concurrency, true}]).

route_federated_message(Message = #{recipients := Recipients}) ->
    Routes = lists:foldl(fun(UserId, Acc) ->
        case determine_user_server(UserId) of
            {ok, Server} ->
                maps:update_with(Server, fun(Users) -> [UserId | Users] end, 
                                [UserId], Acc);
            {error, not_found} ->
                %% Log routing failure
                Acc
        end
    end, #{}, Recipients),
    
    %% Send to each server
    [send_to_server(Server, Message#{recipients := Users}) 
     || {Server, Users} <- maps:to_list(Routes)].
```

## 6. Storage Layer Implementation

### 6.1 Message Storage

```erlang
%% Message storage interface (technology-independent)
-behavior(message_store).

-callback store_message(Message) -> {ok, MessageId} | {error, Reason}.
-callback retrieve_message(MessageId) -> {ok, Message} | {error, not_found}.
-callback list_messages(ConversationId, Limit, Offset) -> {ok, [Message]}.
-callback delete_message(MessageId) -> ok | {error, Reason}.

%% Possible implementations:
%% - norc_message_store_ets: In-memory ETS tables
%% - norc_message_store_mnesia: Distributed Mnesia database  
%% - norc_message_store_postgres: PostgreSQL backend
%% - norc_message_store_riak: Riak KV backend
```

### 6.2 User and Device Storage

```erlang
%% User storage with device management
-record(user, {
    user_id :: binary(),
    display_name :: binary(),
    avatar_url :: binary(),
    created_at :: integer(),
    last_seen :: integer(),
    status :: user_status(),
    devices :: [device_id()]
}).

-record(device, {
    device_id :: binary(),
    user_id :: binary(),
    public_key :: binary(),
    device_name :: binary(),
    device_type :: device_type(),
    capabilities :: [capability()],
    last_seen :: integer(),
    active :: boolean()
}).

%% Efficient device lookup for message encryption
get_user_devices(UserId) ->
    case ets:lookup(users, UserId) of
        [#user{devices = DeviceIds}] ->
            Devices = [ets:lookup(devices, DevId) || DevId <- DeviceIds],
            {ok, lists:flatten(Devices)};
        [] ->
            {error, user_not_found}
    end.
```

## 7. Error Handling and Resilience

### 7.1 Graceful Degradation

```erlang
%% Graceful handling of federation failures
handle_federation_failure(Server, Reason) ->
    %% 1. Mark server as temporarily unavailable
    mark_server_unavailable(Server, Reason),
    
    %% 2. Queue messages for retry
    QueuedMessages = get_pending_messages(Server),
    [queue_for_retry(Msg, retry_policy(Reason)) || Msg <- QueuedMessages],
    
    %% 3. Notify clients of delivery delays
    notify_clients_of_delay(Server),
    
    %% 4. Attempt alternative routes if available
    case find_alternative_route(Server) of
        {ok, AlternativeServer} ->
            reroute_messages(QueuedMessages, AlternativeServer);
        {error, no_alternative} ->
            schedule_retry(Server, exponential_backoff)
    end.
```

### 7.2 Circuit Breaker Pattern

```erlang
%% Circuit breaker for federation connections
-record(circuit_breaker, {
    state :: closed | open | half_open,
    failure_count :: integer(),
    last_failure :: integer(),
    threshold :: integer(),
    timeout :: integer()
}).

call_with_circuit_breaker(Function, Args, CircuitBreaker) ->
    case CircuitBreaker#circuit_breaker.state of
        closed ->
            try apply(Function, Args) of
                Result -> 
                    reset_circuit_breaker(CircuitBreaker),
                    Result
            catch
                error:Reason ->
                    increment_failure_count(CircuitBreaker),
                    maybe_open_circuit(CircuitBreaker),
                    {error, Reason}
            end;
        open ->
            case should_attempt_recovery(CircuitBreaker) of
                true -> 
                    set_circuit_state(CircuitBreaker, half_open),
                    call_with_circuit_breaker(Function, Args, CircuitBreaker);
                false -> 
                    {error, circuit_open}
            end;
        half_open ->
            %% Single test call
            call_with_circuit_breaker(Function, Args, 
                CircuitBreaker#circuit_breaker{state = closed})
    end.
```

## 8. Performance Optimization

### 8.1 Connection Pooling

```erlang
%% Connection pool management
-record(connection_pool, {
    name :: atom(),
    target :: binary(),
    min_connections :: integer(),
    max_connections :: integer(),
    active_connections :: [pid()],
    idle_connections :: [pid()],
    connection_opts :: map()
}).

get_connection_from_pool(PoolName) ->
    case gen_server:call({pool, PoolName}, get_connection) of
        {ok, Connection} -> {ok, Connection};
        {error, pool_exhausted} -> {error, no_connections_available}
    end.

return_connection_to_pool(PoolName, Connection) ->
    gen_server:cast({pool, PoolName}, {return_connection, Connection}).
```

### 8.2 Message Batching

```erlang
%% Batch multiple messages for efficiency
-record(message_batch, {
    target_server :: binary(),
    messages :: [message()],
    max_size :: integer(),
    max_age :: integer(),
    created_at :: integer()
}).

maybe_send_batch(Batch) ->
    Now = erlang:system_time(millisecond),
    Age = Now - Batch#message_batch.created_at,
    
    ShouldSend = 
        length(Batch#message_batch.messages) >= Batch#message_batch.max_size orelse
        Age >= Batch#message_batch.max_age,
    
    case ShouldSend of
        true -> send_message_batch(Batch);
        false -> {wait, Batch}
    end.
```

## 9. Monitoring and Observability

### 9.1 Metrics Collection

```erlang
%% Key metrics to collect
-define(METRICS, [
    %% Protocol metrics
    {messages_sent_total, counter, "Total messages sent"},
    {messages_received_total, counter, "Total messages received"},
    {message_processing_duration, histogram, "Message processing time"},
    
    %% Federation metrics  
    {federation_connections_active, gauge, "Active federation connections"},
    {federation_messages_relayed, counter, "Messages relayed to other servers"},
    {trust_establishments_total, counter, "Trust relationships established"},
    
    %% Performance metrics
    {memory_usage_bytes, gauge, "Memory usage in bytes"},
    {cpu_usage_percent, gauge, "CPU usage percentage"},
    {connection_pool_utilization, gauge, "Connection pool utilization"}
]).

%% Metrics reporting
report_metric(MetricName, Value) ->
    prometheus:counter_inc(MetricName, Value).
```

### 9.2 Health Checks

```erlang
%% Health check implementation
health_check() ->
    Checks = [
        {database, fun check_database_connection/0},
        {federation, fun check_federation_status/0},
        {crypto, fun check_crypto_services/0},
        {memory, fun check_memory_usage/0}
    ],
    
    Results = [{Name, Check()} || {Name, Check} <- Checks],
    OverallHealth = case lists:all(fun({_, ok}) -> true; (_) -> false end, Results) of
        true -> healthy;
        false -> unhealthy
    end,
    
    #{
        status => OverallHealth,
        checks => Results,
        timestamp => erlang:system_time(second)
    }.
```

## 10. Configuration Management

### 10.1 Environment-Specific Configuration

```erlang
%% Configuration structure
-record(norc_config, {
    server_id :: binary(),
    federation_port :: integer(),
    client_port :: integer(),
    trust_policies :: trust_policies(),
    crypto_config :: crypto_config(),
    storage_config :: storage_config(),
    monitoring_config :: monitoring_config()
}).

%% Load configuration based on environment
load_config() ->
    Environment = os:getenv("NORC_ENV", "development"),
    ConfigFile = "config/" ++ Environment ++ ".config",
    {ok, Config} = file:consult(ConfigFile),
    parse_config(Config).
```

### 10.2 Runtime Configuration Updates

```erlang
%% Hot configuration updates
update_config(ConfigKey, NewValue) ->
    case validate_config_change(ConfigKey, NewValue) of
        ok ->
            OldValue = application:get_env(norc, ConfigKey),
            application:set_env(norc, ConfigKey, NewValue),
            notify_config_change(ConfigKey, OldValue, NewValue),
            ok;
        {error, Reason} ->
            {error, Reason}
    end.
```

## 11. Testing Strategy

### 11.1 Unit Testing

```erlang
%% Example unit test structure
-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

message_encryption_test() ->
    %% Test message encryption/decryption roundtrip
    {PubKey, PrivKey} = norc_crypto:generate_keypair(),
    Message = <<"Hello, NORC!">>,
    
    Encrypted = norc_crypto:encrypt(Message, PubKey),
    ?assertMatch({ok, _}, Encrypted),
    
    {ok, EncryptedData} = Encrypted,
    Decrypted = norc_crypto:decrypt(EncryptedData, PrivKey),
    ?assertEqual({ok, Message}, Decrypted).

federation_routing_test() ->
    %% Test message routing between servers
    Message = #{
        type => message_send,
        recipients => [<<"alice@server2.org">>],
        content => <<"Test message">>
    },
    
    Routes = norc_router:determine_routes(Message),
    ?assertEqual([<<"server2.org">>], Routes).
    
-endif.
```

### 11.2 Integration Testing

```erlang
%% Integration test for full message flow
full_message_flow_test() ->
    %% Start test servers
    {ok, Server1} = start_test_server("server1.test"),
    {ok, Server2} = start_test_server("server2.test"),
    
    %% Establish trust between servers
    establish_test_trust(Server1, Server2),
    
    %% Send message from client on server1 to client on server2
    {ok, Client1} = connect_test_client(Server1, "alice"),
    {ok, Client2} = connect_test_client(Server2, "bob"),
    
    Message = <<"Integration test message">>,
    ok = send_message(Client1, "bob@server2.test", Message),
    
    %% Verify message delivery
    ?assertMatch({ok, Message}, receive_message(Client2, 5000)),
    
    %% Cleanup
    disconnect_client(Client1),
    disconnect_client(Client2),
    stop_test_server(Server1),
    stop_test_server(Server2).
```

## 12. Deployment Considerations

### 12.1 Container Deployment

```dockerfile
# Example Dockerfile for NORC server
FROM erlang:26-alpine

# Install dependencies
RUN apk add --no-cache openssl-dev

# Copy application
COPY . /opt/norc
WORKDIR /opt/norc

# Build application
RUN rebar3 release

# Expose ports
EXPOSE 8843 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1

# Start application
CMD ["_build/default/rel/norc/bin/norc", "foreground"]
```

### 12.2 Kubernetes Deployment

```yaml
# Example Kubernetes deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: norc-server
spec:
  replicas: 3
  selector:
    matchLabels:
      app: norc-server
  template:
    metadata:
      labels:
        app: norc-server
    spec:
      containers:
      - name: norc-server
        image: norc-server:latest
        ports:
        - containerPort: 8843
          name: federation
        - containerPort: 8080
          name: client
        env:
        - name: NORC_SERVER_ID
          value: "cluster.example.org"
        - name: NORC_ENV
          value: "production"
        resources:
          requests:
            memory: "256Mi"
            cpu: "100m"
          limits:
            memory: "512Mi" 
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
```

---

This implementation guide provides a comprehensive foundation for building NORC-compliant servers and clients in any programming language, with specific optimizations and examples for Erlang/OTP implementations.
