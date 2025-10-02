# NORC System Architecture

## Overview

NORC (NavaTron Open Real-time Communication Protocol) is a federated, real-time communication system with strong security guarantees through mutual TLS (mTLS) authentication and certificate-based identity management.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                         NORC Architecture                            │
└─────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────┐
│                          Client Layer                                 │
├──────────────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐   │
│  │ norc-client  │  │   norc-tui   │  │     norc-diag           │   │
│  │   (CLI)      │  │ (Terminal UI)│  │  (Diagnostics CLI)      │   │
│  └──────┬───────┘  └──────┬───────┘  └──────────┬───────────────┘   │
│         │                  │                     │                   │
│         └──────────────────┴─────────────────────┘                   │
│                            │                                          │
│                   ┌────────▼─────────┐                               │
│                   │  client-core     │                               │
│                   │  (Client Logic)  │                               │
│                   └────────┬─────────┘                               │
└────────────────────────────┼──────────────────────────────────────────┘
                             │
                    ┌────────▼──────────┐
                    │    Transport      │
                    │   (TLS/mTLS)      │
                    └────────┬──────────┘
                             │
┌────────────────────────────┼──────────────────────────────────────────┐
│                    Server Layer                                       │
├────────────────────────────┼──────────────────────────────────────────┤
│                   ┌────────▼─────────┐                               │
│                   │   norc-server    │                               │
│                   │  (Server Binary) │                               │
│                   └────────┬─────────┘                               │
│                            │                                          │
│         ┌──────────────────┼──────────────────┐                      │
│         │                  │                  │                      │
│  ┌──────▼──────┐  ┌────────▼────────┐  ┌─────▼──────┐              │
│  │ server-core │  │   admin-api     │  │ transport  │              │
│  │  (Logic)    │  │  (REST API)     │  │  (Health)  │              │
│  └──────┬──────┘  └────────┬────────┘  └─────┬──────┘              │
│         │                  │                  │                      │
│         └──────────────────┼──────────────────┘                      │
│                            │                                          │
└────────────────────────────┼──────────────────────────────────────────┘
                             │
┌────────────────────────────┼──────────────────────────────────────────┐
│                    Data Layer                                         │
├────────────────────────────┼──────────────────────────────────────────┤
│                   ┌────────▼─────────┐                               │
│                   │   persistence    │                               │
│                   │  (SQLite/DB)     │                               │
│                   └──────────────────┘                               │
└───────────────────────────────────────────────────────────────────────┘

┌───────────────────────────────────────────────────────────────────────┐
│                    Cross-Cutting Concerns                             │
├───────────────────────────────────────────────────────────────────────┤
│  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐    │
│  │  Metrics   │  │  Logging   │  │  Tracing   │  │   Config   │    │
│  │(Prometheus)│  │ (Tracing)  │  │  (Spans)   │  │   (TOML)   │    │
│  └────────────┘  └────────────┘  └────────────┘  └────────────┘    │
└───────────────────────────────────────────────────────────────────────┘
```

## Component Architecture

### 1. Client Components

```
┌─────────────────────────────────────────────────────────────┐
│                      Client Architecture                     │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│  User Interface Layer                                        │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐   ┌──────────────┐   ┌───────────────┐   │
│  │ norc-client  │   │  norc-tui    │   │  norc-diag    │   │
│  │              │   │              │   │               │   │
│  │ • CLI        │   │ • Terminal   │   │ • Validate    │   │
│  │ • Commands   │   │ • Interactive│   │ • Revocation  │   │
│  │ • Scripts    │   │ • Real-time  │   │ • Health      │   │
│  └──────┬───────┘   └──────┬───────┘   └───────┬───────┘   │
│         │                  │                   │            │
└─────────┼──────────────────┼───────────────────┼────────────┘
          │                  │                   │
          └──────────────────┴───────────────────┘
                             │
┌──────────────────────────────┼──────────────────────────────┐
│  Client Core Layer           │                              │
├──────────────────────────────┼──────────────────────────────┤
│                    ┌─────────▼─────────┐                    │
│                    │  norc-client-core │                    │
│                    ├───────────────────┤                    │
│                    │ • Connection Mgmt │                    │
│                    │ • Message Routing │                    │
│                    │ • State Machine   │                    │
│                    │ • Error Handling  │                    │
│                    └─────────┬─────────┘                    │
└──────────────────────────────┼──────────────────────────────┘
                               │
┌──────────────────────────────┼──────────────────────────────┐
│  Transport Layer             │                              │
├──────────────────────────────┼──────────────────────────────┤
│                    ┌─────────▼─────────┐                    │
│                    │  norc-transport   │                    │
│                    ├───────────────────┤                    │
│                    │ • TLS Config      │                    │
│                    │ • mTLS Auth       │                    │
│                    │ • Cert Validation │                    │
│                    │ • Health Checks   │                    │
│                    └───────────────────┘                    │
└─────────────────────────────────────────────────────────────┘
```

### 2. Server Components

```
┌─────────────────────────────────────────────────────────────┐
│                      Server Architecture                     │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│  Entry Point                                                 │
├─────────────────────────────────────────────────────────────┤
│                    ┌─────────────────┐                       │
│                    │  norc-server    │                       │
│                    │  (main binary)  │                       │
│                    └────────┬────────┘                       │
└─────────────────────────────┼──────────────────────────────┘
                              │
       ┌──────────────────────┼──────────────────────┐
       │                      │                      │
┌──────▼──────────┐  ┌────────▼────────┐  ┌─────────▼────────┐
│ norc-server-core│  │  norc-admin-api │  │ norc-transport   │
├─────────────────┤  ├─────────────────┤  ├──────────────────┤
│ • Federation    │  │ • REST API      │  │ • TLS Server     │
│ • Auth Logic    │  │ • Cert Mgmt     │  │ • Health Checks  │
│ • Message Flow  │  │ • Endpoints     │  │ • Rotation Mgmt  │
│ • State Mgmt    │  │ • Auth/Authz    │  │ • Revocation     │
└────────┬────────┘  └────────┬────────┘  └─────────┬────────┘
         │                    │                      │
         └────────────────────┼──────────────────────┘
                              │
┌─────────────────────────────┼──────────────────────────────┐
│  Data & Configuration       │                              │
├─────────────────────────────┼──────────────────────────────┤
│         ┌───────────────────┼───────────────────┐          │
│         │                   │                   │          │
│  ┌──────▼──────┐   ┌────────▼────────┐   ┌─────▼─────┐   │
│  │ persistence │   │  norc-config    │   │  protocol │   │
│  ├─────────────┤   ├─────────────────┤   ├───────────┤   │
│  │ • SQLite    │   │ • Server Config │   │ • Messages│   │
│  │ • Migrations│   │ • Security      │   │ • Types   │   │
│  │ • Queries   │   │ • Validation    │   │ • Schemas │   │
│  └─────────────┘   └─────────────────┘   └───────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### 3. Certificate Management Flow

```
┌──────────────────────────────────────────────────────────────┐
│           Certificate Lifecycle Management                   │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│  Certificate Operations                                       │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  Upload Certificate                                           │
│  ┌──────┐  POST /api/v1/certificates  ┌──────────────┐      │
│  │Client├────────────────────────────►│Admin API     │      │
│  └──────┘                              │              │      │
│                                        │ • Validate   │      │
│                                        │ • Parse      │      │
│                                        │ • Store      │      │
│                                        └──────┬───────┘      │
│                                               │              │
│                                        ┌──────▼───────┐      │
│                                        │ Persistence  │      │
│                                        └──────────────┘      │
│                                                               │
│  Certificate Rotation                                         │
│  ┌──────────────┐                     ┌──────────────┐      │
│  │File Watcher  ├─────────────────────►Rotation Mgr  │      │
│  │              │  Detects changes     │              │      │
│  └──────────────┘                     │ • Check mod  │      │
│                                        │ • Reload     │      │
│                                        │ • Notify     │      │
│                                        └──────┬───────┘      │
│                                               │              │
│                                        ┌──────▼───────┐      │
│                                        │ TLS Config   │      │
│                                        │ (Hot Reload) │      │
│                                        └──────────────┘      │
│                                                               │
│  Revocation Checking                                          │
│  ┌──────┐                              ┌──────────────┐      │
│  │Client├──────────────────────────────►Revocation    │      │
│  └──────┘  mTLS connection             │Checker       │      │
│                                        │              │      │
│                                        │ • OCSP Query │      │
│                                        │ • CRL Check  │      │
│                                        │ • Cache      │      │
│                                        └──────────────┘      │
└──────────────────────────────────────────────────────────────┘
```

### 4. Observability Architecture

```
┌──────────────────────────────────────────────────────────────┐
│              Observability Infrastructure                     │
└──────────────────────────────────────────────────────────────┘

Application Code
       │
       ├─────────────────────────────────────────┐
       │                                         │
       ▼                                         ▼
┌──────────────┐                        ┌──────────────┐
│   Metrics    │                        │   Logging    │
│              │                        │              │
│ • Counters   │                        │ • Structured │
│ • Gauges     │                        │ • Levels     │
│ • Histograms │                        │ • Context    │
└──────┬───────┘                        └──────┬───────┘
       │                                       │
       │                                       │
       ▼                                       ▼
┌──────────────┐                        ┌──────────────┐
│ Prometheus   │                        │  Tracing     │
│  /metrics    │                        │              │
│              │                        │ • Spans      │
│ • Scraping   │                        │ • Context    │
│ • Storage    │                        │ • Propagate  │
│ • Queries    │                        └──────┬───────┘
└──────┬───────┘                               │
       │                                       │
       │                                       ▼
       │                                ┌──────────────┐
       │                                │  Log Files   │
       │                                │              │
       │                                │ • JSON       │
       │                                │ • Rotation   │
       │                                └──────────────┘
       │
       ▼
┌──────────────┐
│   Grafana    │
│              │
│ • Dashboards │
│ • Alerts     │
│ • Explore    │
└──────────────┘

Health Checks
       │
       ├─────────────┬─────────────┬─────────────┐
       │             │             │             │
       ▼             ▼             ▼             ▼
┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐
│  Cert    │  │  OCSP    │  │  Database│  │  Backup  │
│  Store   │  │Responder │  │          │  │  Service │
└──────────┘  └──────────┘  └──────────┘  └──────────┘
```

## Data Flow

### 1. Client Connection Flow

```
┌──────┐                                              ┌──────┐
│Client│                                              │Server│
└──┬───┘                                              └───┬──┘
   │                                                      │
   │ 1. TCP Connection                                   │
   ├────────────────────────────────────────────────────►│
   │                                                      │
   │ 2. TLS Handshake (Client Hello)                    │
   ├────────────────────────────────────────────────────►│
   │                                                      │
   │ 3. Server Certificate + Request Client Cert        │
   │◄────────────────────────────────────────────────────┤
   │                                                      │
   │ 4. Client Certificate                               │
   ├────────────────────────────────────────────────────►│
   │                                                      │
   │    (Server validates client certificate)            │
   │    • Check signature                                │
   │    • Verify chain                                   │
   │    • Check expiration                               │
   │    • OCSP/CRL check                                 │
   │    • Pin validation                                 │
   │                                                      │
   │ 5. TLS Session Established                          │
   │◄────────────────────────────────────────────────────┤
   │                                                      │
   │ 6. Application Messages (encrypted)                 │
   │◄────────────────────────────────────────────────────►│
   │                                                      │
```

### 2. Message Processing Flow

```
Client Message
      │
      ▼
┌─────────────┐
│ Deserialize │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  Validate   │
│  • Schema   │
│  • Auth     │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   Route     │
│  • Handler  │
│  • Logic    │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  Process    │
│  • Business │
│  • State    │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   Store     │
│  • Database │
│  • Cache    │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  Serialize  │
└──────┬──────┘
       │
       ▼
Server Response
```

## Security Architecture

### Certificate Trust Model

```
┌──────────────────────────────────────────────────────────────┐
│                   Certificate Trust Chain                     │
└──────────────────────────────────────────────────────────────┘

                    ┌─────────────────┐
                    │   Root CA       │
                    │                 │
                    │ • Self-signed   │
                    │ • Long-lived    │
                    │ • Offline       │
                    └────────┬────────┘
                             │
                             │ signs
                             │
                    ┌────────▼────────┐
                    │ Intermediate CA │
                    │                 │
                    │ • Medium-lived  │
                    │ • Online        │
                    └────────┬────────┘
                             │
                 ┌───────────┴───────────┐
                 │                       │
          signs  │                       │ signs
                 │                       │
        ┌────────▼────────┐     ┌────────▼────────┐
        │  Server Cert    │     │  Client Cert    │
        │                 │     │                 │
        │ • Short-lived   │     │ • Short-lived   │
        │ • Rotatable     │     │ • Per-user      │
        │ • SAN: server.* │     │ • CN: user-id   │
        └─────────────────┘     └─────────────────┘
```

### mTLS Authentication Flow

```
┌──────────────────────────────────────────────────────────────┐
│          Mutual TLS Authentication Process                    │
└──────────────────────────────────────────────────────────────┘

Client Side:                    Server Side:
┌──────────────┐               ┌──────────────┐
│ Load Client  │               │ Load Server  │
│ Certificate  │               │ Certificate  │
└──────┬───────┘               └──────┬───────┘
       │                              │
       │        TLS Handshake         │
       │◄────────────────────────────►│
       │                              │
       │   Server Cert Validation     │
       │   • Verify signature         │
       │   • Check expiration         │
       │   • Validate hostname        │
       │                              │
       │                              │   Client Cert Validation
       │                              │   • Verify signature
       │                              │   • Check expiration
       │                              │   • Extract org ID
       │                              │   • Check revocation
       │                              │   • Verify pin
       │                              │
       ▼                              ▼
┌──────────────┐               ┌──────────────┐
│ Authenticated│               │ Authenticated│
│ Connection   │               │ Connection   │
└──────────────┘               └──────────────┘
```

## Deployment Architecture

### Single Server Deployment

```
┌────────────────────────────────────────────────────────────┐
│                      Single Server                          │
├────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │                    norc-server                       │  │
│  │                                                      │  │
│  │  Ports:                                             │  │
│  │  • 8080  (HTTP)                                     │  │
│  │  • 8443  (HTTPS/mTLS)                               │  │
│  │  • 9090  (Metrics)                                  │  │
│  └────────────────┬─────────────────────────────────────┘  │
│                   │                                        │
│  ┌────────────────▼─────────────────────────────────────┐  │
│  │                  SQLite Database                     │  │
│  │  /var/lib/norc/norc.db                              │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              Certificate Storage                     │  │
│  │  /etc/norc/certs/                                   │  │
│  │  • server.pem                                       │  │
│  │  • server-key.pem                                   │  │
│  └──────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────┘
```

### High Availability Deployment

```
┌────────────────────────────────────────────────────────────────┐
│                  Load Balancer (HAProxy/Nginx)                 │
│                     • TLS Termination                          │
│                     • Health Checks                            │
└───────────────┬─────────────────────────┬──────────────────────┘
                │                         │
    ┌───────────┴───────────┐ ┌──────────┴──────────┐
    │                       │ │                     │
┌───▼────────────────┐  ┌───▼────────────────┐  ┌──▼─────────────────┐
│  norc-server-1     │  │  norc-server-2     │  │  norc-server-3     │
│                    │  │                    │  │                    │
│  • Active          │  │  • Active          │  │  • Active          │
│  • Metrics         │  │  • Metrics         │  │  • Metrics         │
└────────┬───────────┘  └────────┬───────────┘  └────────┬───────────┘
         │                       │                       │
         └───────────────────────┴───────────────────────┘
                                 │
                    ┌────────────▼───────────────┐
                    │   PostgreSQL Cluster       │
                    │   • Primary + Replicas     │
                    │   • Automatic Failover     │
                    └────────────────────────────┘
```

### Container Deployment (Kubernetes)

```
┌─────────────────────────────────────────────────────────────────┐
│                      Kubernetes Cluster                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │                      Ingress Controller                     │ │
│  │  • TLS Termination                                         │ │
│  │  • Rate Limiting                                           │ │
│  └──────────────┬─────────────────────────────────────────────┘ │
│                 │                                               │
│  ┌──────────────▼────────────────────────────────┐             │
│  │              Service (LoadBalancer)            │             │
│  │              norc-server-service              │             │
│  └──────────────┬─────────────────────────────────┘             │
│                 │                                               │
│     ┌───────────┼───────────┬───────────┐                      │
│     │           │           │           │                      │
│  ┌──▼──────┐ ┌──▼──────┐ ┌──▼──────┐ ┌──▼──────┐             │
│  │ Pod 1   │ │ Pod 2   │ │ Pod 3   │ │ Pod N   │             │
│  │         │ │         │ │         │ │         │             │
│  │ norc-   │ │ norc-   │ │ norc-   │ │ norc-   │             │
│  │ server  │ │ server  │ │ server  │ │ server  │             │
│  └─────────┘ └─────────┘ └─────────┘ └─────────┘             │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │              Persistent Volume (PVC)                      │  │
│  │              Database Storage                             │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                     ConfigMap                             │  │
│  │                     • Server Config                       │  │
│  │                     • Certificates                        │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                      Secrets                              │  │
│  │                      • TLS Keys                           │  │
│  │                      • API Tokens                         │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## Performance Characteristics

### Scalability

- **Vertical Scaling**: Up to 16 cores, 32GB RAM per instance
- **Horizontal Scaling**: Linear scaling with load balancer
- **Connection Capacity**: 10,000+ concurrent connections per instance
- **Message Throughput**: 100,000+ messages/sec per instance

### Latency Targets

- **p50 Latency**: < 10ms
- **p95 Latency**: < 50ms
- **p99 Latency**: < 100ms
- **TLS Handshake**: < 100ms

## Technology Stack

### Languages & Frameworks
- **Rust 1.90+**: Core implementation
- **Tokio**: Async runtime
- **Axum**: HTTP server framework
- **SQLx**: Database access
- **rustls**: TLS implementation

### Data Storage
- **SQLite**: Single-server deployments
- **PostgreSQL**: Multi-server deployments
- **Redis**: Caching (optional)

### Observability
- **Prometheus**: Metrics collection
- **Grafana**: Visualization
- **Tracing**: Structured logging
- **OpenTelemetry**: Distributed tracing

### DevOps
- **Docker**: Containerization
- **Kubernetes**: Orchestration
- **GitHub Actions**: CI/CD
- **cargo-llvm-cov**: Code coverage

## Design Principles

1. **Security First**: mTLS for all connections, certificate pinning, revocation checking
2. **Observability**: Comprehensive metrics, logging, and tracing
3. **Reliability**: Graceful degradation, health checks, automatic recovery
4. **Performance**: Async I/O, zero-copy where possible, efficient serialization
5. **Maintainability**: Clear separation of concerns, comprehensive testing, documentation

## Future Architecture

### Planned Enhancements

1. **QUIC Transport**: UDP-based transport for better performance
2. **Federation Protocol**: Cross-server communication
3. **Edge Caching**: CDN-like certificate caching
4. **Service Mesh**: Istio/Linkerd integration
5. **Event Sourcing**: Complete audit trail

---

*Last Updated: 2025-10-02*  
*NORC System Architecture v0.1.0*
