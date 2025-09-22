# NORC: Why Organizations Need a New Approach to Secure Real-time Communication

**The first protocol that doesn't make you choose between security and collaboration**

In a world where data breaches make headlines daily and quantum computers threaten to break today's encryption, organizations face a critical challenge: How do you enable secure collaboration across different companies, governments, and partners without compromising security or creating operational nightmares?

Current solutions force you to choose between security and collaboration. **NORC (NavaTron Open Real-time Communication)** is the first protocol designed specifically to solve this problem.

---

## What is NORC?

NORC is a secure real-time communication protocol built for organizations that need both ironclad security and practical federation. Think of it as the next evolution beyond Signal (secure but centralized) and Matrix (federated but complex)—combining the best of both worlds while preparing for the post-quantum future.

**Key Innovation**: NORC uses a five-state graduated trust hierarchy instead of the traditional all-or-nothing approach to federation:

| Level | Purpose | Cryptographic Requirement (summary) |
|-------|---------|--------------------------------------|
| Untrusted | No relationship – communication blocked | N/A (connection refused) |
| Basic | Standard business collaboration | Classical E2E (Ed25519 + X25519 + ChaCha20-Poly1305) |
| Verified | Higher assurance (validated org identity) | Mandatory hybrid (X25519 + Kyber768) |
| Classified | Security-cleared, regulated environments | Hybrid + hardened deployment (HSM recommended) |
| NATO | International defense/security cooperation | Hybrid + national/FIPS-aligned algorithms + PQ signature roadmap |

Hybrid post-quantum key agreement (classical + Kyber768) is mandatory for Verified and above; Basic can opportunistically upgrade if both sides advertise support. Any downgrade attempt when hybrid is mutually supported is cryptographically detected and aborted.

> Footnote: References to "256-bit" (e.g., in planning materials or comparative charts) denote a long-term symmetric security retention objective derived from combining classical + post-quantum key establishment (hybrid X25519 + Kyber768) and do not imply that all asymmetric primitives presently provide 256 bits of classical security. Current asymmetric primitives (Ed25519, X25519) remain ~128-bit classical strength while achieving a post-quantum hedge through hybrid KEM. PQ signature deployment follows the published roadmap; until standardized and mandated, signature operations remain classical-only.

### Three-Layer Architecture

```
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│   NORC-T        │  │   NORC-F        │  │   NORC-C        │
│ Trust Management│◄─┤ Federation Layer│◄─┤ Client-Server   │
│                 │  │                 │  │                 │
│ * Trust levels  │  │ * Message relay │  │ * Device auth   │
│ * Verification  │  │ * Trust enforce │  │ * E2E messaging │
│ * Revocation    │  │ * Load balance  │  │ * File transfer │
│ * Audit trails  │  │ * Performance   │  │ * Presence      │
└─────────────────┘  └─────────────────┘  └─────────────────┘
```

**NORC-C** (Client): Your apps and devices - handles encryption, authentication, and user experience  
**NORC-F** (Federation): Your servers - relay encrypted messages between organizations  
**NORC-T** (Trust): The governance layer - manages who can talk to whom and at what security level

---
## Operational Guarantees (Current Targets)

| Property | Target | Notes |
|----------|--------|-------|
| Interactive Latency | ≤500 ms (95th pct), ≤100 ms intra-org typical | Under normal load conditions |
| Version Compatibility | Adjacent major only (N ↔ N±1) | Deterministic reject outside window |
| Revocation Propagation | ≤300 s federation-wide | Push + ≤60 s polling fallback |
| Availability (Ref Arch) | ≥99.9% with redundancy | Not a protocol guarantee—deployment guidance |
| Max Interactive Message | 4 MiB | Larger via chunked file transfer |
| Padding | Bucketed (1KB–256KB) | Adaptive privacy vs overhead |
| Hybrid PQ Adoption | Mandatory ≥ Verified | Basic opportunistic upgrade |
| Forward Secrecy | Ephemeral per-session + wrapped per-message keys | No plaintext on servers |

## Formal Assurance & Security Engineering

* Handshake & key schedule modelled (Tamarin/ProVerif – in progress) for secrecy, authentication, downgrade resistance.
* Cryptographically chained audit logs (BLAKE3 hash chain) – metadata only, no plaintext content.
* Replay / KCI / downgrade resistance enforced via transcript binding, sequence windows, hybrid negotiation.
* Supply chain integrity (reproducible builds, signed artifacts, SBOM, provenance attestations) – see Requirements §18.3.
* PQ Signature Roadmap: Evaluation 2026 → experimental dual-sign → staged mandate (Classified/NATO earliest 2027).

## Algorithm Agility

Baseline: Ed25519 / X25519 (+ Kyber768 for Verified+) / ChaCha20-Poly1305 / BLAKE3 / HKDF (`norc:` labels).

Negotiable alternatives: AES-256-GCM (FIPS / hardware), SHA-256 (FIPS), future PQ signatures (Dilithium/Falcon), additional PQ KEM variants. Selection always prefers strongest mutually supported set; downgrade ambiguity aborts the handshake.

## Why Does NORC Exist?

### The Current Problem

Existing secure communication protocols fail organizations in three critical ways:

1. **Security vs Federation Trade-off**: Signal is incredibly secure but only works within one company. Matrix enables federation but makes security optional, creating vulnerabilities.

2. **Maintenance Nightmare**: Protocols like TLS and Matrix accumulate decades of backward compatibility requirements, making them increasingly complex and vulnerable.

3. **Quantum Vulnerability**: Most current protocols will be broken by quantum computers, which may arrive sooner than expected. Organizations need protection against "harvest now, decrypt later" attacks happening today.

### The NORC Solution

NORC solves these problems through four key innovations:

🛡️ **Security-First Design**: Every message is encrypted end-to-end by default. No optional security, no plaintext fallbacks, no exceptions.

🤝 **Smart Federation**: Organizations can federate selectively based on verified trust relationships rather than hoping everyone plays nice.

🔄 **Bounded Complexity**: NORC only supports adjacent major versions (N ↔ N+1), preventing the complexity explosion that kills other protocols.

🔮 **Quantum Ready**: Built-in hybrid post-quantum cryptography protects against both current and future threats.

---

## Who is NORC For?

NORC is designed for organizations that can't compromise on security:

### Defense and Government

* Multi-national cooperation (NATO, Five Eyes, allied defense contractors)
* Classified information sharing with cryptographic audit trails  
* Supply chain coordination across security-cleared vendors
* Diplomatic communications requiring both security and deniability

### Enterprise and Critical Infrastructure

* Financial institutions sharing threat intelligence
* Healthcare systems collaborating on patient care across organizations
* Energy companies coordinating grid operations and incident response
* Technology companies with sensitive IP and customer data

### Why Not Just Use Signal or Teams?

* **Signal**: Perfect for individuals and small teams, but doesn't scale to multi-organization collaboration
* **Microsoft Teams**: Great for business, but no on-premises installation—you need to trust Microsoft
* **Slack/Discord**: Designed for convenience, not security
* **Matrix**: Federation-capable but security is optional and implementation is complex

---

## What Problems Does NORC Solve?

### 1. The Federation Security Problem

**Traditional Approach**: "Trust everyone or trust no one"
* Matrix: Anyone can join, security is optional
* Signal: Only works within one organization

**NORC's Approach**: "Trust selectively with cryptographic verification"
* Organizations explicitly negotiate trust relationships
* Each level has different security requirements
* Trust can be instantly revoked with cryptographic proof
* All decisions are recorded in tamper-evident audit logs

### 2. The Complexity Time Bomb  

**The Problem**: Every protocol eventually becomes unmaintainable
* TLS supports ancient SSL versions vulnerable to attacks
* Email protocols carry 40+ years of legacy extensions
* Matrix rooms can have incompatible encryption settings

**NORC's Solution**: Adjacent-Major Compatibility (AMC)
* Only support 2 versions at once (current + next OR current + previous)
* Forces regular upgrades but prevents breaking changes
* Predictable migration timelines for IT departments
* Bounded testing and security analysis requirements

### 3. The Quantum Computing Threat

**The Reality**: Quantum computers that can break current encryption are coming
* Could happen in 10-30 years (experts disagree on timeline)
* "Harvest now, decrypt later" attacks are happening TODAY
* Most organizations have no quantum-resistant strategy

**NORC's Approach**: Hybrid cryptography from day one
* Combines classical encryption (secure today) with post-quantum (secure tomorrow)
* If either approach is broken, your data stays protected
* Gradual transition as quantum threats become real
* No painful migration when quantum computers arrive

---

## How Does NORC Work?

### Security Features That Actually Matter

**Device-Level Security**: Every device has its own encryption keys

* Lost phone? Only that device is compromised
* Employee leaves? Revoke only their devices
* Granular access control based on device trust

**Metadata Protection**: Servers can't see what you're sharing

* File names, sizes, and types are encrypted
* Message timing is randomized to prevent analysis
* Only encrypted blobs flow between organizations

**Forward Secrecy**: Past messages stay secure even if keys are stolen

* Each conversation uses ephemeral keys
* Keys are automatically deleted after use
* Compromise of today's keys doesn't affect yesterday's messages

**Audit Everything**: Perfect for compliance and investigation

* Every trust decision is cryptographically recorded
* Message routing is logged without revealing content
* Tamper-evident audit trails for regulatory compliance

### Cryptography Stack

NORC uses modern, battle-tested cryptographic primitives:

| Function | Algorithm | Why |
|----------|-----------|-----|
| Signatures | Ed25519 | Fast, small, widely reviewed |
| Key Exchange | X25519 + Kyber768 (hybrid) | Classical security + post-quantum |
| Encryption | ChaCha20-Poly1305 | High performance, well studied |
| Hashing | BLAKE3 | Fastest secure hash function |

---

## Why Another Protocol?

### The Honest Answer: Because None of the Existing Ones Work for Organizations

**Signal Protocol**: Brilliant cryptography, wrong architecture

* Built for consumer messaging apps
* Centralized design doesn't support federation
* No enterprise governance features

**Matrix Protocol**: Right idea, execution problems

* Security is optional (most deployments are insecure)
* Complexity grows without bound (operational nightmare)
* Federation is trust-everyone-or-no-one

**TLS + Application Layer**: The current enterprise approach

* Every app rolls its own security (inconsistent, usually wrong)
* No standardized federation between different systems
* Compliance features bolted on as afterthoughts

**NORC's Advantage**: Purpose-built for organizational security needs

* Federation designed into the protocol from day one
* Security is mandatory, not optional
* Governance and compliance features are built-in, not add-ons
* Predictable complexity through version management

---

## What's Next?

NORC is currently in active development with implementations in Rust (performance-focused). The protocol specifications are open source under Apache-2.0 license.

### Post-Quantum Signature Roadmap (Preview)

| Phase | Target Window | Goal |
|-------|---------------|------|
| Evaluation | Q1–Q2 2026 | Benchmark Dilithium/Falcon/SPHINCS+, side-channel review |
| Experimental Extension | Q3 2026 | Dual-sign (Ed25519 + PQ) extension & test vectors |
| Hybrid Adoption | Q4 2026 | Optional dual-sign for Verified+ production pilots |
| Mandate Proposal | Q1 2027 | Governance decision for Classified/NATO requirement |
| Potential Enforcement | Q4 2027+ | PQ signatures required at highest trust levels |

Timeline assumes standardization stability and positive interoperability/security outcomes.

### For Security Researchers

* Formal verification of security properties using tools like Tamarin/ProVerif
* Performance optimization and cryptographic analysis
* Integration with post-quantum cryptography research

### For Organizations

* Evaluate NORC for future secure collaboration requirements
* Participate in early adopter programs and testing
* Contribute to compliance and governance requirements

---

## The Bottom Line

NORC exists because organizations need secure communication that actually works in the real world.

You shouldn't have to choose between security and collaboration. You shouldn't have to manage increasingly complex legacy protocols. You shouldn't have to rebuild your entire infrastructure when quantum computers arrive.

NORC is designed to be the communication protocol your organization will still be using in 2040—secure, federated, maintainable, and quantum-resistant.

The future of organizational communication will be determined by the protocols we build today. NORC aims to be one of them.

---

## License & Community

**License**: Apache 2.0 – Enterprise-friendly, patent-protected, commercially permissive

**Community**:
* [Protocol Discussions](../../discussions) - Design and implementation questions
* [Security Issues](mailto:security@navatron.com) - Private security disclosure
* [Blog & Updates](https://clemens.ms/norc/) - Latest developments and insights
* [Contact](mailto:norc@navatron.com) - Partnership and early access programs

---

**NORC: Secure federatated messaging without compromise**