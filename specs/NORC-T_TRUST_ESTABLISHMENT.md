# NORC-T: Trust Establishment Protocol Specification  
## Version 1.0

---

## 1. Overview

NORC-T defines the trust establishment and management protocol between NORC servers. It handles the cryptographic handshakes, certificate validation, trust levels, and ongoing trust maintenance required for secure federation.

### 1.1 Quick Glossary
| Term | Meaning |
|------|---------|
| Trust Request | Initial proposal containing desired level & evidence |
| Challenge | Structured set of verification tasks (DNS, cert, crypto proof) |
| Trust Decision | Accept / reject / conditional result with permissions |
| Trust Certificate | Signed artifact codifying granted permissions & expiry |
| Revocation | Signed notice withdrawing previously granted trust |
| Renewal | Update to extend or modify existing trust relationship |

### 1.2 End-to-End Trust Flow (Narrative)
1. Capability advertisement enumerates methods & supported levels.
2. Requesting server issues `trust_request` referencing evidence & desired level.
3. Responding server generates `trust_challenge` (domain, certificate, cryptographic proof, organization documents). 
4. Requester replies with `trust_response` satisfying each challenge element.
5. Responding server evaluates, computes trust score, issues `trust_decision` and certificate.
6. Requester acknowledges with `trust_acknowledgment`; mutual trust becomes active.
7. Continuous monitoring (health & compliance) may trigger renewal or revocation.

### 1.3 Trust Decision Matrix (Example Heuristic)
| Evidence Attribute | Weight | Criteria | Score Contribution |
|--------------------|-------:|---------|-------------------|
| Certificate Chain Validity | 0.30 | Valid + CT + OCSP | 0..30 |
| Domain Proof Freshness | 0.15 | Within 24h | 0..15 |
| Organization Verification | 0.20 | Third-party attested | 0..20 |
| Security Posture (Incidents) | 0.15 | < threshold incidents | 0..15 |
| Compliance Certifications | 0.10 | FIPS / ISO present | 0..10 |
| Historical Reliability | 0.10 | Uptime & response metrics | 0..10 |
> Threshold for `verified` ≥70, `classified` ≥85 (deployment-specific – illustrative only).

### 1.4 Certificate Lifecycle Overview
| Phase | Action | Key Checks |
|-------|--------|------------|
| Issuance | Sign trust certificate | Validity window, signature integrity |
| Distribution | Provide to peer | Channel security (mTLS) |
| Active Monitoring | Health, incident, revocation scanning | Expiry proximity, condition deadlines |
| Renewal | New certificate before `not_after` | Overlap to prevent delivery gaps |
| Revocation | Broadcast & cache revocation | Immediate route disablement |

**Version Compatibility**: NORC-T follows Adjacent-Major Compatibility (AMC):
- Version 1.x ↔ 2.x ✅ Compatible
- Version 1.x ↔ 3.x ❌ Not Compatible  
- Version 2.x ↔ 3.x ✅ Compatible

**Cross-Protocol Compatibility**: NORC-T version must be compatible with both participating servers' NORC-F versions.

## 2. Trust Models

### 2.1 Trust Levels

NORC-T supports hierarchical trust levels with increasing security requirements:

```erlang
-type trust_level() :: untrusted     % No trust established
                    | basic          % Basic domain verification
                    | verified       % Organization verification
                    | classified     % Government/enterprise PKI
                    | nato           % NATO-level security clearance.

%% Trust level requirements
-record(trust_requirements, {
    level :: trust_level(),
    certificate_authority :: ca_type(),
    key_algorithm :: key_algorithm(),
    min_key_size :: integer(),
    certificate_transparency :: boolean(),
    compliance_standards :: [compliance_standard()],
    background_check :: boolean()
}).

-type ca_type() :: self_signed | commercial_ca | government_ca | nato_ca.
-type key_algorithm() :: ed25519 | rsa_pss | ecdsa_p256.
-type compliance_standard() :: fips_140_2 | common_criteria | nato_unclass.
```

### 2.2 Trust Establishment Methods

```erlang
-type trust_method() :: direct_exchange    % Direct key exchange
                      | ca_validation      % Certificate Authority validation
                      | web_of_trust      % Peer recommendation
                      | government_pki    % Government PKI integration
                      | manual_verification. % Out-of-band verification

%% Trust method capabilities
-record(trust_method_spec, {
    method :: trust_method(),
    automatic :: boolean(),          % Can be automated
    max_trust_level :: trust_level(), % Highest achievable trust
    validation_time :: integer(),    % Typical validation time (seconds)
    cost :: cost_level(),           % Implementation cost
    revocation_support :: boolean()  % Supports revocation
}).

-type cost_level() :: free | low | medium | high | enterprise.
```

## 3. Trust Establishment Flow

### 3.1 Trust Discovery Phase

```erlang
%% Trust Capability Advertisement with Version Support
#{
    type => trust_capabilities,
    protocol_version => <<"1.0">>,
    supported_versions => [<<"1.0">>, <<"1.1">>, <<"2.0">>],  % AMC compatible versions
    server_id => <<"alice.example.org">>,
    supported_methods => [direct_exchange, ca_validation, web_of_trust],
    supported_trust_levels => [basic, verified, classified],
    certificate_authorities => [
        <<"DigiCert Global Root CA">>,
        <<"ISRG Root X1">>,
        <<"DOD Root CA 3">>
    ],
    key_algorithms => [ed25519, rsa_pss],
    compliance_certifications => [fips_140_2],
    trust_policies => #{
        auto_accept_basic => false,
        require_manual_approval => true,
        trust_inheritance => false,  % Don't inherit trust from peers
        max_trust_age => 31536000,   % 1 year in seconds
        version_compatibility => #{
            enforce_amc => true,      % Enforce AMC rules
            allow_downgrade => false, % Don't allow version downgrade
            require_latest_minor => false % Don't require latest minor version
        }
    }
}
```

### 3.2 Trust Initiation

```erlang
%% Trust Request Initiation
#{
    type => trust_request,
    request_id => <<"trust-req-uuid">>,
    requesting_server => <<"alice.example.org">>,
    target_server => <<"bob.example.org">>,
    requested_trust_level => verified,
    trust_method => ca_validation,
    certificate_chain => [
        <<AliceServerCert/binary>>,
        <<IntermediateCert/binary>>,
        <<RootCACert/binary>>
    ],
    server_public_key => <<Ed25519PubKey:32/binary>>,
    domain_proof => #{
        method => dns_txt,           % DNS TXT record verification
        challenge => <<"norc-trust-", ChallengeBytes:32/binary>>,
        txt_record => <<"alice.example.org">>,
        expires_at => UnixTimestamp
    },
    organization_info => #{
        name => <<"Alice Corp">>,
        country => <<"US">>,
        contact_email => <<"admin@alice.example.org">>,
        phone => <<"+1-555-0123">>,
        address => <<"123 Main St, Anytown, US">>
    },
    compliance_attestations => [
        #{standard => fips_140_2, certificate_id => <<"FIPS-12345">>,
          issued_by => <<"NIST">>, expires_at => UnixTimestamp}
    ],
    trust_requirements => #{
        mutual => true,              % Require mutual trust
        witness_required => false,   % Third-party witness needed
        background_check => false,
        audit_trail => true
    },
    timestamp => UnixTimestamp,
    signature => <<Ed25519RequestSignature:64/binary>>
}
```

### 3.3 Trust Validation

```erlang
%% Trust Challenge
#{
    type => trust_challenge,
    request_id => <<"trust-req-uuid">>,
    challenge_id => <<"challenge-uuid">>,
    target_server => <<"alice.example.org">>,
    challenging_server => <<"bob.example.org">>,
    validation_method => ca_validation,
    challenges => [
        #{
            type => domain_ownership,
            method => dns_txt,
            domain => <<"alice.example.org">>,
            txt_record_name => <<"_norc-trust-challenge.alice.example.org">>,
            expected_value => <<"norc-trust-", ChallengeData:32/binary>>,
            expires_at => UnixTimestamp
        },
        #{
            type => certificate_validation,
            certificate_chain => [<<AliceServerCert/binary>>, <<IntermediateCert/binary>>],
            validation_requirements => #{
                check_revocation => true,
                require_ct_logs => true,    % Certificate Transparency
                max_age_days => 90
            }
        },
        #{
            type => cryptographic_proof,
            challenge_data => <<RandomBytes:64/binary>>,
            required_signature_algorithm => ed25519,
            must_sign_with => server_key
        }
    ],
    organization_verification => #{
        required_documents => [business_registration, contact_verification],
        verification_method => third_party,     % manual | automated | third_party
        compliance_check_required => true
    },
    deadline => UnixTimestamp  % Challenge response deadline
}

%% Trust Challenge Response
#{
    type => trust_response,
    request_id => <<"trust-req-uuid">>,
    challenge_id => <<"challenge-uuid">>,
    responding_server => <<"alice.example.org">>,
    challenge_responses => [
        #{
            type => domain_ownership,
            proof_method => dns_txt,
            dns_response => <<DNSResponse/binary>>,
            timestamp => UnixTimestamp
        },
        #{
            type => certificate_validation,
            ocsp_responses => [<<OCSPResponse1/binary>>, <<OCSPResponse2/binary>>],
            ct_log_proofs => [<<CTProof1/binary>>, <<CTProof2/binary>>]
        },
        #{
            type => cryptographic_proof,
            challenge_data => <<RandomBytes:64/binary>>,
            signature => <<Ed25519ChallengeSignature:64/binary>>,
            signing_key => server_key
        }
    ],
    organization_proofs => [
        #{document_type => business_registration,
          document_hash => <<SHA256:32/binary>>,
          issuing_authority => <<"Delaware Secretary of State">>,
          verification_code => <<"BIZ-12345">>},
        #{document_type => contact_verification,
          verification_method => phone_call,
          verified_by => <<"TrustProvider Inc">>,
          verification_id => <<"VP-67890">>}
    ],
    timestamp => UnixTimestamp,
    signature => <<Ed25519ResponseSignature:64/binary>>
}
```

### 3.4 Trust Decision

```erlang
%% Trust Decision
#{
    type => trust_decision,
    request_id => <<"trust-req-uuid">>,
    decision_server => <<"bob.example.org">>,
    target_server => <<"alice.example.org">>,
    decision => accept,              % accept | reject | conditional
    granted_trust_level => verified,
    trust_conditions => [
        #{condition => certificate_renewal,
          deadline => UnixTimestamp,
          auto_revoke => true},
        #{condition => compliance_audit,
          frequency => quarterly,
          next_audit => UnixTimestamp}
    ],
    trust_metadata => #{
        established_at => UnixTimestamp,
        expires_at => UnixTimestamp,
        renewable => true,
        revocable => true,
        trust_score => 95.5,         % Computed trust score (0-100)
        validation_evidence => [
            #{type => dns_validation, status => verified, timestamp => UnixTimestamp},
            #{type => certificate_validation, status => verified, timestamp => UnixTimestamp},
            #{type => organization_verification, status => verified, timestamp => UnixTimestamp}
        ]
    },
    federation_permissions => #{
        message_relay => true,
        user_discovery => true,
        presence_federation => true,
        media_relay => false,        % Media relay not authorized
        archive_sync => true,
        voice_calls => true,
        file_transfer => true,
        max_message_size => 16777216, % 16MB
        rate_limits => #{
            messages_per_second => 500,
            bandwidth_mbps => 50
        }
    },
    mutual_trust_required => true,
    decision_signature => <<Ed25519DecisionSignature:64/binary>>,
    certificate_bundle => [
        <<TrustCertificate/binary>>, % Certificate representing this trust relationship
        <<SigningCACert/binary>>
    ]
}

%% Trust Acknowledgment
#{
    type => trust_acknowledgment,
    request_id => <<"trust-req-uuid">>,
    acknowledging_server => <<"alice.example.org">>,
    decision_accepted => true,
    mutual_trust_established => true,
    trust_certificate => <<MutualTrustCert/binary>>,
    effective_date => UnixTimestamp,
    next_renewal_date => UnixTimestamp,
    acknowledgment_signature => <<Ed25519AckSignature:64/binary>>
}
```

## 4. Trust Certificate Format

### 4.1 NORC Trust Certificate

```erlang
%% NORC Trust Certificate Structure
-record(norc_trust_certificate, {
    version :: integer(),            % Certificate format version
    certificate_id :: binary(),     % Unique certificate identifier
    issuer_server :: binary(),       % Server that issued trust
    subject_server :: binary(),      % Server receiving trust
    trust_level :: trust_level(),
    permissions :: [federation_permission()],
    not_before :: integer(),         % Valid from timestamp
    not_after :: integer(),          % Valid until timestamp
    renewable :: boolean(),
    revocable :: boolean(),
    conditions :: [trust_condition()],
    public_key :: binary(),          % Subject server's public key
    key_algorithm :: key_algorithm(),
    extensions :: [certificate_extension()],
    signature_algorithm :: signature_algorithm(),
    signature :: binary()           % Issuer's signature
}).

-type federation_permission() :: message_relay | user_discovery | presence_federation |
                                media_relay | archive_sync | voice_calls | file_transfer.

-record(trust_condition, {
    condition_type :: condition_type(),
    parameters :: map(),
    deadline :: integer(),
    auto_action :: auto_action()     % What happens if condition fails
}).

-type condition_type() :: certificate_renewal | compliance_audit | 
                         security_review | trust_revalidation.
-type auto_action() :: revoke | downgrade | notify.
```

### 4.2 Certificate Validation

```erlang
%% Trust Certificate Validation
validate_trust_certificate(Cert = #norc_trust_certificate{}) ->
    Checks = [
        fun validate_signature/1,
        fun validate_expiry/1,
        fun validate_issuer/1,
        fun validate_permissions/1,
        fun validate_conditions/1,
        fun check_revocation_status/1
    ],
    case run_validation_checks(Cert, Checks) of
        {ok, valid} -> {ok, Cert};
        {error, Reason} -> {error, {invalid_certificate, Reason}}
    end.

%% Certificate revocation check
check_revocation_status(#norc_trust_certificate{certificate_id = CertId}) ->
    case query_crl_or_ocsp(CertId) of
        {ok, not_revoked} -> ok;
        {ok, revoked} -> {error, certificate_revoked};
        {error, unavailable} -> {warning, revocation_status_unknown}
    end.
```

## 5. Trust Revocation

### 5.1 Revocation Initiation

```erlang
%% Trust Revocation Request
#{
    type => trust_revoke,
    revocation_id => <<"revoke-uuid">>,
    revoking_server => <<"bob.example.org">>,
    target_server => <<"alice.example.org">>,
    trust_certificate_id => <<"trust-cert-uuid">>,
    revocation_reason => compromised_key, % compromised_key | policy_violation | 
                                         % voluntary | expired | superseded
    effective_date => UnixTimestamp,     % When revocation takes effect
    evidence => [
        #{type => security_incident,
          incident_id => <<"SEC-2024-001">>,
          description => <<"Suspected private key compromise">>,
          severity => high},
        #{type => policy_violation,
          policy => <<"federation_policy_v1.0">>,
          violation_details => <<"Unauthorized data sharing detected">>}
    ],
    revocation_scope => full,            % full | partial | conditional
    partial_revocation_permissions => [], % If scope = partial
    grace_period => 3600,               % Seconds before full effect
    notification_recipients => [
        <<"admin@alice.example.org">>,
        <<"security@alice.example.org">>
    ],
    revocation_signature => <<Ed25519RevocationSignature:64/binary>>
}

%% Revocation Acknowledgment  
#{
    type => revocation_acknowledgment,
    revocation_id => <<"revoke-uuid">>,
    acknowledging_server => <<"alice.example.org">>,
    acknowledgment_status => accepted,   % accepted | disputed | appealing
    effective_acknowledgment => UnixTimestamp,
    cleanup_actions => [
        <<"Terminated all federation connections">>,
        <<"Purged cached trust certificates">>,
        <<"Notified local administrators">>
    ],
    appeal_filed => false,
    acknowledgment_signature => <<Ed25519AckSignature:64/binary>>
}
```

### 5.2 Certificate Revocation Lists (CRL)

```erlang
%% NORC Certificate Revocation List
-record(norc_crl, {
    issuer_server :: binary(),
    this_update :: integer(),        % CRL generation timestamp
    next_update :: integer(),        % Next CRL update expected
    revoked_certificates :: [revoked_certificate()],
    crl_extensions :: [crl_extension()],
    signature_algorithm :: signature_algorithm(),
    signature :: binary()
}).

-record(revoked_certificate, {
    certificate_id :: binary(),
    revocation_date :: integer(),
    revocation_reason :: revocation_reason(),
    extensions :: [revocation_extension()]
}).

-type revocation_reason() :: unspecified | key_compromise | ca_compromise |
                            affiliation_changed | superseded | cessation_of_operation |
                            privilege_withdrawn | aa_compromise.
```

## 6. Web of Trust Model

### 6.1 Trust Recommendation

```erlang
%% Trust Recommendation Request
#{
    type => trust_recommendation,
    request_id => <<"recommend-uuid">>,
    requesting_server => <<"charlie.example.org">>,
    target_server => <<"alice.example.org">>,
    recommender_server => <<"bob.example.org">>,
    recommendation_level => basic,   % basic | verified | strong
    evidence_required => true,
    context => <<"Charlie Corp seeking to establish business communications">>,
    vouch_data => #{
        relationship_duration => 2592000, % 30 days in seconds
        interaction_frequency => high,
        trust_incidents => 0,
        business_relationship => verified,
        security_assessment => passed
    }
}

%% Trust Recommendation Response
#{
    type => trust_recommendation_response,
    request_id => <<"recommend-uuid">>,
    recommender_server => <<"bob.example.org">>,
    target_server => <<"alice.example.org">>,
    recommendation => positive,      % positive | negative | neutral | declined
    confidence_level => high,        % low | medium | high
    recommended_trust_level => verified,
    recommendation_evidence => [
        #{type => business_verification,
          verification_method => direct_contact,
          verification_date => UnixTimestamp,
          verifier => <<"Bob Corp Security Team">>},
        #{type => security_assessment,
          assessment_score => 92,
          assessment_date => UnixTimestamp,
          assessment_criteria => [certificate_management, security_practices, incident_history]}
    ],
    conditions => [
        #{condition => periodic_review,
          frequency => quarterly,
          next_review => UnixTimestamp}
    ],
    recommendation_expires => UnixTimestamp,
    signature => <<Ed25519RecommendationSignature:64/binary>>
}
```

### 6.2 Trust Transitivity

```erlang
%% Trust path calculation for transitive trust
calculate_trust_path(SourceServer, TargetServer, MaxHops) ->
    TrustGraph = build_trust_graph(),
    case shortest_path(TrustGraph, SourceServer, TargetServer, MaxHops) of
        {ok, Path} ->
            TrustScore = calculate_path_trust_score(Path),
            {ok, Path, TrustScore};
        {error, no_path} ->
            {error, no_trust_path}
    end.

%% Trust score calculation along a path
calculate_path_trust_score([]) -> 0.0;
calculate_path_trust_score([_Single]) -> 1.0;  % Direct trust
calculate_path_trust_score([A, B | Rest]) ->
    DirectTrust = get_direct_trust_score(A, B),
    RestScore = calculate_path_trust_score([B | Rest]),
    DirectTrust * RestScore * 0.95.  % Decay factor for each hop
```

## 7. Government and NATO PKI Integration

### 7.1 Government PKI Support

```erlang
%% Government PKI Trust Request
#{
    type => gov_pki_trust_request,
    requesting_server => <<"agency.gov">>,
    target_server => <<"contractor.example.org">>,
    security_clearance => secret,    % unclassified | confidential | secret | top_secret
    pki_hierarchy => us_federal,     % us_federal | nato | uk_gov | etc.
    certificate_policy_oid => <<"2.16.840.1.101.2.1.11.5">>, % Federal PKI policy
    sponsor_agency => <<"Department of Defense">>,
    investigation_scope => <<"Single Scope Background Investigation">>,
    clearance_adjudication_date => UnixTimestamp,
    facility_security_clearance => <<"FCL-SECRET-12345">>,
    classified_network_authority => true,
    cross_domain_requirements => [
        #{classification_from => secret,
          classification_to => unclassified,
          guard_system => <<"Trusted Guard v3.2">>,
          accreditation => <<"ATO-2024-001">>}
    ]
}
```

### 7.2 NATO Trust Levels

```erlang
%% NATO-specific trust levels and requirements
-type nato_classification() :: nato_unclassified 
                             | nato_restricted 
                             | nato_confidential 
                             | nato_secret.

-record(nato_trust_requirements, {
    classification_level :: nato_classification(),
    security_agreement :: binary(),  % NATO Security Agreement reference
    facility_clearance :: binary(),  % NATO Facility Security Clearance
    personnel_clearance :: [personnel_clearance()],
    cryptographic_approval :: crypto_approval(),
    tempest_certification :: boolean(), % TEMPEST/EMSEC certification
    comsec_approval :: binary()     % COMSEC equipment approval
}).

-record(personnel_clearance, {
    person_id :: binary(),
    clearance_level :: nato_classification(),
    issuing_nation :: binary(),
    clearance_date :: integer(),
    expiry_date :: integer(),
    special_access :: [binary()]    % Special access programs
}).
```

## 8. Trust Monitoring and Maintenance

### 8.1 Continuous Trust Assessment

```erlang
%% Trust Health Monitoring
#{
    type => trust_health_check,
    monitoring_server => <<"monitor.example.org">>,
    target_server => <<"alice.example.org">>,
    check_parameters => #{
        certificate_validity => true,
        revocation_status => true,
        compliance_status => true,
        security_incidents => true,
        performance_metrics => true
    },
    assessment_period => #{
        start_time => UnixTimestamp,
        end_time => UnixTimestamp
    }
}

%% Trust Health Report
#{
    type => trust_health_report,
    target_server => <<"alice.example.org">>,
    overall_trust_score => 87.5,    % Computed trust score (0-100)
    health_metrics => #{
        certificate_status => valid,
        revocation_checks => passing,
        compliance_score => 92,
        security_incidents => 0,
        uptime_percentage => 99.8,
        response_time_avg => 150     % milliseconds
    },
    risk_factors => [
        #{risk_type => certificate_expiry,
          severity => low,
          time_to_impact => 2592000,  % 30 days
          mitigation => <<"Schedule certificate renewal">>}
    ],
    recommendations => [
        #{type => security_improvement,
          priority => medium,
          action => <<"Enable CT monitoring">>,
          estimated_effort => low}
    ],
    next_assessment => UnixTimestamp
}
```

### 8.2 Trust Renewal

```erlang
%% Trust Renewal Request
#{
    type => trust_renewal,
    renewal_id => <<"renewal-uuid">>,
    renewing_server => <<"alice.example.org">>,
    trust_server => <<"bob.example.org">>,
    existing_certificate_id => <<"trust-cert-uuid">>,
    renewal_reason => scheduled,     % scheduled | early | security_update
    requested_trust_level => verified,
    changes_requested => [
        #{change_type => add_permission,
          permission => media_relay,
          justification => <<"Adding video conferencing capability">>},
        #{change_type => update_rate_limit,
          parameter => messages_per_second,
          old_value => 500,
          new_value => 1000,
          justification => <<"Increased usage requirements">>}
    ],
    updated_certificates => [<<NewServerCert/binary>>],
    compliance_updates => [
        #{standard => fips_140_2,
          new_certificate_id => <<"FIPS-67890">>,
          effective_date => UnixTimestamp}
    ],
    renewal_signature => <<Ed25519RenewalSignature:64/binary>>
}
```

## 9. Trust Audit and Compliance

### 9.1 Trust Audit Trail

```erlang
%% Trust Audit Event
-record(trust_audit_event, {
    event_id :: binary(),
    timestamp :: integer(),
    event_type :: audit_event_type(),
    source_server :: binary(),
    target_server :: binary(),
    actor :: binary(),              % User or system performing action
    action :: binary(),             % Description of action taken
    parameters :: map(),            % Action-specific parameters
    result :: audit_result(),       % success | failure | partial
    risk_level :: risk_level(),     % low | medium | high | critical
    evidence_hash :: binary(),      % Hash of supporting evidence
    signature :: binary()          % Audit log signature
}).

-type audit_event_type() :: trust_request | trust_granted | trust_revoked | 
                           trust_renewed | access_granted | access_denied |
                           compliance_check | security_incident.

-type audit_result() :: success | failure | partial | pending.
-type risk_level() :: low | medium | high | critical.
```

### 9.2 Compliance Reporting

```erlang
%% Compliance Report Request
#{
    type => compliance_report,
    report_id => <<"report-uuid">>,
    requesting_authority => <<"NIST Auditor">>,
    target_server => <<"alice.example.org">>,
    compliance_standard => fips_140_2,
    report_period => #{
        start_date => UnixTimestamp,
        end_date => UnixTimestamp
    },
    report_scope => [
        trust_establishment,
        key_management,
        certificate_lifecycle,
        access_controls,
        incident_response
    ],
    evidence_required => true,
    confidentiality_level => restricted
}

%% Compliance Report Response
#{
    type => compliance_report_response,
    report_id => <<"report-uuid">>,
    target_server => <<"alice.example.org">>,
    compliance_status => compliant,  % compliant | non_compliant | conditional
    compliance_score => 94,          % Percentage compliance score
    assessment_results => [
        #{control_id => <<"FIPS-140-2-4.1">>,
          control_name => <<"Cryptographic Key Management">>,
          status => compliant,
          evidence => [<<"Key rotation logs">>, <<"Audit trail">>],
          last_tested => UnixTimestamp},
        #{control_id => <<"FIPS-140-2-4.2">>,
          control_name => <<"Authentication">>,
          status => compliant,
          evidence => [<<"Certificate validation logs">>],
          last_tested => UnixTimestamp}
    ],
    findings => [
        #{finding_id => <<"FIND-001">>,
          severity => low,
          description => <<"Certificate rotation could be automated">>,
          recommendation => <<"Implement automated certificate renewal">>,
          target_date => UnixTimestamp}
    ],
    supporting_documents => [
        #{document_type => configuration_baseline,
          document_hash => <<SHA256:32/binary>>,
          classification => restricted},
        #{document_type => security_assessment,
          document_hash => <<SHA256:32/binary>>,
          classification => confidential}
    ],
    report_signature => <<Ed25519ReportSignature:64/binary>>
}
```

## 10. Implementation Guidelines

### 10.1 Erlang/OTP Trust Management Architecture

```erlang
%% Trust management supervision tree
norc_trust_sup
├── norc_trust_manager          % Main trust state management
├── norc_certificate_store      % Certificate storage and validation
├── norc_trust_validator        % Trust validation logic
├── norc_crl_manager           % Certificate revocation list management
├── norc_trust_monitor         % Continuous trust monitoring
└── norc_compliance_reporter   % Compliance and audit reporting

%% Trust state management
-record(trust_state, {
    trusted_servers :: #{binary() => trust_relationship()},
    pending_requests :: #{binary() => trust_request()},
    revoked_trusts :: #{binary() => revocation_record()},
    trust_cache :: ets:tab(),
    trust_policies :: trust_policies(),
    audit_log :: pid()
}).

-record(trust_relationship, {
    server_id :: binary(),
    trust_level :: trust_level(),
    established_at :: integer(),
    expires_at :: integer(),
    permissions :: [federation_permission()],
    conditions :: [trust_condition()],
    certificate :: #norc_trust_certificate{},
    last_verified :: integer(),
    trust_score :: float()
}).
```

### 10.2 Certificate Management

```erlang
%% Certificate store implementation
init_certificate_store() ->
    ets:new(trust_certificates, [
        named_table, 
        {keypos, #norc_trust_certificate.certificate_id},
        {read_concurrency, true}
    ]).

store_trust_certificate(Cert = #norc_trust_certificate{}) ->
    case validate_trust_certificate(Cert) of
        {ok, ValidCert} ->
            ets:insert(trust_certificates, ValidCert),
            audit_log(certificate_stored, ValidCert),
            {ok, stored};
        {error, Reason} ->
            audit_log(certificate_rejected, {Cert, Reason}),
            {error, Reason}
    end.

%% Efficient certificate lookup with caching
lookup_trust_certificate(CertId) ->
    case ets:lookup(trust_certificates, CertId) of
        [Cert] -> 
            case is_certificate_valid(Cert) of
                true -> {ok, Cert};
                false -> {error, expired_or_revoked}
            end;
        [] -> 
            {error, not_found}
    end.
```

### 10.3 Trust Validation Pipeline

```erlang
%% Trust validation pipeline
validate_trust_request(Request) ->
    ValidationSteps = [
        fun validate_request_format/1,
        fun validate_certificate_chain/1,
        fun validate_domain_proof/1,
        fun validate_organization/1,
        fun check_security_requirements/1,
        fun assess_risk_factors/1
    ],
    
    case pipeline:run(ValidationSteps, Request) of
        {ok, ValidatedRequest} ->
            TrustScore = calculate_trust_score(ValidatedRequest),
            {ok, ValidatedRequest, TrustScore};
        {error, Step, Reason} ->
            audit_log(validation_failed, {Step, Reason, Request}),
            {error, {validation_failed, Step, Reason}}
    end.

%% Trust score calculation
calculate_trust_score(Request) ->
    Factors = [
        {certificate_quality, weight_certificate_quality(Request)},
        {domain_verification, weight_domain_verification(Request)},
        {organization_reputation, weight_organization_reputation(Request)},
        {security_posture, weight_security_posture(Request)},
        {compliance_status, weight_compliance_status(Request)}
    ],
    
    WeightedSum = lists:foldl(fun({_Factor, Score}, Acc) -> 
        Acc + Score 
    end, 0.0, Factors),
    
    max(0.0, min(100.0, WeightedSum)).
```

### 10.4 Performance Optimizations

```erlang
%% Concurrent trust validation
validate_multiple_trust_requests(Requests) ->
    ValidationTasks = [
        spawn_link(fun() -> 
            Result = validate_trust_request(Req),
            ReplyPid ! {validation_result, ReqId, Result}
        end) || {ReqId, Req} <- Requests
    ],
    
    collect_validation_results(length(ValidationTasks), #{}).

%% Efficient trust cache with TTL
-record(trust_cache_entry, {
    key :: binary(),
    value :: term(),
    inserted_at :: integer(),
    ttl :: integer()
}).

cache_lookup(Key) ->
    case ets:lookup(trust_cache, Key) of
        [#trust_cache_entry{value = Value, inserted_at = Time, ttl = TTL}] ->
            Now = erlang:system_time(second),
            case Now - Time < TTL of
                true -> {ok, Value};
                false -> 
                    ets:delete(trust_cache, Key),
                    {error, expired}
            end;
        [] -> 
            {error, not_found}
    end.
```

---

This specification defines the complete NORC-T protocol for trust establishment and management between NORC servers, providing the cryptographic foundation for secure federation while supporting various trust models from basic web-of-trust to government and NATO-level PKI integration.

---
### Appendix A: Enhanced Trust & Security (v1.1 Draft Forward Compatibility)

The following upcoming enhancements align NORC-T with master specification Sections 6.8–6.21:

1. **Transcript Hashing**: All trust handshake messages (`trust_capabilities`, `trust_request`, `trust_challenge`, `trust_response`, `trust_decision`, `trust_acknowledgment`) will be canonically serialized & hashed into a `transcript_hash` bound into key derivation and signatures to prevent downgrade / message splicing.
2. **Hybrid PQ Support**: Trust exchanges MAY advertise PQ KEM support (e.g., Kyber768). When selected, certificate attestation includes PQ public key fingerprint; both classical & PQ secrets feed HKDF.
3. **Revocation Propagation**: `trust_revoke` events SHOULD include optional `prev_revocation_hash` forming a revocation chain enabling detection of suppression. Future Merkle root transparency publication recommended.
4. **Audit Log Hash Chain**: Trust audit events SHOULD export daily root hash; peers MAY request `audit_root_query` (future message) for transparency validation.
5. **Time Synchronization Dependency**: Trust validation that includes expiry / freshness criteria MUST reference signed `time_sync` values when available to reduce false negatives due to skew.
6. **Supply Chain Signals**: `trust_capabilities` MAY include `build_attestation_hash` and `software_sbom_hash` fields; policies can enforce matching against known-good lists.

Backward Compatibility: v1.0 peers ignore new fields. Implementations SHOULD store canonical forms now to simplify later transcript hash integration.
