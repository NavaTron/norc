# NORC Admin API Documentation

## Overview

The NORC Admin API provides REST endpoints for certificate management, system monitoring, and administrative operations. All endpoints require authentication and appropriate authorization.

## Base URL

```
https://server.example.com:8443/api/v1
```

## Authentication

All API requests require authentication using one of the following methods:

### 1. mTLS Client Certificate
```bash
curl --cert client.pem --key client-key.pem \
     https://server.example.com:8443/api/v1/certificates
```

### 2. API Token (Header)
```bash
curl -H "Authorization: Bearer ${API_TOKEN}" \
     https://server.example.com:8443/api/v1/certificates
```

## Common Headers

```http
Content-Type: application/json
Authorization: Bearer <token>
X-Request-ID: <uuid>  # Optional, for request tracking
```

## Error Responses

All errors follow a consistent format:

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid certificate format",
    "details": {
      "field": "certificate",
      "reason": "PEM format required"
    },
    "request_id": "550e8400-e29b-41d4-a716-446655440000"
  }
}
```

### Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `VALIDATION_ERROR` | 400 | Request validation failed |
| `UNAUTHORIZED` | 401 | Authentication required |
| `FORBIDDEN` | 403 | Insufficient permissions |
| `NOT_FOUND` | 404 | Resource not found |
| `CONFLICT` | 409 | Resource already exists |
| `INTERNAL_ERROR` | 500 | Server error |

---

## Endpoints

## 1. List Certificates

Retrieve a list of certificates with optional filtering.

### Request

```http
GET /api/v1/certificates
```

### Query Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `status` | string | No | Filter by status: `active`, `expired`, `revoked` |
| `organization` | string | No | Filter by organization ID |
| `expires_before` | ISO8601 | No | Certificates expiring before this date |
| `limit` | integer | No | Maximum results to return (default: 100, max: 1000) |
| `offset` | integer | No | Pagination offset (default: 0) |

### Example Request

```bash
curl -H "Authorization: Bearer ${API_TOKEN}" \
     "https://server.example.com:8443/api/v1/certificates?status=active&limit=50"
```

### Example Response

```json
{
  "certificates": [
    {
      "fingerprint": "SHA256:ab:cd:ef:12:34:56:78:90:ab:cd:ef:12:34:56:78:90",
      "subject": {
        "common_name": "client-001.org-a.example.com",
        "organization": "OrgA",
        "organizational_unit": "Engineering",
        "country": "US"
      },
      "issuer": {
        "common_name": "NORC Intermediate CA",
        "organization": "NavaTron"
      },
      "serial_number": "1234567890abcdef",
      "valid_from": "2025-01-01T00:00:00Z",
      "valid_until": "2026-01-01T00:00:00Z",
      "status": "active",
      "key_algorithm": "RSA",
      "key_size": 2048,
      "signature_algorithm": "SHA256withRSA",
      "san": [
        "client-001.org-a.example.com",
        "192.168.1.100"
      ],
      "revocation": {
        "status": "not_revoked",
        "checked_at": "2025-10-02T10:30:00Z"
      },
      "created_at": "2025-01-01T00:00:00Z",
      "updated_at": "2025-10-02T10:30:00Z"
    }
  ],
  "pagination": {
    "total": 150,
    "limit": 50,
    "offset": 0,
    "has_more": true
  }
}
```

---

## 2. Get Certificate Details

Retrieve detailed information about a specific certificate.

### Request

```http
GET /api/v1/certificates/{fingerprint}
```

### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `fingerprint` | string | SHA256 fingerprint of the certificate (colon-separated hex) |

### Example Request

```bash
curl -H "Authorization: Bearer ${API_TOKEN}" \
     "https://server.example.com:8443/api/v1/certificates/SHA256:ab:cd:ef:12:34:56:78:90:ab:cd:ef:12:34:56:78:90"
```

### Example Response

```json
{
  "certificate": {
    "fingerprint": "SHA256:ab:cd:ef:12:34:56:78:90:ab:cd:ef:12:34:56:78:90",
    "subject": {
      "common_name": "client-001.org-a.example.com",
      "organization": "OrgA",
      "organizational_unit": "Engineering",
      "country": "US",
      "state": "California",
      "locality": "San Francisco"
    },
    "issuer": {
      "common_name": "NORC Intermediate CA",
      "organization": "NavaTron",
      "country": "US"
    },
    "serial_number": "1234567890abcdef",
    "version": 3,
    "valid_from": "2025-01-01T00:00:00Z",
    "valid_until": "2026-01-01T00:00:00Z",
    "status": "active",
    "key_algorithm": "RSA",
    "key_size": 2048,
    "signature_algorithm": "SHA256withRSA",
    "san": [
      "client-001.org-a.example.com",
      "192.168.1.100"
    ],
    "extensions": {
      "key_usage": [
        "digitalSignature",
        "keyEncipherment"
      ],
      "extended_key_usage": [
        "clientAuth"
      ],
      "basic_constraints": {
        "ca": false
      },
      "subject_key_identifier": "a1:b2:c3:d4:e5:f6",
      "authority_key_identifier": "f6:e5:d4:c3:b2:a1"
    },
    "revocation": {
      "status": "not_revoked",
      "ocsp_url": "http://ocsp.example.com",
      "crl_url": "http://crl.example.com/latest.crl",
      "checked_at": "2025-10-02T10:30:00Z",
      "next_check": "2025-10-02T16:30:00Z"
    },
    "chain": [
      {
        "subject": "CN=NORC Intermediate CA,O=NavaTron",
        "fingerprint": "SHA256:12:34:56:78:90:ab:cd:ef:12:34:56:78:90:ab:cd:ef"
      },
      {
        "subject": "CN=NORC Root CA,O=NavaTron",
        "fingerprint": "SHA256:90:ab:cd:ef:12:34:56:78:90:ab:cd:ef:12:34:56:78"
      }
    ],
    "metadata": {
      "uploaded_by": "admin@example.com",
      "uploaded_at": "2025-01-01T00:00:00Z",
      "last_used": "2025-10-02T10:00:00Z",
      "usage_count": 1523
    },
    "created_at": "2025-01-01T00:00:00Z",
    "updated_at": "2025-10-02T10:30:00Z"
  }
}
```

---

## 3. Upload Certificate

Upload a new certificate to the system.

### Request

```http
POST /api/v1/certificates
```

### Request Body

```json
{
  "certificate": "-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIJAKZ...\n-----END CERTIFICATE-----",
  "certificate_chain": [
    "-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIJAKZ...\n-----END CERTIFICATE-----"
  ],
  "metadata": {
    "description": "Client certificate for user john@org-a.example.com",
    "tags": ["production", "client", "org-a"]
  }
}
```

### Request Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `certificate` | string | Yes | PEM-encoded certificate |
| `certificate_chain` | array | No | Array of PEM-encoded intermediate certificates |
| `metadata` | object | No | Additional metadata |

### Example Request

```bash
curl -X POST \
     -H "Authorization: Bearer ${API_TOKEN}" \
     -H "Content-Type: application/json" \
     -d @certificate.json \
     https://server.example.com:8443/api/v1/certificates
```

### Example Response

```json
{
  "certificate": {
    "fingerprint": "SHA256:ab:cd:ef:12:34:56:78:90:ab:cd:ef:12:34:56:78:90",
    "status": "active",
    "valid_from": "2025-01-01T00:00:00Z",
    "valid_until": "2026-01-01T00:00:00Z",
    "created_at": "2025-10-02T10:35:00Z"
  },
  "message": "Certificate uploaded successfully"
}
```

---

## 4. Rotate Certificates

Initiate certificate rotation for specified certificates.

### Request

```http
POST /api/v1/certificates/rotate
```

### Request Body

```json
{
  "certificates": [
    {
      "fingerprint": "SHA256:ab:cd:ef:12:34:56:78:90:ab:cd:ef:12:34:56:78:90",
      "new_certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
      "new_certificate_chain": [
        "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
      ]
    }
  ],
  "graceful": true,
  "rollback_on_error": true
}
```

### Request Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `certificates` | array | Yes | Array of certificate rotation requests |
| `graceful` | boolean | No | Allow graceful transition (default: true) |
| `rollback_on_error` | boolean | No | Rollback all if any fails (default: true) |

### Example Request

```bash
curl -X POST \
     -H "Authorization: Bearer ${API_TOKEN}" \
     -H "Content-Type: application/json" \
     -d @rotation.json \
     https://server.example.com:8443/api/v1/certificates/rotate
```

### Example Response

```json
{
  "rotation_id": "rot-550e8400-e29b-41d4-a716-446655440000",
  "status": "in_progress",
  "certificates": [
    {
      "old_fingerprint": "SHA256:ab:cd:ef:12:34:56:78:90:ab:cd:ef:12:34:56:78:90",
      "new_fingerprint": "SHA256:12:34:56:78:90:ab:cd:ef:12:34:56:78:90:ab:cd:ef",
      "status": "rotating"
    }
  ],
  "started_at": "2025-10-02T10:40:00Z",
  "estimated_completion": "2025-10-02T10:45:00Z"
}
```

---

## 5. Delete Certificate

Delete a certificate from the system.

### Request

```http
DELETE /api/v1/certificates/{fingerprint}
```

### Query Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `force` | boolean | No | Force deletion even if in use (default: false) |

### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `fingerprint` | string | SHA256 fingerprint of the certificate |

### Example Request

```bash
curl -X DELETE \
     -H "Authorization: Bearer ${API_TOKEN}" \
     "https://server.example.com:8443/api/v1/certificates/SHA256:ab:cd:ef:12:34:56:78:90:ab:cd:ef:12:34:56:78:90?force=false"
```

### Example Response

```json
{
  "message": "Certificate deleted successfully",
  "fingerprint": "SHA256:ab:cd:ef:12:34:56:78:90:ab:cd:ef:12:34:56:78:90",
  "deleted_at": "2025-10-02T10:50:00Z"
}
```

---

## 6. Check Revocation Status

Check the revocation status of a certificate.

### Request

```http
POST /api/v1/certificates/check-revocation
```

### Request Body

```json
{
  "fingerprint": "SHA256:ab:cd:ef:12:34:56:78:90:ab:cd:ef:12:34:56:78:90",
  "methods": ["ocsp", "crl"],
  "force_refresh": false
}
```

### Request Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `fingerprint` | string | Yes | Certificate fingerprint |
| `methods` | array | No | Revocation check methods (default: ["ocsp", "crl"]) |
| `force_refresh` | boolean | No | Bypass cache (default: false) |

### Example Request

```bash
curl -X POST \
     -H "Authorization: Bearer ${API_TOKEN}" \
     -H "Content-Type: application/json" \
     -d '{"fingerprint":"SHA256:ab:cd:ef:12:34:56:78:90:ab:cd:ef:12:34:56:78:90"}' \
     https://server.example.com:8443/api/v1/certificates/check-revocation
```

### Example Response

```json
{
  "fingerprint": "SHA256:ab:cd:ef:12:34:56:78:90:ab:cd:ef:12:34:56:78:90",
  "revocation_status": "not_revoked",
  "checks": [
    {
      "method": "ocsp",
      "status": "not_revoked",
      "responder": "http://ocsp.example.com",
      "checked_at": "2025-10-02T10:55:00Z",
      "next_update": "2025-10-02T16:55:00Z",
      "response_time_ms": 45
    },
    {
      "method": "crl",
      "status": "not_revoked",
      "crl_url": "http://crl.example.com/latest.crl",
      "checked_at": "2025-10-02T10:55:00Z",
      "next_update": "2025-10-03T00:00:00Z",
      "response_time_ms": 120
    }
  ],
  "cached": false,
  "checked_at": "2025-10-02T10:55:00Z"
}
```

---

## 7. System Health

Check the health status of the certificate management system.

### Request

```http
GET /api/v1/certificates/health
```

### Example Request

```bash
curl -H "Authorization: Bearer ${API_TOKEN}" \
     https://server.example.com:8443/api/v1/certificates/health
```

### Example Response

```json
{
  "status": "healthy",
  "components": [
    {
      "component": "certificate_store",
      "status": "healthy",
      "message": "All certificates valid",
      "details": {
        "total_certificates": 150,
        "active_certificates": 145,
        "expiring_soon": 5,
        "expired": 0,
        "revoked": 0
      }
    },
    {
      "component": "ocsp_responder",
      "status": "healthy",
      "message": "OCSP responder responding normally",
      "details": {
        "url": "http://ocsp.example.com",
        "response_time_ms": 45,
        "success_rate": 99.8
      }
    },
    {
      "component": "crl_distribution",
      "status": "degraded",
      "message": "High latency detected",
      "details": {
        "url": "http://crl.example.com/latest.crl",
        "response_time_ms": 1200,
        "last_updated": "2025-10-02T00:00:00Z"
      }
    },
    {
      "component": "database",
      "status": "healthy",
      "message": "Database connection healthy",
      "details": {
        "type": "sqlite",
        "size_mb": 124,
        "connections": 5
      }
    },
    {
      "component": "backup_service",
      "status": "unhealthy",
      "message": "Service unavailable",
      "details": {
        "last_backup": "2025-10-01T00:00:00Z",
        "error": "Connection timeout"
      }
    }
  ],
  "metrics": {
    "uptime_seconds": 86400,
    "requests_per_second": 125,
    "average_response_time_ms": 15,
    "error_rate": 0.02
  },
  "timestamp": "2025-10-02T11:00:00Z"
}
```

---

## Rate Limiting

API requests are rate-limited to prevent abuse:

- **Authenticated requests**: 1000 requests per hour per user
- **Certificate operations**: 100 operations per hour per user
- **Rotation operations**: 10 rotations per hour per user

### Rate Limit Headers

```http
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 950
X-RateLimit-Reset: 1633176000
```

### Rate Limit Exceeded Response

```json
{
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "API rate limit exceeded",
    "details": {
      "limit": 1000,
      "reset_at": "2025-10-02T12:00:00Z"
    }
  }
}
```

---

## Audit Logging

All API operations are logged for audit purposes. Audit logs include:

- Request ID
- User identity (from mTLS certificate or API token)
- Timestamp
- Endpoint accessed
- Request parameters
- Response status
- Client IP address

Audit logs can be queried through the system logs or exported to external SIEM systems.

---

## SDK Examples

### Python

```python
import requests
import json

class NorcAdminAPI:
    def __init__(self, base_url, api_token=None, cert_path=None, key_path=None):
        self.base_url = base_url
        self.headers = {"Content-Type": "application/json"}
        
        if api_token:
            self.headers["Authorization"] = f"Bearer {api_token}"
        
        self.cert = (cert_path, key_path) if cert_path and key_path else None
    
    def list_certificates(self, status=None, organization=None, limit=100):
        params = {"limit": limit}
        if status:
            params["status"] = status
        if organization:
            params["organization"] = organization
        
        response = requests.get(
            f"{self.base_url}/certificates",
            headers=self.headers,
            params=params,
            cert=self.cert
        )
        response.raise_for_status()
        return response.json()
    
    def upload_certificate(self, cert_pem, chain_pems=None, metadata=None):
        data = {
            "certificate": cert_pem,
            "certificate_chain": chain_pems or [],
            "metadata": metadata or {}
        }
        
        response = requests.post(
            f"{self.base_url}/certificates",
            headers=self.headers,
            json=data,
            cert=self.cert
        )
        response.raise_for_status()
        return response.json()

# Usage
api = NorcAdminAPI(
    "https://server.example.com:8443/api/v1",
    cert_path="client.pem",
    key_path="client-key.pem"
)

# List active certificates
certs = api.list_certificates(status="active")
print(f"Found {len(certs['certificates'])} active certificates")

# Upload certificate
with open("new-cert.pem") as f:
    cert_pem = f.read()

result = api.upload_certificate(cert_pem)
print(f"Uploaded certificate: {result['certificate']['fingerprint']}")
```

### Rust

```rust
use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
struct UploadCertRequest {
    certificate: String,
    certificate_chain: Vec<String>,
    metadata: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct CertificateResponse {
    certificate: Certificate,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::builder()
        .identity(reqwest::Identity::from_pem(
            &std::fs::read("client.pem")?
        )?)
        .build()?;
    
    // List certificates
    let response = client
        .get("https://server.example.com:8443/api/v1/certificates")
        .query(&[("status", "active"), ("limit", "50")])
        .send()
        .await?;
    
    let certs: serde_json::Value = response.json().await?;
    println!("Certificates: {:#?}", certs);
    
    // Upload certificate
    let cert_pem = std::fs::read_to_string("new-cert.pem")?;
    let request = UploadCertRequest {
        certificate: cert_pem,
        certificate_chain: vec![],
        metadata: None,
    };
    
    let response = client
        .post("https://server.example.com:8443/api/v1/certificates")
        .json(&request)
        .send()
        .await?;
    
    let result: CertificateResponse = response.json().await?;
    println!("Uploaded: {}", result.certificate.fingerprint);
    
    Ok(())
}
```

---

## Webhook Notifications

Configure webhooks to receive real-time notifications about certificate events:

### Events

- `certificate.uploaded`
- `certificate.rotated`
- `certificate.deleted`
- `certificate.expiring_soon` (30 days before expiration)
- `certificate.expired`
- `certificate.revoked`

### Webhook Configuration

Contact your system administrator to configure webhooks for your organization.

---

*Last Updated: 2025-10-02*  
*NORC Admin API v1.0*
