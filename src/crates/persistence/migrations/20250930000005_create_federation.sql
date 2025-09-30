-- Create federation_trust table
CREATE TABLE IF NOT EXISTS federation_trust (
    id TEXT PRIMARY KEY NOT NULL,
    organization_id TEXT NOT NULL UNIQUE,
    server_address TEXT NOT NULL,
    trust_level TEXT NOT NULL,
    cert_fingerprint TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_federation_organization ON federation_trust(organization_id);
CREATE INDEX idx_federation_status ON federation_trust(status);
