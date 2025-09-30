-- Create audit_log table
CREATE TABLE IF NOT EXISTS audit_log (
    id TEXT PRIMARY KEY NOT NULL,
    event_type TEXT NOT NULL,
    user_id TEXT,
    device_id TEXT,
    ip_address TEXT,
    event_data TEXT NOT NULL,
    result TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_audit_event_type ON audit_log(event_type);
CREATE INDEX idx_audit_user ON audit_log(user_id);
CREATE INDEX idx_audit_device ON audit_log(device_id);
CREATE INDEX idx_audit_created ON audit_log(created_at);
