-- Create devices table
CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL,
    name TEXT NOT NULL,
    device_type TEXT NOT NULL,
    public_key BLOB NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    last_seen TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_devices_user ON devices(user_id);
CREATE INDEX idx_devices_status ON devices(status);
