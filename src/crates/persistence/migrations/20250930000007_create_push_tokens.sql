-- Create push_tokens table
CREATE TABLE IF NOT EXISTS push_tokens (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    platform TEXT NOT NULL,
    token TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE,
    UNIQUE(device_id, platform)
);

CREATE INDEX idx_push_tokens_device ON push_tokens(device_id);
CREATE INDEX idx_push_tokens_status ON push_tokens(status);
