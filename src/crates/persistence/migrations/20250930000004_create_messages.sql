-- Create persisted_messages table for offline delivery
CREATE TABLE IF NOT EXISTS persisted_messages (
    id TEXT PRIMARY KEY NOT NULL,
    sender_device_id TEXT NOT NULL,
    recipient_device_id TEXT NOT NULL,
    payload BLOB NOT NULL,
    priority INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    delivered_at TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    FOREIGN KEY (sender_device_id) REFERENCES devices(id),
    FOREIGN KEY (recipient_device_id) REFERENCES devices(id)
);

CREATE INDEX idx_messages_recipient ON persisted_messages(recipient_device_id);
CREATE INDEX idx_messages_status ON persisted_messages(status);
CREATE INDEX idx_messages_priority ON persisted_messages(priority);
CREATE INDEX idx_messages_expires ON persisted_messages(expires_at);
