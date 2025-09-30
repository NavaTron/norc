-- Create presence table
CREATE TABLE IF NOT EXISTS presence (
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'offline',
    status_message TEXT,
    last_activity TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, device_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
);

CREATE INDEX idx_presence_user ON presence(user_id);
CREATE INDEX idx_presence_status ON presence(status);
CREATE INDEX idx_presence_activity ON presence(last_activity);
