//! WebSocket transport implementation

/// WebSocket configuration placeholder
#[derive(Debug)]
pub struct WebSocketConfig {
    /// Placeholder field
    pub placeholder: bool,
}

impl Default for WebSocketConfig {
    fn default() -> Self {
        Self { placeholder: true }
    }
}