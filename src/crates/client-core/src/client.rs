//! Client implementation

/// NORC client
pub struct Client {
    /// Placeholder
    placeholder: bool,
}

impl Client {
    /// Create a new client
    pub fn new() -> Self {
        Self { placeholder: true }
    }
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}