//! TLS connection handling

/// TLS configuration placeholder
#[derive(Debug)]
pub struct TlsConfig {
    /// Placeholder field
    pub placeholder: bool,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self { placeholder: true }
    }
}