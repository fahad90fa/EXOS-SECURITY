use serde::{Deserialize, Serialize};
use nexus_core::models::{CapturedRequest, CapturedResponse};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// Address to listen on (default 0.0.0.0)
    pub host:                String,
    /// Port to listen on (default 8080)
    pub port:                u16,
    /// Intercept mode — pause every request waiting for user action
    pub intercept_mode:      bool,
    /// Whether to record all traffic to storage
    pub record_traffic:      bool,
    /// Upstream proxy (e.g. socks5://127.0.0.1:9050 for Tor)
    pub upstream_proxy:      Option<String>,
    /// Path to CA cert PEM (if loading from disk instead of generating)
    pub ca_cert_pem:         Option<String>,
    /// Path to CA key PEM
    pub ca_key_pem:          Option<String>,
    /// TLS verification for upstream (disable for scanning self-signed certs)
    pub verify_upstream_tls: bool,
    /// Maximum body size to buffer in memory (bytes)
    pub max_body_size:       usize,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            host:                "127.0.0.1".into(),
            port:                8080,
            intercept_mode:      false,
            record_traffic:      true,
            upstream_proxy:      None,
            ca_cert_pem:         None,
            ca_key_pem:          None,
            verify_upstream_tls: false,
            max_body_size:       10 * 1024 * 1024, // 10 MB
        }
    }
}

// ─── Events ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum ProxyEvent {
    /// A new request was captured.
    RequestCaptured(Box<CapturedRequest>),
    /// A response was captured (paired with its request).
    ResponseCaptured(Box<CapturedRequest>, Box<CapturedResponse>),
    /// Request is held in intercept mode — send it on or drop it.
    InterceptRequest(Box<CapturedRequest>),
    /// Upstream connection error.
    ConnectionError { host: String, error: String },
    /// TLS handshake error.
    TlsError { host: String, error: String },
    /// Proxy started.
    Started { addr: String },
    /// Proxy stopped.
    Stopped,
}
