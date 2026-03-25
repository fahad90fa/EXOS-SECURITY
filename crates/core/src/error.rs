use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    // ── Infrastructure ───────────────────────────────────────────────────
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Redis error: {0}")]
    Redis(#[from] redis::RedisError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    // ── HTTP / Network ───────────────────────────────────────────────────
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Hyper error: {0}")]
    Hyper(#[from] hyper::Error),

    #[error("TLS error: {0}")]
    Tls(String),

    // ── Serialization ────────────────────────────────────────────────────
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    // ── Auth ────────────────────────────────────────────────────────────
    #[error("Authentication failed: {0}")]
    Auth(String),

    #[error("Forbidden: {0}")]
    Forbidden(String),

    // ── Validation ──────────────────────────────────────────────────────
    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Not found: {0}")]
    NotFound(String),

    // ── Scan ────────────────────────────────────────────────────────────
    #[error("Scan error: {0}")]
    Scan(String),

    #[error("Timeout after {0}ms")]
    Timeout(u64),

    // ── Certificate ─────────────────────────────────────────────────────
    #[error("Certificate error: {0}")]
    Certificate(String),

    // ── Plugin ──────────────────────────────────────────────────────────
    #[error("Plugin error: {0}")]
    Plugin(String),

    // ── Catch-all ───────────────────────────────────────────────────────
    #[error("Internal error: {0}")]
    Internal(#[from] anyhow::Error),
}

impl From<rcgen::RcgenError> for Error {
    fn from(e: rcgen::RcgenError) -> Self {
        Error::Certificate(e.to_string())
    }
}

impl From<rustls::Error> for Error {
    fn from(e: rustls::Error) -> Self {
        Error::Tls(e.to_string())
    }
}
