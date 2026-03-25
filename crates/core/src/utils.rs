use base64::{engine::general_purpose::STANDARD, Engine};
use sha2::{Digest, Sha256};

/// URL-encode a string.
pub fn url_encode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// URL-decode a string.
pub fn url_decode(s: &str) -> String {
    url::form_urlencoded::parse(s.as_bytes())
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join("&")
}

/// Base64-encode bytes.
pub fn b64_encode(data: &[u8]) -> String {
    STANDARD.encode(data)
}

/// Base64-decode a string.
pub fn b64_decode(s: &str) -> anyhow::Result<Vec<u8>> {
    Ok(STANDARD.decode(s)?)
}

/// SHA-256 hex digest of bytes.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Truncate a string to at most `max` characters, appending `…` if truncated.
pub fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max])
    }
}

/// Determine the content type from a response body snippet.
pub fn detect_content_type(body: &[u8]) -> &'static str {
    if body.starts_with(b"<?xml") || body.starts_with(b"<") {
        return "text/html";
    }
    if body.starts_with(b"{") || body.starts_with(b"[") {
        return "application/json";
    }
    "text/plain"
}

/// Extract the host[:port] from a URL string.
pub fn extract_host(url: &str) -> Option<String> {
    url::Url::parse(url).ok().and_then(|u| {
        u.host_str().map(|h| {
            match u.port() {
                Some(p) => format!("{}:{}", h, p),
                None    => h.to_string(),
            }
        })
    })
}

/// Check whether a string looks like a valid URL.
pub fn is_valid_url(s: &str) -> bool {
    url::Url::parse(s).map(|u| u.scheme() == "http" || u.scheme() == "https").unwrap_or(false)
}

/// Redact sensitive values from headers for safe logging.
pub fn redact_header(name: &str, value: &str) -> String {
    let sensitive = ["authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token"];
    if sensitive.iter().any(|s| name.to_lowercase().contains(s)) {
        "[REDACTED]".to_string()
    } else {
        value.to_string()
    }
}
