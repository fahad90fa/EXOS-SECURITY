use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

// ─── HTTP Method ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "text")]
pub enum HttpMethod {
    GET,
    POST,
    PUT,
    PATCH,
    DELETE,
    HEAD,
    OPTIONS,
    TRACE,
    CONNECT,
    Custom(String),
}

impl std::fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpMethod::Custom(s) => write!(f, "{}", s),
            other => write!(f, "{:?}", other),
        }
    }
}

impl From<&str> for HttpMethod {
    fn from(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "GET"     => HttpMethod::GET,
            "POST"    => HttpMethod::POST,
            "PUT"     => HttpMethod::PUT,
            "PATCH"   => HttpMethod::PATCH,
            "DELETE"  => HttpMethod::DELETE,
            "HEAD"    => HttpMethod::HEAD,
            "OPTIONS" => HttpMethod::OPTIONS,
            "TRACE"   => HttpMethod::TRACE,
            "CONNECT" => HttpMethod::CONNECT,
            other     => HttpMethod::Custom(other.to_string()),
        }
    }
}

// ─── Parameter ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ParameterLocation {
    Query,
    Body,
    Header,
    Cookie,
    Path,
    Json,
    Xml,
    Multipart,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Parameter {
    pub name:     String,
    pub value:    String,
    pub location: ParameterLocation,
}

// ─── Captured HTTP Request ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedRequest {
    pub id:          Uuid,
    pub scan_id:     Option<Uuid>,
    pub method:      HttpMethod,
    pub url:         String,
    pub host:        String,
    pub path:        String,
    pub query:       Option<String>,
    pub headers:     HashMap<String, String>,
    pub body:        Option<Vec<u8>>,
    pub body_text:   Option<String>,
    pub parameters:  Vec<Parameter>,
    pub is_https:    bool,
    pub timestamp:   DateTime<Utc>,
    pub tags:        Vec<String>,
}

impl CapturedRequest {
    pub fn new(method: HttpMethod, url: &str) -> Self {
        let parsed = url::Url::parse(url).ok();
        let host   = parsed.as_ref().and_then(|u| u.host_str()).unwrap_or("").to_string();
        let path   = parsed.as_ref().map(|u| u.path().to_string()).unwrap_or("/".into());
        let query  = parsed.as_ref().and_then(|u| u.query()).map(|q| q.to_string());
        let is_https = url.starts_with("https");

        Self {
            id:         Uuid::new_v4(),
            scan_id:    None,
            method,
            url:        url.to_string(),
            host,
            path,
            query,
            headers:    HashMap::new(),
            body:       None,
            body_text:  None,
            parameters: Vec::new(),
            is_https,
            timestamp:  Utc::now(),
            tags:       Vec::new(),
        }
    }

    /// Extract parameters from query string, body, etc.
    pub fn extract_parameters(&mut self) {
        // Query parameters
        if let Ok(parsed) = url::Url::parse(&self.url) {
            for (k, v) in parsed.query_pairs() {
                self.parameters.push(Parameter {
                    name:     k.to_string(),
                    value:    v.to_string(),
                    location: ParameterLocation::Query,
                });
            }
        }

        // Body parameters (application/x-www-form-urlencoded)
        if let Some(body) = &self.body_text {
            let ct = self.headers.get("content-type")
                .or_else(|| self.headers.get("Content-Type"))
                .cloned()
                .unwrap_or_default();

            if ct.contains("application/x-www-form-urlencoded") {
                for pair in body.split('&') {
                    let mut parts = pair.splitn(2, '=');
                    let name  = parts.next().unwrap_or("").to_string();
                    let value = parts.next().unwrap_or("").to_string();
                    if !name.is_empty() {
                        self.parameters.push(Parameter {
                            name,
                            value,
                            location: ParameterLocation::Body,
                        });
                    }
                }
            } else if ct.contains("application/json") {
                // Flatten JSON keys at depth 1
                if let Ok(serde_json::Value::Object(map)) = serde_json::from_str(body) {
                    for (k, v) in map {
                        self.parameters.push(Parameter {
                            name:     k,
                            value:    v.to_string(),
                            location: ParameterLocation::Json,
                        });
                    }
                }
            }
        }

        // Cookie parameters
        if let Some(cookie_header) = self.headers.get("Cookie")
            .or_else(|| self.headers.get("cookie")) {
            for part in cookie_header.split(';') {
                let mut kv = part.trim().splitn(2, '=');
                let name  = kv.next().unwrap_or("").to_string();
                let value = kv.next().unwrap_or("").to_string();
                if !name.is_empty() {
                    self.parameters.push(Parameter {
                        name,
                        value,
                        location: ParameterLocation::Cookie,
                    });
                }
            }
        }
    }

    /// Produce a raw HTTP bytes representation.
    pub fn to_raw(&self) -> Vec<u8> {
        let mut raw = format!(
            "{} {}{} HTTP/1.1\r\n",
            self.method,
            self.path,
            self.query.as_deref().map(|q| format!("?{}", q)).unwrap_or_default(),
        );
        for (k, v) in &self.headers {
            raw.push_str(&format!("{}: {}\r\n", k, v));
        }
        raw.push_str("\r\n");
        let mut bytes = raw.into_bytes();
        if let Some(body) = &self.body {
            bytes.extend_from_slice(body);
        }
        bytes
    }
}

// ─── Captured HTTP Response ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedResponse {
    pub id:             Uuid,
    pub request_id:     Uuid,
    pub status_code:    u16,
    pub headers:        HashMap<String, String>,
    pub body:           Option<Vec<u8>>,
    pub body_text:      Option<String>,
    pub content_type:   Option<String>,
    pub content_length: Option<usize>,
    pub response_time_ms: u64,
    pub timestamp:      DateTime<Utc>,
}

impl CapturedResponse {
    pub fn new(request_id: Uuid, status_code: u16) -> Self {
        Self {
            id:               Uuid::new_v4(),
            request_id,
            status_code,
            headers:          HashMap::new(),
            body:             None,
            body_text:        None,
            content_type:     None,
            content_length:   None,
            response_time_ms: 0,
            timestamp:        Utc::now(),
        }
    }

    pub fn body_str(&self) -> &str {
        self.body_text.as_deref().unwrap_or("")
    }
}
