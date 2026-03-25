//! Rate-limited, configurable HTTP client for scanner use.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use reqwest::{
    header::{HeaderMap, HeaderName, HeaderValue},
    redirect::Policy,
    Client, Response,
};
use tokio::sync::Semaphore;
use tracing::{debug, warn};

// ─── ScanRequest ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ScanRequest {
    pub method:  String,
    pub url:     String,
    pub headers: HashMap<String, String>,
    pub body:    Option<String>,
    pub timeout_ms: Option<u64>,
}

impl ScanRequest {
    pub fn get(url: impl Into<String>) -> Self {
        Self {
            method:     "GET".into(),
            url:        url.into(),
            headers:    HashMap::new(),
            body:       None,
            timeout_ms: None,
        }
    }

    pub fn post(url: impl Into<String>, body: impl Into<String>) -> Self {
        Self {
            method:     "POST".into(),
            url:        url.into(),
            headers:    HashMap::new(),
            body:       Some(body.into()),
            timeout_ms: None,
        }
    }

    pub fn with_header(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.headers.insert(k.into(), v.into());
        self
    }

    pub fn with_timeout(mut self, ms: u64) -> Self {
        self.timeout_ms = Some(ms);
        self
    }
}

// ─── ScanResponse ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ScanResponse {
    pub status:       u16,
    pub headers:      HashMap<String, String>,
    pub body:         String,
    pub elapsed_ms:   u64,
    pub content_length: usize,
    pub redirect_url: Option<String>,
}

impl ScanResponse {
    pub fn body_lower(&self) -> String {
        self.body.to_lowercase()
    }

    pub fn contains_any(&self, patterns: &[&str]) -> bool {
        let lower = self.body_lower();
        patterns.iter().any(|p| lower.contains(p))
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(&name.to_lowercase()).map(String::as_str)
    }
}

// ─── HttpClientConfig ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct HttpClientConfig {
    pub timeout_ms:        u64,
    pub max_concurrency:   usize,
    pub user_agent:        String,
    pub follow_redirects:  bool,
    pub verify_tls:        bool,
    pub max_body_size:     usize,
    pub default_headers:   HashMap<String, String>,
    pub cookie:            Option<String>,
}

impl Default for HttpClientConfig {
    fn default() -> Self {
        Self {
            timeout_ms:       10_000,
            max_concurrency:  20,
            user_agent:       "NexusSentinel/0.1 Security Scanner".into(),
            follow_redirects: false, // off by default so we can detect open redirects
            verify_tls:       false,
            max_body_size:    5 * 1024 * 1024,
            default_headers:  HashMap::new(),
            cookie:           None,
        }
    }
}

// ─── HttpClient ──────────────────────────────────────────────────────────────

pub struct HttpClient {
    inner:       Client,
    semaphore:   Arc<Semaphore>,
    max_body:    usize,
    default_timeout: Duration,
}

impl HttpClient {
    pub fn new(cfg: &HttpClientConfig) -> Result<Self> {
        let mut default_hdrs = HeaderMap::new();
        default_hdrs.insert(
            reqwest::header::USER_AGENT,
            HeaderValue::from_str(&cfg.user_agent)?,
        );
        if let Some(cookie) = &cfg.cookie {
            default_hdrs.insert(
                reqwest::header::COOKIE,
                HeaderValue::from_str(cookie)?,
            );
        }
        for (k, v) in &cfg.default_headers {
            if let (Ok(name), Ok(val)) = (
                HeaderName::from_bytes(k.as_bytes()),
                HeaderValue::from_str(v),
            ) {
                default_hdrs.insert(name, val);
            }
        }

        let redirect_policy = if cfg.follow_redirects {
            Policy::limited(5)
        } else {
            Policy::none()
        };

        let client = Client::builder()
            .danger_accept_invalid_certs(!cfg.verify_tls)
            .default_headers(default_hdrs)
            .redirect(redirect_policy)
            .timeout(Duration::from_millis(cfg.timeout_ms))
            .pool_max_idle_per_host(10)
            .build()
            .context("Build reqwest client")?;

        Ok(Self {
            inner:           client,
            semaphore:       Arc::new(Semaphore::new(cfg.max_concurrency)),
            max_body:        cfg.max_body_size,
            default_timeout: Duration::from_millis(cfg.timeout_ms),
        })
    }

    /// Send a request and return a `ScanResponse`.
    pub async fn send(&self, req: ScanRequest) -> Result<ScanResponse> {
        let _permit = self.semaphore.acquire().await?;

        let timeout = req.timeout_ms
            .map(Duration::from_millis)
            .unwrap_or(self.default_timeout);

        let method = reqwest::Method::from_bytes(req.method.as_bytes())
            .unwrap_or(reqwest::Method::GET);

        let mut builder = self.inner
            .request(method, &req.url)
            .timeout(timeout);

        for (k, v) in &req.headers {
            if let (Ok(name), Ok(val)) = (
                HeaderName::from_bytes(k.as_bytes()),
                HeaderValue::from_str(v),
            ) {
                builder = builder.header(name, val);
            }
        }

        if let Some(body) = req.body {
            builder = builder.body(body);
        }

        let start = Instant::now();
        let response = builder.send().await.context("HTTP request failed")?;
        let elapsed = start.elapsed().as_millis() as u64;

        Self::consume_response(response, elapsed, self.max_body).await
    }

    /// Send baseline + modified request pair; used for boolean-based detection.
    pub async fn send_pair(
        &self,
        baseline: ScanRequest,
        modified: ScanRequest,
    ) -> Result<(ScanResponse, ScanResponse)> {
        let (b, m) = tokio::join!(self.send(baseline), self.send(modified));
        Ok((b?, m?))
    }

    async fn consume_response(
        resp: Response,
        elapsed_ms: u64,
        max_body: usize,
    ) -> Result<ScanResponse> {
        let status = resp.status().as_u16();

        let headers: HashMap<String, String> = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();

        let redirect_url = headers.get("location").cloned();

        let body_bytes = resp.bytes().await.unwrap_or_default();
        let content_length = body_bytes.len();
        let body = if content_length <= max_body {
            String::from_utf8_lossy(&body_bytes).to_string()
        } else {
            warn!("Response body too large ({} bytes), truncating", content_length);
            String::from_utf8_lossy(&body_bytes[..max_body]).to_string()
        };

        debug!("HTTP {} {} → {} ({} ms)", "?", "?", status, elapsed_ms);

        Ok(ScanResponse {
            status,
            headers,
            body,
            elapsed_ms,
            content_length,
            redirect_url,
        })
    }

    /// Utility: replace a query parameter value in a URL.
    pub fn replace_query_param(url: &str, param: &str, value: &str) -> String {
        if let Ok(mut parsed) = url::Url::parse(url) {
            let new_pairs: Vec<(String, String)> = parsed
                .query_pairs()
                .map(|(k, v)| {
                    if k == param {
                        (k.to_string(), value.to_string())
                    } else {
                        (k.to_string(), v.to_string())
                    }
                })
                .collect();

            {
                let mut qs = parsed.query_pairs_mut();
                qs.clear();
                for (k, v) in &new_pairs {
                    qs.append_pair(k, v);
                }
            }
            parsed.to_string()
        } else {
            url.to_string()
        }
    }

    /// Utility: replace a body form parameter value.
    pub fn replace_form_param(body: &str, param: &str, value: &str) -> String {
        let encoded_value = url::form_urlencoded::byte_serialize(value.as_bytes()).collect::<String>();
        let mut parts: Vec<String> = body
            .split('&')
            .map(|kv| {
                let mut it = kv.splitn(2, '=');
                let k = it.next().unwrap_or("");
                let v = it.next().unwrap_or("");
                if k == param {
                    format!("{}={}", k, encoded_value)
                } else {
                    format!("{}={}", k, v)
                }
            })
            .collect();
        parts.join("&")
    }

    /// Utility: replace a JSON body field at depth-1.
    pub fn replace_json_param(body: &str, param: &str, value: &str) -> String {
        if let Ok(mut map) = serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(body) {
            map.insert(param.to_string(), serde_json::Value::String(value.to_string()));
            serde_json::to_string(&map).unwrap_or_else(|_| body.to_string())
        } else {
            body.to_string()
        }
    }
}
