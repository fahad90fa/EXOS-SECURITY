//! Quantum Fuzzer engine — directory brute-force and parameter mutation.

use std::sync::Arc;

use anyhow::Result;
use futures::stream::{self, StreamExt};
use nexus_scanner::http_client::{HttpClient, HttpClientConfig, ScanRequest, ScanResponse};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};
use uuid::Uuid;

use crate::wordlists::{mutate_value, COMMON_PATHS, COMMON_PARAMS};

// ─── FuzzerConfig ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzerConfig {
    pub concurrency:     usize,
    pub timeout_ms:      u64,
    pub user_agent:      String,
    pub auth_cookie:     Option<String>,
    /// HTTP status codes to treat as "found"
    pub positive_codes:  Vec<u16>,
    /// Minimum response body length to consider interesting
    pub min_body_length: usize,
}

impl Default for FuzzerConfig {
    fn default() -> Self {
        Self {
            concurrency:     20,
            timeout_ms:      5_000,
            user_agent:      "NexusSentinel/0.1 Fuzzer".into(),
            auth_cookie:     None,
            positive_codes:  vec![200, 201, 202, 204, 301, 302, 307, 401, 403],
            min_body_length: 10,
        }
    }
}

// ─── FuzzResult ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzResult {
    pub url:           String,
    pub status:        u16,
    pub body_length:   usize,
    pub redirect_url:  Option<String>,
    pub interesting:   bool,
    pub notes:         Vec<String>,
}

// ─── Fuzzer ───────────────────────────────────────────────────────────────────

pub struct Fuzzer {
    config: FuzzerConfig,
    client: Arc<HttpClient>,
}

impl Fuzzer {
    pub fn new(config: FuzzerConfig) -> Result<Self> {
        let client_cfg = HttpClientConfig {
            timeout_ms:       config.timeout_ms,
            max_concurrency:  config.concurrency,
            user_agent:       config.user_agent.clone(),
            follow_redirects: false,
            cookie:           config.auth_cookie.clone(),
            ..Default::default()
        };
        let client = Arc::new(HttpClient::new(&client_cfg)?);
        Ok(Self { config, client })
    }

    /// Brute-force directories and files on a base URL.
    pub async fn fuzz_paths(&self, base_url: &str) -> Vec<FuzzResult> {
        let base = base_url.trim_end_matches('/');

        let results: Vec<_> = stream::iter(COMMON_PATHS.iter())
            .map(|path| {
                let url    = format!("{}/{}", base, path);
                let client = self.client.clone();
                let cfg    = self.config.clone();
                async move {
                    Self::probe(&client, &url, &cfg).await
                }
            })
            .buffer_unordered(self.config.concurrency)
            .filter_map(|r| async move { r })
            .collect()
            .await;

        info!("Path fuzzing complete: {} interesting paths on {}", results.len(), base_url);
        results
    }

    /// Fuzz parameters on an existing URL using mutation strategies.
    pub async fn fuzz_params(
        &self,
        url:    &str,
        method: &str,
        body:   Option<&str>,
    ) -> Vec<FuzzResult> {
        // Get baseline response first
        let baseline_req = ScanRequest {
            method:     method.to_string(),
            url:        url.to_string(),
            headers:    Default::default(),
            body:       body.map(str::to_string),
            timeout_ms: None,
        };
        let baseline = match self.client.send(baseline_req).await {
            Ok(r) => r,
            Err(_) => return vec![],
        };

        let mut interesting = Vec::new();

        // Inject common params into query string
        for param_name in COMMON_PARAMS {
            for value in &["1", "test", "true", "'", "<"] {
                let test_url = HttpClient::replace_query_param(url, param_name, value);
                if let Some(result) = Self::probe(&self.client, &test_url, &self.config).await {
                    if result.body_length != baseline.content_length {
                        let mut r = result;
                        r.notes.push(format!("Body length differs from baseline ({} vs {})",
                            r.body_length, baseline.content_length));
                        r.interesting = true;
                        interesting.push(r);
                    }
                }
            }
        }

        interesting
    }

    /// Fuzz IDOR by incrementing/decrementing numeric IDs in the URL.
    pub async fn fuzz_idor(
        &self,
        url:     &str,
        param:   &str,
        id:      i64,
    ) -> Vec<FuzzResult> {
        let ids: Vec<i64> = (-2..=2).map(|d| id + d).chain([0, 1, 999, 9999].iter().copied()).collect();
        let mut results = Vec::new();

        for test_id in ids {
            let test_url = HttpClient::replace_query_param(url, param, &test_id.to_string());
            if let Some(r) = Self::probe(&self.client, &test_url, &self.config).await {
                results.push(r);
            }
        }

        results
    }

    /// Send a single probe request, returning a result only if the status is "interesting".
    async fn probe(client: &Arc<HttpClient>, url: &str, cfg: &FuzzerConfig) -> Option<FuzzResult> {
        let req = ScanRequest {
            method:     "GET".into(),
            url:        url.to_string(),
            headers:    Default::default(),
            body:       None,
            timeout_ms: Some(cfg.timeout_ms),
        };

        let resp = client.send(req).await.ok()?;

        if !cfg.positive_codes.contains(&resp.status) {
            return None;
        }
        if resp.content_length < cfg.min_body_length {
            return None;
        }

        let interesting = resp.status == 200
            || resp.status == 403   // access-controlled endpoint
            || resp.redirect_url.is_some();

        let mut notes = Vec::new();
        if resp.status == 403 { notes.push("Access denied — endpoint exists".into()); }
        if resp.redirect_url.is_some() {
            notes.push(format!("Redirects to: {}", resp.redirect_url.as_deref().unwrap_or("")));
        }

        debug!("Fuzz hit: {} → HTTP {}", url, resp.status);

        Some(FuzzResult {
            url:          url.to_string(),
            status:       resp.status,
            body_length:  resp.content_length,
            redirect_url: resp.redirect_url,
            interesting,
            notes,
        })
    }
}
