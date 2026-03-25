use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanStatus {
    Queued,
    Running,
    Paused,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanType {
    Active,        // sends payloads
    Passive,       // proxy traffic analysis only
    Crawl,         // discovery only
    Fuzz,          // parameter fuzzing
    Api,           // REST/GraphQL API focused
    Authentication,
    BusinessLogic,
    Full,          // all of the above
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub scan_type:       ScanType,
    pub max_depth:       u32,
    pub concurrency:     usize,
    pub timeout_ms:      u64,
    pub rate_limit:      u32,
    pub follow_redirects: bool,
    pub include_sqli:    bool,
    pub include_xss:     bool,
    pub include_ssrf:    bool,
    pub include_xxe:     bool,
    pub include_cmdi:    bool,
    pub include_csrf:    bool,
    pub include_idor:    bool,
    pub include_auth:    bool,
    pub include_crypto:  bool,
    pub oast_domain:     Option<String>,
    pub custom_headers:  std::collections::HashMap<String, String>,
    pub auth_cookie:     Option<String>,
    pub auth_token:      Option<String>,
    pub user_agent:      String,
    pub scope_regex:     Vec<String>,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            scan_type:        ScanType::Full,
            max_depth:        10,
            concurrency:      20,
            timeout_ms:       10_000,
            rate_limit:       100,
            follow_redirects: true,
            include_sqli:     true,
            include_xss:      true,
            include_ssrf:     true,
            include_xxe:      true,
            include_cmdi:     true,
            include_csrf:     true,
            include_idor:     true,
            include_auth:     true,
            include_crypto:   true,
            oast_domain:      None,
            custom_headers:   Default::default(),
            auth_cookie:      None,
            auth_token:       None,
            user_agent:       "NexusSentinel/0.1 (Security Scanner)".into(),
            scope_regex:      Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scan {
    pub id:            Uuid,
    pub project_id:    Uuid,
    pub config:        ScanConfig,
    pub status:        ScanStatus,

    pub target_url:    String,
    pub urls_crawled:  u64,
    pub requests_sent: u64,
    pub vulns_found:   u64,
    pub errors:        u64,

    pub progress_pct:  f32,
    pub current_task:  Option<String>,
    pub error_message: Option<String>,

    pub started_at:    Option<DateTime<Utc>>,
    pub finished_at:   Option<DateTime<Utc>>,
    pub created_at:    DateTime<Utc>,
}

impl Scan {
    pub fn new(project_id: Uuid, target_url: impl Into<String>, config: ScanConfig) -> Self {
        Self {
            id:            Uuid::new_v4(),
            project_id,
            config,
            status:        ScanStatus::Queued,
            target_url:    target_url.into(),
            urls_crawled:  0,
            requests_sent: 0,
            vulns_found:   0,
            errors:        0,
            progress_pct:  0.0,
            current_task:  None,
            error_message: None,
            started_at:    None,
            finished_at:   None,
            created_at:    Utc::now(),
        }
    }

    pub fn duration_secs(&self) -> Option<i64> {
        match (self.started_at, self.finished_at) {
            (Some(s), Some(e)) => Some((e - s).num_seconds()),
            _ => None,
        }
    }
}
