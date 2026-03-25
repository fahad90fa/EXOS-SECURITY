//! Sentinel Core Scanner engine — coordinates crawl, detection, and finding aggregation.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use futures::stream::{self, StreamExt};
use nexus_core::models::{
    finding::Finding,
    scan::{ScanConfig, ScanStatus},
    vulnerability::{Severity, Vulnerability, VulnerabilityClass, VulnStatus},
};
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::{
    detectors::{build_detectors, ParamLocation, ScanContext, ScanParam},
    http_client::{HttpClient, HttpClientConfig, ScanRequest},
};

// ─── Scan Events ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum ScanEvent {
    UrlStarted  { url: String },
    UrlFinished { url: String, findings: usize },
    FindingDiscovered(Finding),
    StatusUpdate { status: ScanStatus, progress_pct: f32, message: String },
    Error { url: String, message: String },
    Finished { total_urls: usize, total_findings: usize },
}

// ─── ScanEngine ──────────────────────────────────────────────────────────────

pub struct ScanEngine {
    config:     ScanConfig,
    client:     Arc<HttpClient>,
}

impl ScanEngine {
    pub fn new(config: ScanConfig) -> Result<Self> {
        let client_cfg = HttpClientConfig {
            timeout_ms:       config.timeout_ms,
            max_concurrency:  config.concurrency,
            follow_redirects: config.follow_redirects,
            cookie:           config.auth_cookie.clone(),
            default_headers:  config.custom_headers.clone(),
            ..Default::default()
        };

        let client = Arc::new(HttpClient::new(&client_cfg)?);
        Ok(Self { config, client })
    }

    /// Scan a list of URLs, emitting `ScanEvent`s on `tx`.
    pub async fn run(
        &self,
        scan_id:    Uuid,
        project_id: Uuid,
        urls:       Vec<String>,
        tx:         mpsc::Sender<ScanEvent>,
    ) {
        let _ = tx.send(ScanEvent::StatusUpdate {
            status:       ScanStatus::Running,
            progress_pct: 0.0,
            message:      "Scan started".into(),
        }).await;

        let total = urls.len();
        let detectors = Arc::new(build_detectors(&self.config));

        let results: Vec<_> = stream::iter(urls.into_iter().enumerate())
            .map(|(i, url)| {
                let tx       = tx.clone();
                let client   = self.client.clone();
                let config   = self.config.clone();
                let dets     = detectors.clone();
                let oast     = config.oast_domain.clone();

                async move {
                    let _ = tx.send(ScanEvent::UrlStarted { url: url.clone() }).await;

                    // Build ScanContext for this URL
                    let params = extract_params_from_url(&url);
                    let ctx = ScanContext {
                        scan_id,
                        project_id,
                        url:         url.clone(),
                        method:      "GET".into(),
                        headers:     config.custom_headers.clone(),
                        body:        None,
                        parameters:  params,
                        client:      client.clone(),
                        oast_domain: oast,
                    };

                    let mut url_findings = Vec::new();
                    for det in dets.iter() {
                        match det.detect(&ctx).await {
                            findings if !findings.is_empty() => {
                                for f in &findings {
                                    let _ = tx.send(ScanEvent::FindingDiscovered(f.clone())).await;
                                }
                                url_findings.extend(findings);
                            }
                            _ => {}
                        }
                    }

                    let count = url_findings.len();
                    let progress = (i + 1) as f32 / total as f32 * 100.0;
                    let _ = tx.send(ScanEvent::UrlFinished { url: url.clone(), findings: count }).await;
                    let _ = tx.send(ScanEvent::StatusUpdate {
                        status:       ScanStatus::Running,
                        progress_pct: progress,
                        message:      format!("[{}/{}] {}", i + 1, total, url),
                    }).await;

                    url_findings
                }
            })
            .buffer_unordered(self.config.concurrency)
            .collect()
            .await;

        let all_findings: Vec<Finding> = results.into_iter().flatten().collect();
        let total_findings = all_findings.len();

        info!("Scan {} complete: {} URLs scanned, {} findings", scan_id, total, total_findings);

        let _ = tx.send(ScanEvent::StatusUpdate {
            status:       ScanStatus::Completed,
            progress_pct: 100.0,
            message:      format!("Scan complete: {} findings", total_findings),
        }).await;

        let _ = tx.send(ScanEvent::Finished {
            total_urls:     total,
            total_findings,
        }).await;
    }

    /// Scan a POST endpoint with a known body.
    pub async fn scan_post_endpoint(
        &self,
        scan_id:    Uuid,
        project_id: Uuid,
        url:        &str,
        headers:    HashMap<String, String>,
        body:       &str,
    ) -> Vec<Finding> {
        let ct = headers.get("content-type")
            .or_else(|| headers.get("Content-Type"))
            .map(String::as_str)
            .unwrap_or("application/x-www-form-urlencoded");

        let params = if ct.contains("application/json") {
            extract_params_from_json(body)
        } else {
            extract_params_from_form(body)
        };

        let ctx = ScanContext {
            scan_id,
            project_id,
            url:         url.to_string(),
            method:      "POST".into(),
            headers,
            body:        Some(body.to_string()),
            parameters:  params,
            client:      self.client.clone(),
            oast_domain: self.config.oast_domain.clone(),
        };

        let mut findings = Vec::new();
        for det in build_detectors(&self.config) {
            let mut f = det.detect(&ctx).await;
            findings.append(&mut f);
        }
        findings
    }
}

// ─── Finding → Vulnerability conversion ──────────────────────────────────────

/// Deduplicate and convert raw findings into `Vulnerability` records.
pub fn findings_to_vulns(findings: Vec<Finding>) -> Vec<Vulnerability> {
    // Group by (class, url, parameter)
    let mut groups: HashMap<(String, String, String), Vec<Finding>> = HashMap::new();
    for f in findings {
        let key = (
            format!("{:?}", f.class),
            f.url.clone(),
            f.parameter.clone(),
        );
        groups.entry(key).or_default().push(f);
    }

    groups.into_values().map(|mut group| {
        group.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap());
        let best = &group[0];

        let mut v = Vulnerability::new(
            best.scan_id,
            best.scan_id, // project_id placeholder — set by caller
            best.class.clone(),
            best.severity.clone(),
            format!("{}", best.class),
            &best.url,
        );
        v.parameter    = Some(best.parameter.clone());
        v.payload      = Some(best.payload.clone());
        v.evidence     = Some(best.evidence.clone());
        v.poc_request  = if best.request.is_empty() { None } else { Some(best.request.clone()) };
        v.poc_response = if best.response.is_empty() { None } else { Some(best.response.clone()) };
        v.confidence   = best.confidence;
        v.description  = generate_description(&best.class, &best.url, &best.parameter, &best.payload);
        v.remediation  = generate_remediation(&best.class);
        v.cwe_id       = class_to_cwe(&best.class);
        v.owasp_cat    = Some(class_to_owasp(&best.class).to_string());

        v
    })
    .collect()
}

// ─── Parameter extraction helpers ────────────────────────────────────────────

pub fn extract_params_from_url(url: &str) -> Vec<ScanParam> {
    let mut params = Vec::new();
    if let Ok(parsed) = url::Url::parse(url) {
        for (k, v) in parsed.query_pairs() {
            params.push(ScanParam {
                name:     k.to_string(),
                value:    v.to_string(),
                location: ParamLocation::Query,
            });
        }
    }
    params
}

fn extract_params_from_form(body: &str) -> Vec<ScanParam> {
    body.split('&')
        .filter_map(|kv| {
            let mut parts = kv.splitn(2, '=');
            let k = parts.next()?;
            let v = parts.next().unwrap_or("");
            if k.is_empty() { return None; }
            Some(ScanParam {
                name:     k.to_string(),
                value:    v.to_string(),
                location: ParamLocation::Body,
            })
        })
        .collect()
}

fn extract_params_from_json(body: &str) -> Vec<ScanParam> {
    if let Ok(serde_json::Value::Object(map)) = serde_json::from_str(body) {
        map.into_iter()
            .map(|(k, v)| ScanParam {
                name:     k,
                value:    v.to_string().trim_matches('"').to_string(),
                location: ParamLocation::Json,
            })
            .collect()
    } else {
        Vec::new()
    }
}

// ─── Metadata helpers ─────────────────────────────────────────────────────────

fn generate_description(
    class: &VulnerabilityClass,
    url: &str,
    param: &str,
    payload: &str,
) -> String {
    format!(
        "{} vulnerability detected at {} in parameter `{}`. \
        Injected payload: `{}`. \
        This may allow an attacker to {}.",
        class,
        url,
        param,
        payload,
        class_impact(class)
    )
}

fn generate_remediation(class: &VulnerabilityClass) -> String {
    match class {
        VulnerabilityClass::SqlInjection => "Use parameterized queries or prepared statements. Never concatenate user input into SQL strings.".into(),
        VulnerabilityClass::XssReflected | VulnerabilityClass::XssStored | VulnerabilityClass::XssDom =>
            "HTML-encode all user-supplied data before rendering in the browser. Implement a strict Content-Security-Policy.".into(),
        VulnerabilityClass::Ssrf => "Validate and allowlist outbound URLs. Block access to internal IP ranges and cloud metadata endpoints.".into(),
        VulnerabilityClass::Xxe => "Disable external entity processing in the XML parser. Use a safe XML library configuration.".into(),
        VulnerabilityClass::CommandInjection => "Never pass user input to shell commands. Use language APIs instead of shell execution.".into(),
        VulnerabilityClass::SstiTemplateInjection => "Do not render user-supplied data as template source. Use a sandboxed template environment.".into(),
        VulnerabilityClass::PathTraversal => "Canonicalize file paths and enforce they reside within an allowed base directory.".into(),
        VulnerabilityClass::OpenRedirect => "Validate redirect targets against an allowlist of trusted domains.".into(),
        VulnerabilityClass::CorsMisconfiguration => "Set CORS Access-Control-Allow-Origin to specific trusted origins only.".into(),
        VulnerabilityClass::SecurityMisconfiguration => "Add the missing security header with an appropriate value per the OWASP Secure Headers Project.".into(),
        _ => "Apply defense-in-depth controls and consult OWASP guidance for this vulnerability class.".into(),
    }
}

fn class_to_cwe(class: &VulnerabilityClass) -> Option<u32> {
    Some(match class {
        VulnerabilityClass::SqlInjection            => 89,
        VulnerabilityClass::XssReflected            => 79,
        VulnerabilityClass::XssStored               => 79,
        VulnerabilityClass::XssDom                  => 79,
        VulnerabilityClass::Ssrf                    => 918,
        VulnerabilityClass::Xxe                     => 611,
        VulnerabilityClass::CommandInjection        => 78,
        VulnerabilityClass::SstiTemplateInjection   => 94,
        VulnerabilityClass::PathTraversal           => 22,
        VulnerabilityClass::OpenRedirect            => 601,
        VulnerabilityClass::CorsMisconfiguration    => 942,
        VulnerabilityClass::SecurityMisconfiguration => 16,
        VulnerabilityClass::InsecureDeserialization => 502,
        VulnerabilityClass::BrokenAuthentication    => 287,
        VulnerabilityClass::JwtVulnerability        => 287,
        _ => return None,
    })
}

fn class_to_owasp(class: &VulnerabilityClass) -> &'static str {
    match class {
        VulnerabilityClass::SqlInjection | VulnerabilityClass::CommandInjection |
        VulnerabilityClass::Xxe | VulnerabilityClass::SstiTemplateInjection => "A03:2021 – Injection",
        VulnerabilityClass::XssReflected | VulnerabilityClass::XssStored | VulnerabilityClass::XssDom => "A03:2021 – Injection (XSS)",
        VulnerabilityClass::BrokenAuthentication | VulnerabilityClass::JwtVulnerability => "A07:2021 – Identification and Authentication Failures",
        VulnerabilityClass::Ssrf => "A10:2021 – Server-Side Request Forgery",
        VulnerabilityClass::SecurityMisconfiguration | VulnerabilityClass::CorsMisconfiguration => "A05:2021 – Security Misconfiguration",
        VulnerabilityClass::SensitiveDataExposure => "A02:2021 – Cryptographic Failures",
        VulnerabilityClass::InsecureDeserialization => "A08:2021 – Software and Data Integrity Failures",
        VulnerabilityClass::BrokenAccessControl | VulnerabilityClass::Idor => "A01:2021 – Broken Access Control",
        _ => "A05:2021 – Security Misconfiguration",
    }
}

fn class_impact(class: &VulnerabilityClass) -> &'static str {
    match class {
        VulnerabilityClass::SqlInjection => "read, modify, or delete database data",
        VulnerabilityClass::XssReflected => "execute arbitrary JavaScript in victims' browsers",
        VulnerabilityClass::Ssrf => "access internal services and cloud metadata",
        VulnerabilityClass::CommandInjection => "execute arbitrary OS commands on the server",
        VulnerabilityClass::PathTraversal => "read arbitrary files on the server",
        VulnerabilityClass::SstiTemplateInjection => "achieve remote code execution",
        _ => "compromise application security",
    }
}
