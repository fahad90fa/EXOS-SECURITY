//! Detector trait and scan context shared by all vulnerability checks.

pub mod cmdi;
pub mod cors;
pub mod headers;
pub mod open_redirect;
pub mod path_traversal;
pub mod sqli;
pub mod ssrf;
pub mod ssti;
pub mod xss;
pub mod xxe;

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use nexus_core::models::{
    finding::Finding, scan::ScanConfig, vulnerability::VulnerabilityClass,
};
use uuid::Uuid;

use crate::http_client::HttpClient;

pub use cmdi::CommandInjectionDetector;
pub use cors::CorsDetector;
pub use headers::HeadersDetector;
pub use open_redirect::OpenRedirectDetector;
pub use path_traversal::PathTraversalDetector;
pub use sqli::SqlInjectionDetector;
pub use ssrf::SsrfDetector;
pub use ssti::SstiDetector;
pub use xss::XssDetector;
pub use xxe::XxeDetector;

// ─── ScanContext ──────────────────────────────────────────────────────────────

/// All information needed to test a single request endpoint.
#[derive(Clone)]
pub struct ScanContext {
    pub scan_id:     Uuid,
    pub project_id:  Uuid,
    pub url:         String,
    pub method:      String,
    pub headers:     HashMap<String, String>,
    /// URL-encoded or JSON body, if any.
    pub body:        Option<String>,
    /// Detected parameters (name, location).
    pub parameters:  Vec<ScanParam>,
    pub client:      Arc<HttpClient>,
    /// OAST domain for out-of-band callbacks (e.g. "oast.nexussentinel.io").
    pub oast_domain: Option<String>,
}

/// A single parameter extracted from a request.
#[derive(Debug, Clone)]
pub struct ScanParam {
    pub name:     String,
    pub value:    String,
    pub location: ParamLocation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParamLocation {
    Query,
    Body,
    Json,
    Header,
    Cookie,
    Path,
}

impl ScanContext {
    /// Build the URL with `param` replaced by `value` (query params only).
    pub fn url_with_param(&self, param: &str, value: &str) -> String {
        HttpClient::replace_query_param(&self.url, param, value)
    }

    /// Build a body with `param` replaced by `value`.
    pub fn body_with_param(&self, param: &str, value: &str) -> Option<String> {
        self.body.as_deref().map(|b| {
            let ct = self.headers.get("content-type")
                .or_else(|| self.headers.get("Content-Type"))
                .map(String::as_str)
                .unwrap_or("");
            if ct.contains("application/json") {
                HttpClient::replace_json_param(b, param, value)
            } else {
                HttpClient::replace_form_param(b, param, value)
            }
        })
    }

    /// Content-Type from headers.
    pub fn content_type(&self) -> &str {
        self.headers.get("content-type")
            .or_else(|| self.headers.get("Content-Type"))
            .map(String::as_str)
            .unwrap_or("")
    }
}

// ─── Detector ────────────────────────────────────────────────────────────────

#[async_trait]
pub trait Detector: Send + Sync {
    fn name(&self) -> &'static str;
    fn vuln_class(&self) -> VulnerabilityClass;
    fn is_enabled(&self, config: &ScanConfig) -> bool;
    async fn detect(&self, ctx: &ScanContext) -> Vec<Finding>;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Build all detectors respecting scan config flags.
pub fn build_detectors(config: &ScanConfig) -> Vec<Box<dyn Detector>> {
    let mut detectors: Vec<Box<dyn Detector>> = Vec::new();

    if config.include_sqli {
        detectors.push(Box::new(SqlInjectionDetector));
    }
    if config.include_xss {
        detectors.push(Box::new(XssDetector));
    }
    if config.include_ssrf {
        detectors.push(Box::new(SsrfDetector));
    }
    if config.include_xxe {
        detectors.push(Box::new(XxeDetector));
    }
    if config.include_cmdi {
        detectors.push(Box::new(CommandInjectionDetector));
    }
    // SSTI always on when XSS is on (similar surface)
    if config.include_xss {
        detectors.push(Box::new(SstiDetector));
    }
    detectors.push(Box::new(PathTraversalDetector));
    detectors.push(Box::new(OpenRedirectDetector));
    detectors.push(Box::new(CorsDetector));
    detectors.push(Box::new(HeadersDetector));

    detectors
}
