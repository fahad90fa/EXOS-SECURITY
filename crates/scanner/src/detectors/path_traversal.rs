//! Path Traversal detector.

use async_trait::async_trait;
use nexus_core::models::{
    finding::Finding,
    scan::ScanConfig,
    vulnerability::{Severity, VulnerabilityClass},
};
use tracing::debug;

use crate::{
    detectors::{Detector, ParamLocation, ScanContext},
    http_client::ScanRequest,
    payloads::{PATH_TRAVERSAL_INDICATORS, PATH_TRAVERSAL_PAYLOADS},
};

pub struct PathTraversalDetector;

/// Parameter names likely to reflect file paths.
const PATH_PARAMS: &[&str] = &[
    "file", "path", "page", "include", "template", "doc", "document",
    "folder", "root", "dir", "name", "resource", "load", "view",
    "content", "read", "download", "filepath", "filename",
];

#[async_trait]
impl Detector for PathTraversalDetector {
    fn name(&self) -> &'static str { "path_traversal" }
    fn vuln_class(&self) -> VulnerabilityClass { VulnerabilityClass::PathTraversal }
    fn is_enabled(&self, _c: &ScanConfig) -> bool { true }

    async fn detect(&self, ctx: &ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        let target_params: Vec<_> = ctx.parameters.iter()
            .filter(|p| {
                p.location != ParamLocation::Header &&
                p.location != ParamLocation::Cookie &&
                (PATH_PARAMS.iter().any(|&s| p.name.to_lowercase().contains(s)) ||
                 p.value.contains('/') || p.value.contains('\\'))
            })
            .collect();

        for param in target_params {
            for payload in PATH_TRAVERSAL_PAYLOADS {
                let req = ScanRequest {
                    method:     ctx.method.clone(),
                    url:        ctx.url_with_param(&param.name, payload),
                    headers:    ctx.headers.clone(),
                    body:       ctx.body_with_param(&param.name, payload),
                    timeout_ms: Some(5000),
                };

                if let Ok(resp) = ctx.client.send(req).await {
                    if resp.contains_any(PATH_TRAVERSAL_INDICATORS) {
                        debug!("Path traversal hit on {} param={}", ctx.url, param.name);
                        findings.push(
                            Finding::new(
                                ctx.scan_id,
                                VulnerabilityClass::PathTraversal,
                                Severity::High,
                                &ctx.url,
                                &param.name,
                                *payload,
                                "Server returned file system content (e.g. /etc/passwd)",
                                "path_traversal",
                            )
                            .with_confidence(0.95),
                        );
                        break;
                    }
                }
            }
        }

        findings
    }
}
