//! XXE (XML External Entity) detector.

use async_trait::async_trait;
use nexus_core::models::{
    finding::Finding,
    scan::ScanConfig,
    vulnerability::{Severity, VulnerabilityClass},
};
use tracing::debug;

use crate::{
    detectors::{Detector, ScanContext},
    http_client::ScanRequest,
    payloads::{XXE_PAYLOADS, XXE_RESPONSE_INDICATORS},
};

pub struct XxeDetector;

#[async_trait]
impl Detector for XxeDetector {
    fn name(&self) -> &'static str { "xxe" }
    fn vuln_class(&self) -> VulnerabilityClass { VulnerabilityClass::Xxe }
    fn is_enabled(&self, c: &ScanConfig) -> bool { c.include_xxe }

    async fn detect(&self, ctx: &ScanContext) -> Vec<Finding> {
        // Only test XML endpoints
        let ct = ctx.content_type();
        if !ct.contains("xml") && !ctx.body.as_deref().map(|b| b.trim_start().starts_with('<')).unwrap_or(false) {
            return vec![];
        }

        let mut findings = Vec::new();
        let oast_domain = ctx.oast_domain.as_deref().unwrap_or("oast.localhost");

        for template in XXE_PAYLOADS {
            let payload = template.replace("{oast}", oast_domain);
            let req = ScanRequest {
                method:     ctx.method.clone(),
                url:        ctx.url.clone(),
                headers:    {
                    let mut h = ctx.headers.clone();
                    h.insert("content-type".into(), "application/xml".into());
                    h
                },
                body:       Some(payload.clone()),
                timeout_ms: Some(8000),
            };

            if let Ok(resp) = ctx.client.send(req).await {
                if resp.contains_any(XXE_RESPONSE_INDICATORS) {
                    debug!("XXE hit on {}", ctx.url);
                    findings.push(
                        Finding::new(
                            ctx.scan_id,
                            VulnerabilityClass::Xxe,
                            Severity::Critical,
                            &ctx.url,
                            "xml-body",
                            &payload,
                            "XXE: server returned file contents via entity expansion",
                            "xxe/file-read",
                        )
                        .with_confidence(0.95),
                    );
                    break;
                }
            }
        }

        findings
    }
}
