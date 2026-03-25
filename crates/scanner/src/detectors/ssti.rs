//! Server-Side Template Injection (SSTI) detector.

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
    payloads::SSTI_PAYLOADS,
};

pub struct SstiDetector;

#[async_trait]
impl Detector for SstiDetector {
    fn name(&self) -> &'static str { "ssti" }
    fn vuln_class(&self) -> VulnerabilityClass { VulnerabilityClass::SstiTemplateInjection }
    fn is_enabled(&self, c: &ScanConfig) -> bool { c.include_xss } // gate on XSS flag

    async fn detect(&self, ctx: &ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        for param in &ctx.parameters {
            if param.location == ParamLocation::Header || param.location == ParamLocation::Cookie {
                continue;
            }

            for (payload, expected) in SSTI_PAYLOADS {
                let req = ScanRequest {
                    method:     ctx.method.clone(),
                    url:        ctx.url_with_param(&param.name, payload),
                    headers:    ctx.headers.clone(),
                    body:       ctx.body_with_param(&param.name, payload),
                    timeout_ms: None,
                };

                if let Ok(resp) = ctx.client.send(req).await {
                    if resp.body.contains(expected) {
                        debug!("SSTI hit on {} param={} payload={}", ctx.url, param.name, payload);
                        findings.push(
                            Finding::new(
                                ctx.scan_id,
                                VulnerabilityClass::SstiTemplateInjection,
                                Severity::Critical,
                                &ctx.url,
                                &param.name,
                                *payload,
                                format!("Template expression `{}` evaluated to `{}`", payload, expected),
                                "ssti/expression",
                            )
                            .with_confidence(0.95)
                            .with_traffic(
                                format!("{} {} {}={}", ctx.method, ctx.url, param.name, payload),
                                format!("HTTP {} body_contains='{}'", resp.status, expected),
                            ),
                        );
                        break;
                    }
                }
            }
        }

        findings
    }
}
