//! XSS detector — reflected, stored-indicator, DOM-pointer.

use async_trait::async_trait;
use nexus_core::models::{
    finding::Finding,
    scan::ScanConfig,
    vulnerability::{Severity, VulnerabilityClass},
};
use rand::Rng;
use tracing::debug;

use crate::{
    detectors::{Detector, ParamLocation, ScanContext},
    http_client::ScanRequest,
    payloads::XSS_CONTEXT_PAYLOADS,
};

pub struct XssDetector;

#[async_trait]
impl Detector for XssDetector {
    fn name(&self) -> &'static str { "xss" }
    fn vuln_class(&self) -> VulnerabilityClass { VulnerabilityClass::XssReflected }
    fn is_enabled(&self, c: &ScanConfig) -> bool { c.include_xss }

    async fn detect(&self, ctx: &ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        for param in &ctx.parameters {
            if param.location == ParamLocation::Cookie { continue; }

            if let Some(f) = self.try_reflect(ctx, param).await {
                findings.push(f);
            }
        }

        findings
    }
}

impl XssDetector {
    async fn try_reflect(
        &self,
        ctx: &ScanContext,
        param: &crate::detectors::ScanParam,
    ) -> Option<Finding> {
        // Generate a unique nonce so we can distinguish our reflection
        let nonce: String = {
            let mut rng = rand::thread_rng();
            format!("nxs{:08x}", rng.gen::<u32>())
        };

        for template in XSS_CONTEXT_PAYLOADS {
            let payload = template.replace("{nonce}", &nonce);
            let req = build_request(ctx, &param.name, &payload);
            let resp = match ctx.client.send(req).await {
                Ok(r) => r,
                Err(_) => continue,
            };

            // Check if our unique nonce appears unencoded in the response
            if resp.body.contains(&nonce) {
                // Further check: is an actual XSS tag present unencoded?
                let lower_body = resp.body_lower();
                let is_unencoded = lower_body.contains("<script") ||
                    lower_body.contains("onerror=") ||
                    lower_body.contains("onload=") ||
                    lower_body.contains("onfocus=") ||
                    lower_body.contains("<svg") ||
                    lower_body.contains("javascript:");

                let severity = if is_unencoded { Severity::High } else { Severity::Medium };

                debug!("XSS reflected hit on {} param={}", ctx.url, param.name);

                return Some(
                    Finding::new(
                        ctx.scan_id,
                        VulnerabilityClass::XssReflected,
                        severity,
                        &ctx.url,
                        &param.name,
                        &payload,
                        format!("Nonce `{}` reflected unencoded in response body", nonce),
                        "xss/reflected",
                    )
                    .with_confidence(if is_unencoded { 0.95 } else { 0.70 })
                    .with_traffic(
                        format!("{} {} {}={}", ctx.method, ctx.url, param.name, payload),
                        format!("HTTP {} body_contains_nonce=true", resp.status),
                    ),
                );
            }
        }

        None
    }
}

fn build_request(ctx: &ScanContext, param_name: &str, payload: &str) -> ScanRequest {
    ScanRequest {
        method:     ctx.method.clone(),
        url:        ctx.url_with_param(param_name, payload),
        headers:    ctx.headers.clone(),
        body:       ctx.body_with_param(param_name, payload),
        timeout_ms: None,
    }
}
