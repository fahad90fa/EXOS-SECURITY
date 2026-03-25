//! Open Redirect detector.

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
    payloads::{REDIRECT_PARAMS, REDIRECT_PAYLOADS},
};

pub struct OpenRedirectDetector;

#[async_trait]
impl Detector for OpenRedirectDetector {
    fn name(&self) -> &'static str { "open_redirect" }
    fn vuln_class(&self) -> VulnerabilityClass { VulnerabilityClass::OpenRedirect }
    fn is_enabled(&self, _c: &ScanConfig) -> bool { true }

    async fn detect(&self, ctx: &ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        let redirect_params: Vec<_> = ctx.parameters.iter()
            .filter(|p| {
                p.location != ParamLocation::Header &&
                REDIRECT_PARAMS.iter().any(|&r| p.name.to_lowercase().contains(r))
            })
            .collect();

        for param in redirect_params {
            for payload in REDIRECT_PAYLOADS {
                let req = ScanRequest {
                    method:     ctx.method.clone(),
                    url:        ctx.url_with_param(&param.name, payload),
                    headers:    ctx.headers.clone(),
                    body:       ctx.body_with_param(&param.name, payload),
                    timeout_ms: Some(5000),
                };

                if let Ok(resp) = ctx.client.send(req).await {
                    let redirected = resp.redirect_url.as_deref().unwrap_or("");
                    let is_3xx = (300..=399).contains(&resp.status);

                    let redirects_to_evil = redirected.contains("evil.com") ||
                        redirected.contains("attacker.com");

                    if is_3xx && redirects_to_evil {
                        debug!("Open redirect on {} param={}", ctx.url, param.name);
                        findings.push(
                            Finding::new(
                                ctx.scan_id,
                                VulnerabilityClass::OpenRedirect,
                                Severity::Medium,
                                &ctx.url,
                                &param.name,
                                payload,
                                format!("Server redirected to external domain: {}", redirected),
                                "open_redirect",
                            )
                            .with_confidence(0.90),
                        );
                        break;
                    }
                }
            }
        }

        findings
    }
}
