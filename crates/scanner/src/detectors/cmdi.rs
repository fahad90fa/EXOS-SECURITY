//! OS Command Injection detector — output-based and time-based.

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
    payloads::{CMDI_PAYLOADS, CMDI_TIME_PAYLOADS},
};

pub struct CommandInjectionDetector;

#[async_trait]
impl Detector for CommandInjectionDetector {
    fn name(&self) -> &'static str { "cmdi" }
    fn vuln_class(&self) -> VulnerabilityClass { VulnerabilityClass::CommandInjection }
    fn is_enabled(&self, c: &ScanConfig) -> bool { c.include_cmdi }

    async fn detect(&self, ctx: &ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        for param in &ctx.parameters {
            if param.location == ParamLocation::Header || param.location == ParamLocation::Cookie {
                continue;
            }

            // Output-based
            for (payload, indicator) in CMDI_PAYLOADS {
                let req = build_req(ctx, &param.name, payload);
                if let Ok(resp) = ctx.client.send(req).await {
                    let lower = resp.body_lower();
                    if lower.contains(indicator) {
                        debug!("CMDi output hit on {} param={}", ctx.url, param.name);
                        findings.push(
                            Finding::new(
                                ctx.scan_id,
                                VulnerabilityClass::CommandInjection,
                                Severity::Critical,
                                &ctx.url,
                                &param.name,
                                *payload,
                                format!("Command output indicator `{}` found in response", indicator),
                                "cmdi/output",
                            )
                            .with_confidence(0.95),
                        );
                        break;
                    }
                }
            }

            // Time-based
            for (payload, threshold_ms) in CMDI_TIME_PAYLOADS {
                let req = build_req(ctx, &param.name, payload)
                    .with_timeout(threshold_ms + 3000);
                if let Ok(resp) = ctx.client.send(req).await {
                    if resp.elapsed_ms >= *threshold_ms {
                        debug!("CMDi time-based hit on {} param={}", ctx.url, param.name);
                        findings.push(
                            Finding::new(
                                ctx.scan_id,
                                VulnerabilityClass::CommandInjection,
                                Severity::Critical,
                                &ctx.url,
                                &param.name,
                                *payload,
                                format!("Response delayed {}ms suggesting blind command injection", resp.elapsed_ms),
                                "cmdi/time",
                            )
                            .with_confidence(0.80),
                        );
                        break;
                    }
                }
            }
        }

        findings
    }
}

fn build_req(ctx: &ScanContext, param: &str, payload: &str) -> ScanRequest {
    ScanRequest {
        method:     ctx.method.clone(),
        url:        ctx.url_with_param(param, payload),
        headers:    ctx.headers.clone(),
        body:       ctx.body_with_param(param, payload),
        timeout_ms: None,
    }
}
