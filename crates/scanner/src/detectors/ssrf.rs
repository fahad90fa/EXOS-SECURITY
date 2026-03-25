//! SSRF detector — injects cloud metadata URLs and OAST callbacks.

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
    payloads::SSRF_CLOUD_TARGETS,
};

pub struct SsrfDetector;

/// Heuristics indicating a successful SSRF against cloud metadata.
const SSRF_INDICATORS: &[&str] = &[
    "ami-id", "instance-id", "local-hostname", "local-ipv4",
    "security-credentials", "iam", "computemetadata",
    "subscriptionid", "resourcegroupname", "vmid",
];

/// URL-like parameter names that are likely SSRF entry points.
const SSRF_PARAMS: &[&str] = &[
    "url", "uri", "path", "file", "src", "source", "href", "action",
    "host", "domain", "target", "endpoint", "callback", "return",
    "next", "data", "load", "resource", "fetch", "proxy", "image",
    "link", "redirect", "location", "dest", "view",
];

#[async_trait]
impl Detector for SsrfDetector {
    fn name(&self) -> &'static str { "ssrf" }
    fn vuln_class(&self) -> VulnerabilityClass { VulnerabilityClass::Ssrf }
    fn is_enabled(&self, c: &ScanConfig) -> bool { c.include_ssrf }

    async fn detect(&self, ctx: &ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        let target_params: Vec<_> = ctx.parameters.iter()
            .filter(|p| {
                p.location != ParamLocation::Header &&
                p.location != ParamLocation::Cookie &&
                SSRF_PARAMS.iter().any(|&s| p.name.to_lowercase().contains(s))
            })
            .collect();

        for param in target_params {
            // Cloud metadata probes
            for target in SSRF_CLOUD_TARGETS {
                let req = ScanRequest {
                    method:     ctx.method.clone(),
                    url:        ctx.url_with_param(&param.name, target),
                    headers:    ctx.headers.clone(),
                    body:       ctx.body_with_param(&param.name, target),
                    timeout_ms: Some(5000),
                };

                if let Ok(resp) = ctx.client.send(req).await {
                    if resp.contains_any(SSRF_INDICATORS) || is_success_status(resp.status) {
                        debug!("SSRF hit on {} param={} target={}", ctx.url, param.name, target);
                        findings.push(
                            Finding::new(
                                ctx.scan_id,
                                VulnerabilityClass::Ssrf,
                                Severity::Critical,
                                &ctx.url,
                                &param.name,
                                *target,
                                format!("Potential SSRF — server fetched {} (HTTP {})", target, resp.status),
                                "ssrf/cloud-metadata",
                            )
                            .with_confidence(0.80),
                        );
                        break;
                    }
                }
            }

            // OAST-based probe
            if let Some(oast) = &ctx.oast_domain {
                let oast_url = format!("http://{}.ssrf.{}/", ctx.scan_id, oast);
                let req = ScanRequest {
                    method:     ctx.method.clone(),
                    url:        ctx.url_with_param(&param.name, &oast_url),
                    headers:    ctx.headers.clone(),
                    body:       ctx.body_with_param(&param.name, &oast_url),
                    timeout_ms: Some(5000),
                };
                if ctx.client.send(req).await.is_ok() {
                    // Note: actual OAST confirmation requires checking the OAST server;
                    // here we record the probe as an informational finding
                    findings.push(
                        Finding::new(
                            ctx.scan_id,
                            VulnerabilityClass::Ssrf,
                            Severity::High,
                            &ctx.url,
                            &param.name,
                            oast_url.as_str(),
                            format!("OAST SSRF probe sent — check {} for callback", oast),
                            "ssrf/oast",
                        )
                        .with_confidence(0.60),
                    );
                }
            }
        }

        findings
    }
}

fn is_success_status(status: u16) -> bool {
    status == 200
}
