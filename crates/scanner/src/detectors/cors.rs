//! CORS misconfiguration detector.

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
    payloads::CORS_TEST_ORIGINS,
};

pub struct CorsDetector;

#[async_trait]
impl Detector for CorsDetector {
    fn name(&self) -> &'static str { "cors" }
    fn vuln_class(&self) -> VulnerabilityClass { VulnerabilityClass::CorsMisconfiguration }
    fn is_enabled(&self, _c: &ScanConfig) -> bool { true }

    async fn detect(&self, ctx: &ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        for origin in CORS_TEST_ORIGINS {
            let mut headers = ctx.headers.clone();
            headers.insert("Origin".into(), origin.to_string());
            headers.insert("Access-Control-Request-Method".into(), "GET".into());

            let req = ScanRequest {
                method:     "OPTIONS".into(),
                url:        ctx.url.clone(),
                headers:    headers.clone(),
                body:       None,
                timeout_ms: Some(5000),
            };

            if let Ok(resp) = ctx.client.send(req).await {
                let acao = resp.header("access-control-allow-origin").unwrap_or("").to_string();
                let acac = resp.header("access-control-allow-credentials").unwrap_or("").to_string();

                // ACAO mirrors attacker origin
                let mirrors_origin = acao == *origin;
                // ACAO is wildcard
                let is_wildcard = acao == "*";
                // ACAO is null (dangerous — sandbox iframe bypass)
                let is_null = acao == "null" && *origin == "null";

                if mirrors_origin && acac.to_lowercase() == "true" {
                    debug!("CORS critical: mirrors origin + credentials on {}", ctx.url);
                    findings.push(
                        Finding::new(
                            ctx.scan_id,
                            VulnerabilityClass::CorsMisconfiguration,
                            Severity::Critical,
                            &ctx.url,
                            "Origin",
                            *origin,
                            format!("ACAO mirrors attacker origin ({}) AND ACAC=true — allows credentialed XS reads", origin),
                            "cors/mirror-with-credentials",
                        )
                        .with_confidence(0.95),
                    );
                } else if mirrors_origin {
                    findings.push(
                        Finding::new(
                            ctx.scan_id,
                            VulnerabilityClass::CorsMisconfiguration,
                            Severity::Medium,
                            &ctx.url,
                            "Origin",
                            *origin,
                            format!("ACAO mirrors attacker origin ({}) without credentials flag", origin),
                            "cors/mirror",
                        )
                        .with_confidence(0.80),
                    );
                } else if is_null {
                    findings.push(
                        Finding::new(
                            ctx.scan_id,
                            VulnerabilityClass::CorsMisconfiguration,
                            Severity::High,
                            &ctx.url,
                            "Origin",
                            "null",
                            "ACAO: null — exploitable via sandboxed iframe",
                            "cors/null-origin",
                        )
                        .with_confidence(0.85),
                    );
                } else if is_wildcard && acac.to_lowercase() == "true" {
                    findings.push(
                        Finding::new(
                            ctx.scan_id,
                            VulnerabilityClass::CorsMisconfiguration,
                            Severity::High,
                            &ctx.url,
                            "Origin",
                            "*",
                            "ACAO: * with ACAC: true — browser will reject but config is broken",
                            "cors/wildcard-credentials",
                        )
                        .with_confidence(0.70),
                    );
                }
            }

            if !findings.is_empty() { break; }
        }

        findings
    }
}
