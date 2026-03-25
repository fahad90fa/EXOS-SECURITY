//! Security response headers checker.

use async_trait::async_trait;
use nexus_core::models::{
    finding::Finding,
    scan::ScanConfig,
    vulnerability::{Severity, VulnerabilityClass},
};

use crate::{
    detectors::{Detector, ScanContext},
    http_client::ScanRequest,
    payloads::{DANGEROUS_HEADERS, REQUIRED_SECURITY_HEADERS},
};

pub struct HeadersDetector;

#[async_trait]
impl Detector for HeadersDetector {
    fn name(&self) -> &'static str { "headers" }
    fn vuln_class(&self) -> VulnerabilityClass { VulnerabilityClass::SecurityMisconfiguration }
    fn is_enabled(&self, _c: &ScanConfig) -> bool { true }

    async fn detect(&self, ctx: &ScanContext) -> Vec<Finding> {
        let req = ScanRequest::get(&ctx.url);
        let resp = match ctx.client.send(req).await {
            Ok(r) => r,
            Err(_) => return vec![],
        };

        let mut findings = Vec::new();

        // Missing security headers
        for (header_name, description) in REQUIRED_SECURITY_HEADERS {
            if resp.header(header_name).is_none() {
                findings.push(
                    Finding::new(
                        ctx.scan_id,
                        VulnerabilityClass::SecurityMisconfiguration,
                        Severity::Low,
                        &ctx.url,
                        header_name,
                        "",
                        *description,
                        "headers/missing",
                    )
                    .with_confidence(1.0),
                );
            }
        }

        // Dangerous info-disclosure headers
        for (header_name, description) in DANGEROUS_HEADERS {
            if let Some(value) = resp.header(header_name) {
                // Only flag if it has a version-like value
                let is_versioned = value.chars().any(|c| c.is_ascii_digit());
                if is_versioned {
                    findings.push(
                        Finding::new(
                            ctx.scan_id,
                            VulnerabilityClass::SensitiveDataExposure,
                            Severity::Info,
                            &ctx.url,
                            header_name,
                            value,
                            format!("{}: `{}: {}`", description, header_name, value),
                            "headers/disclosure",
                        )
                        .with_confidence(0.90),
                    );
                }
            }
        }

        // Check X-Frame-Options value quality
        if let Some(xfo) = resp.header("x-frame-options") {
            let lower = xfo.to_lowercase();
            if !lower.contains("deny") && !lower.contains("sameorigin") {
                findings.push(
                    Finding::new(
                        ctx.scan_id,
                        VulnerabilityClass::SecurityMisconfiguration,
                        Severity::Low,
                        &ctx.url,
                        "x-frame-options",
                        xfo,
                        format!("X-Frame-Options has weak value: {}", xfo),
                        "headers/xfo-weak",
                    )
                    .with_confidence(0.85),
                );
            }
        }

        // HSTS: check max-age is adequate
        if let Some(hsts) = resp.header("strict-transport-security") {
            if let Some(max_age_str) = hsts.split(';').find_map(|p| {
                let p = p.trim();
                p.to_lowercase().starts_with("max-age=").then(|| &p["max-age=".len()..])
            }) {
                let max_age: u64 = max_age_str.parse().unwrap_or(0);
                if max_age < 31_536_000 {
                    findings.push(
                        Finding::new(
                            ctx.scan_id,
                            VulnerabilityClass::SecurityMisconfiguration,
                            Severity::Low,
                            &ctx.url,
                            "strict-transport-security",
                            hsts,
                            format!("HSTS max-age too short: {} (recommend ≥ 31536000)", max_age),
                            "headers/hsts-short",
                        )
                        .with_confidence(0.90),
                    );
                }
            }
        }

        findings
    }
}
