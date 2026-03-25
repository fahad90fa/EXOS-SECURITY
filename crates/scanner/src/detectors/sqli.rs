//! SQL Injection detector — error-based, boolean-blind, time-based.

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
    payloads::{SQLI_BOOL_PAIRS, SQLI_ERROR_PATTERNS, SQLI_ERROR_PAYLOADS, SQLI_TIME_PAYLOADS},
};

pub struct SqlInjectionDetector;

#[async_trait]
impl Detector for SqlInjectionDetector {
    fn name(&self) -> &'static str { "sqli" }
    fn vuln_class(&self) -> VulnerabilityClass { VulnerabilityClass::SqlInjection }
    fn is_enabled(&self, c: &ScanConfig) -> bool { c.include_sqli }

    async fn detect(&self, ctx: &ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        for param in &ctx.parameters {
            if param.location == ParamLocation::Header { continue; }

            // ── Error-based ─────────────────────────────────────────────
            for payload in SQLI_ERROR_PAYLOADS {
                if let Some(f) = self.try_error(ctx, param, payload).await {
                    findings.push(f);
                    break; // one finding per parameter is enough at this stage
                }
            }

            // ── Boolean-based blind ──────────────────────────────────────
            for (true_pl, false_pl) in SQLI_BOOL_PAIRS {
                if let Some(f) = self.try_boolean(ctx, param, true_pl, false_pl).await {
                    findings.push(f);
                    break;
                }
            }

            // ── Time-based blind ─────────────────────────────────────────
            for (payload, threshold_ms) in SQLI_TIME_PAYLOADS {
                if let Some(f) = self.try_time(ctx, param, payload, *threshold_ms).await {
                    findings.push(f);
                    break;
                }
            }
        }

        findings
    }
}

impl SqlInjectionDetector {
    async fn try_error(
        &self,
        ctx: &ScanContext,
        param: &crate::detectors::ScanParam,
        payload: &str,
    ) -> Option<Finding> {
        let req = build_request(ctx, &param.name, payload, &param.location);
        let resp = ctx.client.send(req).await.ok()?;
        let lower = resp.body_lower();

        let matched_pattern = SQLI_ERROR_PATTERNS
            .iter()
            .find(|&&p| lower.contains(p))?;

        debug!("SQLi error-based hit on {} param={} payload={}", ctx.url, param.name, payload);

        Some(
            Finding::new(
                ctx.scan_id,
                VulnerabilityClass::SqlInjection,
                Severity::High,
                &ctx.url,
                &param.name,
                payload,
                format!("DB error pattern found: `{}`", matched_pattern),
                "sqli/error",
            )
            .with_confidence(0.95)
            .with_traffic(
                format!("{} {} payload={}", ctx.method, ctx.url, payload),
                format!("HTTP {} body_snippet=...{matched_pattern}...", resp.status),
            ),
        )
    }

    async fn try_boolean(
        &self,
        ctx: &ScanContext,
        param: &crate::detectors::ScanParam,
        true_pl: &str,
        false_pl: &str,
    ) -> Option<Finding> {
        let r_true  = build_request(ctx, &param.name, true_pl, &param.location);
        let r_false = build_request(ctx, &param.name, false_pl, &param.location);

        let (resp_true, resp_false) = ctx.client.send_pair(r_true, r_false).await.ok()?;

        // Significant body length difference → boolean injection
        let len_true  = resp_true.content_length;
        let len_false = resp_false.content_length;
        let diff = (len_true as i64 - len_false as i64).unsigned_abs() as usize;
        let larger = len_true.max(len_false);

        if larger > 0 && diff * 100 / larger > 20 {
            debug!("SQLi boolean-blind hit on {} param={}", ctx.url, param.name);
            return Some(
                Finding::new(
                    ctx.scan_id,
                    VulnerabilityClass::SqlInjection,
                    Severity::High,
                    &ctx.url,
                    &param.name,
                    true_pl,
                    format!("Response size differs: TRUE={} FALSE={}", len_true, len_false),
                    "sqli/boolean",
                )
                .with_confidence(0.75),
            );
        }

        None
    }

    async fn try_time(
        &self,
        ctx: &ScanContext,
        param: &crate::detectors::ScanParam,
        payload: &str,
        threshold_ms: u64,
    ) -> Option<Finding> {
        let req = build_request(ctx, &param.name, payload, &param.location)
            .with_timeout(threshold_ms + 3000);
        let resp = ctx.client.send(req).await.ok()?;

        if resp.elapsed_ms >= threshold_ms {
            debug!("SQLi time-based hit on {} param={} delay={}ms", ctx.url, param.name, resp.elapsed_ms);
            return Some(
                Finding::new(
                    ctx.scan_id,
                    VulnerabilityClass::SqlInjection,
                    Severity::High,
                    &ctx.url,
                    &param.name,
                    payload,
                    format!("Response delayed {}ms (threshold {}ms)", resp.elapsed_ms, threshold_ms),
                    "sqli/time",
                )
                .with_confidence(0.80),
            );
        }

        None
    }
}

fn build_request(
    ctx: &ScanContext,
    param_name: &str,
    payload: &str,
    location: &ParamLocation,
) -> ScanRequest {
    let url = ctx.url_with_param(param_name, payload);
    let body = ctx.body_with_param(param_name, payload);

    let mut req = ScanRequest {
        method:     ctx.method.clone(),
        url,
        headers:    ctx.headers.clone(),
        body,
        timeout_ms: None,
    };

    if *location == ParamLocation::Header {
        req.headers.insert(param_name.to_string(), payload.to_string());
    }

    req
}
