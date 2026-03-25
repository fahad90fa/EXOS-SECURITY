use regex::Regex;

use crate::common::{
    finding, AnalysisSeverity, ApkAnalysisReport, Finding, FindingCategory,
};

pub fn analyze_resource_indicators(report: &ApkAnalysisReport) -> Vec<Finding> {
    let mut findings = Vec::new();
    let suspicious_secret_re = Regex::new(r"(?i)(api[_-]?key|secret|token|password)").ok();

    if !report.urls.is_empty() {
        findings.push(finding(
            "MOB-RES-001",
            "URLs extracted from resources",
            "The APK contains URL-like strings that should be checked for hardcoded endpoints, staging hosts, or direct backend references.",
            AnalysisSeverity::Low,
            FindingCategory::Resources,
            "Review resource strings for hardcoded environments and rotate any embedded credentials.",
            report.urls.iter().take(10).cloned().collect(),
        ));
    }

    if !report.api_endpoints.is_empty() {
        findings.push(finding(
            "MOB-RES-002",
            "API endpoints discovered",
            "Potential backend endpoints were discovered in the APK resources or embedded text.",
            AnalysisSeverity::Medium,
            FindingCategory::Resources,
            "Check whether endpoints expose internal services, test APIs, or sensitive administrative functions.",
            report.api_endpoints.iter().take(10).cloned().collect(),
        ));
    }

    if !report.secrets.is_empty() {
        findings.push(finding(
            "MOB-RES-003",
            "Hardcoded secret patterns detected",
            "String patterns resembling secrets or credentials were discovered during static resource extraction.",
            AnalysisSeverity::High,
            FindingCategory::Resources,
            "Remove secrets from the app bundle and move all credentials into a secure server-side store or platform keystore.",
            report.secrets.iter().take(10).cloned().collect(),
        ));
    } else if let Some(re) = suspicious_secret_re {
        if report
            .urls
            .iter()
            .chain(report.api_endpoints.iter())
            .any(|value| re.is_match(value))
        {
            findings.push(finding(
                "MOB-RES-004",
                "Sensitive resource labels detected",
                "Some resource strings include secret-like labels that may indicate misplaced configuration values.",
                AnalysisSeverity::Medium,
                FindingCategory::Resources,
                "Inspect resource files for configuration leakage and redact any sensitive labels or values.",
                report
                    .urls
                    .iter()
                    .chain(report.api_endpoints.iter())
                    .filter(|value| re.is_match(value))
                    .take(10)
                    .cloned()
                    .collect(),
            ));
        }
    }

    findings
}
