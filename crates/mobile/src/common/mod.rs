use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AnalysisSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FindingCategory {
    Manifest,
    Permissions,
    Certificate,
    Resources,
    Code,
    Network,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: AnalysisSeverity,
    pub category: FindingCategory,
    pub recommendation: String,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SignatureSchemeStatus {
    pub v1: bool,
    pub v2_or_higher: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AndroidManifestSummary {
    pub package_name: Option<String>,
    pub min_sdk: Option<String>,
    pub target_sdk: Option<String>,
    pub debuggable: bool,
    pub allow_backup: bool,
    pub uses_cleartext_traffic: bool,
    pub network_security_config: Option<String>,
    pub permissions: Vec<String>,
    pub exported_components: Vec<String>,
    pub intent_filters: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ApkAnalysisReport {
    pub file_path: String,
    pub package_name: Option<String>,
    pub file_count: usize,
    pub urls: Vec<String>,
    pub api_endpoints: Vec<String>,
    pub secrets: Vec<String>,
    pub signature: SignatureSchemeStatus,
    pub manifest: AndroidManifestSummary,
    pub findings: Vec<Finding>,
}

impl ApkAnalysisReport {
    pub fn risk_score(&self) -> u32 {
        let mut score = 0;
        for f in &self.findings {
            score += match f.severity {
                AnalysisSeverity::Info => 1,
                AnalysisSeverity::Low => 3,
                AnalysisSeverity::Medium => 8,
                AnalysisSeverity::High => 15,
                AnalysisSeverity::Critical => 25,
            };
        }

        score.min(100)
    }
}

pub(crate) fn finding(
    id: &str,
    title: &str,
    description: &str,
    severity: AnalysisSeverity,
    category: FindingCategory,
    recommendation: &str,
    evidence: Vec<String>,
) -> Finding {
    Finding {
        id: id.to_string(),
        title: title.to_string(),
        description: description.to_string(),
        severity,
        category,
        recommendation: recommendation.to_string(),
        evidence,
    }
}
