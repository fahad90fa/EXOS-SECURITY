use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SecuritySeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFinding {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: SecuritySeverity,
    pub line: Option<usize>,
    pub column: Option<usize>,
    pub recommendation: String,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityReport {
    pub source_name: String,
    pub language: String,
    pub analyzed_at: DateTime<Utc>,
    pub risk_score: u32,
    pub findings: Vec<SecurityFinding>,
}

impl SecurityReport {
    pub fn new(source_name: impl Into<String>, language: impl Into<String>) -> Self {
        Self {
            source_name: source_name.into(),
            language: language.into(),
            analyzed_at: Utc::now(),
            risk_score: 0,
            findings: Vec::new(),
        }
    }

    pub fn push(&mut self, finding: SecurityFinding) {
        self.risk_score = (self.risk_score + severity_weight(&finding.severity)).min(100);
        self.findings.push(finding);
    }
}

pub fn severity_weight(severity: &SecuritySeverity) -> u32 {
    match severity {
        SecuritySeverity::Info => 1,
        SecuritySeverity::Low => 4,
        SecuritySeverity::Medium => 10,
        SecuritySeverity::High => 20,
        SecuritySeverity::Critical => 30,
    }
}

pub(crate) fn finding(
    id: impl Into<String>,
    title: impl Into<String>,
    description: impl Into<String>,
    severity: SecuritySeverity,
    line: Option<usize>,
    recommendation: impl Into<String>,
    evidence: Vec<String>,
) -> SecurityFinding {
    SecurityFinding {
        id: id.into(),
        title: title.into(),
        description: description.into(),
        severity,
        line,
        column: None,
        recommendation: recommendation.into(),
        evidence,
    }
}
