use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::reporting::{RedTeamReport, RedTeamStep, StepStatus};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanFinding {
    pub class: String,
    pub url: Option<String>,
    pub parameter: Option<String>,
    pub severity: Option<String>,
    pub evidence: Option<String>,
}

pub fn build_attack_plan(findings: &[PlanFinding]) -> RedTeamReport {
    let mut report = RedTeamReport::new("Attack-path planning and validation workflow");
    for (idx, finding) in findings.iter().enumerate() {
        let (title, mitre) = classify(finding);
        report.push_step(RedTeamStep {
            id: format!("step-{:03}", idx + 1),
            title,
            description: format!(
                "Validate the {} issue at {}{}",
                finding.class,
                finding.url.as_deref().unwrap_or("<unknown target>"),
                finding
                    .parameter
                    .as_deref()
                    .map(|p| format!(" parameter {}", p))
                    .unwrap_or_default()
            ),
            status: StepStatus::Planned,
            mitre_technique: mitre,
            evidence: finding
                .evidence
                .iter()
                .map(|e| e.clone())
                .collect::<Vec<_>>(),
        });
    }
    report
}

pub fn attack_narrative(report: &RedTeamReport) -> String {
    let mut narrative = String::new();
    narrative.push_str(&format!("Plan summary: {}\n", report.summary));
    for step in &report.steps {
        narrative.push_str(&format!(
            "- {} [{}]\n",
            step.title,
            step.mitre_technique.as_deref().unwrap_or("unmapped")
        ));
    }
    narrative
}

pub fn mitre_coverage(report: &RedTeamReport) -> Vec<String> {
    report
        .steps
        .iter()
        .filter_map(|step| step.mitre_technique.clone())
        .collect()
}

fn classify(finding: &PlanFinding) -> (String, Option<String>) {
    let class = finding.class.to_lowercase();
    let rule = [
        ("sql", "T1190: Exploit Public-Facing Application"),
        ("xss", "T1059: Command and Scripting Interpreter"),
        ("ssrf", "T1190: Exploit Public-Facing Application"),
        ("auth", "T1110: Brute Force"),
        ("idor", "T1213: Data from Information Repositories"),
        ("sqli", "T1190: Exploit Public-Facing Application"),
    ];

    for (needle, mitre) in rule {
        if class.contains(needle) {
            return (format!("Validate {}", finding.class), Some(mitre.to_string()));
        }
    }

    (
        format!("Review {}", finding.class),
        Some("T1580: Cloud Service Discovery".to_string()),
    )
}

pub fn classify_text_findings(text: &str) -> Vec<PlanFinding> {
    let mut out = Vec::new();
    let patterns = [
        ("sql_injection", r"(?i)sql syntax|union select|database error"),
        ("xss", r"(?i)<script|onerror=|javascript:"),
        ("ssrf", r"(?i)169\.254\.169\.254|metadata|localhost|127\.0\.0\.1"),
        ("auth", r"(?i)token|session|jwt|unauthorized|forbidden"),
    ];

    for (class, pattern) in patterns {
        let re = Regex::new(pattern).unwrap();
        if re.is_match(text) {
            out.push(PlanFinding {
                class: class.to_string(),
                url: None,
                parameter: None,
                severity: Some("medium".to_string()),
                evidence: Some(re.find(text).map(|m| m.as_str().to_string()).unwrap_or_default()),
            });
        }
    }

    out
}
