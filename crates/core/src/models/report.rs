//! Intel Nexus — Advanced reporting and intelligence system.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{finding::Finding, vulnerability::Vulnerability, Scan};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub id: Uuid,
    pub project_id: Uuid,
    pub scan_id: Uuid,
    pub title: String,
    pub summary: ReportSummary,
    pub findings: Vec<Vulnerability>,
    pub recommendations: Vec<Recommendation>,
    pub compliance_status: ComplianceStatus,
    pub generated_at: DateTime<Utc>,
    pub format: ReportFormat,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSummary {
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
    pub scan_duration: i64,
    pub coverage_score: f32,
    pub risk_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    pub id: String,
    pub title: String,
    pub description: String,
    pub priority: Priority,
    pub effort: Effort,
    pub category: String,
    pub affected_findings: Vec<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Priority {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Effort {
    Low,
    Medium,
    High,
    VeryHigh,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceStatus {
    pub owasp_top_10: ComplianceScore,
    pub pci_dss: ComplianceScore,
    pub gdpr: ComplianceScore,
    pub hipaa: ComplianceScore,
    pub soc2: ComplianceScore,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceScore {
    pub score: f32,
    pub status: ComplianceLevel,
    pub gaps: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComplianceLevel {
    Compliant,
    Partial,
    NonCompliant,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReportFormat {
    Pdf,
    Html,
    Json,
    Sarif,
    Markdown,
}

impl Report {
    pub fn generate(scan: &Scan, findings: &[Vulnerability]) -> Self {
        let summary = Self::calculate_summary(scan, findings);
        let recommendations = Self::generate_recommendations(findings);
        let compliance = Self::assess_compliance(findings);

        Self {
            id: Uuid::new_v4(),
            project_id: scan.project_id,
            scan_id: scan.id,
            title: format!("Security Scan Report - {}", scan.target_url),
            summary,
            findings: findings.to_vec(),
            recommendations,
            compliance_status: compliance,
            generated_at: Utc::now(),
            format: ReportFormat::Html,
        }
    }

    fn calculate_summary(scan: &Scan, findings: &[Vulnerability]) -> ReportSummary {
        let mut critical = 0;
        let mut high = 0;
        let mut medium = 0;
        let mut low = 0;
        let mut info = 0;

        for finding in findings {
            match finding.severity {
                super::vulnerability::Severity::Critical => critical += 1,
                super::vulnerability::Severity::High => high += 1,
                super::vulnerability::Severity::Medium => medium += 1,
                super::vulnerability::Severity::Low => low += 1,
                super::vulnerability::Severity::Info => info += 1,
            }
        }

        let total = findings.len();
        let risk_score = if total == 0 {
            0.0
        } else {
            (critical as f32 * 10.0 + high as f32 * 7.0 + medium as f32 * 4.0 + low as f32 * 1.0) / total as f32
        };

        ReportSummary {
            total_findings: total,
            critical_count: critical,
            high_count: high,
            medium_count: medium,
            low_count: low,
            info_count: info,
            scan_duration: scan.duration_secs().unwrap_or(0),
            coverage_score: 95.0, // Placeholder - would be calculated based on scan coverage
            risk_score: risk_score.min(10.0),
        }
    }

    fn generate_recommendations(findings: &[Vulnerability]) -> Vec<Recommendation> {
        let mut recommendations = Vec::new();

        // Group findings by vulnerability class
        let mut class_counts = std::collections::HashMap::new();
        for finding in findings {
            *class_counts.entry(&finding.class).or_insert(0) += 1;
        }

        for (class, count) in class_counts {
            let rec = match class {
                super::vulnerability::VulnerabilityClass::SqlInjection => Recommendation {
                    id: format!("sql-injection-{}", Uuid::new_v4().simple()),
                    title: "Implement Parameterized Queries".to_string(),
                    description: format!("Found {} SQL injection vulnerabilities. Use parameterized queries or prepared statements to prevent SQL injection attacks.", count),
                    priority: Priority::Critical,
                    effort: Effort::Medium,
                    category: "Injection".to_string(),
                    affected_findings: findings.iter()
                        .filter(|f| &f.class == class)
                        .map(|f| f.id)
                        .collect(),
                },
                super::vulnerability::VulnerabilityClass::XssReflected => Recommendation {
                    id: format!("xss-{}", Uuid::new_v4().simple()),
                    title: "Implement Output Encoding".to_string(),
                    description: format!("Found {} XSS vulnerabilities. HTML-encode all user-supplied data before rendering in HTML contexts.", count),
                    priority: Priority::High,
                    effort: Effort::Medium,
                    category: "Injection".to_string(),
                    affected_findings: findings.iter()
                        .filter(|f| &f.class == class)
                        .map(|f| f.id)
                        .collect(),
                },
                super::vulnerability::VulnerabilityClass::SecurityMisconfiguration => Recommendation {
                    id: format!("security-headers-{}", Uuid::new_v4().simple()),
                    title: "Add Security Headers".to_string(),
                    description: "Missing security headers detected. Implement HSTS, CSP, X-Frame-Options, and other security headers.".to_string(),
                    priority: Priority::High,
                    effort: Effort::Low,
                    category: "Configuration".to_string(),
                    affected_findings: findings.iter()
                        .filter(|f| &f.class == class)
                        .map(|f| f.id)
                        .collect(),
                },
                _ => continue,
            };
            recommendations.push(rec);
        }

        recommendations
    }

    fn assess_compliance(findings: &[Vulnerability]) -> ComplianceStatus {
        // Simplified compliance assessment
        let owasp_score = Self::calculate_owasp_score(findings);
        let pci_score = Self::calculate_pci_score(findings);

        ComplianceStatus {
            owasp_top_10: ComplianceScore {
                score: owasp_score,
                status: if owasp_score >= 8.0 { ComplianceLevel::Compliant }
                       else if owasp_score >= 5.0 { ComplianceLevel::Partial }
                       else { ComplianceLevel::NonCompliant },
                gaps: vec!["Sample gap analysis".to_string()],
            },
            pci_dss: ComplianceScore {
                score: pci_score,
                status: if pci_score >= 9.0 { ComplianceLevel::Compliant }
                       else if pci_score >= 7.0 { ComplianceLevel::Partial }
                       else { ComplianceLevel::NonCompliant },
                gaps: vec!["PCI compliance gaps".to_string()],
            },
            gdpr: ComplianceScore {
                score: 7.5,
                status: ComplianceLevel::Partial,
                gaps: vec!["Data processing assessment needed".to_string()],
            },
            hipaa: ComplianceScore {
                score: 8.0,
                status: ComplianceLevel::Compliant,
                gaps: vec![],
            },
            soc2: ComplianceScore {
                score: 6.5,
                status: ComplianceLevel::Partial,
                gaps: vec!["Security controls review required".to_string()],
            },
        }
    }

    fn calculate_owasp_score(findings: &[Vulnerability]) -> f32 {
        let injection_count = findings.iter()
            .filter(|f| matches!(f.class, super::vulnerability::VulnerabilityClass::SqlInjection |
                                      super::vulnerability::VulnerabilityClass::CommandInjection |
                                      super::vulnerability::VulnerabilityClass::Xxe))
            .count();

        let xss_count = findings.iter()
            .filter(|f| matches!(f.class, super::vulnerability::VulnerabilityClass::XssReflected |
                                      super::vulnerability::VulnerabilityClass::XssStored |
                                      super::vulnerability::VulnerabilityClass::XssDom))
            .count();

        let auth_count = findings.iter()
            .filter(|f| matches!(f.class, super::vulnerability::VulnerabilityClass::BrokenAuthentication))
            .count();

        let config_count = findings.iter()
            .filter(|f| matches!(f.class, super::vulnerability::VulnerabilityClass::SecurityMisconfiguration))
            .count();

        // Simplified scoring
        let base_score = 10.0;
        let penalty = (injection_count + xss_count + auth_count + config_count) as f32 * 0.5;
        (base_score - penalty).max(0.0)
    }

    fn calculate_pci_score(findings: &[Vulnerability]) -> f32 {
        let pci_relevant = findings.iter()
            .filter(|f| matches!(f.class, super::vulnerability::VulnerabilityClass::SqlInjection |
                                      super::vulnerability::VulnerabilityClass::XssStored |
                                      super::vulnerability::VulnerabilityClass::BrokenAuthentication |
                                      super::vulnerability::VulnerabilityClass::SecurityMisconfiguration))
            .count();

        (10.0 - pci_relevant as f32 * 1.5).max(0.0)
    }
}
