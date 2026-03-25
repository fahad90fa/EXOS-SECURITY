use crate::reporting::RedTeamReport;

pub fn to_markdown(report: &RedTeamReport) -> String {
    let mut md = String::new();
    md.push_str(&format!("# Red Team Report\n\n{}\n\n", report.summary));
    md.push_str(&format!("Risk Score: `{}`\n\n", report.risk_score));
    for step in &report.steps {
        md.push_str(&format!(
            "## {}\n\n- Status: `{:?}`\n- MITRE: `{}`\n",
            step.title,
            step.status,
            step.mitre_technique.as_deref().unwrap_or("unmapped")
        ));
        if !step.evidence.is_empty() {
            md.push_str("\nEvidence:\n");
            for item in &step.evidence {
                md.push_str(&format!("- {}\n", item));
            }
            md.push('\n');
        }
    }
    md
}
