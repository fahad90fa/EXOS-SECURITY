use std::fs;

use anyhow::Result;
use nexus_redteam::{attack_narrative, build_attack_plan, planning::classify_text_findings, reporting::format::to_markdown};

pub async fn plan(findings_path: String) -> Result<()> {
    let raw = fs::read_to_string(&findings_path)?;
    let findings: Vec<nexus_redteam::planning::PlanFinding> = serde_json::from_str(&raw)
        .unwrap_or_else(|_| classify_text_findings(&raw));
    let report = build_attack_plan(&findings);
    println!("{}", to_markdown(&report));
    println!("\nNarrative:\n{}", attack_narrative(&report));
    Ok(())
}
