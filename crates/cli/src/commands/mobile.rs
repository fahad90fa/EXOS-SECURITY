use anyhow::Result;
use nexus_mobile::analyze_apk;

pub async fn analyze(apk: String) -> Result<()> {
    let report = analyze_apk(&apk)?;

    println!("Mobile analysis: {}", report.file_path);
    println!("Package: {}", report.package_name.as_deref().unwrap_or("<unknown>"));
    println!("Files: {}", report.file_count);
    println!("Risk score: {}", report.risk_score());
    println!("Findings: {}", report.findings.len());

    for finding in &report.findings {
        println!(
            "- [{}] {}: {}",
            format!("{:?}", finding.severity),
            finding.id,
            finding.title
        );
    }

    Ok(())
}

pub async fn report(apk: String) -> Result<()> {
    let report = analyze_apk(&apk)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
