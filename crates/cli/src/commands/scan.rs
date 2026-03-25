use nexus_scanner::{ScanEngine, ScanEvent};
use nexus_core::models::{ScanConfig, ScanType};
use anyhow::Result;
use tokio::sync::mpsc;
use uuid::Uuid;

pub async fn run(url: String, scan_type: String, format: String, output: Option<String>) -> Result<()> {
    println!("Starting scan of: {}", url);
    println!("Scan type: {}", scan_type);

    let scan_type = match scan_type.as_str() {
        "full" => ScanType::Full,
        "active" => ScanType::Active,
        "passive" => ScanType::Passive,
        "crawl" => ScanType::Crawl,
        "api" => ScanType::Api,
        _ => return Err(anyhow::anyhow!("Invalid scan type: {}", scan_type)),
    };

    let config = ScanConfig {
        scan_type: scan_type.clone(),
        ..Default::default()
    };

    let engine = ScanEngine::new(config)?;
    let (tx, mut rx) = mpsc::channel(100);

    // For demo, we'll scan just this single URL
    let urls = vec![url.clone()];
    let scan_id = Uuid::new_v4();
    let project_id = Uuid::new_v4();

    // Spawn scan task
    let handle = tokio::spawn(async move {
        engine.run(scan_id, project_id, urls, tx).await;
    });

    // Process events
    let mut total_findings = 0;
    let mut processed_urls = 0;
    let mut total_urls = 0;

    while let Some(event) = rx.recv().await {
        match event {
            ScanEvent::UrlStarted { url } => {
                println!("🔍 Scanning: {}", url);
            }
            ScanEvent::UrlFinished { url, findings } => {
                processed_urls += 1;
                total_findings += findings;
                if findings > 0 {
                    println!("✅ Found {} vulnerabilities in: {}", findings, url);
                } else {
                    println!("✅ No issues found in: {}", url);
                }
            }
            ScanEvent::FindingDiscovered(finding) => {
                println!("🚨 [{}] {} in {} (param: {})",
                    finding.severity, finding.class, finding.url, finding.parameter);
            }
            ScanEvent::StatusUpdate { progress_pct, message, .. } => {
                println!("📊 Progress: {:.1}% - {}", progress_pct, message);
            }
            ScanEvent::Finished { total_urls: t, total_findings: f } => {
                total_urls = t;
                total_findings = f;
                break;
            }
            ScanEvent::Error { url, message } => {
                eprintln!("❌ Error scanning {}: {}", url, message);
            }
            _ => {}
        }
    }

    handle.await?;

    println!("\n🎯 Scan Summary:");
    println!("   URLs scanned: {}", total_urls);
    println!("   Vulnerabilities found: {}", total_findings);
    println!("   Scan type: {:?}", scan_type);

    if let Some(output) = output {
        println!("💾 Results would be saved to: {}", output);
    }

    Ok(())
}
