use anyhow::Result;
use nexus_core::models::scan::ScanConfig;
use nexus_scanner::{ScanEngine, ScanEvent};
use tokio::sync::mpsc;
use tracing_subscriber::{fmt, EnvFilter};
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<()> {
    fmt().with_env_filter(EnvFilter::from_default_env()).init();

    let args: Vec<String> = std::env::args().collect();
    let url = args.get(1).cloned().unwrap_or_else(|| "http://testphp.vulnweb.com/".into());

    println!("🔍 Nexus Sentinel Scanner — scanning {}", url);

    let config = ScanConfig::default();
    let engine = ScanEngine::new(config)?;

    let (tx, mut rx) = mpsc::channel(1024);

    let scan_id    = Uuid::new_v4();
    let project_id = Uuid::new_v4();

    tokio::spawn(async move {
        engine.run(scan_id, project_id, vec![url], tx).await;
    });

    let mut findings_count = 0usize;
    while let Some(event) = rx.recv().await {
        match event {
            ScanEvent::FindingDiscovered(f) => {
                findings_count += 1;
                println!("[{}] {:?} in {} (param: {})", f.severity, f.class, f.url, f.parameter);
            }
            ScanEvent::StatusUpdate { message, progress_pct, .. } => {
                println!("[{:.0}%] {}", progress_pct, message);
            }
            ScanEvent::Finished { total_urls, total_findings } => {
                println!("\n✅ Scan complete: {} URLs, {} findings", total_urls, total_findings);
                break;
            }
            _ => {}
        }
    }

    Ok(())
}
