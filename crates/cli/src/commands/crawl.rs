use nexus_crawler::{Crawler, CrawlerConfig, CrawlResult};
use anyhow::Result;
use std::collections::HashMap;

pub async fn run(url: String, depth: u32, max_urls: usize, concurrency: usize, format: String) -> Result<()> {
    println!("Starting crawl of: {}", url);
    println!("Depth: {}, Max URLs: {}, Concurrency: {}", depth, max_urls, concurrency);

    let config = CrawlerConfig {
        max_depth: depth,
        max_urls,
        concurrency,
        ..Default::default()
    };

    let crawler = Crawler::new(&url, config)?;
    let result = crawler.crawl(&url).await;

    println!("Crawl completed! Found {} URLs and {} forms", result.urls.len(), result.forms.len());

    match format.as_str() {
        "json" => {
            let output = serde_json::json!({
                "urls": result.urls,
                "forms": result.forms.iter().map(|f| {
                    serde_json::json!({
                        "action": f.action,
                        "method": f.method,
                        "fields": f.fields.iter().map(|field| {
                            serde_json::json!({
                                "name": field.name,
                                "type": field.field_type,
                                "default_value": field.default_value
                            })
                        }).collect::<Vec<_>>()
                    })
                }).collect::<Vec<_>>(),
                "errors": result.errors
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
        "table" => {
            println!("\n📄 Discovered Forms:");
            if result.forms.is_empty() {
                println!("  No forms found");
            } else {
                for (i, form) in result.forms.iter().enumerate() {
                    println!("  {}. {} {} ({} fields)", i + 1, form.method, form.action, form.fields.len());
                    for field in &form.fields {
                        println!("     - {} ({}) = '{}'", field.name, field.field_type, field.default_value);
                    }
                }
            }

            println!("\n🔗 Sample URLs (first 20):");
            for (i, url) in result.urls.iter().take(20).enumerate() {
                println!("  {}. {}", i + 1, url);
            }
            if result.urls.len() > 20 {
                println!("  ... and {} more URLs", result.urls.len() - 20);
            }

            if !result.errors.is_empty() {
                println!("\n⚠️  Errors ({}):", result.errors.len());
                for error in result.errors.iter().take(5) {
                    println!("  - {}", error);
                }
                if result.errors.len() > 5 {
                    println!("  ... and {} more errors", result.errors.len() - 5);
                }
            }
        }
        _ => return Err(anyhow::anyhow!("Invalid format: {}", format)),
    }

    Ok(())
}
