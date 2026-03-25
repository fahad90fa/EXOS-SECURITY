use nexus_proxy::{ProxyConfig, ProxyServer};
use anyhow::Result;
use std::str::FromStr;

pub async fn run(listen: String, upstream: Option<String>, intercept: bool) -> Result<()> {
    println!("Starting Nexus Sentinel Proxy on {}", listen);
    println!("Intercept mode: {}", if intercept { "enabled" } else { "disabled" });

    if let Some(upstream) = &upstream {
        println!("Upstream proxy: {}", upstream);
    }

    // Parse listen address
    let parts: Vec<&str> = listen.split(':').collect();
    let host = parts.get(0).unwrap_or(&"127.0.0.1").to_string();
    let port = parts.get(1)
        .and_then(|p| u16::from_str(p).ok())
        .unwrap_or(8080);

    let config = ProxyConfig {
        host,
        port,
        intercept_mode: intercept,
        upstream_proxy: upstream,
        ..Default::default()
    };

    let server = ProxyServer::new(config)?;
    println!("Proxy server initialized. CA certificate saved to /tmp/nexus-sentinel-ca.pem");

    server.run().await?;

    Ok(())
}
