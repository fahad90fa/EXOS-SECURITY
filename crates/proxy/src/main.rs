use anyhow::Result;
use nexus_proxy::{ProxyConfig, ProxyServer};
use tracing_subscriber::{fmt, EnvFilter};

#[tokio::main]
async fn main() -> Result<()> {
    fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let config = ProxyConfig::default();
    let server = ProxyServer::new(config)?;

    // Print the CA cert so the user can install it
    let ca_pem = server.ca().ca_cert_pem()?;
    let cert_path = "/tmp/nexus-sentinel-ca.pem";
    std::fs::write(cert_path, &ca_pem)?;
    tracing::info!("CA certificate written to {}", cert_path);
    tracing::info!("Import this certificate into your browser/OS trust store to inspect HTTPS");

    server.run().await
}
