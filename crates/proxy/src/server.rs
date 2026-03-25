//! Main proxy server — accepts TCP connections and dispatches to `ProxyHandler`.

use std::sync::Arc;

use anyhow::Result;
use tokio::net::TcpListener;
use tracing::{error, info};

use crate::{
    ca::CertificateAuthority,
    handler::ProxyHandler,
    intercept::InterceptHandle,
    storage::ProxyStorage,
    types::{ProxyConfig, ProxyEvent},
};

pub struct ProxyServer {
    config:    Arc<ProxyConfig>,
    ca:        Arc<CertificateAuthority>,
    storage:   Arc<ProxyStorage>,
    intercept: Arc<InterceptHandle>,
}

impl ProxyServer {
    pub fn new(config: ProxyConfig) -> Result<Self> {
        let ca        = Arc::new(CertificateAuthority::new()?);
        let storage   = Arc::new(ProxyStorage::new());
        let intercept = Arc::new(InterceptHandle::new());
        Ok(Self {
            config: Arc::new(config),
            ca,
            storage,
            intercept,
        })
    }

    /// Handles a pre-built CA (e.g. loaded from disk).
    pub fn with_ca(mut self, ca: CertificateAuthority) -> Self {
        self.ca = Arc::new(ca);
        self
    }

    pub fn storage(&self) -> Arc<ProxyStorage> {
        self.storage.clone()
    }

    pub fn intercept(&self) -> Arc<InterceptHandle> {
        self.intercept.clone()
    }

    pub fn ca(&self) -> Arc<CertificateAuthority> {
        self.ca.clone()
    }

    /// Start accepting connections.  Runs until the future is dropped.
    pub async fn run(&self) -> Result<()> {
        let addr = format!("{}:{}", self.config.host, self.config.port);
        let listener = TcpListener::bind(&addr).await?;

        let event = ProxyEvent::Started { addr: addr.clone() };
        let _ = self.storage.event_sender().send(event);

        info!("🔍 HyperProxy Core listening on http://{}  (set browser proxy to this address)", addr);
        info!("📜 Install CA cert in your browser/OS to inspect HTTPS traffic");

        loop {
            let (stream, peer) = listener.accept().await?;
            debug_assert!(true); // satisfy lint

            let handler = ProxyHandler {
                config:    self.config.clone(),
                ca:        self.ca.clone(),
                storage:   self.storage.clone(),
                intercept: self.intercept.clone(),
            };

            tokio::spawn(async move {
                if let Err(e) = handler.handle(stream).await {
                    let msg = e.to_string();
                    // Suppress noisy EOF / reset errors
                    if !msg.contains("os error 104")
                        && !msg.contains("connection reset")
                        && !msg.contains("UnexpectedEof")
                    {
                        error!("Proxy connection error from {}: {}", peer, msg);
                    }
                }
            });
        }
    }
}
