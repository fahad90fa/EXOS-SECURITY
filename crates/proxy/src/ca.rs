//! Certificate Authority for MITM TLS interception.
//! Generates a self-signed root CA at startup, then dynamically issues
//! per-hostname leaf certificates signed by that CA.

use anyhow::{Context, Result};
use dashmap::DashMap;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose,
    IsCa, KeyPair, SanType,
};
use std::sync::Arc;
use tokio_rustls::rustls::{
    self,
    server::AllowAnyAuthenticatedClient,
    Certificate as RustlsCert,
    PrivateKey as RustlsKey,
    ServerConfig,
};
use tracing::{debug, info};

// ─── CertificateAuthority ────────────────────────────────────────────────────

pub struct CertificateAuthority {
    ca_cert:     Certificate,
    ca_cert_der: Vec<u8>,
    ca_key_pair: KeyPair,
    /// Cache of already-generated ServerConfigs, keyed by hostname.
    cache: DashMap<String, Arc<ServerConfig>>,
}

impl CertificateAuthority {
    /// Create a fresh in-memory CA.
    pub fn new() -> Result<Self> {
        info!("Generating Nexus Sentinel CA certificate…");

        let ca_key_pair = KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256)
            .context("Generate CA key pair")?;

        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.distinguished_name.push(DnType::CommonName,        "Nexus Sentinel CA");
        params.distinguished_name.push(DnType::OrganizationName,  "Nexus Sentinel Security");
        params.distinguished_name.push(DnType::CountryName,       "US");
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        // Valid for 10 years
        let not_before = rcgen::date_time_ymd(2024, 1, 1);
        let not_after  = rcgen::date_time_ymd(2034, 1, 1);
        params.not_before = not_before;
        params.not_after  = not_after;

        let ca_cert = Certificate::from_params(params)
            .context("Generate CA certificate")?;
        let ca_cert_der = ca_cert.serialize_der()
            .context("Serialize CA cert to DER")?;

        info!("CA certificate generated ({} bytes DER)", ca_cert_der.len());

        Ok(Self {
            ca_cert,
            ca_cert_der,
            ca_key_pair,
            cache: DashMap::new(),
        })
    }

    /// PEM-encoded CA certificate (install in browser/OS trust store).
    pub fn ca_cert_pem(&self) -> Result<String> {
        self.ca_cert.serialize_pem().context("Serialize CA cert PEM")
    }

    /// DER-encoded CA certificate.
    pub fn ca_cert_der(&self) -> &[u8] {
        &self.ca_cert_der
    }

    /// Build (or retrieve from cache) a rustls `ServerConfig` for the given hostname.
    /// The leaf certificate is signed by our CA.
    pub fn server_config(&self, hostname: &str) -> Result<Arc<ServerConfig>> {
        // Strip port if present
        let host = hostname.split(':').next().unwrap_or(hostname);

        if let Some(cfg) = self.cache.get(host) {
            debug!("TLS cert cache hit for {}", host);
            return Ok(cfg.clone());
        }

        debug!("Generating TLS cert for {}", host);

        // ── Leaf key + cert ──────────────────────────────────────────────
        let leaf_key = KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256)
            .context("Generate leaf key")?;

        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, host);
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        params.subject_alt_names = vec![
            SanType::DnsName(host.to_string()),
        ];

        // Also add wildcard
        if !host.starts_with("*.") {
            let wildcard = format!("*.{}", host);
            params.subject_alt_names.push(SanType::DnsName(wildcard));
        }

        let not_before = rcgen::date_time_ymd(2024, 1, 1);
        let not_after  = rcgen::date_time_ymd(2026, 1, 1);
        params.not_before = not_before;
        params.not_after  = not_after;

        let leaf_cert = Certificate::from_params(params)
            .context("Generate leaf cert params")?;

        // Sign with CA
        let leaf_cert_der = leaf_cert
            .serialize_der_with_signer(&self.ca_cert)
            .context("Sign leaf cert with CA")?;
        let leaf_key_der = leaf_key.serialize_der();

        // ── Build rustls ServerConfig ────────────────────────────────────
        let cert_chain = vec![
            RustlsCert(leaf_cert_der),
            RustlsCert(self.ca_cert_der.clone()),
        ];
        let private_key = RustlsKey(leaf_key_der);

        let tls_config = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)
            .context("Build rustls ServerConfig")?;

        let tls_config = Arc::new(tls_config);
        self.cache.insert(host.to_string(), tls_config.clone());

        Ok(tls_config)
    }
}
