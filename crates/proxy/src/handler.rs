//! Per-connection handler.
//! – Detects HTTP CONNECT method → TLS MITM tunnel
//! – Regular HTTP → transparent forwarding with inspection

use std::sync::Arc;
use std::time::Instant;

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use hyper::{
    body::to_bytes,
    client::HttpConnector,
    header::{self, HeaderValue},
    Body, Client, Method, Request, Response, StatusCode, Uri,
};
use nexus_core::models::{CapturedRequest, CapturedResponse, HttpMethod};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::{
    ca::CertificateAuthority,
    intercept::InterceptHandle,
    storage::ProxyStorage,
    types::ProxyConfig,
};

// ─── ProxyHandler ─────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct ProxyHandler {
    pub config:    Arc<ProxyConfig>,
    pub ca:        Arc<CertificateAuthority>,
    pub storage:   Arc<ProxyStorage>,
    pub intercept: Arc<InterceptHandle>,
}

impl ProxyHandler {
    pub async fn handle(&self, stream: TcpStream) -> Result<()> {
        // Read the first line to detect CONNECT vs plain HTTP
        let mut buf = [0u8; 8192];
        let n = stream.peek(&mut buf).await.context("peek TCP stream")?;
        if n == 0 {
            return Ok(());
        }

        let first_line = std::str::from_utf8(&buf[..n.min(512)]).unwrap_or("");

        if first_line.starts_with("CONNECT ") {
            self.handle_connect(stream).await
        } else {
            self.handle_plain_http(stream).await
        }
    }

    // ── HTTPS CONNECT ──────────────────────────────────────────────────────

    async fn handle_connect(&self, mut stream: TcpStream) -> Result<()> {
        // Read the full CONNECT request
        let mut raw = Vec::new();
        let mut tmp = [0u8; 4096];
        loop {
            let n = stream.read(&mut tmp).await?;
            raw.extend_from_slice(&tmp[..n]);
            if raw.windows(4).any(|w| w == b"\r\n\r\n") || n == 0 {
                break;
            }
        }

        let req_str = String::from_utf8_lossy(&raw);
        let first_line = req_str.lines().next().unwrap_or("");
        // CONNECT example.com:443 HTTP/1.1
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        if parts.len() < 2 {
            bail!("Invalid CONNECT request: {}", first_line);
        }
        let host_port = parts[1];

        // Send 200 Connection established
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .context("Write 200 CONNECT response")?;

        // Wrap in TLS using our generated cert
        let tls_config = self
            .ca
            .server_config(host_port)
            .context("Generate server TLS config")?;

        let acceptor = TlsAcceptor::from(tls_config);
        let tls_stream = acceptor
            .accept(stream)
            .await
            .context("TLS accept failed")?;

        // Now handle the decrypted HTTPS traffic as plain HTTP
        let (mut reader, mut writer) = tokio::io::split(tls_stream);
        let scheme = "https";
        let host_name = host_port.split(':').next().unwrap_or(host_port);

        // Read the decrypted HTTP request
        let mut raw_req = Vec::new();
        let mut tmp2 = [0u8; 65536];
        let n2 = reader.read(&mut tmp2).await?;
        raw_req.extend_from_slice(&tmp2[..n2]);

        let (captured_req, forwarded_req) = self
            .parse_and_capture_request(&raw_req, scheme, host_name, host_port)
            .await?;

        // Intercept check
        let captured_req = match self.intercept.maybe_intercept(captured_req).await {
            Some(r) => r,
            None => {
                debug!("Request dropped by intercept: {}", forwarded_req.uri());
                return Ok(());
            }
        };

        if self.config.record_traffic {
            self.storage.store_request(captured_req.clone());
        }

        // Forward to upstream over TLS
        let resp = self.forward_request(forwarded_req, true).await?;
        let (captured_resp, raw_resp) = self.capture_response(resp, captured_req.id).await?;

        if self.config.record_traffic {
            self.storage.store_response(captured_req, captured_resp);
        }

        // Send response back to client
        writer.write_all(&raw_resp).await?;
        Ok(())
    }

    // ── Plain HTTP ─────────────────────────────────────────────────────────

    async fn handle_plain_http(&self, mut stream: TcpStream) -> Result<()> {
        let mut raw = Vec::new();
        let mut tmp = [0u8; 65536];
        let n = stream.read(&mut tmp).await?;
        raw.extend_from_slice(&tmp[..n]);

        let (captured_req, forwarded_req) =
            self.parse_and_capture_request(&raw, "http", "", "").await?;

        let captured_req = match self.intercept.maybe_intercept(captured_req).await {
            Some(r) => r,
            None => return Ok(()),
        };

        if self.config.record_traffic {
            self.storage.store_request(captured_req.clone());
        }

        let resp = self.forward_request(forwarded_req, false).await?;
        let (captured_resp, raw_resp) = self.capture_response(resp, captured_req.id).await?;

        if self.config.record_traffic {
            self.storage.store_response(captured_req, captured_resp);
        }

        stream.write_all(&raw_resp).await?;
        Ok(())
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    async fn parse_and_capture_request(
        &self,
        raw: &[u8],
        scheme: &str,
        host_name: &str,
        host_port: &str,
    ) -> Result<(CapturedRequest, Request<Body>)> {
        let raw_str = String::from_utf8_lossy(raw);
        let mut lines = raw_str.lines();
        let req_line = lines.next().unwrap_or("");
        let parts: Vec<&str> = req_line.splitn(3, ' ').collect();
        if parts.len() < 2 {
            bail!("Invalid HTTP request line: {}", req_line);
        }

        let method_str = parts[0];
        let path_query = parts[1];

        // Build full URL
        let url = if path_query.starts_with("http") {
            path_query.to_string()
        } else {
            let host = host_name.to_string();
            let port_suffix = if host_port.contains(':') {
                format!(":{}", host_port.split(':').nth(1).unwrap_or("443"))
            } else {
                String::new()
            };
            format!("{}://{}{}{}", scheme, host, port_suffix, path_query)
        };

        // Parse headers + body
        let mut headers = std::collections::HashMap::new();
        let mut body_start = 0usize;
        let mut i = 0usize;
        for line in raw_str.lines().skip(1) {
            i += line.len() + 2;
            if line.is_empty() {
                body_start = i;
                break;
            }
            if let Some((k, v)) = line.split_once(": ") {
                headers.insert(k.to_lowercase(), v.to_string());
            }
        }

        let body_bytes = if body_start < raw.len() {
            raw[body_start..].to_vec()
        } else {
            Vec::new()
        };

        let mut captured = CapturedRequest::new(HttpMethod::from(method_str), &url);
        captured.headers = headers.clone();
        if !body_bytes.is_empty() {
            captured.body_text = Some(String::from_utf8_lossy(&body_bytes).to_string());
            captured.body = Some(body_bytes.clone());
        }
        captured.extract_parameters();

        // Build hyper Request
        let uri: Uri = url.parse().context("Parse URL as URI")?;
        let mut builder = Request::builder()
            .method(method_str)
            .uri(uri);

        for (k, v) in &headers {
            if k != "proxy-connection" {
                builder = builder.header(k.as_str(), v.as_str());
            }
        }

        let hyper_req = builder
            .body(Body::from(body_bytes))
            .context("Build hyper request")?;

        Ok((captured, hyper_req))
    }

    async fn forward_request(&self, req: Request<Body>, tls: bool) -> Result<Response<Body>> {
        if tls {
            // Use rustls connector
            let mut connector = HttpConnector::new();
            connector.enforce_http(false);
            let https = hyper_rustls::HttpsConnectorBuilder::new()
                .with_native_roots()
                .https_or_http()
                .enable_http1()
                .build();
            let client = Client::builder().build(https);
            client.request(req).await.context("Forward HTTPS request")
        } else {
            let client = Client::new();
            client.request(req).await.context("Forward HTTP request")
        }
    }

    async fn capture_response(
        &self,
        resp: Response<Body>,
        req_id: Uuid,
    ) -> Result<(CapturedResponse, Vec<u8>)> {
        let status = resp.status().as_u16();
        let headers: std::collections::HashMap<String, String> = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();

        let ct = headers.get("content-type").cloned();
        let start = Instant::now();
        let body_bytes = to_bytes(resp.into_body()).await.unwrap_or_default();
        let elapsed = start.elapsed().as_millis() as u64;

        let mut captured = CapturedResponse::new(req_id, status);
        captured.headers        = headers;
        captured.content_type   = ct;
        captured.content_length = Some(body_bytes.len());
        captured.body_text      = Some(String::from_utf8_lossy(&body_bytes).to_string());
        captured.body           = Some(body_bytes.to_vec());
        captured.response_time_ms = elapsed;

        // Reconstruct raw HTTP response
        let mut raw = format!("HTTP/1.1 {}\r\n", status);
        for (k, v) in &captured.headers {
            raw.push_str(&format!("{}: {}\r\n", k, v));
        }
        raw.push_str("\r\n");
        let mut raw_bytes = raw.into_bytes();
        raw_bytes.extend_from_slice(&body_bytes);

        Ok((captured, raw_bytes))
    }
}
