//! Upstream proxy support (SOCKS5, HTTP CONNECT chains, Tor).

use anyhow::{bail, Context, Result};
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Connect through an upstream proxy to reach `target_host:target_port`.
pub async fn connect_via_upstream(
    upstream_url: &str,
    target_host: &str,
    target_port: u16,
) -> Result<TcpStream> {
    let url = url::Url::parse(upstream_url).context("Parse upstream proxy URL")?;

    match url.scheme() {
        "http" | "https" => {
            http_connect_tunnel(&url, target_host, target_port).await
        }
        "socks5" => {
            socks5_connect(&url, target_host, target_port).await
        }
        other => bail!("Unsupported upstream proxy scheme: {}", other),
    }
}

async fn http_connect_tunnel(
    proxy: &url::Url,
    target_host: &str,
    target_port: u16,
) -> Result<TcpStream> {
    let proxy_host = proxy.host_str().context("No proxy host")?;
    let proxy_port = proxy.port().unwrap_or(if proxy.scheme() == "https" { 443 } else { 80 });

    let mut stream = TcpStream::connect(format!("{}:{}", proxy_host, proxy_port))
        .await
        .context("Connect to HTTP proxy")?;

    let connect_req = format!(
        "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
        target_host, target_port, target_host, target_port
    );

    stream.write_all(connect_req.as_bytes()).await?;

    // Read response
    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).await?;
    let resp = String::from_utf8_lossy(&buf[..n]);

    if !resp.starts_with("HTTP/1.1 200") && !resp.starts_with("HTTP/1.0 200") {
        bail!("HTTP proxy CONNECT failed: {}", resp.lines().next().unwrap_or(""));
    }

    Ok(stream)
}

async fn socks5_connect(
    proxy: &url::Url,
    target_host: &str,
    target_port: u16,
) -> Result<TcpStream> {
    let proxy_host = proxy.host_str().context("No proxy host")?;
    let proxy_port = proxy.port().unwrap_or(1080);

    let mut stream = TcpStream::connect(format!("{}:{}", proxy_host, proxy_port))
        .await
        .context("Connect to SOCKS5 proxy")?;

    // Greeting: VER=5, NMETHODS=1, METHOD=0 (no auth)
    stream.write_all(&[0x05, 0x01, 0x00]).await?;

    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await?;
    if resp[0] != 0x05 || resp[1] != 0x00 {
        bail!("SOCKS5 auth negotiation failed: {:?}", resp);
    }

    // Request: VER=5, CMD=CONNECT, RSV=0, ATYP=3 (domain), ADDR, PORT
    let host_bytes = target_host.as_bytes();
    let mut req = vec![
        0x05, 0x01, 0x00, 0x03,
        host_bytes.len() as u8,
    ];
    req.extend_from_slice(host_bytes);
    req.push((target_port >> 8) as u8);
    req.push((target_port & 0xFF) as u8);
    stream.write_all(&req).await?;

    // Response header (10 bytes for IPv4)
    let mut resp2 = [0u8; 10];
    stream.read_exact(&mut resp2).await?;
    if resp2[1] != 0x00 {
        bail!("SOCKS5 connect failed, reply code: 0x{:02x}", resp2[1]);
    }

    Ok(stream)
}
