//! HTTP CONNECT proxy server that intercepts TLS ClientHello and extracts
//! SNI / JA4 fingerprints.

use anyhow::{Context, Result};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Structured TLS fingerprint info emitted via event channel.
#[derive(Debug, Clone)]
pub struct TlsClientHelloInfo {
    pub sni: Option<String>,
    pub alpn: Option<String>,
    pub tls_version: String,
    pub ja4: String,
    pub ja4_r: String,
    pub ja4_o: String,
    pub ja4_s1: String,
    pub cipher_suite_count: usize,
    pub extension_count: usize,
}

pub use self::tls_detect::is_tls_client_hello;

mod tls_detect {
    /// Detect TLS ClientHello traffic from raw byte stream.
    ///
    /// TLS Record format:
    ///   [1 byte ContentType][2 bytes Version][2 bytes Length][payload]
    /// ClientHello requires ContentType == 0x16 (Handshake)
    /// and Version ∈ [0x0300, 0x0304].
    pub fn is_tls_client_hello(data: &[u8]) -> bool {
        if data.len() < 5 {
            return false;
        }
        let content_type = data[0];
        // 0x16 = Handshake
        if content_type != 0x16 {
            return false;
        }
        let version = u16::from_be_bytes([data[1], data[2]]);
        // Valid TLS version range: SSL 3.0 (0x0300) to TLS 1.3 (0x0304)
        (0x0300..=0x0304).contains(&version)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn tls_client_hello_tls13() {
            // TLS 1.3 ClientHello: ContentType=0x16, Version=0x0301, Length=0
            let data = [0x16, 0x03, 0x01, 0x00, 0x00];
            assert!(is_tls_client_hello(&data));
        }

        #[test]
        fn tls_client_hello_tls12() {
            let data = [0x16, 0x03, 0x03, 0x00, 0x00];
            assert!(is_tls_client_hello(&data));
        }

        #[test]
        fn tls_client_hello_ssl30() {
            let data = [0x16, 0x03, 0x00, 0x00, 0x00];
            assert!(is_tls_client_hello(&data));
        }

        #[test]
        fn not_tls_wrong_content_type() {
            // 0x17 = Application Data, not Handshake
            let data = [0x17, 0x03, 0x03, 0x00, 0x00];
            assert!(!is_tls_client_hello(&data));
        }

        #[test]
        fn not_tls_invalid_version() {
            let data = [0x16, 0x04, 0x00, 0x00, 0x00];
            assert!(!is_tls_client_hello(&data));
        }

        #[test]
        fn not_tls_too_short() {
            assert!(!is_tls_client_hello(&[]));
            assert!(!is_tls_client_hello(&[0x16]));
            assert!(!is_tls_client_hello(&[0x16, 0x03, 0x01, 0x00]));
        }

        #[test]
        fn not_tls_http_request() {
            // "GET / HTTP/1.1\r\n" — definitely not TLS
            let data = b"GET / HTTP/1.1\r\n";
            assert!(!is_tls_client_hello(&data[..]));
        }
    }
}

/// Parse TLS ClientHello and return structured info.
pub fn try_parse_client_hello_info(data: &[u8]) -> Result<TlsClientHelloInfo> {
    let sig = huginn_net_tls::parse_tls_client_hello(data)
        .context("failed to parse TLS ClientHello")?;

    let ja4 = sig.generate_ja4();
    let ja4_original = sig.generate_ja4_original();
    let ja4_stable_v1 = sig.generate_ja4_stable_v1();

    Ok(TlsClientHelloInfo {
        sni: sig.sni,
        alpn: sig.alpn,
        tls_version: sig.version.to_string(),
        ja4: ja4.full.value().to_string(),
        ja4_r: ja4.raw.value().to_string(),
        ja4_o: ja4_original.full.value().to_string(),
        ja4_s1: ja4_stable_v1.full.value().to_string(),
        cipher_suite_count: sig.cipher_suites.len(),
        extension_count: sig.extensions.len(),
    })
}

/// Parse TLS ClientHello and return a human-readable summary string.
pub fn try_parse_client_hello(data: &[u8]) -> Result<String> {
    let info = try_parse_client_hello_info(data)?;
    Ok(format!(
        "  SNI:              {}\n\
          ALPN:             {}\n\
          TLS Version:      {}\n\
          Cipher Suites:    {}\n\
          Extensions:       {}\n\
          JA4 (sorted):     {}\n\
          JA4_r (raw):      {}\n\
          JA4_o (original): {}\n\
          JA4_s1 (stable):  {}\n",
        info.sni.as_deref().unwrap_or("(none)"),
        info.alpn.as_deref().unwrap_or("(none)"),
        info.tls_version,
        info.cipher_suite_count,
        info.extension_count,
        info.ja4,
        info.ja4_r,
        info.ja4_o,
        info.ja4_s1,
    ))
}

/// Start the proxy server. Blocks until the accept loop exits.
///
/// If `events_tx` is provided, each parsed TLS fingerprint is sent as a
/// [`TlsClientHelloInfo`] (or `None` on parse failure).
pub async fn run_proxy(
    bind_addr: SocketAddr,
    events_tx: Option<mpsc::UnboundedSender<Option<TlsClientHelloInfo>>>,
) -> Result<()> {
    let listener = TcpListener::bind(bind_addr)
        .await
        .context(format!("bind {bind_addr} failed"))?;

    info!("HTTP CONNECT proxy listening on {bind_addr}");
    info!("Configure your browser proxy to {bind_addr} to test");

    loop {
        match listener.accept().await {
            Ok((client, addr)) => {
                let tx = events_tx.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(client, addr, tx).await {
                        error!("[{addr}] connection error: {e:#}");
                    }
                });
            }
            Err(e) => {
                // channel closed → graceful shutdown
                if events_tx.is_none() {
                    error!("accept failed: {e}");
                }
                break;
            }
        }
    }
    Ok(())
}

/// Handle a single client connection through the proxy.
async fn handle_connection(
    mut client: TcpStream,
    client_addr: SocketAddr,
    events_tx: Option<mpsc::UnboundedSender<Option<TlsClientHelloInfo>>>,
) -> Result<()> {
    // ---- Step 1: Read CONNECT request ----
    let mut buf = vec![0u8; 8192];
    let n = client
        .read(&mut buf)
        .await
        .context("failed to read CONNECT request")?;
    if n == 0 {
        return Ok(());
    }

    let request = String::from_utf8_lossy(&buf[..n]);
    let (target_host, target_port) =
        parse_connect_request(&request).context("failed to parse CONNECT request")?;

    info!("[{client_addr}] CONNECT {target_host}:{target_port}");

    // ---- Step 2: Connect to target server ----
    let target_addr = format!("{target_host}:{target_port}");
    let mut server = TcpStream::connect(&target_addr)
        .await
        .context(format!("failed to connect to {target_addr}"))?;

    // Respond 200 to tell the client the tunnel is established
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .context("failed to send 200 response")?;

    // ---- Step 3: Sniff TLS ClientHello from client ----
    let remaining = &buf[n..];
    let mut sniffed = Vec::with_capacity(4096);

    if !remaining.is_empty() && is_tls_client_hello(remaining) {
        sniffed.extend_from_slice(remaining);
    }

    while sniffed.len() < 5 || !is_tls_handshake_complete(&sniffed) {
        let mut chunk = vec![0u8; 4096];
        match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.read(&mut chunk),
        )
        .await
        {
            Ok(Ok(0)) => break,
            Ok(Ok(read_n)) => {
                chunk.truncate(read_n);
                sniffed.extend_from_slice(&chunk);
            }
            Ok(Err(e)) => {
                warn!("[{client_addr}] sniff read error: {e}");
                break;
            }
            Err(_) => {
                warn!("[{client_addr}] sniff read timeout");
                break;
            }
        }

        if sniffed.len() < 10 {
            if !is_tls_client_hello(&sniffed) && !sniffed.is_empty() {
                break;
            }
        }
    }

    // ---- Step 4: Parse TLS ClientHello ----
    if !sniffed.is_empty() && is_tls_client_hello(&sniffed) {
        let record_len = u16::from_be_bytes([sniffed[3], sniffed[4]]) as usize;
        debug!(
            "[{client_addr}] TLS ClientHello detected, record_len={record_len}, buffered={} bytes",
            sniffed.len()
        );

        let tls_info = try_parse_client_hello_info(&sniffed);
        match &tls_info {
            Ok(info) => {
                let summary = try_parse_client_hello(&sniffed)
                    .unwrap_or_else(|_| "(summary generation failed)".into());
                info!("[{client_addr}] TLS fingerprint:\n{summary}");
                // Emit event (for tests)
                if let Some(tx) = &events_tx {
                    let _ = tx.send(Some(info.clone()));
                }
            }
            Err(e) => {
                warn!("[{client_addr}] TLS parse error: {e:#}");
                if let Some(tx) = &events_tx {
                    let _ = tx.send(None);
                }
            }
        }
    } else if !sniffed.is_empty() {
        info!(
            "[{client_addr}] non-TLS traffic (first byte 0x{:02x}), forwarding directly",
            sniffed[0]
        );
    } else {
        debug!("[{client_addr}] no data, forwarding directly");
    }

    // ---- Step 5: Bidirectional relay ----
    if !sniffed.is_empty() {
        server
            .write_all(&sniffed)
            .await
            .context("failed to forward sniffed data to target")?;
    }

    relay(client, server).await;
    info!("[{client_addr}] connection closed");
    Ok(())
}

/// Check whether the full TLS record has been received.
fn is_tls_handshake_complete(data: &[u8]) -> bool {
    if data.len() < 5 {
        return false;
    }
    let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    data.len() >= record_len + 5
}

/// Extract host and port from an HTTP CONNECT request line.
pub fn parse_connect_request(request: &str) -> Option<(String, u16)> {
    let first_line = request.lines().next()?;
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 || parts[0].to_uppercase() != "CONNECT" {
        return None;
    }
    let host_port = parts[1];
    let (host, port) = host_port.rsplit_once(':')?;
    let port: u16 = port.parse().ok()?;
    Some((host.to_string(), port))
}

/// Full-duplex byte relay between two TCP streams.
async fn relay(mut a: TcpStream, mut b: TcpStream) {
    let (mut ar, mut aw) = a.split();
    let (mut br, mut bw) = b.split();

    let a_to_b = async {
        let _ = tokio::io::copy(&mut ar, &mut bw).await;
    };
    let b_to_a = async {
        let _ = tokio::io::copy(&mut br, &mut aw).await;
    };

    tokio::join!(a_to_b, b_to_a);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_connect_standard() {
        let req = "CONNECT www.google.com:443 HTTP/1.1\r\nHost: www.google.com:443\r\n\r\n";
        let (host, port) = parse_connect_request(req).unwrap();
        assert_eq!(host, "www.google.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_parse_connect_with_extra_headers() {
        let req =
            "CONNECT api.example.com:8443 HTTP/1.1\r\nProxy-Authorization: Basic xxxx\r\n\r\n";
        let (host, port) = parse_connect_request(req).unwrap();
        assert_eq!(host, "api.example.com");
        assert_eq!(port, 8443);
    }

    #[test]
    fn test_parse_connect_invalid_method() {
        let req = "GET http://example.com HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert!(parse_connect_request(req).is_none());
    }

    #[test]
    fn test_parse_connect_missing_port() {
        let req = "CONNECT example.com HTTP/1.1\r\n\r\n";
        assert!(parse_connect_request(req).is_none());
    }

    #[test]
    fn test_parse_connect_empty() {
        assert!(parse_connect_request("").is_none());
    }

    #[test]
    fn test_is_tls_handshake_complete_exact() {
        // TLS record header says length=0, so 5 bytes is complete
        let data = [0x16, 0x03, 0x01, 0x00, 0x00];
        assert!(is_tls_handshake_complete(&data));
    }

    #[test]
    fn test_is_tls_handshake_complete_not_enough() {
        // Record length 100, but we only have 5 bytes
        let data = [0x16, 0x03, 0x01, 0x00, 0x64]; // 0x0064 = 100
        assert!(!is_tls_handshake_complete(&data));

        // Now with enough data
        let mut full = vec![0x16, 0x03, 0x01, 0x00, 0x02];
        full.extend(vec![0x00; 2]); // 2 bytes payload → total 7 bytes
        assert!(is_tls_handshake_complete(&full));
    }

    #[test]
    fn test_is_tls_handshake_complete_too_short() {
        assert!(!is_tls_handshake_complete(&[]));
        assert!(!is_tls_handshake_complete(&[0x16, 0x03, 0x01, 0x00]));
    }
}
