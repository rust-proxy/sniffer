//! Integration tests: drive the proxy with curl and verify TLS fingerprint extraction.
//!
//! Requires `curl` installed on the system.
//!
//! Run: cargo test --test proxy_test -- --nocapture

use sniffer::TlsClientHelloInfo;
use std::process::{Command, Stdio};
use std::time::Duration;
use tokio::sync::mpsc;

// ── helpers ───────────────────────────────────────────────

fn get_free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("failed to bind random port")
        .local_addr()
        .unwrap()
        .port()
}

/// Start the proxy with an event channel.
/// Returns (port, abort_handle, event_rx).
fn start_proxy_with_events() -> (
    u16,
    tokio::task::AbortHandle,
    mpsc::UnboundedReceiver<Option<TlsClientHelloInfo>>,
) {
    let port = get_free_port();
    let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let (tx, rx) = mpsc::unbounded_channel();

    let handle = tokio::spawn(async move {
        let _ = sniffer::run_proxy(addr, Some(tx)).await;
    });

    std::thread::sleep(Duration::from_millis(200));
    (port, handle.abort_handle(), rx)
}

fn curl_via_proxy(proxy_port: u16, url: &str) -> std::process::Output {
    Command::new("curl")
        .args([
            "--proxy",
            &format!("http://127.0.0.1:{proxy_port}"),
            "--connect-timeout",
            "10",
            "--max-time",
            "15",
            "-s",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            url,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("curl command failed")
}

/// Receive an event from the channel, returning `None` on timeout.
async fn recv_event(
    rx: &mut mpsc::UnboundedReceiver<Option<TlsClientHelloInfo>>,
    timeout: Duration,
) -> Option<Option<TlsClientHelloInfo>> {
    tokio::time::timeout(timeout, rx.recv()).await.ok().flatten()
}

// ── tests ─────────────────────────────────────────────────

/// Core test: the proxy parses SNI and JA4 from curl's TLS stream.
#[tokio::test(flavor = "multi_thread")]
async fn test_tls_fingerprint_from_curl() {
    let (port, abort, mut rx) = start_proxy_with_events();

    let output = curl_via_proxy(port, "https://httpbin.org/get?test=1");
    let http_status = String::from_utf8_lossy(&output.stdout);

    // 1. curl receives 200
    assert_eq!(
        http_status.trim(),
        "200",
        "curl should receive 200, got: {http_status}"
    );

    // 2. Receive TLS fingerprint event from channel
    let event = recv_event(&mut rx, Duration::from_secs(5))
        .await
        .expect("timed out waiting for TLS fingerprint event");

    abort.abort();

    let info = event.expect("TLS parse event was None (parse failed)");

    // 3. SNI must match the target domain
    assert_eq!(
        info.sni.as_deref(),
        Some("httpbin.org"),
        "SNI should be httpbin.org, got: {:?}",
        info.sni
    );

    // 4. JA4 fingerprint format check
    assert!(info.ja4.starts_with('t'), "JA4 should start with 't': {}", info.ja4);
    assert!(
        info.ja4.contains('_'),
        "JA4 should contain '_': {}",
        info.ja4
    );
    let parts: Vec<&str> = info.ja4.split('_').collect();
    assert!(parts.len() >= 3, "JA4 should have at least 3 parts: {}", info.ja4);

    // 5. All variants are present and non-empty
    assert!(!info.ja4.is_empty(), "JA4 should not be empty");
    assert!(!info.ja4_r.is_empty(), "JA4_r should not be empty");
    assert!(!info.ja4_o.is_empty(), "JA4_o should not be empty");
    assert!(!info.ja4_s1.is_empty(), "JA4_s1 should not be empty");

    // 6. TLS version should be present
    assert!(!info.tls_version.is_empty(), "TLS version should not be empty");

    // 7. Cipher suites and extensions should have values
    assert!(
        info.cipher_suite_count > 0,
        "should have at least 1 cipher suite"
    );
    assert!(info.extension_count > 0, "should have at least 1 extension");
}

/// Google test: SNI should contain "google".
#[tokio::test(flavor = "multi_thread")]
async fn test_tls_fingerprint_google() {
    let (port, abort, mut rx) = start_proxy_with_events();

    let output = curl_via_proxy(port, "https://www.google.com");
    let http_status = String::from_utf8_lossy(&output.stdout);

    let status: u16 = http_status.trim().parse().expect("invalid status code");
    assert!(
        status == 200 || status == 302 || status == 301,
        "expected 200/302/301, got {status}"
    );

    let event = recv_event(&mut rx, Duration::from_secs(5))
        .await
        .expect("timed out waiting for TLS fingerprint event");

    abort.abort();

    let info = event.expect("TLS parse failed");
    let sni = info.sni.as_deref().unwrap_or("");
    assert!(
        sni.contains("google"),
        "SNI should contain 'google', got: {sni}"
    );
    assert!(!info.ja4.is_empty(), "JA4 should not be empty");
}

/// HTTP (non-CONNECT) requests should not produce TLS events.
#[tokio::test(flavor = "multi_thread")]
async fn test_http_no_tls_event() {
    let (port, abort, mut rx) = start_proxy_with_events();

    let _output = Command::new("curl")
        .args([
            "--proxy",
            &format!("http://127.0.0.1:{port}"),
            "--connect-timeout",
            "5",
            "--max-time",
            "10",
            "-s",
            "-o",
            "/dev/null",
            "http://httpbin.org/get",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("curl command failed");

    abort.abort();

    // HTTP request should not produce a TLS event
    let event = recv_event(&mut rx, Duration::from_secs(2)).await;
    assert!(
        event.is_none(),
        "HTTP request should not produce a TLS event, but got: {event:?}"
    );
}

/// 3 concurrent connections, each returning a valid TLS fingerprint.
#[tokio::test(flavor = "multi_thread")]
async fn test_concurrent_tls_fingerprints() {
    let (port, abort, mut rx) = start_proxy_with_events();

    let urls = [
        "https://httpbin.org/get?req=1",
        "https://httpbin.org/get?req=2",
        "https://httpbin.org/get?req=3",
    ];

    let handles: Vec<_> = urls
        .iter()
        .map(|url| {
            let p = port;
            let u = *url;
            tokio::task::spawn_blocking(move || curl_via_proxy(p, u))
        })
        .collect();

    for handle in handles {
        let output = handle.await.unwrap();
        let status = String::from_utf8_lossy(&output.stdout);
        assert_eq!(status.trim(), "200", "concurrent request should return 200");
    }

    // Collect 3 fingerprint events
    let mut infos = Vec::new();
    for _ in 0..3 {
        if let Some(Some(info)) = recv_event(&mut rx, Duration::from_secs(5)).await {
            infos.push(info);
        }
    }

    abort.abort();

    assert_eq!(infos.len(), 3, "should have 3 fingerprint events, got {}", infos.len());
    for (i, info) in infos.iter().enumerate() {
        assert!(!info.ja4.is_empty(), "request {i}: JA4 is empty");
        assert!(
            info.sni.as_deref() == Some("httpbin.org"),
            "request {i}: SNI should be httpbin.org, got: {:?}",
            info.sni
        );
    }
}
