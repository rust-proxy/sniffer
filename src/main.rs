//! HTTP CONNECT proxy server that intercepts TLS ClientHello and extracts
//! SNI / JA4 fingerprints.
//!
//! Usage:
//!   cargo run -- 127.0.0.1:8080
//!
//! Then test with curl:
//!   curl --proxy http://127.0.0.1:8080 https://httpbin.org/ip -v

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let bind_addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8080".to_string());

    let addr: std::net::SocketAddr = bind_addr.parse()?;
    sniffer::run_proxy(addr, None).await
}
