use std::{net::SocketAddr, sync::Arc};

use prometheus_client::{
    encoding::{EncodeLabelSet, text::encode},
    metrics::{
        counter::Counter,
        family::Family,
        histogram::{Histogram, exponential_buckets},
    },
    registry::{Registry, Unit},
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpListener,
};

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct TlsLabels {
    pub comm: String,
    pub direction: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct RequestLabels {
    pub comm: String,
    pub host: String,
    pub method: String,
    pub path: String,
    pub status: u16,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct EndpointLabels {
    pub comm: String,
    pub host: String,
    pub path: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct TokenLabels {
    pub comm: String,
    pub host: String,
    pub kind: &'static str,
}

type HistogramFamily<L> = Family<L, Histogram, fn() -> Histogram>;

pub struct Metrics {
    pub tls_bytes: Family<TlsLabels, Counter>,
    pub requests: Family<RequestLabels, Counter>,
    pub response_header: HistogramFamily<EndpointLabels>,
    pub duration: HistogramFamily<EndpointLabels>,
    pub tokens: Family<TokenLabels, Counter>,
    registry: Registry,
}

fn latency_histogram() -> Histogram {
    // 10ms .. ~164s: covers both API round-trips and long streaming generations.
    Histogram::new(exponential_buckets(0.01, 2.0, 15))
}

impl Metrics {
    pub fn new() -> Self {
        let mut registry = Registry::with_prefix("oxtrace");
        let tls_bytes = Family::default();
        let requests = Family::default();
        let response_header = HistogramFamily::new_with_constructor(latency_histogram as fn() -> _);
        let duration = HistogramFamily::new_with_constructor(latency_histogram as fn() -> _);
        let tokens = Family::default();
        registry.register(
            "tls_bytes",
            "Plaintext bytes passed through libssl",
            tls_bytes.clone(),
        );
        registry.register(
            "http_requests",
            "Completed HTTP/1.x exchanges over TLS",
            requests.clone(),
        );
        registry.register_with_unit(
            "http_response_header",
            "Time from request write to response status line (time to first byte)",
            Unit::Seconds,
            response_header.clone(),
        );
        registry.register_with_unit(
            "http_duration",
            "Time from request write to the last response read",
            Unit::Seconds,
            duration.clone(),
        );
        registry.register(
            "llm_tokens",
            "LLM token usage reported in API responses",
            tokens.clone(),
        );
        Self {
            tls_bytes,
            requests,
            response_header,
            duration,
            tokens,
            registry,
        }
    }

    pub fn encode(&self) -> String {
        let mut out = String::new();
        encode(&mut out, &self.registry).expect("writing to a String cannot fail");
        out
    }
}

/// Serves `GET /metrics` in the OpenMetrics text format.
pub async fn serve(addr: SocketAddr, metrics: Arc<Metrics>) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    loop {
        let (mut sock, _) = listener.accept().await?;
        let metrics = metrics.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let n = sock.read(&mut buf).await.unwrap_or(0);
            let (status, body) = if buf[..n].starts_with(b"GET /metrics") {
                ("200 OK", metrics.encode())
            } else {
                ("404 Not Found", String::new())
            };
            let resp = format!(
                "HTTP/1.1 {status}\r\n\
                 Content-Type: application/openmetrics-text; version=1.0.0; charset=utf-8\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = sock.write_all(resp.as_bytes()).await;
        });
    }
}
