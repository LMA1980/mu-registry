//! OpenTelemetry W3C-traced span and audit log middleware for `MuRegist`.
//!
//! Preserves `MuRegist`'s local `DuckDbCatalog` (`catalog.duckdb`) for artifact CAS metadata
//! while streaming `MUOB`-framed `OtelSpanEntry` and `OtelLogEntry` batches for
//! `/api/v1/crates/new`, `/yank`, `/api/v1/bundles/it`, sparse index requests, and
//! `/api/v1/canary/{digest}/{promote,taint}` to `MuObserve` / `MuObserve-collector`.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use axum::{
    extract::{Request, State},
    http::{HeaderName, HeaderValue},
    middleware::Next,
    response::Response,
};
use mu_observable_ipc::{
    encode_log_batch, encode_span_batch, write_frame, DeterministicSecretRedactor, IpcHeader,
    OtelLogEntry, OtelSpanEntry, TraceContext, MSG_TYPE_ARROW_OTEL_LOGS, MSG_TYPE_ARROW_OTEL_SPANS,
};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use crate::api::canary::AppState;

/// Canonical service name emitted on `MuRegist` spans and audit logs.
pub const REGISTRY_SERVICE_NAME: &str = "muregist";

/// Current timestamp in nanoseconds since Unix epoch.
#[must_use]
pub fn now_unix_nano() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

/// Abstract sink receiving OpenTelemetry spans and audit log batches from `MuRegist`.
#[async_trait]
pub trait RegistryTelemetrySink: Send + Sync + fmt::Debug {
    /// Emits a batch of [`OtelSpanEntry`] records.
    async fn emit_spans(&self, spans: Vec<OtelSpanEntry>);

    /// Emits a batch of [`OtelLogEntry`] audit records.
    async fn emit_logs(&self, logs: Vec<OtelLogEntry>);
}

/// Network sink streaming `MUOB`-framed Arrow batches (`MSG_TYPE_ARROW_OTEL_SPANS` and
/// `MSG_TYPE_ARROW_OTEL_LOGS`) to `MuObserve` / `MuObserve-collector` with non-blocking
/// graceful fallback.
#[derive(Debug)]
pub struct MuObserveRegistrySink {
    collector_addr: Option<String>,
    node_id: String,
    sequence: AtomicU64,
    connect_timeout: Duration,
}

impl MuObserveRegistrySink {
    #[must_use]
    pub fn new(collector_addr: Option<String>, node_id: impl Into<String>) -> Self {
        Self {
            collector_addr,
            node_id: node_id.into(),
            sequence: AtomicU64::new(1),
            connect_timeout: Duration::from_millis(500),
        }
    }

    #[must_use]
    pub fn from_env() -> Self {
        let addr = std::env::var("MUOBSERVE_COLLECTOR_ADDR")
            .or_else(|_| std::env::var("MUOBSERVE_ADDR"))
            .ok();
        let node_id = std::env::var("MUREGIST_NODE_ID").unwrap_or_else(|_| "node-a".to_string());
        Self::new(addr, node_id)
    }

    #[must_use]
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    async fn send_frame(&self, msg_type: u16, payload: Vec<u8>) {
        let Some(ref addr) = self.collector_addr else {
            return;
        };
        let seq = self.sequence.fetch_add(1, Ordering::Relaxed);
        let header = IpcHeader::new(msg_type, payload.len() as u32, 0, seq);

        let connect_fut = TcpStream::connect(addr);
        if let Ok(Ok(mut stream)) = tokio::time::timeout(self.connect_timeout, connect_fut).await {
            let _ = write_frame(&mut stream, &header, &payload).await;
        }
    }
}

#[async_trait]
impl RegistryTelemetrySink for MuObserveRegistrySink {
    async fn emit_spans(&self, mut spans: Vec<OtelSpanEntry>) {
        if spans.is_empty() || self.collector_addr.is_none() {
            return;
        }
        let redactor = DeterministicSecretRedactor::new();
        for span in &mut spans {
            span.redact_in_place(&redactor);
        }
        if let Ok(bytes) = encode_span_batch(&spans) {
            self.send_frame(MSG_TYPE_ARROW_OTEL_SPANS, bytes).await;
        }
    }

    async fn emit_logs(&self, mut logs: Vec<OtelLogEntry>) {
        if logs.is_empty() || self.collector_addr.is_none() {
            return;
        }
        let redactor = DeterministicSecretRedactor::new();
        for log in &mut logs {
            log.redact_in_place(&redactor);
        }
        if let Ok(bytes) = encode_log_batch(&logs) {
            self.send_frame(MSG_TYPE_ARROW_OTEL_LOGS, bytes).await;
        }
    }
}

/// In-memory recording sink for deterministic unit and integration testing, with optional
/// forwarding to a live [`MuObserveRegistrySink`].
#[derive(Default)]
pub struct RecordingRegistryTelemetrySink {
    spans: Mutex<Vec<OtelSpanEntry>>,
    logs: Mutex<Vec<OtelLogEntry>>,
    forward_to: Option<Arc<dyn RegistryTelemetrySink>>,
}

impl fmt::Debug for RecordingRegistryTelemetrySink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecordingRegistryTelemetrySink").finish()
    }
}

impl RecordingRegistryTelemetrySink {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_forwarder(mut self, sink: Arc<dyn RegistryTelemetrySink>) -> Self {
        self.forward_to = Some(sink);
        self
    }

    pub async fn recorded_spans(&self) -> Vec<OtelSpanEntry> {
        self.spans.lock().await.clone()
    }

    pub async fn recorded_logs(&self) -> Vec<OtelLogEntry> {
        self.logs.lock().await.clone()
    }
}

#[async_trait]
impl RegistryTelemetrySink for RecordingRegistryTelemetrySink {
    async fn emit_spans(&self, mut spans: Vec<OtelSpanEntry>) {
        let redactor = DeterministicSecretRedactor::new();
        for span in &mut spans {
            span.redact_in_place(&redactor);
        }
        self.spans.lock().await.extend(spans.clone());
        if let Some(ref fwd) = self.forward_to {
            fwd.emit_spans(spans).await;
        }
    }

    async fn emit_logs(&self, mut logs: Vec<OtelLogEntry>) {
        let redactor = DeterministicSecretRedactor::new();
        for log in &mut logs {
            log.redact_in_place(&redactor);
        }
        self.logs.lock().await.extend(logs.clone());
        if let Some(ref fwd) = self.forward_to {
            fwd.emit_logs(logs).await;
        }
    }
}

/// Classifies a request `(method, path)` into its canonical OpenTelemetry `span_name`
/// and optional audit event name (`Some(audit_action)` for mutating audit operations).
#[must_use]
pub fn classify_registry_operation(method: &str, path: &str) -> (String, Option<&'static str>) {
    if path == "/api/v1/crates/new" && method == "PUT" {
        (
            "muregist.cargo.publish".to_string(),
            Some("cargo.crate.publish"),
        )
    } else if path.ends_with("/yank") && method == "DELETE" {
        ("muregist.cargo.yank".to_string(), Some("cargo.crate.yank"))
    } else if path.ends_with("/unyank") && method == "PUT" {
        (
            "muregist.cargo.unyank".to_string(),
            Some("cargo.crate.unyank"),
        )
    } else if path == "/api/v1/bundles/it" && method == "POST" {
        (
            "muregist.canary.bundle.upload".to_string(),
            Some("canary.bundle.upload"),
        )
    } else if path.starts_with("/api/v1/bundles/it/") && method == "GET" {
        ("muregist.canary.bundle.get".to_string(), None)
    } else if path.starts_with("/api/v1/canary/") && path.ends_with("/promote") && method == "POST"
    {
        (
            "muregist.canary.promote".to_string(),
            Some("canary.release.promote"),
        )
    } else if path.starts_with("/api/v1/canary/") && path.ends_with("/taint") && method == "POST" {
        (
            "muregist.canary.taint".to_string(),
            Some("canary.release.taint"),
        )
    } else if path == "/api/v1/canary/status" {
        ("muregist.canary.status".to_string(), None)
    } else if path.starts_with("/index/") {
        ("muregist.cargo.sparse_index".to_string(), None)
    } else if path.starts_with("/api/v1/crates/") && path.ends_with("/download") {
        ("muregist.cargo.download".to_string(), None)
    } else if (path == "/api/v1/packages"
        || path == "/api/v1/console/packages"
        || path == "/api/packages")
        && method == "GET"
    {
        ("muregist.packages.list".to_string(), None)
    } else if path == "/api/v1/registry/crates" && method == "GET" {
        ("muregist.crates.list".to_string(), None)
    } else if (path.starts_with("/api/v1/registry/crates/") || path.starts_with("/api/crates/"))
        && method == "GET"
    {
        ("muregist.crates.detail".to_string(), None)
    } else if (path == "/api/v1/canaries" || path == "/api/v1/console/canaries") && method == "GET"
    {
        ("muregist.canaries.list".to_string(), None)
    } else if path == "/api/v1/registry/bundles" && method == "GET" {
        ("muregist.bundles.list".to_string(), None)
    } else if path == "/api/v1/registry/taints" && method == "GET" {
        ("muregist.taints.list".to_string(), None)
    } else if (path == "/api/v1/cas/status"
        || path == "/api/v1/console/cas"
        || path == "/api/v1/cas/health"
        || path == "/api/cas/status"
        || path == "/api/cas/health")
        && method == "GET"
    {
        ("muregist.cas.status".to_string(), None)
    } else if (path == "/api/v1/registry/overview"
        || path == "/api/overview"
        || path == "/api/v1/overview")
        && method == "GET"
    {
        ("muregist.overview".to_string(), None)
    } else if (path == "/api/v1/registry/events"
        || path == "/api/events"
        || path == "/api/v1/events")
        && method == "GET"
    {
        ("muregist.events.sse".to_string(), None)
    } else {
        (format!("muregist.http.{method}"), None)
    }
}

static REQUEST_SEED_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Axum middleware extracting or generating W3C `traceparent` context and emitting
/// [`OtelSpanEntry`] and [`OtelLogEntry`] audit records to `MuObserve`.
pub async fn registry_telemetry_middleware(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let method = req.method().as_str().to_string();
    let path = req.uri().path().to_string();
    let start_ns = now_unix_nano();

    // Extract artifact_digest from headers, query, or path if present
    let artifact_digest = req
        .headers()
        .get("x-artifact-digest")
        .or_else(|| req.headers().get("x-payload-digest"))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .or_else(|| {
            req.uri().query().and_then(|q| {
                for pair in q.split('&') {
                    if let Some(d) = pair.strip_prefix("digest=") {
                        return Some(d.to_string());
                    }
                }
                None
            })
        })
        .or_else(|| {
            for seg in path.split('/') {
                if seg.starts_with("sha256:") || seg.starts_with("sha256-") {
                    return Some(seg.to_string());
                }
            }
            None
        });

    // Extract W3C traceparent header if valid, otherwise generate a root TraceContext
    let incoming_parent = req
        .headers()
        .get("traceparent")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| TraceContext::parse_traceparent(s).ok());

    let seq = REQUEST_SEED_COUNTER.fetch_add(1, Ordering::Relaxed);
    let (trace_ctx, parent_span_id) = match incoming_parent {
        Some(parent) => {
            let child = parent.next_deterministic_child(seq);
            (child, Some(parent.span_id_hex()))
        }
        None => {
            let root = TraceContext::from_seed(start_ns as u64, seq, seq ^ 0x517c_c1b7, true);
            (root, None)
        }
    };

    let mut response = next.run(req).await;
    let end_ns = now_unix_nano().max(start_ns);
    let duration_ns = (end_ns - start_ns) as u64;
    let status_u16 = response.status().as_u16();
    let is_error = status_u16 >= 400;

    if let Ok(val) = HeaderValue::from_str(&trace_ctx.to_traceparent()) {
        response
            .headers_mut()
            .insert(HeaderName::from_static("traceparent"), val);
    }

    let (span_name, audit_action) = classify_registry_operation(&method, &path);
    let node_id = state.config.node_id.clone();

    let mut attrs = serde_json::json!({
        "http.method": method,
        "http.route": path,
        "http.status_code": status_u16,
    });
    if let Some(ref digest) = artifact_digest {
        attrs["artifact_digest"] = serde_json::Value::String(digest.clone());
    }
    let attrs_json = attrs.to_string();

    let span = OtelSpanEntry {
        trace_id: trace_ctx.trace_id_hex(),
        span_id: trace_ctx.span_id_hex(),
        parent_span_id,
        service_name: REGISTRY_SERVICE_NAME.to_string(),
        node_id: node_id.clone(),
        span_name: span_name.clone(),
        span_kind: "SERVER".to_string(),
        start_time_unix_nano: start_ns,
        end_time_unix_nano: end_ns,
        duration_ns,
        status_code: if is_error { "ERROR" } else { "OK" }.to_string(),
        status_message: if is_error {
            Some(format!("HTTP {status_u16}"))
        } else {
            None
        },
        attributes_json: attrs_json,
    };

    state.config.telemetry_sink.emit_spans(vec![span]).await;

    if let Some(action) = audit_action {
        let (sev_num, sev_txt) = if is_error { (13, "WARN") } else { (9, "INFO") };
        let log_entry = OtelLogEntry {
            timestamp_unix_nano: end_ns,
            trace_id: trace_ctx.trace_id_hex(),
            span_id: trace_ctx.span_id_hex(),
            severity_number: sev_num,
            severity_text: sev_txt.to_string(),
            service_name: REGISTRY_SERVICE_NAME.to_string(),
            node_id,
            body: format!("MuRegist audit event: {action} ({method} {path} -> {status_u16})"),
            attributes_json: serde_json::json!({
                "audit.action": action,
                "http.method": method,
                "http.path": path,
                "http.status_code": status_u16,
                "duration_ns": duration_ns,
            })
            .to_string(),
            job_id: None,
            stage_id: None,
        };
        state.config.telemetry_sink.emit_logs(vec![log_entry]).await;
    }

    response
}
