//! Observability stack (wp25) — structured request tracing, correlation IDs, Prometheus metrics,
//! and the liveness/readiness probes.
//!
//! This module owns the cross-cutting operational surface the prod-readiness audit found missing:
//!
//! - [`observe`] — the outermost router middleware. It assigns/propagates a request-correlation id
//!   (`x-request-id`), opens a `tracing` span carrying `method`/`route`/`request_id`, times the
//!   request, records HTTP metrics (count + latency histogram + in-flight gauge), logs a single
//!   structured completion event, and echoes the id back in the response header. It deliberately
//!   logs **only** method / matched route template / status / latency / request-id — never raw URL
//!   paths, auth headers, session tokens, cookies, or bodies.
//! - [`metrics_endpoint`] — `GET /metrics`, Prometheus text exposition. Refreshes a few cheap app
//!   gauges (ledger length, degraded 0/1, cluster follower lag) from live state on each scrape,
//!   reusing exactly what `/health` already computes, then renders the recorder. It is
//!   unauthenticated for scraper compatibility and must be kept on an internal network or behind an
//!   allowlist; it is not safe to publish directly to the public internet.
//! - [`livez`] / [`readyz`] — the Kubernetes-style probe split. `readyz` is deliberately narrow: it
//!   reports only the degraded read-only integrity mode, not full dependency readiness.
//!
//! `/health` is intentionally left untouched: it stays the rich, backward-compatible cluster-LB
//! signal. `/livez` and `/readyz` are the cheap orchestrator probes layered beside it.

use std::sync::OnceLock;
use std::time::Instant;

use axum::extract::{MatchedPath, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use metrics::{counter, gauge, histogram};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use tracing::{Instrument, info_span};
use uuid::Uuid;

use crate::AppState;

/// The correlation-id request/response header. A caller (or an upstream proxy / API gateway) may set
/// it; we honour a sane inbound value and otherwise mint a fresh UUIDv4 so every request is traceable
/// end-to-end.
const REQUEST_ID_HEADER: &str = "x-request-id";

/// Latency histogram buckets (seconds). Chosen to straddle the range from a fast in-memory read
/// (single-digit ms) to a slow signing / export round-trip (multiple seconds).
const LATENCY_BUCKETS_SECONDS: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// The process-wide Prometheus handle. Installed once (idempotent across the many `router()` builds a
/// test binary performs) via [`install_recorder`]; the `/metrics` handler renders from it.
static PROMETHEUS: OnceLock<PrometheusHandle> = OnceLock::new();

/// Install the global Prometheus recorder (once) and return the handle used to render `/metrics`.
///
/// Idempotent: guarded by a [`OnceLock`], so building the router repeatedly — as the test suite does —
/// installs exactly one recorder per process. Must be called while assembling the router so the global
/// recorder exists before any request records a metric (the `metrics::*!` macros are silent no-ops
/// until a recorder is installed).
pub(crate) fn install_recorder() -> &'static PrometheusHandle {
    PROMETHEUS.get_or_init(|| {
        PrometheusBuilder::new()
            .set_buckets(LATENCY_BUCKETS_SECONDS)
            .expect("static latency buckets are non-empty")
            .install_recorder()
            .expect("no other global metrics recorder is installed in this process")
    })
}

/// Whether an inbound `x-request-id` is safe to adopt and echo back verbatim: non-empty, bounded in
/// length (no unbounded log/label growth), and printable ASCII only (a valid, injection-free header
/// value). Anything else is ignored in favour of a freshly minted id.
fn is_acceptable_request_id(candidate: &str) -> bool {
    !candidate.is_empty()
        && candidate.len() <= 200
        && candidate.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

/// Return a bounded Prometheus label for an HTTP method.
///
/// HTTP allows extension methods, so using the raw method token as a metric label would let a
/// remote client create an unbounded number of retained Prometheus time series. Keep the common
/// standard methods as distinct labels for operational usefulness and collapse every extension or
/// uncommon method into `OTHER`.
fn metric_method_label(method: &Method) -> &'static str {
    match *method {
        Method::GET => "GET",
        Method::POST => "POST",
        Method::PUT => "PUT",
        Method::DELETE => "DELETE",
        Method::PATCH => "PATCH",
        Method::HEAD => "HEAD",
        Method::OPTIONS => "OPTIONS",
        Method::TRACE => "TRACE",
        Method::CONNECT => "CONNECT",
        _ => "OTHER",
    }
}

/// Resolve the correlation id for a request: honour a sane inbound `x-request-id`, else mint a UUIDv4.
fn resolve_request_id(headers: &axum::http::HeaderMap) -> String {
    headers
        .get(REQUEST_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| is_acceptable_request_id(s))
        .map(str::to_owned)
        .unwrap_or_else(|| Uuid::new_v4().to_string())
}

/// **Outermost router middleware (wp25).** Correlation id + tracing span + HTTP metrics for every
/// request the router serves.
///
/// Flow: resolve the request id → open an `http_request` span (`method`, `route`, `request_id`) →
/// increment the in-flight gauge → run the handler inside the span → record count + latency, log one
/// structured completion event, echo the id in the response header.
///
/// Metrics are labelled by a bounded HTTP method bucket and the **matched route template**
/// (e.g. `/v1/acts/{id}`), never the raw path, so attacker-controlled methods and path parameters
/// cannot explode label cardinality. Privacy: nothing but method bucket / path template / status /
/// latency / request-id is ever recorded — no auth headers, tokens, cookies, or bodies.
pub(crate) async fn observe(
    request: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Response {
    let start = Instant::now();
    let method = request.method().clone();
    let route_label = request
        .extensions()
        .get::<MatchedPath>()
        .map(|m| m.as_str().to_owned())
        .unwrap_or_else(|| "<unmatched>".to_owned());
    let request_id = resolve_request_id(request.headers());

    let span = info_span!(
        "http_request",
        method = %method,
        route = %route_label,
        request_id = %request_id,
    );

    let method_label = metric_method_label(&method);
    gauge!("http_requests_in_flight").increment(1.0);

    let mut response = next.run(request).instrument(span.clone()).await;

    gauge!("http_requests_in_flight").decrement(1.0);

    let status = response.status();
    let latency = start.elapsed();
    let status_label = status.as_u16().to_string();

    counter!(
        "http_requests_total",
        "method" => method_label,
        "path" => route_label.clone(),
        "status" => status_label.clone(),
    )
    .increment(1);
    histogram!(
        "http_request_duration_seconds",
        "method" => method_label,
        "path" => route_label,
        "status" => status_label,
    )
    .record(latency.as_secs_f64());

    span.in_scope(|| {
        tracing::info!(
            status = status.as_u16(),
            latency_ms = latency.as_millis() as u64,
            "request completed"
        );
    });

    // Echo the correlation id so a caller (and the aggregator) can stitch the response to its logs.
    // `request_id` is validated printable ASCII, so this parse cannot fail; fall back defensively.
    let header_value =
        HeaderValue::from_str(&request_id).unwrap_or_else(|_| HeaderValue::from_static("invalid"));
    response
        .headers_mut()
        .insert(REQUEST_ID_HEADER, header_value);

    response
}

/// `GET /metrics` — Prometheus text exposition (v0.0.4).
///
/// Refreshes a few cheap application gauges from live state on every scrape — reusing exactly the
/// signals `/health` already computes (ledger length, degraded flag, cluster follower lag) — then
/// renders the recorder. Classified `Exempt` (unauthenticated) like `/health`; operators must scrape
/// it only on an internal network or behind a reverse-proxy/network allowlist, never as a public
/// internet endpoint.
pub(crate) async fn metrics_endpoint(State(state): State<AppState>) -> Response {
    let handle = install_recorder();

    // App gauges (cheap, reused from /health).
    let ledger_length = state.ledger.read().await.len() as f64;
    let degraded = *state.degraded.read().await;
    gauge!("chancela_ledger_length").set(ledger_length);
    gauge!("chancela_degraded").set(if degraded { 1.0 } else { 0.0 });
    if let Some(lag) = state.cluster_read_lag().await
        && let Some(events_behind) = lag.lag
    {
        gauge!("chancela_cluster_follower_lag_events").set(events_behind as f64);
    }

    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        handle.render(),
    )
        .into_response()
}

/// `GET /livez` — **liveness**. Cheap and dependency-free: if the process can service this handler it
/// is alive, so it always returns `200`. A failing liveness probe tells an orchestrator to *restart*
/// the process, so it must never depend on downstream state (store, cluster).
pub(crate) async fn livez() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

/// `GET /readyz` — **readiness**, narrowly scoped to degraded read-only mode.
///
/// Returns `503` when the instance is in the fail-closed degraded (read-only) mode — a broken
/// integrity chain that gates mutations — so a load balancer sheds it until an operator restores /
/// re-anchors. Otherwise `200`. This is not a full dependency readiness probe: it does not poll the
/// database, Redis, remote signing providers, trust-list endpoints, or cluster peers. Unlike `/livez`
/// a `503` here means "don't route to me", not "restart me". `/health` remains the richer,
/// backward-compatible cluster signal.
pub(crate) async fn readyz(State(state): State<AppState>) -> impl IntoResponse {
    let degraded = *state.degraded.read().await;
    if degraded {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "not ready: degraded read-only mode (integrity chain broken)",
        )
    } else {
        (StatusCode::OK, "ready")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metric_method_label_preserves_common_methods() {
        assert_eq!(metric_method_label(&Method::GET), "GET");
        assert_eq!(metric_method_label(&Method::POST), "POST");
        assert_eq!(metric_method_label(&Method::PUT), "PUT");
        assert_eq!(metric_method_label(&Method::DELETE), "DELETE");
        assert_eq!(metric_method_label(&Method::PATCH), "PATCH");
        assert_eq!(metric_method_label(&Method::HEAD), "HEAD");
        assert_eq!(metric_method_label(&Method::OPTIONS), "OPTIONS");
        assert_eq!(metric_method_label(&Method::TRACE), "TRACE");
        assert_eq!(metric_method_label(&Method::CONNECT), "CONNECT");
    }

    #[test]
    fn metric_method_label_collapses_extension_methods() {
        let first = Method::from_bytes(b"M000001").expect("valid extension method");
        let second = Method::from_bytes(b"M000002").expect("valid extension method");

        assert_eq!(metric_method_label(&first), "OTHER");
        assert_eq!(metric_method_label(&second), "OTHER");
    }
}
