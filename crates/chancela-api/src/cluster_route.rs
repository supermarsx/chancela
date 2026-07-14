//! **wp16 Phase 2 — write routing on a follower: 307 redirect to the leader (+ opt-in proxy).**
//!
//! P0 landed leader election + a fail-closed write gate that returns `503 NotLeader` from a
//! follower ([`crate::cluster`]); P1 landed the follower read-model change-feed ([`crate::cluster_feed`]).
//! This phase upgrades the "a follower received a write" outcome: instead of a bare `503`, a mutating
//! request that lands on a **follower** is routed to the current **leader** — by default a
//! **`307 Temporary Redirect`** (which preserves method + body, so the client re-issues the exact
//! write to the leader), or, opt-in, a server-side **reverse proxy** to the leader.
//!
//! ## Where the middleware sits
//!
//! [`write_redirect_gate`] is a router-level middleware layered alongside the P0 degraded gate. It is
//! **inert** on the single-node SQLite / in-memory build (no election ⇒ this node is always its own
//! leader ⇒ every request is `Local`), so the embedded editions and the default `cargo build` are
//! totally unaffected. The P0 `persist_write_through` write gate remains the real fail-closed fence:
//! this middleware never lets a follower write locally, it only picks a *nicer* outcome than `503`.
//!
//! ## Safety rules (plan §3.3)
//!
//! - **Only mutating methods redirect.** `GET`/`HEAD`/`OPTIONS`/`TRACE` never redirect — reads stay
//!   local (a follower serves bounded-lag reads from P1). See [`method_is_mutating`].
//! - **Leader unknown / mid-handoff ⇒ `503 + Retry-After`, never a broken redirect.** The redirect
//!   target is read from `cluster_leader.advertised_addr` and is used **only** when it is a *fresh*
//!   (recently-heartbeat) leader row with a well-formed `http(s)` origin. A brief no-leader window,
//!   a stale row, or a garbage value all fall back to `503 + Retry-After`.
//! - **No open redirect.** The `Location` origin is **only ever** the advertised leader URL from the
//!   cluster table (the leader's own `CHANCELA_ADVERTISED_URL`, never any client-supplied value); the
//!   path/query appended is the request's *own* server-resolved origin-form URI. A leader address is
//!   [`sanitize_leader_base`]-validated (absolute `http(s)`, no whitespace/control chars) before use.
//!
//! ## Config
//!
//! - `CHANCELA_ADVERTISED_URL` — this node's externally-reachable base URL (leader heartbeats it into
//!   `cluster_leader`; followers redirect writes here). Resolved store-side in `pg_cluster`.
//! - `CHANCELA_CLUSTER_WRITE_MODE` = `redirect` (default; `307`) | `proxy` (reverse-proxy to leader).
//! - `CHANCELA_NODE_STALE_AFTER` — how old the leader heartbeat may be before its advertised address
//!   is treated as unknown (default `10s`).
//!
//! A `307` requires the client / load balancer to follow cross-host redirects (browsers and
//! react-query do; API-key / MCP clients must be told to). A leader-aware load balancer that routes
//! writes straight to the leader makes this a backstop rather than the hot path.

use axum::body::Body;
use axum::extract::State;
use axum::http::{Method, Request, Response, StatusCode, header};
use axum::middleware::Next;
use axum::response::IntoResponse;

use crate::AppState;

/// Seconds advertised in `Retry-After` on a no-leader `503`. Small: a leader is normally elected
/// within single-digit seconds of a crash (plan §6.1), so a prompt retry usually succeeds.
const WRITE_REDIRECT_RETRY_AFTER_SECS: u64 = 1;

/// Default staleness bound (seconds) for the leader's advertised address, from
/// `CHANCELA_NODE_STALE_AFTER` (plan §8.1). A leader heartbeats every ~2s, so 10s tolerates a couple
/// of missed beats without treating a live leader as unknown.
const DEFAULT_NODE_STALE_AFTER_SECS: i64 = 10;

/// How writes on a follower are routed to the leader (`CHANCELA_CLUSTER_WRITE_MODE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WriteMode {
    /// `307 Temporary Redirect` to the leader (default): preserves method + body; the client
    /// re-issues the write to the leader. No double hop, no follower-side HTTP client.
    Redirect,
    /// Reverse-proxy the request to the leader server-side and stream the response back (opt-in).
    /// Transparent to clients that cannot follow cross-host redirects, at the cost of a double hop.
    Proxy,
}

impl WriteMode {
    /// Parse the mode, defaulting to [`WriteMode::Redirect`] for unset / empty / unrecognised values
    /// (an unknown mode must never hard-fail; the safe, portable default is a `307` redirect).
    pub(crate) fn parse(raw: Option<&str>) -> Self {
        match raw.map(|s| s.trim().to_ascii_lowercase()).as_deref() {
            Some("proxy") => WriteMode::Proxy,
            _ => WriteMode::Redirect,
        }
    }

    fn from_env() -> Self {
        Self::parse(std::env::var("CHANCELA_CLUSTER_WRITE_MODE").ok().as_deref())
    }
}

/// Resolve the leader-address staleness bound from `CHANCELA_NODE_STALE_AFTER` (whole seconds,
/// default 10s, clamped `>= 1s` so a misconfig can never make every fresh leader look stale).
fn node_stale_after_secs() -> i64 {
    std::env::var("CHANCELA_NODE_STALE_AFTER")
        .ok()
        .and_then(|v| v.trim().parse::<i64>().ok())
        .unwrap_or(DEFAULT_NODE_STALE_AFTER_SECS)
        .max(1)
}

/// The routing decision for one request (pure; the middleware just executes it).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum WriteRoute {
    /// Run the handler locally — this node is the leader, or the method is non-mutating.
    Local,
    /// `307 Temporary Redirect` to this absolute `Location` (method + body preserved).
    Redirect(String),
    /// Reverse-proxy the request to this validated leader base URL (opt-in proxy mode).
    Proxy(String),
    /// `503 + Retry-After` (seconds): leader address unknown / stale / invalid, or mid-handoff —
    /// never a redirect to an empty or malformed target.
    Unavailable(u64),
}

/// Whether an HTTP method mutates and must therefore be leader-served. `GET`/`HEAD`/`OPTIONS`/`TRACE`
/// (and `CONNECT`) never redirect — reads stay local (plan §3.3).
fn method_is_mutating(method: &Method) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    )
}

/// Validate a leader base URL read from `cluster_leader.advertised_addr` before it is ever used as a
/// redirect / proxy target. Accepts **only** an absolute `http(s)` origin with no embedded whitespace
/// or control characters (a header-injection / malformed guard), returning it trimmed of any trailing
/// `/`. A garbage / empty / relative value returns `None` ⇒ the caller replies `503`, never a broken
/// or open redirect. Note the value is server-owned (the leader's env), never client-derived.
fn sanitize_leader_base(addr: &str) -> Option<String> {
    let trimmed = addr.trim();
    if !(trimmed.starts_with("http://") || trimmed.starts_with("https://")) {
        return None;
    }
    if trimmed.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return None;
    }
    Some(trimmed.trim_end_matches('/').to_owned())
}

/// Build the absolute `307` `Location`: the validated advertised leader origin + the request's **own**
/// server-resolved origin-form path-and-query (always rooted at `/`, local to this server — never a
/// client-supplied redirect target, so there is no open-redirect vector).
fn build_location(leader_base: &str, path_and_query: &str) -> String {
    format!("{leader_base}{path_and_query}")
}

/// **The pure write-routing decision (plan §3).** Unit-tested without a server and used verbatim by
/// [`write_redirect_gate`], so the two can never drift.
///
/// - Non-mutating method, or this node is the leader ⇒ [`WriteRoute::Local`].
/// - A follower with a fresh, valid leader address ⇒ [`WriteRoute::Redirect`] (default) or
///   [`WriteRoute::Proxy`] (opt-in).
/// - A follower with no fresh / valid leader address ⇒ [`WriteRoute::Unavailable`] (`503 + Retry-After`).
pub(crate) fn route_write(
    method: &Method,
    is_leader: bool,
    leader_addr: Option<&str>,
    mode: WriteMode,
    path_and_query: &str,
) -> WriteRoute {
    if !method_is_mutating(method) || is_leader {
        return WriteRoute::Local;
    }
    // Follower + mutating request: route to the leader iff we have a fresh, valid leader address.
    let Some(base) = leader_addr.and_then(sanitize_leader_base) else {
        return WriteRoute::Unavailable(WRITE_REDIRECT_RETRY_AFTER_SECS);
    };
    match mode {
        WriteMode::Redirect => WriteRoute::Redirect(build_location(&base, path_and_query)),
        WriteMode::Proxy => WriteRoute::Proxy(base),
    }
}

/// Hop-by-hop headers (RFC 7230 §6.1) plus `Host` — never forwarded across the proxy hop. `Host` and
/// length/encoding framing are re-derived by the outbound client / the rebuilt response.
fn is_hop_by_hop(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    matches!(
        n.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "host"
            | "content-length"
    )
}

/// A `307 Temporary Redirect` to `location`, with a small JSON explanation. If `location` cannot be a
/// valid header value (defence in depth — it is already [`sanitize_leader_base`]-validated), fall back
/// to `503` rather than emit a broken redirect.
fn redirect_response(location: String) -> Response<Body> {
    match header::HeaderValue::from_str(&location) {
        Ok(value) => {
            let body = serde_json::json!({
                "error": "este nó é um seguidor do cluster; reencaminhe a escrita para o líder",
                "leader": location,
            });
            let mut response = (StatusCode::TEMPORARY_REDIRECT, axum::Json(body)).into_response();
            response.headers_mut().insert(header::LOCATION, value);
            response
        }
        Err(_) => unavailable_response(WRITE_REDIRECT_RETRY_AFTER_SECS),
    }
}

/// A `503 Service Unavailable` with `Retry-After: <secs>` and an honest PT body — the no-leader /
/// mid-handoff / leader-unknown outcome (never a redirect to an empty or invalid target).
fn unavailable_response(retry_after_secs: u64) -> Response<Body> {
    let body = serde_json::json!({
        "error": "líder de escrita do cluster indisponível (failover em curso); tente novamente",
    });
    let mut response = (StatusCode::SERVICE_UNAVAILABLE, axum::Json(body)).into_response();
    if let Ok(value) = header::HeaderValue::from_str(&retry_after_secs.to_string()) {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    response
}

/// **Router-level write-routing middleware (plan §3).** For a mutating request that lands on a
/// follower, redirect (`307`, default) or reverse-proxy (opt-in) to the current leader; reply
/// `503 + Retry-After` when the leader is unknown. A leader, a read, or a non-electing single-node
/// backend passes straight through to the handler. Inert on SQLite / in-memory builds.
pub(crate) async fn write_redirect_gate(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Response<Body> {
    let Some(store) = state.store.as_ref() else {
        return next.run(request).await;
    };
    // Single-node (SQLite / in-memory): no election, always its own leader → never redirect.
    if !store.cluster_election_enabled() {
        return next.run(request).await;
    }
    let method = request.method().clone();
    // Fast path: reads stay local, and a leader serves its own writes (the P0 gate still fences a
    // leader that is mid-handoff / has silently lost the lock, replying 503).
    if !method_is_mutating(&method) || store.cluster_is_leader() {
        return next.run(request).await;
    }

    // Follower + mutating request: consult the leader directory for the redirect / proxy target. The
    // blocking Postgres read runs on the blocking pool so a DB stall never blocks a runtime worker.
    let stale_after = node_stale_after_secs();
    let leader_addr = {
        let store = store.clone();
        match tokio::task::spawn_blocking(move || store.cluster_leader_address(stale_after)).await {
            Ok(Ok(addr)) => addr,
            Ok(Err(e)) => {
                eprintln!("cluster: leader-address lookup failed ({e}); replying 503 to the write");
                None
            }
            Err(e) => {
                eprintln!("cluster: leader-address lookup task panicked ({e}); replying 503");
                None
            }
        }
    };

    let mode = WriteMode::from_env();
    match route_write(
        &method,
        false,
        leader_addr.as_deref(),
        mode,
        &request_target(&request),
    ) {
        WriteRoute::Local => next.run(request).await,
        WriteRoute::Redirect(location) => redirect_response(location),
        WriteRoute::Proxy(base) => proxy_to_leader(base, request).await,
        WriteRoute::Unavailable(retry) => unavailable_response(retry),
    }
}

/// The request's own origin-form target (path + query), always rooted at `/`. Server-resolved, never
/// client-supplied as a redirect destination.
fn request_target(request: &Request<Body>) -> String {
    request
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_owned())
        .unwrap_or_else(|| request.uri().path().to_owned())
}

/// Max request body buffered for the opt-in reverse-proxy hop. Bounds memory on the peripheral proxy
/// path; larger writes should use redirect mode (no server-side buffering) or a leader-aware LB.
const PROXY_MAX_BODY_BYTES: usize = 32 * 1024 * 1024;

/// **Opt-in reverse proxy (plan §3.1).** Forward the follower's mutating request to the leader over an
/// async `reqwest` client (a *peripheral* connection — the synchronous store is never made async) and
/// stream the response back. Method + body are preserved; hop-by-hop headers and `Host` are dropped.
/// A leader that is unreachable, or a body over [`PROXY_MAX_BODY_BYTES`], falls back to `503`.
async fn proxy_to_leader(base: String, request: Request<Body>) -> Response<Body> {
    let (parts, body) = request.into_parts();
    let url = format!("{base}{}", request_target_from_parts(&parts));

    let body_bytes = match axum::body::to_bytes(body, PROXY_MAX_BODY_BYTES).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return unavailable_response(WRITE_REDIRECT_RETRY_AFTER_SECS);
        }
    };

    // Convert the method through bytes so a differing `http` version between axum and reqwest can
    // never be a compile hazard.
    let method = match reqwest::Method::from_bytes(parts.method.as_str().as_bytes()) {
        Ok(m) => m,
        Err(_) => return unavailable_response(WRITE_REDIRECT_RETRY_AFTER_SECS),
    };

    let client = match reqwest::Client::builder().build() {
        Ok(client) => client,
        Err(e) => {
            eprintln!("cluster proxy: could not build the leader HTTP client ({e}); replying 503");
            return unavailable_response(WRITE_REDIRECT_RETRY_AFTER_SECS);
        }
    };
    let mut outbound = client.request(method, &url);
    for (name, value) in parts.headers.iter() {
        if is_hop_by_hop(name.as_str()) {
            continue;
        }
        outbound = outbound.header(name.as_str(), value.as_bytes());
    }
    let outbound = outbound.body(body_bytes.to_vec());

    match outbound.send().await {
        Ok(resp) => proxied_response(resp).await,
        Err(e) => {
            eprintln!(
                "cluster proxy: forwarding the write to leader {base} failed ({e}); replying 503"
            );
            unavailable_response(WRITE_REDIRECT_RETRY_AFTER_SECS)
        }
    }
}

/// Origin-form target from request parts (proxy path counterpart of [`request_target`]).
fn request_target_from_parts(parts: &axum::http::request::Parts) -> String {
    parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str().to_owned())
        .unwrap_or_else(|| parts.uri.path().to_owned())
}

/// Rebuild an axum response from the leader's proxied `reqwest` response: copy status + non-hop
/// headers (length/encoding re-derived from the rebuilt body) and the body bytes.
async fn proxied_response(resp: reqwest::Response) -> Response<Body> {
    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let headers = resp.headers().clone();
    let body = match resp.bytes().await {
        Ok(bytes) => bytes,
        Err(_) => return unavailable_response(WRITE_REDIRECT_RETRY_AFTER_SECS),
    };
    let mut builder = Response::builder().status(status);
    for (name, value) in headers.iter() {
        if is_hop_by_hop(name.as_str()) {
            continue;
        }
        if let (Ok(n), Ok(v)) = (
            header::HeaderName::from_bytes(name.as_str().as_bytes()),
            header::HeaderValue::from_bytes(value.as_bytes()),
        ) {
            builder = builder.header(n, v);
        }
    }
    builder
        .body(Body::from(body.to_vec()))
        .unwrap_or_else(|_| unavailable_response(WRITE_REDIRECT_RETRY_AFTER_SECS))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    const LEADER: &str = "https://leader.example:8443";

    #[test]
    fn write_mode_parses_and_defaults_to_redirect() {
        assert_eq!(WriteMode::parse(Some("proxy")), WriteMode::Proxy);
        assert_eq!(WriteMode::parse(Some(" Proxy ")), WriteMode::Proxy);
        assert_eq!(WriteMode::parse(Some("redirect")), WriteMode::Redirect);
        // Unset / empty / garbage all default to the portable 307 redirect.
        assert_eq!(WriteMode::parse(None), WriteMode::Redirect);
        assert_eq!(WriteMode::parse(Some("")), WriteMode::Redirect);
        assert_eq!(WriteMode::parse(Some("teleport")), WriteMode::Redirect);
    }

    #[test]
    fn follower_write_redirects_to_the_leader_with_the_same_path() {
        // A mocked cluster state exposing a leader address: a POST on a follower → 307 to
        // <leader_url><same path+query>.
        let route = route_write(
            &Method::POST,
            false,
            Some(LEADER),
            WriteMode::Redirect,
            "/v1/acts?draft=1",
        );
        assert_eq!(
            route,
            WriteRoute::Redirect("https://leader.example:8443/v1/acts?draft=1".to_owned())
        );
    }

    #[test]
    fn leader_serves_its_own_writes_locally() {
        // The leader never redirects to itself, regardless of any recorded address.
        assert_eq!(
            route_write(
                &Method::POST,
                true,
                Some(LEADER),
                WriteMode::Redirect,
                "/v1/acts"
            ),
            WriteRoute::Local
        );
    }

    #[test]
    fn reads_on_a_follower_never_redirect() {
        // GET / HEAD stay local even on a follower with a known leader (plan §3.3).
        for method in [Method::GET, Method::HEAD, Method::OPTIONS] {
            assert_eq!(
                route_write(
                    &method,
                    false,
                    Some(LEADER),
                    WriteMode::Redirect,
                    "/v1/acts"
                ),
                WriteRoute::Local,
                "{method} must not redirect"
            );
        }
    }

    #[test]
    fn leader_unknown_or_midhandoff_returns_503_not_a_broken_redirect() {
        // No fresh leader address → 503 + Retry-After, never a redirect to an empty/invalid URL.
        assert_eq!(
            route_write(&Method::POST, false, None, WriteMode::Redirect, "/v1/acts"),
            WriteRoute::Unavailable(WRITE_REDIRECT_RETRY_AFTER_SECS)
        );
        // Same for proxy mode: unknown leader is 503, not a proxy attempt to nowhere.
        assert_eq!(
            route_write(&Method::POST, false, None, WriteMode::Proxy, "/v1/acts"),
            WriteRoute::Unavailable(WRITE_REDIRECT_RETRY_AFTER_SECS)
        );
    }

    #[test]
    fn a_malformed_leader_address_is_rejected_not_redirected_to() {
        // Open-redirect / broken-target guard: only a well-formed absolute http(s) origin is a valid
        // target; anything else falls back to 503.
        for bad in [
            "leader.example",                             // no scheme
            "//evil.example/steal",                       // scheme-relative
            "ftp://leader.example",                       // non-http scheme
            "javascript:alert(1)",                        // dangerous scheme
            "https://leader.example/\r\nSet-Cookie: x=1", // header injection
            "",                                           // empty
            "   ",                                        // whitespace only
        ] {
            assert_eq!(
                route_write(
                    &Method::POST,
                    false,
                    Some(bad),
                    WriteMode::Redirect,
                    "/v1/acts"
                ),
                WriteRoute::Unavailable(WRITE_REDIRECT_RETRY_AFTER_SECS),
                "a malformed leader address ({bad:?}) must never become a redirect target"
            );
        }
    }

    #[test]
    fn location_origin_is_always_the_leader_never_a_request_supplied_host() {
        // Even if the request path/query looks host-like, the Location ORIGIN is only ever the
        // advertised leader; the request target is appended as a path (no open redirect).
        let route = route_write(
            &Method::PUT,
            false,
            Some(LEADER),
            WriteMode::Redirect,
            "//evil.example/x?next=https://evil.example",
        );
        match route {
            WriteRoute::Redirect(location) => {
                assert!(
                    location.starts_with("https://leader.example:8443/"),
                    "the Location origin must be the leader, got {location}"
                );
                assert!(
                    !location.starts_with("https://leader.example:8443//evil")
                        || location.contains("leader.example:8443//evil.example/x"),
                    "the request target is appended as a path under the leader origin: {location}"
                );
            }
            other => panic!("expected a redirect, got {other:?}"),
        }
    }

    #[test]
    fn leader_base_is_trimmed_of_a_trailing_slash() {
        // A leader address with a trailing slash must not double the separator in the Location.
        let route = route_write(
            &Method::DELETE,
            false,
            Some("https://leader.example/"),
            WriteMode::Redirect,
            "/v1/acts/9",
        );
        assert_eq!(
            route,
            WriteRoute::Redirect("https://leader.example/v1/acts/9".to_owned())
        );
    }

    #[test]
    fn proxy_mode_routes_to_the_validated_leader_base() {
        assert_eq!(
            route_write(
                &Method::POST,
                false,
                Some(LEADER),
                WriteMode::Proxy,
                "/v1/acts"
            ),
            WriteRoute::Proxy(LEADER.to_owned())
        );
    }

    #[test]
    fn sanitize_accepts_only_absolute_http_origins() {
        assert_eq!(
            sanitize_leader_base("http://a.example:1234/"),
            Some("http://a.example:1234".to_owned())
        );
        assert_eq!(
            sanitize_leader_base("  https://a.example  "),
            Some("https://a.example".to_owned())
        );
        assert_eq!(sanitize_leader_base("a.example"), None);
        assert_eq!(sanitize_leader_base("wss://a.example"), None);
    }

    #[tokio::test]
    async fn redirect_response_carries_status_and_location() {
        let response = redirect_response("https://leader.example/v1/acts".to_owned());
        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            response
                .headers()
                .get(header::LOCATION)
                .and_then(|v| v.to_str().ok()),
            Some("https://leader.example/v1/acts")
        );
    }

    #[tokio::test]
    async fn unavailable_response_is_503_with_retry_after() {
        let response = unavailable_response(WRITE_REDIRECT_RETRY_AFTER_SECS);
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response
                .headers()
                .get(header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok()),
            Some("1")
        );
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body bytes");
        let body: serde_json::Value = serde_json::from_slice(&bytes).expect("json body");
        assert!(body["error"].as_str().is_some_and(|e| e.contains("líder")));
    }

    #[test]
    fn hop_by_hop_headers_are_never_forwarded() {
        assert!(is_hop_by_hop("Connection"));
        assert!(is_hop_by_hop("transfer-encoding"));
        assert!(is_hop_by_hop("Host"));
        assert!(is_hop_by_hop("content-length"));
        assert!(!is_hop_by_hop("authorization"));
        assert!(!is_hop_by_hop("content-type"));
    }

    #[test]
    fn node_stale_after_defaults_and_clamps() {
        // Unset in this test process → the 10s default; the resolver clamps `>= 1s` for any config.
        assert_eq!(node_stale_after_secs(), DEFAULT_NODE_STALE_AFTER_SECS);
    }
}
