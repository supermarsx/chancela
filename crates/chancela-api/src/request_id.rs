//! Per-request correlation id (t58-e2): mint/propagate an `x-request-id`, make it readable from
//! anywhere in the request's async task via [`current`], and splice it into JSON error bodies so a
//! user-facing localised error can be quoted back to an operator and matched to a specific request
//! in the logs (plan `t58.md` §1.2/§3 — "an id present in logs but absent from what the user can
//! quote back is only half the mechanism").
//!
//! ## Relationship to `observability::observe`
//!
//! `observability.rs` already runs a correlation-id middleware (`observe`, wired as the documented
//! **outermost** layer in [`crate::router`]): it resolves an id the same way this module does — honour
//! a sane inbound `x-request-id`, else mint a UUIDv4 — opens a tracing span carrying it, and echoes it
//! on the response header. That covers logs. It does **not** reach the JSON error body, and
//! `error.rs`'s `Internal`/`Upstream` server-side `eprintln!` lines are not id-prefixed — both gaps are
//! this module's job (plan §6, t58-e2).
//!
//! Rather than mint a **second**, independent id (which would desynchronise the id a client reads off
//! the wire from the id attached to the tracing span/logs — exactly the "half the mechanism" failure
//! this exists to close), this module's middleware is layered **outside** `observe` in
//! [`crate::router`] and, when no inbound id is present, writes its freshly minted id onto the
//! *request* headers before calling `next.run(..)`. `observe` then sees that header as if a caller (or
//! upstream proxy) had supplied it and "honours" it verbatim — so both layers agree on exactly one id
//! per request without either needing to know about the other's internals. This module owns minting;
//! `observe` keeps owning tracing/metrics.
//!
//! ## Reaching the error body without touching `error.rs`
//!
//! `error.rs` is `t58-e1`'s exclusive lock for this lane, so this module cannot add a `request_id`
//! field to `ApiError`'s response structs directly. Instead the middleware here inspects the
//! **outgoing** response: for any JSON object body on a 4xx/5xx status, it adds a `request_id` key
//! (skipped if already present, so this is a no-op backstop once/if `error.rs` grows a native field —
//! see the note at the bottom of this file). Non-JSON and non-error responses pass through untouched;
//! nothing here ever buffers a 2xx body, so streamed downloads (PDFs, exports) are unaffected.
//!
//! ## What is deliberately NOT done here
//!
//! `error.rs`'s two `eprintln!` calls for `Internal`/`Upstream` (the scrubbed variants, `error.rs`
//! around line 237/241) still log the full operator detail **without** the request id prefix. Fixing
//! that requires editing `error.rs`, which is out of this lock. [`current`] is exported specifically so
//! that a follow-up inside `error.rs` (by t58-e1, or a later pass) can do it in one line per site, e.g.
//! `eprintln!("chancela-api internal error request_id={}: {msg}", crate::request_id::current()
//! .unwrap_or_default())`. Flagged in the t58-e2 log rather than silently left undone.

use axum::body::Body;
use axum::http::{HeaderValue, header};
use axum::middleware::Next;
use axum::response::Response;
use serde_json::Value;
use uuid::Uuid;

/// The correlation-id header name. Deliberately the same literal `observability.rs` uses
/// (`x-request-id`) so the two layers converge on one header regardless of which runs first;
/// duplicated rather than imported because `observability::REQUEST_ID_HEADER` is private to that
/// module and this lane does not touch `observability.rs`.
const REQUEST_ID_HEADER: &str = "x-request-id";

/// Upper bound on a JSON error body this middleware will buffer to splice `request_id` in.
/// `error.rs`'s bodies are small, in-memory, hand-built `serde_json` structs — never a streamed
/// payload — so this is a defensive ceiling against buffering something unexpected, not a limit
/// expected to ever bind in practice.
const MAX_SPLICED_BODY_BYTES: usize = 8 * 1024 * 1024;

tokio::task_local! {
    /// The current request's correlation id, scoped for the lifetime of the (unspawned) async
    /// task running the handler. Not available outside a request — e.g. in `#[tokio::test]` code
    /// that calls handler logic directly without going through [`propagate_request_id`] — and not
    /// visible across a `tokio::spawn` boundary, which starts a fresh task with no local scope.
    static CURRENT_REQUEST_ID: String;
}

/// Whether an inbound `x-request-id` is safe to adopt and echo back verbatim: non-empty, bounded in
/// length (no unbounded log/label growth), and printable ASCII only (a valid, injection-free header
/// value). Anything else is ignored in favour of a freshly minted id. Mirrors
/// `observability::is_acceptable_request_id` exactly, so the two layers apply the identical
/// acceptance rule to the identical header.
fn is_acceptable_request_id(candidate: &str) -> bool {
    !candidate.is_empty()
        && candidate.len() <= 200
        && candidate.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

/// Resolve the correlation id for a request: honour a sane inbound `x-request-id`, else mint a
/// UUIDv4. Mirrors `observability::resolve_request_id`.
fn resolve_request_id(headers: &axum::http::HeaderMap) -> String {
    headers
        .get(REQUEST_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| is_acceptable_request_id(s))
        .map(str::to_owned)
        .unwrap_or_else(|| Uuid::new_v4().to_string())
}

/// Read the current request's correlation id from anywhere in its (unspawned) async call graph.
/// Returns `None` outside a request scope (e.g. a `#[tokio::test]` calling handler logic directly,
/// or code running after a `tokio::spawn`).
pub fn current() -> Option<String> {
    CURRENT_REQUEST_ID.try_with(String::clone).ok()
}

/// Router middleware (t58-e2): resolve/mint the correlation id, make it readable via [`current`] for
/// the duration of the request, and ensure it reaches a JSON error response body.
///
/// Layered **outside** `observability::observe` in [`crate::router`] (see the module doc) so both
/// converge on one id. Positioned there rather than inside the stack for exactly that reason — moving
/// it would desynchronise the id a client reads from the id attached to the logs.
pub async fn propagate_request_id(mut request: axum::http::Request<Body>, next: Next) -> Response {
    let id = resolve_request_id(request.headers());

    // Seed the request header when absent so `observe` (which runs inside this layer) honours the
    // exact same id instead of minting its own. When the caller already supplied a valid id this is
    // a no-op (the header is already present and unchanged).
    if request.headers().get(REQUEST_ID_HEADER).is_none()
        && let Ok(value) = HeaderValue::from_str(&id)
    {
        request.headers_mut().insert(REQUEST_ID_HEADER, value);
    }

    let response = CURRENT_REQUEST_ID
        .scope(id.clone(), next.run(request))
        .await;

    splice_request_id_into_error_body(response, &id).await
}

/// For a 4xx/5xx JSON-object response body, add a `request_id` key (skipped if already present) so a
/// client-visible error can be quoted back and matched to a specific request in the logs. Every other
/// response — including every 2xx, and any error body that is not a JSON object — passes through
/// unbuffered and unchanged; the `x-request-id` response header is defensively (re-)asserted in all
/// cases, which is idempotent with what `observe` has already set from the same seeded id.
async fn splice_request_id_into_error_body(response: Response, id: &str) -> Response {
    let status = response.status();
    if !(status.is_client_error() || status.is_server_error()) {
        return with_request_id_header(response, id);
    }
    let is_json = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("application/json"));
    if !is_json {
        return with_request_id_header(response, id);
    }

    let (mut parts, body) = response.into_parts();
    let bytes = match axum::body::to_bytes(body, MAX_SPLICED_BODY_BYTES).await {
        Ok(bytes) => bytes,
        // Fail open: cannot recover the original bytes once consumed, but this path is not expected
        // to be reachable for the small in-memory JSON `error.rs` produces. Reject-never-silently-
        // transform is honoured for the ordinary path; this is a defensive last resort, not the norm.
        Err(_) => {
            let response = Response::from_parts(parts, Body::empty());
            return with_request_id_header(response, id);
        }
    };

    let spliced = match serde_json::from_slice::<Value>(&bytes) {
        Ok(Value::Object(mut map)) => {
            map.entry("request_id")
                .or_insert_with(|| Value::String(id.to_owned()));
            serde_json::to_vec(&Value::Object(map)).ok()
        }
        _ => None,
    };

    let body = match spliced {
        Some(new_bytes) => {
            // The byte count changed (a key was added); drop any stale Content-Length so the server
            // recomputes it from the new body rather than truncating/mismatching the response.
            parts.headers.remove(header::CONTENT_LENGTH);
            Body::from(new_bytes)
        }
        // Not a JSON object, or malformed — pass the original bytes through unchanged.
        None => Body::from(bytes),
    };

    with_request_id_header(Response::from_parts(parts, body), id)
}

/// Idempotently ensure the `x-request-id` response header carries `id`. Usually already set by
/// `observability::observe` (which honours the same seeded id) — asserted here too so this module
/// stays correct on its own if the two layers are ever reordered.
fn with_request_id_header(mut response: Response, id: &str) -> Response {
    if let Ok(value) = HeaderValue::from_str(id) {
        response.headers_mut().insert(REQUEST_ID_HEADER, value);
    }
    response
}

#[cfg(test)]
mod tests {
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use axum::routing::get;
    use tower::ServiceExt;

    use super::*;

    fn app() -> Router {
        Router::new()
            .route(
                "/ok",
                get(|| async { (StatusCode::OK, "plain text, not json") }),
            )
            .route(
                "/error",
                get(|| async {
                    (
                        StatusCode::CONFLICT,
                        [(header::CONTENT_TYPE, "application/json")],
                        r#"{"error":"stale facts"}"#,
                    )
                }),
            )
            .route(
                "/error-already-has-id",
                get(|| async {
                    (
                        StatusCode::UNPROCESSABLE_ENTITY,
                        [(header::CONTENT_TYPE, "application/json")],
                        r#"{"error":"bad body","request_id":"caller-supplied"}"#,
                    )
                }),
            )
            .route(
                "/error-not-json",
                get(|| async { (StatusCode::BAD_GATEWAY, "erro de gateway") }),
            )
            .route(
                "/reads-current",
                get(|| async {
                    let id = current().unwrap_or_else(|| "MISSING".to_owned());
                    (StatusCode::OK, id)
                }),
            )
            .layer(axum::middleware::from_fn(propagate_request_id))
    }

    async fn send(request: Request<Body>) -> Response {
        app().oneshot(request).await.expect("infallible service")
    }

    #[tokio::test]
    async fn error_body_gains_request_id_and_keeps_original_error_field() {
        let response = send(Request::get("/error").body(Body::empty()).unwrap()).await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let header_id = response
            .headers()
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .unwrap()
            .to_owned();
        assert!(!header_id.is_empty());

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["error"], "stale facts");
        assert_eq!(
            body["request_id"], header_id,
            "body id must match the header id — one id, both places"
        );
    }

    #[tokio::test]
    async fn already_present_request_id_in_body_is_not_overwritten() {
        let response = send(
            Request::get("/error-already-has-id")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["request_id"], "caller-supplied");
    }

    #[tokio::test]
    async fn ok_response_body_is_never_buffered_or_altered() {
        let response = send(Request::get("/ok").body(Body::empty()).unwrap()).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get("x-request-id").is_some());
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&bytes[..], b"plain text, not json");
    }

    #[tokio::test]
    async fn non_json_error_response_passes_through_unchanged_but_still_gets_the_header() {
        let response = send(Request::get("/error-not-json").body(Body::empty()).unwrap()).await;
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert!(response.headers().get("x-request-id").is_some());
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&bytes[..], b"erro de gateway");
    }

    #[tokio::test]
    async fn inbound_valid_request_id_is_honoured_verbatim() {
        let response = send(
            Request::get("/error")
                .header("x-request-id", "caller-req-42")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(
            response.headers().get("x-request-id").unwrap(),
            "caller-req-42"
        );
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["request_id"], "caller-req-42");
    }

    #[tokio::test]
    async fn current_is_readable_inside_the_request_scope() {
        let response = send(Request::get("/reads-current").body(Body::empty()).unwrap()).await;
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_ne!(&bytes[..], b"MISSING");
    }

    #[test]
    fn acceptance_rule_rejects_empty_oversized_and_non_ascii() {
        assert!(is_acceptable_request_id("abc-123"));
        assert!(!is_acceptable_request_id(""));
        assert!(!is_acceptable_request_id(&"x".repeat(201)));
        assert!(!is_acceptable_request_id("bad\u{0}id"));
    }
}
