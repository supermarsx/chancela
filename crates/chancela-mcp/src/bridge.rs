//! The API-key bridge: the HTTP client that calls `/api/v1/<...>` on the integration API with the
//! configured key and maps responses/errors honestly.
//!
//! Design (t65 plan §2.4): the MCP server is an **HTTP client of the integration API**, not an
//! in-process link. It **forwards a key** and never re-implements authorization — every tool call
//! is RBAC-gated server-side by the key's principal (t65-E3). This module builds the request,
//! attaches `Authorization: Bearer <key>`, and translates the HTTP status into an honest outcome
//! (including 401/403/429). **The key is never logged and never placed in an error/outcome body.**
//!
//! The transport is abstracted behind [`HttpTransport`] so the whole bridge is unit-testable against
//! a mock (asserting method + path + auth header) without a live server. [`ReqwestTransport`] is the
//! real blocking implementation.

use crate::config::McpConfig;

/// HTTP verbs the tool catalog uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
    Patch,
    Delete,
}

impl HttpMethod {
    /// The uppercase wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Patch => "PATCH",
            HttpMethod::Delete => "DELETE",
        }
    }
}

/// A fully-built outbound HTTP request handed to a [`HttpTransport`]. `headers` already carries the
/// `Authorization` header, so the mock can assert the key was attached.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: HttpMethod,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
}

impl HttpRequest {
    /// Look up a header value (case-insensitive) — convenience for tests.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// A raw HTTP response from the transport.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub body: String,
}

/// The swappable HTTP transport seam.
pub trait HttpTransport {
    /// Send `req` and return the raw response, or a transport-level failure.
    fn send(&self, req: &HttpRequest) -> Result<HttpResponse, BridgeError>;
}

/// A failure calling the integration API. Distinguishes the auth/rate outcomes the MCP layer must
/// surface honestly from a generic transport failure. **No variant carries the API key.**
#[derive(Debug, thiserror::Error)]
pub enum BridgeError {
    /// The transport could not complete the request (connection refused, DNS, timeout, …). The
    /// message is scrubbed of any credential.
    #[error("could not reach the integration API: {0}")]
    Transport(String),

    /// The API returned 401 — the key is missing/invalid/expired/revoked, or integration is off.
    #[error("authentication failed (HTTP 401): the integration API rejected the API key")]
    Unauthorized { body: String },

    /// The API returned 403 — the key's principal lacks the permission this operation requires.
    #[error("permission denied (HTTP 403): the API key is not authorized for this operation")]
    Forbidden { body: String },

    /// The API returned 429 — the per-key rate limit was exceeded.
    #[error("rate limited (HTTP 429): too many requests for this API key")]
    TooManyRequests {
        retry_after: Option<String>,
        body: String,
    },
}

/// The successful (2xx) outcome of a bridged call, or a non-2xx status the tool layer reports as a
/// tool error. `value` is the parsed JSON body when the body is valid JSON, else `None` (the raw
/// text is still in `raw`).
#[derive(Debug, Clone)]
pub struct ApiOutcome {
    pub status: u16,
    pub raw: String,
    pub value: Option<serde_json::Value>,
}

impl ApiOutcome {
    /// Whether the HTTP status is 2xx.
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// The api-key bridge: owns the base URL/path and the key, wraps a [`HttpTransport`].
pub struct ApiBridge<T: HttpTransport> {
    base_url: String,
    base_path: String,
    auth_header: String,
    transport: T,
}

impl<T: HttpTransport> ApiBridge<T> {
    /// Build a bridge from config + a transport. The `Authorization: Bearer <key>` header is
    /// composed once here and held privately; it is never logged.
    pub fn new(config: &McpConfig, transport: T) -> Self {
        Self {
            base_url: config.base_url.trim_end_matches('/').to_string(),
            base_path: normalize_base_path(&config.base_path),
            auth_header: format!("Bearer {}", config.api_key.expose()),
            transport,
        }
    }

    /// Borrow the underlying transport (used by tests to inspect a mock's recorded requests).
    pub fn transport_ref(&self) -> &T {
        &self.transport
    }

    /// Compose the full request for a resolved tool call and return the built [`HttpRequest`]
    /// (without sending it) — used by tests and by [`Self::execute`].
    pub fn build(
        &self,
        method: HttpMethod,
        path: &str,
        query: &[(String, String)],
        body: Option<&serde_json::Value>,
    ) -> HttpRequest {
        let mut url = format!(
            "{}{}{}",
            self.base_url,
            self.base_path,
            ensure_leading_slash(path)
        );
        if !query.is_empty() {
            url.push('?');
            url.push_str(&encode_query(query));
        }
        let mut headers = vec![
            ("Authorization".to_string(), self.auth_header.clone()),
            ("Accept".to_string(), "application/json".to_string()),
        ];
        let body = body.map(|v| {
            headers.push(("Content-Type".to_string(), "application/json".to_string()));
            v.to_string()
        });
        HttpRequest {
            method,
            url,
            headers,
            body,
        }
    }

    /// Send a resolved call and map the HTTP status to an outcome or a [`BridgeError`]. 401/403/429
    /// become their dedicated variants (honest surfacing); other non-2xx are returned as an
    /// [`ApiOutcome`] the tool layer reports as a tool error with the status.
    pub fn execute(
        &self,
        method: HttpMethod,
        path: &str,
        query: &[(String, String)],
        body: Option<&serde_json::Value>,
    ) -> Result<ApiOutcome, BridgeError> {
        let req = self.build(method, path, query, body);
        let resp = self.transport.send(&req)?;
        match resp.status {
            401 => Err(BridgeError::Unauthorized { body: resp.body }),
            403 => Err(BridgeError::Forbidden { body: resp.body }),
            429 => Err(BridgeError::TooManyRequests {
                retry_after: None,
                body: resp.body,
            }),
            status => Ok(ApiOutcome {
                status,
                value: serde_json::from_str(&resp.body).ok(),
                raw: resp.body,
            }),
        }
    }
}

/// Normalize a base path to `"/x"` form (leading slash, no trailing slash). Empty ⇒ `""`.
fn normalize_base_path(p: &str) -> String {
    let trimmed = p.trim_matches('/');
    if trimmed.is_empty() {
        String::new()
    } else {
        format!("/{trimmed}")
    }
}

/// Ensure `path` has exactly one leading slash.
fn ensure_leading_slash(path: &str) -> String {
    if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
}

/// Percent-encode a `key=value&...` query string (RFC 3986 unreserved kept; everything else `%XX`).
fn encode_query(pairs: &[(String, String)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", percent_encode(k), percent_encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Minimal, dependency-free percent-encoding for path-segment/query values. Keeps the RFC 3986
/// unreserved set (`A-Z a-z 0-9 - _ . ~`); everything else is `%XX` uppercase-hex.
pub fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => {
                out.push('%');
                out.push(hex_upper(b >> 4));
                out.push(hex_upper(b & 0x0f));
            }
        }
    }
    out
}

fn hex_upper(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        _ => (b'A' + (nibble - 10)) as char,
    }
}

/// The real blocking HTTP transport over `reqwest`. Constructs its own client; the base URL and key
/// live in [`ApiBridge`], so this type holds no secret.
pub struct ReqwestTransport {
    client: reqwest::blocking::Client,
}

impl ReqwestTransport {
    /// Build a blocking client. Fails only if the client cannot be constructed.
    pub fn new() -> Result<Self, BridgeError> {
        let client = reqwest::blocking::Client::builder()
            .build()
            .map_err(|e| BridgeError::Transport(e.to_string()))?;
        Ok(Self { client })
    }
}

impl HttpTransport for ReqwestTransport {
    fn send(&self, req: &HttpRequest) -> Result<HttpResponse, BridgeError> {
        let method = match req.method {
            HttpMethod::Get => reqwest::Method::GET,
            HttpMethod::Post => reqwest::Method::POST,
            HttpMethod::Patch => reqwest::Method::PATCH,
            HttpMethod::Delete => reqwest::Method::DELETE,
        };
        let mut builder = self.client.request(method, &req.url);
        for (k, v) in &req.headers {
            builder = builder.header(k.as_str(), v.as_str());
        }
        if let Some(body) = &req.body {
            builder = builder.body(body.clone());
        }
        // NOTE: on any error path we surface `e.to_string()`; reqwest scrubs auth headers from its
        // Display, and the URL carries no secret (the key travels only in the Authorization header).
        let resp = builder
            .send()
            .map_err(|e| BridgeError::Transport(e.to_string()))?;
        let status = resp.status().as_u16();
        let body = resp
            .text()
            .map_err(|e| BridgeError::Transport(e.to_string()))?;
        Ok(HttpResponse { status, body })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{McpConfig, Secret};
    use std::cell::RefCell;

    /// A recording mock transport: captures every outbound request and returns a programmed response.
    struct MockTransport {
        recorded: RefCell<Vec<HttpRequest>>,
        response: HttpResponse,
    }

    impl MockTransport {
        fn new(status: u16, body: &str) -> Self {
            Self {
                recorded: RefCell::new(Vec::new()),
                response: HttpResponse {
                    status,
                    body: body.to_string(),
                },
            }
        }
    }

    impl HttpTransport for MockTransport {
        fn send(&self, req: &HttpRequest) -> Result<HttpResponse, BridgeError> {
            self.recorded.borrow_mut().push(req.clone());
            Ok(self.response.clone())
        }
    }

    fn cfg() -> McpConfig {
        McpConfig {
            enabled: true,
            base_url: "http://127.0.0.1:8080".to_string(),
            base_path: "/api/v1".to_string(),
            api_key: Secret::new("chk_ab12cd_secretsecret"),
            ..McpConfig::default()
        }
    }

    #[test]
    fn build_composes_url_path_and_bearer_header() {
        let bridge = ApiBridge::new(&cfg(), MockTransport::new(200, "{}"));
        let req = bridge.build(HttpMethod::Get, "/entities", &[], None);
        assert_eq!(req.method, HttpMethod::Get);
        assert_eq!(req.url, "http://127.0.0.1:8080/api/v1/entities");
        assert_eq!(
            req.header("Authorization"),
            Some("Bearer chk_ab12cd_secretsecret")
        );
    }

    #[test]
    fn build_encodes_query_and_path() {
        let bridge = ApiBridge::new(&cfg(), MockTransport::new(200, "{}"));
        let req = bridge.build(
            HttpMethod::Get,
            "/law",
            &[("q".to_string(), "código civil".to_string())],
            None,
        );
        assert!(req.url.starts_with("http://127.0.0.1:8080/api/v1/law?q="));
        assert!(req.url.contains("c%C3%B3digo%20civil"));
    }

    #[test]
    fn execute_records_method_path_and_key() {
        let bridge = ApiBridge::new(&cfg(), MockTransport::new(200, r#"{"items":[]}"#));
        let out = bridge
            .execute(HttpMethod::Get, "/entities", &[], None)
            .unwrap();
        assert!(out.is_success());
        assert_eq!(out.value, Some(serde_json::json!({"items": []})));
        // Assert the mock saw the right method + path + auth header.
        let bridge_ref = &bridge;
        let recorded = bridge_ref.transport.recorded.borrow();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].method, HttpMethod::Get);
        assert_eq!(recorded[0].url, "http://127.0.0.1:8080/api/v1/entities");
        assert_eq!(
            recorded[0].header("Authorization"),
            Some("Bearer chk_ab12cd_secretsecret")
        );
    }

    #[test]
    fn post_sets_body_and_content_type() {
        let bridge = ApiBridge::new(&cfg(), MockTransport::new(201, "{}"));
        let body = serde_json::json!({"name": "Encosto Estratégico Lda"});
        let req = bridge.build(HttpMethod::Post, "/entities", &[], Some(&body));
        assert_eq!(req.method, HttpMethod::Post);
        assert!(req.body.as_deref().unwrap().contains("Encosto"));
        assert_eq!(req.header("Content-Type"), Some("application/json"));
    }

    #[test]
    fn status_401_maps_to_unauthorized() {
        let bridge = ApiBridge::new(&cfg(), MockTransport::new(401, "unauthorized"));
        assert!(matches!(
            bridge.execute(HttpMethod::Get, "/entities", &[], None),
            Err(BridgeError::Unauthorized { .. })
        ));
    }

    #[test]
    fn status_403_maps_to_forbidden() {
        let bridge = ApiBridge::new(&cfg(), MockTransport::new(403, "forbidden"));
        assert!(matches!(
            bridge.execute(HttpMethod::Post, "/acts", &[], None),
            Err(BridgeError::Forbidden { .. })
        ));
    }

    #[test]
    fn status_429_maps_to_too_many_requests() {
        let bridge = ApiBridge::new(&cfg(), MockTransport::new(429, "slow down"));
        assert!(matches!(
            bridge.execute(HttpMethod::Get, "/entities", &[], None),
            Err(BridgeError::TooManyRequests { .. })
        ));
    }

    #[test]
    fn bridge_errors_never_contain_the_key() {
        let bridge = ApiBridge::new(&cfg(), MockTransport::new(401, "nope"));
        let err = bridge
            .execute(HttpMethod::Get, "/entities", &[], None)
            .unwrap_err();
        assert!(!format!("{err}").contains("secretsecret"));
        assert!(!format!("{err:?}").contains("secretsecret"));
    }
}
