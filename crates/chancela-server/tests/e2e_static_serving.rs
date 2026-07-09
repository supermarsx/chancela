//! Journey: static / SPA serving — **the regression guard** for the bug this whole suite exists for.
//!
//! With a real web build mounted, the composed server must:
//!   - serve `index.html` at `/` (200, `text/html`);
//!   - serve the SAME shell for a client deep-link with no matching file (`/livros`) — SPA fallback;
//!   - serve a real asset with a JS content-type;
//!   - return a **JSON 404** for unknown `/v1` and `/api/v1` paths — never the SPA `index.html`,
//!     which a client would try to `JSON.parse` ("Unexpected token '<'"). This is t15-f1's landed
//!     fix plus the integration API alias, asserted here over real HTTP against the real binary +
//!     the real static-serving stack.

mod common;

use common::*;

async fn assert_unknown_api_path_is_json_404(h: &ServerHarness, path: &str) {
    let (status, body, ctype) = h.get_text(path).await;
    assert_eq!(status, 404, "{path} is a 404, not a 200 shell");
    assert!(
        !body.contains(SPA_MARKER),
        "{path} must NOT fall through to the SPA shell: {body}"
    );
    assert!(
        ctype.contains("application/json"),
        "{path} answers JSON, got: {ctype}"
    );
    assert!(
        !ctype.contains("text/html"),
        "{path} must not answer HTML, got: {ctype}"
    );
    let value: serde_json::Value = serde_json::from_str(&body)
        .unwrap_or_else(|e| panic!("{path} body is not JSON: {e}: {body}"));
    let error = value["error"]
        .as_str()
        .unwrap_or_else(|| panic!("{path} JSON body has no string error: {value}"));
    assert!(
        error.starts_with("unknown API route: GET "),
        "{path} should use API 404 shape, got: {value}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg_attr(
    not(feature = "e2e"),
    ignore = "composed-system e2e: spawns the real server binary (run with --features e2e)"
)]
async fn static_spa_serving_and_unknown_v1_is_json_404() {
    let dist = write_synthetic_dist();
    let h =
        ServerHarness::start_with(HarnessOptions::default().with_web_dist(dist.dir.clone())).await;

    // `/` serves the SPA shell as HTML.
    let (status, body, ctype) = h.get_text("/").await;
    assert_eq!(status, 200);
    assert!(ctype.contains("text/html"), "content-type: {ctype}");
    assert!(body.contains(SPA_MARKER), "index shell served at /: {body}");

    // A client deep-link with no matching file falls back to the same shell.
    let (status, body, _) = h.get_text("/livros").await;
    assert_eq!(status, 200);
    assert!(body.contains(SPA_MARKER), "SPA deep-link fallback");

    // A real asset is served with a JS content-type.
    let (status, body, ctype) = h.get_text("/assets/app.js").await;
    assert_eq!(status, 200);
    assert!(
        ctype.contains("javascript"),
        "asset content-type is JS, got: {ctype}"
    );
    assert!(body.contains(ASSET_MARKER), "asset bytes served");

    // THE REGRESSION GUARD: an unknown /v1 path is a JSON 404, never the SPA shell.
    let (status, body, ctype) = h.get_text("/v1/does-not-exist").await;
    assert_eq!(status, 404, "unknown /v1 path is a 404, not a 200 shell");
    assert!(
        !body.contains(SPA_MARKER),
        "must NOT fall through to the SPA shell: {body}"
    );
    assert!(
        ctype.contains("application/json"),
        "unknown /v1 path answers JSON, got: {ctype}"
    );
    let value: serde_json::Value =
        serde_json::from_str(&body).expect("unknown /v1 path body is valid JSON");
    assert_eq!(value["error"], "unknown API route: GET /v1/does-not-exist");

    // Integration alias: no bearer API-key gate in this slice, just the same router mounted under
    // `/api/v1`. Unknown integration paths are JSON 404s too, never the SPA shell.
    let (status, body, ctype) = h.get_text("/api/v1/does-not-exist").await;
    assert_eq!(
        status, 404,
        "unknown /api/v1 path is a 404, not a 200 shell"
    );
    assert!(
        !body.contains(SPA_MARKER),
        "must NOT fall through to the SPA shell: {body}"
    );
    assert!(
        ctype.contains("application/json"),
        "unknown /api/v1 path answers JSON, got: {ctype}"
    );
    let value: serde_json::Value =
        serde_json::from_str(&body).expect("unknown /api/v1 path body is valid JSON");
    assert_eq!(
        value["error"],
        "unknown API route: GET /api/v1/does-not-exist"
    );

    // Obscure API-looking paths must stay on the API 404 path even when they are encoded, oddly
    // slashed, or resemble a static asset below the API prefix.
    for path in ["/api/v1/%2e%2e", "/api/v1//foo", "/v1/assets/app.js"] {
        assert_unknown_api_path_is_json_404(&h, path).await;
    }

    // Public/exempt route also works through the integration alias.
    let (status, body, ctype) = h.get_text("/api/v1/session/password-policy").await;
    assert_eq!(status, 200);
    assert!(
        ctype.contains("application/json"),
        "password policy answers JSON, got: {ctype}"
    );
    assert!(
        !body.contains(SPA_MARKER),
        "alias route must not fall through to the SPA shell: {body}"
    );
    let value: serde_json::Value =
        serde_json::from_str(&body).expect("alias password-policy body is valid JSON");
    assert_eq!(value["allow_weak_passwords"], false);
    assert!(
        value["rules"]
            .as_array()
            .is_some_and(|rules| !rules.is_empty()),
        "password policy exposes rules: {value}"
    );

    // API routes keep priority over the static tree.
    let (status, body, _) = h.get_text("/health").await;
    assert_eq!(status, 200);
    assert!(
        body.contains("\"status\":\"ok\""),
        "health, not the shell: {body}"
    );
}
