//! A Trusted List verdict decided from the **durable cache** is reported as such on the trust read
//! paths.
//!
//! The fault behind this: the configured Trusted List URL was reachable from the operator's own
//! host but not from where the server runs, so every qualified signature failed outright with
//! `signing_trusted_list_unavailable`. The fix caches the raw list bytes and falls back to them, and
//! the reason this test exists is the *other* half of that fix — a Trusted List is how a withdrawn
//! trust service stops being trusted, so an installation quietly deciding from an expired copy is
//! exactly the state an operator must be able to see.
//!
//! The record is written by the **signing** path, in whatever process took that decision, and read
//! here by a request that never signed anything. That indirection is the point: nothing else would
//! carry the fact to a screen.
//!
//! Nothing here fetches anything. The cache directory is populated directly, which is also what
//! makes the assertion sharp — the read path is being shown to report the recorded provenance, not
//! to re-derive it.

use crate::common;

use std::path::PathBuf;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use chancela_api::{AppState, User, UserId, router};
use chancela_authz::{OWNER_ROLE_ID, RoleAssignment, RoleCatalog, RoleId, Scope};
use chancela_tsl::{
    CODE_TSL_SERVED_FROM_CACHE, CODE_TSL_SERVED_FROM_STALE_CACHE, TSL_CACHE_DIR, TslCacheServe,
    TslDiskCache,
};
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use time::macros::datetime;
use tower::ServiceExt;
use uuid::Uuid;

use common::{TEST_PASSWORD, password_hash};

const STATUS: &str = "/v1/trust/status";
const TSA: &str = "/v1/trust/tsa";

/// The URL the legacy `signing.tsl_url` selector resolves to. Not reachable and never contacted.
const TSL_URL: &str = "https://trusted-list.example.invalid/TSL.xml";
/// The id `SigningSettings::runtime_tsl_selection` gives the `signing.tsl_url` fallback entry.
const LEGACY_SOURCE_ID: &str = "legacy-tsl-url";

/// A transport failure with its terminal cause attached — the whole reason the detail is worth
/// carrying. "connection timed out" and "certificate verify failed" send an operator to completely
/// different places, and `error sending request for url (…)` alone distinguishes neither.
const FETCH_ERROR: &str = "error sending request for url \
                           (https://trusted-list.example.invalid/TSL.xml): client error (Connect): \
                           dns error: failed to lookup address information";

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("chancela-api-tsl-cache-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        Self(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn send(state: AppState, req: Request<Body>) -> (StatusCode, Value) {
    let response = router(state).oneshot(req).await.expect("router responds");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body collects");
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).expect("body is JSON")
    };
    (status, value)
}

fn get(uri: &str, token: &str) -> Request<Body> {
    let mut req = Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())
        .expect("request builds");
    req.headers_mut()
        .insert("x-chancela-session", token.parse().expect("session header"));
    req
}

async fn seed_owner_session(state: &AppState) -> String {
    {
        let mut roles = state.roles.write().await;
        *roles = RoleCatalog::seeded_defaults();
    }
    let uid = UserId(Uuid::new_v4());
    state.users.write().await.insert(
        uid,
        User {
            passkeys: Vec::new(),
            id: uid,
            username: "amelia.marques".to_owned(),
            display_name: "Amélia Marques".to_owned(),
            email: None,
            created_at: OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .unwrap_or_default(),
            active: true,
            password_hash: Some(password_hash()),
            attestation_key: None,
            retired_attestation_keys: Vec::new(),
            totp: None,
            two_factor_required: false,
            force_password_change: false,
            secret_source: Default::default(),
            recovery_hash: None,
            role_assignments: vec![RoleAssignment::new(RoleId(OWNER_ROLE_ID.0), Scope::Global)],
            language: Default::default(),
        },
    );
    let (status, body) = send(
        state.clone(),
        Request::builder()
            .method("POST")
            .uri("/v1/session")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({ "user_id": uid.0, "password": TEST_PASSWORD }).to_string(),
            ))
            .expect("request builds"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "session opens: {body}");
    body["token"].as_str().expect("token").to_owned()
}

/// An install whose signing path resolves the legacy `signing.tsl_url` source.
///
/// The shipped defaults enable a `tsl_sources` entry pointing at the real national endpoint; every
/// one of them is disabled here so the selector falls through to `tsl_url`, and the only location
/// this test names is an unreachable `.invalid` host. Nothing contacts it either way — the point is
/// simply that no real endpoint appears in a test fixture.
async fn install(dir: &TempDir) -> AppState {
    let state = AppState::with_data_dir(dir.0.clone());
    {
        let mut settings = state.settings.write().await;
        for entry in &mut settings.signing.tsl_sources {
            entry.enabled = false;
        }
        settings.signing.tsl_url = Some(TSL_URL.to_owned());
    }
    state
}

/// The cache entry key the signing path writes under for the legacy source. Derived through the
/// same public helper `build_trust_policy` uses, so a change to the keying breaks this test rather
/// than silently detaching the read path from what signing records.
fn legacy_key() -> String {
    TslDiskCache::key_for(LEGACY_SOURCE_ID, &format!("url:{TSL_URL}"))
}

/// Record that the durable cache answered a fetch, exactly as `CachingTslSource` would have.
fn record_serve(dir: &TempDir, stale: bool) {
    let cache = TslDiskCache::new(dir.0.join(TSL_CACHE_DIR));
    cache
        .record_serve(
            &legacy_key(),
            &TslCacheServe {
                fetched_at: datetime!(2026-01-15 0:00 UTC),
                expires_at: datetime!(2026-07-15 0:00 UTC),
                served_at: datetime!(2026-07-16 9:30 UTC),
                stale,
                fetch_error: FETCH_ERROR.to_owned(),
            },
        )
        .expect("record the cache serve");
}

#[tokio::test]
async fn an_install_that_fetched_its_list_reports_no_cache_fallback() {
    // The ordinary state. The marker's whole value is that its appearance means something, so its
    // absence has to be the default rather than something a test had to arrange.
    let dir = TempDir::new();
    let state = install(&dir).await;
    let token = seed_owner_session(&state).await;

    let (status, body) = send(state, get(STATUS, &token)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body["validation"].get("cache_fallback").is_none(),
        "a list that came live must not be marked as cached: {}",
        body["validation"]
    );
}

#[tokio::test]
async fn a_stale_cache_serve_is_reported_on_the_trust_status_and_tsa_screens() {
    let dir = TempDir::new();
    record_serve(&dir, true);
    let state = install(&dir).await;
    let token = seed_owner_session(&state).await;

    let (status, body) = send(state.clone(), get(STATUS, &token)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let fallback = &body["validation"]["cache_fallback"];
    assert_eq!(
        fallback["code"], CODE_TSL_SERVED_FROM_STALE_CACHE,
        "a copy past its NextUpdate is the loud code: {fallback}"
    );
    assert_eq!(fallback["stale"], true);
    assert_eq!(fallback["fetched_at"], "2026-01-15T00:00:00Z");
    assert_eq!(fallback["expires_at"], "2026-07-15T00:00:00Z");
    assert_eq!(fallback["served_at"], "2026-07-16T09:30:00Z");
    // The terminal cause rides along. Without it the operator is told a fallback happened and given
    // no way to find out why, which is where this whole investigation started.
    let reported = fallback["fetch_error"].as_str().expect("fetch_error");
    assert!(
        reported.contains("dns error"),
        "the recorded cause must survive to the wire: {reported}"
    );

    // The TSA records are read off the same list, so the same disclosure belongs there.
    let (status, body) = send(state, get(TSA, &token)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["summary"]["tsl"]["cache_fallback"]["code"], CODE_TSL_SERVED_FROM_STALE_CACHE,
        "the TSA diagnostics read the same list and must carry the same marker: {}",
        body["summary"]["tsl"]
    );
}

#[tokio::test]
async fn a_cache_serve_inside_the_validity_window_is_reported_but_not_as_stale() {
    // Inside `NextUpdate` a cached copy is ordinary — the scheme operator's own document says the
    // list is valid until then. It is still disclosed (the network is unreachable, which an
    // operator wants to know) but it must not carry the code that says the verdict may be wrong.
    let dir = TempDir::new();
    record_serve(&dir, false);
    let state = install(&dir).await;
    let token = seed_owner_session(&state).await;

    let (status, body) = send(state, get(STATUS, &token)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let fallback = &body["validation"]["cache_fallback"];
    assert_eq!(fallback["code"], CODE_TSL_SERVED_FROM_CACHE);
    assert_eq!(fallback["stale"], false);
    assert_ne!(fallback["code"], CODE_TSL_SERVED_FROM_STALE_CACHE);
}

#[tokio::test]
async fn a_serve_recorded_for_another_source_is_not_attributed_to_this_one() {
    // Re-pointing a configured entry at a different URL changes which list the installation trusts.
    // Reporting the previous entry's fallback against the new one would attribute a stale copy to a
    // list it was never taken from.
    let dir = TempDir::new();
    let cache = TslDiskCache::new(dir.0.join(TSL_CACHE_DIR));
    cache
        .record_serve(
            &TslDiskCache::key_for(
                LEGACY_SOURCE_ID,
                "url:https://somewhere.else.invalid/TSL.xml",
            ),
            &TslCacheServe {
                fetched_at: datetime!(2026-01-15 0:00 UTC),
                expires_at: datetime!(2026-07-15 0:00 UTC),
                served_at: datetime!(2026-07-16 9:30 UTC),
                stale: true,
                fetch_error: FETCH_ERROR.to_owned(),
            },
        )
        .expect("record a serve for a different location");

    let state = install(&dir).await;
    let token = seed_owner_session(&state).await;
    let (status, body) = send(state, get(STATUS, &token)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body["validation"].get("cache_fallback").is_none(),
        "another location's cache must not be reported against this source: {}",
        body["validation"]
    );
}

#[test]
fn the_durable_cache_rides_the_instance_backup() {
    // It is a cache, so a restore that dropped it would cost one fetch — but it is also the
    // material a qualified signature's trust decision was taken from while the network was down,
    // and an archive of an instance should carry what that instance was deciding on. Keeping it is
    // safe in the other direction because nothing is trusted for having been restored: every entry
    // is re-hashed, re-parsed and re-verified against the current anchors on use, and one past its
    // maximum age is refused rather than served.
    assert!(
        chancela_api::INSTANCE_SIDECAR_NAMES.contains(&TSL_CACHE_DIR),
        "the durable Trusted List cache is missing from the shared sidecar set"
    );
}
