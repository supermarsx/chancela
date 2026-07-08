//! Shared harness for the composed-system end-to-end journeys (t15-e1).
//!
//! Every journey drives the **real** cargo-built `chancela-server` binary over real HTTP — the
//! composition the layer-isolated unit tests never exercised (the bug this suite exists to catch:
//! a stale server + the SPA static fallback swallowing an unknown `/v1` path into `index.html`).
//!
//! ## What this module gives a journey
//!
//! - [`ServerHarness`] — reserves an ephemeral port, spawns the real binary (via
//!   `env!("CARGO_BIN_EXE_chancela-server")`, which cargo builds before running these tests) with a
//!   unique temp `CHANCELA_DATA_DIR`, polls `/health` until ready, and — via its `Drop` guard —
//!   kills the child and removes the temp dir so every journey is hermetic (own process, own clean
//!   state; the in-memory ledger resets on restart, so nothing bleeds between tests). It can also
//!   [`restart`](ServerHarness::restart) over the *same* data dir to prove persistence.
//! - In-process [`spawn_registry_fixture`] / [`spawn_cae_fixture`] axum servers on ephemeral ports —
//!   injected into the child via `CHANCELA_REGISTRY_URL` / `CHANCELA_CAE_URL`, so the child's **real**
//!   `reqwest::blocking` transports run end to end against a local URL (no Node process).
//! - [`write_synthetic_dist`] — a throwaway `apps/web/dist`-shaped directory (marker `index.html` +
//!   one asset) for the static/SPA-serving journey.
//! - [`contract`] + [`assert_shape`] — load a canonical `contracts/*.json` fixture and assert a live
//!   response shape-matches it (recursive key-set + JSON-type over real wire bytes).
//!
//! The whole module always **compiles** (dev-deps compile under `cargo test --workspace`); the
//! journeys are `#[cfg_attr(not(feature = "e2e"), ignore)]`, so only `--features e2e` runs them.

#![allow(dead_code)] // each `tests/*.rs` binary includes this module and uses a subset of it.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};

use axum::extract::State;
use axum::http::header::CONTENT_TYPE;
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};

/// The `X-Chancela-Session` header the API resolves the ledger actor from.
pub const SESSION_HEADER: &str = "x-chancela-session";

// ---------------------------------------------------------------------------------------------
// Server harness
// ---------------------------------------------------------------------------------------------

/// Environment the child server is spawned with (beyond the always-set `CHANCELA_ADDR` +
/// `CHANCELA_DATA_DIR`). Every field is optional; `Default` is a plain API-only server.
#[derive(Clone, Default)]
pub struct HarnessOptions {
    /// Mounted as `CHANCELA_WEB_DIST` (the static/SPA tree).
    pub web_dist: Option<PathBuf>,
    /// Mounted as `CHANCELA_REGISTRY_URL` (points the real registry transport at a fixture).
    pub registry_url: Option<String>,
    /// Mounted as `CHANCELA_CAE_URL` (points the real CAE source at a fixture).
    pub cae_url: Option<String>,
    /// Written to `<data_dir>/cae-catalog.json` **before** the first spawn. Used to seed a
    /// stale-content-but-fresh-mtime cache that suppresses the startup background refresh without
    /// becoming the active catalog (see the CAE journey). Not re-applied on `restart`.
    pub seed_cae_cache: Option<String>,
}

impl HarnessOptions {
    /// Serve the given static tree.
    pub fn with_web_dist(mut self, dir: impl Into<PathBuf>) -> Self {
        self.web_dist = Some(dir.into());
        self
    }
    /// Point the registry transport at this URL.
    pub fn with_registry(mut self, url: impl Into<String>) -> Self {
        self.registry_url = Some(url.into());
        self
    }
    /// Point the CAE source at this URL.
    pub fn with_cae(mut self, url: impl Into<String>) -> Self {
        self.cae_url = Some(url.into());
        self
    }
    /// Seed a cache file into the data dir before the first spawn.
    pub fn with_seed_cae_cache(mut self, dataset_json: impl Into<String>) -> Self {
        self.seed_cae_cache = Some(dataset_json.into());
        self
    }
}

/// A running child `chancela-server` plus its temp state, cleaned up on drop.
pub struct ServerHarness {
    child: Child,
    /// The base URL of the running server, e.g. `http://127.0.0.1:54321`.
    pub base_url: String,
    /// The temp `CHANCELA_DATA_DIR` this server persists to (unique per harness).
    pub data_dir: PathBuf,
    opts: HarnessOptions,
    client: reqwest::Client,
    /// The session token **GET** reads are auto-authenticated with (t64-E3): under the RBAC gate a
    /// read (`GET /v1/entities`, `/ledger/*`, `/dashboard`, …) now requires a permission, so an
    /// unauthenticated read is `401`. [`open_session`] records the operator's token here so a
    /// journey's existing `get_json`/`get_text` reads carry it without threading a token through every
    /// call. Mutations are unaffected (they still use the explicit `*_auth` helpers, and the one
    /// unauthenticated-mutation-is-401 assertion keeps using `post_json`). Interior mutability so the
    /// `&self` helpers can set it; reset by `restart`/`start_again` (the in-memory session is dropped).
    default_token: std::sync::Mutex<Option<String>>,
}

impl ServerHarness {
    /// Spawn a plain API-only server (no static tree, no registry/CAE fixtures).
    pub async fn start() -> Self {
        Self::start_with(HarnessOptions::default()).await
    }

    /// Spawn a server with the given options.
    pub async fn start_with(opts: HarnessOptions) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(2))
            .build()
            .expect("reqwest client builds");

        let data_dir = unique_temp_dir("chancela-e2e");
        std::fs::create_dir_all(&data_dir).expect("temp data dir created");
        if let Some(cache) = &opts.seed_cae_cache {
            std::fs::write(data_dir.join(chancela_cae::CACHE_FILE), cache)
                .expect("seed cae cache written");
        }

        let (child, base_url) = spawn_child(&data_dir, &opts);
        let mut harness = ServerHarness {
            child,
            base_url,
            data_dir,
            opts,
            client,
            default_token: std::sync::Mutex::new(None),
        };
        harness.wait_ready().await;
        harness
    }

    /// Record the session token that GET reads are auto-authenticated with (t64-E3). Called by
    /// [`open_session`]; a journey rarely needs to call it directly.
    pub fn set_default_token(&self, token: &str) {
        *self.default_token.lock().expect("default_token lock") = Some(token.to_owned());
    }

    /// The current auto-auth token, if a session has been opened.
    fn default_token(&self) -> Option<String> {
        self.default_token
            .lock()
            .expect("default_token lock")
            .clone()
    }

    /// The current auto-auth token (public: for journeys' own byte-reading helpers that build their
    /// own client and must carry the operator session on RBAC-gated reads, t64-E3).
    pub fn current_token(&self) -> Option<String> {
        self.default_token()
    }

    /// Kill the current child and start a fresh one over the **same** data dir (proving
    /// persistence-across-restart). The cache seed is not re-applied — the on-disk state the first
    /// run wrote is exactly what the new run must load.
    pub async fn restart(&mut self) {
        self.stop();
        self.start_again().await;
    }

    /// Kill the current child and wait for it to exit, **without** respawning — leaving the data
    /// dir untouched and unlocked. Used by the backup/restore + tamper journeys, which mutate the
    /// on-disk state (wipe + unpack an archive, or flip a byte in an event row) while the server is
    /// down, then bring it back up with [`start_again`](ServerHarness::start_again). Idempotent.
    pub fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    /// Spawn a fresh child over the **same** data dir and poll it ready. Pairs with
    /// [`stop`](ServerHarness::stop); [`restart`](ServerHarness::restart) is exactly the two in
    /// sequence.
    pub async fn start_again(&mut self) {
        // The in-memory session table is dropped on restart, so the recorded auto-auth token is now
        // stale. Clear it, and — if the journey had an operator session before the restart —
        // transparently re-sign-in as the earliest active user (the bootstrap Owner), exactly as a
        // real operator would after a restart, so the journey's permission-gated reads keep working
        // (t64-E3). Journeys still signed out before the restart get no session.
        let had_session = self.default_token().is_some();
        *self.default_token.lock().expect("default_token lock") = None;
        let (child, base_url) = spawn_child(&self.data_dir, &self.opts);
        self.child = child;
        self.base_url = base_url;
        self.wait_ready().await;
        if had_session {
            self.reopen_default_session().await;
        }
    }

    /// Re-establish the auto-auth session by signing in as the earliest active **passwordless** user
    /// (the bootstrap Owner, in journeys that never set a secret) from the unauthenticated roster.
    /// Used after a restart drops the in-memory session (t64-E3). Skips users that hold a secret — it
    /// cannot know their password, and a failed passwordless attempt would trip the sign-in backoff;
    /// those journeys re-authenticate explicitly (with the password) themselves. A no-op if no
    /// passwordless active user exists.
    pub async fn reopen_default_session(&self) {
        let (_s, roster) = self.get_json_noauth("/v1/session/roster").await;
        let Some(uid) = roster["users"].as_array().and_then(|users| {
            users
                .iter()
                .find(|u| u["has_secret"] == serde_json::Value::Bool(false))
                .and_then(|u| u["id"].as_str())
        }) else {
            return;
        };
        let (status, s) = self
            .post_json("/v1/session", json!({ "user_id": uid }))
            .await;
        if status == 200 {
            if let Some(t) = s["token"].as_str() {
                self.set_default_token(t);
            }
        }
    }

    /// `GET path` with **no** auto-auth (for the unauthenticated surface: health, roster, session).
    pub async fn get_json_noauth(&self, path: &str) -> (u16, Value) {
        self.exec(reqwest::Method::GET, path, None, None).await
    }

    /// Drop `CHANCELA_CAE_URL` from the options a future [`restart`](ServerHarness::restart) uses,
    /// so the restarted server loads the CAE catalog purely from its on-disk cache.
    pub fn clear_cae_url(&mut self) {
        self.opts.cae_url = None;
    }

    /// Poll `GET /health` until it answers `200`, failing fast if the child exits early.
    async fn wait_ready(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(status) = self.child.try_wait().expect("try_wait") {
                panic!("server exited before becoming ready (status {status})");
            }
            if let Ok(resp) = self
                .client
                .get(format!("{}/health", self.base_url))
                .send()
                .await
            {
                if resp.status().is_success() {
                    return;
                }
            }
            if Instant::now() >= deadline {
                panic!("server at {} not ready within 20s", self.base_url);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    // --- HTTP helpers ---------------------------------------------------------------------

    /// `GET path` → (status, JSON body). Auto-authenticated with the operator session recorded by
    /// [`open_session`] (t64-E3): reads are permission-gated, so a journey's reads carry the token
    /// without threading it through every call. Falls back to unauthenticated before any session.
    pub async fn get_json(&self, path: &str) -> (u16, Value) {
        let tok = self.default_token();
        self.exec(reqwest::Method::GET, path, None, tok.as_deref())
            .await
    }

    /// `GET path` with a session token → (status, JSON body).
    pub async fn get_json_auth(&self, path: &str, token: &str) -> (u16, Value) {
        self.exec(reqwest::Method::GET, path, None, Some(token))
            .await
    }

    /// `POST path` with a JSON body → (status, JSON body).
    pub async fn post_json(&self, path: &str, body: Value) -> (u16, Value) {
        self.exec(reqwest::Method::POST, path, Some(body), None)
            .await
    }

    /// `POST path` with a JSON body and a session token → (status, JSON body).
    pub async fn post_json_auth(&self, path: &str, body: Value, token: &str) -> (u16, Value) {
        self.exec(reqwest::Method::POST, path, Some(body), Some(token))
            .await
    }

    /// `PUT path` with a JSON body → (status, JSON body).
    pub async fn put_json(&self, path: &str, body: Value) -> (u16, Value) {
        self.exec(reqwest::Method::PUT, path, Some(body), None)
            .await
    }

    /// `PUT path` with a JSON body and a session token → (status, JSON body).
    pub async fn put_json_auth(&self, path: &str, body: Value, token: &str) -> (u16, Value) {
        self.exec(reqwest::Method::PUT, path, Some(body), Some(token))
            .await
    }

    /// `PATCH path` with a JSON body → (status, JSON body).
    pub async fn patch_json(&self, path: &str, body: Value) -> (u16, Value) {
        self.exec(reqwest::Method::PATCH, path, Some(body), None)
            .await
    }

    /// `PATCH path` with a JSON body and a session token → (status, JSON body).
    pub async fn patch_json_auth(&self, path: &str, body: Value, token: &str) -> (u16, Value) {
        self.exec(reqwest::Method::PATCH, path, Some(body), Some(token))
            .await
    }

    /// `DELETE path` with a session token → (status, JSON body; `Null` when empty).
    pub async fn delete_auth(&self, path: &str, token: &str) -> (u16, Value) {
        self.exec(reqwest::Method::DELETE, path, None, Some(token))
            .await
    }

    /// `DELETE path` with a JSON body and a session token → (status, JSON body). Used by the RBAC
    /// role-unassign / delegation-revoke endpoints (t64-E4), which carry a `{role_id, scope}` body.
    pub async fn delete_auth_json(&self, path: &str, body: Value, token: &str) -> (u16, Value) {
        self.exec(reqwest::Method::DELETE, path, Some(body), Some(token))
            .await
    }

    /// `GET path` → (status, raw body text, content-type). For the static/SPA journey, where the
    /// body is HTML/JS rather than JSON and the content-type is itself under test.
    pub async fn get_text(&self, path: &str) -> (u16, String, String) {
        let mut req = self.client.get(format!("{}{}", self.base_url, path));
        if let Some(t) = self.default_token() {
            req = req.header(SESSION_HEADER, t);
        }
        let resp = req
            .send()
            .await
            .unwrap_or_else(|e| panic!("GET {path} failed: {e}"));
        let status = resp.status().as_u16();
        let ctype = resp
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();
        let body = resp.text().await.unwrap_or_default();
        (status, body, ctype)
    }

    async fn exec(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
        token: Option<&str>,
    ) -> (u16, Value) {
        let mut req = self
            .client
            .request(method, format!("{}{}", self.base_url, path));
        if let Some(b) = body {
            req = req.json(&b);
        }
        if let Some(t) = token {
            req = req.header(SESSION_HEADER, t);
        }
        let resp = req
            .send()
            .await
            .unwrap_or_else(|e| panic!("request to {path} failed: {e}"));
        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap_or_default();
        let value = if text.trim().is_empty() {
            Value::Null
        } else {
            serde_json::from_str(&text)
                .unwrap_or_else(|e| panic!("response from {path} is not JSON ({e}): {text}"))
        };
        (status, value)
    }
}

impl Drop for ServerHarness {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.data_dir);
    }
}

/// Reserve a currently-free loopback port by binding `:0`, reading the assigned port, and dropping
/// the listener. A negligible TOCTOU window before the child rebinds is acceptable for tests.
fn reserve_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let port = listener.local_addr().expect("local_addr").port();
    drop(listener);
    port
}

/// Spawn the real server binary bound to a fresh reserved port with the given data dir + options,
/// returning the child and its base URL. Ambient `CHANCELA_*` env vars are cleared so a dev box's
/// configuration cannot leak into a hermetic journey.
fn spawn_child(data_dir: &Path, opts: &HarnessOptions) -> (Child, String) {
    let port = reserve_port();
    let addr = format!("127.0.0.1:{port}");

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_chancela-server"));
    cmd.env_remove("CHANCELA_WEB_DIST")
        .env_remove("CHANCELA_REGISTRY_URL")
        .env_remove("CHANCELA_CAE_URL")
        .env("CHANCELA_ADDR", &addr)
        .env("CHANCELA_DATA_DIR", data_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    if let Some(dir) = &opts.web_dist {
        cmd.env("CHANCELA_WEB_DIST", dir);
    }
    if let Some(url) = &opts.registry_url {
        cmd.env("CHANCELA_REGISTRY_URL", url);
    }
    if let Some(url) = &opts.cae_url {
        cmd.env("CHANCELA_CAE_URL", url);
    }

    let child = cmd.spawn().expect("spawn chancela-server binary");
    (child, format!("http://{addr}"))
}

/// A unique temp directory path (no `uuid` dev-dep): pid + a nanosecond clock + a monotonic counter.
fn unique_temp_dir(prefix: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("{prefix}-{}-{seq}-{nanos}", std::process::id()))
}

// ---------------------------------------------------------------------------------------------
// In-process fixture servers (registry / CAE)
// ---------------------------------------------------------------------------------------------

/// A tiny in-process axum server serving one canned body on any path/method, aborted on drop.
pub struct Fixture {
    /// The base URL to hand the child via `CHANCELA_REGISTRY_URL` / `CHANCELA_CAE_URL`.
    pub url: String,
    handle: tokio::task::JoinHandle<()>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// Spawn a fixture serving `body` with `content_type` for every request.
async fn spawn_fixture(body: String, content_type: &'static str) -> Fixture {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("fixture binds ephemeral port");
    let addr = listener.local_addr().expect("fixture local_addr");
    let state = (content_type, Arc::new(body));
    let app = axum::Router::new()
        .fallback(fixture_handler)
        .with_state(state);
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Fixture {
        url: format!("http://{addr}"),
        handle,
    }
}

async fn fixture_handler(State((ctype, body)): State<(&'static str, Arc<String>)>) -> Response {
    ([(CONTENT_TYPE, ctype)], (*body).clone()).into_response()
}

/// A registry fixture serving certidão HTML (the child's real registry transport fetches it).
pub async fn spawn_registry_fixture(html: impl Into<String>) -> Fixture {
    spawn_fixture(html.into(), "text/html; charset=utf-8").await
}

/// A CAE fixture serving dataset JSON (the child's real CAE source fetches it).
pub async fn spawn_cae_fixture(dataset_json: impl Into<String>) -> Fixture {
    spawn_fixture(dataset_json.into(), "application/json").await
}

// ---------------------------------------------------------------------------------------------
// Synthetic web dist (static / SPA serving journey)
// ---------------------------------------------------------------------------------------------

/// Marker string embedded in the synthetic `index.html`, asserted by the static-serving journey.
pub const SPA_MARKER: &str = "CHANCELA-SPA-MARKER";
/// Marker string embedded in the synthetic asset, asserted by the static-serving journey.
pub const ASSET_MARKER: &str = "CHANCELA-ASSET-MARKER";

/// A throwaway `apps/web/dist`-shaped directory (marker `index.html` + one `/assets/app.js`),
/// removed on drop. Passed to the harness as `CHANCELA_WEB_DIST`.
pub struct SyntheticDist {
    /// The dist directory to hand the harness.
    pub dir: PathBuf,
}

impl Drop for SyntheticDist {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Write a synthetic dist and return its handle.
pub fn write_synthetic_dist() -> SyntheticDist {
    let dir = unique_temp_dir("chancela-e2e-dist");
    std::fs::create_dir_all(dir.join("assets")).expect("synthetic assets dir");
    let index = format!(
        "<!doctype html><html lang=\"pt-PT\"><head><meta charset=\"utf-8\"><title>Chancela</title>\
         </head><body><div id=\"root\"></div><!-- {SPA_MARKER} -->\
         <script type=\"module\" src=\"/assets/app.js\"></script></body></html>"
    );
    std::fs::write(dir.join("index.html"), index).expect("synthetic index.html");
    std::fs::write(
        dir.join("assets").join("app.js"),
        format!("/* {ASSET_MARKER} */\nconsole.log(\"chancela\");\n"),
    )
    .expect("synthetic app.js");
    SyntheticDist { dir }
}

// ---------------------------------------------------------------------------------------------
// Canonical fixtures shared across journeys
// ---------------------------------------------------------------------------------------------

/// A structurally faithful certidão permanente page: firma + control-digit-**valid** NIPC
/// (`503004642`, so the import-from-registry create path succeeds), natureza jurídica →
/// `SociedadePorQuotas`, a Principal (catalogued Rev.4 `68110`) + a Secundário (uncatalogued
/// `99999`) CAE, and one inscrição. Shared by the entities and contracts journeys.
pub const CERTIDAO_HTML: &str = "<!DOCTYPE html><html lang=\"pt-PT\"><body>\
    <div class=\"matricula\"><p>MATRÍCULA</p><table>\
    <tr><td>Matrícula:</td><td>99999/20200101</td></tr>\
    <tr><td>NIF/NIPC:</td><td>503004642</td></tr>\
    <tr><td>Firma:</td><td>Encosto Estratégico, Lda</td></tr>\
    <tr><td>Natureza Jurídica:</td><td>Sociedade por quotas</td></tr>\
    <tr><td>Sede:</td><td>Avenida da Liberdade, Lisboa</td></tr>\
    <tr><td>Capital:</td><td>5.000,00 EUR</td></tr>\
    <tr><td>CAE Principal:</td><td>68110 - Compra e venda de bens imobiliários</td></tr>\
    <tr><td>CAE Secundário:</td><td>99999</td></tr>\
    <tr><td>Data de constituição:</td><td>2020-01-01</td></tr>\
    </table></div>\
    <div class=\"inscricoes\"><p>Inscrições - Averbamentos - Anotações</p>\
    <div><p>Insc. 1 AP. 1/20200101</p><p>CONSTITUIÇÃO DE SOCIEDADE</p></div>\
    </div></body></html>";

/// A structurally valid CAE dataset that **supersedes** the embedded catalog (far-future
/// `generated_at`, distinct digest), served to the CAE refresh leg. After a refresh, `GET /v1/cae/A`
/// resolves to "Secção de teste".
pub const SUPERSEDING_CAE_DATASET: &str = r#"{
  "schema_version": 1,
  "generated_at": "2099-01-01T00:00:00Z",
  "source_note": "e2e refresh dataset (t15-e1)",
  "rev3": [],
  "rev4": [
    { "code": "A", "designation": "Secção de teste", "level": "Seccao", "revision": "Rev4", "parent": null },
    { "code": "01", "designation": "Divisão de teste", "level": "Divisao", "revision": "Rev4", "parent": "A" }
  ]
}"#;

/// A structurally valid but **older** (`generated_at` 2000) CAE dataset with distinct nodes, seeded
/// as the on-disk cache before the CAE journey's first spawn. Because its mtime is fresh, the startup
/// background refresh treats the cache as up to date and does nothing (so it cannot race the manual
/// refresh); because its `generated_at` predates the embedded dataset, `load_catalog` keeps the
/// embedded catalog active — the journey observes `origin: Embedded` until the manual refresh.
pub const STALE_CAE_CACHE: &str = r#"{
  "schema_version": 1,
  "generated_at": "2000-01-01T00:00:00Z",
  "source_note": "stale placeholder (t15-e1)",
  "rev3": [],
  "rev4": [
    { "code": "B", "designation": "Secção obsoleta", "level": "Seccao", "revision": "Rev4", "parent": null },
    { "code": "02", "designation": "Divisão obsoleta", "level": "Divisao", "revision": "Rev4", "parent": "B" }
  ]
}"#;

// ---------------------------------------------------------------------------------------------
// Contract fixtures (contracts/*.json) — live-wire shape assertions
// ---------------------------------------------------------------------------------------------

/// Load a canonical fixture from the top-level `contracts/` directory.
pub fn contract(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("contracts")
        .join(name);
    let bytes =
        std::fs::read(&path).unwrap_or_else(|e| panic!("read contract {}: {e}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|e| panic!("parse contract {}: {e}", path.display()))
}

/// Assert `actual` (a live wire response) shape-matches `expected` (a `contracts/*.json` fixture):
/// objects must have the **exact same key set** (renamed/added/removed fields fail here), leaf JSON
/// types must match, and array element shapes are checked when both sides are non-empty. Nullable
/// fields are permissive (presence is enforced by the parent's key-set check; type is verified only
/// when both sides are non-null), since a nullable field cannot express "string or null" in one
/// example value.
pub fn assert_shape(label: &str, actual: &Value, expected: &Value) {
    assert_shape_at(label, actual, expected);
}

fn assert_shape_at(path: &str, actual: &Value, expected: &Value) {
    // Nullable leaf/field: presence already ensured by the enclosing object's key-set check.
    if actual.is_null() || expected.is_null() {
        return;
    }
    match expected {
        Value::Object(e) => {
            let a = actual
                .as_object()
                .unwrap_or_else(|| panic!("{path}: expected object, got {actual}"));
            let ek: BTreeSet<&String> = e.keys().collect();
            let ak: BTreeSet<&String> = a.keys().collect();
            assert!(
                ek == ak,
                "{path}: object key-set mismatch\n  contract: {ek:?}\n  live:     {ak:?}"
            );
            for (k, ev) in e {
                assert_shape_at(&format!("{path}.{k}"), &a[k], ev);
            }
        }
        Value::Array(e) => {
            let a = actual
                .as_array()
                .unwrap_or_else(|| panic!("{path}: expected array, got {actual}"));
            if let (Some(ev), Some(av)) = (e.first(), a.first()) {
                assert_shape_at(&format!("{path}[0]"), av, ev);
            }
        }
        Value::String(_) => assert!(actual.is_string(), "{path}: expected string, got {actual}"),
        Value::Number(_) => assert!(actual.is_number(), "{path}: expected number, got {actual}"),
        Value::Bool(_) => assert!(actual.is_boolean(), "{path}: expected bool, got {actual}"),
        Value::Null => unreachable!("handled above"),
    }
}

// ---------------------------------------------------------------------------------------------
// Shared journey helpers
// ---------------------------------------------------------------------------------------------

/// Bootstrap an authenticated session for a fresh server: create the first user (the first-run
/// `POST /v1/users` is auth-exempt while no users exist) and open a session, returning the token.
///
/// Under the t41 security model every mutation endpoint requires a valid `X-Chancela-Session`, so a
/// journey that mutates state threads this token through its mutation helpers. Journeys that need the
/// user id later (e.g. to re-open a session after a restart drops the in-memory one) create the user
/// and session inline instead of calling this.
pub async fn bootstrap_session(h: &ServerHarness) -> String {
    let user_id = create_user(h, "e2e.operator", "E2E Operator").await;
    open_session(h, &user_id).await
}

/// Create an entity and return its id.
pub async fn create_entity(
    h: &ServerHarness,
    name: &str,
    nipc: &str,
    seat: &str,
    kind: &str,
    token: &str,
) -> String {
    let (status, entity) = h
        .post_json_auth(
            "/v1/entities",
            json!({ "name": name, "nipc": nipc, "seat": seat, "kind": kind }),
            token,
        )
        .await;
    assert_eq!(status, 201, "create entity: {entity}");
    entity["id"].as_str().expect("entity id").to_owned()
}

/// Open a book for an entity and return its id.
pub async fn open_book(h: &ServerHarness, entity_id: &str, token: &str) -> String {
    let (status, book) = h
        .post_json_auth(
            "/v1/books",
            json!({
                "entity_id": entity_id,
                "kind": "AssembleiaGeral",
                "purpose": "livro de atas da assembleia geral",
                "opening_date": "2026-01-15",
                "required_signatories": ["Administrador"],
            }),
            token,
        )
        .await;
    assert_eq!(status, 201, "open book: {book}");
    assert_eq!(book["state"], "Open");
    book["id"].as_str().expect("book id").to_owned()
}

/// Draft an act into a book and return its id.
pub async fn draft_act(
    h: &ServerHarness,
    book_id: &str,
    title: &str,
    token: Option<&str>,
) -> String {
    let body = json!({ "book_id": book_id, "title": title, "channel": "Physical" });
    let (status, act) = match token {
        Some(t) => h.post_json_auth("/v1/acts", body, t).await,
        None => h.post_json("/v1/acts", body).await,
    };
    assert_eq!(status, 201, "draft act: {act}");
    act["id"].as_str().expect("act id").to_owned()
}

/// Fill an act's mandatory CSC art. 63.º contents — including the mesa, time, and agenda now that
/// the wire carries them (t31) — so a CSC ata seals cleanly with no acknowledgement.
pub async fn fill_act_contents(h: &ServerHarness, act_id: &str, token: &str) {
    let (status, _) = h
        .patch_json_auth(
            &format!("/v1/acts/{act_id}"),
            json!({
                "meeting_date": "2026-03-30",
                "meeting_time": "10:00",
                "place": "Sede social",
                "mesa": { "presidente": "Ana Presidente", "secretarios": ["Rui Secretário"] },
                "agenda": [{ "number": 1, "text": "Aprovação das contas do exercício" }],
                "attendance_reference": "Lista de presenças anexa",
                "deliberations": "Aprovadas por unanimidade as contas do exercício de 2025.",
            }),
            token,
        )
        .await;
    assert_eq!(status, 200, "patch act contents");
}

/// Advance an act through the lifecycle up to `Signing`.
pub async fn advance_to_signing(h: &ServerHarness, act_id: &str, token: Option<&str>) {
    for to in [
        "Review",
        "Convened",
        "Deliberated",
        "TextApproved",
        "Signing",
    ] {
        let body = json!({ "to": to });
        let (status, advanced) = match token {
            Some(t) => {
                h.post_json_auth(&format!("/v1/acts/{act_id}/advance"), body, t)
                    .await
            }
            None => {
                h.post_json(&format!("/v1/acts/{act_id}/advance"), body)
                    .await
            }
        };
        assert_eq!(status, 200, "advance to {to}: {advanced}");
    }
}

/// Create a user and return its id.
pub async fn create_user(h: &ServerHarness, username: &str, display_name: &str) -> String {
    let (status, user) = h
        .post_json(
            "/v1/users",
            json!({ "username": username, "display_name": display_name }),
        )
        .await;
    assert_eq!(status, 201, "create user: {user}");
    user["id"].as_str().expect("user id").to_owned()
}

/// Open a session for a user id and return its token. Also records the token as the harness'
/// auto-auth session for GET reads (t64-E3), so the journey's permission-gated reads carry it.
pub async fn open_session(h: &ServerHarness, user_id: &str) -> String {
    let (status, s) = h
        .post_json("/v1/session", json!({ "user_id": user_id }))
        .await;
    assert_eq!(status, 200, "open session: {s}");
    let token = s["token"].as_str().expect("session token").to_owned();
    h.set_default_token(&token);
    token
}

/// Every actor recorded across the whole ledger dump.
pub async fn ledger_actors(h: &ServerHarness) -> Vec<String> {
    let (status, events) = h.get_json("/v1/ledger/events").await;
    assert_eq!(status, 200);
    events
        .as_array()
        .expect("events array")
        .iter()
        .map(|e| e["actor"].as_str().unwrap_or_default().to_owned())
        .collect()
}

/// Every event `kind` recorded across the whole ledger dump (in order).
pub async fn ledger_kinds(h: &ServerHarness) -> Vec<String> {
    let (status, events) = h.get_json("/v1/ledger/events").await;
    assert_eq!(status, 200);
    events
        .as_array()
        .expect("events array")
        .iter()
        .map(|e| e["kind"].as_str().unwrap_or_default().to_owned())
        .collect()
}
