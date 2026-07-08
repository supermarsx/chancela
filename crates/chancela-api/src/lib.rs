//! # chancela-api
//!
//! The HTTP layer for **Chancela**. This crate is a library: it builds an [`axum::Router`]
//! over shared in-memory state and exposes it via [`router`]. The `chancela-server` binary
//! wraps this router with a Tokio runtime and a listener; tests drive it directly with
//! `tower`'s `oneshot`.
//!
//! The API is deliberately thin (ARC-02): handlers translate JSON to and from the
//! `chancela-core` domain types (via the DTOs in [`dto`], never serializing core types
//! directly) and record mutations in a `chancela-ledger` hash chain. There is no persistence
//! yet — state lives in `Arc<RwLock<..>>` and resets on restart.
//!
//! ## Endpoints (v1)
//!
//! - `GET  /health` — liveness plus the crate version.
//! - `POST|GET /v1/entities`, `GET /v1/entities/{id}` — entity CRUD (§2.3).
//! - `POST|GET /v1/books`, `GET /v1/books/{id}`, `POST /v1/books/{id}/close`,
//!   `GET /v1/books/{id}/acts` — book open/list/close and the acts-in-a-book feed (§2.4).
//! - `POST /v1/acts`, `GET|PATCH /v1/acts/{id}`, `POST /v1/acts/{id}/advance`,
//!   `GET /v1/acts/{id}/compliance`, `POST /v1/acts/{id}/seal`,
//!   `POST /v1/acts/{id}/archive` — the ata lifecycle, compliance gate, and seal (§2.5).
//! - `GET /v1/ledger/events`, `GET /v1/ledger/verify` — the audit feed and chain probe (§2.6).
//! - `GET /v1/dashboard` — WFL-40 counts and recent events (§2.7).
//! - `GET|PUT /v1/settings` — the typed, versioned application settings document (§2.8).
//! - `POST /v1/registry/lookup`, `GET /v1/entities/{id}/registry`,
//!   `POST /v1/entities/{id}/registry/import`, `POST /v1/entities/import-from-registry` —
//!   certidão permanente consultation and import by access code (§2.7, LEG-20/21/22).
//!
//! ## Serving the web UI
//!
//! [`router`] wires the API only. [`app`] additionally mounts the built web shell so the
//! whole application is reachable from one origin: pass the `apps/web/dist` directory and it
//! is served at `/` with a single-page-app fallback (any unknown, non-API path returns
//! `index.html`, so client-side routes like `/livros` deep-link correctly). API routes keep
//! priority over the static tree. Pass `None` to run API-only with a friendly landing page.

mod actor;
mod acts;
mod attestation;
mod backup;
mod books;
mod cae;
mod dashboard;
mod dto;
mod entities;
mod error;
mod hex;
mod law;
mod ledger;
mod registry;
mod session;
mod settings;
mod users;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use chancela_cae::{CaeCatalog, CaeSource, CaeSourceChain};
use chancela_core::{Act, ActId, Book, BookId, Entity, EntityId};
use chancela_ledger::{Event, Ledger, LedgerError};
use chancela_registry::{RegistryExtract, RegistryTransport};
use chancela_store::{Store, StoreError, Tx};
use serde::Serialize;
use tokio::sync::RwLock;
use tower_http::services::{ServeDir, ServeFile};

pub use actor::{CurrentActor, CurrentAttestor};
pub use error::ApiError;
pub use law::{LawEntry, LawEntryView, LawStore, StoredLawInfo};
pub use settings::{
    AppearanceSettings, CaeSourceEntry, CatalogSettings, DocumentSettings, Locale,
    OnboardingSettings, OrganizationSettings, Settings, SignatureFamily, SigningSettings,
    ThemeMode,
};
pub use users::{User, UserId};

/// Environment variable naming a data directory for on-disk persistence (currently
/// `settings.json`). When unset, [`AppState::from_env`] falls back to walking up for an
/// existing `chancela-data/` directory, and finally to pure in-memory state.
pub const DATA_DIR_ENV: &str = "CHANCELA_DATA_DIR";

/// Shared, in-memory application state (ARC-02 scaffold; no persistence yet).
///
/// Every field is `Arc<RwLock<..>>` so the state is cheap to clone into each handler and safe
/// to mutate concurrently. Cloning an [`AppState`] shares the same underlying maps and ledger.
/// Handlers that take several locks acquire them in the fixed order **entities → books → acts
/// → registry_extracts → users → ledger** to avoid deadlock. The `cae` and `sessions` locks are
/// independent, short-lived locks not part of that chain (a handler acquires and releases one
/// before touching the ordered locks, or after — never interleaved with them).
#[derive(Clone, Default)]
pub struct AppState {
    /// All known entities, keyed by their [`EntityId`].
    pub entities: Arc<RwLock<HashMap<EntityId, Entity>>>,
    /// All books (livros de atas), keyed by their [`BookId`].
    pub books: Arc<RwLock<HashMap<BookId, Book>>>,
    /// All acts (atas), keyed by their [`ActId`].
    pub acts: Arc<RwLock<HashMap<ActId, Act>>>,
    /// The append-only audit ledger backing every mutation (DAT-10/11).
    pub ledger: Arc<RwLock<Ledger>>,
    /// The current application settings document (contract §2.8). Defaults until a `PUT`.
    pub settings: Arc<RwLock<settings::Settings>>,
    /// Where `settings.json` is persisted, or `None` for pure in-memory state. Shared (and so
    /// cheap to clone) via `Arc`; set only by [`AppState::with_data_dir`]/[`AppState::from_env`].
    pub persist_path: Option<Arc<PathBuf>>,
    /// Injected certidão permanente transport; `None` ⇒ handlers build an
    /// `HttpRegistryTransport` from the environment (contract §2.7). Boxed behind `Option` so
    /// `Default` stays derivable (mirrors `persist_path`); tests inject a mock here.
    pub registry: Option<Arc<dyn RegistryTransport>>,
    /// Registry extracts imported per entity, with provenance (LEG-22). In-memory like the
    /// rest of the scaffold state.
    pub registry_extracts: Arc<RwLock<HashMap<EntityId, RegistryExtract>>>,
    /// The active CAE catalog (contract §2.7). `Default` is the embedded both-revision dataset;
    /// [`AppState::with_data_dir`] prefers a valid `cae-catalog.json` cache, and
    /// `POST /v1/cae/refresh` swaps it in place.
    pub cae: Arc<RwLock<CaeCatalog>>,
    /// Legacy injected CAE dataset source for `POST /v1/cae/refresh` (single-envelope back-compat
    /// seam): when set, the refresh runs the original [`chancela_cae::refresh`] path unchanged.
    /// `None` in production, where the refresh builds an ordered chain from settings + environment.
    /// Mirrors `registry`; some tests inject a source here.
    pub cae_source: Option<Arc<dyn CaeSource>>,
    /// Test/DI seam (§cae-v2): when set, `POST /v1/cae/refresh` builds its source chain from this
    /// factory instead of from settings/environment, so tests drive the multi-source
    /// [`chancela_cae::obtain_from_chain`] pipeline over in-memory `Bytes`/`File` sources without a
    /// network. Called fresh per request (so `?source` pinning can consume it). `None` in production.
    #[allow(clippy::type_complexity)]
    pub cae_chain_factory: Option<Arc<dyn Fn() -> CaeSourceChain + Send + Sync>>,
    /// Test/DI seam (§cae-v2 no-config default): the chain `POST /v1/cae/refresh` runs when *nothing*
    /// is configured (no `cae_sources`, `cae_official_source` off, no `cae_update_url`/`CHANCELA_CAE_URL`,
    /// no `?source` pin) — the "no URL ⇒ obtain from the official gov artifacts" fallback. `None` in
    /// production, where it is [`chancela_cae::default_official_chain`] (the digest-pinned Diário da
    /// República diploma pair); tests inject a fixture DR pair here to exercise the substitution
    /// without a network. Called fresh per request. Mirrors `cae_chain_factory`.
    #[allow(clippy::type_complexity)]
    pub cae_default_chain_factory: Option<Arc<dyn Fn() -> CaeSourceChain + Send + Sync>>,
    /// Test/DI seam: when set, `GET /v1/cae/updates` points its [`chancela_cae::SmiSource`] at this
    /// base URL instead of the official INE SMI host, so the real `fetch_catalog` decode+parse path
    /// runs against an in-process fixture server without hitting the network. `None` in production
    /// (mirrors `law_pdf_base_override`).
    pub smi_base_override: Option<Arc<String>>,
    /// Named user profiles for actor attribution (contract §2.8), keyed by [`UserId`]. `Default`
    /// empty; `with_data_dir`/`from_env` load `users.json`.
    pub users: Arc<RwLock<HashMap<UserId, User>>>,
    /// Where `users.json` is persisted, or `None` for in-memory profiles. Mirrors `persist_path`.
    pub users_path: Option<Arc<PathBuf>>,
    /// In-memory session tokens → the [`SessionEntry`](session::SessionEntry) they open: the
    /// user, plus (when the user signed in with a password and holds an attestation key) the
    /// decrypted signing key held for the life of the session. Reset on restart; the unlocked key
    /// never persists and never leaves the process (plan t29 §4.4).
    pub sessions: Arc<RwLock<HashMap<String, session::SessionEntry>>>,
    /// In-memory audit-attestation sidecar (plan t29 §2/§4.4): ledger `seq` → the per-event
    /// signature produced by the signed-in user's unlocked key. Kept out of the `chancela-ledger`
    /// crate and, like the in-memory ledger, **resets on restart** (a persisted attestation would
    /// orphan against a reused `seq`). Bound to the chain by the event `hash` it signs.
    pub attestations: Arc<RwLock<HashMap<u64, attestation::Attestation>>>,
    /// Per-user sign-in backoff (plan t29 §4.5): a naive in-memory speed-bump against repeated
    /// wrong-password attempts. Resets on restart; not a hardened anti-brute-force.
    pub signin_backoff: Arc<RwLock<HashMap<UserId, session::Backoff>>>,
    /// The law archive's directory (`<data_dir>/laws`), or `None` for in-memory (no persistence).
    /// Mirrors `users_path`; set only by [`AppState::with_data_dir`]/[`AppState::from_env`].
    pub laws_dir: Option<Arc<PathBuf>>,
    /// The law-archive store state (per-diploma stored PDF metadata). `Default` empty;
    /// `with_data_dir`/`from_env` load `laws/manifest-state.json`.
    pub law_store: Arc<RwLock<law::LawStore>>,
    /// Test/DI seam: when set, `POST /v1/law/{id}/fetch` downloads from `<base>/<id>.pdf` instead
    /// of the manifest's pinned `pdf_url`, so tests exercise the real download path against an
    /// in-process fixture server. `None` in production (mirrors `registry`/`cae_source`).
    pub law_pdf_base_override: Option<Arc<String>>,
    /// The durable system of record (t30): the SQLite store backing `entities`/`books`/`acts`/
    /// `registry_extracts` and the ledger's `events` table. `None` = pure in-memory (the current
    /// behaviour, byte-identical). Set only by [`AppState::with_data_dir`]/[`AppState::from_env`];
    /// every mutation write-through goes through [`AppState::persist_write_through`].
    pub store: Option<Store>,
    /// The boot-time chain-verification outcome recorded by [`AppState::with_data_dir`] when the
    /// durable ledger was rehydrated (§D-boot): `Some(Ok(len))` for an intact chain, `Some(Err(..))`
    /// for a broken one (surfaced on `/health` + the startup banner), `None` in-memory. Shared via
    /// `Arc` so cloning the state stays cheap.
    pub chain_status: Option<Arc<Result<u64, LedgerError>>>,
}

impl AppState {
    /// Build state whose settings are read from — and written back to — `data_dir/settings.json`.
    ///
    /// A missing or unreadable file yields the default settings (the directory is created lazily
    /// on the first successful `PUT`); a present-but-malformed file also falls back to defaults
    /// with a warning, so a bad file never blocks startup. All other state stays in-memory.
    pub fn with_data_dir(data_dir: impl Into<PathBuf>) -> Self {
        let dir = data_dir.into();
        let settings_path = dir.join(settings::SETTINGS_FILE);
        let loaded = settings::load_settings(&settings_path).unwrap_or_default();
        let users_path = dir.join(users::USERS_FILE);
        let loaded_users = users::load_users(&users_path).unwrap_or_default();
        // Prefer a valid, newer `cae-catalog.json` cache over the embedded catalog (never errors).
        let catalog = chancela_cae::load_catalog(Some(&dir));
        // Law archive: the `laws/` subdir plus its state file (missing/malformed → empty archive).
        let laws_dir = dir.join(law::LAWS_DIR);
        let law_store = law::load_law_store(&laws_dir);
        let mut state = AppState {
            settings: Arc::new(RwLock::new(loaded)),
            persist_path: Some(Arc::new(settings_path)),
            users: Arc::new(RwLock::new(loaded_users)),
            users_path: Some(Arc::new(users_path)),
            cae: Arc::new(RwLock::new(catalog)),
            laws_dir: Some(Arc::new(laws_dir)),
            law_store: Arc::new(RwLock::new(law_store)),
            ..AppState::default()
        };

        // Durable system of record (t30): open the SQLite store and rehydrate the domain
        // aggregates + the hash-chained ledger from it. A store that fails to open or load falls
        // back to pure in-memory (`store` stays `None`) with a loud warning — durability is never
        // allowed to block startup (plan §D-boot); a broken but readable chain still boots and is
        // surfaced via `chain_status` (banner + `/health`).
        match Store::open(&dir) {
            Ok(store) => match store.load() {
                Ok(loaded) => {
                    if let Err(e) = &loaded.chain_status {
                        eprintln!(
                            "chancela-store: ledger chain integrity check FAILED on boot ({e}) — \
                             starting anyway so the operator can inspect and restore from backup"
                        );
                    }
                    state.entities = Arc::new(RwLock::new(loaded.entities));
                    state.books = Arc::new(RwLock::new(loaded.books));
                    state.acts = Arc::new(RwLock::new(loaded.acts));
                    state.registry_extracts = Arc::new(RwLock::new(loaded.registry_extracts));
                    state.ledger = Arc::new(RwLock::new(loaded.ledger));
                    state.chain_status = Some(Arc::new(loaded.chain_status));
                    state.store = Some(store);
                }
                Err(e) => eprintln!(
                    "chancela-store: failed to load durable state from {} ({e}) — running \
                     in-memory (the domain will NOT persist across restart)",
                    dir.display()
                ),
            },
            Err(e) => eprintln!(
                "chancela-store: failed to open the durable store at {} ({e}) — running in-memory \
                 (the domain will NOT persist across restart)",
                dir.display()
            ),
        }

        state
    }

    /// Durable write-through (t30 §D2): persist the last `event_count` events just appended to
    /// `ledger`, together with any changed store-owned aggregates (via `upserts`), in one SQLite
    /// transaction. A **no-op** when the state is in-memory (`store` is `None`) — the current
    /// behaviour, byte-identical.
    ///
    /// Call this while holding the ledger write lock, immediately after `ledger.append(..)`, so the
    /// store write happens under the ledger lock and no `seq` can interleave. On a store failure the
    /// just-appended events are rolled back out of the in-memory `ledger` (rebuilt without them, so
    /// memory matches the untouched durable chain) and a `500` error is returned; the caller must
    /// then **not** commit its aggregate change to the in-memory maps. This keeps memory and disk
    /// from ever diverging (the plan's ruling).
    fn persist_write_through(
        &self,
        ledger: &mut Ledger,
        event_count: usize,
        upserts: impl FnOnce(&Tx<'_>) -> Result<(), StoreError>,
    ) -> Result<(), ApiError> {
        let Some(store) = &self.store else {
            return Ok(());
        };
        let len = ledger.len();
        // The events just appended are the tail of the chain; persist them plus the changed
        // aggregates atomically (one commits-or-rolls-back transaction).
        let events: Vec<Event> = ledger.events()[len - event_count..].to_vec();
        if let Err(e) = store.persist(|tx| {
            for event in &events {
                tx.append_event(event)?;
            }
            upserts(tx)
        }) {
            // Roll the in-memory ledger back to match the (unchanged) durable chain on disk.
            let kept: Vec<Event> = ledger.events()[..len - event_count].to_vec();
            *ledger = Ledger::try_from_events(kept).0;
            return Err(ApiError::Internal(format!(
                "failed to persist to the durable store: {e}"
            )));
        }
        Ok(())
    }

    /// Attest the most recently appended ledger event with the request's unlocked key, if it
    /// carries one (plan t29 §4.4). Best-effort enrichment: a signing failure is logged and
    /// skipped, never blocking the mutation. Call **after** [`persist_write_through`] has
    /// committed (so a rolled-back event is not attested); the tail event is the one just
    /// appended. The attestation sidecar is an independent lock, acquired last.
    async fn attest_latest(&self, attestor: &CurrentAttestor, ledger: &Ledger) {
        let Some((username, key)) = attestor.signer() else {
            return;
        };
        let Some(event) = ledger.events().last() else {
            return;
        };
        match attestation::sign_event(key, username, event) {
            Some(att) => {
                self.attestations.write().await.insert(att.event_seq, att);
            }
            None => eprintln!(
                "attestation: failed to sign event seq {} for {username}; continuing",
                event.seq
            ),
        }
    }

    /// The data directory backing on-disk persistence, or `None` for in-memory state. Derived
    /// from `persist_path` (the settings file's parent) so the CAE refresh writes its cache into
    /// the same directory `with_data_dir` seeded the catalog from.
    fn data_dir(&self) -> Option<PathBuf> {
        self.persist_path
            .as_ref()
            .and_then(|p| p.parent().map(PathBuf::from))
    }

    /// Resolve on-disk persistence from the environment, mirroring how `chancela-server` finds
    /// the web build: honour `CHANCELA_DATA_DIR` first, else walk up from the current directory
    /// for an existing `chancela-data/` directory, else run purely in memory.
    ///
    /// This is the one call a binary swaps in for [`AppState::default`] to gain persistence.
    pub fn from_env() -> Self {
        match Self::resolve_data_dir() {
            Some(dir) => Self::with_data_dir(dir),
            None => Self::default(),
        }
    }

    /// The data directory `from_env` would use, or `None` for in-memory. Exposed so a binary can
    /// report the resolved path in its startup banner.
    pub fn resolve_data_dir() -> Option<PathBuf> {
        if let Ok(raw) = std::env::var(DATA_DIR_ENV) {
            if !raw.trim().is_empty() {
                return Some(PathBuf::from(raw));
            }
        }
        let start = std::env::current_dir().ok()?;
        for base in start.ancestors() {
            let candidate = base.join("chancela-data");
            if candidate.is_dir() {
                return Some(candidate);
            }
        }
        None
    }
}

/// Build the v1 API router over the supplied [`AppState`].
///
/// The returned router carries `/health` and the `/v1/*` endpoints only. Use [`app`] to also
/// serve the web UI. The router is fully wired and can be served by a listener or exercised
/// in tests via `tower::ServiceExt::oneshot`.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route(
            "/v1/entities",
            get(entities::list_entities).post(entities::create_entity),
        )
        .route(
            "/v1/entities/{id}",
            get(entities::get_entity).patch(entities::patch_entity),
        )
        .route(
            "/v1/entities/import-from-registry",
            post(registry::import_from_registry),
        )
        .route(
            "/v1/entities/{id}/registry",
            get(registry::get_entity_registry),
        )
        .route(
            "/v1/entities/{id}/registry/import",
            post(registry::import_into_entity),
        )
        .route("/v1/registry/lookup", post(registry::registry_lookup))
        .route("/v1/books", get(books::list_books).post(books::create_book))
        .route("/v1/books/{id}", get(books::get_book))
        .route("/v1/books/{id}/close", post(books::close_book))
        .route("/v1/books/{id}/acts", get(books::list_book_acts))
        .route("/v1/acts", post(acts::draft_act))
        .route("/v1/acts/{id}", get(acts::get_act).patch(acts::patch_act))
        .route("/v1/acts/{id}/advance", post(acts::advance_act))
        .route("/v1/acts/{id}/compliance", get(acts::get_compliance))
        .route("/v1/acts/{id}/seal", post(acts::seal_act_handler))
        .route("/v1/acts/{id}/archive", post(acts::archive_act))
        .route("/v1/ledger/events", get(ledger::list_ledger_events))
        .route("/v1/ledger/verify", get(ledger::verify_ledger))
        .route("/v1/dashboard", get(dashboard::dashboard))
        .route("/v1/backup", post(backup::create_backup))
        .route(
            "/v1/settings",
            get(settings::get_settings).put(settings::put_settings),
        )
        .route("/v1/cae", get(cae::list_cae))
        .route("/v1/cae/refresh", post(cae::refresh_cae))
        .route("/v1/cae/updates", get(cae::cae_updates))
        .route("/v1/cae/sections", get(cae::list_sections))
        .route("/v1/cae/{code}", get(cae::get_cae))
        .route("/v1/cae/{code}/children", get(cae::list_children))
        .route("/v1/law", get(law::list_law))
        .route("/v1/law/{id}/fetch", post(law::fetch_law))
        .route(
            "/v1/law/{id}/pdf",
            get(law::get_law_pdf).delete(law::delete_law_pdf),
        )
        .route("/v1/users", get(users::list_users).post(users::create_user))
        .route(
            "/v1/users/{id}",
            get(users::get_user).patch(users::patch_user),
        )
        .route(
            "/v1/users/{id}/secret",
            post(users::set_secret).delete(users::remove_secret),
        )
        .route(
            "/v1/users/{id}/attestation-key",
            post(users::generate_attestation_key).delete(users::remove_attestation_key),
        )
        .route(
            "/v1/ledger/attestations/{seq}",
            get(ledger::get_attestation),
        )
        .route(
            "/v1/session",
            get(session::get_session)
                .post(session::create_session)
                .delete(session::delete_session),
        )
        // Own the entire `/v1` and `/health` namespaces: any unmatched path under them is a
        // JSON 404, never a fall-through. Registered as low-priority catch-alls (matchit ranks
        // the specific routes above them), so a stale binary or a typo'd path can never reach
        // the SPA fallback in [`app`] and hand the web client `index.html` where it expects
        // JSON (the "Unexpected token '<'" failure). Non-API paths keep the SPA fallback.
        .route("/v1", any(unknown_api_route))
        .route("/v1/{*rest}", any(unknown_api_route))
        .route("/health/{*rest}", any(unknown_api_route))
        // Security response headers (t41 M2).
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

/// Middleware that sets security response headers on every response (t41 M2).
async fn security_headers(request: axum::http::Request<axum::body::Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        axum::http::header::X_CONTENT_TYPE_OPTIONS,
        "nosniff".parse().unwrap(),
    );
    headers.insert(axum::http::header::X_FRAME_OPTIONS, "DENY".parse().unwrap());
    headers.insert(
        axum::http::HeaderName::from_static("referrer-policy"),
        "no-referrer".parse().unwrap(),
    );
    headers.insert(
        axum::http::HeaderName::from_static("content-security-policy"),
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; \
         script-src 'self'; object-src 'none'; base-uri 'self'"
            .parse()
            .unwrap(),
    );
    response
}

/// Fallback for any unmatched path under an API namespace (`/v1`, `/v1/*`, `/health/*`).
///
/// Returns `404 {"error": "unknown API route: <method> <path>"}` so a client that reached a
/// route the running binary does not serve — e.g. a UI newer than a stale server — gets a
/// diagnosable JSON error instead of the single-page-app shell (see [`app`]).
async fn unknown_api_route(method: axum::http::Method, uri: axum::http::Uri) -> Response {
    let body = serde_json::json!({
        "error": format!("unknown API route: {} {}", method, uri.path()),
    });
    (StatusCode::NOT_FOUND, Json(body)).into_response()
}

/// Build the full application router: the [`router`] API plus, optionally, the web UI.
///
/// The API routes always take priority. When `web_dist` is `Some(dir)`, everything else is
/// served from that directory as a single-page app — files resolve to their contents and any
/// unmatched, non-API path falls back to `index.html` so client-side routing works. When it
/// is `None`, the server runs API-only and unmatched paths get a short landing message
/// explaining how to build the UI (see [`landing`]).
pub fn app(state: AppState, web_dist: Option<PathBuf>) -> Router {
    let api = router(state);
    match web_dist {
        Some(dir) => {
            // ServeDir handles real files; its own fallback returns index.html for anything
            // it can't find, which is exactly SPA deep-link behaviour.
            let serve = ServeDir::new(&dir).fallback(ServeFile::new(dir.join("index.html")));
            api.fallback_service(serve)
        }
        None => api.fallback(landing),
    }
}

/// API-only fallback served at `/` (and any unmatched path) when no web build is present.
///
/// Plain text so it reads cleanly in a browser and in `curl`; it points the operator at the
/// one command needed to get the UI, and lists the live API endpoints so the server is still
/// self-describing without a UI.
async fn landing() -> Response {
    let body = concat!(
        "Chancela API is running (web UI not built).\n",
        "\n",
        "To serve the web interface, build it once:\n",
        "    npm run build --workspace apps/web\n",
        "then restart the server.\n",
        "\n",
        "Available API endpoints:\n",
        "    GET  /health\n",
        "    GET  /v1/entities\n",
        "    POST /v1/entities\n",
        "    GET  /v1/entities/{id}\n",
        "    GET  /v1/books\n",
        "    POST /v1/books\n",
        "    GET  /v1/acts/{id}\n",
        "    POST /v1/acts\n",
        "    GET  /v1/ledger/events\n",
        "    GET  /v1/ledger/verify\n",
        "    GET  /v1/dashboard\n",
    );
    (
        StatusCode::OK,
        [("content-type", "text/plain; charset=utf-8")],
        body,
    )
        .into_response()
}

/// Body of `GET /health`. The `persistent`/`ledger_*`/`store_schema_version` fields are additive
/// (t30 §3.3): older clients and the web version-check tolerate the extra keys.
#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    version: &'static str,
    /// Whether the server is backed by the durable on-disk store (t30). `false` = in-memory.
    persistent: bool,
    /// Number of events currently in the ledger.
    ledger_length: u64,
    /// The boot-time chain-verification outcome: `true`/`false` when persistent (the durable chain
    /// was verified as it loaded), `null` in-memory (nothing was loaded to verify). Gives the web a
    /// signal for a future "chain verified / BROKEN — restore" banner.
    ledger_verified: Option<bool>,
    /// The store schema version, present only when persistent.
    #[serde(skip_serializing_if = "Option::is_none")]
    store_schema_version: Option<i64>,
}

/// Liveness probe; also reports the running crate version (used by the Docker healthcheck) and,
/// additively, the durability/ledger signal (t30 §3.3).
async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    let persistent = state.store.is_some();
    let ledger_length = state.ledger.read().await.len() as u64;
    let ledger_verified = state.chain_status.as_ref().map(|status| status.is_ok());
    let store_schema_version = persistent.then_some(chancela_store::schema::SCHEMA_VERSION);
    Json(HealthResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
        persistent,
        ledger_length,
        ledger_verified,
        store_schema_version,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode};
    use serde_json::{Value, json};
    use tower::ServiceExt; // for `oneshot`
    use uuid::Uuid;

    /// Send one request through a fresh router and return (status, parsed JSON body).
    /// Does NOT auto-seed a session — used by [`send`] and [`auth_token`] internally, and by
    /// tests that check auth rejection (401 without a session).
    async fn send_raw(state: AppState, req: Request<Body>) -> (StatusCode, Value) {
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

    /// Like [`send_raw`] but auto-seeds a session token for requests that don't carry one (t41:
    /// all mutation endpoints now require auth). For GET requests the extra header is harmless;
    /// for mutations it satisfies the fallible `CurrentActor` extractor. Tests that specifically
    /// check auth rejection (401 without a session) use [`send_raw`] directly.
    async fn send(state: AppState, req: Request<Body>) -> (StatusCode, Value) {
        if req.headers().get("x-chancela-session").is_none() {
            let token = auth_token(&state).await;
            send_raw(state, with_session(req, &token)).await
        } else {
            send_raw(state, req).await
        }
    }

    /// Auto-seeding variant kept for potential future use.
    #[allow(dead_code)]
    async fn send_mut(state: AppState, req: Request<Body>) -> (StatusCode, Value) {
        send(state, req).await
    }

    fn get(uri: &str) -> Request<Body> {
        Request::builder()
            .uri(uri)
            .body(Body::empty())
            .expect("request builds")
    }

    fn body_json(method: &str, uri: &str, body: Value) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("request builds")
    }

    fn post_json(uri: &str, body: Value) -> Request<Body> {
        body_json("POST", uri, body)
    }

    fn patch_json(uri: &str, body: Value) -> Request<Body> {
        body_json("PATCH", uri, body)
    }

    /// A request builder carrying an `X-Chancela-Session` token.
    fn with_session(mut req: Request<Body>, token: &str) -> Request<Body> {
        req.headers_mut().insert(
            "x-chancela-session",
            token.parse().expect("valid header value"),
        );
        req
    }

    /// Seed a test user + session directly into the state (bypassing the API) and return the
    /// token (t41: all mutation endpoints require auth). This avoids creating `user.created`
    /// ledger events and extra users in lists — the test's own mutations are the only ones
    /// recorded. The user is passwordless and active.
    async fn auth_token(state: &AppState) -> String {
        use crate::users::{User, UserId};
        use time::format_description::well_known::Rfc3339;
        let uid = UserId(Uuid::new_v4());
        let user = User {
            id: uid,
            username: "test.actor".to_owned(),
            display_name: "Test Actor".to_owned(),
            created_at: time::OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .unwrap_or_default(),
            active: true,
            password_hash: None,
            attestation_key: None,
        };
        state.users.write().await.insert(uid, user);
        let token = Uuid::new_v4().to_string();
        let now = time::OffsetDateTime::now_utc();
        state.sessions.write().await.insert(
            token.clone(),
            crate::session::SessionEntry {
                user_id: uid,
                unlocked_key: None,
                expires_at: now + time::Duration::seconds(crate::actor::SESSION_TTL_SECS),
            },
        );
        token
    }

    /// Create an entity and an open book for it; returns (state, entity_id, book_id).
    async fn entity_and_open_book(kind: &str) -> (AppState, String, String) {
        let state = AppState::default();
        let token = auth_token(&state).await;
        let (status, entity) = send(
            state.clone(),
            with_session(
                post_json(
                    "/v1/entities",
                    json!({
                        "name": "Encosto Estratégico, S.A.",
                        "nipc": "503004642",
                        "seat": "Lisboa",
                        "kind": kind,
                    }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let entity_id = entity["id"].as_str().expect("entity id").to_owned();

        let (status, book) = send(
            state.clone(),
            with_session(
                post_json(
                    "/v1/books",
                    json!({
                        "entity_id": entity_id,
                        "kind": "AssembleiaGeral",
                        "purpose": "livro de atas da assembleia geral",
                        "opening_date": "2026-01-15",
                        "required_signatories": ["Administrador"],
                    }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(book["state"], "Open");
        let book_id = book["id"].as_str().expect("book id").to_owned();
        (state, entity_id, book_id)
    }

    #[tokio::test]
    async fn health_returns_ok_and_version() {
        let (status, body) = send(AppState::default(), get("/health")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "ok");
        assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
    }

    #[tokio::test]
    async fn create_then_get_entity_round_trips() {
        let state = AppState::default();
        let create = post_json(
            "/v1/entities",
            json!({
                "name": "Encosto Estratégico, S.A.",
                "nipc": "503004642",
                "seat": "Lisboa",
                "kind": "SociedadeAnonima",
            }),
        );
        let (status, created) = send(state.clone(), create).await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(created["name"], "Encosto Estratégico, S.A.");
        assert_eq!(created["family"], "CommercialCompany");
        let id = created["id"].as_str().expect("id is a string").to_owned();

        let (status, fetched) = send(state.clone(), get(&format!("/v1/entities/{id}"))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(fetched, created);

        let (status, list) = send(state, get("/v1/entities")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(list.as_array().expect("list is array").len(), 1);
    }

    #[tokio::test]
    async fn invalid_nipc_is_rejected_with_422() {
        let create = post_json(
            "/v1/entities",
            json!({
                "name": "Bad NIPC, Lda.",
                "nipc": "111111111",
                "seat": "Porto",
                "kind": "SociedadePorQuotas",
            }),
        );
        let (status, body) = send(AppState::default(), create).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(body["error"].is_string());
    }

    #[tokio::test]
    async fn missing_entity_returns_404() {
        let missing = Uuid::new_v4();
        let (status, _) = send(AppState::default(), get(&format!("/v1/entities/{missing}"))).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn entity_view_carries_nipc_validated_true_for_a_valid_nipc() {
        // A validated NIPC serializes as a bare string with an explicit `nipc_validated: true`.
        let state = AppState::default();
        let (status, created) = send(
            state.clone(),
            post_json(
                "/v1/entities",
                json!({
                    "name": "Encosto Estratégico, S.A.",
                    "nipc": "503004642",
                    "seat": "Lisboa",
                    "kind": "SociedadeAnonima",
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(created["nipc"], "503004642");
        assert_eq!(created["nipc_validated"], true);
        let id = created["id"].as_str().expect("id").to_owned();

        // GET and the list both expose the same stable shape.
        let (_, got) = send(state.clone(), get(&format!("/v1/entities/{id}"))).await;
        assert_eq!(got["nipc"], "503004642");
        assert_eq!(got["nipc_validated"], true);
        let (_, list) = send(state, get("/v1/entities")).await;
        assert_eq!(list[0]["nipc_validated"], true);
    }

    #[tokio::test]
    async fn override_stores_an_invalid_nipc_unvalidated() {
        // With the override, a NIPC that fails validation is stored raw and flagged unvalidated
        // instead of being rejected — the foreign/legacy-entity affordance.
        let state = AppState::default();
        let (status, created) = send(
            state.clone(),
            post_json(
                "/v1/entities",
                json!({
                    "name": "Foreign Holding Ltd",
                    "nipc": "GB-12345",
                    "seat": "London",
                    "kind": "SociedadeAnonima",
                    "allow_invalid_nipc": true,
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        // The raw identifier is preserved verbatim as a bare string, flagged unvalidated.
        assert_eq!(created["nipc"], "GB-12345");
        assert_eq!(created["nipc_validated"], false);
        let id = created["id"].as_str().expect("id").to_owned();

        // It is queryable with the same stable shape.
        let (status, got) = send(state.clone(), get(&format!("/v1/entities/{id}"))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(got["nipc"], "GB-12345");
        assert_eq!(got["nipc_validated"], false);

        // The override is recorded on the entity.created audit event.
        let (_, events) = send(state, get("/v1/ledger/events")).await;
        let created_event = events
            .as_array()
            .expect("events")
            .iter()
            .find(|e| e["kind"] == "entity.created")
            .expect("entity.created present");
        assert_eq!(
            created_event["justification"],
            "nipc validation overridden (stored unvalidated)"
        );
    }

    #[tokio::test]
    async fn override_flag_does_not_downgrade_a_valid_nipc() {
        // A NIPC that parses is always stored validated, even with the override flag set.
        let (status, created) = send(
            AppState::default(),
            post_json(
                "/v1/entities",
                json!({
                    "name": "Encosto Estratégico, S.A.",
                    "nipc": "503004642",
                    "seat": "Lisboa",
                    "kind": "SociedadeAnonima",
                    "allow_invalid_nipc": true,
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(created["nipc"], "503004642");
        assert_eq!(created["nipc_validated"], true);
    }

    #[tokio::test]
    async fn invalid_nipc_without_override_is_still_422() {
        // The default path is byte-identical to before: an invalid NIPC is rejected.
        let (status, body) = send(
            AppState::default(),
            post_json(
                "/v1/entities",
                json!({
                    "name": "Bad NIPC, Lda.",
                    "nipc": "GB-12345",
                    "seat": "Porto",
                    "kind": "SociedadePorQuotas",
                    "allow_invalid_nipc": false,
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(body["error"].is_string());
    }

    #[tokio::test]
    async fn unvalidated_nipc_entity_warns_and_seals_only_when_acknowledged() {
        // The LEG-05 warning-acknowledgement path, driven over HTTP: an entity whose NIPC was
        // stored via the override raises the CSC-63/nipc-unvalidated Warning on its acts. The
        // warning does not block by itself, but sealing requires it to be acknowledged.
        let state = AppState::default();
        let (status, entity) = send(
            state.clone(),
            post_json(
                "/v1/entities",
                json!({
                    "name": "Foreign Holding Ltd",
                    "nipc": "GB-12345",
                    "seat": "London",
                    "kind": "SociedadeAnonima",
                    "allow_invalid_nipc": true,
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let entity_id = entity["id"].as_str().expect("entity id").to_owned();

        let (status, book) = send(
            state.clone(),
            post_json(
                "/v1/books",
                json!({
                    "entity_id": entity_id,
                    "kind": "AssembleiaGeral",
                    "purpose": "livro de atas da assembleia geral",
                    "opening_date": "2026-01-15",
                    "required_signatories": ["Administrador"],
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let book_id = book["id"].as_str().expect("book id").to_owned();

        // Draft, fill mandatory contents, and advance to Signing so nothing but the NIPC warning
        // stands between the act and a seal.
        let (_, act) = send(
            state.clone(),
            post_json(
                "/v1/acts",
                json!({ "book_id": book_id, "title": "Ata da AG anual", "channel": "Physical" }),
            ),
        )
        .await;
        let act_id = act["id"].as_str().expect("act id").to_owned();
        let (status, _) = send(
            state.clone(),
            patch_json(
                &format!("/v1/acts/{act_id}"),
                json!({
                    "meeting_date": "2026-03-30",
                    "meeting_time": "10:00",
                    "place": "Sede social",
                    "mesa": { "presidente": "Ana Presidente", "secretarios": ["Rui Secretário"] },
                    "agenda": [{ "number": 1, "text": "Contas" }],
                    "attendance_reference": "Lista de presenças",
                    "deliberations": "Aprovadas as contas do exercício.",
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        for to in [
            "Review",
            "Convened",
            "Deliberated",
            "TextApproved",
            "Signing",
        ] {
            let (status, _) = send(
                state.clone(),
                post_json(&format!("/v1/acts/{act_id}/advance"), json!({ "to": to })),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
        }

        // Compliance surfaces the NIPC warning but is not error-blocked: seal is allowed once the
        // warning is acknowledged. With the mesa now filled, the NIPC warning is the only finding.
        let (status, comp) =
            send(state.clone(), get(&format!("/v1/acts/{act_id}/compliance"))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(comp["errors"], 0);
        assert!(comp["warnings"].as_u64().expect("warnings count") >= 1);
        assert_eq!(comp["seal_allowed"], true);
        let issues = comp["issues"].as_array().expect("issues");
        assert!(
            issues
                .iter()
                .any(|i| i["rule_id"] == "CSC-63/nipc-unvalidated" && i["severity"] == "Warning"),
            "the unvalidated-NIPC warning is present: {issues:?}"
        );

        // Sealing without acknowledging the warning is refused (409) with the warning surfaced.
        let (status, body) = send(
            state.clone(),
            post_json(&format!("/v1/acts/{act_id}/seal"), json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        let warnings = body["warnings"].as_array().expect("warnings");
        assert!(
            warnings
                .iter()
                .any(|w| w["rule_id"] == "CSC-63/nipc-unvalidated"),
            "seal refusal carries the warning: {warnings:?}"
        );

        // Acknowledging the warning seals the act.
        let (status, sealed) = send(
            state,
            post_json(
                &format!("/v1/acts/{act_id}/seal"),
                json!({ "acknowledge_warnings": true }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(sealed["act"]["state"], "Sealed");
        assert!(
            sealed["acknowledged_warnings"]
                .as_array()
                .expect("acknowledged")
                .iter()
                .any(|w| w["rule_id"] == "CSC-63/nipc-unvalidated"),
            "the acknowledged warning is echoed back"
        );
    }

    #[tokio::test]
    async fn full_lifecycle_happy_path() {
        let (state, _entity_id, book_id) = entity_and_open_book("SociedadeAnonima").await;

        // Draft an act into the open book.
        let (status, act) = send(
            state.clone(),
            post_json(
                "/v1/acts",
                json!({ "book_id": book_id, "title": "Ata da AG anual", "channel": "Physical" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(act["state"], "Draft");
        let act_id = act["id"].as_str().expect("act id").to_owned();

        // PATCH the working content — including the mesa/time/agenda now that the wire carries
        // them (t31); no ledger event is appended for this.
        let (status, patched) = send(
            state.clone(),
            patch_json(
                &format!("/v1/acts/{act_id}"),
                json!({
                    "meeting_date": "2026-03-30",
                    "meeting_time": "10:00",
                    "place": "Sede social",
                    "mesa": { "presidente": "Ana Presidente", "secretarios": ["Rui Secretário"] },
                    "agenda": [{ "number": 1, "text": "Aprovação das contas do exercício" }],
                    "attendance_reference": "Lista de presenças",
                    "deliberations": "Aprovadas as contas do exercício.",
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(patched["meeting_date"], "2026-03-30");
        assert_eq!(patched["meeting_time"], "10:00");
        assert_eq!(patched["place"], "Sede social");
        assert_eq!(patched["mesa"]["presidente"], "Ana Presidente");

        // Advance through the lifecycle to Signing.
        for to in [
            "Review",
            "Convened",
            "Deliberated",
            "TextApproved",
            "Signing",
        ] {
            let (status, advanced) = send(
                state.clone(),
                post_json(&format!("/v1/acts/{act_id}/advance"), json!({ "to": to })),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "advance to {to}");
            assert_eq!(advanced["state"], to);
        }

        // A fully-filled CSC v2 ata (mesa, time, agenda all set) has no findings at all, so
        // sealing is allowed with no acknowledgement. The dispatched pack is the CSC family pack.
        let (status, comp) =
            send(state.clone(), get(&format!("/v1/acts/{act_id}/compliance"))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(comp["rule_pack"], "csc-art63/v2");
        assert_eq!(comp["family"], "CommercialCompany");
        assert_eq!(comp["statute_overlay"], false);
        assert_eq!(comp["errors"], 0);
        assert_eq!(comp["warnings"], 0);
        assert_eq!(comp["seal_allowed"], true);

        // Seal — no warnings to acknowledge.
        let (status, sealed) = send(
            state.clone(),
            post_json(&format!("/v1/acts/{act_id}/seal"), json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(sealed["ata_number"], 1);
        assert_eq!(sealed["act"]["state"], "Sealed");
        assert_eq!(
            sealed["payload_digest"].as_str().expect("hex digest").len(),
            64
        );

        // The act now reads as Sealed with its ata number.
        let (status, got) = send(state.clone(), get(&format!("/v1/acts/{act_id}"))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(got["state"], "Sealed");
        assert_eq!(got["ata_number"], 1);

        // The ledger holds the whole chain.
        let (status, events) = send(state.clone(), get("/v1/ledger/events")).await;
        assert_eq!(status, StatusCode::OK);
        let kinds: Vec<&str> = events
            .as_array()
            .expect("events array")
            .iter()
            .map(|e| e["kind"].as_str().expect("kind"))
            .collect();
        assert!(kinds.contains(&"book.opened"));
        assert!(kinds.contains(&"act.drafted"));
        assert!(kinds.contains(&"act.advanced"));
        assert!(kinds.contains(&"act.sealed"));

        // The dashboard reflects the sealed ata.
        let (status, dash) = send(state.clone(), get("/v1/dashboard")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(dash["entities"], 1);
        assert_eq!(dash["books_total"], 1);
        assert_eq!(dash["books_open"], 1);
        assert_eq!(dash["acts_total"], 1);
        assert_eq!(dash["acts_sealed"], 1);
        assert_eq!(dash["ledger_valid"], true);

        // The book's acts feed lists the sealed ata.
        let (status, book_acts) = send(state, get(&format!("/v1/books/{book_id}/acts"))).await;
        assert_eq!(status, StatusCode::OK);
        let arr = book_acts.as_array().expect("acts array");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["ata_number"], 1);
    }

    #[tokio::test]
    async fn draft_in_non_open_book_is_409() {
        let (state, _entity_id, book_id) = entity_and_open_book("SociedadeAnonima").await;

        // Close the book so it is no longer open.
        let (status, _) = send(
            state.clone(),
            post_json(
                &format!("/v1/books/{book_id}/close"),
                json!({
                    "reason": "BookFull",
                    "closing_date": "2026-12-31",
                    "required_signatories": ["Administrador"],
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // Drafting into a closed book is refused.
        let (status, body) = send(
            state,
            post_json(
                "/v1/acts",
                json!({ "book_id": book_id, "title": "Tardio", "channel": "Physical" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(body["error"].is_string());
    }

    #[tokio::test]
    async fn seal_with_missing_contents_is_422_with_issues() {
        let (state, _entity_id, book_id) = entity_and_open_book("SociedadeAnonima").await;

        // Draft an empty act and push it to Signing without filling the mandatory contents.
        let (_, act) = send(
            state.clone(),
            post_json(
                "/v1/acts",
                json!({ "book_id": book_id, "title": "Vazia", "channel": "Physical" }),
            ),
        )
        .await;
        let act_id = act["id"].as_str().expect("act id").to_owned();
        for to in [
            "Review",
            "Convened",
            "Deliberated",
            "TextApproved",
            "Signing",
        ] {
            let (status, _) = send(
                state.clone(),
                post_json(&format!("/v1/acts/{act_id}/advance"), json!({ "to": to })),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
        }

        let (status, body) = send(
            state,
            post_json(&format!("/v1/acts/{act_id}/seal"), json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        let issues = body["issues"].as_array().expect("issues array");
        assert!(!issues.is_empty());
        assert!(issues.iter().all(|i| i["severity"] == "Error"));
    }

    #[tokio::test]
    async fn seal_when_not_signing_is_409() {
        let (state, _entity_id, book_id) = entity_and_open_book("SociedadeAnonima").await;
        let (_, act) = send(
            state.clone(),
            post_json(
                "/v1/acts",
                json!({ "book_id": book_id, "title": "Rascunho", "channel": "Physical" }),
            ),
        )
        .await;
        let act_id = act["id"].as_str().expect("act id").to_owned();

        // Sealing a Draft act (never advanced to Signing) is refused with a conflict.
        let (status, body) = send(
            state,
            post_json(&format!("/v1/acts/{act_id}/seal"), json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(body["error"].is_string());
    }

    #[tokio::test]
    async fn close_non_open_book_is_409() {
        let (state, _entity_id, book_id) = entity_and_open_book("SociedadeAnonima").await;
        let close = || {
            post_json(
                &format!("/v1/books/{book_id}/close"),
                json!({
                    "reason": "BookFull",
                    "closing_date": "2026-12-31",
                    "required_signatories": ["Administrador"],
                }),
            )
        };
        let (status, _) = send(state.clone(), close()).await;
        assert_eq!(status, StatusCode::OK);

        // Closing an already-closed book is refused.
        let (status, body) = send(state, close()).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(body["error"].is_string());
    }

    #[tokio::test]
    async fn book_create_rejects_bad_date_with_422() {
        let state = AppState::default();
        let (_, entity) = send(
            state.clone(),
            post_json(
                "/v1/entities",
                json!({
                    "name": "Encosto Estratégico, S.A.",
                    "nipc": "503004642",
                    "seat": "Lisboa",
                    "kind": "SociedadeAnonima",
                }),
            ),
        )
        .await;
        let entity_id = entity["id"].as_str().unwrap().to_owned();

        let (status, body) = send(
            state,
            post_json(
                "/v1/books",
                json!({
                    "entity_id": entity_id,
                    "kind": "AssembleiaGeral",
                    "purpose": "livro",
                    "opening_date": "not-a-date",
                    "required_signatories": [],
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(body["error"].is_string());
    }

    #[tokio::test]
    async fn book_on_missing_entity_is_404() {
        let missing = Uuid::new_v4();
        let (status, _) = send(
            AppState::default(),
            post_json(
                "/v1/books",
                json!({
                    "entity_id": missing,
                    "kind": "AssembleiaGeral",
                    "purpose": "livro",
                    "opening_date": "2026-01-15",
                    "required_signatories": [],
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    /// A throwaway `apps/web/dist`-shaped directory with an `index.html`, cleaned up on drop.
    struct TempWeb {
        dir: PathBuf,
    }

    impl TempWeb {
        fn new(index_html: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("chancela-web-test-{}", Uuid::new_v4()));
            std::fs::create_dir_all(&dir).expect("temp web dir created");
            std::fs::write(dir.join("index.html"), index_html).expect("index.html written");
            Self { dir }
        }
    }

    impl Drop for TempWeb {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// Drive one request through the full [`app`] router and return (status, body text).
    async fn send_text(router: Router, req: Request<Body>) -> (StatusCode, String) {
        let response = router.oneshot(req).await.expect("router responds");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body collects");
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    #[tokio::test]
    async fn web_dist_serves_index_at_root() {
        let web = TempWeb::new("<!doctype html><title>Chancela</title>");
        let app = app(AppState::default(), Some(web.dir.clone()));
        let (status, body) = send_text(app, get("/")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("<title>Chancela</title>"), "got: {body}");
    }

    #[tokio::test]
    async fn unknown_route_falls_back_to_index_html() {
        let web = TempWeb::new("SPA-SHELL-MARKER");
        let app = app(AppState::default(), Some(web.dir.clone()));
        // A client-side route with no matching file must return the SPA shell, not 404.
        let (status, body) = send_text(app, get("/livros")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "SPA-SHELL-MARKER");
    }

    #[tokio::test]
    async fn unknown_v1_route_is_json_404_not_spa_shell() {
        // The regression under test: with a web build mounted, an unknown /v1 path (a typo, or a
        // route a stale binary predates) must return a JSON 404 — never the SPA `index.html`,
        // which the web client would try to `JSON.parse` ("Unexpected token '<'").
        let web = TempWeb::new("SPA-SHELL-MARKER");
        let app = app(AppState::default(), Some(web.dir.clone()));
        let (status, body) = send_text(app, get("/v1/definitely-not-a-route")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(
            !body.contains("SPA-SHELL-MARKER"),
            "must not be the SPA shell: {body}"
        );
        let value: Value = serde_json::from_str(&body).expect("body is JSON");
        assert_eq!(
            value["error"],
            "unknown API route: GET /v1/definitely-not-a-route"
        );
    }

    #[tokio::test]
    async fn unknown_health_subpath_is_json_404_not_spa_shell() {
        let web = TempWeb::new("SPA-SHELL-MARKER");
        let app = app(AppState::default(), Some(web.dir.clone()));
        let (status, body) = send_text(app, get("/health/nope")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(
            !body.contains("SPA-SHELL-MARKER"),
            "must not be the SPA shell: {body}"
        );
        let value: Value = serde_json::from_str(&body).expect("body is JSON");
        assert!(
            value["error"]
                .as_str()
                .expect("error string")
                .starts_with("unknown API route:"),
        );
    }

    #[tokio::test]
    async fn unknown_v1_route_is_json_404_in_api_only_mode() {
        // Even without a web build, an unknown /v1 path is a JSON 404, not the plain-text landing.
        let app = app(AppState::default(), None);
        let (status, body) = send_text(app, get("/v1/nope")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(
            !body.contains("web UI not built"),
            "must not be the landing page: {body}"
        );
        let value: Value = serde_json::from_str(&body).expect("body is JSON");
        assert_eq!(value["error"], "unknown API route: GET /v1/nope");
    }

    #[tokio::test]
    async fn known_v1_route_still_wins_over_the_catch_all() {
        // The catch-all is low priority: a real endpoint keeps serving its own response.
        let web = TempWeb::new("SPA-SHELL-MARKER");
        let app = app(AppState::default(), Some(web.dir.clone()));
        let (status, body) = send_text(app, get("/v1/entities")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "[]", "the entities list, not a 404 or the SPA shell");
    }

    #[tokio::test]
    async fn api_routes_keep_priority_over_static_tree() {
        let web = TempWeb::new("SPA-SHELL-MARKER");
        let app = app(AppState::default(), Some(web.dir.clone()));
        let (status, body) = send_text(app, get("/health")).await;
        assert_eq!(status, StatusCode::OK);
        // Must be the JSON health body, never the SPA shell.
        assert!(body.contains("\"status\":\"ok\""), "got: {body}");
    }

    #[tokio::test]
    async fn api_only_mode_serves_helpful_landing() {
        let app = app(AppState::default(), None);
        let (status, body) = send_text(app, get("/")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("web UI not built"), "got: {body}");
        assert!(body.contains("npm run build"), "got: {body}");
    }

    #[tokio::test]
    async fn ledger_verify_reports_valid_chain_after_creates() {
        let state = AppState::default();

        // Empty ledger verifies with length 0.
        let (status, body) = send(state.clone(), get("/v1/ledger/verify")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["valid"], true);
        assert_eq!(body["length"], 0);

        // Two creates append two events; the chain still verifies.
        for nipc in ["503004642", "500000000"] {
            let create = post_json(
                "/v1/entities",
                json!({
                    "name": "Entity",
                    "nipc": nipc,
                    "seat": "Lisboa",
                    "kind": "Cooperativa",
                }),
            );
            let (status, _) = send(state.clone(), create).await;
            assert_eq!(status, StatusCode::CREATED);
        }

        let (status, body) = send(state, get("/v1/ledger/verify")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["valid"], true);
        assert_eq!(body["length"], 2);
    }

    // --- Settings (§2.8) -----------------------------------------------------------------

    fn put_json(uri: &str, body: Value) -> Request<Body> {
        body_json("PUT", uri, body)
    }

    /// A complete, non-default settings document used to prove PUT round-trips every section.
    fn sample_settings() -> Value {
        json!({
            "schema_version": 1,
            "organization": { "name": "Encosto Estratégico, S.A.", "default_actor": "amelia.marques" },
            "documents": { "locale": "en-US", "numbering_scheme_default": "LooseLeaf" },
            "catalog": {
                "cae_update_url": "https://catalog.example.pt/cae.json",
                "cae_sources": [
                    { "url": "https://espelho.example.pt/cae.json", "format": "Envelope", "digest": null },
                    { "url": "https://files.example.pt/cae.pdf", "format": "Pdf",
                      "digest": "0000000000000000000000000000000000000000000000000000000000000000" }
                ],
                "cae_official_source": true,
                "preferred_official_source": "Ine"
            },
            "signing": {
                "preferred_family": "ChaveMovelDigital",
                "tsa_url": "https://tsa.example.pt/tsr",
                "tsl_url": "https://tsl.example.pt/tsl.xml",
                "require_qualified_for_seal": true
            },
            "appearance": { "theme": "dark", "leather_texture": false, "texture_intensity": 25, "button_texture": false },
            "onboarding": { "completed": false, "completed_at": null }
        })
    }

    #[tokio::test]
    async fn settings_get_returns_defaults() {
        let (status, body) = send(AppState::default(), get("/v1/settings")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["schema_version"], 1);
        assert_eq!(body["organization"]["name"], Value::Null);
        assert_eq!(body["organization"]["default_actor"], "api");
        assert_eq!(body["documents"]["locale"], "pt-PT");
        assert_eq!(body["documents"]["numbering_scheme_default"], "Sequential");
        // The CAE update URL is unset by default (no official feed to ride); the ordered source
        // chain is empty and the official DR obtain is off (§cae-v2).
        assert_eq!(body["catalog"]["cae_update_url"], Value::Null);
        assert_eq!(body["catalog"]["cae_sources"], json!([]));
        assert_eq!(body["catalog"]["cae_official_source"], false);
        assert_eq!(body["signing"]["preferred_family"], "CartaoCidadao");
        // Trust-service URLs now default to the official Portuguese endpoints (not null).
        assert_eq!(
            body["signing"]["tsa_url"],
            "http://ts.cartaodecidadao.pt/tsa/server"
        );
        assert_eq!(
            body["signing"]["tsl_url"],
            "https://www.gns.gov.pt/media/TSLPT.xml"
        );
        assert_eq!(body["signing"]["require_qualified_for_seal"], false);
        assert_eq!(body["appearance"]["theme"], "system");
        assert_eq!(body["appearance"]["leather_texture"], true);
        assert_eq!(body["appearance"]["texture_intensity"], 60);
        assert_eq!(body["appearance"]["button_texture"], true);
    }

    #[tokio::test]
    async fn settings_put_round_trips_and_get_reflects() {
        let state = AppState::default();
        let (status, stored) =
            send(state.clone(), put_json("/v1/settings", sample_settings())).await;
        assert_eq!(status, StatusCode::OK);
        // PUT echoes the stored document.
        assert_eq!(stored, sample_settings());

        // A subsequent GET reflects the stored document exactly.
        let (status, got) = send(state, get("/v1/settings")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(got, sample_settings());
    }

    #[tokio::test]
    async fn settings_partial_document_fills_defaults() {
        // Only one nested field is supplied; every other field must default cleanly.
        let (status, stored) = send(
            AppState::default(),
            put_json(
                "/v1/settings",
                json!({ "organization": { "name": "Solo" } }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(stored["schema_version"], 1);
        assert_eq!(stored["organization"]["name"], "Solo");
        assert_eq!(stored["organization"]["default_actor"], "api");
        assert_eq!(stored["documents"]["locale"], "pt-PT");
        assert_eq!(stored["appearance"]["texture_intensity"], 60);
        // Omitted trust URLs and button_texture inherit the official/textured defaults.
        assert_eq!(
            stored["signing"]["tsa_url"],
            "http://ts.cartaodecidadao.pt/tsa/server"
        );
        assert_eq!(
            stored["signing"]["tsl_url"],
            "https://www.gns.gov.pt/media/TSLPT.xml"
        );
        assert_eq!(stored["appearance"]["button_texture"], true);
    }

    #[tokio::test]
    async fn settings_stored_null_tsa_url_is_preserved() {
        // An operator who explicitly cleared the URL (stored `null`) keeps `null` — their
        // recorded choice wins over the new official default (null-vs-default policy).
        let mut doc = sample_settings();
        doc["signing"]["tsa_url"] = Value::Null;
        let (status, stored) = send(AppState::default(), put_json("/v1/settings", doc)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(stored["signing"]["tsa_url"], Value::Null);
        // A sibling field left explicit is untouched.
        assert_eq!(
            stored["signing"]["tsl_url"],
            "https://tsl.example.pt/tsl.xml"
        );
    }

    #[test]
    fn settings_old_document_inherits_new_defaults_and_preserves_null() {
        // An older settings.json that predates these fields: it omits button_texture and
        // tsa_url entirely, and stores tsl_url as an explicit null.
        let old = json!({
            "schema_version": 1,
            "organization": { "name": "Legado", "default_actor": "api" },
            "documents": { "locale": "en-US", "numbering_scheme_default": "Sequential" },
            "signing": { "preferred_family": "CartaoCidadao", "tsl_url": null },
            "appearance": { "theme": "system", "leather_texture": true, "texture_intensity": 60 }
        });
        let parsed: Settings = serde_json::from_value(old).expect("old document deserializes");
        // Omitted field inherits the new official default...
        assert_eq!(
            parsed.signing.tsa_url.as_deref(),
            Some("http://ts.cartaodecidadao.pt/tsa/server")
        );
        // ...while an explicit stored null is preserved as None (operator's choice wins).
        assert_eq!(parsed.signing.tsl_url, None);
        // Omitted additive appearance flag inherits its default (textured buttons on).
        assert!(parsed.appearance.button_texture);
    }

    #[tokio::test]
    async fn settings_put_invalid_intensity_is_422() {
        let mut bad = sample_settings();
        bad["appearance"]["texture_intensity"] = json!(150);
        let (status, body) = send(AppState::default(), put_json("/v1/settings", bad)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(body["error"].is_string());
    }

    #[tokio::test]
    async fn settings_put_invalid_locale_is_422() {
        let mut bad = sample_settings();
        // `fr-FR` is now a supported locale; use a tag outside the 14-locale set.
        bad["documents"]["locale"] = json!("zz-ZZ");
        let (status, body) = send(AppState::default(), put_json("/v1/settings", bad)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(body["error"].is_string());
    }

    #[tokio::test]
    async fn settings_put_invalid_tsa_url_is_422() {
        let mut bad = sample_settings();
        bad["signing"]["tsa_url"] = json!("ftp://tsa.example.pt");
        let (status, body) = send(AppState::default(), put_json("/v1/settings", bad)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(body["error"].is_string());
    }

    #[tokio::test]
    async fn settings_put_invalid_cae_update_url_is_422() {
        let mut bad = sample_settings();
        bad["catalog"]["cae_update_url"] = json!("not-a-url");
        let (status, body) = send(AppState::default(), put_json("/v1/settings", bad)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(body["error"].is_string());
    }

    #[tokio::test]
    async fn settings_put_bad_cae_source_entry_is_422() {
        // A cae_sources entry with a non-http(s) URL is rejected.
        let mut bad = sample_settings();
        bad["catalog"]["cae_sources"] =
            json!([{ "url": "ftp://espelho.example/cae.json", "format": "Auto" }]);
        let (status, body) = send(AppState::default(), put_json("/v1/settings", bad.clone())).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(body["error"].is_string());

        // A malformed digest pin (not 64-char sha256 hex) is also rejected.
        bad["catalog"]["cae_sources"] = json!([{ "url": "https://espelho.example/cae.json", "format": "Auto", "digest": "xyz" }]);
        let (status, body) = send(AppState::default(), put_json("/v1/settings", bad)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(body["error"].is_string());
    }

    #[tokio::test]
    async fn settings_catalog_v2_round_trips() {
        // The whole §catalog-v2 block (update URL + ordered sources with format/digest + official
        // toggle) round-trips through PUT/GET unchanged.
        let state = AppState::default();
        let (status, stored) =
            send(state.clone(), put_json("/v1/settings", sample_settings())).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(stored["catalog"]["cae_official_source"], true);
        assert_eq!(
            stored["catalog"]["cae_sources"][0]["url"],
            "https://espelho.example.pt/cae.json"
        );
        assert_eq!(stored["catalog"]["cae_sources"][0]["format"], "Envelope");
        assert_eq!(stored["catalog"]["cae_sources"][1]["format"], "Pdf");
        let (status, got) = send(state, get("/v1/settings")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(got["catalog"], sample_settings()["catalog"]);
    }

    #[tokio::test]
    async fn settings_preferred_official_source_defaults_to_ine_and_round_trips() {
        // Default (omitted) → Ine (user directive t37: "default is ine").
        let state = AppState::default();
        let (status, defaults) = send(state, get("/v1/settings")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(defaults["catalog"]["preferred_official_source"], "Ine");

        // A non-default value round-trips.
        let state = AppState::default();
        let mut doc = sample_settings();
        doc["catalog"]["preferred_official_source"] = json!("DiarioRepublica");
        let (status, stored) = send(state.clone(), put_json("/v1/settings", doc)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            stored["catalog"]["preferred_official_source"],
            "DiarioRepublica"
        );

        // An unknown value is rejected by deserialization → 422.
        let mut bad = sample_settings();
        bad["catalog"]["preferred_official_source"] = json!("Eurostat");
        let (status, body) = send(state, put_json("/v1/settings", bad)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(body["error"].is_string());
    }

    #[tokio::test]
    async fn settings_put_appends_ledger_event_with_default_actor() {
        let state = AppState::default();
        let (status, _) = send(state.clone(), put_json("/v1/settings", sample_settings())).await;
        assert_eq!(status, StatusCode::OK);

        let (status, events) = send(state, get("/v1/ledger/events")).await;
        assert_eq!(status, StatusCode::OK);
        let arr = events.as_array().expect("events array");
        let updated = arr
            .iter()
            .find(|e| e["kind"] == "settings.updated")
            .expect("settings.updated event present");
        // t41: with a session, the actor is the session username ("test.actor"),
        // not the document's organization.default_actor.
        assert_eq!(updated["actor"], "test.actor");
        assert_eq!(updated["scope"], "settings");
        assert_eq!(updated["justification"], "settings updated");
    }

    #[tokio::test]
    async fn settings_put_actor_query_overrides_default_actor() {
        let state = AppState::default();
        let (status, _) = send(
            state.clone(),
            put_json("/v1/settings?actor=auditor", sample_settings()),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (_, events) = send(state, get("/v1/ledger/events")).await;
        let arr = events.as_array().expect("events array");
        let updated = arr
            .iter()
            .find(|e| e["kind"] == "settings.updated")
            .expect("settings.updated event present");
        // t41: with a session, the actor is the session username ("test.actor"),
        // which takes precedence over the ?actor= query param.
        assert_eq!(updated["actor"], "test.actor");
    }

    /// A throwaway data directory (unique under the OS temp dir), cleaned up on drop.
    struct TempDir {
        dir: PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!("chancela-data-test-{}", Uuid::new_v4()));
            std::fs::create_dir_all(&dir).expect("temp data dir created");
            Self { dir }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[tokio::test]
    async fn settings_file_persistence_round_trip() {
        let tmp = TempDir::new();

        // A file-backed state starts at defaults and has no settings.json yet.
        let first = AppState::with_data_dir(tmp.dir.clone());
        let settings_file = tmp.dir.join("settings.json");
        assert!(!settings_file.exists(), "no file before the first PUT");

        // PUT persists the document to disk.
        let (status, _) = send(first, put_json("/v1/settings", sample_settings())).await;
        assert_eq!(status, StatusCode::OK);
        assert!(settings_file.is_file(), "settings.json written on PUT");

        // A fresh state over the same directory loads the persisted document at startup.
        let second = AppState::with_data_dir(tmp.dir.clone());
        let (status, got) = send(second, get("/v1/settings")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(got, sample_settings());
    }

    // --- CAE library (§2.7) --------------------------------------------------------------

    // `with_session` is defined near the top of the test module (before `entity_and_open_book`).

    #[tokio::test]
    async fn cae_lookup_returns_entry_with_hierarchy() {
        let (status, view) = send(AppState::default(), get("/v1/cae/68110")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(view["code"], "68110");
        assert_eq!(view["designation"], "Compra e venda de bens imobiliários.");
        assert_eq!(view["level"], "Subclasse");
        assert_eq!(view["revision"], "Rev4");
        let hierarchy = view["hierarchy"].as_array().expect("hierarchy array");
        // secção → divisão → grupo → classe → subclasse.
        assert_eq!(hierarchy.len(), 5);
        assert_eq!(hierarchy[0]["level"], "Seccao");
        assert_eq!(hierarchy[4]["code"], "68110");
    }

    #[tokio::test]
    async fn cae_lookup_respects_a_revision_pin() {
        // 68100 exists only in Rev.3; pinning Rev.4 misses (404), Rev.3 hits.
        let (status, _) = send(AppState::default(), get("/v1/cae/68100?revision=Rev4")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, view) = send(AppState::default(), get("/v1/cae/68100?revision=Rev3")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(view["revision"], "Rev3");
    }

    #[tokio::test]
    async fn cae_lookup_unknown_code_is_404() {
        let (status, _) = send(AppState::default(), get("/v1/cae/99999")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn cae_search_returns_matching_nodes_without_hierarchy() {
        // Accent-folded search: "imobili" matches "imobiliários" in both revisions.
        let (status, hits) = send(AppState::default(), get("/v1/cae?search=imobili&limit=5")).await;
        assert_eq!(status, StatusCode::OK);
        let arr = hits.as_array().expect("hits array");
        assert!(!arr.is_empty(), "at least one match");
        assert!(arr.len() <= 5, "limit respected");
        // The list form omits the hierarchy field entirely.
        assert!(arr[0].get("hierarchy").is_none());
        assert!(arr[0]["designation"].as_str().unwrap().contains("imobili"));
    }

    #[tokio::test]
    async fn cae_no_search_returns_catalog_metadata() {
        let (status, meta) = send(AppState::default(), get("/v1/cae")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(meta["origin"], "Embedded");
        assert_eq!(meta["schema_version"], 1);
        // Official Rev.4 totals (the structural-integrity gate).
        assert_eq!(meta["counts"]["rev4"]["seccao"], 22);
        assert_eq!(meta["counts"]["rev4"]["subclasse"], 915);
        assert!(meta["digest"].as_str().expect("digest").len() == 64);
    }

    /// A tiny but structurally-valid dataset that supersedes the embedded catalog (distinct
    /// digest, far-future `generated_at`), for the refresh path.
    fn superseding_dataset() -> Value {
        json!({
            "schema_version": 1,
            "generated_at": "2099-01-01T00:00:00Z",
            "source_note": "test refresh dataset",
            "rev3": [],
            "rev4": [
                { "code": "A", "designation": "Secção de teste", "level": "Seccao",
                  "revision": "Rev4", "parent": null },
                { "code": "01", "designation": "Divisão de teste", "level": "Divisao",
                  "revision": "Rev4", "parent": "A" }
            ]
        })
    }

    /// A data-dir-backed state with an injected CAE source, so the refresh writes a cache the
    /// second attempt can compare against (the no-op path only holds once a cache exists).
    fn state_with_cae_source(dir: PathBuf, dataset: Value) -> AppState {
        let bytes = serde_json::to_vec(&dataset).expect("dataset serializes");
        let mut state = AppState::with_data_dir(dir);
        state.cae_source = Some(Arc::new(chancela_cae::BytesCaeSource::new(bytes)));
        state
    }

    #[tokio::test]
    async fn cae_refresh_swaps_catalog_and_appends_event() {
        let tmp = TempDir::new();
        let state = state_with_cae_source(tmp.dir.clone(), superseding_dataset());

        let (status, report) = send(state.clone(), post_json("/v1/cae/refresh", json!({}))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(report["updated"], true);
        // The fetched dataset is labelled a Cache origin, and the cache file was written.
        assert_eq!(report["metadata"]["origin"], "Cache");
        assert!(tmp.dir.join("cae-catalog.json").is_file());

        // The live catalog now serves the refreshed data (the tiny test dataset).
        let (status, view) = send(state.clone(), get("/v1/cae/A")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(view["designation"], "Secção de teste");

        // A `cae.updated` event was appended.
        let (_, events) = send(state.clone(), get("/v1/ledger/events")).await;
        let updated = events
            .as_array()
            .expect("events")
            .iter()
            .find(|e| e["kind"] == "cae.updated")
            .expect("cae.updated event present");
        assert_eq!(updated["scope"], "cae");
        assert_eq!(updated["actor"], "test.actor"); // t41: session actor

        // A second refresh of the same dataset is a no-op: it no longer supersedes the cache.
        let (status, report) = send(state, post_json("/v1/cae/refresh", json!({}))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(report["updated"], false);
    }

    #[tokio::test]
    async fn cae_refresh_on_a_bad_source_is_502() {
        // A source returning non-dataset bytes → CaeError::Parse → 502.
        let state = AppState {
            cae_source: Some(Arc::new(chancela_cae::BytesCaeSource::new(
                b"not a dataset".to_vec(),
            ))),
            ..AppState::default()
        };
        let (status, body) = send(state, post_json("/v1/cae/refresh", json!({}))).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert!(body["error"].is_string());
    }

    // --- CAE multi-source chain refresh (§cae-v2) -----------------------------------------

    /// A data-dir-backed state whose refresh chain is driven by an injected factory (in-memory
    /// sources), so the multi-source pipeline is exercised without a network. Rebuilds the chain per
    /// call so `?source` pinning + repeat refreshes work.
    fn state_with_cae_chain(
        dir: PathBuf,
        factory: impl Fn() -> chancela_cae::CaeSourceChain + Send + Sync + 'static,
    ) -> AppState {
        let mut state = AppState::with_data_dir(dir);
        state.cae_chain_factory = Some(Arc::new(factory));
        state
    }

    /// A **complete both-revision** envelope dataset built from the vendored embedded revision
    /// arrays, with code `68110`'s Rev.4 designation tagged by `marker` so it (a) differs in digest
    /// from the embedded catalog (thus supersedes) while keeping the exact official per-level counts
    /// the chain's fidelity gate demands, and (b) is identifiable after a refresh. Unlike the legacy
    /// `refresh` path, the chain runs the full-count fidelity gate, so a tiny fixture cannot win.
    fn full_fidelity_envelope(marker: &str) -> Value {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../chancela-cae/data");
        let read = |name: &str| -> Vec<Value> {
            serde_json::from_slice(&std::fs::read(dir.join(name)).expect("vendored array readable"))
                .expect("vendored array parses")
        };
        let rev3 = read("cae_rev3.json");
        let mut rev4 = read("cae_rev4.json");
        for node in &mut rev4 {
            if node["code"] == "68110" {
                let d = node["designation"].as_str().unwrap_or_default().to_owned();
                node["designation"] = json!(format!("{d} [{marker}]"));
            }
        }
        json!({
            "schema_version": 1,
            "generated_at": "2099-01-01T00:00:00Z",
            "source_note": "test full-fidelity mirror",
            "rev3": rev3,
            "rev4": rev4,
        })
    }

    /// A one-entry `MirrorArtifactSource` chain over the given envelope-JSON `Value`.
    fn bytes_mirror_chain(
        dataset: Value,
    ) -> impl Fn() -> chancela_cae::CaeSourceChain + Send + Sync {
        use chancela_cae::{CaeSourceChain, CaeSourceFormat, ChainEntry, MirrorArtifactSource};
        let bytes = serde_json::to_vec(&dataset).expect("dataset serializes");
        move || {
            CaeSourceChain::new(vec![ChainEntry::Mirror(MirrorArtifactSource::from_bytes(
                bytes.clone(),
                CaeSourceFormat::Envelope,
            ))])
        }
    }

    #[tokio::test]
    async fn cae_chain_refresh_supersedes_records_mirror_provenance_and_no_ops() {
        let tmp = TempDir::new();
        let state = state_with_cae_chain(
            tmp.dir.clone(),
            bytes_mirror_chain(full_fidelity_envelope("mirror")),
        );

        // A superseding mirror wins: catalog swapped, provenance recorded (Mirror), cache written,
        // cae.updated appended, and it cleared the full-count fidelity gate.
        let (status, report) = send(state.clone(), post_json("/v1/cae/refresh", json!({}))).await;
        assert_eq!(status, StatusCode::OK, "refresh: {report}");
        assert_eq!(report["updated"], true);
        assert_eq!(report["metadata"]["origin"], "Cache");
        assert_eq!(report["metadata"]["provenance"]["source_kind"], "Mirror");
        assert_eq!(report["metadata"]["counts"]["rev4"]["subclasse"], 915);
        assert_eq!(report["source"], "<bytes>");
        assert_eq!(report["failures"].as_array().expect("failures").len(), 0);
        assert!(tmp.dir.join("cae-catalog.json").is_file());

        // The live catalog serves the tagged designation from the mirror.
        let (status, view) = send(state.clone(), get("/v1/cae/68110")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            view["designation"]
                .as_str()
                .expect("designation")
                .contains("[mirror]")
        );

        let (_, events) = send(state.clone(), get("/v1/ledger/events")).await;
        assert!(
            events
                .as_array()
                .expect("events")
                .iter()
                .any(|e| e["kind"] == "cae.updated" && e["scope"] == "cae"),
            "cae.updated appended"
        );

        // Repeat: the same dataset no longer supersedes the written cache → up to date, no event.
        let (status, report) = send(state, post_json("/v1/cae/refresh", json!({}))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(report["updated"], false);
        assert_eq!(report["source"], Value::Null);
    }

    #[tokio::test]
    async fn cae_chain_first_superseding_source_wins() {
        use chancela_cae::{CaeSourceChain, CaeSourceFormat, ChainEntry, MirrorArtifactSource};
        // Two superseding mirrors, each a complete dataset tagged distinctly; the FIRST in order wins
        // and its data lands (the second is never obtained).
        let tmp = TempDir::new();
        let b1 = serde_json::to_vec(&full_fidelity_envelope("FIRST")).unwrap();
        let b2 = serde_json::to_vec(&full_fidelity_envelope("SECOND")).unwrap();
        let state = state_with_cae_chain(tmp.dir.clone(), move || {
            CaeSourceChain::new(vec![
                ChainEntry::Mirror(MirrorArtifactSource::from_bytes(
                    b1.clone(),
                    CaeSourceFormat::Envelope,
                )),
                ChainEntry::Mirror(MirrorArtifactSource::from_bytes(
                    b2.clone(),
                    CaeSourceFormat::Envelope,
                )),
            ])
        });

        let (status, report) = send(state.clone(), post_json("/v1/cae/refresh", json!({}))).await;
        assert_eq!(status, StatusCode::OK, "refresh: {report}");
        assert_eq!(report["updated"], true);
        let (status, view) = send(state, get("/v1/cae/68110")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            view["designation"]
                .as_str()
                .expect("designation")
                .contains("[FIRST]"),
            "the first source won: {}",
            view["designation"]
        );
    }

    #[tokio::test]
    async fn cae_chain_all_sources_fail_is_502_with_failures() {
        // A single mirror returning non-dataset bytes fails every gate → 502, catalog untouched, the
        // per-source failure surfaced.
        let tmp = TempDir::new();
        let state = state_with_cae_chain(tmp.dir.clone(), || {
            use chancela_cae::{CaeSourceChain, CaeSourceFormat, ChainEntry, MirrorArtifactSource};
            CaeSourceChain::new(vec![ChainEntry::Mirror(MirrorArtifactSource::from_bytes(
                b"not a dataset".to_vec(),
                CaeSourceFormat::Auto,
            ))])
        });
        let (status, body) = send(state.clone(), post_json("/v1/cae/refresh", json!({}))).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY, "body: {body}");
        assert!(body["error"].is_string());
        assert_eq!(body["failures"].as_array().expect("failures").len(), 1);
        // The catalog is unchanged (still the embedded dataset).
        let (_, meta) = send(state, get("/v1/cae")).await;
        assert_eq!(meta["origin"], "Embedded");
    }

    #[tokio::test]
    async fn cae_refresh_pinned_source_with_no_match_is_settings_aware_422() {
        // The one case that still refuses: a `?source` pin matching nothing configured (a default is
        // impossible for a pin, e.g. `?source=mirror` with no mirrors) → friendly 422 pointing at
        // Configurações (the message the web/e2e error surface keys on). No network is touched — the
        // pin short-circuits before any chain runs. (Plain no-config refresh now runs the official
        // default chain instead; see `cae_refresh_with_no_config_runs_the_official_default_chain`.)
        let (status, body) = send(
            AppState::default(),
            post_json("/v1/cae/refresh?source=mirror", json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            body["error"]
                .as_str()
                .expect("error string")
                .contains("Configurações")
        );
    }

    /// A data-dir-backed state whose *no-config default* chain (run when nothing at all is
    /// configured) is driven by an injected factory, so the "no URL ⇒ official gov artifacts"
    /// substitution is exercised without a network. Nothing else is configured, so the refresh
    /// reaches the default path. Mirrors `state_with_cae_chain`.
    fn state_with_cae_default_chain(
        dir: PathBuf,
        factory: impl Fn() -> chancela_cae::CaeSourceChain + Send + Sync + 'static,
    ) -> AppState {
        let mut state = AppState::with_data_dir(dir);
        state.cae_default_chain_factory = Some(Arc::new(factory));
        state
    }

    #[tokio::test]
    async fn cae_refresh_with_no_config_runs_the_official_default_chain() {
        use chancela_cae::{CaeSourceChain, ChainEntry, DrPdfSource};
        // Nothing configured (no cae_source, no cae_sources, cae_official_source off, no
        // cae_update_url, no ?source pin) → instead of the old 422, the refresh runs the built-in
        // official Diário da República pair. The default is injected here as the vendored diploma
        // PDFs (via the no-config-default seam) so the substitution is proven end-to-end offline.
        let cae_data =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../chancela-cae/data/source");
        let (rev4, rev3) = (cae_data.join("rev4.pdf"), cae_data.join("rev3.pdf"));
        let tmp = TempDir::new();
        let state = state_with_cae_default_chain(tmp.dir.clone(), move || {
            CaeSourceChain::new(vec![ChainEntry::Official(DrPdfSource::from_files(
                &rev4, &rev3,
            ))])
        });

        let (status, report) = send(state, post_json("/v1/cae/refresh", json!({}))).await;
        assert_eq!(status, StatusCode::OK, "refresh: {report}");
        assert_eq!(report["updated"], true);
        assert_eq!(report["source"], "Diário da República (fonte oficial)");
        assert_eq!(
            report["metadata"]["provenance"]["source_kind"],
            "DiarioRepublica"
        );
        // The obtained catalog reproduces the official structural counts (full-count fidelity gate).
        assert_eq!(report["metadata"]["counts"]["rev4"]["subclasse"], 915);
    }

    #[tokio::test]
    async fn cae_refresh_source_official_over_injected_dr_pdf_pair() {
        use chancela_cae::{CaeSourceChain, ChainEntry, DrPdfSource};
        // `?source=official` runs the official DR pair; injected here as `DrPdfSource::from_files`
        // over the vendored diploma PDFs, so the in-app lopdf parser produces a complete dataset that
        // supersedes the embedded catalog with DiarioRepublica provenance.
        let cae_data =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../chancela-cae/data/source");
        let (rev4, rev3) = (cae_data.join("rev4.pdf"), cae_data.join("rev3.pdf"));
        let tmp = TempDir::new();
        let state = state_with_cae_chain(tmp.dir.clone(), move || {
            CaeSourceChain::new(vec![ChainEntry::Official(DrPdfSource::from_files(
                &rev4, &rev3,
            ))])
        });

        let (status, report) = send(
            state,
            post_json("/v1/cae/refresh?source=official", json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "refresh: {report}");
        assert_eq!(report["updated"], true);
        assert_eq!(report["source"], "Diário da República (fonte oficial)");
        assert_eq!(
            report["metadata"]["provenance"]["source_kind"],
            "DiarioRepublica"
        );
        // The obtained catalog reproduces the official structural counts.
        assert_eq!(report["metadata"]["counts"]["rev4"]["subclasse"], 915);
    }

    // --- CAE update signal: GET /v1/cae/updates (§cae-v2) ---------------------------------

    /// The checked-in INE SMI version-catalog fixture (UTF-16LE + BOM, a trimmed real capture),
    /// reused from `chancela-cae` so the `/v1/cae/updates` decode+parse path runs on the real shape.
    const SMI_FIXTURE: &[u8] =
        include_bytes!("../../chancela-cae/fixtures/smi_version_catalog.csv");

    /// Spawn a tiny in-process HTTP server that returns `body` for the SMI version-export path, and
    /// return its base URL. The state's `smi_base_override` points `GET /v1/cae/updates` here, so the
    /// real `SmiSource::fetch_catalog` transport + UTF-16 decode runs without hitting the network.
    async fn spawn_smi_fixture(body: &'static [u8]) -> String {
        let app = axum::Router::new().route(
            "/Versao/Exportacao",
            axum::routing::get(move || async move { body }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("fixture binds");
        let addr = listener.local_addr().expect("fixture addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        format!("http://{addr}")
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cae_updates_reports_the_current_smi_cae_versions() {
        // The mock SMI transport serves the real UTF-16 fixture; /updates decodes it and reports the
        // two current official CAE versions INE publishes, plus a checked_at stamp.
        let base = spawn_smi_fixture(SMI_FIXTURE).await;
        let state = AppState {
            smi_base_override: Some(Arc::new(base)),
            ..AppState::default()
        };

        let (status, body) = send(state, get("/v1/cae/updates")).await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        assert_eq!(body["rev4"]["version"], "V05497");
        assert_eq!(
            body["rev4"]["designation"],
            "Classificação portuguesa das atividades económicas, revisão 4"
        );
        assert_eq!(body["rev3"]["version"], "V00554");
        assert!(
            !body["checked_at"]
                .as_str()
                .expect("checked_at string")
                .is_empty(),
            "checked_at is stamped"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cae_updates_on_a_non_smi_response_is_502() {
        // A transport that answers with a non-SMI body → parse error → 502 (SMI unusable as a signal).
        let base = spawn_smi_fixture(b"not an SMI version export\r\n").await;
        let state = AppState {
            smi_base_override: Some(Arc::new(base)),
            ..AppState::default()
        };
        let (status, body) = send(state, get("/v1/cae/updates")).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY, "body: {body}");
        assert!(body["error"].is_string());
    }

    // --- CAE tree browse: sections + children (§cae-v2) -----------------------------------

    #[tokio::test]
    async fn cae_sections_lists_the_top_level_of_a_revision() {
        // Rev.4 has 22 secções, Rev.3 has 21; every entry is a Seccao node.
        let (status, rev4) = send(AppState::default(), get("/v1/cae/sections?revision=Rev4")).await;
        assert_eq!(status, StatusCode::OK);
        let arr = rev4.as_array().expect("sections array");
        assert_eq!(arr.len(), 22);
        assert!(
            arr.iter()
                .all(|n| n["level"] == "Seccao" && n["revision"] == "Rev4")
        );

        let (_, rev3) = send(AppState::default(), get("/v1/cae/sections?revision=Rev3")).await;
        assert_eq!(rev3.as_array().expect("sections array").len(), 21);

        // No revision defaults to Rev.4.
        let (_, default) = send(AppState::default(), get("/v1/cae/sections")).await;
        assert_eq!(default.as_array().expect("sections").len(), 22);
    }

    #[tokio::test]
    async fn cae_children_drills_down_and_404s_unknown_codes() {
        // A secção drills down to its divisões (all Divisao-level).
        let (status, kids) =
            send(AppState::default(), get("/v1/cae/L/children?revision=Rev4")).await;
        assert_eq!(status, StatusCode::OK);
        let arr = kids.as_array().expect("children array");
        assert!(!arr.is_empty() && arr.iter().all(|n| n["level"] == "Divisao"));

        // A divisão drills down to its grupos: 68 → 681.
        let (status, kids) = send(
            AppState::default(),
            get("/v1/cae/68/children?revision=Rev4"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let arr = kids.as_array().expect("children array");
        assert!(
            arr.iter()
                .any(|n| n["code"] == "681" && n["level"] == "Grupo"),
            "681 is a child of 68: {arr:?}"
        );

        // A known leaf (subclasse) legitimately has no children → empty array, 200.
        let (status, leaf) = send(AppState::default(), get("/v1/cae/68110/children")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(leaf.as_array().expect("empty").len(), 0);

        // An unknown code is a 404.
        let (status, _) = send(AppState::default(), get("/v1/cae/ZZ/children")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    // --- Law archive (spec/09 AI-20..22) --------------------------------------------------

    /// A minimal but structurally-recognisable PDF body for the fixture server.
    const PDF_BODY: &[u8] = b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n";

    /// Spawn a tiny in-process HTTP server that returns `body` for any `/{id}` path, and return its
    /// base URL. Used so the real `reqwest` download path (size cap + `%PDF` check) is exercised
    /// without hitting the network — the state's `law_pdf_base_override` points the fetch here.
    async fn spawn_pdf_fixture(body: &'static [u8]) -> String {
        let app =
            axum::Router::new().route("/{id}", axum::routing::get(move || async move { body }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("fixture binds");
        let addr = listener.local_addr().expect("fixture addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        format!("http://{addr}")
    }

    /// A data-dir-backed state whose law fetches are redirected to the fixture `base` URL.
    fn law_state(dir: PathBuf, base: String) -> AppState {
        let mut state = AppState::with_data_dir(dir);
        state.law_pdf_base_override = Some(Arc::new(base));
        state
    }

    fn delete(uri: &str) -> Request<Body> {
        Request::builder()
            .method("DELETE")
            .uri(uri)
            .body(Body::empty())
            .expect("request builds")
    }

    /// Send one request and return (status, headers, raw body bytes) — for the non-JSON PDF stream.
    async fn send_raw_bytes(
        state: AppState,
        req: Request<Body>,
    ) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
        let response = router(state).oneshot(req).await.expect("router responds");
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body collects")
            .to_vec();
        (status, headers, bytes)
    }

    #[tokio::test]
    async fn law_manifest_lists_curated_entries() {
        let (status, body) = send(AppState::default(), get("/v1/law")).await;
        assert_eq!(status, StatusCode::OK);
        let arr = body.as_array().expect("law array");
        assert_eq!(arr.len(), 9, "the curated statutory table");

        let csc = arr.iter().find(|e| e["id"] == "csc").expect("csc entry");
        assert_eq!(csc["ref"], "Decreto-Lei n.º 262/86, de 2 de setembro");
        assert_eq!(
            csc["official_url"],
            "https://data.dre.pt/eli/dec-lei/262/1986/p/cons/20260101"
        );
        assert!(csc["pdf_url"].is_null(), "csc has no pinned PDF");
        assert_eq!(csc["articles"][0], "Artigo 63.º");

        // The two CAE diplomas carry the pinned Diário da República PDF URLs (PROVENANCE.md).
        let cae4 = arr
            .iter()
            .find(|e| e["id"] == "dl-9-2025")
            .expect("dl-9-2025");
        assert_eq!(
            cae4["pdf_url"],
            "https://files.diariodarepublica.pt/1s/2025/02/03000/0000800049.pdf"
        );
        let cae3 = arr
            .iter()
            .find(|e| e["id"] == "dl-381-2007")
            .expect("dl-381-2007");
        assert_eq!(
            cae3["pdf_url"],
            "https://files.dre.pt/1s/2007/11/21900/0844008464.pdf"
        );

        // In memory nothing is archived.
        assert!(arr.iter().all(|e| e["stored"] == false));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn law_fetch_stores_pdf_and_appends_event() {
        let tmp = TempDir::new();
        let base = spawn_pdf_fixture(PDF_BODY).await;
        let state = law_state(tmp.dir.clone(), base);

        let (status, body) = send(
            state.clone(),
            post_json("/v1/law/dl-9-2025/fetch", json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["stored"], true);
        assert_eq!(
            body["stored_digest"].as_str().expect("digest").len(),
            64,
            "sha256 hex"
        );
        assert!(body["stored_bytes"].as_u64().expect("bytes") > 0);
        assert!(body["retrieved_at"].is_string());

        // The bytes and the state file are on disk.
        assert!(tmp.dir.join("laws").join("dl-9-2025.pdf").is_file());
        assert!(tmp.dir.join("laws").join("manifest-state.json").is_file());

        // A `law.fetched` event was appended, scoped to `law`.
        let (_, events) = send(state.clone(), get("/v1/ledger/events")).await;
        let ev = events
            .as_array()
            .expect("events")
            .iter()
            .find(|e| e["kind"] == "law.fetched")
            .expect("law.fetched event present");
        assert_eq!(ev["scope"], "law");

        // The manifest now reports the entry as stored.
        let (_, list) = send(state, get("/v1/law")).await;
        let e = list
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["id"] == "dl-9-2025")
            .unwrap();
        assert_eq!(e["stored"], true);
    }

    #[tokio::test]
    async fn law_fetch_without_pinned_pdf_is_409() {
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.dir.clone());
        // `csc` has pdf_url = null → nothing trustworthy to archive.
        let (status, body) = send(state, post_json("/v1/law/csc/fetch", json!({}))).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(body["error"].is_string());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn law_fetch_non_pdf_body_is_502() {
        let tmp = TempDir::new();
        let base = spawn_pdf_fixture(b"<html>not a pdf</html>").await;
        let state = law_state(tmp.dir.clone(), base);
        let (status, body) = send(state, post_json("/v1/law/dl-9-2025/fetch", json!({}))).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert!(body["error"].is_string());
    }

    #[tokio::test]
    async fn law_fetch_without_data_dir_is_422() {
        let (status, body) = send(
            AppState::default(),
            post_json("/v1/law/dl-9-2025/fetch", json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            body["error"]
                .as_str()
                .expect("error")
                .contains("CHANCELA_DATA_DIR")
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn law_serve_stored_pdf_returns_bytes_and_headers() {
        let tmp = TempDir::new();
        let base = spawn_pdf_fixture(PDF_BODY).await;
        let state = law_state(tmp.dir.clone(), base);

        // Not yet fetched → serving is a 404.
        let (status, _, _) = send_raw_bytes(state.clone(), get("/v1/law/dl-9-2025/pdf")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let (status, _) = send(
            state.clone(),
            post_json("/v1/law/dl-9-2025/fetch", json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, headers, bytes) = send_raw_bytes(state, get("/v1/law/dl-9-2025/pdf")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers.get("content-type").unwrap(), "application/pdf");
        assert!(
            headers
                .get("content-disposition")
                .unwrap()
                .to_str()
                .unwrap()
                .contains("inline")
        );
        assert!(bytes.starts_with(b"%PDF"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn law_delete_removes_pdf_and_appends_event() {
        let tmp = TempDir::new();
        let base = spawn_pdf_fixture(PDF_BODY).await;
        let state = law_state(tmp.dir.clone(), base);
        send(
            state.clone(),
            post_json("/v1/law/dl-9-2025/fetch", json!({})),
        )
        .await;

        let (status, body) = send(state.clone(), delete("/v1/law/dl-9-2025/pdf")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["stored"], false);
        assert!(!tmp.dir.join("laws").join("dl-9-2025.pdf").exists());

        // Serving is now a 404, and a `law.removed` event was appended.
        let (status, _, _) = send_raw_bytes(state.clone(), get("/v1/law/dl-9-2025/pdf")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (_, events) = send(state.clone(), get("/v1/ledger/events")).await;
        assert!(
            events
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e["kind"] == "law.removed")
        );

        // Deleting again (nothing stored) is a 404.
        let (status, _) = send(state, delete("/v1/law/dl-9-2025/pdf")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn law_archive_state_reloads_after_restart() {
        let tmp = TempDir::new();
        let base = spawn_pdf_fixture(PDF_BODY).await;
        let first = law_state(tmp.dir.clone(), base);
        let (status, _) = send(first, post_json("/v1/law/dl-9-2025/fetch", json!({}))).await;
        assert_eq!(status, StatusCode::OK);

        // A fresh state over the same data dir reloads `manifest-state.json`.
        let second = AppState::with_data_dir(tmp.dir.clone());
        let (_, list) = send(second, get("/v1/law")).await;
        let e = list
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["id"] == "dl-9-2025")
            .unwrap();
        assert_eq!(e["stored"], true);
        assert_eq!(e["stored_digest"].as_str().unwrap().len(), 64);
    }

    // --- Users + session + actor attribution (§2.8) --------------------------------------

    /// Create a user and return (user_id, username).
    async fn create_user(state: &AppState, username: &str) -> String {
        let (status, user) = send(
            state.clone(),
            post_json("/v1/users", json!({ "username": username })),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "user created");
        user["id"].as_str().expect("user id").to_owned()
    }

    /// Open a session for a user id and return its token.
    async fn open_session(state: &AppState, user_id: &str) -> String {
        let (status, s) = send_raw(
            state.clone(),
            post_json("/v1/session", json!({ "user_id": user_id })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "session opened");
        s["token"].as_str().expect("token").to_owned()
    }

    #[tokio::test]
    async fn create_user_appends_event_and_lists() {
        let state = AppState::default();
        // Bootstrap: first user created without auth (no users exist yet).
        let (status, user) = send_raw(
            state.clone(),
            post_json(
                "/v1/users",
                json!({ "username": "amelia.marques", "display_name": "Amélia Marques" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(user["username"], "amelia.marques");
        assert_eq!(user["display_name"], "Amélia Marques");
        assert_eq!(user["active"], true);
        assert!(user.get("password_hash").is_none());
        let id = user["id"].as_str().expect("id").to_owned();

        // GET by id (no auth needed for get_user).
        let (status, got) = send_raw(state.clone(), get(&format!("/v1/users/{id}"))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(got["username"], "amelia.marques");

        // List requires auth (t41); auto-seed adds "test.actor" as well.
        let (status, list) = send(state.clone(), get("/v1/users")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            list.as_array()
                .expect("list")
                .iter()
                .any(|u| u["username"] == "amelia.marques"),
            "amelia.marques is in the list: {list}"
        );

        // A `user.created` event was appended.
        let (_, events) = send(state, get("/v1/ledger/events")).await;
        let created = events
            .as_array()
            .expect("events")
            .iter()
            .find(|e| e["kind"] == "user.created" && e["actor"] == "api")
            .expect("user.created event present with actor=api (bootstrap)");
        assert_eq!(created["scope"], "user");
    }

    #[tokio::test]
    async fn create_user_defaults_display_name_to_username() {
        let (status, user) = send(
            AppState::default(),
            post_json("/v1/users", json!({ "username": "auditor" })),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(user["display_name"], "auditor");
    }

    #[tokio::test]
    async fn create_user_rejects_invalid_username_422() {
        for bad in ["", "Amelia", "has space", "a@b"] {
            let (status, body) = send(
                AppState::default(),
                post_json("/v1/users", json!({ "username": bad })),
            )
            .await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "rejects {bad:?}");
            assert!(body["error"].is_string());
        }
    }

    #[tokio::test]
    async fn create_duplicate_user_is_409() {
        let state = AppState::default();
        create_user(&state, "amelia.marques").await;
        // The same username again is a conflict (uniqueness is case-insensitive).
        let (status, body) = send(
            state,
            post_json("/v1/users", json!({ "username": "amelia.marques" })),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(body["error"].is_string());
    }

    #[tokio::test]
    async fn patch_user_renames_and_deactivates() {
        let state = AppState::default();
        let id = create_user(&state, "amelia.marques").await;

        let (status, patched) = send(
            state.clone(),
            patch_json(
                &format!("/v1/users/{id}"),
                json!({ "display_name": "Amélia M.", "active": false }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(patched["display_name"], "Amélia M.");
        assert_eq!(patched["active"], false);

        let (_, events) = send(state, get("/v1/ledger/events")).await;
        assert!(
            events
                .as_array()
                .expect("events")
                .iter()
                .any(|e| e["kind"] == "user.updated")
        );
    }

    #[tokio::test]
    async fn session_issue_and_inspect() {
        let state = AppState::default();
        let id = create_user(&state, "amelia.marques").await;
        let token = open_session(&state, &id).await;

        // GET /v1/session with the header resolves the user.
        let (status, s) = send(state.clone(), with_session(get("/v1/session"), &token)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(s["user"]["username"], "amelia.marques");

        // No header → user is null.
        let (status, s) = send_raw(state.clone(), get("/v1/session")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(s["user"], Value::Null);

        // DELETE drops it; a subsequent GET is null again.
        let del = with_session(
            Request::builder()
                .method("DELETE")
                .uri("/v1/session")
                .body(Body::empty())
                .unwrap(),
            &token,
        );
        let (status, _) = send(state.clone(), del).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (_, s) = send(state, with_session(get("/v1/session"), &token)).await;
        assert_eq!(s["user"], Value::Null);
    }

    #[tokio::test]
    async fn session_for_unknown_user_is_401() {
        // t41 H1: uniform 401, no enumeration
        let missing = Uuid::new_v4();
        let (status, _) = send_raw(
            AppState::default(),
            post_json("/v1/session", json!({ "user_id": missing })),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn session_attributes_the_ledger_actor_to_the_username() {
        let (state, _entity_id, book_id) = entity_and_open_book("SociedadeAnonima").await;
        let user_id = create_user(&state, "amelia.marques").await;
        let token = open_session(&state, &user_id).await;

        // t41: all mutations now require a session. Draft WITH the amelia.marques session →
        // the ledger actor is "amelia.marques".
        let (status, act) = send_raw(
            state.clone(),
            with_session(
                post_json(
                    "/v1/acts",
                    json!({ "book_id": book_id, "title": "Ata da AG", "channel": "Physical" }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let act_id = act["id"].as_str().expect("act id").to_owned();

        // Fill content + advance, all with the amelia.marques session.
        let (status, _) = send_raw(
            state.clone(),
            with_session(
                patch_json(
                    &format!("/v1/acts/{act_id}"),
                    json!({
                        "meeting_date": "2026-03-30",
                        "meeting_time": "10:00",
                        "place": "Sede social",
                        "mesa": { "presidente": "Ana Presidente", "secretarios": ["Rui Secretário"] },
                        "agenda": [{ "number": 1, "text": "Contas" }],
                        "attendance_reference": "Lista de presenças",
                        "deliberations": "Aprovadas as contas.",
                    }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        for to in [
            "Review",
            "Convened",
            "Deliberated",
            "TextApproved",
            "Signing",
        ] {
            let (status, _) = send_raw(
                state.clone(),
                with_session(
                    post_json(&format!("/v1/acts/{act_id}/advance"), json!({ "to": to })),
                    &token,
                ),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
        }

        // Seal WITH the session → the seal event's actor is "amelia.marques".
        let (status, _) = send_raw(
            state.clone(),
            with_session(
                post_json(&format!("/v1/acts/{act_id}/seal"), json!({})),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (_, events) = send(state, get("/v1/ledger/events")).await;
        let arr = events.as_array().expect("events");
        let drafted = arr
            .iter()
            .find(|e| e["kind"] == "act.drafted")
            .expect("act.drafted present");
        let sealed = arr
            .iter()
            .find(|e| e["kind"] == "act.sealed")
            .expect("act.sealed present");
        // t41: with a session, both draft and seal events are attributed to "amelia.marques".
        assert_eq!(drafted["actor"], "amelia.marques");
        assert_eq!(sealed["actor"], "amelia.marques");
    }

    // --- Per-family dispatch + statute overlay + back-compat (t31) ------------------------

    /// Advance an act (already drafted + filled) through the lifecycle to `Signing`.
    async fn advance_to_signing(state: &AppState, act_id: &str) {
        for to in [
            "Review",
            "Convened",
            "Deliberated",
            "TextApproved",
            "Signing",
        ] {
            let (status, _) = send(
                state.clone(),
                post_json(&format!("/v1/acts/{act_id}/advance"), json!({ "to": to })),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "advance to {to}");
        }
    }

    #[tokio::test]
    async fn condominium_seals_under_the_condominio_pack_without_a_mesa() {
        // Per-family dispatch: a condominium ata is checked by the DL 268/94 pack, which does not
        // require a mesa — so an act with no mesa seals clean, proving the gate is family-anchored
        // (not the CSC one, which would block on the missing chair).
        let (state, _entity_id, book_id) = entity_and_open_book("Condominio").await;
        let (_, act) = send(
            state.clone(),
            post_json(
                "/v1/acts",
                json!({ "book_id": book_id, "title": "Ata da assembleia", "channel": "Physical" }),
            ),
        )
        .await;
        let act_id = act["id"].as_str().expect("act id").to_owned();
        let (status, _) = send(
            state.clone(),
            patch_json(
                &format!("/v1/acts/{act_id}"),
                json!({
                    "meeting_date": "2026-03-30",
                    "place": "Hall do prédio",
                    "attendance_reference": "Folha de presenças",
                    "deliberations": "Aprovado o orçamento anual.",
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        advance_to_signing(&state, &act_id).await;

        let (status, comp) =
            send(state.clone(), get(&format!("/v1/acts/{act_id}/compliance"))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(comp["rule_pack"], "condominio-dl268/v1");
        assert_eq!(comp["family"], "Condominium");
        assert_eq!(comp["statute_overlay"], false);
        assert_eq!(comp["errors"], 0);
        assert_eq!(comp["seal_allowed"], true);

        // Seals with no mesa and no acknowledgement — the condo pack has nothing to flag here.
        let (status, sealed) = send(
            state,
            post_json(&format!("/v1/acts/{act_id}/seal"), json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "condo seal: {sealed}");
        assert_eq!(sealed["ata_number"], 1);
    }

    #[tokio::test]
    async fn csc_seal_blocked_without_mesa_then_passes_with_mesa() {
        // The re-promoted mesa Error: a CSC ata missing its presidente da mesa is refused at the
        // seal (422), then seals once the mesa is filled through the wire.
        let (state, _entity_id, book_id) = entity_and_open_book("SociedadeAnonima").await;
        let (_, act) = send(
            state.clone(),
            post_json(
                "/v1/acts",
                json!({ "book_id": book_id, "title": "Ata", "channel": "Physical" }),
            ),
        )
        .await;
        let act_id = act["id"].as_str().expect("act id").to_owned();

        // Fill everything except the mesa.
        let (status, _) = send(
            state.clone(),
            patch_json(
                &format!("/v1/acts/{act_id}"),
                json!({
                    "meeting_date": "2026-03-30",
                    "meeting_time": "10:00",
                    "place": "Sede social",
                    "agenda": [{ "number": 1, "text": "Contas" }],
                    "attendance_reference": "Lista de presenças",
                    "deliberations": "Aprovadas as contas.",
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        advance_to_signing(&state, &act_id).await;

        // Compliance reports the blocking mesa Error and refuses the seal.
        let (_, comp) = send(state.clone(), get(&format!("/v1/acts/{act_id}/compliance"))).await;
        assert!(comp["errors"].as_u64().expect("errors") >= 1);
        assert_eq!(comp["seal_allowed"], false);
        assert!(
            comp["issues"]
                .as_array()
                .expect("issues")
                .iter()
                .any(|i| { i["rule_id"] == "CSC-63/mesa-presidente" && i["severity"] == "Error" }),
            "the blocking mesa Error is present: {comp}"
        );

        let (status, body) = send(
            state.clone(),
            post_json(&format!("/v1/acts/{act_id}/seal"), json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            body["issues"]
                .as_array()
                .expect("issues")
                .iter()
                .any(|i| i["rule_id"] == "CSC-63/mesa-presidente"),
            "the seal refusal carries the mesa Error: {body}"
        );

        // Fill the mesa through the wire → the seal now succeeds.
        let (status, _) = send(
            state.clone(),
            patch_json(
                &format!("/v1/acts/{act_id}"),
                json!({ "mesa": { "presidente": "Ana Presidente", "secretarios": ["Rui Secretário"] } }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, sealed) = send(
            state,
            post_json(&format!("/v1/acts/{act_id}/seal"), json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "seal after mesa: {sealed}");
        assert_eq!(sealed["ata_number"], 1);
    }

    #[tokio::test]
    async fn patch_entity_statute_drives_the_overlay_and_audits() {
        // PATCH /v1/entities/{id} sets a statute overlay, appends `entity.statute_updated`, and the
        // overlay then drives the STATUTE/majority check over a structured vote — all through the
        // wire. A null statute clears it.
        let state = AppState::default();
        let (status, entity) = send(
            state.clone(),
            post_json(
                "/v1/entities",
                json!({ "name": "Encosto Estratégico, S.A.", "nipc": "503004642", "seat": "Lisboa", "kind": "SociedadeAnonima" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let entity_id = entity["id"].as_str().expect("entity id").to_owned();
        // The view carries the derived profile and a null statute.
        assert!(entity["statute"].is_null());
        assert_eq!(entity["profile"]["rule_pack_id"], "csc-art63/v2");
        assert_eq!(entity["profile"]["family"], "CommercialCompany");

        // Set a 2/3 statutory majority.
        let (status, patched) = send(
            state.clone(),
            patch_json(
                &format!("/v1/entities/{entity_id}"),
                json!({ "statute": { "majority": { "numerator": 2, "denominator": 3 } } }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(patched["statute"]["majority"]["numerator"], 2);
        assert_eq!(patched["statute"]["majority"]["denominator"], 3);

        // The audit trail records the overlay edit.
        let (_, events) = send(state.clone(), get("/v1/ledger/events")).await;
        assert!(
            events
                .as_array()
                .expect("events")
                .iter()
                .any(|e| e["kind"] == "entity.statute_updated"),
            "entity.statute_updated is on the chain: {events}"
        );

        // Open a book, draft an ata with a structured non-unanimous vote below the 2/3 majority.
        let (_, book) = send(
            state.clone(),
            post_json(
                "/v1/books",
                json!({ "entity_id": entity_id, "kind": "AssembleiaGeral", "purpose": "livro", "opening_date": "2026-01-15", "required_signatories": ["Administrador"] }),
            ),
        )
        .await;
        let book_id = book["id"].as_str().expect("book id").to_owned();
        let (_, act) = send(
            state.clone(),
            post_json(
                "/v1/acts",
                json!({ "book_id": book_id, "title": "Ata", "channel": "Physical" }),
            ),
        )
        .await;
        let act_id = act["id"].as_str().expect("act id").to_owned();
        let (status, _) = send(
            state.clone(),
            patch_json(
                &format!("/v1/acts/{act_id}"),
                json!({
                    "meeting_date": "2026-03-30",
                    "meeting_time": "10:00",
                    "place": "Sede social",
                    "mesa": { "presidente": "Ana Presidente", "secretarios": ["Rui Secretário"] },
                    "agenda": [{ "number": 1, "text": "Alteração ao contrato" }],
                    "attendance_reference": "Lista de presenças",
                    "deliberation_items": [{
                        "agenda_number": 1,
                        "text": "Deliberada a alteração ao contrato.",
                        "vote": { "type": "Recorded", "em_favor": 60, "contra": 40, "abstencoes": 0 },
                        "statements": []
                    }],
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        advance_to_signing(&state, &act_id).await;

        let (_, comp) = send(state.clone(), get(&format!("/v1/acts/{act_id}/compliance"))).await;
        assert_eq!(comp["statute_overlay"], true);
        assert!(
            comp["issues"]
                .as_array()
                .expect("issues")
                .iter()
                .any(|i| i["rule_id"] == "STATUTE/majority" && i["severity"] == "Warning"),
            "60/100 misses the 2/3 majority: {comp}"
        );

        // Clearing the statute removes the overlay.
        let (status, cleared) = send(
            state.clone(),
            patch_json(
                &format!("/v1/entities/{entity_id}"),
                json!({ "statute": null }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(cleared["statute"].is_null());
        let (_, comp) = send(state, get(&format!("/v1/acts/{act_id}/compliance"))).await;
        assert_eq!(comp["statute_overlay"], false);
        assert!(
            !comp["issues"]
                .as_array()
                .expect("issues")
                .iter()
                .any(|i| i["rule_id"] == "STATUTE/majority"),
            "cleared statute drops the overlay finding: {comp}"
        );
    }

    #[tokio::test]
    async fn old_shape_persisted_act_is_served_patched_and_sealed() {
        // §3 back-compat: an act persisted in the pre-t31 shape (no mesa/time/agenda/…, attachments
        // without `beginning_of_proof`, signatories without `permilage`) deserializes with defaults
        // and flows through GET / PATCH / advance / seal on the wire.
        let (state, _entity_id, book_id) = entity_and_open_book("SociedadeAnonima").await;
        let act_uuid = Uuid::new_v4();
        let old_shape = format!(
            r#"{{
                "id": "{act_uuid}",
                "book_id": "{book_id}",
                "title": "Ata antiga",
                "channel": "Physical",
                "meeting_date": null,
                "place": "Sede social",
                "attendance_reference": "Lista de presenças",
                "deliberations": "Aprovadas as contas.",
                "telematic_evidence": null,
                "attachments": [{{ "label": "Anexo", "kind": "Exhibit", "digest": null }}],
                "signatories": [{{ "name": "Ana", "capacity": "Chair", "signed": false }}],
                "state": "Draft",
                "ata_number": null,
                "payload_digest": null,
                "seal_event_seq": null,
                "retifies": null
            }}"#
        );
        let act: Act = serde_json::from_str(&old_shape).expect("old-shape act deserializes");
        state.acts.write().await.insert(ActId(act_uuid), act);

        // GET serves it with the new fields defaulted (mesa empty, time/agenda absent, and the new
        // nested flags at their defaults).
        let (status, got) = send(state.clone(), get(&format!("/v1/acts/{act_uuid}"))).await;
        assert_eq!(status, StatusCode::OK);
        assert!(got["mesa"]["presidente"].is_null());
        assert!(got["meeting_time"].is_null());
        assert_eq!(got["agenda"].as_array().expect("agenda").len(), 0);
        assert_eq!(
            got["deliberation_items"].as_array().expect("items").len(),
            0
        );
        assert_eq!(got["attachments"][0]["beginning_of_proof"], false);
        assert!(got["signatories"][0]["permilage"].is_null());

        // PATCH a mesa (+ time/agenda) onto it, advance, and seal — the whole wire serves it.
        let (status, _) = send(
            state.clone(),
            patch_json(
                &format!("/v1/acts/{act_uuid}"),
                json!({
                    "meeting_date": "2026-03-30",
                    "meeting_time": "10:00",
                    "mesa": { "presidente": "Ana Presidente", "secretarios": ["Rui Secretário"] },
                    "agenda": [{ "number": 1, "text": "Contas" }],
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        advance_to_signing(&state, &act_uuid.to_string()).await;
        let (status, sealed) = send(
            state,
            post_json(&format!("/v1/acts/{act_uuid}/seal"), json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "old-shape seal: {sealed}");
        assert_eq!(sealed["ata_number"], 1);
    }

    // --- Durable store persistence (t30) --------------------------------------------------

    /// Drive a full create → open book → draft → fill → advance → seal against `state`,
    /// returning `(entity_id, book_id, act_id)` with the act sealed as ata n.º 1.
    async fn seal_one(state: &AppState) -> (String, String, String) {
        let (status, entity) = send(
            state.clone(),
            post_json(
                "/v1/entities",
                json!({ "name": "Encosto Estratégico, S.A.", "nipc": "503004642", "seat": "Lisboa", "kind": "SociedadeAnonima" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let entity_id = entity["id"].as_str().expect("entity id").to_owned();

        let (status, book) = send(
            state.clone(),
            post_json(
                "/v1/books",
                json!({ "entity_id": entity_id, "kind": "AssembleiaGeral", "purpose": "livro", "opening_date": "2026-01-15", "required_signatories": ["Administrador"] }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let book_id = book["id"].as_str().expect("book id").to_owned();

        let (status, act) = send(
            state.clone(),
            post_json(
                "/v1/acts",
                json!({ "book_id": book_id, "title": "Ata", "channel": "Physical" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let act_id = act["id"].as_str().expect("act id").to_owned();

        let (status, _) = send(
            state.clone(),
            patch_json(
                &format!("/v1/acts/{act_id}"),
                json!({ "meeting_date": "2026-03-30", "meeting_time": "10:00", "place": "Sede social", "mesa": { "presidente": "Ana Presidente", "secretarios": ["Rui Secretário"] }, "agenda": [{ "number": 1, "text": "Contas" }], "attendance_reference": "Lista de presenças", "deliberations": "Aprovadas as contas." }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        for to in [
            "Review",
            "Convened",
            "Deliberated",
            "TextApproved",
            "Signing",
        ] {
            let (status, _) = send(
                state.clone(),
                post_json(&format!("/v1/acts/{act_id}/advance"), json!({ "to": to })),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
        }
        let (status, sealed) = send(
            state.clone(),
            // A fully-filled CSC v2 ata (mesa set) has no findings — no acknowledgement needed.
            post_json(&format!("/v1/acts/{act_id}/seal"), json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(sealed["ata_number"], 1);
        (entity_id, book_id, act_id)
    }

    #[tokio::test]
    async fn domain_and_ledger_survive_a_restart_via_the_store() {
        let tmp = TempDir::new();
        let (entity_id, book_id, act_id) = {
            let state = AppState::with_data_dir(tmp.dir.clone());
            assert!(
                state.store.is_some(),
                "with_data_dir opens the durable store"
            );
            seal_one(&state).await
        };

        // A fresh state over the same dir rebuilds every aggregate + the whole chain from disk.
        let restarted = AppState::with_data_dir(tmp.dir.clone());

        let (status, entity) =
            send(restarted.clone(), get(&format!("/v1/entities/{entity_id}"))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(entity["nipc"], "503004642");

        let (status, book) = send(restarted.clone(), get(&format!("/v1/books/{book_id}"))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(book["id"], book_id);

        let (status, act) = send(restarted.clone(), get(&format!("/v1/acts/{act_id}"))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(act["state"], "Sealed");
        assert_eq!(
            act["ata_number"], 1,
            "the sealed ata number survived the restart"
        );

        // The rehydrated chain verifies and the dashboard counts are intact.
        let (_, verify) = send(restarted.clone(), get("/v1/ledger/verify")).await;
        assert_eq!(verify["valid"], true);
        assert!(
            verify["length"].as_u64().expect("length") >= 4,
            "the whole chain reloaded: {verify}"
        );

        let (_, dash) = send(restarted, get("/v1/dashboard")).await;
        assert_eq!(dash["entities"], 1);
        assert_eq!(dash["acts_sealed"], 1);
    }

    #[tokio::test]
    async fn in_memory_state_has_no_store() {
        // AppState::default() keeps the historical in-memory behaviour: no durable store.
        let state = AppState::default();
        assert!(state.store.is_none());
        let _ = seal_one(&state).await;
        // A separate default state shares nothing durable — its chain is empty.
        let (_, verify) = send(AppState::default(), get("/v1/ledger/verify")).await;
        assert_eq!(verify["length"], 0);
    }

    #[tokio::test]
    async fn import_from_registry_persists_entity_and_extract_across_restart() {
        let tmp = TempDir::new();
        let html = "<!DOCTYPE html><html lang=\"pt-PT\"><body><div class=\"matricula\">\
             <p>MATRÍCULA</p><table>\
             <tr><td>Matrícula:</td><td>99999/20200101</td></tr>\
             <tr><td>NIF/NIPC:</td><td>503004642</td></tr>\
             <tr><td>Firma:</td><td>Encosto Estratégico, Lda</td></tr>\
             <tr><td>Natureza Jurídica:</td><td>Sociedade por quotas</td></tr>\
             <tr><td>Sede:</td><td>Lisboa</td></tr>\
             </table></div></body></html>";
        let entity_id = {
            let mut state = AppState::with_data_dir(tmp.dir.clone());
            state.registry = Some(Arc::new(
                chancela_registry::MockRegistryTransport::empty().with_html(html.to_owned()),
            ));
            let (status, report) = send(
                state.clone(),
                post_json(
                    "/v1/entities/import-from-registry",
                    json!({ "code": "1234-5678-9012" }),
                ),
            )
            .await;
            assert_eq!(status, StatusCode::CREATED);
            report["entity"]["id"]
                .as_str()
                .expect("entity id")
                .to_owned()
        };

        // Rebuild from disk: both the created entity and the imported extract are durable.
        let restarted = AppState::with_data_dir(tmp.dir.clone());
        let (status, entity) =
            send(restarted.clone(), get(&format!("/v1/entities/{entity_id}"))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(entity["nipc"], "503004642");

        let (status, extract) = send(
            restarted.clone(),
            get(&format!("/v1/entities/{entity_id}/registry")),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(extract["nipc"], "503004642");

        // Both events (entity.created + registry.imported) persisted and the chain verifies.
        let (_, verify) = send(restarted, get("/v1/ledger/verify")).await;
        assert_eq!(verify["valid"], true);
        assert_eq!(verify["length"], 2);
    }

    #[tokio::test]
    async fn backup_returns_a_manifest_when_persistent() {
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.dir.clone());
        let _ = seal_one(&state).await;

        let (status, manifest) = send(state.clone(), post_json("/v1/backup", json!({}))).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            manifest["path"].as_str().expect("path").ends_with(".zip"),
            "manifest path is the archive: {manifest}"
        );
        assert!(manifest["bytes"].as_u64().expect("bytes") > 0);
        assert_eq!(manifest["store_schema_version"], 1);
        assert_eq!(manifest["ledger_verified"], true);
        assert!(manifest["ledger_length"].as_u64().expect("length") >= 4);
        let files = manifest["files"].as_array().expect("files");
        assert!(files.iter().any(|f| f["name"] == "chancela.db"));

        // The archive really exists on disk under backups/.
        let path = manifest["path"].as_str().expect("path");
        assert!(
            std::path::Path::new(path).is_file(),
            "archive written: {path}"
        );

        // The backup itself is recorded in the chain.
        let (_, events) = send(state, get("/v1/ledger/events")).await;
        assert!(
            events
                .as_array()
                .expect("events")
                .iter()
                .any(|e| e["kind"] == "backup.created"),
            "a backup.created event was appended"
        );
    }

    #[tokio::test]
    async fn backup_in_memory_is_422() {
        let (status, body) = send(AppState::default(), post_json("/v1/backup", json!({}))).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            body["error"]
                .as_str()
                .expect("error")
                .contains("CHANCELA_DATA_DIR"),
            "422 explains how to enable persistence: {body}"
        );
    }

    #[tokio::test]
    async fn health_reports_durability_fields() {
        // In-memory: not persistent, boot-verify is null, no schema version key.
        let (status, body) = send(AppState::default(), get("/health")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "ok");
        assert_eq!(body["persistent"], false);
        assert_eq!(body["ledger_length"], 0);
        assert_eq!(body["ledger_verified"], Value::Null);
        assert!(body.get("store_schema_version").is_none());

        // Persistent: durable store, a boot-verified chain, and the schema version present.
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.dir.clone());
        let _ = seal_one(&state).await;
        let (status, body) = send(state, get("/health")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["persistent"], true);
        assert_eq!(body["ledger_verified"], true);
        assert_eq!(body["store_schema_version"], 1);
        assert!(body["ledger_length"].as_u64().expect("length") >= 4);
    }

    // --- t29: optional passwords + PKI audit attestation ----------------------------------
    //
    // These exercise the §4 contract over the router. Attestation is checked against
    // `entity.created`/`book.opened` mutations (not `seal`) so the suite is independent of the
    // CSC rule-pack's seal preconditions.

    /// Create a user and return its id.
    async fn make_user(state: &AppState, username: &str) -> String {
        let (status, u) = send(
            state.clone(),
            post_json("/v1/users", json!({ "username": username })),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        u["id"].as_str().expect("user id").to_owned()
    }

    /// Give a user a secret + attestation key, sign in with the password, and create one attested
    /// entity. Returns `(user_id, session_token, entity_event_seq)`.
    async fn attested_entity(state: &AppState, username: &str) -> (String, String, u64) {
        let id = make_user(state, username).await;
        send(
            state.clone(),
            post_json(
                &format!("/v1/users/{id}/secret"),
                json!({ "password": "s3cret-pass" }),
            ),
        )
        .await;
        send(
            state.clone(),
            post_json(
                &format!("/v1/users/{id}/attestation-key"),
                json!({ "current_password": "s3cret-pass" }),
            ),
        )
        .await;
        let (status, sess) = send(
            state.clone(),
            post_json(
                "/v1/session",
                json!({ "user_id": id, "password": "s3cret-pass" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let token = sess["token"].as_str().expect("token").to_owned();
        let (status, _) = send(
            state.clone(),
            with_session(
                post_json(
                    "/v1/entities",
                    json!({ "name": "Ent", "nipc": "503004642", "seat": "Lisboa", "kind": "SociedadeAnonima" }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let (_, events) = send(state.clone(), get("/v1/ledger/events")).await;
        let seq = events
            .as_array()
            .expect("events")
            .iter()
            .find(|e| e["kind"] == "entity.created")
            .expect("entity.created present")["seq"]
            .as_u64()
            .expect("seq");
        (id, token, seq)
    }

    #[tokio::test]
    async fn secret_gates_session_and_rejects_wrong_password() {
        let state = AppState::default();
        let id = make_user(&state, "amelia.marques").await;

        // Passwordless: the view says so and sign-in needs no password.
        let (_, view) = send(state.clone(), get(&format!("/v1/users/{id}"))).await;
        assert_eq!(view["has_secret"], false);
        assert_eq!(view["has_attestation_key"], false);
        assert!(view.get("attestation_key_fingerprint").is_none());
        let (status, _) = send(
            state.clone(),
            post_json("/v1/session", json!({ "user_id": id })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // Set a secret — no current_password needed the first time.
        let (status, view) = send(
            state.clone(),
            post_json(
                &format!("/v1/users/{id}/secret"),
                json!({ "password": "correct horse" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(view["has_secret"], true);

        // Now the password is required: wrong → 401, right → 200.
        let (status, body) = send(
            state.clone(),
            post_json("/v1/session", json!({ "user_id": id, "password": "nope" })),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(body["error"].is_string());
        // t41 M1: the new backoff table [1,2,4,...] kicks in after the first failure,
        // so clear the backoff before the correct attempt.
        state.signin_backoff.write().await.clear();
        let (status, _) = send(
            state.clone(),
            post_json(
                "/v1/session",
                json!({ "user_id": id, "password": "correct horse" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn repeated_wrong_password_triggers_backoff_429() {
        let state = AppState::default();
        let id = make_user(&state, "bruno").await;
        send(
            state.clone(),
            post_json(
                &format!("/v1/users/{id}/secret"),
                json!({ "password": "s3cret-pass" }),
            ),
        )
        .await;
        // t41 M1: the new backoff table [1,2,4,...] means the FIRST wrong attempt sets a 1s
        // window. So the first attempt is 401, and any immediate subsequent attempt is 429.
        let (status, _) = send(
            state.clone(),
            post_json("/v1/session", json!({ "user_id": id, "password": "wrong" })),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        // Within the 1s window even the correct password is refused with 429.
        let (status, body) = send(
            state.clone(),
            post_json(
                "/v1/session",
                json!({ "user_id": id, "password": "s3cret-pass" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert!(
            body["error"]
                .as_str()
                .expect("error")
                .contains("tente novamente")
        );
    }

    #[tokio::test]
    async fn attestation_key_requires_a_secret_and_verifies_the_current_one() {
        let state = AppState::default();
        let id = make_user(&state, "carla").await;
        // No secret → 409.
        let (status, _) = send(
            state.clone(),
            post_json(&format!("/v1/users/{id}/attestation-key"), json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);

        send(
            state.clone(),
            post_json(
                &format!("/v1/users/{id}/secret"),
                json!({ "password": "s3cret-pass" }),
            ),
        )
        .await;
        // Wrong current password → 401.
        let (status, _) = send(
            state.clone(),
            post_json(
                &format!("/v1/users/{id}/attestation-key"),
                json!({ "current_password": "nope" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        // Correct → 200 with a 32-hex fingerprint.
        let (status, view) = send(
            state.clone(),
            post_json(
                &format!("/v1/users/{id}/attestation-key"),
                json!({ "current_password": "s3cret-pass" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(view["has_attestation_key"], true);
        assert_eq!(
            view["attestation_key_fingerprint"]
                .as_str()
                .expect("fingerprint")
                .len(),
            32
        );
    }

    #[tokio::test]
    async fn attested_mutation_verifies_and_names_the_user() {
        let state = AppState::default();
        let (_id, _token, seq) = attested_entity(&state, "diana").await;

        // The ledger event carries the attestation summary.
        let (_, events) = send(state.clone(), get("/v1/ledger/events")).await;
        let created = events
            .as_array()
            .expect("events")
            .iter()
            .find(|e| e["kind"] == "entity.created")
            .expect("entity.created");
        assert_eq!(created["attestation"]["username"], "diana");
        assert_eq!(created["attestation"]["algorithm"], "ES256");
        assert_eq!(
            created["attestation"]["fingerprint"]
                .as_str()
                .expect("fingerprint")
                .len(),
            32
        );

        // Server-side verify: valid, correct user, no reason.
        let (status, v) = send(state, get(&format!("/v1/ledger/attestations/{seq}"))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(v["valid"], true);
        assert_eq!(v["attestation"]["username"], "diana");
        assert_eq!(v["attestation"]["event_seq"], seq);
        assert!(v.get("reason").is_none_or(Value::is_null));
    }

    #[tokio::test]
    async fn tampered_attestation_is_reported_invalid() {
        let state = AppState::default();
        let (_id, _token, seq) = attested_entity(&state, "elsa").await;
        // Simulate a rebuilt/tampered chain: overwrite the stored event_hash so the signature no
        // longer matches what is recorded.
        {
            let mut atts = state.attestations.write().await;
            let att = atts.get_mut(&seq).expect("attestation present");
            att.event_hash = "00".repeat(32);
        }
        let (status, v) = send(state, get(&format!("/v1/ledger/attestations/{seq}"))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(v["valid"], false);
        assert!(v["reason"].is_string());
    }

    #[tokio::test]
    async fn removing_the_key_makes_prior_attestations_unverifiable() {
        let state = AppState::default();
        let (id, _token, seq) = attested_entity(&state, "iris").await;
        // Valid while the key exists.
        let (_, v) = send(
            state.clone(),
            get(&format!("/v1/ledger/attestations/{seq}")),
        )
        .await;
        assert_eq!(v["valid"], true);
        // Remove the attestation key.
        let (status, view) = send(
            state.clone(),
            body_json(
                "DELETE",
                &format!("/v1/users/{id}/attestation-key"),
                json!({ "current_password": "s3cret-pass" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(view["has_attestation_key"], false);
        // The attestation is still stored, but its key is gone → invalid with a key-not-found reason.
        let (status, v) = send(state, get(&format!("/v1/ledger/attestations/{seq}"))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(v["valid"], false);
        assert!(v["reason"].as_str().expect("reason").contains("key"));
    }

    #[tokio::test]
    async fn passwordless_mutation_has_no_attestation() {
        let state = AppState::default();
        let id = make_user(&state, "eva").await;
        let (_, sess) = send(
            state.clone(),
            post_json("/v1/session", json!({ "user_id": id })),
        )
        .await;
        let token = sess["token"].as_str().expect("token").to_owned();
        let (status, _) = send(
            state.clone(),
            with_session(
                post_json(
                    "/v1/entities",
                    json!({ "name": "E", "nipc": "503004642", "seat": "L", "kind": "Cooperativa" }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let (_, events) = send(state.clone(), get("/v1/ledger/events")).await;
        let created = events
            .as_array()
            .expect("events")
            .iter()
            .find(|e| e["kind"] == "entity.created")
            .expect("entity.created");
        assert!(created["attestation"].is_null());
        let seq = created["seq"].as_u64().expect("seq");
        // No attestation to fetch → 404.
        let (status, _) = send(state, get(&format!("/v1/ledger/attestations/{seq}"))).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn removing_the_secret_cascades_the_attestation_key() {
        let state = AppState::default();
        let id = make_user(&state, "fabio").await;
        send(
            state.clone(),
            post_json(
                &format!("/v1/users/{id}/secret"),
                json!({ "password": "s3cret-pass" }),
            ),
        )
        .await;
        send(
            state.clone(),
            post_json(
                &format!("/v1/users/{id}/attestation-key"),
                json!({ "current_password": "s3cret-pass" }),
            ),
        )
        .await;
        // Wrong current password on removal → 401.
        let (status, _) = send(
            state.clone(),
            body_json(
                "DELETE",
                &format!("/v1/users/{id}/secret"),
                json!({ "current_password": "nope" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        // Correct → 200; both the secret and the (now unrecoverable) key are cleared.
        let (status, view) = send(
            state.clone(),
            body_json(
                "DELETE",
                &format!("/v1/users/{id}/secret"),
                json!({ "current_password": "s3cret-pass" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(view["has_secret"], false);
        assert_eq!(view["has_attestation_key"], false);
    }

    #[tokio::test]
    async fn changing_the_secret_rewraps_the_key() {
        let state = AppState::default();
        let id = make_user(&state, "gita").await;
        send(
            state.clone(),
            post_json(
                &format!("/v1/users/{id}/secret"),
                json!({ "password": "old-secret" }),
            ),
        )
        .await;
        send(
            state.clone(),
            post_json(
                &format!("/v1/users/{id}/attestation-key"),
                json!({ "current_password": "old-secret" }),
            ),
        )
        .await;
        // Change the secret (current one required).
        let (status, _) = send(
            state.clone(),
            post_json(
                &format!("/v1/users/{id}/secret"),
                json!({ "password": "new-secret", "current_password": "old-secret" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        // Old password no longer signs in; the new one does and still unlocks the re-wrapped key.
        let (status, _) = send(
            state.clone(),
            post_json(
                "/v1/session",
                json!({ "user_id": id, "password": "old-secret" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        // t41 M1: clear backoff so the correct attempt isn't blocked by the 1s window.
        state.signin_backoff.write().await.clear();
        let (status, sess) = send(
            state.clone(),
            post_json(
                "/v1/session",
                json!({ "user_id": id, "password": "new-secret" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let token = sess["token"].as_str().expect("token").to_owned();
        let (status, _) = send(
            state.clone(),
            with_session(
                post_json(
                    "/v1/entities",
                    json!({ "name": "E", "nipc": "503004642", "seat": "L", "kind": "Cooperativa" }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let (_, events) = send(state, get("/v1/ledger/events")).await;
        let created = events
            .as_array()
            .expect("events")
            .iter()
            .find(|e| e["kind"] == "entity.created")
            .expect("entity.created");
        assert_eq!(created["attestation"]["username"], "gita");
    }

    #[tokio::test]
    async fn onboarding_flag_round_trips() {
        let state = AppState::default();
        let (_, body) = send(state.clone(), get("/v1/settings")).await;
        assert_eq!(body["onboarding"]["completed"], false);
        assert_eq!(body["onboarding"]["completed_at"], Value::Null);

        let mut doc = sample_settings();
        doc["onboarding"] = json!({ "completed": true, "completed_at": "2026-07-07T10:00:00Z" });
        let (status, stored) = send(state.clone(), put_json("/v1/settings", doc)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(stored["onboarding"]["completed"], true);

        let (_, got) = send(state, get("/v1/settings")).await;
        assert_eq!(got["onboarding"]["completed"], true);
        assert_eq!(got["onboarding"]["completed_at"], "2026-07-07T10:00:00Z");
    }

    #[tokio::test]
    async fn short_secret_is_422_and_users_wire_hides_material() {
        let state = AppState::default();
        let id = make_user(&state, "hugo").await;
        // Below the 8-char floor → 422.
        let (status, body) = send(
            state.clone(),
            post_json(
                &format!("/v1/users/{id}/secret"),
                json!({ "password": "short" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(body["error"].is_string());

        // Set a valid secret + key, then confirm the wire dump carries no secret material.
        send(
            state.clone(),
            post_json(
                &format!("/v1/users/{id}/secret"),
                json!({ "password": "s3cret-pass" }),
            ),
        )
        .await;
        send(
            state.clone(),
            post_json(
                &format!("/v1/users/{id}/attestation-key"),
                json!({ "current_password": "s3cret-pass" }),
            ),
        )
        .await;
        let (_, list) = send(state, get("/v1/users")).await;
        let dump = list.to_string().to_lowercase();
        assert!(!dump.contains("password"), "no password token: {dump}");
        assert!(!dump.contains("$argon2"), "no PHC hash: {dump}");
        assert!(!dump.contains("ciphertext"), "no wrapped key: {dump}");
        assert!(!dump.contains("kdf_salt"), "no KDF material: {dump}");
    }
}
