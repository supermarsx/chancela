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
mod authz;
mod backup;
mod books;
mod bundles;
mod cae;
mod chronology;
mod dashboard;
mod data;
mod delegations;
mod documents;
mod dto;
mod entities;
mod error;
mod hex;
mod law;
mod ledger;
mod recovery;
mod registry;
mod roles;
mod session;
mod settings;
mod signature;
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
use axum::routing::{any, delete, get, patch, post};
use chancela_cae::{CaeCatalog, CaeSource, CaeSourceChain};
use chancela_cmd::ScmdTransport;
use chancela_core::{Act, ActId, Book, BookId, Entity, EntityId};
use chancela_ledger::{Event, Ledger, LedgerError};
use chancela_registry::{RegistryExtract, RegistryTransport};
use chancela_signing::{SignerProvider, SigningError, TrustPolicy};
use chancela_store::{
    PendingCmdSession, Store, StoreError, StoredDocument, StoredSignedDocument, Tx,
};
use serde::Serialize;
use tokio::sync::RwLock;
use tower_http::services::{ServeDir, ServeFile};

pub use actor::{CurrentActor, CurrentAttestor};
pub use authz::{
    Authorizer, authorizer, require_permission, require_permission_with, scope_of_act,
    scope_of_book, scope_of_entity,
};
pub use delegations::{DelegationId, StoredDelegation};
pub use error::ApiError;
pub use law::{LawEntry, LawEntryView, LawStore, StoredLawInfo};
pub use roles::{
    count_owner_admins, effective_permissions_for, effective_permissions_for_actor,
    last_owner_guard_ok, resolve_principal_id,
};
pub use settings::{
    AppearanceSettings, CaeSourceEntry, CatalogSettings, CmdEnvSetting, DocumentSettings, Locale,
    OnboardingSettings, OrganizationSettings, Settings, SignatureFamily, SigningCmdSettings,
    SigningSettings, ThemeMode,
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
    /// The scoped RBAC role catalog (t64): the seeded defaults + any custom roles. `Default` empty;
    /// [`AppState::with_data_dir`] loads `roles.json` and **ensures the seeded defaults are present**
    /// (Owner forced canonical/locked). Mirrors `users`.
    pub roles: Arc<RwLock<chancela_authz::RoleCatalog>>,
    /// Where `roles.json` is persisted, or `None` for in-memory. Mirrors `users_path`.
    pub roles_path: Option<Arc<PathBuf>>,
    /// The scoped delegation table (t64): active **and** revoked delegations, keyed by
    /// [`DelegationId`]. `Default` empty; [`AppState::with_data_dir`] loads `delegations.json`.
    pub delegations: Arc<RwLock<HashMap<DelegationId, delegations::StoredDelegation>>>,
    /// Where `delegations.json` is persisted, or `None` for in-memory. Mirrors `users_path`.
    pub delegations_path: Option<Arc<PathBuf>>,
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
    /// Cross-user secret/reset backoff (t52): the speed-bump on the credential-reset endpoints
    /// (`set_secret`/`remove_secret`/`attestation-key`/`recovery`), keyed by
    /// **`(requester, target-from-request)`** so a failed attempt against a *non-existent* target
    /// accrues and throttles IDENTICALLY to one against a real target (no enumeration oracle), while
    /// an attacker hammering a victim's id cannot lock out that victim's own self-service (a
    /// different key, never throttled). Mirrors `signin_backoff`: in-memory, resets on restart, not a
    /// hardened anti-brute-force. See `users::authorize_secret_op_throttled`.
    pub secret_backoff: Arc<RwLock<HashMap<users::SecretBackoffKey, session::Backoff>>>,
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
    /// The live document read model (t48 / DOC-01): generated documents (PDF/A-2u bytes +
    /// metadata) keyed by the owning [`ActId`]. Book instruments (termos) key on their book id
    /// cast into an `ActId`. Mirrors `acts`/`books`: an in-memory read model backed by the durable
    /// `documents` table; the GET endpoints fall back to the store on a miss (e.g. after a restart,
    /// before the map is repopulated). `Default` empty.
    pub documents: Arc<RwLock<HashMap<ActId, StoredDocument>>>,
    /// The boot-time chain-verification outcome recorded by [`AppState::with_data_dir`] when the
    /// durable ledger was rehydrated (§D-boot): `Some(Ok(len))` for an intact chain, `Some(Err(..))`
    /// for a broken one (surfaced on `/health` + the startup banner), `None` in-memory. Shared via
    /// `Arc` so cloning the state stays cheap.
    pub chain_status: Option<Arc<Result<u64, LedgerError>>>,
    /// The **degraded read-only signal** (t54 §3.1). `true` when the ledger's integrity report is
    /// unhealthy (a broken chain) — set at boot from the rehydrated [`IntegrityReport`], and
    /// recomputed after every recovery op (restore / re-anchor / factory reset). While set, the
    /// [`degraded_gate`] middleware fails **loud** with `503` on ordinary mutations (create / patch /
    /// advance / seal / open / close / start-over / import-into-live), leaving reads, the integrity
    /// report, and the recovery/reset/export/quarantine-import endpoints open so the operator can see
    /// and repair. `Default` is healthy (`false`); pure in-memory state never enters degraded.
    pub degraded: Arc<RwLock<bool>>,
    /// The live SIGNED-document read model (t57-S3): the qualified signed PDF variant + metadata per
    /// act, keyed by [`ActId`]. Mirrors `documents`: an in-memory read model backed by the durable
    /// `signed_documents` table, with the read endpoints falling back to the store on a miss.
    pub signed_documents: Arc<RwLock<HashMap<ActId, StoredSignedDocument>>>,
    /// In-flight two-phase Chave Móvel Digital signing sessions (t57-S3), keyed by session id. The
    /// non-secret resumable handle between `initiate` and `confirm`; **never holds a PIN or OTP**.
    /// Backed by the durable `pending_cmd_sessions` table (rehydrated on boot), so a session survives
    /// a restart.
    pub pending_signatures: Arc<RwLock<HashMap<String, PendingCmdSession>>>,
    /// Test/DI seam (t57-S3): an injected SCMD transport. `None` in production, where the signing
    /// handlers build a real `chancela_cmd::HttpScmdTransport` from the resolved [`CmdConfig`] and run
    /// it off the async runtime. Tests inject a `MockScmdTransport`-backed transport here so the
    /// initiate/confirm round-trip runs offline (no live SCMD). Must be `Send + Sync` for the shared
    /// state; the mock used in tests wraps its recorder so it satisfies that.
    pub cmd_transport: Option<Arc<dyn ScmdTransport + Send + Sync>>,
    /// Test/DI seam (t57-S3): an injected trusted-list policy factory (SIG-11/23). `None` in
    /// production, where the qualified path builds a `TslTrustPolicy` over the settings `tsl_url`
    /// (network-gated, run during the actual sign). Tests inject a `StaticTrustPolicy` factory to
    /// drive the gate offline (granted / withdrawn) without fetching the live TSL.
    ///
    /// **Reused by the Cartão de Cidadão (CC) path too (t58-e2):** the CC qualified signature runs
    /// the same trusted-list gate over the same factory, so both qualified methods agree on how
    /// trust is resolved in tests and production.
    #[allow(clippy::type_complexity)]
    pub cmd_trust_policy: Option<Arc<dyn Fn() -> Box<dyn TrustPolicy + Send> + Send + Sync>>,
    /// Whether this API process is **co-located** with a Cartão de Cidadão reader (t58 CC-B).
    /// Resolved once at construction from the `CHANCELA_LOCAL_SIGNING` signal the desktop shell sets
    /// on the embedded-server process (t58-e3); a remote `chancela-server` never sets it, so this
    /// stays `false` and the CC signing endpoint 409s there (the card is on the client's machine,
    /// unreachable by a remote server's PKCS#11). `Default` is `false`; tests set it directly.
    pub local_signing: bool,
    /// Test/DI seam (t58-e2): an injected Cartão de Cidadão signer-provider factory. `None` in
    /// production, where the co-located desktop handler opens a real `Pkcs11Token` and wraps it as a
    /// `SmartcardProvider` inside `spawn_blocking`. Tests inject a key-backed provider so the CC sign
    /// round-trip runs offline (no reader / PKCS#11 / hardware). Invoked inside `spawn_blocking`
    /// (PKCS#11/PC/SC is blocking + the middleware blocks on PIN entry at the reader); a card/reader
    /// failure surfaces as [`chancela_signing::SigningError::Provider`]. The produced provider never
    /// crosses a thread boundary (built and consumed inside the blocking task), so it need not be
    /// `Send`; only the factory is.
    #[allow(clippy::type_complexity)]
    pub cc_provider:
        Option<Arc<dyn Fn() -> Result<Box<dyn SignerProvider>, SigningError> + Send + Sync>>,
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
        let mut loaded_users = users::load_users(&users_path).unwrap_or_default();

        // Scoped RBAC stores (t64): the role catalog + the delegation table, mirroring `users.json`.
        // The catalog seeds the four defaults if absent (Owner forced canonical/locked); the users
        // are brought forward by the one-time, idempotent, anti-lockout role migration. Each is
        // rewritten to disk exactly once, only when the load actually changed it.
        let roles_path = dir.join(roles::ROLES_FILE);
        let mut roles_catalog = roles::load_roles(&roles_path).unwrap_or_default();
        if roles::ensure_seeded_defaults(&mut roles_catalog) {
            if let Err(e) = roles::write_roles_atomic(&roles_path, &roles_catalog) {
                eprintln!("warning: failed to seed {} ({e})", roles_path.display());
            }
        }
        if roles::migrate_roles(&mut loaded_users) {
            if let Err(e) = users::write_users_atomic(&users_path, &loaded_users) {
                eprintln!(
                    "warning: failed to persist the role migration to {} ({e})",
                    users_path.display()
                );
            }
        }
        let delegations_path = dir.join(delegations::DELEGATIONS_FILE);
        let loaded_delegations =
            delegations::load_delegations(&delegations_path).unwrap_or_default();
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
            roles: Arc::new(RwLock::new(roles_catalog)),
            roles_path: Some(Arc::new(roles_path)),
            delegations: Arc::new(RwLock::new(loaded_delegations)),
            delegations_path: Some(Arc::new(delegations_path)),
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
                    // Fail-loud gate (t54 §3.1): a broken boot chain enters DEGRADED read-only mode
                    // instead of silently booting as if healthy. Reads + recovery stay open; ordinary
                    // mutations return 503 until a restore / re-anchor / factory reset repairs it.
                    let healthy = loaded.integrity.healthy;
                    if let Err(e) = &loaded.chain_status {
                        eprintln!(
                            "chancela-store: ledger chain integrity check FAILED on boot ({e}) — \
                             entering DEGRADED read-only mode: reads and the recovery endpoints \
                             (restore / re-anchor / factory reset) stay open so the operator can \
                             inspect and repair; ordinary mutations are blocked with 503"
                        );
                    }
                    state.entities = Arc::new(RwLock::new(loaded.entities));
                    state.books = Arc::new(RwLock::new(loaded.books));
                    state.acts = Arc::new(RwLock::new(loaded.acts));
                    state.registry_extracts = Arc::new(RwLock::new(loaded.registry_extracts));
                    state.ledger = Arc::new(RwLock::new(loaded.ledger));
                    state.chain_status = Some(Arc::new(loaded.chain_status));
                    state.degraded = Arc::new(RwLock::new(!healthy));
                    // Rehydrate the qualified-signing read models (t57-S3): the signed variants and
                    // any in-flight pending CMD sessions, so a session survives a restart and the
                    // signed-PDF/status reads serve from memory. A read failure is non-fatal (the
                    // endpoints fall back to the store on a miss).
                    if let Ok(signed) = store.all_signed_documents() {
                        state.signed_documents = Arc::new(RwLock::new(signed));
                    }
                    if let Ok(pending) = store.all_pending_cmd_sessions() {
                        state.pending_signatures = Arc::new(RwLock::new(pending));
                    }
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

        // Resolve the CC co-location signal (t58-e2 / CC-B) from the environment the desktop shell
        // set before it spawned this embedded server (t58-e3). Absent (a remote server) ⇒ `false`.
        state.local_signing = signature::local_signing_from_env();
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

    /// Roll the last `count` just-appended events back out of the in-memory `ledger`, rebuilding
    /// the chain without them. Used when an in-memory step **after** an append fails **before** the
    /// durable commit (t48: document generation during a seal / book open), so the in-memory chain
    /// stays identical to the untouched store and no aggregate change is committed. Mirrors the
    /// rollback [`persist_write_through`] performs on a store failure.
    pub(crate) fn rollback_ledger_events(ledger: &mut Ledger, count: usize) {
        let len = ledger.len();
        let kept: Vec<Event> = ledger.events()[..len - count].to_vec();
        *ledger = Ledger::try_from_events(kept).0;
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

    /// The whole-instance sidecar files bundled alongside the SQLite snapshot in a backup / export
    /// archive and removed on a factory reset (t54 §2.11): `settings.json`, `users.json`, the CAE
    /// cache, and the `laws/` archive. Mirrors [`backup::create_backup`]'s list. Empty when in-memory.
    pub(crate) fn instance_sidecars(&self) -> Vec<PathBuf> {
        match self.data_dir() {
            Some(dir) => vec![
                dir.join(crate::settings::SETTINGS_FILE),
                dir.join(crate::users::USERS_FILE),
                dir.join(crate::roles::ROLES_FILE),
                dir.join(crate::delegations::DELEGATIONS_FILE),
                dir.join(chancela_cae::CACHE_FILE),
                dir.join(crate::law::LAWS_DIR),
            ],
            None => Vec::new(),
        }
    }

    /// Reload the domain read-models (entities / books / acts / registry extracts) from the durable
    /// store into memory and drop the cached documents map (GETs fall back to the store), after a
    /// whole-store restore so reads reflect the swapped-in state. A no-op when in-memory. Does NOT
    /// touch the ledger — the restore path already replaced it in lock-step.
    pub(crate) async fn reload_domain_memory(&self) -> Result<(), ApiError> {
        let Some(store) = &self.store else {
            return Ok(());
        };
        let loaded = store
            .load()
            .map_err(|e| ApiError::Internal(format!("reload after restore failed: {e}")))?;
        *self.entities.write().await = loaded.entities;
        *self.books.write().await = loaded.books;
        *self.acts.write().await = loaded.acts;
        *self.registry_extracts.write().await = loaded.registry_extracts;
        self.documents.write().await.clear();
        Ok(())
    }

    /// Clear the in-memory domain read-models (entities / books / acts / registry extracts /
    /// documents) to match a `BackendDomain` wipe or a whole-instance start-over (the ledger is
    /// preserved / re-seeded by the store, never touched here).
    pub(crate) async fn clear_domain_memory(&self) {
        self.entities.write().await.clear();
        self.books.write().await.clear();
        self.acts.write().await.clear();
        self.registry_extracts.write().await.clear();
        self.documents.write().await.clear();
    }

    /// Clear ALL in-memory state to a blank first-run instance, to match a `BackendFactory` reset
    /// (which also blanked the ledger + removed the sidecar files on disk): the domain read-models,
    /// the user profiles, every live session + unlocked key, the attestation sidecar, and the
    /// settings document (reset to defaults). The acting session is invalidated by design.
    pub(crate) async fn clear_all_memory(&self) {
        self.clear_domain_memory().await;
        self.users.write().await.clear();
        self.sessions.write().await.clear();
        self.attestations.write().await.clear();
        // A blank first-run instance has the seeded default roles and no delegations (t64), matching
        // what a subsequent load of the wiped data dir would reseed.
        *self.roles.write().await = chancela_authz::RoleCatalog::seeded_defaults();
        self.delegations.write().await.clear();
        *self.settings.write().await = settings::Settings::default();
    }

    /// Resolve on-disk persistence from the environment, mirroring how `chancela-server` finds
    /// the web build: honour `CHANCELA_DATA_DIR` first, else walk up from the current directory
    /// for an existing `chancela-data/` directory, else run purely in memory.
    ///
    /// This is the one call a binary swaps in for [`AppState::default`] to gain persistence.
    pub fn from_env() -> Self {
        match Self::resolve_data_dir() {
            Some(dir) => Self::with_data_dir(dir),
            // Pure in-memory (no data dir): seed the RBAC catalog so the bootstrap first user's
            // Owner\@Global assignment resolves to real authority. Without this a fresh in-memory
            // instance would hold an Owner assignment against an EMPTY catalog (fail-closed →
            // no permissions anywhere), locking the operator out of their own instance (t64-E3).
            None => {
                let state = Self::default();
                let seeded = Arc::new(RwLock::new(chancela_authz::RoleCatalog::seeded_defaults()));
                AppState {
                    roles: seeded,
                    // Honour the CC co-location signal even in the pure in-memory desktop dev path.
                    local_signing: signature::local_signing_from_env(),
                    ..state
                }
            }
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
        .route(
            "/v1/entities/{id}/chronology",
            get(chronology::get_entity_chronology),
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
        .route(
            "/v1/acts/{id}/document/preview",
            get(documents::preview_document),
        )
        .route(
            "/v1/acts/{id}/document/generate",
            post(documents::generate_document),
        )
        .route("/v1/acts/{id}/document", get(documents::get_document_pdf))
        .route(
            "/v1/acts/{id}/document/bundle",
            get(documents::get_document_bundle),
        )
        .route(
            "/v1/acts/{id}/signature/cmd/initiate",
            post(signature::initiate_cmd_signature),
        )
        .route(
            "/v1/acts/{id}/signature/cmd/confirm",
            post(signature::confirm_cmd_signature),
        )
        .route(
            "/v1/acts/{id}/signature/cc/sign",
            post(signature::sign_cc_signature),
        )
        .route(
            "/v1/acts/{id}/signature",
            get(signature::get_signature_status),
        )
        .route(
            "/v1/acts/{id}/document/signed",
            get(signature::get_signed_document_pdf),
        )
        .route("/v1/templates", get(documents::list_templates))
        .route("/v1/ledger/events", get(ledger::list_ledger_events))
        .route("/v1/ledger/verify", get(ledger::verify_ledger))
        .route("/v1/ledger/integrity", get(recovery::get_integrity))
        .route(
            "/v1/ledger/recovery/reanchor",
            post(recovery::reanchor_ledger),
        )
        .route("/v1/ledger/recovery/restore", post(recovery::restore_store))
        .route("/v1/books/{id}/export", post(bundles::export_book))
        .route("/v1/books/import", post(bundles::import_book))
        .route("/v1/books/{id}/start-over", post(bundles::start_over_book))
        .route("/v1/data/reset", post(data::reset_data))
        .route("/v1/data/start-over", post(data::start_over_instance))
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
        .route("/v1/users/{id}/recovery", post(users::issue_recovery))
        .route(
            "/v1/ledger/attestations/{seq}",
            get(ledger::get_attestation),
        )
        // RBAC management (t64-E4): role CRUD, the permission catalog, scoped role assignment, and
        // scoped delegation. Mutations are gated + invariant-enforced server-side (see the handlers).
        .route("/v1/roles", get(roles::list_roles).post(roles::create_role))
        .route(
            "/v1/roles/{id}",
            patch(roles::patch_role).delete(roles::delete_role),
        )
        .route("/v1/permissions", get(roles::list_permissions))
        .route(
            "/v1/users/{id}/roles",
            post(roles::assign_role).delete(roles::unassign_role),
        )
        .route(
            "/v1/delegations",
            get(delegations::list_delegations).post(delegations::grant_delegation),
        )
        .route(
            "/v1/delegations/{id}",
            delete(delegations::revoke_delegation),
        )
        .route("/v1/session/roster", get(session::session_roster))
        .route("/v1/session/permissions", get(session::session_permissions))
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
        // Degraded read-only gate (t54 §3.1): block ordinary mutations with 503 when the chain is
        // broken, leaving reads + the recovery/reset/export/quarantine-import endpoints open. Layered
        // BELOW `security_headers` (added after) so a 503 still carries the security headers.
        .layer(middleware::from_fn_with_state(state.clone(), degraded_gate))
        // Security response headers (t41 M2).
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

/// Whether a request is exempt from the degraded (read-only) mutation gate (t54 §3.1).
///
/// Reads (`GET`/`HEAD`/`OPTIONS`) are always allowed. Among mutations, only the **recovery** plane
/// stays reachable in a broken-chain instance — a restore / re-anchor / factory reset is the
/// legitimate last-resort repair, an export lets the operator archive first, a quarantine-import is
/// isolated and never merged into a live chain, and the session endpoints must work so the operator
/// can authenticate to run any of these. Every other mutation is blocked with `503` while degraded.
fn degraded_gate_exempt(method: &axum::http::Method, path: &str) -> bool {
    use axum::http::Method;
    if matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS) {
        return true;
    }
    path == "/v1/ledger/recovery/reanchor"
        || path == "/v1/ledger/recovery/restore"
        || path == "/v1/data/reset"
        || path == "/v1/data/start-over"
        || path == "/v1/books/import"
        || path.starts_with("/v1/session")
        || (path.starts_with("/v1/books/") && path.ends_with("/export"))
}

/// Middleware enforcing the degraded read-only gate. When [`AppState::degraded`] is set, an ordinary
/// mutation (not [`degraded_gate_exempt`]) is refused with a **loud** honest-PT `503` naming the
/// read-only mode; reads and the recovery/reset endpoints pass through unchanged.
async fn degraded_gate(
    State(state): State<AppState>,
    request: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Response {
    if !degraded_gate_exempt(request.method(), request.uri().path()) && *state.degraded.read().await
    {
        let body = serde_json::json!({
            "error": "sistema em modo só-leitura: a cadeia de integridade está quebrada. \
                      Restaure a partir de uma cópia de segurança, faça a re-ancoragem, ou uma \
                      reposição de fábrica antes de continuar a escrever.",
            "read_only": true,
            "integrity": "broken",
        });
        return (StatusCode::SERVICE_UNAVAILABLE, Json(body)).into_response();
    }
    next.run(request).await
}

/// Recompute the degraded (read-only) signal from a ledger's live integrity report and store it on
/// `state` (t54 §3.1). Called after a recovery op (restore / re-anchor / factory reset) so a repaired
/// chain lifts the gate — and a still-broken one keeps it. Runs a full `integrity_report()`; it is
/// only invoked on the rare recovery paths, never on the hot mutation path.
pub(crate) async fn refresh_degraded(state: &AppState, ledger: &Ledger) {
    let healthy = ledger.integrity_report().healthy;
    *state.degraded.write().await = !healthy;
}

/// Route a user-driven ledger append through the validating [`Ledger::try_append`] (t54 deliverable
/// #6): an append that would break a chain (wrong genesis kind, or onto a broken tail) is rejected
/// **before** the ledger is mutated, so nothing is persisted and the surrounding transaction is safe
/// to abort. Replaces the infallible `append` on the api's domain mutation paths.
pub(crate) fn try_append_event(
    ledger: &mut Ledger,
    actor: &str,
    scope: &str,
    kind: &str,
    justification: Option<&str>,
    payload: &[u8],
) -> Result<(), ApiError> {
    ledger
        .try_append(actor, scope, kind, justification, payload)
        .map(|_| ())
        .map_err(|e| ApiError::Conflict(format!("appending {kind} would break a chain: {e}")))
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
    /// The live integrity signal (t54 §3.1): `"broken"` when the instance is in degraded read-only
    /// mode (a broken chain — mutations are gated with `503`), else `"ok"`. The web reads this to
    /// raise the server-driven degraded banner.
    integrity: &'static str,
    /// Whether the instance is in degraded read-only mode (mirrors `integrity == "broken"`).
    degraded: bool,
}

/// Liveness probe; also reports the running crate version (used by the Docker healthcheck) and,
/// additively, the durability/ledger signal (t30 §3.3).
async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    let persistent = state.store.is_some();
    let ledger_length = state.ledger.read().await.len() as u64;
    let ledger_verified = state.chain_status.as_ref().map(|status| status.is_ok());
    let store_schema_version = persistent.then_some(chancela_store::schema::SCHEMA_VERSION);
    let degraded = *state.degraded.read().await;
    Json(HealthResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
        persistent,
        ledger_length,
        ledger_verified,
        store_schema_version,
        integrity: if degraded { "broken" } else { "ok" },
        degraded,
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
        use chancela_authz::{OWNER_ROLE_ID, RoleAssignment, RoleCatalog, Scope};
        use time::format_description::well_known::Rfc3339;
        // RBAC (t64-E3): every gated endpoint resolves the acting user's scoped permissions against
        // the role catalog. A pure in-memory `AppState::default()` has an EMPTY catalog, so seed the
        // defaults and make the test actor **Owner\@Global** — the bootstrap-first-user identity every
        // in-crate test implicitly acts as (an admin operating its own instance). Idempotent.
        {
            let mut roles = state.roles.write().await;
            if roles.is_empty() {
                *roles = RoleCatalog::seeded_defaults();
            }
        }
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
            secret_source: Default::default(),
            recovery_hash: None,
            role_assignments: vec![RoleAssignment::new(OWNER_ROLE_ID, Scope::Global)],
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

    /// A fresh in-memory state with the RBAC catalog seeded — the in-memory equivalent of a real
    /// first-run install (mirrors [`AppState::from_env`]'s in-memory seeding). Used by the tests that
    /// bootstrap the first user through the API and then act AS that Owner: without a seeded catalog
    /// the bootstrap Owner\@Global assignment would resolve against an empty catalog and grant nothing
    /// (fail-closed), which is precisely the in-memory lockout `from_env` now prevents (t64-E3).
    async fn fresh_state() -> AppState {
        let state = AppState::default();
        *state.roles.write().await = chancela_authz::RoleCatalog::seeded_defaults();
        state
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

    /// Send a request and return (status, content-type, raw body bytes) — for the non-JSON PDF
    /// download. Auto-seeds a session like [`send`].
    async fn send_bytes(state: AppState, req: Request<Body>) -> (StatusCode, String, Vec<u8>) {
        let req = if req.headers().get("x-chancela-session").is_none() {
            let token = auth_token(&state).await;
            with_session(req, &token)
        } else {
            req
        };
        let response = router(state).oneshot(req).await.expect("router responds");
        let status = response.status();
        let ctype = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body collects");
        (status, ctype, bytes.to_vec())
    }

    /// Draft an ata into `book_id`, fill mandatory (compliance-clean) contents, and advance it to
    /// Signing; returns the act id. Mirrors `full_lifecycle_happy_path`'s fill.
    async fn draft_fill_and_advance(state: &AppState, book_id: &str) -> String {
        let (_, act) = send(
            state.clone(),
            post_json(
                "/v1/acts",
                json!({ "book_id": book_id, "title": "Ata da AG anual", "channel": "Physical" }),
            ),
        )
        .await;
        let act_id = act["id"].as_str().expect("act id").to_owned();
        send(
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
        act_id
    }

    #[tokio::test]
    async fn seal_produces_a_document_and_a_document_generated_event() {
        let (state, _entity_id, book_id) = entity_and_open_book("SociedadeAnonima").await;
        let act_id = draft_fill_and_advance(&state, &book_id).await;

        // Pre-seal the persisted PDF is 404 (no document until sealing).
        let (status, _, _) =
            send_bytes(state.clone(), get(&format!("/v1/acts/{act_id}/document"))).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // Seal → the additive `document` block names the PDF/A digest + pinned template version.
        let (status, sealed) = send(
            state.clone(),
            post_json(&format!("/v1/acts/{act_id}/seal"), json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "seal: {sealed}");
        let doc = &sealed["document"];
        assert_eq!(doc["template_id"], "csc-ata-ag/v1");
        assert_eq!(doc["pdf_digest"].as_str().expect("digest").len(), 64);
        assert!(doc["id"].is_string());

        // A `document.generated` event is bound into the chain.
        let (_, events) = send(state.clone(), get("/v1/ledger/events")).await;
        assert!(
            events
                .as_array()
                .expect("events")
                .iter()
                .any(|e| e["kind"] == "document.generated"),
            "a document.generated event was appended: {events}"
        );

        // The persisted PDF now downloads as application/pdf and carries the PDF header.
        let (status, ctype, bytes) =
            send_bytes(state, get(&format!("/v1/acts/{act_id}/document"))).await;
        assert_eq!(status, StatusCode::OK);
        assert!(ctype.starts_with("application/pdf"), "content-type={ctype}");
        assert!(bytes.starts_with(b"%PDF-"), "bytes start with a PDF header");
    }

    #[tokio::test]
    async fn document_preview_renders_a_model_pre_seal_without_persisting() {
        let (state, _entity_id, book_id) = entity_and_open_book("SociedadeAnonima").await;
        let (_, act) = send(
            state.clone(),
            post_json(
                "/v1/acts",
                json!({ "book_id": book_id, "title": "Ata da AG anual", "channel": "Physical" }),
            ),
        )
        .await;
        let act_id = act["id"].as_str().expect("act id").to_owned();
        send(
            state.clone(),
            patch_json(
                &format!("/v1/acts/{act_id}"),
                json!({
                    "meeting_date": "2026-03-30",
                    "meeting_time": "10:00",
                    "place": "Sede social",
                    "mesa": { "presidente": "Ana Presidente", "secretarios": ["Rui Secretário"] },
                    "agenda": [{ "number": 1, "text": "Contas" }],
                    "deliberations": "Aprovadas.",
                }),
            ),
        )
        .await;

        // Preview renders the CURRENT (draft) record live to a DocumentModel.
        let (status, model) = send(
            state.clone(),
            get(&format!("/v1/acts/{act_id}/document/preview")),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(model["title"], "Ata da AG anual");
        assert_eq!(model["language"], "pt-PT");
        assert!(!model["blocks"].as_array().expect("blocks").is_empty());

        // Preview does NOT persist: the PDF endpoint is still 404.
        let (status, _, _) = send_bytes(state, get(&format!("/v1/acts/{act_id}/document"))).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn templates_list_exposes_the_spine_templates() {
        let state = AppState::default();
        let (status, all) = send(state.clone(), get("/v1/templates")).await;
        assert_eq!(status, StatusCode::OK);
        let ids: Vec<&str> = all
            .as_array()
            .expect("templates")
            .iter()
            .map(|t| t["id"].as_str().expect("id"))
            .collect();
        assert!(ids.contains(&"csc-ata-ag/v1"));
        assert!(ids.contains(&"csc-termo-abertura/v1"));

        // Filter by family + stage.
        let (status, ata) = send(
            state,
            get("/v1/templates?family=CommercialCompany&stage=Ata"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let arr = ata.as_array().expect("filtered templates");
        assert!(arr.iter().all(|t| t["stage"] == "Ata"));
        assert!(
            arr.iter()
                .any(|t| t["id"] == "csc-ata-ag/v1" && t["locale"] == "pt-PT")
        );
    }

    #[tokio::test]
    async fn opening_a_book_produces_a_preserved_termo_document() {
        let (state, _entity_id, book_id) = entity_and_open_book("SociedadeAnonima").await;

        // A `document.generated` event for the termo is on the chain right after opening.
        let (_, events) = send(state.clone(), get("/v1/ledger/events")).await;
        assert!(
            events
                .as_array()
                .expect("events")
                .iter()
                .any(|e| e["kind"] == "document.generated"),
            "opening a book emits a document.generated event: {events}"
        );

        // The termo PDF is preserved, keyed by the book id (book instruments have no owning act).
        let (status, ctype, bytes) =
            send_bytes(state, get(&format!("/v1/acts/{book_id}/document"))).await;
        assert_eq!(status, StatusCode::OK);
        assert!(ctype.starts_with("application/pdf"), "content-type={ctype}");
        assert!(bytes.starts_with(b"%PDF-"));
    }

    #[tokio::test]
    async fn document_bundle_reserves_the_validation_report_for_wave_d() {
        let (state, _entity_id, book_id) = entity_and_open_book("SociedadeAnonima").await;
        let act_id = draft_fill_and_advance(&state, &book_id).await;

        // The bundle is 404 until sealed.
        let (status, _) = send(
            state.clone(),
            get(&format!("/v1/acts/{act_id}/document/bundle")),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        send(
            state.clone(),
            post_json(&format!("/v1/acts/{act_id}/seal"), json!({})),
        )
        .await;

        let (status, bundle) =
            send(state, get(&format!("/v1/acts/{act_id}/document/bundle"))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(bundle["document"]["template_id"], "csc-ata-ag/v1");
        assert_eq!(
            bundle["document"]["profile"],
            "application/pdf; profile=PDF/A-2u"
        );
        assert_eq!(bundle["pdf"]["media_type"], "application/pdf");
        assert!(bundle["pdf"]["byte_length"].as_u64().expect("length") > 0);
        assert!(bundle["attachments_manifest"].is_array());
        // The DOC-03 validation-report slot is reserved for Wave D — explicitly null in v1.
        assert!(
            bundle["validation_report"].is_null(),
            "the Wave-D validation-report slot is reserved (null): {bundle}"
        );
    }

    #[tokio::test]
    async fn closing_a_book_produces_the_termo_encerramento_document() {
        let (state, _entity_id, book_id) = entity_and_open_book("SociedadeAnonima").await;
        let act_id = draft_fill_and_advance(&state, &book_id).await;
        let (status, _) = send(
            state.clone(),
            post_json(&format!("/v1/acts/{act_id}/seal"), json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // Close the book → the encerramento document is generated in the same commit as book.closed.
        let (status, closed) = send(
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
        assert_eq!(status, StatusCode::OK, "close: {closed}");
        assert_eq!(closed["state"], "Closed");

        // A book-scoped `document.generated` event exists for the encerramento (plus the abertura's).
        let (_, events) = send(state.clone(), get("/v1/ledger/events")).await;
        let book_doc_events = events
            .as_array()
            .expect("events")
            .iter()
            .filter(|e| {
                e["kind"] == "document.generated"
                    && e["scope"].as_str().is_some_and(|s| {
                        s.contains(&format!("book:{book_id}")) && !s.contains("/act:")
                    })
            })
            .count();
        assert!(
            book_doc_events >= 2,
            "abertura + encerramento document.generated events: {events}"
        );

        // The encerramento is the latest document for the book key (a real csc-termo-encerramento).
        let (status, bundle) = send(
            state.clone(),
            get(&format!("/v1/acts/{book_id}/document/bundle")),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            bundle["document"]["template_id"],
            "csc-termo-encerramento/v1"
        );

        let (_, verify) = send(state, get("/v1/ledger/verify")).await;
        assert_eq!(verify["valid"], true, "chain still verifies after close");
    }

    #[tokio::test]
    async fn on_demand_generate_persists_a_chosen_document_and_emits_the_event() {
        let (state, _entity_id, book_id) = entity_and_open_book("SociedadeAnonima").await;
        let act_id = draft_fill_and_advance(&state, &book_id).await;

        // Unknown template id → 404.
        let (status, _) = send(
            state.clone(),
            post_json(
                &format!("/v1/acts/{act_id}/document/generate?template_id=nao-existe/v9"),
                json!({}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // A certidão against an UNSEALED act is refused honestly (422).
        let (status, _) = send(
            state.clone(),
            post_json(
                &format!("/v1/acts/{act_id}/document/generate?template_id=csc-certidao-ata/v1"),
                json!({}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        // Seal, then generate the certidão on demand — it persists + emits a document.generated event.
        let (status, _) = send(
            state.clone(),
            post_json(&format!("/v1/acts/{act_id}/seal"), json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, made) = send(
            state.clone(),
            post_json(
                &format!("/v1/acts/{act_id}/document/generate?template_id=csc-certidao-ata/v1"),
                json!({}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "generate: {made}");
        assert_eq!(made["template_id"], "csc-certidao-ata/v1");
        assert_eq!(made["act_id"], act_id);
        assert_eq!(made["pdf_digest"].as_str().expect("digest").len(), 64);

        let (_, events) = send(state.clone(), get("/v1/ledger/events")).await;
        let doc_events = events
            .as_array()
            .expect("events")
            .iter()
            .filter(|e| e["kind"] == "document.generated")
            .count();
        assert!(
            doc_events >= 2,
            "the sealed ata doc + the on-demand certidão doc are both on the chain: {events}"
        );

        // The chosen document is persisted and downloads as a real PDF.
        let (status, ctype, bytes) =
            send_bytes(state, get(&format!("/v1/acts/{act_id}/document"))).await;
        assert_eq!(status, StatusCode::OK);
        assert!(ctype.starts_with("application/pdf"), "ctype={ctype}");
        assert!(bytes.starts_with(b"%PDF-"));
    }

    #[tokio::test]
    async fn seal_template_id_override_selects_a_subtype_and_unknown_errors() {
        let (state, _entity_id, book_id) = entity_and_open_book("SociedadeAnonima").await;

        // An unknown override id is rejected (422), never silently defaulted to the spine.
        let act_bad = draft_fill_and_advance(&state, &book_id).await;
        let (status, _) = send(
            state.clone(),
            post_json(
                &format!("/v1/acts/{act_bad}/seal"),
                json!({ "template_id": "nao-existe/v9" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        // The bad seal rolled back: the act is not sealed.
        let (_, act) = send(state.clone(), get(&format!("/v1/acts/{act_bad}"))).await;
        assert_ne!(
            act["state"], "Sealed",
            "a failed override seal leaves no trace"
        );

        // A valid ata subtype override generates that subtype instead of the spine.
        let act_id = draft_fill_and_advance(&state, &book_id).await;
        let (status, sealed) = send(
            state.clone(),
            post_json(
                &format!("/v1/acts/{act_id}/seal"),
                json!({ "template_id": "csc-ata-aprovacao-contas/v1" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "override seal: {sealed}");
        assert_eq!(
            sealed["document"]["template_id"],
            "csc-ata-aprovacao-contas/v1"
        );
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
        let state = AppState::default();
        let token = auth_token(&state).await; // RBAC (t64-E3): the gated list needs a session.
        let web = TempWeb::new("SPA-SHELL-MARKER");
        let app = app(state, Some(web.dir.clone()));
        let (status, body) = send_text(app, with_session(get("/v1/entities"), &token)).await;
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
                "require_qualified_for_seal": true,
                "cmd": {
                    "env": "prod",
                    "application_id": "AMA-APP-0001",
                    "ama_cert_configured": true
                }
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
        // t57 Slice 1: the default preferred family is now Chave Móvel Digital (the family wired
        // end-to-end), not Cartão de Cidadão.
        assert_eq!(body["signing"]["preferred_family"], "ChaveMovelDigital");
        // CMD config surface defaults: preprod env, no ApplicationId, AMA cert not configured.
        assert_eq!(body["signing"]["cmd"]["env"], "preprod");
        assert_eq!(body["signing"]["cmd"]["application_id"], Value::Null);
        assert_eq!(body["signing"]["cmd"]["ama_cert_configured"], false);
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

    // --- Scoped RBAC stores + migration + bootstrap + resolution seam (t64-E2) ------------

    /// Insert an active user with the given role assignments directly into the state (bypassing the
    /// API + migration), returning its id. For the store/seam tests below.
    async fn seed_user(
        state: &AppState,
        username: &str,
        assignments: Vec<chancela_authz::RoleAssignment>,
    ) -> crate::users::UserId {
        use crate::users::{User, UserId};
        use time::format_description::well_known::Rfc3339;
        let uid = UserId(Uuid::new_v4());
        let user = User {
            id: uid,
            username: username.to_owned(),
            display_name: username.to_owned(),
            created_at: time::OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .unwrap_or_default(),
            active: true,
            password_hash: None,
            attestation_key: None,
            secret_source: Default::default(),
            recovery_hash: None,
            role_assignments: assignments,
        };
        state.users.write().await.insert(uid, user);
        uid
    }

    #[tokio::test]
    async fn legacy_users_json_migrates_on_load_and_is_idempotent() {
        use chancela_authz::{GESTOR_ROLE_ID, OWNER_ROLE_ID, RoleAssignment, Scope};
        let tmp = TempDir::new();
        // A pre-t64 users.json: two users, with NO `role_assignments` field at all (back-compat).
        let legacy = json!([
            { "id": "00000000-0000-0000-0000-000000000001", "username": "amelia.marques",
              "display_name": "Amélia Marques", "created_at": "2026-01-01T00:00:00Z", "active": true },
            { "id": "00000000-0000-0000-0000-000000000002", "username": "bruno.dias",
              "display_name": "Bruno Dias", "created_at": "2026-02-01T00:00:00Z", "active": true }
        ]);
        std::fs::write(
            tmp.dir.join("users.json"),
            serde_json::to_vec_pretty(&legacy).unwrap(),
        )
        .unwrap();

        let state = AppState::with_data_dir(tmp.dir.clone());
        {
            let users = state.users.read().await;
            let amelia = users
                .values()
                .find(|u| u.username == "amelia.marques")
                .unwrap();
            let bruno = users.values().find(|u| u.username == "bruno.dias").unwrap();
            // Earliest user ⇒ Owner@Global; the rest ⇒ Gestor@Global (no lockout, one Owner).
            assert_eq!(
                amelia.role_assignments,
                vec![RoleAssignment::new(OWNER_ROLE_ID, Scope::Global)]
            );
            assert_eq!(
                bruno.role_assignments,
                vec![RoleAssignment::new(GESTOR_ROLE_ID, Scope::Global)]
            );
        }
        // Rewritten to disk (now carries role_assignments), and roles.json was seeded.
        let on_disk = std::fs::read_to_string(tmp.dir.join("users.json")).unwrap();
        assert!(on_disk.contains("role_assignments"));
        assert!(tmp.dir.join("roles.json").is_file());

        // Idempotent: a second load rewrites nothing (already-migrated ⇒ no-op).
        let before = std::fs::read(tmp.dir.join("users.json")).unwrap();
        let _second = AppState::with_data_dir(tmp.dir.clone());
        let after = std::fs::read(tmp.dir.join("users.json")).unwrap();
        assert_eq!(before, after, "second load is a no-op");
    }

    #[tokio::test]
    async fn bootstrap_first_user_owner_second_user_gestor() {
        use chancela_authz::{GESTOR_ROLE_ID, OWNER_ROLE_ID, RoleAssignment, Scope};
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.dir.clone());

        // Fresh install, zero users: the bootstrap create needs no session.
        let (status, first) = send_raw(
            state.clone(),
            post_json(
                "/v1/users",
                json!({ "username": "amelia.marques", "display_name": "Amélia Marques" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let first_id = first["id"].as_str().unwrap().to_owned();

        // Sign in as the (passwordless) first user to get a session, then create a second user.
        let (status, sess) = send_raw(
            state.clone(),
            post_json("/v1/session", json!({ "user_id": first_id })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let token = sess["token"].as_str().unwrap().to_owned();

        let (status, _second) = send_raw(
            state.clone(),
            with_session(
                post_json("/v1/users", json!({ "username": "bruno.dias" })),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);

        let users = state.users.read().await;
        let amelia = users
            .values()
            .find(|u| u.username == "amelia.marques")
            .unwrap();
        let bruno = users.values().find(|u| u.username == "bruno.dias").unwrap();
        assert_eq!(
            amelia.role_assignments,
            vec![RoleAssignment::new(OWNER_ROLE_ID, Scope::Global)],
            "the first user is Owner"
        );
        assert_eq!(
            bruno.role_assignments,
            vec![RoleAssignment::new(GESTOR_ROLE_ID, Scope::Global)],
            "subsequent users are Gestor"
        );
    }

    #[tokio::test]
    async fn principal_resolution_yields_correct_effective_permissions() {
        use chancela_authz::{
            GESTOR_ROLE_ID, NoBooks, OWNER_ROLE_ID, Permission, RoleAssignment, Scope,
            has_permission,
        };
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.dir.clone());
        let now = time::OffsetDateTime::now_utc();

        let owner_id = seed_user(
            &state,
            "amelia.marques",
            vec![RoleAssignment::new(OWNER_ROLE_ID, Scope::Global)],
        )
        .await;
        let gestor_id = seed_user(
            &state,
            "bruno.dias",
            vec![RoleAssignment::new(GESTOR_ROLE_ID, Scope::Global)],
        )
        .await;

        let owner_eff = crate::roles::effective_permissions_for(&state, owner_id, now).await;
        assert!(has_permission(
            &owner_eff,
            Permission::DataWipe,
            Scope::Global,
            &NoBooks
        ));
        assert!(has_permission(
            &owner_eff,
            Permission::RoleManage,
            Scope::Global,
            &NoBooks
        ));

        let gestor_eff = crate::roles::effective_permissions_for(&state, gestor_id, now).await;
        assert!(has_permission(
            &gestor_eff,
            Permission::BookOpen,
            Scope::Global,
            &NoBooks
        ));
        // Gestor lacks the destructive + meta verbs.
        assert!(!has_permission(
            &gestor_eff,
            Permission::DataWipe,
            Scope::Global,
            &NoBooks
        ));
        assert!(!has_permission(
            &gestor_eff,
            Permission::RoleManage,
            Scope::Global,
            &NoBooks
        ));

        // Unknown principal ⇒ empty authority (fail-closed).
        let ghost = crate::users::UserId(Uuid::new_v4());
        assert!(
            crate::roles::effective_permissions_for(&state, ghost, now)
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn delegation_contributes_to_effective_permissions() {
        use chancela_authz::{
            Delegation, LEITOR_ROLE_ID, NoBooks, Permission, RoleAssignment, Scope, has_permission,
        };
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.dir.clone());
        let now = time::OffsetDateTime::UNIX_EPOCH;

        // A Leitor (read-only) who receives a delegated act.advance.
        let leitor_id = seed_user(
            &state,
            "amelia.marques",
            vec![RoleAssignment::new(LEITOR_ROLE_ID, Scope::Global)],
        )
        .await;
        let did = crate::delegations::DelegationId(Uuid::from_u128(1));
        {
            let mut table = state.delegations.write().await;
            table.insert(
                did,
                crate::delegations::StoredDelegation::new(
                    did,
                    now.format(&time::format_description::well_known::Rfc3339)
                        .unwrap(),
                    Delegation::new(
                        chancela_authz::UserId(Uuid::from_u128(9)),
                        chancela_authz::UserId(leitor_id.0),
                        Permission::ActAdvance,
                        Scope::Global,
                    ),
                ),
            );
        }

        let eff = crate::roles::effective_permissions_for(&state, leitor_id, now).await;
        // Base read stays; the delegated act.advance is present; a non-granted verb is not.
        assert!(has_permission(
            &eff,
            Permission::ActRead,
            Scope::Global,
            &NoBooks
        ));
        assert!(has_permission(
            &eff,
            Permission::ActAdvance,
            Scope::Global,
            &NoBooks
        ));
        assert!(!has_permission(
            &eff,
            Permission::DataWipe,
            Scope::Global,
            &NoBooks
        ));
    }

    #[tokio::test]
    async fn last_owner_guard_tracks_admin_owner_count() {
        use chancela_authz::{GESTOR_ROLE_ID, OWNER_ROLE_ID, RoleAssignment, Scope};
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.dir.clone());

        seed_user(
            &state,
            "amelia.marques",
            vec![RoleAssignment::new(OWNER_ROLE_ID, Scope::Global)],
        )
        .await;
        seed_user(
            &state,
            "bruno.dias",
            vec![RoleAssignment::new(GESTOR_ROLE_ID, Scope::Global)],
        )
        .await;
        // One Owner ⇒ removing it is unsafe (guard false).
        assert_eq!(crate::roles::count_owner_admins(&state).await, 1);
        assert!(!crate::roles::last_owner_guard_ok(&state).await);

        // A second Owner ⇒ safe to remove one.
        seed_user(
            &state,
            "carla.nunes",
            vec![RoleAssignment::new(OWNER_ROLE_ID, Scope::Global)],
        )
        .await;
        assert_eq!(crate::roles::count_owner_admins(&state).await, 2);
        assert!(crate::roles::last_owner_guard_ok(&state).await);
    }

    #[tokio::test]
    async fn roles_and_delegations_persist_through_state() {
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.dir.clone());

        // Add a custom role + a delegation, persist both, reload from disk.
        let custom_id = chancela_authz::RoleId(Uuid::from_u128(0xABCD));
        {
            let mut roles = state.roles.write().await;
            roles.insert(chancela_authz::Role {
                id: custom_id,
                name: "Auditor".to_owned(),
                permission_set: [chancela_authz::Permission::LedgerRead]
                    .into_iter()
                    .collect(),
                protected: false,
            });
        }
        crate::roles::persist_roles(&state).await.unwrap();

        let did = crate::delegations::DelegationId(Uuid::from_u128(1));
        {
            let mut table = state.delegations.write().await;
            table.insert(
                did,
                crate::delegations::StoredDelegation::new(
                    did,
                    time::OffsetDateTime::UNIX_EPOCH
                        .format(&time::format_description::well_known::Rfc3339)
                        .unwrap(),
                    chancela_authz::Delegation::new(
                        chancela_authz::UserId(Uuid::from_u128(1)),
                        chancela_authz::UserId(Uuid::from_u128(2)),
                        chancela_authz::Permission::ActAdvance,
                        chancela_authz::Scope::Global,
                    ),
                ),
            );
        }
        crate::delegations::persist_delegations(&state)
            .await
            .unwrap();

        let reloaded = AppState::with_data_dir(tmp.dir.clone());
        assert!(reloaded.roles.read().await.get(custom_id).is_some());
        assert_eq!(reloaded.delegations.read().await.len(), 1);
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
        // RBAC (t64-E3): serving/reading an archived PDF is `law.read`; carry an Owner session.
        let token = auth_token(&state).await;

        // Not yet fetched → serving is a 404.
        let (status, _, _) = send_raw_bytes(
            state.clone(),
            with_session(get("/v1/law/dl-9-2025/pdf"), &token),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let (status, _) = send(
            state.clone(),
            post_json("/v1/law/dl-9-2025/fetch", json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, headers, bytes) =
            send_raw_bytes(state, with_session(get("/v1/law/dl-9-2025/pdf"), &token)).await;
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
        let token = auth_token(&state).await; // RBAC (t64-E3): the pdf read is `law.read`.
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
        let (status, _, _) = send_raw_bytes(
            state.clone(),
            with_session(get("/v1/law/dl-9-2025/pdf"), &token),
        )
        .await;
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

        // GET by id (RBAC t64-E3: `user.read`; the auto-seeded Owner session satisfies it).
        let (status, got) = send(state.clone(), get(&format!("/v1/users/{id}"))).await;
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
        assert_eq!(
            manifest["store_schema_version"],
            chancela_store::schema::SCHEMA_VERSION
        );
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
        assert_eq!(
            body["store_schema_version"],
            chancela_store::schema::SCHEMA_VERSION
        );
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
        let id = u["id"].as_str().expect("user id").to_owned();
        // RBAC (t64-E3): the API assigns a subsequent user Gestor\@Global, but these pre-t64 tests act
        // AS this user for full-authority operations (destructive ops, cross-user credential resets,
        // user administration). Promote them to Owner\@Global so those journeys authorize exactly as
        // they did before RBAC. Tests that assert a *restricted* role use `seed_user` with an explicit
        // assignment instead (e.g. the new non-Owner-403 journeys).
        {
            use crate::users::UserId;
            use chancela_authz::{OWNER_ROLE_ID, RoleAssignment, Scope};
            let uid = UserId(Uuid::parse_str(&id).expect("uuid"));
            let mut users = state.users.write().await;
            if let Some(user) = users.get_mut(&uid) {
                user.role_assignments = vec![RoleAssignment::new(OWNER_ROLE_ID, Scope::Global)];
            }
        }
        id
    }

    /// Give a user a secret + attestation key, sign in with the password, and create one attested
    /// entity. Returns `(user_id, session_token, entity_event_seq)`.
    async fn attested_entity(state: &AppState, username: &str) -> (String, String, u64) {
        let id = make_user(state, username).await;
        // t51: setting one's own secret/key is a self-service op — open a session as this user so
        // the requester matches the target (a cross-user set would now be a 403).
        let self_tok = open_session(state, &id).await;
        send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{id}/secret"),
                    json!({ "password": "s3cret-pass" }),
                ),
                &self_tok,
            ),
        )
        .await;
        send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{id}/attestation-key"),
                    json!({ "current_password": "s3cret-pass" }),
                ),
                &self_tok,
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
        // t51: self-service session so setting one's own secret is authorized (not a cross-user op).
        let self_tok = open_session(&state, &id).await;

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

        // Set a secret — no current_password needed the first time (self-service).
        let (status, view) = send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{id}/secret"),
                    json!({ "password": "correct horse" }),
                ),
                &self_tok,
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
        let self_tok = open_session(&state, &id).await; // t51: self-service secret set.
        send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{id}/secret"),
                    json!({ "password": "s3cret-pass" }),
                ),
                &self_tok,
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
        let self_tok = open_session(&state, &id).await; // t51: self-service key/secret ops.
        // No secret → 409 (self-service precondition; requester == target).
        let (status, _) = send(
            state.clone(),
            with_session(
                post_json(&format!("/v1/users/{id}/attestation-key"), json!({})),
                &self_tok,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);

        send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{id}/secret"),
                    json!({ "password": "s3cret-pass" }),
                ),
                &self_tok,
            ),
        )
        .await;
        // Wrong current password → 401 (self-service).
        let (status, _) = send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{id}/attestation-key"),
                    json!({ "current_password": "nope" }),
                ),
                &self_tok,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        // Correct → 200 with a 32-hex fingerprint.
        let (status, view) = send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{id}/attestation-key"),
                    json!({ "current_password": "s3cret-pass" }),
                ),
                &self_tok,
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
        let (id, token, seq) = attested_entity(&state, "iris").await;
        // Valid while the key exists.
        let (_, v) = send(
            state.clone(),
            get(&format!("/v1/ledger/attestations/{seq}")),
        )
        .await;
        assert_eq!(v["valid"], true);
        // Remove the attestation key (self-service: iris's own session).
        let (status, view) = send(
            state.clone(),
            with_session(
                body_json(
                    "DELETE",
                    &format!("/v1/users/{id}/attestation-key"),
                    json!({ "current_password": "s3cret-pass" }),
                ),
                &token,
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
        let self_tok = open_session(&state, &id).await; // t51: self-service credential ops.
        send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{id}/secret"),
                    json!({ "password": "s3cret-pass" }),
                ),
                &self_tok,
            ),
        )
        .await;
        send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{id}/attestation-key"),
                    json!({ "current_password": "s3cret-pass" }),
                ),
                &self_tok,
            ),
        )
        .await;
        // Wrong current password on removal → 401 (self-service).
        let (status, _) = send(
            state.clone(),
            with_session(
                body_json(
                    "DELETE",
                    &format!("/v1/users/{id}/secret"),
                    json!({ "current_password": "nope" }),
                ),
                &self_tok,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        // Correct → 200; both the secret and the (now unrecoverable) key are cleared.
        let (status, view) = send(
            state.clone(),
            with_session(
                body_json(
                    "DELETE",
                    &format!("/v1/users/{id}/secret"),
                    json!({ "current_password": "s3cret-pass" }),
                ),
                &self_tok,
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
        let self_tok = open_session(&state, &id).await; // t51: self-service credential ops.
        send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{id}/secret"),
                    json!({ "password": "old-secret" }),
                ),
                &self_tok,
            ),
        )
        .await;
        send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{id}/attestation-key"),
                    json!({ "current_password": "old-secret" }),
                ),
                &self_tok,
            ),
        )
        .await;
        // Change the secret (current one required, self-service).
        let (status, _) = send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{id}/secret"),
                    json!({ "password": "new-secret", "current_password": "old-secret" }),
                ),
                &self_tok,
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
        let self_tok = open_session(&state, &id).await; // t51: self-service credential ops.
        // Below the 8-char floor → 422 (validation precedes authorization).
        let (status, body) = send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{id}/secret"),
                    json!({ "password": "short" }),
                ),
                &self_tok,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(body["error"].is_string());

        // Set a valid secret + key, then confirm the wire dump carries no secret material.
        send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{id}/secret"),
                    json!({ "password": "s3cret-pass" }),
                ),
                &self_tok,
            ),
        )
        .await;
        send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{id}/attestation-key"),
                    json!({ "current_password": "s3cret-pass" }),
                ),
                &self_tok,
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

    // --- t45: signed-out sign-in roster (GET /v1/session/roster) --------------------------

    #[tokio::test]
    async fn session_roster_is_unauthenticated_and_signals_onboarding() {
        let state = fresh_state().await;

        // No users yet → onboarding required, empty roster, and NO session on the request.
        let (status, roster) = send_raw(state.clone(), get("/v1/session/roster")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(roster["onboarding_required"], true);
        assert_eq!(roster["users"].as_array().expect("users").len(), 0);

        // Bootstrap amelia (no session), sign in, create bruno with that session — no auto-seeded
        // "test.actor" pollutes the roster this way.
        let (status, amelia) = send_raw(
            state.clone(),
            post_json("/v1/users", json!({ "username": "amelia.marques" })),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let id = amelia["id"].as_str().expect("id").to_owned();
        let token = open_session(&state, &id).await;
        let (status, _) = send_raw(
            state.clone(),
            with_session(
                post_json("/v1/users", json!({ "username": "bruno" })),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        // Give amelia a secret so has_secret is exercised on both true and false.
        send_raw(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{id}/secret"),
                    json!({ "password": "correct horse" }),
                ),
                &token,
            ),
        )
        .await;

        // Still signed out on this call → onboarding no longer required, both users listed.
        let (status, roster) = send_raw(state.clone(), get("/v1/session/roster")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(roster["onboarding_required"], false);
        let users = roster["users"].as_array().expect("users");
        assert_eq!(users.len(), 2);

        let amelia = users
            .iter()
            .find(|u| u["username"] == "amelia.marques")
            .expect("amelia in roster");
        assert_eq!(amelia["has_secret"], true);
        assert_eq!(amelia["display_name"], "amelia.marques");
        assert!(amelia["id"].is_string());
        // NOTHING sensitive leaks to an anonymous caller: no fingerprint, no created_at, no
        // has_attestation_key, no hash or wrapped-key material, not even `active`.
        for forbidden in [
            "attestation_key_fingerprint",
            "has_attestation_key",
            "created_at",
            "active",
            "password_hash",
            "attestation_key",
        ] {
            assert!(
                amelia.get(forbidden).is_none(),
                "roster user must not carry {forbidden}: {amelia}"
            );
        }
        // A passwordless user reads has_secret:false so the UI knows not to prompt.
        let bruno = users
            .iter()
            .find(|u| u["username"] == "bruno")
            .expect("bruno in roster");
        assert_eq!(bruno["has_secret"], false);
    }

    #[tokio::test]
    async fn session_roster_omits_inactive_users() {
        let state = fresh_state().await;
        let (status, u) = send_raw(
            state.clone(),
            post_json("/v1/users", json!({ "username": "amelia.marques" })),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let id = u["id"].as_str().expect("id").to_owned();
        let token = open_session(&state, &id).await;
        let (status, bruno) = send_raw(
            state.clone(),
            with_session(
                post_json("/v1/users", json!({ "username": "bruno" })),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let bruno_id = bruno["id"].as_str().expect("id").to_owned();

        // Deactivate bruno (amelia stays active, so the last-active guard allows it).
        let (status, _) = send_raw(
            state.clone(),
            with_session(
                patch_json(&format!("/v1/users/{bruno_id}"), json!({ "active": false })),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (_, roster) = send_raw(state.clone(), get("/v1/session/roster")).await;
        let users = roster["users"].as_array().expect("users");
        assert_eq!(
            users.len(),
            1,
            "inactive bruno is not sign-in-able: {roster}"
        );
        assert_eq!(users[0]["username"], "amelia.marques");
    }

    // --- t45: last-active-user deactivation guard -----------------------------------------

    #[tokio::test]
    async fn patch_user_refuses_deactivating_the_last_active_user() {
        let state = fresh_state().await;
        let (status, u) = send_raw(
            state.clone(),
            post_json("/v1/users", json!({ "username": "amelia.marques" })),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let id = u["id"].as_str().expect("id").to_owned();
        let token = open_session(&state, &id).await;

        // She is the only active user → deactivating her is a 409 with the PT message.
        let (status, body) = send_raw(
            state.clone(),
            with_session(
                patch_json(&format!("/v1/users/{id}"), json!({ "active": false })),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(
            body["error"]
                .as_str()
                .expect("error")
                .contains("último utilizador ativo"),
            "PT last-active message: {body}"
        );

        // Add a second active user; now deactivating one of the two is allowed.
        let (status, u2) = send_raw(
            state.clone(),
            with_session(
                post_json("/v1/users", json!({ "username": "bruno" })),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let id2 = u2["id"].as_str().expect("id").to_owned();
        let (status, _) = send_raw(
            state.clone(),
            with_session(
                patch_json(&format!("/v1/users/{id2}"), json!({ "active": false })),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // With only amelia active again, she is once more the last active → 409.
        let (status, _) = send_raw(
            state.clone(),
            with_session(
                patch_json(&format!("/v1/users/{id}"), json!({ "active": false })),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
    }

    // --- t45: patch_user ledger payload carries no secret material ------------------------

    #[tokio::test]
    async fn patch_user_ledger_payload_carries_no_secret_material() {
        use crate::users::{UserId, UserView};
        let state = AppState::default();
        let id = make_user(&state, "hugo").await;
        let self_tok = open_session(&state, &id).await; // t51: self-service credential ops.
        // Give hugo a secret + attestation key so the full `User` carries the argon2 PHC and the
        // AEAD-wrapped key — exactly the material that must never reach the ledger payload.
        send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{id}/secret"),
                    json!({ "password": "s3cret-pass" }),
                ),
                &self_tok,
            ),
        )
        .await;
        send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{id}/attestation-key"),
                    json!({ "current_password": "s3cret-pass" }),
                ),
                &self_tok,
            ),
        )
        .await;

        // Rename him — this patch is the final mutation, so its `user.updated` event is the tail.
        let (status, _) = send(
            state.clone(),
            patch_json(
                &format!("/v1/users/{id}"),
                json!({ "display_name": "Hugo P." }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // The stored `User` (unchanged since the patch) reproduces exactly what was digested.
        let uid = UserId(Uuid::parse_str(&id).expect("uuid"));
        let user = state
            .users
            .read()
            .await
            .get(&uid)
            .cloned()
            .expect("hugo present");
        assert!(
            user.password_hash.is_some() && user.attestation_key.is_some(),
            "hugo holds secret material for the test to be meaningful"
        );
        let view_digest = crate::hex::hex(&chancela_ledger::digest(
            &serde_json::to_vec(&UserView::from(&user)).expect("view serializes"),
        ));
        let full_digest = crate::hex::hex(&chancela_ledger::digest(
            &serde_json::to_vec(&user).expect("user serializes"),
        ));
        assert_ne!(
            view_digest, full_digest,
            "UserView and full User digest differently — the guard below is meaningful"
        );

        // The patch's `user.updated` payload digest must be the UserView digest, never the full User.
        let (_, events) = send(state.clone(), get("/v1/ledger/events")).await;
        let patch_ev = events
            .as_array()
            .expect("events")
            .iter()
            .rev()
            .find(|e| e["kind"] == "user.updated" && e["justification"] == "user updated")
            .expect("patch user.updated event present");
        assert_eq!(
            patch_ev["payload_digest"], view_digest,
            "patch payload is the UserView (no hash/key material)"
        );
        assert_ne!(
            patch_ev["payload_digest"], full_digest,
            "patch payload is NOT the full User"
        );
    }

    // --- t51: cross-user credential authorization + recovery-phrase credential ---------------
    //
    // Matrix (§4): self vs cross × {no secret, password-only, recovery, both} × {no proof, wrong
    // pw, right pw, valid recovery, invalid recovery}. Cross-user no-valid-proof cases collapse to
    // an indistinguishable 403 with constant-work argon2 (no user enumeration). Examples use
    // "amelia.marques" (target) and "bruno" (the other operator); never real names.

    /// Seed a self-service session for an existing user directly into state (works regardless of
    /// whether the user has a password — unlike `open_session`, which signs in passwordless).
    async fn seed_session(state: &AppState, user_id: &str) -> String {
        let uid = UserId(Uuid::parse_str(user_id).expect("uuid"));
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

    // --- t64-E3: fail-closed RBAC enforcement (non-Owner 403; scoped role in/out of scope) --------

    #[tokio::test]
    async fn rbac_non_owner_leitor_reads_but_cannot_write() {
        use chancela_authz::{LEITOR_ROLE_ID, RoleAssignment, Scope};
        let state = fresh_state().await;
        // An Owner (auto-seeded session) creates one entity.
        let (status, _e) = send(
            state.clone(),
            post_json(
                "/v1/entities",
                json!({
                    "name": "Encosto Estratégico Lda",
                    "nipc": "503004642",
                    "seat": "Lisboa",
                    "kind": "SociedadeAnonima",
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);

        // A Leitor\@Global (read-only role).
        let leitor = seed_user(
            &state,
            "amelia.marques",
            vec![RoleAssignment::new(LEITOR_ROLE_ID, Scope::Global)],
        )
        .await;
        let tok = seed_session(&state, &leitor.to_string()).await;

        // READ → 200, and the row is visible (Leitor holds entity.read\@Global).
        let (status, list) = send_raw(state.clone(), with_session(get("/v1/entities"), &tok)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(list.as_array().expect("list").len(), 1);

        // WRITE → 403 with the generic, non-enumerating message (no "valor probatório").
        let (status, body) = send_raw(
            state.clone(),
            with_session(
                post_json(
                    "/v1/entities",
                    json!({
                        "name": "Outra Sociedade Lda",
                        "nipc": "503004642",
                        "seat": "Porto",
                        "kind": "SociedadeAnonima",
                    }),
                ),
                &tok,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(
            body["error"].as_str().expect("error").contains("permissão"),
            "honest permission refusal: {body}"
        );

        // An admin-plane write is likewise refused for a Leitor.
        let (status, _) = send_raw(
            state.clone(),
            with_session(get("/v1/users"), &tok), // user.read — Leitor lacks it
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn rbac_scoped_gestor_acts_within_scope_but_not_outside() {
        use chancela_authz::{EntityId as AuthzEntityId, GESTOR_ROLE_ID, RoleAssignment, Scope};
        let state = fresh_state().await;
        let mk = |name: &str| {
            json!({
                "name": name, "nipc": "503004642", "seat": "Lisboa", "kind": "SociedadeAnonima",
            })
        };
        // Owner creates two entities.
        let (_, e1) = send(
            state.clone(),
            post_json("/v1/entities", mk("Encosto Estratégico Lda")),
        )
        .await;
        let (_, e2) = send(
            state.clone(),
            post_json("/v1/entities", mk("Outra Sociedade Lda")),
        )
        .await;
        let e1_id = e1["id"].as_str().expect("e1 id").to_owned();
        let e2_id = e2["id"].as_str().expect("e2 id").to_owned();

        // A Gestor scoped to entity 1 ONLY.
        let e1_uuid = Uuid::parse_str(&e1_id).expect("uuid");
        let gestor = seed_user(
            &state,
            "amelia.marques",
            vec![RoleAssignment::new(
                GESTOR_ROLE_ID,
                Scope::Entity(AuthzEntityId(e1_uuid)),
            )],
        )
        .await;
        let tok = seed_session(&state, &gestor.to_string()).await;

        let open = |eid: &str| {
            post_json(
                "/v1/books",
                json!({
                    "entity_id": eid,
                    "kind": "AssembleiaGeral",
                    "purpose": "livro de atas",
                    "opening_date": "2026-01-15",
                    "required_signatories": ["Administrador"],
                }),
            )
        };
        // WITHIN scope (entity 1) → 201.
        let (status, _) = send_raw(state.clone(), with_session(open(&e1_id), &tok)).await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "opening a book within the granted entity"
        );
        // OUTSIDE scope (entity 2) → 403 (a scoped grant never reaches another entity).
        let (status, _) = send_raw(state.clone(), with_session(open(&e2_id), &tok)).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "opening a book outside the granted entity is refused"
        );
        // Scope-escape upward is structurally impossible: the Gestor holds ledger.read, but only at
        // Entity(1) — a **Global** integrity read is NOT satisfied by an entity-scoped grant → 403.
        let (status, _) = send_raw(
            state.clone(),
            with_session(get("/v1/ledger/integrity"), &tok),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "an entity-scoped grant can never satisfy a Global-scoped check"
        );
    }

    // --- t64-E4: RBAC-management endpoints (role CRUD + assignment + scoped delegation) ------------

    #[tokio::test]
    async fn e4_owner_role_crud_roundtrip() {
        let state = fresh_state().await;
        // Owner (auto-seeded session) creates a custom role.
        let (status, role) = send(
            state.clone(),
            post_json(
                "/v1/roles",
                json!({ "name": "Auditor", "permissions": ["ledger.read", "entity.read"] }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(role["protected"], json!(false));
        let id = role["id"].as_str().expect("id").to_owned();
        assert!(
            role["permissions"]
                .as_array()
                .expect("perms")
                .iter()
                .any(|p| p == "ledger.read")
        );

        // The catalog now lists the 4 seeded defaults + the new one.
        let (status, list) = send(state.clone(), get("/v1/roles")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(list.as_array().expect("roles").len(), 5);

        // The frozen verb catalog is introspectable by any session.
        let (status, cat) = send(state.clone(), get("/v1/permissions")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(cat["permissions"].as_array().expect("verbs").len(), 37);

        // Rename + narrow the permission-set.
        let (status, patched) = send(
            state.clone(),
            patch_json(
                &format!("/v1/roles/{id}"),
                json!({ "name": "Auditor Sénior", "permissions": ["ledger.read"] }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(patched["name"], json!("Auditor Sénior"));
        assert_eq!(patched["permissions"].as_array().expect("perms").len(), 1);

        // Delete it; the catalog returns to the 4 seeded defaults.
        let (status, _) = send(state.clone(), delete(&format!("/v1/roles/{id}"))).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (_, list) = send(state.clone(), get("/v1/roles")).await;
        assert_eq!(list.as_array().expect("roles").len(), 4);
    }

    #[tokio::test]
    async fn e4_protected_owner_cannot_be_edited_or_deleted() {
        let state = fresh_state().await;
        let owner_role = chancela_authz::OWNER_ROLE_ID.0.to_string();
        // Even an Owner cannot narrow/rename the locked super-role...
        let (status, _) = send(
            state.clone(),
            patch_json(
                &format!("/v1/roles/{owner_role}"),
                json!({ "name": "Proprietário Fraco", "permissions": ["entity.read"] }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        // ...nor delete it.
        let (status, _) = send(state.clone(), delete(&format!("/v1/roles/{owner_role}"))).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn e4_subset_invariant_role_manage_does_not_exempt() {
        use chancela_authz::{Permission, Role, RoleAssignment, RoleId, Scope};
        let state = fresh_state().await;
        // A role that grants role.manage but only entity.read otherwise.
        let mgr = RoleId(Uuid::new_v4());
        state.roles.write().await.insert(Role {
            id: mgr,
            name: "Gestor de Acessos".to_owned(),
            permission_set: [Permission::RoleManage, Permission::EntityRead]
                .into_iter()
                .collect(),
            protected: false,
        });
        let m = seed_user(
            &state,
            "amelia.marques",
            vec![RoleAssignment::new(mgr, Scope::Global)],
        )
        .await;
        let tok = seed_session(&state, &m.to_string()).await;

        // A role fully within the actor's own authority → 201.
        let (status, _) = send_raw(
            state.clone(),
            with_session(
                post_json(
                    "/v1/roles",
                    json!({ "name": "Só Leitura", "permissions": ["entity.read"] }),
                ),
                &tok,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);

        // Crafting a role containing a permission the actor LACKS is refused — holding role.manage
        // does NOT exempt the subset check.
        let (status, body) = send_raw(
            state.clone(),
            with_session(
                post_json(
                    "/v1/roles",
                    json!({ "name": "Perigoso", "permissions": ["data.wipe"] }),
                ),
                &tok,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(body["error"].as_str().expect("err").contains("permissão"));
    }

    #[tokio::test]
    async fn e4_assign_subset_enforced_and_last_owner_guard() {
        use chancela_authz::{
            GESTOR_ROLE_ID, OWNER_ROLE_ID, Permission, Role, RoleAssignment, RoleId, Scope,
        };
        let state = fresh_state().await;

        // An actor holding role.assign but only entity.read otherwise.
        let ra = RoleId(Uuid::new_v4());
        state.roles.write().await.insert(Role {
            id: ra,
            name: "Atribuidor".to_owned(),
            permission_set: [Permission::RoleAssign, Permission::EntityRead]
                .into_iter()
                .collect(),
            protected: false,
        });
        // A role wholly within that actor's authority.
        let ro = RoleId(Uuid::new_v4());
        state.roles.write().await.insert(Role {
            id: ro,
            name: "Só Entidade".to_owned(),
            permission_set: [Permission::EntityRead].into_iter().collect(),
            protected: false,
        });
        let assigner = seed_user(
            &state,
            "amelia.marques",
            vec![RoleAssignment::new(ra, Scope::Global)],
        )
        .await;
        let tok = seed_session(&state, &assigner.to_string()).await;
        let target = seed_user(&state, "bruno.dias", vec![]).await;

        // Assigning the in-authority role → 200.
        let (status, _) = send_raw(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{target}/roles"),
                    json!({ "role_id": ro.0.to_string(), "scope": { "kind": "global" } }),
                ),
                &tok,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        // Assigning the fat Gestor role (perms the assigner lacks) → 403 — role.assign does not exempt.
        let (status, _) = send_raw(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{target}/roles"),
                    json!({ "role_id": GESTOR_ROLE_ID.0.to_string(), "scope": { "kind": "global" } }),
                ),
                &tok,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // Last-Owner guard: two Owners, remove one (ok), then the last (409).
        let owner_a = seed_user(
            &state,
            "owner.a",
            vec![RoleAssignment::new(OWNER_ROLE_ID, Scope::Global)],
        )
        .await;
        let tok_a = seed_session(&state, &owner_a.to_string()).await;
        let owner_b = seed_user(
            &state,
            "owner.b",
            vec![RoleAssignment::new(OWNER_ROLE_ID, Scope::Global)],
        )
        .await;
        let owner_body =
            json!({ "role_id": OWNER_ROLE_ID.0.to_string(), "scope": { "kind": "global" } });
        // 2 → 1 Owner@Global: allowed.
        let (status, _) = send_raw(
            state.clone(),
            with_session(
                body_json(
                    "DELETE",
                    &format!("/v1/users/{owner_b}/roles"),
                    owner_body.clone(),
                ),
                &tok_a,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        // Removing the FINAL Owner@Global (its own) → 409, never lockable-out.
        let (status, body) = send_raw(
            state.clone(),
            with_session(
                body_json("DELETE", &format!("/v1/users/{owner_a}/roles"), owner_body),
                &tok_a,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(
            body["error"]
                .as_str()
                .expect("err")
                .contains("Proprietário")
        );
    }

    #[tokio::test]
    async fn e4_delegation_grant_revoke_meta_and_redelegation_blocked() {
        use crate::delegations::{DelegationId, StoredDelegation};
        use chancela_authz::{
            Delegation, OWNER_ROLE_ID, Permission, Role, RoleAssignment, RoleId, Scope,
            UserId as AuthzUserId,
        };
        use time::format_description::well_known::Rfc3339;
        let state = fresh_state().await;

        let owner = seed_user(
            &state,
            "owner.a",
            vec![RoleAssignment::new(OWNER_ROLE_ID, Scope::Global)],
        )
        .await;
        let tok = seed_session(&state, &owner.to_string()).await;
        let grantee = seed_user(&state, "amelia.marques", vec![]).await;
        let g_tok = seed_session(&state, &grantee.to_string()).await;

        // Grant a non-meta permission the Owner holds via a role → 201.
        let (status, view) = send_raw(
            state.clone(),
            with_session(
                post_json(
                    "/v1/delegations",
                    json!({ "to": grantee.to_string(), "permission": "act.advance", "scope": { "kind": "global" } }),
                ),
                &tok,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(view["permission"], json!("act.advance"));
        assert_eq!(view["revoked"], json!(false));
        let del_id = view["id"].as_str().expect("id").to_owned();

        // The grantee now holds act.advance, sourced from the delegation.
        let (_, perms) = send_raw(
            state.clone(),
            with_session(get("/v1/session/permissions"), &g_tok),
        )
        .await;
        assert!(
            perms["permissions"]
                .as_array()
                .expect("perms")
                .iter()
                .any(|p| p["permission"] == "act.advance" && p["source"] == "delegation")
        );

        // A META permission is non-delegable → 403 (even for an Owner).
        let (status, _) = send_raw(
            state.clone(),
            with_session(
                post_json(
                    "/v1/delegations",
                    json!({ "to": grantee.to_string(), "permission": "role.manage", "scope": { "kind": "global" } }),
                ),
                &tok,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // Re-delegation is impossible: an actor holding delegation.grant via a role but act.advance
        // only via a received delegation cannot pass it on.
        let dg = RoleId(Uuid::new_v4());
        state.roles.write().await.insert(Role {
            id: dg,
            name: "Delegador".to_owned(),
            permission_set: [Permission::DelegationGrant].into_iter().collect(),
            protected: false,
        });
        let carlos = seed_user(
            &state,
            "carlos.nunes",
            vec![RoleAssignment::new(dg, Scope::Global)],
        )
        .await;
        let granted_at = time::OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .expect("fmt");
        let recv = Delegation::new(
            AuthzUserId(owner.0),
            AuthzUserId(carlos.0),
            Permission::ActAdvance,
            Scope::Global,
        );
        let stored = StoredDelegation::new(DelegationId(Uuid::new_v4()), granted_at, recv);
        state.delegations.write().await.insert(stored.id, stored);
        let c_tok = seed_session(&state, &carlos.to_string()).await;
        let dora = seed_user(&state, "dora.silva", vec![]).await;
        let (status, _) = send_raw(
            state.clone(),
            with_session(
                post_json(
                    "/v1/delegations",
                    json!({ "to": dora.to_string(), "permission": "act.advance", "scope": { "kind": "global" } }),
                ),
                &c_tok,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // An already-expired delegation is granted but contributes nothing (expiry honoured).
        let past = (time::OffsetDateTime::now_utc() - time::Duration::hours(1))
            .format(&Rfc3339)
            .expect("fmt");
        let (status, _) = send_raw(
            state.clone(),
            with_session(
                post_json(
                    "/v1/delegations",
                    json!({ "to": grantee.to_string(), "permission": "act.read", "scope": { "kind": "global" }, "expires_at": past }),
                ),
                &tok,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let (_, perms_exp) = send_raw(
            state.clone(),
            with_session(get("/v1/session/permissions"), &g_tok),
        )
        .await;
        assert!(
            !perms_exp["permissions"]
                .as_array()
                .expect("perms")
                .iter()
                .any(|p| p["permission"] == "act.read")
        );

        // Revoke is immediate: the grantee loses act.advance the moment it is revoked.
        let (status, rv) = send_raw(
            state.clone(),
            with_session(delete(&format!("/v1/delegations/{del_id}")), &tok),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(rv["revoked"], json!(true));
        let (_, perms2) = send_raw(
            state.clone(),
            with_session(get("/v1/session/permissions"), &g_tok),
        )
        .await;
        assert!(
            !perms2["permissions"]
                .as_array()
                .expect("perms")
                .iter()
                .any(|p| p["permission"] == "act.advance")
        );
    }

    /// Set `target`'s first password as a self-service op (open a session as the target).
    async fn give_target_password(state: &AppState, target_id: &str, password: &str) {
        let self_tok = open_session(state, target_id).await;
        let (status, _) = send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{target_id}/secret"),
                    json!({ "password": password }),
                ),
                &self_tok,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "self-service first password set");
    }

    /// Clear the t52 cross-user secret/reset backoff so an intentionally-repeated failed attempt in
    /// a matrix test is treated as a fresh (un-throttled) 403 rather than a 429 (mirrors how the
    /// signin tests clear `signin_backoff`). The throttle itself is asserted by the dedicated t52
    /// tests below; here it must not mask the uniform-403 / adjacent-op behaviour under test.
    async fn clear_secret_backoff(state: &AppState) {
        state.secret_backoff.write().await.clear();
    }

    /// Stored provenance + recovery presence for a user (reads the in-memory state directly).
    async fn stored_user(state: &AppState, id: &str) -> User {
        let uid = UserId(Uuid::parse_str(id).expect("uuid"));
        state
            .users
            .read()
            .await
            .get(&uid)
            .cloned()
            .expect("user present")
    }

    #[tokio::test]
    async fn t51_cross_user_set_on_passwordless_target_is_403() {
        // Matrix #7: the closed hole — a signed-in operator setting a FIRST password on a
        // passwordless account is now refused, never silently set.
        let state = AppState::default();
        let target = make_user(&state, "amelia.marques").await;
        let bruno = make_user(&state, "bruno").await;
        let bruno_tok = open_session(&state, &bruno).await;

        let (status, body) = send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{target}/secret"),
                    json!({ "password": "attacker-chosen" }),
                ),
                &bruno_tok,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(
            body["error"]
                .as_str()
                .expect("error")
                .contains("não autorizado")
        );
        // The target is untouched — still passwordless.
        let (_, view) = send(state.clone(), get(&format!("/v1/users/{target}"))).await;
        assert_eq!(view["has_secret"], false);
    }

    #[tokio::test]
    async fn t51_cross_user_set_with_correct_password_succeeds_and_audits() {
        // Matrix #4: cross-user reset authorized by the target's known password → 200 + a
        // `user.secret.reset` event attributed to the requester (honest actor).
        let state = AppState::default();
        let target = make_user(&state, "amelia.marques").await;
        give_target_password(&state, &target, "target-current-pass").await;
        let bruno = make_user(&state, "bruno").await;
        let bruno_tok = open_session(&state, &bruno).await;

        let (status, view) = send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{target}/secret"),
                    json!({ "password": "reset-by-bruno", "current_password": "target-current-pass" }),
                ),
                &bruno_tok,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(view["has_secret"], true);

        // The reset is auditable as bruno's action, via the known password, with no secret material.
        let (_, events) = send(state.clone(), get("/v1/ledger/events")).await;
        let reset = events
            .as_array()
            .expect("events")
            .iter()
            .find(|e| e["kind"] == "user.secret.reset")
            .expect("user.secret.reset present");
        assert_eq!(reset["actor"], "bruno");
        assert!(
            reset["justification"]
                .as_str()
                .expect("justification")
                .contains("palavra-passe atual")
        );
        let dump = reset.to_string().to_lowercase();
        assert!(!dump.contains("reset-by-bruno") && !dump.contains("$argon2"));

        // Provenance stays Password (a known-password reset is not a recovery).
        assert_eq!(
            stored_user(&state, &target).await.secret_source,
            crate::users::SecretSource::Password
        );
    }

    #[tokio::test]
    async fn t51_cross_user_wrong_password_no_proof_and_unknown_target_are_uniform_403() {
        // Matrix #5/#6 + §5 anti-enumeration: wrong password, no proof, and a non-existent target
        // all return the SAME 403 body — no status/message difference reveals target state.
        let state = AppState::default();
        let target = make_user(&state, "amelia.marques").await;
        give_target_password(&state, &target, "target-current-pass").await;
        let bruno = make_user(&state, "bruno").await;
        let bruno_tok = open_session(&state, &bruno).await;

        let attempt = |body: Value, path_id: String| {
            let tok = bruno_tok.clone();
            let st = state.clone();
            async move {
                send(
                    st,
                    with_session(
                        post_json(&format!("/v1/users/{path_id}/secret"), body),
                        &tok,
                    ),
                )
                .await
            }
        };

        // The three attempts hit the same (requester,target) key back-to-back; the t52 backoff would
        // 429 the second one, masking the uniformity under test, so clear it between attempts. Each
        // remains a fresh, un-throttled, constant-work 403 — exactly what this test compares.
        let (s_wrong, b_wrong) = attempt(
            json!({ "password": "x-new-pass", "current_password": "WRONG" }),
            target.clone(),
        )
        .await;
        clear_secret_backoff(&state).await;
        let (s_none, b_none) = attempt(json!({ "password": "x-new-pass" }), target.clone()).await;
        clear_secret_backoff(&state).await;
        let (s_ghost, b_ghost) = attempt(
            json!({ "password": "x-new-pass", "current_password": "whatever" }),
            Uuid::new_v4().to_string(),
        )
        .await;

        assert_eq!(s_wrong, StatusCode::FORBIDDEN);
        assert_eq!(s_none, StatusCode::FORBIDDEN);
        assert_eq!(s_ghost, StatusCode::FORBIDDEN);
        // Indistinguishable bodies: an unknown target is NOT a 404, and no case leaks "has password".
        assert_eq!(b_wrong, b_none);
        assert_eq!(b_none, b_ghost);
    }

    #[tokio::test]
    async fn t51_403_is_distinct_from_401_session() {
        // The 403/401 split is honest: no session is 401 `sessão requerida`; a signed-in but
        // unauthorized cross-user reset is 403 with a different message.
        let state = AppState::default();
        let target = make_user(&state, "amelia.marques").await;
        give_target_password(&state, &target, "target-current-pass").await;

        // No session → 401.
        let (s401, b401) = send_raw(
            state.clone(),
            post_json(
                &format!("/v1/users/{target}/secret"),
                json!({ "password": "x-new-pass" }),
            ),
        )
        .await;
        assert_eq!(s401, StatusCode::UNAUTHORIZED);
        assert_eq!(b401["error"], "sessão requerida");

        // Signed-in but no proof → 403 with a distinct message.
        let bruno = make_user(&state, "bruno").await;
        let bruno_tok = open_session(&state, &bruno).await;
        let (s403, b403) = send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{target}/secret"),
                    json!({ "password": "x-new-pass" }),
                ),
                &bruno_tok,
            ),
        )
        .await;
        assert_eq!(s403, StatusCode::FORBIDDEN);
        assert_ne!(b403["error"], b401["error"]);
    }

    #[tokio::test]
    async fn t51_cross_user_remove_and_key_ops_enforce_the_same_rule() {
        // Adjacent-op parity (§5): remove-secret and the attestation-key ops all refuse a
        // no-proof cross-user caller (matrix #10/#12), and accept a correct-password one (#9/#11).
        let state = AppState::default();
        let target = make_user(&state, "amelia.marques").await;
        give_target_password(&state, &target, "target-current-pass").await;
        // Give the target an attestation key too (self-service).
        let self_tok = seed_session(&state, &target).await;
        send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{target}/attestation-key"),
                    json!({ "current_password": "target-current-pass" }),
                ),
                &self_tok,
            ),
        )
        .await;
        let bruno = make_user(&state, "bruno").await;
        let bruno_tok = open_session(&state, &bruno).await;

        // No-proof cross-user remove-secret → 403 (does not leak via a 200 no-op).
        let (s, _) = send(
            state.clone(),
            with_session(
                body_json("DELETE", &format!("/v1/users/{target}/secret"), json!({})),
                &bruno_tok,
            ),
        )
        .await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        // These adjacent-op probes reuse the same (bruno,target) key back-to-back; clear the t52
        // backoff between them so each is a fresh 403 under test, not a 429 (the throttle has its
        // own dedicated tests below).
        clear_secret_backoff(&state).await;

        // No-proof cross-user attestation-key removal → 403 (matrix #12).
        let (s, _) = send(
            state.clone(),
            with_session(
                body_json(
                    "DELETE",
                    &format!("/v1/users/{target}/attestation-key"),
                    json!({}),
                ),
                &bruno_tok,
            ),
        )
        .await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        clear_secret_backoff(&state).await;
        // Key is still there — nothing was removed.
        assert!(stored_user(&state, &target).await.attestation_key.is_some());

        // Correct-password cross-user attestation-key rotation → 200 (matrix #11).
        let (s, _) = send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{target}/attestation-key"),
                    json!({ "current_password": "target-current-pass" }),
                ),
                &bruno_tok,
            ),
        )
        .await;
        assert_eq!(s, StatusCode::OK);

        // Correct-password cross-user remove-secret → 200 and cascades the key (matrix #9).
        let (s, view) = send(
            state.clone(),
            with_session(
                body_json(
                    "DELETE",
                    &format!("/v1/users/{target}/secret"),
                    json!({ "current_password": "target-current-pass" }),
                ),
                &bruno_tok,
            ),
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(view["has_secret"], false);
        assert_eq!(view["has_attestation_key"], false);
    }

    #[tokio::test]
    async fn t51_recovery_phrase_reset_flow_is_single_use() {
        // Matrix #14 + Phase B: issue an independent recovery phrase, reset a forgotten password
        // with it cross-user, and prove it is single-use and drops the password-locked key.
        let state = AppState::default();
        let target = make_user(&state, "amelia.marques").await;
        give_target_password(&state, &target, "forgotten-pass").await;
        // Target holds an attestation key (wrapped under the forgotten password).
        let self_tok = seed_session(&state, &target).await;
        send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{target}/attestation-key"),
                    json!({ "current_password": "forgotten-pass" }),
                ),
                &self_tok,
            ),
        )
        .await;

        // Issue a recovery phrase for the target (self, proving the current password). Returned ONCE.
        let (status, issued) = send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{target}/recovery"),
                    json!({ "current_password": "forgotten-pass" }),
                ),
                &self_tok,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let phrase = issued["recovery_phrase"]
            .as_str()
            .expect("phrase")
            .to_owned();
        assert_eq!(phrase.len(), 32 + 3); // 4 groups of 8 base32 chars + 3 separators.
        assert_eq!(issued["has_recovery_phrase"], true);
        // The verifier is stored, never the plaintext.
        let stored = stored_user(&state, &target).await;
        assert!(
            stored
                .recovery_hash
                .as_deref()
                .expect("verifier")
                .starts_with("$argon2")
        );
        assert_ne!(stored.recovery_hash.as_deref(), Some(phrase.as_str()));

        // Bruno (another operator) resets the forgotten password using the recovery phrase.
        let bruno = make_user(&state, "bruno").await;
        let bruno_tok = open_session(&state, &bruno).await;
        let (status, view) = send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{target}/secret"),
                    json!({ "password": "recovered-pass", "recovery_phrase": phrase }),
                ),
                &bruno_tok,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(view["has_secret"], true);
        // Recovery consumed (single-use) and the password-locked key was dropped (unrecoverable).
        assert_eq!(view["has_recovery_phrase"], false);
        assert_eq!(view["has_attestation_key"], false);
        let stored = stored_user(&state, &target).await;
        assert_eq!(stored.secret_source, crate::users::SecretSource::Recovery);
        assert!(stored.recovery_hash.is_none());

        // The new password signs in; the forgotten one no longer does.
        let (s_new, _) = send(
            state.clone(),
            post_json(
                "/v1/session",
                json!({ "user_id": target, "password": "recovered-pass" }),
            ),
        )
        .await;
        assert_eq!(s_new, StatusCode::OK);

        // Re-using the SAME phrase again is refused — it was consumed (403, uniform).
        let (s_reuse, _) = send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{target}/secret"),
                    json!({ "password": "second-try", "recovery_phrase": phrase }),
                ),
                &bruno_tok,
            ),
        )
        .await;
        assert_eq!(s_reuse, StatusCode::FORBIDDEN);

        // The reset was audited as a recovery-phrase reset by bruno.
        let (_, events) = send(state.clone(), get("/v1/ledger/events")).await;
        let reset = events
            .as_array()
            .expect("events")
            .iter()
            .find(|e| e["kind"] == "user.secret.reset")
            .expect("reset event");
        assert_eq!(reset["actor"], "bruno");
        assert!(
            reset["justification"]
                .as_str()
                .expect("j")
                .contains("frase de recuperação")
        );
    }

    #[tokio::test]
    async fn t51_recovery_proof_cannot_generate_attestation_key() {
        // A recovery phrase authorizes a reset but CANNOT wrap a new attestation key (no password
        // to derive the KEK) — that specific cross-user op is refused with 403.
        let state = AppState::default();
        let target = make_user(&state, "amelia.marques").await;
        give_target_password(&state, &target, "target-pass").await;
        let self_tok = seed_session(&state, &target).await;
        let (_, issued) = send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{target}/recovery"),
                    json!({ "current_password": "target-pass" }),
                ),
                &self_tok,
            ),
        )
        .await;
        let phrase = issued["recovery_phrase"]
            .as_str()
            .expect("phrase")
            .to_owned();

        let bruno = make_user(&state, "bruno").await;
        let bruno_tok = open_session(&state, &bruno).await;
        let (status, body) = send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{target}/attestation-key"),
                    json!({ "recovery_phrase": phrase }),
                ),
                &bruno_tok,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(
            body["error"]
                .as_str()
                .expect("e")
                .contains("chave de atestação")
        );
    }

    #[tokio::test]
    async fn t51_provenance_defaults_and_old_users_json_loads() {
        // F4: `secret_source` is additive with a `Password` default, so a pre-t51 users.json (no
        // `secret_source`, no `recovery_hash`) still deserializes.
        let json = json!({
            "id": Uuid::new_v4().to_string(),
            "username": "amelia.marques",
            "display_name": "Amélia Marques",
            "created_at": "2026-01-01T00:00:00Z",
            "active": true,
            "password_hash": "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$c29tZWhhc2g"
        })
        .to_string();
        let user: User = serde_json::from_str(&json).expect("old users.json still loads");
        assert_eq!(user.secret_source, crate::users::SecretSource::Password);
        assert!(user.recovery_hash.is_none());
    }

    // --- t52: target-keyed backoff + failed-attempt audit on the cross-user reset endpoints -------
    //
    // These layer ON TOP of the t51 constant-work / uniform-403 guarantees (never below them): a
    // repeated FAILED cross-user attempt is throttled, and each un-throttled 403 is audited — without
    // reintroducing an enumeration oracle (a non-existent target throttles IDENTICALLY to a real one)
    // and without letting an attacker lock a victim out of their own self-service.

    /// One cross-user `POST /v1/users/{target}/secret` from `bruno_tok`, returning (status, body).
    async fn cross_user_set(
        state: &AppState,
        bruno_tok: &str,
        target: &str,
        body: Value,
    ) -> (StatusCode, Value) {
        send(
            state.clone(),
            with_session(
                post_json(&format!("/v1/users/{target}/secret"), body),
                bruno_tok,
            ),
        )
        .await
    }

    /// The t52 backoff key `(requester, target-from-request)` for two id strings (target may be a
    /// non-existent uuid — the key is request-derived, so a ghost target keys just like a real one).
    fn secret_backoff_key(requester: &str, target: &str) -> (Option<UserId>, UserId) {
        (
            Some(UserId(Uuid::parse_str(requester).expect("requester uuid"))),
            UserId(Uuid::parse_str(target).expect("target uuid")),
        )
    }

    /// The recorded consecutive-failure count for `(requester, target)`, or `None` if no failure has
    /// been recorded yet. Time-independent (unlike the window instant), so it is a robust signal that
    /// a failed attempt armed the throttle regardless of how slow argon2 is on the test machine.
    async fn secret_backoff_fails(state: &AppState, requester: &str, target: &str) -> Option<u32> {
        state
            .secret_backoff
            .read()
            .await
            .get(&secret_backoff_key(requester, target))
            .map(|b| b.fails)
    }

    /// Push the `(requester, target)` throttle window `secs` into the future, so the *response* to a
    /// throttled request (429) can be asserted deterministically without racing the real 1 s window
    /// (argon2 cost in a single request can otherwise consume most of it — the wall-clock flake
    /// t51-e2 flagged for signin). The window itself being SET by a real failure is asserted
    /// separately; this only fast-forwards an already-earned window to a stable value.
    async fn push_secret_backoff_window(
        state: &AppState,
        requester: &str,
        target: &str,
        secs: i64,
    ) {
        let now = time::OffsetDateTime::now_utc();
        let mut bo = state.secret_backoff.write().await;
        let entry =
            bo.entry(secret_backoff_key(requester, target))
                .or_insert(crate::session::Backoff {
                    fails: 0,
                    next_allowed_at: now,
                });
        entry.fails = entry.fails.max(1);
        entry.next_allowed_at = now + time::Duration::seconds(secs);
    }

    #[tokio::test]
    async fn t52_repeated_failed_cross_user_attempts_trigger_429() {
        // The reset endpoint now speed-bumps failed cross-user attempts, mirroring `signin_backoff`
        // on `POST /v1/session`: a failure records an escalating window on (requester,target), and a
        // request made while the window is open is refused 429 BEFORE any argon2 — so even the
        // correct password is throttled.
        let state = AppState::default();
        let target = make_user(&state, "amelia.marques").await;
        give_target_password(&state, &target, "target-current-pass").await;
        let bruno = make_user(&state, "bruno").await;
        let bruno_tok = open_session(&state, &bruno).await;

        // A failed cross-user attempt → uniform 403, and it RECORDS a future throttle window.
        let (s1, _) = cross_user_set(
            &state,
            &bruno_tok,
            &target,
            json!({ "password": "x-new-pass", "current_password": "WRONG" }),
        )
        .await;
        assert_eq!(s1, StatusCode::FORBIDDEN);
        assert_eq!(
            secret_backoff_fails(&state, &bruno, &target).await,
            Some(1),
            "the failed attempt armed the throttle (recorded a consecutive-failure window)"
        );

        // While throttled, the next request is 429 even with the CORRECT password (short-circuits
        // before argon2). Fast-forward the earned window to a stable value to avoid the wall-clock race.
        push_secret_backoff_window(&state, &bruno, &target, 30).await;
        let (s2, body) = cross_user_set(
            &state,
            &bruno_tok,
            &target,
            json!({ "password": "x-new-pass", "current_password": "target-current-pass" }),
        )
        .await;
        assert_eq!(
            s2,
            StatusCode::TOO_MANY_REQUESTS,
            "a request within the window is throttled, even with the right password"
        );
        assert!(
            body["error"]
                .as_str()
                .expect("error")
                .contains("tente novamente")
        );
    }

    #[tokio::test]
    async fn t52_backoff_applies_identically_to_a_nonexistent_target() {
        // Anti-enumeration: a NON-EXISTENT target must throttle EXACTLY like a real one — same 403
        // body on the first attempt, and same 429 (byte-identical body) while throttled. If a ghost
        // target were not throttled, or throttled differently, "throttled ⇒ real user" would be an
        // enumeration oracle. Both keys are pushed to the same window so the 429 bodies must match.
        let state = AppState::default();
        let real = make_user(&state, "amelia.marques").await;
        give_target_password(&state, &real, "target-current-pass").await;
        let ghost = Uuid::new_v4().to_string(); // no such user
        let bruno = make_user(&state, "bruno").await;
        let bruno_tok = open_session(&state, &bruno).await;

        // First attempt against each: a uniform, constant-work 403 with IDENTICAL body, and each
        // records its own throttle window (real and ghost alike).
        let (rs1, rb1) = cross_user_set(
            &state,
            &bruno_tok,
            &real,
            json!({ "password": "x-new-pass" }),
        )
        .await;
        let (gs1, gb1) = cross_user_set(
            &state,
            &bruno_tok,
            &ghost,
            json!({ "password": "x-new-pass" }),
        )
        .await;
        assert_eq!(rs1, StatusCode::FORBIDDEN);
        assert_eq!(gs1, StatusCode::FORBIDDEN);
        assert_eq!(
            rb1, gb1,
            "the first-attempt 403 body is identical (t51 uniform-403)"
        );
        // The non-existent target accrued a window JUST like the real one (no "not throttled ⇒ ghost").
        assert_eq!(
            secret_backoff_fails(&state, &bruno, &real).await,
            Some(1),
            "the real target accrued a throttle window"
        );
        assert_eq!(
            secret_backoff_fails(&state, &bruno, &ghost).await,
            Some(1),
            "the NON-EXISTENT target accrued a throttle window identically"
        );

        // While throttled (both windows fast-forwarded to the same value), the 429 bodies are
        // byte-identical — a ghost target is indistinguishable from a real one.
        push_secret_backoff_window(&state, &bruno, &real, 30).await;
        push_secret_backoff_window(&state, &bruno, &ghost, 30).await;
        let (rs2, rb2) = cross_user_set(
            &state,
            &bruno_tok,
            &real,
            json!({ "password": "x-new-pass" }),
        )
        .await;
        let (gs2, gb2) = cross_user_set(
            &state,
            &bruno_tok,
            &ghost,
            json!({ "password": "x-new-pass" }),
        )
        .await;
        assert_eq!(rs2, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(gs2, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            rb2, gb2,
            "the throttled 429 body is identical for a real vs a non-existent target"
        );
    }

    #[tokio::test]
    async fn t52_failed_cross_user_attempt_emits_denied_audit_event() {
        // A failed cross-user authorization (the 403 path) emits `user.secret.reset.denied`,
        // attributed to the honest requester, with a fixed-shape payload naming the target id, the
        // operation, and the attempted proof kind — and NO secret material.
        let state = AppState::default();
        let target = make_user(&state, "amelia.marques").await;
        give_target_password(&state, &target, "target-current-pass").await;
        let bruno = make_user(&state, "bruno").await;
        let bruno_tok = open_session(&state, &bruno).await;

        let (s, _) = cross_user_set(
            &state,
            &bruno_tok,
            &target,
            json!({ "password": "x-new-pass", "current_password": "WRONG" }),
        )
        .await;
        assert_eq!(s, StatusCode::FORBIDDEN);

        let (_, events) = send(state.clone(), get("/v1/ledger/events")).await;
        let denied = events
            .as_array()
            .expect("events")
            .iter()
            .find(|e| e["kind"] == "user.secret.reset.denied")
            .expect("a denied audit event was appended");
        assert_eq!(denied["actor"], "bruno", "honest requester attribution");

        // The payload is exactly {target_id, operation, attempted_proof} (declaration order,
        // compact) — proving all three are recorded and nothing else leaks. The feed exposes only the
        // digest, so match against the reconstructed bytes.
        let expected_bytes = format!(
            r#"{{"target_id":"{target}","operation":"set_secret","attempted_proof":"palavra-passe"}}"#
        )
        .into_bytes();
        let expected_digest = crate::hex::hex(&chancela_ledger::digest(&expected_bytes));
        assert_eq!(
            denied["payload_digest"], expected_digest,
            "payload names the target id, operation, and attempted proof kind — no secret material"
        );
        // Defence in depth: neither the submitted password nor any argon2 hash appears anywhere.
        let dump = denied.to_string().to_lowercase();
        assert!(!dump.contains("wrong") && !dump.contains("$argon2"));
    }

    #[tokio::test]
    async fn t52_self_service_not_throttled_by_third_party_target_hammering() {
        // The throttle bites the abusive requester, keyed on (requester,target) — so an attacker
        // hammering a victim's id as a target can NOT lock the victim out of their own self-service
        // (a different key, `(victim,victim)`, which is never throttled at all).
        let state = AppState::default();
        let target = make_user(&state, "amelia.marques").await;
        give_target_password(&state, &target, "amelia-pass").await;
        let bruno = make_user(&state, "bruno").await;
        let bruno_tok = open_session(&state, &bruno).await;

        // Bruno hammers amelia's id and earns a throttle window on (bruno, amelia); fast-forward it
        // so his next attempt is deterministically 429.
        let (s1, _) = cross_user_set(
            &state,
            &bruno_tok,
            &target,
            json!({ "password": "x-new-pass" }),
        )
        .await;
        assert_eq!(s1, StatusCode::FORBIDDEN);
        push_secret_backoff_window(&state, &bruno, &target, 30).await;
        let (s2, _) = cross_user_set(
            &state,
            &bruno_tok,
            &target,
            json!({ "password": "x-new-pass" }),
        )
        .await;
        assert_eq!(
            s2,
            StatusCode::TOO_MANY_REQUESTS,
            "the attacker is now throttled"
        );

        // Amelia's own self-service password change is UNAFFECTED (different key, never throttled).
        let self_tok = seed_session(&state, &target).await;
        let (s_self, view) = send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{target}/secret"),
                    json!({ "password": "amelia-new-pass", "current_password": "amelia-pass" }),
                ),
                &self_tok,
            ),
        )
        .await;
        assert_eq!(
            s_self,
            StatusCode::OK,
            "the victim's own self-service is not collateral-throttled"
        );
        assert_eq!(view["has_secret"], true);
    }

    // =============================================================================================
    // t54-E3: chain-recovery + per-book export/import/start-over + data management
    // =============================================================================================

    /// A fresh **persistent** state backed by a unique temp data dir (opens a real SQLite store, so
    /// the recovery/export/import/reset endpoints — which require durability — are exercisable). The
    /// dir lives under the OS temp dir; it is left in place (the open sqlite handle makes an eager
    /// remove flaky on Windows), which is fine for a hermetic per-test dir.
    fn persistent_state() -> AppState {
        let dir = std::env::temp_dir().join(format!("chancela-api-t54-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("temp data dir");
        AppState::with_data_dir(dir)
    }

    /// Create an entity + open a book on `state` using `token`; returns `(entity_id, book_id)`.
    async fn seed_entity_and_book(state: &AppState, token: &str) -> (String, String) {
        let (status, entity) = send(
            state.clone(),
            with_session(
                post_json(
                    "/v1/entities",
                    json!({
                        "name": "Encosto Estratégico, S.A.",
                        "nipc": "503004642",
                        "seat": "Lisboa",
                        "kind": "SociedadeAnonima",
                    }),
                ),
                token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "seed entity: {entity}");
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
                token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "seed book: {book}");
        let book_id = book["id"].as_str().expect("book id").to_owned();
        (entity_id, book_id)
    }

    /// Draft, fill, advance, and SEAL an ata into `book_id` on `state` with `token`.
    async fn seal_one_act(state: &AppState, book_id: &str, token: &str) {
        let (_, act) = send(
            state.clone(),
            with_session(
                post_json(
                    "/v1/acts",
                    json!({ "book_id": book_id, "title": "Ata da AG anual", "channel": "Physical" }),
                ),
                token,
            ),
        )
        .await;
        let act_id = act["id"].as_str().expect("act id").to_owned();
        send(
            state.clone(),
            with_session(
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
                token,
            ),
        )
        .await;
        for to in [
            "Review",
            "Convened",
            "Deliberated",
            "TextApproved",
            "Signing",
        ] {
            send(
                state.clone(),
                with_session(
                    post_json(&format!("/v1/acts/{act_id}/advance"), json!({ "to": to })),
                    token,
                ),
            )
            .await;
        }
        let (status, _) = send(
            state.clone(),
            with_session(
                post_json(&format!("/v1/acts/{act_id}/seal"), json!({})),
                token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "seal one act");
    }

    /// Seed a signed-in user WITH a password (for step-up re-auth), returning `(user_id, token)`.
    /// The session is seeded directly (bypassing the password) so `require_step_up`'s re-auth is
    /// what actually proves the password — mirroring the real UI (a live session + a fresh re-auth).
    async fn user_with_password(state: &AppState, username: &str, password: &str) -> String {
        let uid = make_user(state, username).await;
        give_target_password(state, &uid, password).await;
        seed_session(state, &uid).await
    }

    /// POST a raw body (e.g. bundle bytes) with a session token.
    fn post_raw(uri: &str, bytes: Vec<u8>) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(uri)
            .body(Body::from(bytes))
            .expect("request builds")
    }

    /// Re-zip a book bundle with a corrupted `events.jsonl` member (its sha256 no longer matches the
    /// unchanged manifest), so verify-before-trust quarantines it. Proves an api-level forgery is
    /// caught and isolated, never merged as a live chain.
    fn tamper_bundle(zip_bytes: &[u8]) -> Vec<u8> {
        use std::io::{Read, Write};
        let mut archive =
            zip::ZipArchive::new(std::io::Cursor::new(zip_bytes)).expect("valid bundle zip");
        let mut members: Vec<(String, Vec<u8>)> = Vec::new();
        for i in 0..archive.len() {
            let mut f = archive.by_index(i).expect("zip member");
            let name = f.name().to_owned();
            let mut buf = Vec::new();
            f.read_to_end(&mut buf).expect("read member");
            members.push((name, buf));
        }
        for (name, bytes) in members.iter_mut() {
            if name == "events.jsonl" && !bytes.is_empty() {
                bytes[0] ^= 0xff; // corrupt → member digest mismatch → Quarantined
            }
        }
        let mut out = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let opts = zip::write::SimpleFileOptions::default();
        for (name, bytes) in &members {
            out.start_file(name.as_str(), opts).expect("start file");
            out.write_all(bytes).expect("write member");
        }
        out.finish().expect("finish zip").into_inner()
    }

    #[tokio::test]
    async fn integrity_endpoint_reports_a_healthy_chain() {
        let state = persistent_state();
        let token = seed_session(&state, &make_user(&state, "amelia.marques").await).await;
        seed_entity_and_book(&state, &token).await;

        let (status, report) = send(state.clone(), get("/v1/ledger/integrity")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(report["healthy"], true);
        assert_eq!(report["degraded"], false);
        assert_eq!(report["global"]["verified"], true);
        assert!(report["global"]["length"].as_u64().expect("length") >= 1);
        assert!(
            report["reanchored_segments"]
                .as_array()
                .expect("segments")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn reanchor_requires_step_up_reauth() {
        // A signed-in operator WITH a password, so step-up re-auth has a credential to verify against.
        let state = persistent_state();
        let token = user_with_password(&state, "amelia.marques", "reanchor-pass-1234").await;
        seed_entity_and_book(&state, &token).await;

        // A valid session alone (no step-up proof) is refused with 403 — mirrors the destructive wipes.
        let (status, _) = send(
            state.clone(),
            with_session(
                post_json(
                    "/v1/ledger/recovery/reanchor",
                    json!({ "reason": "reparar cadeia" }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "session alone is not enough for reanchor"
        );

        // A wrong password is likewise refused with a uniform 403.
        let (status, _) = send(
            state.clone(),
            with_session(
                post_json(
                    "/v1/ledger/recovery/reanchor",
                    json!({ "reason": "reparar cadeia", "reauth": { "password": "WRONG" } }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "wrong step-up refused");

        // With valid step-up the op PROCEEDS past the gate: the in-memory chain is healthy, so it
        // reaches the handler and refuses with 409 (already valid — nothing to repair).
        let (status, _) = send(
            state.clone(),
            with_session(
                post_json(
                    "/v1/ledger/recovery/reanchor",
                    json!({ "reason": "reparar cadeia", "reauth": { "password": "reanchor-pass-1234" } }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "valid step-up proceeds; already-valid chain → 409"
        );
    }

    #[tokio::test]
    async fn export_import_round_trips_verified_and_a_forged_bundle_quarantines() {
        // Source instance A: a book with a sealed ata.
        let a = persistent_state();
        let a_tok = seed_session(&a, &make_user(&a, "amelia.marques").await).await;
        let (_eid, book_id) = seed_entity_and_book(&a, &a_tok).await;
        seal_one_act(&a, &book_id, &a_tok).await;

        // Export the book bundle (application/zip download, retained under exports/).
        let (status, ctype, bundle) = send_bytes(
            a.clone(),
            with_session(
                post_raw(&format!("/v1/books/{book_id}/export"), Vec::new()),
                &a_tok,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "export book");
        assert!(ctype.starts_with("application/zip"), "ctype={ctype}");
        assert!(!bundle.is_empty(), "bundle has bytes");

        // Fresh instance B: importing the clean bundle VERIFIES (no collision on a fresh instance).
        let b = persistent_state();
        let b_tok = seed_session(&b, &make_user(&b, "bruno").await).await;
        let (status, outcome) = send(
            b.clone(),
            with_session(post_raw("/v1/books/import", bundle.clone()), &b_tok),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "import verified: {outcome}");
        assert_eq!(outcome["verdict"]["status"], "Verified");
        assert_eq!(outcome["collided"], false);
        assert_eq!(outcome["book_id"], book_id);

        // A forged bundle (tampered member) is QUARANTINED, never trusted as valid.
        let c = persistent_state();
        let c_tok = seed_session(&c, &make_user(&c, "carla").await).await;
        let forged = tamper_bundle(&bundle);
        let (status, outcome) = send(
            c.clone(),
            with_session(post_raw("/v1/books/import", forged), &c_tok),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "forged import handled: {outcome}");
        assert_eq!(outcome["verdict"]["status"], "Quarantined");
        assert!(
            outcome["verdict"]["break"].is_object(),
            "break detail present"
        );
    }

    #[tokio::test]
    async fn per_book_start_over_archives_and_opens_a_fresh_successor() {
        let state = persistent_state();
        let token = seed_session(&state, &make_user(&state, "amelia.marques").await).await;
        let (_eid, book_id) = seed_entity_and_book(&state, &token).await;
        seal_one_act(&state, &book_id, &token).await;

        let (status, resp) = send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/books/{book_id}/start-over"),
                    json!({
                        "reason": "livro esgotado — recomeçar",
                        "purpose": "livro de atas da assembleia geral (sucessor)",
                        "opening_date": "2026-07-08",
                        "required_signatories": ["Administrador"],
                    }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "start-over: {resp}");
        assert_eq!(resp["reinit"]["old_book_id"], book_id);
        assert_eq!(resp["new_book"]["state"], "Open");
        assert!(resp["reinit"]["archived_bundle_digest"].is_string());
        let new_book_id = resp["new_book"]["id"].as_str().expect("new id").to_owned();
        assert_ne!(new_book_id, book_id);

        // The old book still exists (append-only; nothing erased); both books are queryable.
        let (status, _) = send(state.clone(), get(&format!("/v1/books/{book_id}"))).await;
        assert_eq!(status, StatusCode::OK, "old book preserved");
        let (status, _) = send(state.clone(), get(&format!("/v1/books/{new_book_id}"))).await;
        assert_eq!(status, StatusCode::OK, "successor opened");

        // The lifecycle events are chained (exported + reinitialized), and the chain still verifies.
        let (_, events) = send(state.clone(), get("/v1/ledger/events?limit=1000")).await;
        let kinds: Vec<&str> = events
            .as_array()
            .expect("events")
            .iter()
            .map(|e| e["kind"].as_str().unwrap_or_default())
            .collect();
        assert!(
            kinds.contains(&"ledger.exported"),
            "exported chained: {kinds:?}"
        );
        assert!(kinds.contains(&"ledger.reinitialized"), "reinit chained");
        let (_, verify) = send(state.clone(), get("/v1/ledger/verify")).await;
        assert_eq!(
            verify["valid"], true,
            "chain still verifies after start-over"
        );
    }

    #[tokio::test]
    async fn whole_instance_start_over_requires_confirm_and_reauth_then_reseeds_empty() {
        let state = persistent_state();
        let token = user_with_password(&state, "amelia.marques", "wipe-pass-1234").await;
        seed_entity_and_book(&state, &token).await;

        // Wrong confirm phrase → 422 (reaches the handler; nothing destroyed).
        let (status, _) = send(
            state.clone(),
            with_session(
                post_json(
                    "/v1/data/start-over",
                    json!({ "reason": "x", "confirm_phrase": "nope",
                            "reauth": { "password": "wipe-pass-1234" } }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "wrong phrase refused"
        );

        // Right phrase but NO step-up re-auth → 403 (a session alone is not enough).
        let (status, _) = send(
            state.clone(),
            with_session(
                post_json(
                    "/v1/data/start-over",
                    json!({ "reason": "x", "confirm_phrase": "RECOMEÇAR" }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "no step-up refused");

        // Confirm + re-auth → archives, then re-seeds a fresh (nearly empty) ledger.
        let (status, resp) = send(
            state.clone(),
            with_session(
                post_json(
                    "/v1/data/start-over",
                    json!({ "reason": "recomeçar a instância", "confirm_phrase": "RECOMEÇAR",
                            "reauth": { "password": "wipe-pass-1234" } }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "instance start-over: {resp}");
        assert!(resp["archive_path"].is_string());

        // Domain is cleared; the fresh ledger's genesis is the reinitialization, and it verifies.
        let (_, entities) = send(state.clone(), get("/v1/entities")).await;
        assert!(
            entities.as_array().expect("entities").is_empty(),
            "domain cleared"
        );
        let (_, verify) = send(state.clone(), get("/v1/ledger/verify")).await;
        assert_eq!(verify["valid"], true);
        assert_eq!(
            verify["length"], 1,
            "fresh ledger holds only the reinit genesis"
        );
    }

    #[tokio::test]
    async fn reset_backend_domain_preserves_the_ledger_and_emits_data_wiped() {
        let state = persistent_state();
        let token = user_with_password(&state, "amelia.marques", "wipe-pass-1234").await;
        let (_eid, book_id) = seed_entity_and_book(&state, &token).await;
        seal_one_act(&state, &book_id, &token).await;
        let (_, verify_before) = send(state.clone(), get("/v1/ledger/verify")).await;
        let len_before = verify_before["length"].as_u64().expect("len");

        let (status, resp) = send(
            state.clone(),
            with_session(
                post_json(
                    "/v1/data/reset",
                    json!({ "scope": "backend_domain", "confirm_phrase": "LIMPAR DADOS",
                            "export_first": true, "reauth": { "password": "wipe-pass-1234" } }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "domain wipe: {resp}");
        assert!(
            resp["export_archive"].is_string(),
            "export-first archive taken"
        );

        // Domain data cleared, but the append-only ledger is PRESERVED + grew a data.wiped event.
        let (_, entities) = send(state.clone(), get("/v1/entities")).await;
        assert!(
            entities.as_array().expect("entities").is_empty(),
            "domain cleared"
        );
        let (_, verify) = send(state.clone(), get("/v1/ledger/verify")).await;
        assert_eq!(verify["valid"], true, "ledger still verifies");
        assert!(
            verify["length"].as_u64().expect("len") > len_before,
            "ledger preserved and grew (data.wiped + export)"
        );
        let (_, events) = send(state.clone(), get("/v1/ledger/events?limit=1000")).await;
        assert!(
            events
                .as_array()
                .expect("events")
                .iter()
                .any(|e| e["kind"] == "data.wiped"),
            "a data.wiped event was chained"
        );
    }

    #[tokio::test]
    async fn reset_backend_factory_blanks_everything_after_export_first() {
        let state = persistent_state();
        let token = user_with_password(&state, "amelia.marques", "wipe-pass-1234").await;
        let (_eid, book_id) = seed_entity_and_book(&state, &token).await;
        seal_one_act(&state, &book_id, &token).await;

        let (status, resp) = send(
            state.clone(),
            with_session(
                post_json(
                    "/v1/data/reset",
                    json!({ "scope": "backend_factory", "confirm_phrase": "REPOR FÁBRICA",
                            "export_first": true, "reauth": { "password": "wipe-pass-1234" } }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "factory reset: {resp}");
        assert!(
            resp["export_archive"].is_string(),
            "export-first archive taken"
        );

        // Blank first-run: the ledger is gone (empty) — the retained archive IS the record.
        let (_, verify) = send(state.clone(), get("/v1/ledger/verify")).await;
        assert_eq!(verify["length"], 0, "ledger blanked");
        let (_, entities) = send(state.clone(), get("/v1/entities")).await;
        assert!(
            entities.as_array().expect("entities").is_empty(),
            "domain blanked"
        );
    }

    #[tokio::test]
    async fn reset_requires_step_up_reauth_and_the_confirm_phrase() {
        let state = persistent_state();
        let token = user_with_password(&state, "amelia.marques", "wipe-pass-1234").await;
        seed_entity_and_book(&state, &token).await;

        // No re-auth (session only) → 403.
        let (status, _) = send(
            state.clone(),
            with_session(
                post_json(
                    "/v1/data/reset",
                    json!({ "scope": "backend_domain", "confirm_phrase": "LIMPAR DADOS",
                            "export_first": true }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "session alone is not enough");

        // Wrong password → 403.
        let (status, _) = send(
            state.clone(),
            with_session(
                post_json(
                    "/v1/data/reset",
                    json!({ "scope": "backend_domain", "confirm_phrase": "LIMPAR DADOS",
                            "export_first": true, "reauth": { "password": "WRONG" } }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "wrong step-up refused");

        // Right re-auth but wrong confirm phrase → 422; the domain is untouched throughout.
        let (status, _) = send(
            state.clone(),
            with_session(
                post_json(
                    "/v1/data/reset",
                    json!({ "scope": "backend_domain", "confirm_phrase": "wrong",
                            "export_first": true, "reauth": { "password": "wipe-pass-1234" } }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "wrong phrase refused"
        );
        let (_, entities) = send(state.clone(), get("/v1/entities")).await;
        assert_eq!(
            entities.as_array().expect("entities").len(),
            1,
            "domain intact"
        );
    }

    #[tokio::test]
    async fn degraded_gate_blocks_mutations_but_leaves_reads_and_recovery_open() {
        let state = persistent_state();
        let token = user_with_password(&state, "amelia.marques", "wipe-pass-1234").await;
        let (_eid, book_id) = seed_entity_and_book(&state, &token).await;

        // Force the degraded (read-only) signal (as a broken boot chain would).
        *state.degraded.write().await = true;

        // An ordinary mutation is blocked with 503 + the honest read-only body.
        let (status, body) = send(
            state.clone(),
            with_session(
                post_json(
                    "/v1/entities",
                    json!({ "name": "X, S.A.", "nipc": "500000000", "seat": "Porto", "kind": "SociedadeAnonima" }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "mutation gated");
        assert_eq!(body["read_only"], true);
        assert_eq!(body["integrity"], "broken");

        // Reads stay open.
        let (status, _) = send(state.clone(), get("/v1/entities")).await;
        assert_eq!(status, StatusCode::OK, "reads open while degraded");
        let (status, report) = send(state.clone(), get("/v1/ledger/integrity")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(report["degraded"], true);

        // The recovery/reset plane stays reachable (NOT 503): each reaches its handler and returns a
        // handler-level status, never the gate's 503.
        let (status, _) = send(
            state.clone(),
            with_session(
                post_json(
                    "/v1/data/reset",
                    json!({ "scope": "backend_domain", "confirm_phrase": "wrong",
                            "reauth": { "password": "wipe-pass-1234" } }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "reset reachable while degraded"
        );

        let (status, _) = send(
            state.clone(),
            with_session(
                post_json(
                    "/v1/ledger/recovery/reanchor",
                    json!({ "reason": "x", "reauth": { "password": "wipe-pass-1234" } }),
                ),
                &token,
            ),
        )
        .await;
        // The in-memory chain is actually healthy, so reanchor (with valid step-up) refuses with 409 —
        // proving it was REACHED (not 503-gated).
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "reanchor reachable while degraded"
        );

        // Export stays open (archive-first before a repair).
        let (status, _, _) = send_bytes(
            state.clone(),
            with_session(
                post_raw(&format!("/v1/books/{book_id}/export"), Vec::new()),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "export reachable while degraded");
    }

    // --- t69: passwordless self-step-up (the lockout fix) -----------------------------------------

    /// Corrupt the in-memory ledger's tail self-hash so the chain no longer verifies (mirrors the
    /// `try_append` test's break). Used to drive a *real* re-anchor repair (→ 200) rather than the
    /// already-valid 409.
    async fn break_ledger_tail(state: &AppState) {
        let mut events = state.ledger.read().await.events().to_vec();
        let n = events.len();
        assert!(n > 0, "need at least one event to break");
        events[n - 1].hash[0] ^= 0xff;
        let (broken, _) = Ledger::try_from_events(events);
        *state.ledger.write().await = broken;
        assert!(
            !state.ledger.read().await.integrity_report().healthy,
            "chain is broken after tampering"
        );
    }

    #[tokio::test]
    async fn t69_passwordless_owner_recovers_while_degraded_without_stepup() {
        // t69 lockout fix: a PASSWORDLESS Owner (no password, no recovery phrase) on a DEGRADED
        // instance can still drive the recovery/destructive plane with a session ONLY — a valid self
        // session IS the strongest proof they can offer, so step-up must not 403 them. Without this
        // fix an all-passwordless instance whose chain breaks could never be recovered by anyone.
        let state = persistent_state();
        let owner = make_user(&state, "amelia.marques").await; // Owner@Global, passwordless
        let token = seed_session(&state, &owner).await;
        seed_entity_and_book(&state, &token).await;

        // Enter degraded (read-only) mode, as a broken boot chain would.
        *state.degraded.write().await = true;

        // Re-anchor with NO reauth: the in-memory chain is healthy so it reaches the handler and
        // returns 409 (already valid) — crucially NOT the 403 a missing step-up used to produce.
        let (status, body) = send(
            state.clone(),
            with_session(
                post_json(
                    "/v1/ledger/recovery/reanchor",
                    json!({ "reason": "reparar cadeia" }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "passwordless Owner reaches reanchor (no step-up 403): {body}"
        );

        // Data reset (backend_domain) with the correct confirm phrase and NO reauth → 200. Step-up
        // is satisfied by the self session; the type-to-confirm phrase is still required.
        let (status, resp) = send(
            state.clone(),
            with_session(
                post_json(
                    "/v1/data/reset",
                    json!({ "scope": "backend_domain", "confirm_phrase": "LIMPAR DADOS",
                            "export_first": true }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "passwordless Owner completes a domain reset without step-up: {resp}"
        );

        // The type-to-confirm phrase is STILL enforced (a passwordless user is not waved through the
        // second confirmation): a wrong phrase is a 422, never a silent wipe.
        let (status, _) = send(
            state.clone(),
            with_session(
                post_json(
                    "/v1/data/reset",
                    json!({ "scope": "backend_domain", "confirm_phrase": "errado",
                            "export_first": true }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "type-to-confirm phrase still required for a passwordless user"
        );
    }

    #[tokio::test]
    async fn t69_passwordless_owner_reanchors_a_broken_chain_and_discloses() {
        // The real repair: a passwordless Owner with a genuinely broken chain re-anchors it with a
        // session only (no step-up) → 200; the disclosure is recorded and the chain verifies again.
        let state = persistent_state();
        let owner = make_user(&state, "amelia.marques").await;
        let token = seed_session(&state, &owner).await;
        seed_entity_and_book(&state, &token).await;

        break_ledger_tail(&state).await;
        *state.degraded.write().await = true;

        let (status, resp) = send(
            state.clone(),
            with_session(
                post_json(
                    "/v1/ledger/recovery/reanchor",
                    json!({ "reason": "reparar cadeia partida" }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "passwordless Owner re-anchors a broken chain without step-up: {resp}"
        );
        // Re-anchor DISCLOSES (never erases): the permanent, chained disclosure is present.
        assert!(
            resp["record"]["pre_reanchor_digest"].is_string(),
            "re-anchor disclosure (pre_reanchor_digest) recorded: {resp}"
        );
        // The chain verifies again — recovery actually succeeded.
        let (_, report) = send(state.clone(), get("/v1/ledger/integrity")).await;
        assert_eq!(report["healthy"], true, "chain repaired");
    }

    #[tokio::test]
    async fn t69_passwordless_leitor_is_403_by_rbac_not_a_stepup_bypass() {
        // The relaxation is SELF-step-up ONLY; RBAC stays the primary gate. A PASSWORDLESS Leitor
        // (lacks ledger.recover / data.wipe) is refused with a PERMISSION 403 — never waved through
        // by the passwordless step-up carve-out. (`require_permission` runs before `require_step_up`.)
        use chancela_authz::{LEITOR_ROLE_ID, RoleAssignment, Scope};
        let state = persistent_state();
        let leitor = seed_user(
            &state,
            "amelia.marques",
            vec![RoleAssignment::new(LEITOR_ROLE_ID, Scope::Global)],
        )
        .await;
        let token = seed_session(&state, &leitor.to_string()).await;
        *state.degraded.write().await = true;

        // Re-anchor → 403 on the permission gate (not a step-up bypass).
        let (status, body) = send(
            state.clone(),
            with_session(
                post_json(
                    "/v1/ledger/recovery/reanchor",
                    json!({ "reason": "tentativa sem permissão" }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "Leitor cannot re-anchor: {body}"
        );
        assert!(
            body["error"].as_str().expect("error").contains("permissão"),
            "refused by RBAC (permission), not a step-up bypass: {body}"
        );

        // Data reset (correct phrase, so the phrase check passes) → 403 on the permission gate too.
        let (status, body) = send(
            state.clone(),
            with_session(
                post_json(
                    "/v1/data/reset",
                    json!({ "scope": "backend_domain", "confirm_phrase": "LIMPAR DADOS",
                            "export_first": true }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "Leitor cannot reset data: {body}"
        );
        assert!(
            body["error"].as_str().expect("error").contains("permissão"),
            "refused by RBAC (permission): {body}"
        );
    }

    #[tokio::test]
    async fn t69_credentialed_user_step_up_is_unchanged() {
        // The carve-out is ONLY for a user who holds NO credential. A user WITH a password must still
        // prove it: session-only and wrong-password both 403; the correct password proceeds (here to
        // a real 200 repair). Guards against the passwordless relaxation leaking to credentialed users.
        let state = persistent_state();
        let token = user_with_password(&state, "amelia.marques", "recover-pass-1234").await;
        seed_entity_and_book(&state, &token).await;
        break_ledger_tail(&state).await;
        *state.degraded.write().await = true;

        // Session only → 403 (has a password, must supply it).
        let (status, _) = send(
            state.clone(),
            with_session(
                post_json(
                    "/v1/ledger/recovery/reanchor",
                    json!({ "reason": "reparar" }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "credentialed session-only still 403"
        );

        // Wrong password → 403.
        let (status, _) = send(
            state.clone(),
            with_session(
                post_json(
                    "/v1/ledger/recovery/reanchor",
                    json!({ "reason": "reparar", "reauth": { "password": "WRONG" } }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "credentialed wrong password still 403"
        );

        // Correct password → proceeds and repairs → 200.
        let (status, resp) = send(
            state.clone(),
            with_session(
                post_json(
                    "/v1/ledger/recovery/reanchor",
                    json!({ "reason": "reparar", "reauth": { "password": "recover-pass-1234" } }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "correct password repairs: {resp}");
    }

    #[tokio::test]
    async fn t69_cross_user_passwordless_target_stays_refused() {
        // The t52 hole stays CLOSED: the self-step-up relaxation must NOT be mistaken for reopening
        // cross-user resets against a passwordless TARGET. A signed-in operator setting a first
        // password on ANOTHER passwordless user is still a uniform 403, and the target is untouched.
        let state = AppState::default();
        let target = make_user(&state, "amelia.marques").await; // passwordless target
        let bruno = make_user(&state, "bruno").await;
        let bruno_tok = open_session(&state, &bruno).await;

        let (status, body) = send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{target}/secret"),
                    json!({ "password": "escolhida-pelo-atacante" }),
                ),
                &bruno_tok,
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "cross-user passwordless-target still refused: {body}"
        );
        assert!(
            body["error"]
                .as_str()
                .expect("error")
                .contains("não autorizado"),
            "uniform cross-user refusal (t52 intact): {body}"
        );
        let (_, view) = send(state.clone(), get(&format!("/v1/users/{target}"))).await;
        assert_eq!(
            view["has_secret"], false,
            "target untouched (still passwordless)"
        );
    }

    #[tokio::test]
    async fn try_append_rejects_a_chain_breaking_mutation() {
        // In-memory state: an entity + open book, then corrupt the ledger's global tail so any
        // further append onto that chain must be rejected by the validating try_append (t54 #6).
        let (state, _eid, book_id) = entity_and_open_book("SociedadeAnonima").await;
        {
            let mut events = state.ledger.read().await.events().to_vec();
            let n = events.len();
            events[n - 1].hash[0] ^= 0xff; // break the tail's self-hash
            let (broken, _) = Ledger::try_from_events(events);
            *state.ledger.write().await = broken;
        }

        // Drafting an act joins the (now broken-tailed) chain → try_append rejects it → 409, and
        // nothing is persisted.
        let (status, body) = send(
            state.clone(),
            post_json(
                "/v1/acts",
                json!({ "book_id": book_id, "title": "Ata", "channel": "Physical" }),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "chain-breaking append rejected: {body}"
        );
        assert!(
            body["error"]
                .as_str()
                .expect("error")
                .contains("break a chain"),
            "the refusal names the chain-break cause: {body}"
        );
    }
}
