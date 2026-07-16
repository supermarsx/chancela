//! CAE library endpoints (contract §2.7, §cae-v2): resolve a code, browse the classification tree
//! (secções + a code's children), search, expose the active catalog's provenance, report the INE
//! SMI update signal, and force a multi-source auto-update refresh.
//!
//! The catalog ([`chancela_cae::CaeCatalog`]) lives in [`AppState::cae`](crate::AppState) — the
//! embedded both-revision dataset by default, replaced by a valid `cae-catalog.json` cache when the
//! state is file-backed, and swapped in place by [`refresh_cae`] on a successful update.
//!
//! [`refresh_cae`] resolves a **strict, fidelity-gated source chain** (the optional official Diário
//! da República diploma pair + each `catalog.cae_sources` entry) and runs it via
//! [`chancela_cae::obtain_from_chain`] — the first source that fetches, parses, clears the integrity
//! **and full-count fidelity** gates, and supersedes the active catalog wins. The legacy single
//! mirror URL (`catalog.cae_update_url`, then `CHANCELA_CAE_URL`) keeps its original integrity-only
//! semantics as the **final fallback**, taken only when the strict chain is empty. The refresh runs
//! on a dedicated OS thread awaited over a oneshot, because each source's `reqwest::blocking` client
//! owns an internal runtime that must be built and dropped clear of the async runtime (as the
//! registry consult does). A supersede swaps the catalog + appends a `cae.updated` ledger event with
//! the obtain's provenance; everything up to date is a no-op (`updated: false`); every source
//! failing is a `502` with the per-source failures.
//!
//! **No-config default.** When *nothing* is configured — no `cae_sources`, `cae_official_source`
//! off, no `cae_update_url`/`CHANCELA_CAE_URL`, and no `?source` pin — the refresh no longer refuses:
//! it runs [`chancela_cae::default_official_chain`] (the digest-pinned Diário da República diploma
//! pair), so "sem configuração, o catálogo é atualizado a partir dos diplomas oficiais do Diário da
//! República". The friendly settings-aware `422` remains only when a default is *impossible*: a
//! `?source` pin that matched nothing (e.g. `?source=mirror` with no mirrors configured). Offline the
//! default chain simply fails its fetch → `502` with the failures list (graceful, correct).
//!
//! [`cae_updates`] (`GET /v1/cae/updates`) reports the INE SMI update signal: it fetches and parses
//! the SMI version catalog off-runtime and returns the current official CAE Rev.3 / Rev.4 version
//! codes + designations (or a `502` when SMI is unreachable / unparseable). Operator-initiated from
//! the Ferramentas panel; not cached.

use std::path::PathBuf;
use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use chancela_cae::{
    CaeCatalog, CaeCounts, CaeEntry, CaeLevel, CaeOrigin, CaeProvenance, CaeRevision, CaeSource,
    CaeSourceChain, ChainEntry, ChainOutcome, ENV_CAE_URL, HttpCaeSource, MirrorArtifactSource,
    SmiSource, obtain_from_chain, official_chain_for, refresh,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use chancela_authz::{Permission, Scope};

use crate::AppState;
use crate::actor::{CurrentActor, CurrentAttestor};
use crate::authz::require_permission;
use crate::error::ApiError;
use crate::settings::CatalogSettings;

// --- Views --------------------------------------------------------------------------------

/// A single classification node without its ancestry — the list/search element and the shape of
/// each `hierarchy` entry.
#[derive(Serialize)]
pub struct CaeNodeView {
    pub code: String,
    pub designation: String,
    pub level: CaeLevel,
    pub revision: CaeRevision,
}

impl From<&CaeEntry> for CaeNodeView {
    fn from(e: &CaeEntry) -> Self {
        CaeNodeView {
            code: e.code.clone(),
            designation: e.designation.clone(),
            level: e.level,
            revision: e.revision,
        }
    }
}

/// A resolved CAE entry. On the single-code `GET /v1/cae/{code}` it carries its `hierarchy`
/// (secção→…→self); in the search list form `hierarchy` is omitted.
#[derive(Serialize)]
pub struct CaeEntryView {
    pub code: String,
    pub designation: String,
    pub level: CaeLevel,
    pub revision: CaeRevision,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hierarchy: Option<Vec<CaeNodeView>>,
}

impl CaeEntryView {
    /// The list/search form: the node alone, no hierarchy.
    fn node(e: &CaeEntry) -> Self {
        CaeEntryView {
            code: e.code.clone(),
            designation: e.designation.clone(),
            level: e.level,
            revision: e.revision,
            hierarchy: None,
        }
    }

    /// The single-code form: the node plus its ancestor chain.
    fn with_hierarchy(e: &CaeEntry, hierarchy: Vec<CaeNodeView>) -> Self {
        CaeEntryView {
            code: e.code.clone(),
            designation: e.designation.clone(),
            level: e.level,
            revision: e.revision,
            hierarchy: Some(hierarchy),
        }
    }
}

/// The active catalog's provenance + integrity metadata (the `GET /v1/cae` no-search form and the
/// `metadata` of a refresh response).
///
/// `provenance` (plan t23 §2.4) carries the five [`CaeProvenance`] fields of an *obtained* catalog
/// (`source_kind` a bare `"DiarioRepublica"`/`"Mirror"` string, plus `source_url`, `artifact_digest`,
/// `retrieved_at`, `parser_version`); it is `null`/omitted for the embedded catalog and any pre-t23
/// cache, so existing `GET /v1/cae` shapes are unchanged.
#[derive(Serialize)]
pub struct CaeCatalogView {
    pub origin: CaeOrigin,
    pub schema_version: u32,
    pub generated_at: String,
    pub source_note: String,
    pub digest: String,
    pub counts: CaeCounts,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provenance: Option<CaeProvenance>,
}

impl From<&chancela_cae::CaeMetadata> for CaeCatalogView {
    fn from(m: &chancela_cae::CaeMetadata) -> Self {
        CaeCatalogView {
            origin: m.origin,
            schema_version: m.schema_version,
            generated_at: m.generated_at.clone(),
            source_note: m.source_note.clone(),
            digest: m.digest.clone(),
            counts: m.counts,
            provenance: m.provenance.clone(),
        }
    }
}

/// One source's failure while walking the refresh chain (§cae-v2), surfaced on the `502` body and
/// (for transparency) on a successful multi-source refresh.
#[derive(Serialize)]
pub struct CaeSourceFailureView {
    /// The source's label (its URL, or "Diário da República (fonte oficial)").
    pub source: String,
    /// The rendered fetch/parse/integrity/fidelity error.
    pub error: String,
}

/// Response of `POST /v1/cae/refresh`.
#[derive(Serialize)]
pub struct CaeRefreshView {
    pub updated: bool,
    pub metadata: CaeCatalogView,
    pub note: String,
    /// The label of the source that superseded, or `null` when nothing was newer (up to date) or on
    /// the legacy single-source path.
    pub source: Option<String>,
    /// Per-source failures collected while walking the chain (empty on a clean run and on the legacy
    /// single-source path).
    pub failures: Vec<CaeSourceFailureView>,
}

/// One current official CAE version as INE SMI publishes it — the `version` code (`V#####`) and its
/// full Portuguese designation. Element of [`CaeUpdatesView`].
#[derive(Serialize)]
pub struct CaeVersionView {
    /// The SMI version code, e.g. `"V05497"`.
    pub version: String,
    /// The full designation INE stamps on that version.
    pub designation: String,
}

/// Response of `GET /v1/cae/updates` (frozen shape, §cae-v2): the current official CAE Rev.3 / Rev.4
/// versions INE currently publishes, plus when the signal was checked. An update-availability signal
/// to compare against the embedded catalog — not the catalog itself.
#[derive(Serialize)]
pub struct CaeUpdatesView {
    /// The current official CAE Rev.3 version.
    pub rev3: CaeVersionView,
    /// The current official CAE Rev.4 version.
    pub rev4: CaeVersionView,
    /// When this signal was fetched (RFC-3339 UTC).
    pub checked_at: String,
}

// --- Queries ------------------------------------------------------------------------------

/// Query for `GET /v1/cae/{code}`: an optional revision pin.
#[derive(Deserialize)]
pub struct CaeLookupQuery {
    pub revision: Option<CaeRevision>,
}

/// Query for `GET /v1/cae`: search text, an optional revision filter, and a result cap.
#[derive(Deserialize)]
pub struct CaeListQuery {
    pub search: Option<String>,
    pub revision: Option<CaeRevision>,
    pub limit: Option<usize>,
}

/// Query for `GET /v1/cae/sections` and `GET /v1/cae/{code}/children`: an optional revision
/// (defaulting to Rev.4, matching the lookup precedence).
#[derive(Deserialize)]
pub struct CaeRevisionQuery {
    pub revision: Option<CaeRevision>,
}

/// Query for `POST /v1/cae/refresh`: an optional `source` pin — `official`, `mirror`, or a 0-based
/// index into the resolved chain — selecting a subset of the source chain to run.
#[derive(Deserialize)]
pub struct CaeRefreshQuery {
    pub source: Option<String>,
}

/// Default and maximum number of search hits returned by `GET /v1/cae?search=`.
const DEFAULT_SEARCH_LIMIT: usize = 50;
const MAX_SEARCH_LIMIT: usize = 500;

/// wp14 Phase 4: TTL for the optional `GET /v1/cae` catalog-metadata cache-aside entry. Short — the
/// catalog rarely changes and every supersede explicitly invalidates the key, so the TTL is only a
/// safety net against a missed invalidation.
const CAE_CATALOG_CACHE_TTL_SECS: u64 = 300;

// --- Handlers -----------------------------------------------------------------------------

/// `GET /v1/cae/{code}` `?revision=Rev3|Rev4` — resolve a code to its designation, level,
/// revision, and hierarchy. Unknown code → `404`. With no `revision`, Rev.4 is tried first, then
/// Rev.3 (the returned entry reports which matched).
pub async fn get_cae(
    State(state): State<AppState>,
    Path(code): Path<String>,
    actor: CurrentActor,
    Query(query): Query<CaeLookupQuery>,
) -> Result<Json<CaeEntryView>, ApiError> {
    // RBAC (t64-E3): the CAE reference is `cae.read` at Global.
    require_permission(&state, &actor, Permission::CaeRead, Scope::Global).await?;
    let cae = state.cae.read().await;
    let entry = cae
        .lookup(&code, query.revision)
        .ok_or(ApiError::NotFound)?;
    let hierarchy = cae
        .hierarchy(&entry.code, entry.revision)
        .into_iter()
        .map(CaeNodeView::from)
        .collect();
    Ok(Json(CaeEntryView::with_hierarchy(entry, hierarchy)))
}

/// `GET /v1/cae` `?search=&revision=&limit=` — with `search`, an accent-folded list of matching
/// nodes (no hierarchy); without it, the active catalog's metadata ([`CaeCatalogView`]).
pub async fn list_cae(
    State(state): State<AppState>,
    actor: CurrentActor,
    Query(query): Query<CaeListQuery>,
) -> Response {
    // RBAC (t64-E3): the CAE reference is `cae.read` at Global.
    if let Err(e) = require_permission(&state, &actor, Permission::CaeRead, Scope::Global).await {
        return e.into_response();
    }
    let cae = state.cae.read().await;
    match query.search.as_deref().map(str::trim) {
        Some(search) if !search.is_empty() => {
            let limit = query
                .limit
                .unwrap_or(DEFAULT_SEARCH_LIMIT)
                .min(MAX_SEARCH_LIMIT);
            let hits: Vec<CaeEntryView> = cae
                .search(search, query.revision, limit)
                .into_iter()
                .map(CaeEntryView::node)
                .collect();
            Json(hits).into_response()
        }
        _ => {
            // wp14 Phase 4: cache-aside on the (rarely-mutated) catalog metadata projection. Serve
            // cached JSON bytes on a hit; on a miss, serialize, populate with a short TTL, and return.
            // Fail-open + inert unless Redis is configured (default NullCache ⇒ this is a plain
            // compute-and-return). Invalidated on a catalog supersede (see `finish_chain_refresh`).
            let cache_key = crate::cache::CacheKey::CaeCatalog;
            if let Some(bytes) = state.cache.get(&cache_key) {
                return crate::cache::json_bytes_response(bytes);
            }
            match serde_json::to_vec(&CaeCatalogView::from(cae.metadata())) {
                Ok(bytes) => {
                    state.cache.set(
                        &cache_key,
                        &bytes,
                        std::time::Duration::from_secs(CAE_CATALOG_CACHE_TTL_SECS),
                    );
                    crate::cache::json_bytes_response(bytes)
                }
                Err(_) => Json(CaeCatalogView::from(cae.metadata())).into_response(),
            }
        }
    }
}

/// `GET /v1/cae/sections` `?revision=Rev3|Rev4` — the top-level secções of a revision (the roots of
/// the Ferramentas classification tree). Defaults to Rev.4. Frozen shape (§cae-v2): a list of
/// [`CaeNodeView`] (`code`, `designation`, `level`, `revision`).
pub async fn list_sections(
    State(state): State<AppState>,
    actor: CurrentActor,
    Query(query): Query<CaeRevisionQuery>,
) -> Result<Json<Vec<CaeNodeView>>, ApiError> {
    // RBAC (t64-E3): the CAE reference is `cae.read` at Global.
    require_permission(&state, &actor, Permission::CaeRead, Scope::Global).await?;
    let cae = state.cae.read().await;
    let revision = query.revision.unwrap_or(CaeRevision::Rev4);
    // Secções are exactly the single-letter top-level codes (A..V in Rev.4, A..U in Rev.3); walk the
    // alphabet and collect those present, in canonical order — no full-catalog scan needed.
    let sections = (b'A'..=b'Z')
        .filter_map(|letter| cae.lookup(&(letter as char).to_string(), Some(revision)))
        .filter(|e| e.level == CaeLevel::Seccao)
        .map(CaeNodeView::from)
        .collect();
    Ok(Json(sections))
}

/// `GET /v1/cae/{code}/children` `?revision=Rev3|Rev4` — the direct children of a code within a
/// revision (the lazy down-drill of the Ferramentas tree). Defaults to Rev.4. An unknown code is a
/// `404`; a known leaf legitimately returns `[]`. Frozen shape (§cae-v2): a list of [`CaeNodeView`].
pub async fn list_children(
    State(state): State<AppState>,
    Path(code): Path<String>,
    actor: CurrentActor,
    Query(query): Query<CaeRevisionQuery>,
) -> Result<Json<Vec<CaeNodeView>>, ApiError> {
    // RBAC (t64-E3): the CAE reference is `cae.read` at Global.
    require_permission(&state, &actor, Permission::CaeRead, Scope::Global).await?;
    let cae = state.cae.read().await;
    let revision = query.revision.unwrap_or(CaeRevision::Rev4);
    // 404 only when the code itself is unknown in this revision; a known leaf has [] children.
    if cae.lookup(&code, Some(revision)).is_none() {
        return Err(ApiError::NotFound);
    }
    let children = cae
        .children(&code, revision)
        .into_iter()
        .map(CaeNodeView::from)
        .collect();
    Ok(Json(children))
}

/// `POST /v1/cae/refresh` `?source=official|mirror|<index>` — refresh the CAE catalog from a
/// configured source, and — if it supersedes the active catalog — swap the in-memory catalog, write
/// the cache, and append a `cae.updated` event (§cae-v2, plan t23 §2.7).
///
/// **Two source tiers.** The new **strict chain** = the built-in official Diário da República pair
/// (when `catalog.cae_official_source`) followed by each `catalog.cae_sources` entry, in order; every
/// entry runs the full pipeline including the exact-count **fidelity gate**, so only a complete
/// both-revision dataset can win (the reliability spine — a partial/mirror artifact is rejected). The
/// legacy single mirror URL — `catalog.cae_update_url` then `CHANCELA_CAE_URL` — retains its original
/// t19-e1b **integrity-only** semantics and is the **final fallback**, used only when the strict
/// chain is empty (nothing new configured), so an existing single-URL config keeps working unchanged.
///
/// `?source` pins the strict chain: `official`/`mirror` keep only those entries, an index keeps one;
/// with a `?source` pin the legacy fallback is never taken.
///
/// **Outcomes** (per t23-e1a's HTTP table): a superseding source → `200 {updated: true}` + swap +
/// event; every source valid-but-up-to-date → `200 {updated: false}`; every strict source failed →
/// `502` with the per-source `failures`; nothing configured → a friendly, settings-aware `422`.
///
/// An injected [`CaeSource`](chancela_cae::CaeSource) (the legacy DI seam) still runs the original
/// single-envelope path unchanged, for backward compatibility.
pub async fn refresh_cae(
    State(state): State<AppState>,
    Query(query): Query<CaeRefreshQuery>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
) -> Result<Response, ApiError> {
    // RBAC (t64-E3): forcing a CAE refresh is `cae.refresh` at Global.
    require_permission(&state, &actor, Permission::CaeRefresh, Scope::Global).await?;
    let data_dir = state.data_dir();

    // Legacy injected single-source seam (back-compat): an injected `CaeSource` runs the original
    // envelope refresh unchanged. Production leaves this `None`.
    if let Some(source) = state.cae_source.clone() {
        return legacy_refresh(state, actor, attestor, source, data_dir).await;
    }

    // Resolve the strict, fidelity-gated chain in the async context: the injected test factory, else
    // the official pair + `cae_sources` from settings.
    let has_pin = query
        .source
        .as_deref()
        .map(str::trim)
        .is_some_and(|s| !s.is_empty());
    let chain = match &state.cae_chain_factory {
        Some(factory) => factory(),
        None => {
            let catalog = state.settings.read().await.catalog.clone();
            build_strict_chain(&catalog)
        }
    };
    let chain = select_source(chain, query.source.as_deref())?;

    if chain.is_empty() {
        // A `?source` pin that matched nothing is the one case that still refuses — a default is
        // impossible for a pin (e.g. `?source=mirror` with no mirrors configured) → friendly 422.
        if has_pin {
            return Err(unconfigured_error(query.source.as_deref()));
        }
        // No pin: prefer the legacy single mirror URL (settings `cae_update_url`, then
        // `CHANCELA_CAE_URL`) when configured; otherwise, with *nothing* configured, default to the
        // built-in official chain ordered by `preferred_official_source` (§catalog-v3) — INE-first by
        // default, with the Diário da República pair always present as the source that actually
        // fulfils the refresh. Offline the default chain fails its fetch → 502 with the failures list.
        let catalog = state.settings.read().await.catalog.clone();
        let env_url = std::env::var(ENV_CAE_URL).ok();
        return match resolve_cae_update_url(catalog.cae_update_url.clone(), env_url) {
            Some(url) => {
                legacy_refresh(
                    state,
                    actor,
                    attestor,
                    Arc::new(HttpCaeSource::new(url)),
                    data_dir,
                )
                .await
            }
            None => {
                let default_chain = match &state.cae_default_chain_factory {
                    Some(factory) => factory(),
                    None => official_chain_for(catalog.preferred_official_source),
                };
                run_chain(state, actor, attestor, default_chain, data_dir).await
            }
        };
    }

    run_chain(state, actor, attestor, chain, data_dir).await
}

/// Run a resolved CAE source chain off the async runtime and map its [`ChainOutcome`] to the HTTP
/// response. The (blocking) chain runs on a dedicated OS thread awaited over a oneshot, so each
/// source's blocking `reqwest` client is built and dropped clear of the async runtime — mirrors
/// `registry::consult`. `obtain_from_chain` is infallible (it never destroys the known-good catalog).
async fn run_chain(
    state: AppState,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    chain: CaeSourceChain,
    data_dir: Option<PathBuf>,
) -> Result<Response, ApiError> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("cae-refresh".to_owned())
        .spawn(move || {
            let _ = tx.send(obtain_from_chain(&chain, data_dir.as_deref()));
        })
        .map_err(|e| ApiError::Internal(format!("failed to spawn cae refresh thread: {e}")))?;
    let outcome = rx
        .await
        .map_err(|_| ApiError::Internal("cae refresh thread ended unexpectedly".to_owned()))?;

    finish_chain_refresh(state, actor, attestor, outcome).await
}

/// `GET /v1/cae/updates` — the INE SMI **update-availability signal** (§cae-v2). Fetches and parses
/// the SMI version catalog off the async runtime (a short-lived blocking `reqwest`, like the refresh
/// path) and returns the current official CAE Rev.3 / Rev.4 version codes + designations INE
/// publishes, plus a `checked_at` timestamp. This is *not* the catalog itself (the SMI code tree is
/// not obtainable non-interactively — see [`chancela_cae::SmiSource`]); it is a signal the operator
/// compares against the embedded dataset from the Ferramentas panel. Not cached.
///
/// SMI unreachable / unparseable, or a catalog missing either current CAE revision, is a `502`.
pub async fn cae_updates(
    State(state): State<AppState>,
    actor: CurrentActor,
) -> Result<Json<CaeUpdatesView>, ApiError> {
    // RBAC (t64-E3): the CAE update signal is `cae.read` at Global.
    require_permission(&state, &actor, Permission::CaeRead, Scope::Global).await?;
    // Point at the test fixture server when injected, else the official INE SMI host.
    let source = match &state.smi_base_override {
        Some(base) => SmiSource::with_base_url(base.as_str()),
        None => SmiSource::official(),
    };

    // Fetch off-runtime (blocking reqwest), mirroring the refresh path's dedicated-thread pattern.
    let (tx, rx) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("cae-updates".to_owned())
        .spawn(move || {
            let _ = tx.send(source.fetch_catalog());
        })
        .map_err(|e| ApiError::Internal(format!("failed to spawn cae updates thread: {e}")))?;
    let catalog = rx
        .await
        .map_err(|_| ApiError::Internal("cae updates thread ended unexpectedly".to_owned()))??;

    // Both current CAE revisions must be present; a catalog missing either is an unusable signal (502).
    let versions = catalog.cae_versions().ok_or_else(|| {
        ApiError::Upstream(
            "o catálogo de versões do INE SMI não indica ambas as revisões CAE (Rev.3 e Rev.4) \
             atuais"
                .to_owned(),
        )
    })?;

    Ok(Json(CaeUpdatesView {
        rev3: CaeVersionView {
            version: versions.rev3.code.clone(),
            designation: versions.rev3.designation.clone(),
        },
        rev4: CaeVersionView {
            version: versions.rev4.code.clone(),
            designation: versions.rev4.designation.clone(),
        },
        checked_at: OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_default(),
    }))
}

/// Map a [`ChainOutcome`] to the HTTP response, swapping the catalog + appending a `cae.updated`
/// event only on a real supersede (write-through), and rendering the per-source failures on `502`.
async fn finish_chain_refresh(
    state: AppState,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    outcome: ChainOutcome,
) -> Result<Response, ApiError> {
    let ChainOutcome {
        catalog,
        refresh,
        winner,
        any_valid,
        failures,
    } = outcome;
    let metadata = CaeCatalogView::from(&refresh.metadata);
    let failures_view: Vec<CaeSourceFailureView> = failures
        .iter()
        .map(|f| CaeSourceFailureView {
            source: f.entry.clone(),
            error: f.error.clone(),
        })
        .collect();

    if let Some(winner) = winner {
        // A source superseded: swap the live catalog, then attribute the update in the ledger with
        // the obtain's provenance (mechanism + artifact digest) recorded on the event.
        *state.cae.write().await = catalog;
        // wp14 Phase 4: the catalog changed → drop the cached `GET /v1/cae` metadata projection so
        // the next read repopulates from the new catalog (no-op for the default NullCache).
        state.cache.invalidate(&crate::cache::CacheKey::CaeCatalog);
        let actor = actor.resolve("api");
        let payload = serde_json::to_vec(&json!({
            "digest": metadata.digest,
            "generated_at": metadata.generated_at,
            "origin": metadata.origin,
            "source": winner,
            "provenance": metadata.provenance,
        }))?;
        let mut ledger = state.ledger.write().await;
        ledger.append(
            &actor,
            "cae",
            "cae.updated",
            Some("cae catalog updated"),
            &payload,
        );
        // Persist the audit event; the catalog itself is durable via its `cae-catalog.json` cache.
        state
            .persist_write_through(&mut ledger, 1, |_tx| Ok(()))
            .await?;
        state.attest_latest(&attestor, &ledger).await;
        drop(ledger);
        return Ok(Json(CaeRefreshView {
            updated: true,
            metadata,
            note: refresh.note,
            source: Some(winner),
            failures: failures_view,
        })
        .into_response());
    }

    if any_valid {
        // Every source obtained is up to date; the known-good catalog is retained.
        return Ok(Json(CaeRefreshView {
            updated: false,
            metadata,
            note: refresh.note,
            source: None,
            failures: failures_view,
        })
        .into_response());
    }

    // Every configured source failed: 502 with the per-source failures, catalog untouched.
    let body = json!({
        "error": "todas as fontes de atualização do catálogo CAE falharam",
        "note": refresh.note,
        "failures": failures
            .iter()
            .map(|f| json!({ "source": f.entry, "error": f.error }))
            .collect::<Vec<_>>(),
    });
    Ok((StatusCode::BAD_GATEWAY, Json(body)).into_response())
}

/// The legacy single-source refresh path: an injected [`CaeSource`](chancela_cae::CaeSource) runs
/// the original envelope [`refresh`] unchanged (back-compat for the pre-chain DI seam + tests).
async fn legacy_refresh(
    state: AppState,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    source: Arc<dyn CaeSource>,
    data_dir: Option<PathBuf>,
) -> Result<Response, ApiError> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("cae-refresh".to_owned())
        .spawn(move || {
            let _ = tx.send(refresh(source.as_ref(), data_dir.as_deref()));
        })
        .map_err(|e| ApiError::Internal(format!("failed to spawn cae refresh thread: {e}")))?;
    let (catalog, outcome) = rx
        .await
        .map_err(|_| ApiError::Internal("cae refresh thread ended unexpectedly".to_owned()))??;

    let metadata = CaeCatalogView::from(&outcome.metadata);
    if outcome.updated {
        *state.cae.write().await = catalog;
        // wp14 Phase 4: invalidate the cached catalog-metadata projection on a supersede (see above).
        state.cache.invalidate(&crate::cache::CacheKey::CaeCatalog);
        let actor = actor.resolve("api");
        let payload = serde_json::to_vec(&json!({
            "digest": metadata.digest,
            "generated_at": metadata.generated_at,
            "origin": metadata.origin,
        }))?;
        let mut ledger = state.ledger.write().await;
        ledger.append(
            &actor,
            "cae",
            "cae.updated",
            Some("cae catalog updated"),
            &payload,
        );
        state
            .persist_write_through(&mut ledger, 1, |_tx| Ok(()))
            .await?;
        state.attest_latest(&attestor, &ledger).await;
    }
    Ok(Json(CaeRefreshView {
        updated: outcome.updated,
        metadata,
        note: outcome.note,
        source: None,
        failures: Vec::new(),
    })
    .into_response())
}

/// Build the strict, fidelity-gated CAE source chain from settings (§cae-v2/§catalog-v3, plan t23
/// §2.7): the optional official source(s) — expanded per `preferred_official_source` via
/// [`official_chain_for`] (INE-first by default, DR always present) — then each `cae_sources` entry
/// (with its declared format + optional digest pin), in order. The legacy
/// `cae_update_url`/`CHANCELA_CAE_URL` are NOT part of this chain — they are the integrity-only
/// fallback handled by [`refresh_cae`] when this chain is empty.
fn build_strict_chain(catalog: &CatalogSettings) -> CaeSourceChain {
    let mut entries: Vec<ChainEntry> = Vec::new();
    if catalog.cae_official_source {
        entries.extend(official_chain_for(catalog.preferred_official_source).0);
    }
    for src in &catalog.cae_sources {
        let mut mirror = MirrorArtifactSource::from_url(src.url.clone(), src.format);
        if let Some(digest) = src
            .digest
            .as_deref()
            .map(str::trim)
            .filter(|d| !d.is_empty())
        {
            mirror = mirror.with_digest(digest.to_owned());
        }
        entries.push(ChainEntry::Mirror(mirror));
    }
    CaeSourceChain::new(entries)
}

/// Resolve the legacy single mirror URL for the fallback path: settings `cae_update_url` takes
/// precedence over `CHANCELA_CAE_URL`, and a blank value at either layer is treated as unset (so a
/// blank setting still falls through to the env var). `None` means neither is configured.
fn resolve_cae_update_url(settings_url: Option<String>, env_url: Option<String>) -> Option<String> {
    non_empty(settings_url).or_else(|| non_empty(env_url))
}

/// Apply a `?source` pin to a resolved chain: `official`/`mirror` keep only those entries, a numeric
/// index keeps the one entry at that position, absent keeps the whole chain. An unparseable selector
/// is a `422`.
///
/// `official` keeps the built-in official government sources — both the Diário da República pair and
/// the INE entry (§catalog-v3) — so it honours the operator's `preferred_official_source` ordering; a
/// mirror is excluded.
fn select_source(chain: CaeSourceChain, source: Option<&str>) -> Result<CaeSourceChain, ApiError> {
    let Some(sel) = source.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(chain);
    };
    let entries = chain.0;
    let filtered: Vec<ChainEntry> = match sel {
        "official" => entries
            .into_iter()
            .filter(|e| matches!(e, ChainEntry::Official(_) | ChainEntry::Ine(_)))
            .collect(),
        "mirror" => entries
            .into_iter()
            .filter(|e| matches!(e, ChainEntry::Mirror(_)))
            .collect(),
        other => match other.parse::<usize>() {
            Ok(i) => entries.into_iter().nth(i).into_iter().collect(),
            Err(_) => {
                return Err(ApiError::Unprocessable(format!(
                    "parâmetro 'source' inválido: {other:?} (use 'official', 'mirror', ou um índice)"
                )));
            }
        },
    };
    Ok(CaeSourceChain::new(filtered))
}

/// The friendly, settings-aware `422` for a refresh with no runnable source: either a `?source` pin
/// that matched nothing, or nothing configured at all (matching t19-e1b's copy, which the e2e/web
/// error surface keys on "Configurações").
fn unconfigured_error(source: Option<&str>) -> ApiError {
    match source.map(str::trim).filter(|s| !s.is_empty()) {
        Some(sel) => ApiError::Unprocessable(format!(
            "a fonte pedida ({sel}) não está configurada em Configurações (Documentos → Catálogo \
             CAE)."
        )),
        None => ApiError::Unprocessable(
            "URL de atualização do catálogo não configurado — defina-o em Configurações \
             (Documentos → Catálogo CAE) ou na variável de ambiente CHANCELA_CAE_URL."
                .to_owned(),
        ),
    }
}

/// Trim an optional URL, treating a blank value as unset.
fn non_empty(url: Option<String>) -> Option<String> {
    url.map(|u| u.trim().to_owned()).filter(|u| !u.is_empty())
}

// --- Registry-view enrichment -------------------------------------------------------------

/// Wire view of a role-tagged CAE reference on a registry extract, enriched from the catalog
/// (contract §2.7). `designation`/`level`/`revision` are `null` when the code is not catalogued —
/// a certidão may carry a withdrawn or mistyped code.
#[derive(Serialize)]
pub struct CaeRefView {
    pub code: String,
    pub role: chancela_registry::CaeRole,
    pub designation: Option<String>,
    pub level: Option<CaeLevel>,
    pub revision: Option<CaeRevision>,
}

/// Enrich one [`chancela_registry::CaeRef`] against the catalog (Rev.4 first, then Rev.3).
pub(crate) fn enrich_cae_ref(r: &chancela_registry::CaeRef, cae: &CaeCatalog) -> CaeRefView {
    match cae.lookup(&r.code, None) {
        Some(e) => CaeRefView {
            code: r.code.clone(),
            role: r.role,
            designation: Some(e.designation.clone()),
            level: Some(e.level),
            revision: Some(e.revision),
        },
        None => CaeRefView {
            code: r.code.clone(),
            role: r.role,
            designation: None,
            level: None,
            revision: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::CaeSourceEntry;
    use chancela_cae::{CaeSourceFormat, PreferredOfficialSource};

    fn entry(url: &str) -> CaeSourceEntry {
        CaeSourceEntry {
            url: url.to_owned(),
            format: CaeSourceFormat::Auto,
            digest: None,
        }
    }

    fn labels(chain: &CaeSourceChain) -> Vec<String> {
        chain.0.iter().map(|e| e.label()).collect()
    }

    const OFFICIAL: &str = "Diário da República (fonte oficial)";
    const INE: &str = "INE (fonte oficial)";

    #[test]
    fn strict_chain_orders_official_then_sources() {
        // With DR preferred, the official prepend is the DR pair alone, before the sources.
        // cae_update_url is NOT part of the strict chain (it is the legacy fallback).
        let catalog = CatalogSettings {
            cae_update_url: Some("https://fallback.example/cae.json".to_owned()),
            cae_sources: vec![
                entry("https://a.example/cae.json"),
                entry("https://b.example/cae.json"),
            ],
            cae_official_source: true,
            preferred_official_source: PreferredOfficialSource::DiarioRepublica,
        };
        assert_eq!(
            labels(&build_strict_chain(&catalog)),
            vec![
                OFFICIAL,
                "https://a.example/cae.json",
                "https://b.example/cae.json",
            ]
        );
    }

    #[test]
    fn strict_chain_ine_first_expands_the_official_pair_by_default() {
        // The default preference is INE (§catalog-v3, "default is ine"): the official prepend expands
        // to [INE, DR] before the sources. INE fails at runtime (no bulk artifact) and DR fulfils.
        let catalog = CatalogSettings {
            cae_sources: vec![entry("https://a.example/cae.json")],
            cae_official_source: true,
            ..CatalogSettings::default()
        };
        assert_eq!(
            catalog.preferred_official_source,
            PreferredOfficialSource::Ine,
            "default preference is INE"
        );
        assert_eq!(
            labels(&build_strict_chain(&catalog)),
            vec![INE, OFFICIAL, "https://a.example/cae.json"]
        );
    }

    #[test]
    fn strict_chain_skips_the_official_entry_when_off() {
        let catalog = CatalogSettings {
            cae_sources: vec![entry("https://only.example/cae.json")],
            cae_official_source: false,
            ..CatalogSettings::default()
        };
        assert_eq!(
            labels(&build_strict_chain(&catalog)),
            vec!["https://only.example/cae.json"]
        );
    }

    #[test]
    fn strict_chain_empty_when_no_official_and_no_sources() {
        // Only a legacy cae_update_url configured → the strict chain is empty (the fallback runs).
        let catalog = CatalogSettings {
            cae_update_url: Some("https://fallback.example/cae.json".to_owned()),
            ..CatalogSettings::default()
        };
        assert!(build_strict_chain(&catalog).is_empty());
        assert!(build_strict_chain(&CatalogSettings::default()).is_empty());
    }

    #[test]
    fn select_official_keeps_the_built_in_official_sources() {
        // `?source=official` keeps the built-in government sources (INE + DR, in preference order),
        // dropping the mirror — so it honours `preferred_official_source` (default INE-first here).
        let catalog = CatalogSettings {
            cae_official_source: true,
            cae_sources: vec![entry("https://m.example/cae.json")],
            ..CatalogSettings::default()
        };
        let chain =
            select_source(build_strict_chain(&catalog), Some("official")).expect("valid selector");
        assert_eq!(labels(&chain), vec![INE, OFFICIAL]);
    }

    #[test]
    fn select_official_with_dr_preference_is_dr_only() {
        let catalog = CatalogSettings {
            cae_official_source: true,
            cae_sources: vec![entry("https://m.example/cae.json")],
            preferred_official_source: PreferredOfficialSource::DiarioRepublica,
            ..CatalogSettings::default()
        };
        let chain =
            select_source(build_strict_chain(&catalog), Some("official")).expect("valid selector");
        assert_eq!(labels(&chain), vec![OFFICIAL]);
    }

    #[test]
    fn select_mirror_keeps_only_mirror_entries() {
        let catalog = CatalogSettings {
            cae_official_source: true,
            cae_sources: vec![entry("https://m.example/cae.json")],
            ..CatalogSettings::default()
        };
        let chain =
            select_source(build_strict_chain(&catalog), Some("mirror")).expect("valid selector");
        assert_eq!(labels(&chain), vec!["https://m.example/cae.json"]);
    }

    #[test]
    fn select_by_index_picks_one_entry() {
        let catalog = CatalogSettings {
            cae_sources: vec![
                entry("https://a.example/cae.json"),
                entry("https://b.example/cae.json"),
            ],
            ..CatalogSettings::default()
        };
        let chain = select_source(build_strict_chain(&catalog), Some("1")).expect("valid index");
        assert_eq!(labels(&chain), vec!["https://b.example/cae.json"]);
    }

    #[test]
    fn select_absent_keeps_the_whole_chain() {
        let catalog = CatalogSettings {
            cae_sources: vec![entry("https://a.example/cae.json")],
            ..CatalogSettings::default()
        };
        let chain = select_source(build_strict_chain(&catalog), None).expect("no selector is ok");
        assert_eq!(labels(&chain), vec!["https://a.example/cae.json"]);
    }

    #[test]
    fn select_bad_selector_is_422() {
        let chain = build_strict_chain(&CatalogSettings::default());
        match select_source(chain, Some("bogus")) {
            Err(ApiError::Unprocessable(_)) => {}
            other => panic!(
                "bad selector must be a 422, got Ok/other: {:?}",
                other.is_ok()
            ),
        }
    }

    #[test]
    fn legacy_fallback_url_prefers_settings_over_env_and_trims_blanks() {
        // The legacy single-URL fallback resolver: settings wins over env; blanks are unset.
        assert_eq!(
            resolve_cae_update_url(
                Some("https://settings.example/cae.json".to_owned()),
                Some("https://env.example/cae.json".to_owned())
            )
            .as_deref(),
            Some("https://settings.example/cae.json")
        );
        assert_eq!(
            resolve_cae_update_url(
                Some("   ".to_owned()),
                Some("https://env.example/cae.json".to_owned())
            )
            .as_deref(),
            Some("https://env.example/cae.json")
        );
        assert_eq!(resolve_cae_update_url(None, None), None);
        assert_eq!(
            resolve_cae_update_url(Some("  ".to_owned()), Some(String::new())),
            None
        );
    }
}
