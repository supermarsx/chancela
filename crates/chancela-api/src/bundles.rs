//! Per-book **portability + lifecycle** endpoints (t54-E3, plan §2.9): export a self-verifying
//! `chancela-book-bundle/v1`, import one (verify-before-trust → Verified | Quarantined), and
//! per-book **start-over** (archive-then-fresh). Every op is auditable and non-destructive to the
//! archive; export is retained under `<data_dir>/exports/`.
//!
//! ## Frozen DTOs (for E4 web)
//!
//! - `POST /v1/books/{id}/export` → the bundle `.zip` bytes (`application/zip`, `attachment`
//!   disposition; the retained path + digest ride in `X-Chancela-Export-Path` /
//!   `X-Chancela-Bundle-Digest` headers). `422` in-memory.
//! - `POST /v1/books/import?policy=refuse|quarantine_copy` — body is the raw bundle `.zip` bytes.
//!   `policy` defaults to `refuse`. → [`ImportOutcomeView`] (`verdict.status` = `"Verified"` or
//!   `"Quarantined"` with the `break`). A verified bundle's book id colliding under `refuse` ⇒ `409`.
//! - `POST /v1/books/{id}/start-over` `{ reason, purpose, opening_date, required_signatories,
//!   numbering_scheme? }` → [`StartOverBookResponse`] (`{ reinit, new_book }`): archives the current
//!   book (retained + chained `ledger.exported`), records `ledger.reinitialized`, and opens the fresh
//!   successor book (a new `book.opened` genesis). The old book's events stay append-only.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderName, StatusCode, header};
use axum::response::{IntoResponse, Response};
use chancela_core::{BookId, TermoDeAbertura, open_and_seal_book};
use chancela_store::recovery::{CollisionPolicy, ImportVerdict};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use chancela_authz::{Permission, Scope};

use crate::AppState;
use crate::actor::{CurrentActor, CurrentAttestor};
use crate::authz::{require_permission, scope_of_book};
use crate::dto::{BookView, TermoSignatoryInput, normalize_termo_signatories, parse_date};
use crate::error::ApiError;
use crate::recovery::{ChainBreakView, map_store_error};

pub(crate) const BOOK_IMPORT_BUNDLE_MAX_BYTES: usize = 64 * 1024 * 1024;

fn default_actor() -> String {
    "api".to_owned()
}

fn default_numbering() -> chancela_core::NumberingScheme {
    chancela_core::NumberingScheme::Sequential
}

// =================================================================================================
// POST /v1/books/{id}/export
// =================================================================================================

/// `POST /v1/books/{id}/export` — export one book to a self-verifying `chancela-book-bundle/v1`
/// `.zip`, retain it under `<data_dir>/exports/`, emit a chained `ledger.exported`, and stream the
/// bytes for download. No secrets ever enter a bundle (store-enforced). `422` in-memory.
pub async fn export_book(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
) -> Result<Response, ApiError> {
    // RBAC (t64-E3): exporting a book is `book.export` scoped to the book.
    require_permission(
        &state,
        &actor,
        Permission::BookExport,
        scope_of_book(BookId(id)),
    )
    .await?;
    let actor = actor.resolve("api");
    let Some(store) = state.store.clone() else {
        return Err(ApiError::Unprocessable(
            "exportação requer persistência em disco".to_owned(),
        ));
    };
    let data_dir = state
        .data_dir()
        .ok_or_else(|| ApiError::Internal("durable store without a data directory".to_owned()))?;

    let outcome = {
        let mut ledger = state.ledger.write().await;
        let at = OffsetDateTime::now_utc();
        store
            .export_book(&mut ledger, BookId(id), &data_dir, &actor, at)
            .map_err(map_store_error)?
    };

    let filename = format!("book-{id}.zip");
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/zip".to_owned()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{filename}\""),
            ),
            (
                HeaderName::from_static("x-chancela-bundle-digest"),
                outcome.manifest.bundle_digest.clone(),
            ),
            (
                HeaderName::from_static("x-chancela-export-path"),
                outcome.path.to_string_lossy().into_owned(),
            ),
        ],
        outcome.bytes,
    )
        .into_response())
}

// =================================================================================================
// POST /v1/books/import
// =================================================================================================

/// Query for `POST /v1/books/import`: the collision policy (default `refuse`).
#[derive(Deserialize)]
pub struct ImportQuery {
    #[serde(default)]
    pub policy: Option<String>,
}

/// Wire view of an [`ImportVerdict`]: `status` is `"Verified"` or `"Quarantined"`, with `break`
/// carrying the precise first break (or the tamper detail) when quarantined.
#[derive(Serialize)]
pub struct ImportVerdictView {
    pub status: String,
    #[serde(rename = "break", skip_serializing_if = "Option::is_none")]
    pub break_: Option<ChainBreakView>,
}

/// Response of `POST /v1/books/import` (verdict + provenance; never any secret material).
#[derive(Serialize)]
pub struct ImportOutcomeView {
    pub import_id: String,
    pub entity_id: String,
    pub book_id: String,
    pub verdict: ImportVerdictView,
    pub source_instance_id: String,
    pub bundle_digest: String,
    pub collided: bool,
}

/// `POST /v1/books/import` — import a per-book bundle with **verify-before-trust** (§2.5). The body
/// is the raw bundle `.zip` bytes. Verifies the manifest self-digest, every member's sha256, and the
/// book chain BEFORE trusting: a clean bundle ⇒ `Verified`, any break/tamper ⇒ `Quarantined`
/// (isolated, read-only, under ORIGINAL ids, never merged onto the live spine). A verified bundle's
/// id colliding under `Refuse` (default) ⇒ `409`; `QuarantineCopy` keeps the isolated copy. Emits a
/// chained `ledger.imported`. Reachable while degraded (a quarantine-import never joins a live chain).
pub async fn import_book(
    State(state): State<AppState>,
    Query(q): Query<ImportQuery>,
    actor: CurrentActor,
    body: axum::body::Bytes,
) -> Result<Json<ImportOutcomeView>, ApiError> {
    // RBAC (t64-E3): importing a book bundle requires `book.import` at Global (the target entity is
    // only known after verifying the bundle, and a fresh-id import creates a new spine; gating at
    // Global is the safe, non-under-restricting choice per §3.3 "Entity(target) or Global if new").
    require_permission(&state, &actor, Permission::BookImport, Scope::Global).await?;
    let actor = actor.resolve("api");
    let policy = parse_policy(q.policy.as_deref())?;
    let Some(store) = state.store.clone() else {
        return Err(ApiError::Unprocessable(
            "importação requer persistência em disco".to_owned(),
        ));
    };
    let data_dir = state
        .data_dir()
        .ok_or_else(|| ApiError::Internal("durable store without a data directory".to_owned()))?;
    if body.is_empty() {
        return Err(ApiError::Unprocessable("corpo do pacote vazio".to_owned()));
    }
    if body.len() > BOOK_IMPORT_BUNDLE_MAX_BYTES {
        return Err(ApiError::Unprocessable(format!(
            "pacote do livro tem {} bytes; o limite é {BOOK_IMPORT_BUNDLE_MAX_BYTES} bytes",
            body.len()
        )));
    }

    // Land the uploaded bytes in a temp file the store reads from (it retains its own copy in the
    // imported_books table), then best-effort remove it.
    let incoming = data_dir.join("imports");
    std::fs::create_dir_all(&incoming)
        .map_err(|e| ApiError::Internal(format!("failed to stage the upload: {e}")))?;
    let tmp = incoming.join(format!("incoming-{}.zip", Uuid::new_v4()));
    std::fs::write(&tmp, &body)
        .map_err(|e| ApiError::Internal(format!("failed to stage the upload: {e}")))?;

    let outcome = {
        let mut ledger = state.ledger.write().await;
        let at = OffsetDateTime::now_utc();
        store.import_book(&mut ledger, &tmp, policy, &actor, at)
    };
    let _ = std::fs::remove_file(&tmp);
    let outcome = outcome.map_err(map_store_error)?;

    let verdict = match &outcome.verdict {
        ImportVerdict::Verified => ImportVerdictView {
            status: "Verified".to_owned(),
            break_: None,
        },
        ImportVerdict::Quarantined { break_ } => ImportVerdictView {
            status: "Quarantined".to_owned(),
            break_: Some(ChainBreakView::from(break_)),
        },
    };
    Ok(Json(ImportOutcomeView {
        import_id: outcome.import_id,
        entity_id: outcome.entity_id,
        book_id: outcome.book_id,
        verdict,
        source_instance_id: outcome.source_instance_id,
        bundle_digest: outcome.bundle_digest,
        collided: outcome.collided,
    }))
}

/// Parse the collision policy query value (default `Refuse`); an unrecognized value is a `422`.
fn parse_policy(raw: Option<&str>) -> Result<CollisionPolicy, ApiError> {
    match raw.map(str::trim) {
        None | Some("") | Some("refuse") | Some("Refuse") => Ok(CollisionPolicy::Refuse),
        Some("quarantine_copy") | Some("quarantine") | Some("QuarantineCopy") => {
            Ok(CollisionPolicy::QuarantineCopy)
        }
        Some(other) => Err(ApiError::Unprocessable(format!(
            "política de colisão desconhecida {other:?} (use refuse | quarantine_copy)"
        ))),
    }
}

// =================================================================================================
// POST /v1/books/{id}/start-over
// =================================================================================================

/// Body of `POST /v1/books/{id}/start-over` — the reason plus the termo de abertura fields for the
/// fresh successor book the endpoint opens.
#[derive(Deserialize)]
pub struct StartOverBookRequest {
    pub reason: String,
    pub purpose: String,
    #[serde(default = "default_numbering")]
    pub numbering_scheme: chancela_core::NumberingScheme,
    pub opening_date: String,
    pub required_signatories: Vec<TermoSignatoryInput>,
    #[serde(default = "default_actor")]
    pub actor: String,
}

/// Wire view of the start-over reinit record.
#[derive(Serialize)]
pub struct ReinitView {
    pub scope: String,
    pub archive_path: String,
    pub archived_bundle_digest: String,
    pub old_book_id: Option<String>,
    pub new_book_id: Option<String>,
}

/// Response of `POST /v1/books/{id}/start-over`.
#[derive(Serialize)]
pub struct StartOverBookResponse {
    pub reinit: ReinitView,
    pub new_book: BookView,
}

/// `POST /v1/books/{id}/start-over` — per-book archive-then-fresh (§2.7). Archives the current book
/// (retained + chained `ledger.exported`), records `ledger.reinitialized`, then opens a fresh
/// successor book (a new `book.opened` genesis) for future atas. The old book's events stay
/// append-only — nothing is erased. `422` in-memory. Blocked with `503` while degraded (it is a
/// forward-writing lifecycle op, not a repair — the recovery endpoints are the repair path).
pub async fn start_over_book(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<StartOverBookRequest>,
) -> Result<Json<StartOverBookResponse>, ApiError> {
    // RBAC (t64-E3): per-book start-over is `book.start_over` scoped to the book.
    require_permission(
        &state,
        &actor,
        Permission::BookStartOver,
        scope_of_book(BookId(id)),
    )
    .await?;
    let StartOverBookRequest {
        reason,
        purpose,
        numbering_scheme,
        opening_date,
        required_signatories,
        actor: req_actor,
    } = req;
    // Fail fast on a bad date before any lock or archive.
    let opening_date = parse_date(&opening_date)?;
    let required_signatory_records =
        normalize_termo_signatories(required_signatories, "required_signatories")?;
    let required_signatories = required_signatory_records
        .iter()
        .map(chancela_core::book::TermoSignatory::legacy_label)
        .collect();
    let actor = actor.resolve(&req_actor);
    let old_book_id = BookId(id);

    let Some(store) = state.store.clone() else {
        return Err(ApiError::Unprocessable(
            "recomeçar um livro requer persistência em disco".to_owned(),
        ));
    };
    let data_dir = state
        .data_dir()
        .ok_or_else(|| ApiError::Internal("durable store without a data directory".to_owned()))?;

    // entities → books → ledger (canonical order; entities read for the termo snapshot).
    let entities = state.entities.read().await;
    let mut books = state.books.write().await;
    let mut ledger = state.ledger.write().await;

    let old_book = books.get(&old_book_id).ok_or(ApiError::NotFound)?;
    let entity = entities
        .get(&old_book.entity_id)
        .ok_or(ApiError::NotFound)?;

    let at = OffsetDateTime::now_utc();
    // 1. Archive-then-fresh: export (retained + ledger.exported) + ledger.reinitialized + a fresh
    //    successor SHELL (Created state, new id) persisted by the store.
    let reinit = store
        .start_over_book(&mut ledger, old_book_id, &reason, &actor, at, &data_dir)
        .map_err(map_store_error)?;
    let new_book_id = reinit
        .new_book_id
        .as_deref()
        .and_then(|s| Uuid::parse_str(s).ok())
        .map(BookId)
        .ok_or_else(|| ApiError::Internal("start-over did not return a successor id".to_owned()))?;

    // 2. Materialize the successor shell from the store and OPEN it (book.opened genesis).
    let mut new_book = store
        .load()
        .map_err(|e| ApiError::Internal(format!("failed to load the successor book: {e}")))?
        .books
        .remove(&new_book_id)
        .ok_or_else(|| {
            ApiError::Internal("successor book shell not found in the store".to_owned())
        })?;

    let termo = TermoDeAbertura {
        entity_name: entity.name.clone(),
        entity_nipc: entity.nipc.to_string(),
        entity_seat: entity.seat.clone(),
        purpose,
        numbering_scheme,
        opening_date,
        required_signatories,
        required_signatory_records,
    };
    // Appends the `book.opened` genesis of the successor chain (fresh chain, always opens cleanly).
    open_and_seal_book(&mut new_book, entity, termo, &actor, &mut ledger)?;

    // 3. Termo de abertura document + persist, mirroring `books::create_book`'s transaction
    //    discipline (a render/write failure rolls the genesis event back so a failed open leaves no
    //    trace; a family without a termo template gets the genesis event alone).
    let termo_ref = new_book
        .termo_abertura
        .as_ref()
        .expect("termo present immediately after open");
    let generated = match crate::documents::generate_for_termo(termo_ref, &new_book, entity.family)
    {
        Ok(g) => g,
        Err(e) => {
            AppState::rollback_ledger_events(&mut ledger, 1);
            return Err(e);
        }
    };
    match generated {
        Some(made) => {
            let scope = format!("entity:{}/book:{}", new_book.entity_id, new_book.id);
            let payload = serde_json::to_vec(&made.event_payload)?;
            crate::try_append_event(
                &mut ledger,
                &actor,
                &scope,
                "document.generated",
                None,
                &payload,
            )?;
            state.persist_write_through(&mut ledger, 2, |tx| {
                tx.upsert_book(&new_book)?;
                tx.upsert_document(&made.stored)
            })?;
            state
                .documents
                .write()
                .await
                .insert(made.stored.act_id, made.stored.clone());
        }
        None => {
            state.persist_write_through(&mut ledger, 1, |tx| tx.upsert_book(&new_book))?;
        }
    }
    state.attest_latest(&attestor, &ledger).await;

    let view = BookView::from(&new_book);
    books.insert(new_book.id, new_book);

    Ok(Json(StartOverBookResponse {
        reinit: ReinitView {
            scope: format!("{:?}", reinit.scope),
            archive_path: reinit.archive_path.to_string_lossy().into_owned(),
            archived_bundle_digest: reinit.archived_bundle_digest,
            old_book_id: reinit.old_book_id,
            new_book_id: reinit.new_book_id,
        },
        new_book: view,
    }))
}
