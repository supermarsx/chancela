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
//! - `POST /v1/books/import/preflight?policy=refuse|quarantine_copy` — body is the raw bundle
//!   `.zip` bytes. Runs the same read-only bundle verification/collision analysis available before
//!   import and returns a no-mutation preview with no `import_id`.
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
use chancela_store::StoreError;
use chancela_store::recovery::{CollisionPolicy, ImportPreflight, ImportVerdict};
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

/// Non-mutating preview of `POST /v1/books/import`; intentionally omits `import_id`.
#[derive(Serialize)]
pub struct ImportPreflightView {
    pub ok: bool,
    pub ready: bool,
    pub would_import: bool,
    pub would_record_ledger_event: bool,
    pub would_store_import_record: bool,
    pub policy: String,
    pub entity_id: Option<String>,
    pub book_id: Option<String>,
    pub verdict: Option<ImportVerdictView>,
    pub source_instance_id: Option<String>,
    pub bundle_digest: Option<String>,
    pub collided: bool,
    pub manifest_file_count: Option<usize>,
    pub manifest_total_bytes: Option<u64>,
    pub zip_member_count: Option<usize>,
    pub event_count: Option<usize>,
    pub book_chain_verified: Option<bool>,
    pub book_chain_length: Option<u64>,
    pub signature_present: Option<bool>,
    pub errors: Vec<String>,
    pub findings: Vec<String>,
    pub next_step: String,
}

/// `POST /v1/books/import/preflight` — read-only per-book bundle import preview. It receives the
/// same raw `.zip` body and collision policy as the mutating import, runs the same manifest
/// self-digest, member sha256, book-chain verification, optional signature-field inspection, and
/// current collision lookup available before confirmation, and returns operator-review evidence.
///
/// It does not stage a durable import, append `ledger.imported`, write `imported_books`, merge live
/// books/entities/acts/documents, or change trust state. A later confirmation can still fail if the
/// store changes concurrently or persistence fails.
pub async fn preflight_import_book(
    State(state): State<AppState>,
    Query(q): Query<ImportQuery>,
    actor: CurrentActor,
    body: axum::body::Bytes,
) -> Result<Json<ImportPreflightView>, ApiError> {
    require_permission(&state, &actor, Permission::BookImport, Scope::Global).await?;
    let policy = parse_policy(q.policy.as_deref())?;
    let Some(store) = state.store.clone() else {
        return Err(ApiError::Unprocessable(
            "pré-validação de importação requer persistência em disco".to_owned(),
        ));
    };
    if body.is_empty() {
        return Err(ApiError::Unprocessable("corpo do pacote vazio".to_owned()));
    }
    if body.len() > BOOK_IMPORT_BUNDLE_MAX_BYTES {
        return Err(ApiError::Unprocessable(format!(
            "pacote do livro tem {} bytes; o limite é {BOOK_IMPORT_BUNDLE_MAX_BYTES} bytes",
            body.len()
        )));
    }

    match store.preflight_import_book_bytes(&body, policy) {
        Ok(preflight) => Ok(Json(import_preflight_view(preflight))),
        Err(StoreError::InvalidBundle(msg)) => Ok(Json(invalid_import_preflight_view(policy, msg))),
        Err(e) => Err(map_store_error(e)),
    }
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

    Ok(Json(ImportOutcomeView {
        import_id: outcome.import_id,
        entity_id: outcome.entity_id,
        book_id: outcome.book_id,
        verdict: import_verdict_view(&outcome.verdict),
        source_instance_id: outcome.source_instance_id,
        bundle_digest: outcome.bundle_digest,
        collided: outcome.collided,
    }))
}

fn import_verdict_view(verdict: &ImportVerdict) -> ImportVerdictView {
    match verdict {
        ImportVerdict::Verified => ImportVerdictView {
            status: "Verified".to_owned(),
            break_: None,
        },
        ImportVerdict::Quarantined { break_ } => ImportVerdictView {
            status: "Quarantined".to_owned(),
            break_: Some(ChainBreakView::from(break_)),
        },
    }
}

fn import_policy_code(policy: CollisionPolicy) -> &'static str {
    match policy {
        CollisionPolicy::Refuse => "refuse",
        CollisionPolicy::QuarantineCopy => "quarantine_copy",
    }
}

fn import_preflight_view(preflight: ImportPreflight) -> ImportPreflightView {
    let verdict = import_verdict_view(&preflight.verdict);
    let mut errors = Vec::new();
    let mut findings = Vec::new();
    let mut ready = matches!(preflight.verdict, ImportVerdict::Verified);
    let book_chain_verified = matches!(preflight.verdict, ImportVerdict::Verified);

    if let ImportVerdict::Quarantined { break_ } = &preflight.verdict {
        ready = false;
        errors.push(format!(
            "bundle would be quarantined by import verification: {}",
            break_.message
        ));
    }
    if preflight.collided {
        if matches!(preflight.policy, CollisionPolicy::Refuse) {
            ready = false;
            errors.push(format!(
                "book id {} already exists and policy=refuse would block the import",
                preflight.book_id
            ));
        } else {
            findings.push(
                "book id already exists; policy=quarantine_copy would keep an isolated read-only copy under the original ids".to_owned(),
            );
        }
    }

    findings.push(
        "Preview checked the manifest self-digest, manifest-listed member sha256 values, events.jsonl book-chain verification, optional signature field presence, and current id collision state.".to_owned(),
    );
    if preflight.signature_present {
        findings.push(
            "Bundle carries an exporter signature field, but current v1 import confirmation does not perform additional exporter-signature validation beyond existing bundle digest/member/chain checks.".to_owned(),
        );
    } else {
        findings.push(
            "No exporter signature is present; current v1 confirmation relies on existing bundle digest/member/chain checks.".to_owned(),
        );
    }
    findings.push(
        "Preflight did not append ledger.imported, store an imported_books record, merge live records, or change trust state.".to_owned(),
    );
    findings.push(
        "Operator-safety preview only: not legal archive certification, not production signed-import validation beyond existing checks, and not DGLAB/legal acceptance.".to_owned(),
    );

    let next_step = if ready {
        "review this preview and explicitly confirm the mutating import; confirmation can still fail if a concurrent change creates a collision or persistence fails".to_owned()
    } else if preflight.collided && matches!(preflight.policy, CollisionPolicy::Refuse) {
        "choose a different bundle or switch to quarantine_copy if an isolated read-only copy is intended, then run preflight again".to_owned()
    } else {
        "choose another bundle and run preflight again; this preview is not ready for confirmation"
            .to_owned()
    };

    ImportPreflightView {
        ok: ready,
        ready,
        would_import: ready,
        would_record_ledger_event: false,
        would_store_import_record: false,
        policy: import_policy_code(preflight.policy).to_owned(),
        entity_id: Some(preflight.entity_id),
        book_id: Some(preflight.book_id),
        verdict: Some(verdict),
        source_instance_id: Some(preflight.source_instance_id),
        bundle_digest: Some(preflight.bundle_digest),
        collided: preflight.collided,
        manifest_file_count: Some(preflight.manifest_file_count),
        manifest_total_bytes: Some(preflight.manifest_total_bytes),
        zip_member_count: Some(preflight.zip_member_count),
        event_count: preflight.event_count,
        book_chain_verified: Some(book_chain_verified),
        book_chain_length: Some(preflight.book_chain.length),
        signature_present: Some(preflight.signature_present),
        errors,
        findings,
        next_step,
    }
}

fn invalid_import_preflight_view(policy: CollisionPolicy, message: String) -> ImportPreflightView {
    ImportPreflightView {
        ok: false,
        ready: false,
        would_import: false,
        would_record_ledger_event: false,
        would_store_import_record: false,
        policy: import_policy_code(policy).to_owned(),
        entity_id: None,
        book_id: None,
        verdict: None,
        source_instance_id: None,
        bundle_digest: None,
        collided: false,
        manifest_file_count: None,
        manifest_total_bytes: None,
        zip_member_count: None,
        event_count: None,
        book_chain_verified: None,
        book_chain_length: None,
        signature_present: None,
        errors: vec![format!("invalid bundle: {message}")],
        findings: vec![
            "Preflight did not append ledger.imported, store an imported_books record, merge live records, or change trust state.".to_owned(),
            "Operator-safety preview only: not legal archive certification, not production signed-import validation beyond existing checks, and not DGLAB/legal acceptance.".to_owned(),
        ],
        next_step: "choose a readable chancela-book-bundle/v1 zip and run preflight again".to_owned(),
    }
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
            let new_book_for_store = new_book.clone();
            let stored_for_store = made.stored.clone();
            state
                .persist_write_through(&mut ledger, 2, move |tx| {
                    tx.upsert_book(&new_book_for_store)?;
                    tx.upsert_document(&stored_for_store)
                })
                .await?;
            state
                .documents
                .write()
                .await
                .insert(made.stored.act_id, made.stored.clone());
        }
        None => {
            let new_book_for_store = new_book.clone();
            state
                .persist_write_through(&mut ledger, 1, move |tx| {
                    tx.upsert_book(&new_book_for_store)
                })
                .await?;
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
