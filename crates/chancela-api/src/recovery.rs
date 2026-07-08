//! Chain-integrity **recovery** endpoints (t54-E3, plan §2.9): the queryable integrity report and
//! the two authorized recovery primitives — whole-store **restore** (verify-before-swap, primary,
//! never rewrites history) and last-resort **re-anchor** (rebuild the hashes in place, permanently
//! disclosed via a chained `ledger.reanchored`). Both stay reachable while the instance is in the
//! degraded read-only state (a broken chain is exactly when you need them); both recompute the
//! [`degraded`](crate::AppState::degraded) signal so a repaired chain lifts the gate.
//!
//! ## Frozen DTOs (for E4 web)
//!
//! - `GET /v1/ledger/integrity` → [`IntegrityReportView`] (per-chain status + precise first break +
//!   permanent re-anchor disclosure + the live `degraded` flag).
//! - `POST /v1/ledger/recovery/reanchor` `{ reason, actor? }` → [`ReanchorResponse`]
//!   (`{ record, integrity }`). `422` empty reason; `409` when the chain already verifies (nothing
//!   to repair); `422` in-memory (no durable store to persist the rebuild into).
//! - `POST /v1/ledger/recovery/restore` `{ archive }` → [`RestoreOutcomeView`]. `archive` is an
//!   absolute path or a bare name resolved under `<data_dir>/backups/`. A backup that does not
//!   verify BEFORE the swap is refused with `422` and the live store is untouched.

use axum::Json;
use axum::extract::State;
use chancela_ledger::{ChainBreak, ChainStatus, IntegrityReport, ReanchorError, ReanchorRecord};
use chancela_store::StoreError;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::AppState;
use crate::actor::CurrentActor;
use crate::error::ApiError;
use crate::hex::hex;

// =================================================================================================
// Integrity report views (shared: also used by the reanchor response and the bundles import verdict)
// =================================================================================================

/// Wire view of a [`ChainBreak`] (the precise first break in a chain): hex digests + string ids, per
/// the api's no-raw-core-types discipline. Shared with the import-quarantine verdict (`bundles`).
#[derive(Debug, Clone, Serialize)]
pub(crate) struct ChainBreakView {
    pub chain: String,
    pub kind: String,
    pub global_seq: Option<u64>,
    pub chain_seq: Option<u64>,
    pub event_id: Option<String>,
    pub expected_hash: Option<String>,
    pub actual_hash: Option<String>,
    pub message: String,
}

impl From<&ChainBreak> for ChainBreakView {
    fn from(b: &ChainBreak) -> Self {
        ChainBreakView {
            chain: b.chain.to_string(),
            kind: format!("{:?}", b.kind),
            global_seq: b.global_seq,
            chain_seq: b.chain_seq,
            event_id: b.event_id.map(|e| e.0.to_string()),
            expected_hash: b.expected_hash.as_ref().map(hex),
            actual_hash: b.actual_hash.as_ref().map(hex),
            message: b.message.clone(),
        }
    }
}

/// Wire view of a per-chain [`ChainStatus`].
#[derive(Debug, Clone, Serialize)]
pub(crate) struct ChainStatusView {
    pub chain: String,
    pub genesis_kind: Option<String>,
    pub length: u64,
    pub head: Option<String>,
    pub verified: bool,
    pub first_break: Option<ChainBreakView>,
}

impl From<&ChainStatus> for ChainStatusView {
    fn from(s: &ChainStatus) -> Self {
        ChainStatusView {
            chain: s.chain.to_string(),
            genesis_kind: s.genesis_kind.clone(),
            length: s.length,
            head: s.head.as_ref().map(hex),
            verified: s.verified,
            first_break: s.first_break.as_ref().map(ChainBreakView::from),
        }
    }
}

/// Wire view of one [`ReanchorRecord`] — the permanent re-anchor disclosure derived from the audit
/// chain. Digests to hex; the caller-supplied `at` renders RFC 3339.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct ReanchorRecordView {
    pub actor: String,
    pub at: String,
    pub reason: String,
    pub affected: Vec<ReanchorSegmentView>,
    pub original_global_head: Option<String>,
    pub new_global_head: String,
    pub pre_reanchor_digest: String,
}

/// Wire view of one rebuilt chain range within a [`ReanchorRecordView`].
#[derive(Debug, Clone, Serialize)]
pub(crate) struct ReanchorSegmentView {
    pub chain: String,
    pub from_chain_seq: u64,
    pub to_chain_seq: u64,
}

impl From<&ReanchorRecord> for ReanchorRecordView {
    fn from(r: &ReanchorRecord) -> Self {
        ReanchorRecordView {
            actor: r.actor.clone(),
            at: r.at.format(&Rfc3339).unwrap_or_default(),
            reason: r.reason.clone(),
            affected: r
                .affected
                .iter()
                .map(|s| ReanchorSegmentView {
                    chain: s.chain.to_string(),
                    from_chain_seq: s.from_chain_seq,
                    to_chain_seq: s.to_chain_seq,
                })
                .collect(),
            original_global_head: r.original_global_head.as_ref().map(hex),
            new_global_head: hex(&r.new_global_head),
            pre_reanchor_digest: hex(&r.pre_reanchor_digest),
        }
    }
}

/// Wire view of a whole-ledger [`IntegrityReport`] (t54 deliverable #1): the global spine + every
/// non-global chain's status (each with its precise first break), the overall `healthy` flag, the
/// live `degraded` (read-only) signal, and the permanent re-anchor disclosure.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct IntegrityReportView {
    pub healthy: bool,
    pub degraded: bool,
    pub global: ChainStatusView,
    pub chains: Vec<ChainStatusView>,
    pub reanchored_segments: Vec<ReanchorRecordView>,
}

impl IntegrityReportView {
    /// Build the view from a live [`IntegrityReport`] plus the current degraded signal.
    pub(crate) fn build(report: &IntegrityReport, degraded: bool) -> Self {
        IntegrityReportView {
            healthy: report.healthy,
            degraded,
            global: ChainStatusView::from(&report.global),
            chains: report.chains.iter().map(ChainStatusView::from).collect(),
            reanchored_segments: report
                .reanchored_segments
                .iter()
                .map(ReanchorRecordView::from)
                .collect(),
        }
    }
}

/// Compute the live integrity view from the in-memory (authoritative) ledger + the degraded flag.
async fn current_integrity(state: &AppState) -> IntegrityReportView {
    let report = state.ledger.read().await.integrity_report();
    let degraded = *state.degraded.read().await;
    IntegrityReportView::build(&report, degraded)
}

// =================================================================================================
// GET /v1/ledger/integrity
// =================================================================================================

/// `GET /v1/ledger/integrity` — the full [`IntegrityReportView`] (per-chain status + first break +
/// re-anchor disclosure). Read-only, always available (degraded or not, in-memory or persistent).
pub async fn get_integrity(State(state): State<AppState>) -> Json<IntegrityReportView> {
    Json(current_integrity(&state).await)
}

// =================================================================================================
// POST /v1/ledger/recovery/reanchor
// =================================================================================================

/// Body of `POST /v1/ledger/recovery/reanchor`.
#[derive(Deserialize)]
pub struct ReanchorRequest {
    /// The required, non-empty human reason for this last-resort operation (recorded permanently).
    pub reason: String,
    /// Optional request actor fallback; the session user takes precedence.
    #[serde(default = "default_actor")]
    pub actor: String,
}

fn default_actor() -> String {
    "api".to_owned()
}

/// Response of a successful re-anchor: the permanent disclosure record + the fresh integrity report.
#[derive(Serialize)]
pub struct ReanchorResponse {
    pub record: ReanchorRecordView,
    pub integrity: IntegrityReportView,
}

/// `POST /v1/ledger/recovery/reanchor` — last-resort rebuild of the chain hashes in place (§2.2).
///
/// Requires a non-empty `reason`; refuses (`409`) when the chain already verifies (nothing to
/// repair). Calls [`Ledger::reanchor`] then durably persists the rebuilt chain via
/// [`Store::persist_reanchored_ledger`](chancela_store::Store::persist_reanchored_ledger), and
/// recomputes the degraded signal (a repaired chain lifts the read-only gate). Reachable while
/// degraded (this IS the repair). The re-anchor is disclosed by a chained `ledger.reanchored` event
/// that cannot be silently removed — it is not a laundering bypass.
pub async fn reanchor_ledger(
    State(state): State<AppState>,
    actor: CurrentActor,
    Json(req): Json<ReanchorRequest>,
) -> Result<Json<ReanchorResponse>, ApiError> {
    let actor = actor.resolve(&req.actor);
    // Re-anchor rebuilds the DURABLE chain; refuse in-memory (nothing to persist the rebuild into).
    let Some(store) = state.store.clone() else {
        return Err(ApiError::Unprocessable(
            "re-ancoragem requer persistência em disco".to_owned(),
        ));
    };

    let mut ledger = state.ledger.write().await;
    let at = OffsetDateTime::now_utc();
    let record = ledger
        .reanchor(&actor, &req.reason, at)
        .map_err(map_reanchor_error)?;
    store
        .persist_reanchored_ledger(&ledger)
        .map_err(|e| ApiError::Internal(format!("failed to persist the re-anchored chain: {e}")))?;

    crate::refresh_degraded(&state, &ledger).await;
    let degraded = *state.degraded.read().await;
    let integrity = IntegrityReportView::build(&ledger.integrity_report(), degraded);
    Ok(Json(ReanchorResponse {
        record: ReanchorRecordView::from(&record),
        integrity,
    }))
}

/// Map a [`ReanchorError`] to its HTTP status: already-valid ⇒ `409` (nothing to repair); empty
/// reason ⇒ `422`; a post-rebuild verification failure ⇒ `500` (should never happen).
fn map_reanchor_error(e: ReanchorError) -> ApiError {
    match e {
        ReanchorError::AlreadyValid => ApiError::Conflict(
            "a cadeia já verifica; re-ancoragem desnecessária (nada a reparar)".to_owned(),
        ),
        ReanchorError::EmptyReason => {
            ApiError::Unprocessable("a re-ancoragem exige um motivo não vazio".to_owned())
        }
        ReanchorError::VerificationFailed(inner) => {
            ApiError::Internal(format!("re-anchor left the chain unverifiable: {inner}"))
        }
    }
}

// =================================================================================================
// POST /v1/ledger/recovery/restore
// =================================================================================================

/// Body of `POST /v1/ledger/recovery/restore`.
#[derive(Deserialize)]
pub struct RestoreRequest {
    /// The backup archive to restore from: an absolute path, or a bare file name resolved under
    /// `<data_dir>/backups/`.
    pub archive: String,
    #[serde(default = "default_actor")]
    pub actor: String,
}

/// Response of a successful whole-store restore.
#[derive(Serialize)]
pub struct RestoreOutcomeView {
    pub restored_from: String,
    pub ledger_length: u64,
    pub ledger_head: Option<String>,
    pub chain_verified: bool,
    pub integrity: IntegrityReportView,
}

/// `POST /v1/ledger/recovery/restore` — whole-store restore from a full backup (§2.5), verify-
/// before-swap. Never rewrites history: it verifies every member digest AND that the snapshot's
/// ledger verifies `Ok` BEFORE an atomic db swap; a bad backup is refused (`422`) and the live store
/// is left untouched. Records a chained `ledger.restored`, reloads the domain read-models into
/// memory, and recomputes the degraded signal. Reachable while degraded.
pub async fn restore_store(
    State(state): State<AppState>,
    actor: CurrentActor,
    Json(req): Json<RestoreRequest>,
) -> Result<Json<RestoreOutcomeView>, ApiError> {
    let actor = actor.resolve(&req.actor);
    let Some(store) = state.store.clone() else {
        return Err(ApiError::Unprocessable(
            "restauro requer persistência em disco".to_owned(),
        ));
    };
    let data_dir = state
        .data_dir()
        .ok_or_else(|| ApiError::Internal("durable store without a data directory".to_owned()))?;

    // Resolve the archive: an existing path as-is, else a bare name under <data_dir>/backups/.
    let raw = std::path::PathBuf::from(&req.archive);
    let archive = if raw.exists() {
        raw
    } else {
        data_dir.join("backups").join(&req.archive)
    };
    if !archive.exists() {
        return Err(ApiError::NotFound);
    }

    let outcome = {
        let mut ledger = state.ledger.write().await;
        let at = OffsetDateTime::now_utc();
        let outcome = store
            .restore(&mut ledger, &archive, &data_dir, &actor, at)
            .map_err(map_store_error)?;
        crate::refresh_degraded(&state, &ledger).await;
        outcome
    };

    // The swap replaced the whole DB; refresh the in-memory read-models so reads reflect it.
    state.reload_domain_memory().await?;

    let integrity = current_integrity(&state).await;
    Ok(Json(RestoreOutcomeView {
        restored_from: outcome.restored_from.to_string_lossy().into_owned(),
        ledger_length: outcome.ledger_length,
        ledger_head: outcome.ledger_head,
        chain_verified: outcome.chain_verified,
        integrity,
    }))
}

/// Map a recovery [`StoreError`] to its HTTP status (shared by restore/import/reset/start-over).
pub(crate) fn map_store_error(e: StoreError) -> ApiError {
    match e {
        StoreError::NotPersistent => {
            ApiError::Unprocessable("operação requer persistência em disco".to_owned())
        }
        StoreError::BadBackup(msg) => {
            ApiError::Unprocessable(format!("cópia de segurança inválida: {msg}"))
        }
        StoreError::InvalidBundle(msg) => {
            ApiError::Unprocessable(format!("pacote inválido: {msg}"))
        }
        StoreError::ImportCollision { book_id } => ApiError::Conflict(format!(
            "importação recusada: o livro {book_id} já existe (política de colisão = Refuse)"
        )),
        StoreError::NotFound(msg) => {
            eprintln!("chancela-api recovery not-found: {msg}");
            ApiError::NotFound
        }
        other => ApiError::Internal(format!("recovery store error: {other}")),
    }
}
