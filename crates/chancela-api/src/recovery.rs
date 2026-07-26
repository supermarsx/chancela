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
//! - `POST /v1/ledger/recovery/reanchor` `{ reason, reauth, actor? }` → [`ReanchorResponse`]
//!   (`{ record, integrity }`). Requires **step-up re-auth** (the acting user's password OR a
//!   recovery phrase — for a credentialed user a valid session alone is `403`; a legacy no-hash user
//!   with no recovery phrase is satisfied by their self session, see
//!   [`require_step_up`](crate::data::require_step_up)), mirroring the destructive wipes: re-anchor
//!   rebuilds the chain hashes and is the most evidence-sensitive op. `422` empty reason; `409` when
//!   the chain already verifies (nothing to repair); `422` in-memory (no durable store to persist
//!   the rebuild into).
//! - `POST /v1/ledger/recovery/restore` `{ archive, passphrase?, reauth, actor? }` →
//!   [`RestoreOutcomeView`]. `archive` is an absolute path or a bare name resolved under
//!   `<data_dir>/backups/`. Also requires **step-up re-auth**, on the same terms as the re-anchor
//!   above (t22) — a restore replaces every book and the ledger. A backup that does not verify
//!   BEFORE the swap is refused with `422` and the live store is untouched.
//! - `POST /v1/ledger/recovery/restore/preflight` `{ archive, passphrase? }` →
//!   [`RestorePreflightOutcomeView`]. Same archive/key mode as restore, but read-only: no DB swap,
//!   no sidecar staging, no `ledger.restored`, no reload — and therefore **no step-up**, which
//!   would otherwise make the safe way to inspect a backup harder than the destructive one.

use axum::Json;
use axum::extract::State;
use chancela_ledger::{ChainBreak, ChainStatus, IntegrityReport, ReanchorError, ReanchorRecord};
use chancela_store::recovery::{RestorePreflightManifestEvidence, RestorePreflightOutcome};
use chancela_store::{Store, StoreError};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use chancela_authz::{Permission, Scope};

use crate::AppState;
use crate::actor::CurrentActor;
use crate::authz::require_permission;
use crate::data::{ReAuth, require_step_up};
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
pub async fn get_integrity(
    State(state): State<AppState>,
    actor: CurrentActor,
) -> Result<Json<IntegrityReportView>, ApiError> {
    // RBAC (t64-E3): the integrity report is `ledger.read` at Global.
    require_permission(&state, &actor, Permission::LedgerRead, Scope::Global).await?;
    Ok(Json(current_integrity(&state).await))
}

// =================================================================================================
// POST /v1/ledger/recovery/reanchor
// =================================================================================================

/// Body of `POST /v1/ledger/recovery/reanchor`.
#[derive(Deserialize)]
pub struct ReanchorRequest {
    /// The required, non-empty human reason for this last-resort operation (recorded permanently).
    pub reason: String,
    /// Step-up re-auth proof (mirrors the destructive wipes) — required; a valid session alone is
    /// NOT enough.
    #[serde(default)]
    pub reauth: ReAuth,
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
///
/// Gated by **step-up re-auth** (the acting user's password OR a valid recovery phrase) exactly like
/// the destructive wipes (`/v1/data/reset`, `/v1/data/start-over`): a valid session alone is refused
/// with `403`. Re-anchor rebuilds the chain hashes in place, so it carries the same second-factor bar
/// as a destructive wipe.
pub async fn reanchor_ledger(
    State(state): State<AppState>,
    actor: CurrentActor,
    Json(req): Json<ReanchorRequest>,
) -> Result<Json<ReanchorResponse>, ApiError> {
    // RBAC (t64-E3, re-gated t27): re-anchoring the chain requires the granular `ledger.reanchor`
    // at Global (split off the broad `ledger.recover`) — AND the existing step-up re-auth
    // (RBAC = who-may, step-up = confirm-now; both are kept).
    require_permission(&state, &actor, Permission::LedgerReanchor, Scope::Global).await?;
    // Step-up re-auth — a valid session alone is NOT enough (mirrors the destructive wipes).
    require_step_up(&state, &actor, &req.reauth).await?;
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
    // The in-memory `reanchor` above is worker-safe, but the durable write drives postgres (and a
    // `postgres::Client` `Drop`) that must not run on an async worker (wp28). Move the owned ledger
    // into the blocking closure (read-only there) and restore it afterwards; the write guard is held.
    let owned_ledger = std::mem::take(&mut *ledger);
    let (owned_ledger, persisted) = store
        .read_blocking_async(move |s| {
            let persisted = s.persist_reanchored_ledger(&owned_ledger);
            (owned_ledger, persisted)
        })
        .await;
    *ledger = owned_ledger;
    persisted.map_err(|e| {
        AppState::map_store_write_error("failed to persist the re-anchored chain", e)
    })?;

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
    /// Optional passphrase for encrypted `.cbackup` envelopes. Omit for legacy plaintext zips.
    pub passphrase: Option<String>,
    /// Step-up re-auth proof (§8-F) — required by the **executing** restore, ignored by the
    /// read-only preflight. The archive passphrase above proves nothing about the operator: it
    /// travels with the backup file, so anyone holding the file holds it.
    #[serde(default)]
    pub reauth: ReAuth,
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

/// Response of a non-mutating restore preflight.
#[derive(Serialize)]
pub struct RestorePreflightOutcomeView {
    pub ok: bool,
    pub ready: bool,
    pub encrypted: Option<bool>,
    pub archive: String,
    pub manifest: Option<RestorePreflightManifestView>,
    pub ledger_verified: bool,
    pub findings: Vec<String>,
    pub errors: Vec<String>,
    pub next_step: String,
}

/// Secret-free manifest evidence for the recovery UI.
#[derive(Serialize)]
pub struct RestorePreflightManifestView {
    pub path: String,
    pub schema: String,
    pub version: u32,
    pub app_version: String,
    pub store_schema_version: i64,
    pub ledger_length: u64,
    pub ledger_verified: bool,
    pub member_count: usize,
    pub sidecar_member_count: usize,
    pub db_member_present: bool,
    pub total_member_bytes: u64,
}

impl From<RestorePreflightManifestEvidence> for RestorePreflightManifestView {
    fn from(m: RestorePreflightManifestEvidence) -> Self {
        RestorePreflightManifestView {
            path: m.path,
            schema: m.schema,
            version: m.version,
            app_version: m.app_version,
            store_schema_version: m.store_schema_version,
            ledger_length: m.ledger_length,
            ledger_verified: m.ledger_verified,
            member_count: m.member_count,
            sidecar_member_count: m.sidecar_member_count,
            db_member_present: m.db_member_present,
            total_member_bytes: m.total_member_bytes,
        }
    }
}

impl From<RestorePreflightOutcome> for RestorePreflightOutcomeView {
    fn from(o: RestorePreflightOutcome) -> Self {
        RestorePreflightOutcomeView {
            ok: o.ok,
            ready: o.ready,
            encrypted: o.encrypted,
            archive: o.archive.to_string_lossy().into_owned(),
            manifest: o.manifest.map(RestorePreflightManifestView::from),
            ledger_verified: o.ledger_verified,
            findings: o.findings,
            errors: o.errors,
            next_step: o.next_step,
        }
    }
}

/// `POST /v1/ledger/recovery/restore/preflight` — read-only verification of a full backup before
/// restore. Uses the same archive/passphrase mode and (re-gated t27) `ledger.restore` gate as
/// execution restore, but never swaps the live DB, stages sidecars, appends restore events, reloads
/// memory, or mutates API/store state.
pub async fn restore_store_preflight(
    State(state): State<AppState>,
    actor: CurrentActor,
    Json(req): Json<RestoreRequest>,
) -> Result<Json<RestorePreflightOutcomeView>, ApiError> {
    require_permission(&state, &actor, Permission::LedgerRestore, Scope::Global).await?;
    let Some(store) = state.store.clone() else {
        return Err(ApiError::Unprocessable(
            "pré-validação de restauro requer persistência em disco".to_owned(),
        ));
    };
    let data_dir = state
        .data_dir()
        .ok_or_else(|| ApiError::Internal("durable store without a data directory".to_owned()))?;
    let archive = resolve_restore_archive(&data_dir, &req.archive)?;

    // Offload the sync preflight (postgres in-memory verify + `Client` `Drop`) off the async worker
    // (wp28) — same hazard as the execution restore, even though it never swaps the live DB.
    let passphrase = req.passphrase;
    let outcome = store
        .read_blocking_async(move |s| {
            s.restore_preflight(&archive, &data_dir, passphrase.as_deref())
        })
        .await
        .map_err(map_store_error)?;
    Ok(Json(RestorePreflightOutcomeView::from(outcome)))
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
    // RBAC (t64-E3, re-gated t27): a whole-store restore requires the granular `ledger.restore` at
    // Global (split off the broad `ledger.recover`).
    require_permission(&state, &actor, Permission::LedgerRestore, Scope::Global).await?;
    // t22: and step-up, which the route map has claimed since it was written but the handler never
    // had. A restore silently replaces every book and the ledger; it is at least as destructive as
    // the re-anchor immediately above, which has required step-up all along. The t69 carve-out in
    // `require_step_up` keeps a credential-less operator from being locked out of recovery.
    require_step_up(&state, &actor, &req.reauth).await?;
    let actor = actor.resolve(&req.actor);
    let Some(store) = state.store.clone() else {
        return Err(ApiError::Unprocessable(
            "restauro requer persistência em disco".to_owned(),
        ));
    };
    let data_dir = state
        .data_dir()
        .ok_or_else(|| ApiError::Internal("durable store without a data directory".to_owned()))?;

    let archive = resolve_restore_archive(&data_dir, &req.archive)?;
    let sidecars = state.instance_sidecars()?;
    let passphrase = req.passphrase;

    // Fail-closed BEFORE swapping durable state: if the shared session authority cannot be reached,
    // abort now rather than recover into an instance whose pre-restore bearers cannot be revoked.
    // This only probes — the sessions themselves are invalidated after the swap succeeds, because a
    // restore that is refused (bad archive ⇒ 422, nothing applied) must not destroy the operator's
    // session as a side effect. Invalidating up front made "this operation was refused" and "your
    // session is dead" the same outcome, which is exactly the partial-apply leak this endpoint's
    // verify-before-swap contract promises does not happen.
    state.probe_session_authority()?;

    let coordinator = tokio::spawn(async move {
        let result = restore_store_owned(
            &state, store, data_dir, archive, sidecars, passphrase, actor,
        )
        .await;
        if let Err(error) = &result {
            eprintln!(
                "whole-store restore coordinator failed after taking ownership of the operation: \
                 {error:?}"
            );
        }
        #[cfg(test)]
        if let Some(pause) = state.destructive_operation_test_pause.as_ref() {
            pause.coordinator_settled.notify_one();
        }
        result
    });
    let outcome = coordinator.await.map_err(|error| {
        ApiError::Internal(format!(
            "whole-store restore coordinator task failed: {error}"
        ))
    })??;
    Ok(Json(outcome))
}

#[allow(clippy::too_many_arguments)]
async fn restore_store_owned(
    state: &AppState,
    store: Store,
    data_dir: std::path::PathBuf,
    archive: std::path::PathBuf,
    sidecars: Vec<std::path::PathBuf>,
    passphrase: Option<String>,
    actor: String,
) -> Result<RestoreOutcomeView, ApiError> {
    // A settings coordinator owns this gate until its durable transaction and live publication
    // both finish, even when the originating HTTP request is cancelled. Restore must retain the
    // same gate from before the destructive search fence and store swap through authoritative
    // reload/failure clearing, otherwise an older live settings snapshot can overwrite a commit
    // that landed in the replacement store.
    let settings_update_guard = state.settings_update_gate.clone().lock_owned().await;
    state
        .settings_store_commit_tracker
        .wait_until_settled()
        .await;
    crate::settings::reconcile_pending_settings_audit(state).await?;
    crate::search::prepare_destructive_change(state)
        .await
        .map_err(ApiError::Unavailable)?;
    let restore_result = {
        // The owned guard remains inside this spawned coordinator if the HTTP waiter disappears.
        let mut ledger_guard = state.ledger.clone().write_owned().await;
        let at = OffsetDateTime::now_utc();
        let mut ledger = std::mem::take(&mut *ledger_guard);
        #[cfg(test)]
        let pause = state.destructive_operation_test_pause.clone();
        let (ledger, result) = store
            .read_blocking_async(move |store| {
                #[cfg(test)]
                if let Err(error) = crate::destructive_store_operation_checkpoint(pause.as_ref()) {
                    return (ledger, Err(error));
                }
                let outcome = match passphrase.as_deref() {
                    Some(passphrase) => store.restore_encrypted_with_sidecars(
                        &mut ledger,
                        &archive,
                        &data_dir,
                        &actor,
                        at,
                        passphrase,
                        &sidecars,
                    ),
                    None => store.restore_with_sidecars(
                        &mut ledger,
                        &archive,
                        &data_dir,
                        &actor,
                        at,
                        &sidecars,
                    ),
                };
                (ledger, outcome)
            })
            .await;
        *ledger_guard = ledger;
        if result.is_ok() {
            // On the complete path the store handed back the replacement ledger (including
            // ledger.restored), so the degraded flag can be refreshed immediately. A committed
            // post-step error retains the old passed ledger and is refreshed by strict reload.
            if let Ok(_outcome) = &result {
                crate::refresh_degraded(state, &ledger_guard).await;
            }
        }
        result
    };
    let (outcome, committed_store_error) = match restore_result {
        Ok(outcome) => (Some(outcome), None),
        Err(StoreError::RestoreCommitted(detail)) => (
            None,
            Some(ApiError::Internal(format!(
                "o restauro foi aplicado, mas a reconciliação pós-restauro falhou: {detail}"
            ))),
        ),
        Err(error) => {
            crate::search::abort_destructive_change(state).await;
            return Err(map_store_error(error));
        }
    };

    // The swap landed. Both post-commit operations must be attempted: returning early after a
    // session-authority failure used to strand the destructive search fence forever. Likewise, a
    // reload failure must release the fence only after all mutable search sources have been cleared,
    // so no worker can reconstruct pre-restore text.
    let session_result = state.invalidate_all_sessions().await.map_err(|_| {
        ApiError::Unavailable(
            "o restauro foi aplicado, mas não foi possível invalidar todas as sessões; repita o \
             restauro quando a autoridade de sessões estiver disponível"
                .to_owned(),
        )
    });
    let reload_result = state
        .reload_domain_memory_with_settings_gate_held()
        .await
        .map_err(|error| {
            eprintln!("post-commit restore reload failed: {error:?}");
            ApiError::Internal(
                "o restauro foi aplicado, mas a memória de domínio não foi recarregada; a pesquisa \
                 ficou vazia e o restauro deve ser repetido"
                    .to_owned(),
            )
        });
    let settlement = finish_committed_restore(state, session_result, reload_result).await;
    drop(settings_update_guard);
    if let Some(committed_error) = committed_store_error {
        if let Err(settlement_error) = settlement {
            eprintln!(
                "committed restore also failed API reconciliation: {settlement_error:?}; original \
                 store reconciliation failure: {committed_error:?}"
            );
            return Err(settlement_error);
        }
        return Err(committed_error);
    }
    settlement?;
    let outcome = outcome.expect("complete restore result exists without a committed error");

    let integrity = current_integrity(state).await;
    Ok(RestoreOutcomeView {
        restored_from: outcome.restored_from.to_string_lossy().into_owned(),
        ledger_length: outcome.ledger_length,
        ledger_head: outcome.ledger_head,
        chain_verified: outcome.chain_verified,
        integrity,
    })
}

/// Settle post-commit recovery without ever leaving the local destructive fence stuck.
///
/// `reload_domain_memory_with_settings_gate_held` releases the fence itself on success. If it fails
/// before that point, all mutable corpus sources are discarded before the fence is released. The
/// durable projection was already tombstoned transactionally by restore, so a retry starts from
/// replacement data only.
async fn finish_committed_restore(
    state: &AppState,
    session_result: Result<(), ApiError>,
    reload_result: Result<(), ApiError>,
) -> Result<(), ApiError> {
    if let Err(reload_error) = reload_result {
        state
            .clear_search_source_memory_after_failed_restore_with_settings_gate_held()
            .await;
        state
            .clear_security_source_memory_after_failed_restore()
            .await;
        crate::search::abort_destructive_change(state).await;
        if let Err(session_error) = session_result {
            eprintln!("post-commit restore also failed to reload domain memory: {reload_error:?}");
            return Err(session_error);
        }
        return Err(reload_error);
    }
    if let Err(session_error) = session_result {
        // The replacement domain loaded, but old bearers could not be revoked. Discard every local
        // authorization source so a pre-restore principal cannot regain access while reconciliation
        // is retried or the process is restarted.
        state
            .clear_security_source_memory_after_failed_restore()
            .await;
        return Err(session_error);
    }
    Ok(())
}

fn resolve_restore_archive(
    data_dir: &std::path::Path,
    archive: &str,
) -> Result<std::path::PathBuf, ApiError> {
    // Resolve the archive: an existing path as-is, else a bare name under <data_dir>/backups/.
    let raw = std::path::PathBuf::from(archive);
    let archive = if raw.exists() {
        raw
    } else {
        data_dir.join("backups").join(archive)
    };
    if !archive.exists() {
        return Err(ApiError::NotFound);
    }
    Ok(archive)
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
        StoreError::NotLeader => AppState::not_leader_error(),
        other => ApiError::Internal(format!("recovery store error: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chancela_core::{Entity, EntityKind, Nipc};

    #[tokio::test]
    async fn post_commit_failure_clears_stale_sources_and_releases_fence_for_retry() {
        let state = AppState::default();
        *state.roles.write().await = chancela_authz::RoleCatalog::seeded_defaults();
        state.ledger.write().await.append(
            "pre-restore-actor",
            "recovery",
            "pre_restore.searchable",
            None,
            b"stale ledger text",
        );
        state.backup_recovery_drill_receipts.write().await.push(
            serde_json::from_value(serde_json::json!({
                "id": "pre-restore-receipt",
                "created_at": "2026-07-01T00:00:00Z",
                "archive": "pre-restore-secret.zip",
                "preflight_ok": true,
                "preflight_ready": true,
                "encrypted": true,
                "ledger_verified": true,
                "manifest": null
            }))
            .expect("stale backup-recovery receipt fixture"),
        );
        state.settings.write().await.workflow.reminders.enabled = false;
        let stale = Entity::new(
            "Pre-restore secret",
            Nipc::unvalidated("stale-entity"),
            "Lisboa",
            EntityKind::SociedadePorQuotas,
        );
        state.entities.write().await.insert(stale.id, stale);

        crate::search::prepare_destructive_change(&state)
            .await
            .expect("first restore acquires destructive fence");
        let result = finish_committed_restore(
            &state,
            Err(ApiError::Unavailable(
                "injected session invalidation failure".to_owned(),
            )),
            Err(ApiError::Internal("injected reload failure".to_owned())),
        )
        .await;

        assert!(matches!(result, Err(ApiError::Unavailable(_))));
        assert!(
            state.entities.read().await.is_empty(),
            "pre-restore searchable sources must be discarded before release"
        );
        assert!(
            state.ledger.read().await.is_empty(),
            "pre-restore ledger events must not be rebuilt into search after release"
        );
        assert!(
            state.backup_recovery_drill_receipts.read().await.is_empty(),
            "pre-restore Action Center sources must be discarded before release"
        );
        assert!(
            state.settings.read().await.workflow.reminders.enabled,
            "pre-restore Action Center settings must reset to fail-closed defaults"
        );
        assert!(
            state.roles.read().await.is_empty(),
            "pre-restore authorization sources must fail closed after reconciliation failure"
        );
        crate::search::prepare_destructive_change(&state)
            .await
            .expect("released fence permits a safe retry");
        crate::search::abort_destructive_change(&state).await;
    }

    #[tokio::test]
    async fn post_commit_session_failure_clears_reloaded_auth_and_remains_retryable() {
        let state = AppState::default();
        *state.roles.write().await = chancela_authz::RoleCatalog::seeded_defaults();
        crate::search::prepare_destructive_change(&state)
            .await
            .expect("restore acquires destructive fence");
        // A successful reload completes the local fence before settlement sees the independent
        // shared-session failure.
        crate::search::reset_after_destructive_change(&state).await;

        let result = finish_committed_restore(
            &state,
            Err(ApiError::Unavailable(
                "injected shared-session invalidation failure".to_owned(),
            )),
            Ok(()),
        )
        .await;

        assert!(matches!(result, Err(ApiError::Unavailable(_))));
        assert!(
            state.roles.read().await.is_empty(),
            "reloaded authorization must be discarded while old bearers may remain live"
        );
        crate::search::prepare_destructive_change(&state)
            .await
            .expect("session failure does not strand the destructive fence");
        crate::search::abort_destructive_change(&state).await;
    }
}
