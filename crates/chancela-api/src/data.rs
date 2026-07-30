//! Destructive **data-management** endpoints (t54-E3, plan §2.11): the server side of the "Gestão de
//! Dados" settings area. Two operations, each gated by a **type-to-confirm phrase** AND **step-up
//! re-auth** (for a credentialed acting user a session alone is never enough; a legacy no-hash user
//! with no recovery phrase has nothing stronger than their self session — see [`require_step_up`])
//! — the two independent confirmations that make these the highest-bar operations in the app:
//!
//! - `POST /v1/data/reset` `{ scope, confirm_phrase, export_first, skip_export_confirm?, reauth }` —
//!   `scope` = `backend_domain` (clears domain data, PRESERVES the ledger, emits `data.wiped`) |
//!   `backend_factory` (clears EVERYTHING incl. the ledger + the sidecar files → blank first-run; the
//!   export-first archive is the record). Export-first is MANDATORY, except a `backend_factory` reset
//!   may skip it via an explicit `skip_export_confirm: true` (an "I have my own backup" opt-out).
//! - `POST /v1/data/start-over` `{ reason, confirm_phrase, reauth }` — whole-instance archive-then-
//!   fresh: archive the whole store, then a fresh ledger whose genesis is `ledger.reinitialized`.
//!   Same double-confirm + re-auth; domain data is re-seeded empty, users/settings are preserved.
//!
//! Both stay reachable while the instance is in the degraded read-only state (a factory reset /
//! whole-instance reset is a legitimate last-resort recovery from an irreparably broken instance —
//! but export-first still applies). The **frontend reset** is client-only (no endpoint here).

use axum::Json;
use axum::extract::State;
use chancela_authz::{Permission, Scope};
use chancela_store::recovery::ResetScope;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::AppState;
use crate::actor::CurrentActor;
use crate::attestation::verify_secret;
use crate::authz::require_permission;
use crate::credentials::{HeldCredentials, step_up_is_vacuous};
use crate::error::ApiError;
use crate::recovery::map_store_error;

/// The exact type-to-confirm phrase for a `backend_domain` wipe.
const DOMAIN_PHRASE: &str = "LIMPAR DADOS";
/// The exact type-to-confirm phrase for a `backend_factory` reset.
const FACTORY_PHRASE: &str = "REPOR FÁBRICA";
/// The exact type-to-confirm phrase for a whole-instance start-over.
const INSTANCE_STARTOVER_PHRASE: &str = "RECOMEÇAR";

/// The single honest-PT refusal for a failed step-up re-auth (never says which of password/phrase
/// was tried or whether the acting user even holds one).
const STEP_UP_REQUIRED: &str =
    "re-autenticação necessária: forneça a palavra-passe atual ou uma frase de recuperação válida";

fn default_actor() -> String {
    "api".to_owned()
}

/// The step-up re-auth proof carried on a destructive request (mirrors the t51/t52 secret-op
/// posture): the acting user's current **password** OR a valid **recovery phrase**. For a
/// credentialed acting user a valid session alone is NOT enough (§8-F); a user who holds **no
/// credential at all** can leave both fields empty — their self session is the proof (see
/// [`require_step_up`]).
///
/// **Adding a proof here (e.g. a passkey assertion): read this first.** This struct is the "with
/// what" axis, and it is the right place for a new alternative — do *not* add a rung to
/// [`crate::confirmation::ConfirmationStrictness`], which answers "how hard"; the existing
/// precedent is [`crate::confirmation::PairingConfirmationMethod`]. A **passkey assertion field
/// must carry a server-issued, single-use, short-TTL challenge scoped to step-up** — not a sign-in
/// challenge, and never a client-chosen nonce. Without that binding an assertion captured at
/// sign-in replays into a factory reset. See [`crate::credentials::StepUpRole::ProofPending`] for
/// the full list of what that arm owes.
#[derive(Deserialize, Default)]
pub struct ReAuth {
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub recovery_phrase: Option<String>,
}

/// Enforce step-up re-authentication for a destructive server op (§8-F) — **SELF re-auth only**.
/// Step-up means *the strongest proof the acting user CAN provide*:
///
/// - The acting user HAS a password → they must supply+pass it (or a valid recovery phrase).
/// - The acting user has NO password but HAS a recovery phrase → they must supply+pass the phrase.
/// - The acting user holds **no credential of any kind** → a valid **authenticated self session**
///   already IS the strongest proof they can offer; there is nothing further to prove, so the
///   session satisfies step-up and this returns `Ok`. This is the t69 lockout fix: a legacy
///   no-hash operator with no recovery phrase must never be `403`'d for lacking a credential
///   they never set, or a legacy no-hash-only instance whose chain breaks could never be recovered
///   (the degraded gate exempts recovery, but step-up would otherwise block it).
///
/// **"No credential of any kind" is a membership test over
/// [`CredentialKind`](crate::credentials::CredentialKind), not over the two fields this function
/// reads verifiers from.** Those are not the same statement the moment a third kind exists: a
/// credential that can start a session but is not named by the exemption would let its holder pass
/// this gate — and therefore every `ConfirmWithReauth` gate in the product — on their session token
/// alone. The predicate therefore lives in [`crate::credentials::step_up_is_vacuous`], derived from
/// per-kind declarations, and this function passes it the whole held set.
///
/// A session with a wrong proof, or a *credentialed* acting user who supplies no proof, is still
/// refused with a uniform `403` — the destructive op cannot proceed on the session token alone when
/// the user actually holds a credential. Uses the same [`verify_secret`] argon2id path t51/t52 use.
///
/// **Scope:** this only relaxes the acting user's OWN self re-auth. It does NOT touch the cross-user
/// authorization path ([`crate::users`] `authorize_secret_op` / `verify_cross_user_proof`): resetting
/// ANOTHER user's credential when the target is legacy no-hash stays refused (t52 hole stays closed).
/// RBAC (`require_permission`) at each call site remains the primary who-may gate — step-up is
/// defense-in-depth layered on top of it, never a substitute.
pub(crate) async fn require_step_up(
    state: &AppState,
    actor: &CurrentActor,
    reauth: &ReAuth,
) -> Result<(), ApiError> {
    let username = actor
        .session_username()
        .ok_or_else(|| ApiError::Forbidden(STEP_UP_REQUIRED.to_owned()))?;
    let (held, password_hash, recovery_hash) = {
        let users = state.users.read().await;
        match users.values().find(|u| u.username == username) {
            Some(u) => (
                HeldCredentials::held_by(u),
                u.password_hash.clone(),
                u.recovery_hash.clone(),
            ),
            // A valid session that no longer maps to a user should not happen (the `CurrentActor`
            // extractor resolves only existing, active users) — refuse rather than treat a phantom
            // acting user as credential-less-and-therefore-exempt.
            None => return Err(ApiError::Forbidden(STEP_UP_REQUIRED.to_owned())),
        }
    };

    decide_step_up(
        &held,
        password_hash.as_deref(),
        recovery_hash.as_deref(),
        reauth,
    )
}

/// The step-up decision itself, with the user already resolved — pure, so the rule can be exercised
/// against account shapes the record cannot express yet (see `credentials.rs`'s red-proof for a
/// session-capable account holding neither of the two verifiers below).
///
/// `held` is the *membership* the exemption is decided on; `password_hash` / `recovery_hash` are the
/// verifiers the two implemented proof arms check against. They are separate parameters precisely
/// because they will stop coinciding: a passkey is held, counts, and has no argon2id verifier here.
pub(crate) fn decide_step_up(
    held: &HeldCredentials,
    password_hash: Option<&str>,
    recovery_hash: Option<&str>,
    reauth: &ReAuth,
) -> Result<(), ApiError> {
    // t69: the acting user holds NO credential at all. A valid authenticated self session is the
    // strongest proof they can provide (there is nothing stronger to demand), so it satisfies
    // step-up. SELF only — the cross-user path is untouched.
    if step_up_is_vacuous(held) {
        return Ok(());
    }

    // The acting user HAS at least one credential — they must actually prove it (unchanged).
    // Prove the current password …
    if let (Some(pw), Some(phc)) = (reauth.password.as_deref(), password_hash)
        && verify_secret(pw, phc)
    {
        return Ok(());
    }
    // … or a valid recovery phrase.
    if let (Some(phrase), Some(phc)) = (reauth.recovery_phrase.as_deref(), recovery_hash)
        && verify_secret(phrase, phc)
    {
        return Ok(());
    }
    // Every other case, including a held credential whose proof arm does not exist yet
    // (`StepUpRole::ProofPending`), is the same uniform `403`. Fail-closed: an account with
    // something to prove that cannot prove it is refused, never exempted.
    Err(ApiError::Forbidden(STEP_UP_REQUIRED.to_owned()))
}

// =================================================================================================
// POST /v1/data/reset
// =================================================================================================

/// Body of `POST /v1/data/reset` (the frozen §2.11 shape).
#[derive(Deserialize)]
pub struct ResetRequest {
    /// `"backend_domain"` | `"backend_factory"`.
    pub scope: String,
    /// The type-to-confirm phrase; must equal the scope's exact phrase.
    pub confirm_phrase: String,
    /// The user's export-first intent. Export-first is mandatory; `false` is honored ONLY on a
    /// `backend_factory` reset that also sets `skip_export_confirm: true`.
    #[serde(default = "yes")]
    pub export_first: bool,
    /// The explicit "I have my own backup — skip the export" opt-out, valid only for
    /// `backend_factory`.
    #[serde(default)]
    pub skip_export_confirm: bool,
    /// Step-up re-auth proof (§8-F) — required.
    #[serde(default)]
    pub reauth: ReAuth,
    #[serde(default = "default_actor")]
    pub actor: String,
}

fn yes() -> bool {
    true
}

/// Response of `POST /v1/data/reset`.
#[derive(Serialize)]
pub struct ResetOutcomeView {
    pub scope: String,
    pub export_archive: Option<String>,
    pub cleared: Vec<String>,
}

/// `POST /v1/data/reset` — a destructive wipe / factory reset with double-confirm, step-up re-auth,
/// and the export-first safety rail (§2.11). Atomic (never a partial half-wipe): the store clears in
/// a single all-or-rollback transaction, and the in-memory read-models are cleared to match only
/// after it commits. `backend_domain` preserves the append-only ledger and emits a chained
/// `data.wiped`; `backend_factory` blanks the ledger and removes the sidecars, the retained
/// export-first archive being the record. `422` in-memory.
pub async fn reset_data(
    State(state): State<AppState>,
    actor: CurrentActor,
    Json(req): Json<ResetRequest>,
) -> Result<Json<ResetOutcomeView>, ApiError> {
    let scope = parse_scope(&req.scope)?;
    let expected = match scope {
        ResetScope::BackendDomain => DOMAIN_PHRASE,
        ResetScope::BackendFactory => FACTORY_PHRASE,
    };
    if req.confirm_phrase.trim() != expected {
        return Err(ApiError::Unprocessable(format!(
            "frase de confirmação incorreta; escreva exatamente {expected:?} para confirmar"
        )));
    }

    // RBAC (t64-E3): a destructive wipe / factory reset requires `data.wipe` at Global — AND the
    // existing step-up re-auth (RBAC = who-may, step-up = confirm-now; both kept).
    require_permission(&state, &actor, Permission::DataWipe, Scope::Global).await?;
    // Step-up re-auth — a valid session alone is NOT enough (§8-F).
    require_step_up(&state, &actor, &req.reauth).await?;
    let actor = actor.resolve(&req.actor);

    let Some(store) = state.store.clone() else {
        return Err(ApiError::Unprocessable(
            "reposição requer persistência em disco".to_owned(),
        ));
    };
    let data_dir = state
        .data_dir()
        .ok_or_else(|| ApiError::Internal("durable store without a data directory".to_owned()))?;

    // Export-first is MANDATORY, except an explicit factory-only opt-out (export_first=false AND a
    // backend_factory scope AND the skip_export_confirm flag).
    let factory_skip =
        !req.export_first && matches!(scope, ResetScope::BackendFactory) && req.skip_export_confirm;
    let export_first = !factory_skip;
    let sidecars = state.instance_sidecars()?;

    // From this point onward the operation belongs to an owned task. Dropping the HTTP future only
    // detaches the waiter: the coordinator retains every guard, resolves the non-cancellable
    // blocking store call, and publishes or aborts the destructive search fence before it exits.
    let coordinator = tokio::spawn(async move {
        let result = reset_data_owned(
            &state,
            store,
            data_dir,
            sidecars,
            scope,
            export_first,
            actor,
        )
        .await;
        if let Err(error) = &result {
            eprintln!(
                "data reset coordinator failed after taking ownership of the operation: {error:?}"
            );
        }
        #[cfg(test)]
        if let Some(pause) = state.destructive_operation_test_pause.as_ref() {
            pause.coordinator_settled.notify_one();
        }
        result
    });
    let outcome = coordinator.await.map_err(|error| {
        ApiError::Internal(format!("data reset coordinator task failed: {error}"))
    })??;
    Ok(Json(outcome))
}

#[allow(clippy::too_many_arguments)]
async fn reset_data_owned(
    state: &AppState,
    store: chancela_store::Store,
    data_dir: std::path::PathBuf,
    sidecars: Vec<std::path::PathBuf>,
    scope: ResetScope,
    export_first: bool,
    actor: String,
) -> Result<ResetOutcomeView, ApiError> {
    // Lock order: settings gate → search fence → settings → ledger. The owned coordinator retains
    // this gate through the durable result and all live-state publication.
    let settings_update_guard = state.settings_update_gate.clone().lock_owned().await;
    state
        .settings_store_commit_tracker
        .wait_until_settled()
        .await;
    crate::settings::reconcile_pending_settings_audit(state).await?;

    // A factory reset must never leave an old bearer valid against the new first-run instance.
    // In HA the Redis epoch advance is fail-closed and happens before the store transaction.
    if matches!(scope, ResetScope::BackendFactory) {
        state.invalidate_all_sessions().await?;
    }

    crate::search::prepare_destructive_change(state)
        .await
        .map_err(ApiError::Unavailable)?;
    let outcome = {
        // `write_owned` makes the ledger guard part of the coordinator's owned state. It cannot be
        // dropped merely because the HTTP task waiting on this coordinator is cancelled.
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
                let outcome = store.reset(
                    &mut ledger,
                    &data_dir,
                    scope,
                    export_first,
                    &sidecars,
                    &actor,
                    at,
                );
                (ledger, outcome)
            })
            .await;
        *ledger_guard = ledger;
        match result {
            Ok(outcome) => {
                crate::refresh_degraded(state, &ledger_guard).await;
                Ok(outcome)
            }
            Err(error) => Err(map_store_error(error)),
        }
    };
    let outcome = match outcome {
        Ok(outcome) => outcome,
        Err(error) => {
            crate::search::abort_destructive_change(state).await;
            return Err(error);
        }
    };

    // The store committed; bring the in-memory read-models in line only while the coordinator still
    // owns the settings gate and fence. Any publication error explicitly aborts the fence.
    let publication = match scope {
        ResetScope::BackendDomain => state.clear_domain_memory().await,
        ResetScope::BackendFactory => state.clear_all_memory_with_settings_gate_held().await,
    };
    if let Err(error) = publication {
        crate::search::abort_destructive_change(state).await;
        return Err(error);
    }
    drop(settings_update_guard);

    Ok(ResetOutcomeView {
        scope: format!("{:?}", outcome.scope),
        export_archive: outcome
            .export_archive
            .map(|path| path.to_string_lossy().into_owned()),
        cleared: outcome.cleared,
    })
}

/// Parse the reset scope; an unrecognized value is a `422`.
fn parse_scope(raw: &str) -> Result<ResetScope, ApiError> {
    match raw.trim() {
        "backend_domain" | "BackendDomain" => Ok(ResetScope::BackendDomain),
        "backend_factory" | "BackendFactory" => Ok(ResetScope::BackendFactory),
        other => Err(ApiError::Unprocessable(format!(
            "âmbito de reposição desconhecido {other:?} (use backend_domain | backend_factory)"
        ))),
    }
}

// =================================================================================================
// POST /v1/data/start-over  (whole-instance)
// =================================================================================================

/// Body of `POST /v1/data/start-over` (whole-instance archive-then-fresh).
#[derive(Deserialize)]
pub struct InstanceStartOverRequest {
    pub reason: String,
    pub confirm_phrase: String,
    #[serde(default)]
    pub reauth: ReAuth,
    #[serde(default = "default_actor")]
    pub actor: String,
}

/// Response of `POST /v1/data/start-over`.
#[derive(Serialize)]
pub struct InstanceStartOverResponse {
    pub scope: String,
    pub archive_path: String,
    pub archived_bundle_digest: String,
}

/// `POST /v1/data/start-over` — whole-instance archive-then-fresh (§2.7), same double-confirm +
/// step-up re-auth as the reset. Archives the whole store, then seeds a FRESH ledger whose genesis is
/// `ledger.reinitialized` referencing the archive; domain data is re-seeded empty, users/settings are
/// preserved. `422` in-memory.
pub async fn start_over_instance(
    State(state): State<AppState>,
    actor: CurrentActor,
    Json(req): Json<InstanceStartOverRequest>,
) -> Result<Json<InstanceStartOverResponse>, ApiError> {
    if req.confirm_phrase.trim() != INSTANCE_STARTOVER_PHRASE {
        return Err(ApiError::Unprocessable(format!(
            "frase de confirmação incorreta; escreva exatamente {INSTANCE_STARTOVER_PHRASE:?} para confirmar"
        )));
    }
    // RBAC (t64-E3): a whole-instance start-over requires `data.start_over` at Global — AND step-up.
    require_permission(&state, &actor, Permission::DataStartOver, Scope::Global).await?;
    require_step_up(&state, &actor, &req.reauth).await?;
    let actor = actor.resolve(&req.actor);

    let Some(store) = state.store.clone() else {
        return Err(ApiError::Unprocessable(
            "recomeçar a instância requer persistência em disco".to_owned(),
        ));
    };
    let data_dir = state
        .data_dir()
        .ok_or_else(|| ApiError::Internal("durable store without a data directory".to_owned()))?;
    let sidecars = state.instance_sidecars()?;

    let reason = req.reason;
    let coordinator = tokio::spawn(async move {
        let result =
            start_over_instance_owned(&state, store, data_dir, sidecars, reason, actor).await;
        if let Err(error) = &result {
            eprintln!(
                "instance start-over coordinator failed after taking ownership of the operation: \
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
            "instance start-over coordinator task failed: {error}"
        ))
    })??;
    Ok(Json(outcome))
}

async fn start_over_instance_owned(
    state: &AppState,
    store: chancela_store::Store,
    data_dir: std::path::PathBuf,
    sidecars: Vec<std::path::PathBuf>,
    reason: String,
    actor: String,
) -> Result<InstanceStartOverResponse, ApiError> {
    // A start-over replaces the durable domain tables while preserving settings. Retain the gate
    // inside the owned coordinator until the replacement read-models are published.
    let settings_update_guard = state.settings_update_gate.clone().lock_owned().await;
    state
        .settings_store_commit_tracker
        .wait_until_settled()
        .await;
    crate::settings::reconcile_pending_settings_audit(state).await?;
    crate::search::prepare_destructive_change(state)
        .await
        .map_err(ApiError::Unavailable)?;
    let outcome = {
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
                let outcome = store.start_over_instance(
                    &mut ledger,
                    &reason,
                    &actor,
                    at,
                    &data_dir,
                    &sidecars,
                );
                (ledger, outcome)
            })
            .await;
        *ledger_guard = ledger;
        match result {
            Ok(outcome) => {
                crate::refresh_degraded(state, &ledger_guard).await;
                Ok(outcome)
            }
            Err(error) => Err(map_store_error(error)),
        }
    };
    let outcome = match outcome {
        Ok(outcome) => outcome,
        Err(error) => {
            crate::search::abort_destructive_change(state).await;
            return Err(error);
        }
    };

    // The whole store was re-seeded empty; clear the in-memory domain read-models to match (the
    // ledger was replaced in lock-step; users/settings are preserved).
    if let Err(error) = state.clear_domain_memory().await {
        crate::search::abort_destructive_change(state).await;
        return Err(error);
    }
    drop(settings_update_guard);

    Ok(InstanceStartOverResponse {
        scope: format!("{:?}", outcome.scope),
        archive_path: outcome.archive_path.to_string_lossy().into_owned(),
        archived_bundle_digest: outcome.archived_bundle_digest,
    })
}
