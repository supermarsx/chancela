//! Certidão permanente registry endpoints (contract §2.7): preview a lookup, enrich an
//! existing entity, and create a new entity from a `código de acesso`.
//!
//! Every consultation goes through [`consult`], which parses and validates the access code
//! (`422` on a malformed one), resolves the transport (the injected
//! [`AppState::registry`](crate::AppState) or an [`HttpRegistryTransport`] from the
//! environment), and runs the **blocking** fetch on a dedicated OS thread so the live transport
//! (whose `reqwest::blocking` client owns an internal runtime) is built and dropped clear of the
//! async runtime — see [`consult`]. A `RegistryError` maps to `422`/`502` via
//! [`From<RegistryError>`](crate::error::ApiError).
//!
//! Secret handling (LEG-22 / GDPR): the full access code is used only to fetch; nothing beyond
//! its masked `****-****-NNNN` form is stored, returned, or written to the ledger. The
//! `registry.imported` audit event carries only the extract digest and the masked code.
//!
//! Multi-lock handlers extend the fixed global order to **entities → books → acts →
//! registry_extracts → ledger**.

use std::fmt::Write as _;
use std::sync::Arc;

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use chancela_authz::{Permission, Scope};
use chancela_core::{DEFAULT_TENANT_ID, Entity, EntityId, EntityKind, Nipc, TenantId};
use chancela_registry::{
    AccessCode, HttpRegistryTransport, LegalForm, RegistryExtract, RegistryTransport,
    parse_certidao,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use crate::AppState;
use crate::actor::{CurrentActor, CurrentAttestor};
use crate::authz::{authorizer, require_permission, scope_of_entity, scope_of_tenant};
use crate::dto::{
    EntityView, RegistryConflict, RegistryExtractView, RegistryImportReport, compute_expired,
    read_redaction_for_actor,
};
use crate::error::ApiError;
use crate::settings::RegistryAutoUpdateSettings;

// --- Request bodies ----------------------------------------------------------------------

/// Body of `POST /v1/registry/lookup`.
#[derive(Deserialize)]
pub struct RegistryLookupRequest {
    /// The 12-digit certidão permanente access code (any grouping; validated server-side).
    pub code: String,
    /// Optional e-mail the new consultation platform requires.
    pub email: Option<String>,
}

/// Body of `POST /v1/entities/{id}/registry/import`.
#[derive(Deserialize)]
pub struct RegistryImportRequest {
    pub code: String,
    pub email: Option<String>,
    /// When `true`, divergent fields are overwritten from the extract instead of kept as
    /// conflicts. Defaults to `false`.
    #[serde(default)]
    pub overwrite: bool,
}

/// Body of `POST /v1/entities/import-from-registry`.
#[derive(Deserialize)]
pub struct RegistryCreateRequest {
    pub code: String,
    pub email: Option<String>,
    /// The tenant to create the imported entity in (wp27 tenancy P4, e3 follow-up). Absent (the
    /// common single-tenant case) the singleton [`DEFAULT_TENANT_ID`] is used, so single-tenant
    /// callers never name a tenant and behaviour is byte-identical to before tenancy. When present
    /// it must name a known tenant the caller is authorized to create in.
    #[serde(default)]
    pub tenant_id: Option<Uuid>,
}

// --- LegalForm → EntityKind mapping ------------------------------------------------------

/// Map a normalized [`LegalForm`] to the 1:1 [`EntityKind`] (variant names are aligned by
/// design). `Other`, and any future unmapped variant, yield `None`.
pub(crate) fn legal_form_to_kind(lf: &LegalForm) -> Option<EntityKind> {
    match lf {
        LegalForm::SociedadePorQuotas => Some(EntityKind::SociedadePorQuotas),
        LegalForm::SociedadeUnipessoalPorQuotas => Some(EntityKind::SociedadeUnipessoalPorQuotas),
        LegalForm::SociedadeAnonima => Some(EntityKind::SociedadeAnonima),
        LegalForm::SociedadeEmNomeColetivo => Some(EntityKind::SociedadeEmNomeColetivo),
        LegalForm::SociedadeEmComanditaSimples => Some(EntityKind::SociedadeEmComanditaSimples),
        LegalForm::SociedadeEmComanditaPorAcoes => Some(EntityKind::SociedadeEmComanditaPorAcoes),
        LegalForm::Cooperativa => Some(EntityKind::Cooperativa),
        LegalForm::Fundacao => Some(EntityKind::Fundacao),
        LegalForm::Associacao => Some(EntityKind::Associacao),
        // `Other(_)` and any future non-exhaustive variant are unmappable.
        _ => None,
    }
}

/// The bare variant name of a [`LegalForm`] for the wire view: a mapped form's name, else
/// `None` (the raw natureza jurídica text stays in `forma_juridica`).
pub(crate) fn legal_form_name(lf: &LegalForm) -> Option<String> {
    legal_form_to_kind(lf).map(|k| kind_name(k).to_owned())
}

/// The contract's `EntityKind` encoding (§2.1): the bare variant name.
fn kind_name(kind: EntityKind) -> &'static str {
    use EntityKind::*;
    match kind {
        SociedadeEmNomeColetivo => "SociedadeEmNomeColetivo",
        SociedadePorQuotas => "SociedadePorQuotas",
        SociedadeUnipessoalPorQuotas => "SociedadeUnipessoalPorQuotas",
        SociedadeAnonima => "SociedadeAnonima",
        SociedadeEmComanditaSimples => "SociedadeEmComanditaSimples",
        SociedadeEmComanditaPorAcoes => "SociedadeEmComanditaPorAcoes",
        Condominio => "Condominio",
        Associacao => "Associacao",
        Fundacao => "Fundacao",
        Cooperativa => "Cooperativa",
    }
}

// --- Consultation ------------------------------------------------------------------------

/// Validate the code, then fetch + parse the certidão on a dedicated OS thread.
///
/// The live [`HttpRegistryTransport`] wraps a `reqwest::blocking::Client`, which owns its own
/// internal tokio runtime. That client must be **built and dropped outside any async context**:
/// a `tokio::task::spawn_blocking` worker still carries the outer runtime's context, so dropping
/// the client there panics with "Cannot drop a runtime in a context where blocking is not
/// allowed". We therefore run the whole consultation on a freshly spawned `std::thread` (which
/// has no tokio runtime context) and await its result over a oneshot channel — so nothing blocks
/// the async runtime and the client is dropped safely on that thread. For an injected transport
/// (e.g. the test mock) this just clones an `Arc` and drops the clone on the thread — harmless.
///
/// The full access code is used only inside the thread (to build the request); the returned
/// extract's provenance carries only its masked form.
async fn consult(
    state: &AppState,
    code: &str,
    email: Option<&str>,
) -> Result<RegistryExtract, ApiError> {
    let access = AccessCode::parse(code).map_err(ApiError::from)?;
    let injected = state.registry.clone();
    let email = email.map(str::to_owned);

    let (tx, rx) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("registry-consult".to_owned())
        .spawn(move || {
            let result: Result<RegistryExtract, ApiError> = (|| {
                // Build the live transport here (not in the async context) so its blocking
                // client is also dropped here, never on a runtime-bearing thread.
                let transport: Arc<dyn RegistryTransport> = match injected {
                    Some(transport) => transport,
                    None => Arc::new(HttpRegistryTransport::from_env()?),
                };
                let document = transport.fetch(&access, email.as_deref())?;
                Ok(parse_certidao(
                    &document.html,
                    &access.masked(),
                    &document.source_url,
                    &document.retrieved_at,
                )?)
            })();
            // If the receiver was dropped (request cancelled) the result is simply discarded.
            let _ = tx.send(result);
        })
        .map_err(|e| ApiError::Internal(format!("failed to spawn registry consult thread: {e}")))?;

    rx.await.map_err(|_| {
        ApiError::Internal("registry consultation thread ended unexpectedly".to_owned())
    })?
}

/// Lowercase-hex sha256, matching the ledger/registry digest convention.
fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Serialize the `registry.imported` ledger payload (LEG-22): the extract digest and the
/// **masked** code only — never the full código de acesso.
fn imported_payload(extract: &RegistryExtract) -> Result<Vec<u8>, ApiError> {
    let extract_digest = registry_extract_digest(extract)?;
    let payload = json!({
        "extract_digest": extract_digest,
        "code_masked": extract.provenance.access_code_masked,
    });
    Ok(serde_json::to_vec(&payload)?)
}

fn registry_extract_digest(extract: &RegistryExtract) -> Result<String, ApiError> {
    Ok(sha256_hex(&serde_json::to_vec(extract)?))
}

/// Non-fatal import advisories (contract §2.7 `warnings`). An **expired** certidão (its
/// `valid_until` strictly before today, UTC) yields a PT notice but never blocks the import —
/// honest surfacing over a hard failure.
fn import_warnings(extract: &RegistryExtract) -> Vec<String> {
    let mut warnings = Vec::new();
    let today = OffsetDateTime::now_utc().date();
    let valid_until = extract.provenance.valid_until.as_deref();
    if compute_expired(valid_until, today) == Some(true)
        && let Some(vu) = valid_until
    {
        warnings.push(format!("certidão expirada em {vu}"));
    }
    warnings
}

// --- Registry auto-update foundation -----------------------------------------------------

/// Worker-visible state for one entity's registry auto-update lifecycle.
///
/// This is deliberately metadata-only. It never stores the full access code or a frontend-supplied
/// registry result; the audit event records only masked code + extract digest evidence.
#[derive(Debug, Clone)]
pub struct RegistryAutoUpdateState {
    pub enabled_override: Option<bool>,
    pub status: RegistryAutoUpdateStatus,
    pub last_attempt_at: Option<OffsetDateTime>,
    pub next_allowed_at: Option<OffsetDateTime>,
    pub failure_count: u32,
    pub last_error: Option<String>,
    pub last_audit_event_seq: Option<u64>,
    pub last_extract_digest: Option<String>,
}

impl Default for RegistryAutoUpdateState {
    fn default() -> Self {
        RegistryAutoUpdateState {
            enabled_override: None,
            status: RegistryAutoUpdateStatus::Idle,
            last_attempt_at: None,
            next_allowed_at: None,
            failure_count: 0,
            last_error: None,
            last_audit_event_seq: None,
            last_extract_digest: None,
        }
    }
}

/// Backend worker lifecycle labels. `Due` is computed in plans; the other labels may be persisted
/// in worker state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistryAutoUpdateStatus {
    #[default]
    Idle,
    Due,
    Queued,
    Running,
    Completed,
    Failed,
    ManualRequired,
}

#[derive(Debug, Clone, Serialize)]
pub struct RegistryAutoUpdateDuePlan {
    pub generated_at: String,
    pub dry_run_only: bool,
    pub config: RegistryAutoUpdateSettings,
    pub due: Vec<RegistryAutoUpdateDueItem>,
    pub skipped: RegistryAutoUpdateSkippedCounts,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RegistryAutoUpdateDueItem {
    pub entity_id: String,
    pub entity_name: String,
    pub entity_profile: String,
    pub retrieved_at: String,
    pub age_hours: Option<i64>,
    pub stale_threshold_hours: u16,
    pub code_masked: String,
    pub status: RegistryAutoUpdateStatus,
    pub reason: String,
    pub next_allowed_at: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct RegistryAutoUpdateSkippedCounts {
    pub disabled: usize,
    pub fresh: usize,
    pub backoff: usize,
    pub running: usize,
    pub orphaned: usize,
    pub capped: usize,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RegistryAutoUpdateAttemptRequest {
    /// Let an operator retry a stale item before the backoff window elapses. This never bypasses
    /// global/entity disabled flags.
    force: bool,
    /// Advisory only in this first slice: the backend is dry-run-only until a secure full-code source
    /// exists.
    dry_run: bool,
    /// Optional operator note. Stored only in the audit payload if the attempt is accepted.
    reason: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RegistryAutoUpdateAttemptView {
    pub accepted: bool,
    pub entity_id: String,
    pub status: RegistryAutoUpdateStatus,
    pub generated_at: String,
    pub dry_run_only: bool,
    pub reason: String,
    pub last_attempt_at: Option<String>,
    pub next_allowed_at: Option<String>,
    pub failure_count: u32,
    pub audit_event_seq: Option<u64>,
}

fn format_ts(ts: OffsetDateTime) -> String {
    ts.format(&Rfc3339).unwrap_or_default()
}

fn parse_ts(raw: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(raw, &Rfc3339).ok()
}

fn entity_profile(entity: &Entity) -> String {
    kind_name(entity.kind).to_owned()
}

fn entity_auto_update_enabled(
    entity: &Entity,
    settings: &RegistryAutoUpdateSettings,
    worker: Option<&RegistryAutoUpdateState>,
) -> bool {
    if let Some(enabled) = worker.and_then(|s| s.enabled_override) {
        return enabled;
    }
    if !settings.entity_defaults.enabled {
        return false;
    }
    let profile = entity_profile(entity);
    let profiles = &settings.entity_defaults.enabled_profiles;
    profiles.is_empty() || profiles.iter().any(|p| p.trim() == profile)
}

fn stale_status(
    extract: &RegistryExtract,
    settings: &RegistryAutoUpdateSettings,
    now: OffsetDateTime,
) -> (bool, Option<i64>, String) {
    let Some(retrieved_at) = parse_ts(&extract.provenance.retrieved_at) else {
        return (
            true,
            None,
            "registry extract retrieved_at is missing or unparseable".to_owned(),
        );
    };
    let age = now - retrieved_at;
    let age_hours = age.whole_hours();
    let threshold = time::Duration::hours(settings.stale_threshold_hours.into());
    if age >= threshold {
        (
            true,
            Some(age_hours),
            format!(
                "registry extract is {age_hours}h old; threshold is {}h",
                settings.stale_threshold_hours
            ),
        )
    } else {
        (
            false,
            Some(age_hours),
            format!(
                "registry extract is {age_hours}h old; threshold is {}h",
                settings.stale_threshold_hours
            ),
        )
    }
}

fn backoff_duration(settings: &RegistryAutoUpdateSettings, failure_count: u32) -> time::Duration {
    let base = i64::from(settings.min_backoff_minutes);
    let max = i64::from(settings.max_backoff_minutes);
    let shift = failure_count.saturating_sub(1).min(10);
    let multiplier = 1_i64 << shift;
    time::Duration::minutes((base.saturating_mul(multiplier)).min(max))
}

fn build_due_plan(
    entities: &std::collections::HashMap<EntityId, Entity>,
    extracts: &std::collections::HashMap<EntityId, RegistryExtract>,
    states: &std::collections::HashMap<EntityId, RegistryAutoUpdateState>,
    settings: RegistryAutoUpdateSettings,
    now: OffsetDateTime,
) -> RegistryAutoUpdateDuePlan {
    let generated_at = format_ts(now);
    let mut skipped = RegistryAutoUpdateSkippedCounts::default();
    let mut due = Vec::new();
    let mut capped = false;

    if !settings.enabled {
        skipped.disabled = extracts.len();
        return RegistryAutoUpdateDuePlan {
            generated_at,
            dry_run_only: true,
            config: settings,
            due,
            skipped,
            notes: vec![
                "registry auto-update is disabled in settings; no records are due".to_owned(),
            ],
        };
    }

    for (eid, extract) in extracts {
        let Some(entity) = entities.get(eid) else {
            skipped.orphaned += 1;
            continue;
        };
        let state = states.get(eid);
        if !entity_auto_update_enabled(entity, &settings, state) {
            skipped.disabled += 1;
            continue;
        }
        if let Some(state) = state {
            if state.status == RegistryAutoUpdateStatus::Running
                || state.status == RegistryAutoUpdateStatus::Queued
            {
                skipped.running += 1;
                continue;
            }
            if state
                .next_allowed_at
                .is_some_and(|next_allowed| next_allowed > now)
            {
                skipped.backoff += 1;
                continue;
            }
        }

        let (is_stale, age_hours, reason) = stale_status(extract, &settings, now);
        if !is_stale {
            skipped.fresh += 1;
            continue;
        }
        if due.len() >= usize::from(settings.max_attempts_per_run) {
            skipped.capped += 1;
            capped = true;
            continue;
        }

        due.push(RegistryAutoUpdateDueItem {
            entity_id: eid.to_string(),
            entity_name: entity.name.clone(),
            entity_profile: entity_profile(entity),
            retrieved_at: extract.provenance.retrieved_at.clone(),
            age_hours,
            stale_threshold_hours: settings.stale_threshold_hours,
            code_masked: extract.provenance.access_code_masked.clone(),
            status: RegistryAutoUpdateStatus::Due,
            reason,
            next_allowed_at: state.and_then(|s| s.next_allowed_at).map(format_ts),
        });
    }

    let mut notes = vec![
        "dry-run-only: stored registry provenance intentionally contains only the masked access code"
            .to_owned(),
    ];
    if capped {
        notes.push("due list was capped by registry_auto_update.max_attempts_per_run".to_owned());
    }

    RegistryAutoUpdateDuePlan {
        generated_at,
        dry_run_only: true,
        config: settings,
        due,
        skipped,
        notes,
    }
}

fn parse_auto_update_attempt(body: Bytes) -> Result<RegistryAutoUpdateAttemptRequest, ApiError> {
    if body.is_empty() {
        return Ok(RegistryAutoUpdateAttemptRequest::default());
    }
    serde_json::from_slice(&body)
        .map_err(|e| ApiError::Unprocessable(format!("invalid registry auto-update request: {e}")))
}

// --- Cross-check -------------------------------------------------------------------------

/// Reconcile an existing entity with the extract (contract §2.7): fill blank text fields
/// silently (→ `applied`), and on a divergence keep the current value as a `conflict` unless
/// `overwrite` (then apply it, reported in `applied`).
fn cross_check(
    entity: &mut Entity,
    extract: &RegistryExtract,
    overwrite: bool,
) -> (Vec<String>, Vec<RegistryConflict>) {
    let mut applied = Vec::new();
    let mut conflicts = Vec::new();

    // Backfill blanks from the matrícula block, falling back to the constitution body (t21 §3.3)
    // so a certidão whose summary block is absent still enriches from its constitution — exactly
    // like the matrícula fields, via the registry crate's `effective_*` accessors.
    let eff_firma = extract.effective_firma();
    let eff_sede = extract.effective_sede();
    let eff_nipc = extract.effective_nipc();

    check_text_field(
        "name",
        &mut entity.name,
        eff_firma.as_deref(),
        overwrite,
        &mut applied,
        &mut conflicts,
    );
    check_text_field(
        "seat",
        &mut entity.seat,
        eff_sede.as_deref(),
        overwrite,
        &mut applied,
        &mut conflicts,
    );
    // NIPC is never blank (validated at creation), so only a divergence is possible — and
    // overwriting requires the incoming NIPC to itself be valid (Nipc::parse).
    if let Some(incoming) = eff_nipc.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        let current = entity.nipc.as_str().to_owned();
        if current != incoming {
            match (overwrite, Nipc::parse(incoming)) {
                (true, Ok(nipc)) => {
                    entity.nipc = nipc;
                    applied.push("nipc".to_owned());
                }
                // Kept on no-overwrite, or when the incoming NIPC cannot be validated.
                _ => conflicts.push(RegistryConflict {
                    field: "nipc".to_owned(),
                    current: Some(current),
                    incoming: Some(incoming.to_owned()),
                }),
            }
        }
    }

    // Kind via legal_form → EntityKind; an unmapped natureza jurídica is not cross-checked.
    if let Some(incoming) = extract.legal_form.as_ref().and_then(legal_form_to_kind)
        && incoming != entity.kind
    {
        if overwrite {
            entity.kind = incoming;
            entity.family = incoming.family();
            applied.push("kind".to_owned());
        } else {
            conflicts.push(RegistryConflict {
                field: "kind".to_owned(),
                current: Some(kind_name(entity.kind).to_owned()),
                incoming: Some(kind_name(incoming).to_owned()),
            });
        }
    }

    (applied, conflicts)
}

/// Cross-check one text field (name/seat): fill a blank current value, else keep a divergence
/// as a conflict unless overwriting.
fn check_text_field(
    field: &str,
    current: &mut String,
    incoming: Option<&str>,
    overwrite: bool,
    applied: &mut Vec<String>,
    conflicts: &mut Vec<RegistryConflict>,
) {
    let Some(incoming) = incoming.map(str::trim).filter(|s| !s.is_empty()) else {
        return; // the extract carried nothing for this field
    };
    if current.trim().is_empty() {
        *current = incoming.to_owned();
        applied.push(field.to_owned());
    } else if current.as_str() != incoming {
        if overwrite {
            *current = incoming.to_owned();
            applied.push(field.to_owned());
        } else {
            conflicts.push(RegistryConflict {
                field: field.to_owned(),
                current: Some(current.clone()),
                incoming: Some(incoming.to_owned()),
            });
        }
    }
    // else: equal → no change, no report
}

// --- Handlers ----------------------------------------------------------------------------

/// `POST /v1/registry/lookup` — preview only: consult + parse, **no storage, no ledger event**.
pub async fn registry_lookup(
    State(state): State<AppState>,
    actor: CurrentActor,
    Json(req): Json<RegistryLookupRequest>,
) -> Result<Json<RegistryExtractView>, ApiError> {
    // RBAC: gated on `entity.registry.lookup` at Global — Global because a lookup names no entity
    // (it is pointed at a código de acesso, and the company may not exist in this instance at all).
    //
    // This was `EntityRead` until t95. `entity.read` means "read entities in this instance"; a
    // lookup reaches an external government service, spends a metered consultation, and can be
    // aimed at any Portuguese company. Under the old gate a Guest — who holds `entity.read` — could
    // make this installation fire live outbound requests at a third party using a purchased
    // credential. The verbs differ in blast radius, so they differ in permission.
    let authz = authorizer(&state, &actor).await?;
    authz.require(Permission::EntityRead, Scope::Global)?; // PROBE: t99 red/green check
    let redaction = read_redaction_for_actor(&state, &actor).await?;
    let extract = consult(&state, &req.code, req.email.as_deref()).await?;
    let cae = state.cae.read().await;
    Ok(Json(RegistryExtractView::build_with_redaction(
        &extract, &cae, redaction,
    )))
}

/// `GET /v1/registry/lookup` — backend-owned dry-run plan for registry auto-update work.
///
/// The path is intentionally an existing registry path: this first backend slice does not add a new
/// route classification surface. The response is a plan/status view only; it never performs a live
/// fetch and never asks the frontend to poll or provide registry result data.
pub async fn registry_auto_update_due_plan(
    State(state): State<AppState>,
    actor: CurrentActor,
) -> Result<Json<RegistryAutoUpdateDuePlan>, ApiError> {
    require_permission(&state, &actor, Permission::EntityRead, Scope::Global).await?;
    let settings = state.settings.read().await.registry_auto_update.clone();
    settings.validate()?;

    let entities = state.entities.read().await;
    let extracts = state.registry_extracts.read().await;
    let states = state.registry_auto_updates.read().await;
    Ok(Json(build_due_plan(
        &entities,
        &extracts,
        &states,
        settings,
        OffsetDateTime::now_utc(),
    )))
}

/// `GET /v1/entities/{id}/registry` — the stored extract for an entity, or `404` if the entity
/// is unknown or nothing has been imported. Requires a valid session (t41 C1).
pub async fn get_entity_registry(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
) -> Result<Json<RegistryExtractView>, ApiError> {
    let eid = EntityId(id);
    let authz = authorizer(&state, &actor).await?;
    authz.require(Permission::EntityRead, scope_of_entity(eid))?;
    let redaction = read_redaction_for_actor(&state, &actor).await?;
    let extracts = state.registry_extracts.read().await;
    let extract = extracts.get(&eid).ok_or(ApiError::NotFound)?;
    let cae = state.cae.read().await;
    Ok(Json(RegistryExtractView::build_with_redaction(
        extract, &cae, redaction,
    )))
}

/// `POST /v1/entities/{id}/registry` — accept one backend-owned auto-update attempt.
///
/// This endpoint accepts only worker control metadata (`force`, `dry_run`, `reason`). Raw HTML,
/// parsed extracts, status completions, and other frontend-supplied heavy/provenance-free result
/// data are rejected by `deny_unknown_fields`.
pub async fn request_registry_auto_update(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    body: Bytes,
) -> Result<(StatusCode, Json<RegistryAutoUpdateAttemptView>), ApiError> {
    let eid = EntityId(id);
    require_permission(
        &state,
        &actor,
        Permission::EntityRegistryImport,
        scope_of_entity(eid),
    )
    .await?;
    let req = parse_auto_update_attempt(body)?;
    let settings = state.settings.read().await.registry_auto_update.clone();
    settings.validate()?;
    let now = OffsetDateTime::now_utc();
    let generated_at = format_ts(now);

    let (
        entity_for_enabled,
        entity_name,
        entity_profile_name,
        retrieved_at,
        code_masked,
        extract_digest,
        is_stale_initial,
        stale_reason,
    ) = {
        let entities = state.entities.read().await;
        let entity = entities.get(&eid).ok_or(ApiError::NotFound)?;
        let extracts = state.registry_extracts.read().await;
        let extract = extracts.get(&eid).ok_or(ApiError::NotFound)?;
        let (is_stale, _, stale_reason) = stale_status(extract, &settings, now);
        (
            entity.clone(),
            entity.name.clone(),
            entity_profile(entity),
            extract.provenance.retrieved_at.clone(),
            extract.provenance.access_code_masked.clone(),
            registry_extract_digest(extract)?,
            is_stale,
            stale_reason,
        )
    };

    let mut states = state.registry_auto_updates.write().await;
    let current_state = states.entry(eid).or_default();
    let enabled = if settings.enabled {
        entity_auto_update_enabled(&entity_for_enabled, &settings, Some(current_state))
    } else {
        false
    };

    if !enabled {
        return Ok((
            StatusCode::OK,
            Json(RegistryAutoUpdateAttemptView {
                accepted: false,
                entity_id: eid.to_string(),
                status: current_state.status,
                generated_at,
                dry_run_only: true,
                reason: "registry auto-update is disabled for this entity".to_owned(),
                last_attempt_at: current_state.last_attempt_at.map(format_ts),
                next_allowed_at: current_state.next_allowed_at.map(format_ts),
                failure_count: current_state.failure_count,
                audit_event_seq: current_state.last_audit_event_seq,
            }),
        ));
    }

    if !req.force {
        if current_state.status == RegistryAutoUpdateStatus::Running
            || current_state.status == RegistryAutoUpdateStatus::Queued
        {
            return Ok((
                StatusCode::OK,
                Json(RegistryAutoUpdateAttemptView {
                    accepted: false,
                    entity_id: eid.to_string(),
                    status: current_state.status,
                    generated_at,
                    dry_run_only: true,
                    reason: "registry auto-update is already queued or running".to_owned(),
                    last_attempt_at: current_state.last_attempt_at.map(format_ts),
                    next_allowed_at: current_state.next_allowed_at.map(format_ts),
                    failure_count: current_state.failure_count,
                    audit_event_seq: current_state.last_audit_event_seq,
                }),
            ));
        }
        if let Some(next_allowed_at) = current_state.next_allowed_at
            && next_allowed_at > now
        {
            return Ok((
                StatusCode::OK,
                Json(RegistryAutoUpdateAttemptView {
                    accepted: false,
                    entity_id: eid.to_string(),
                    status: current_state.status,
                    generated_at,
                    dry_run_only: true,
                    reason: "registry auto-update is in backoff".to_owned(),
                    last_attempt_at: current_state.last_attempt_at.map(format_ts),
                    next_allowed_at: current_state.next_allowed_at.map(format_ts),
                    failure_count: current_state.failure_count,
                    audit_event_seq: current_state.last_audit_event_seq,
                }),
            ));
        }
        if !is_stale_initial {
            return Ok((
                StatusCode::OK,
                Json(RegistryAutoUpdateAttemptView {
                    accepted: false,
                    entity_id: eid.to_string(),
                    status: RegistryAutoUpdateStatus::Idle,
                    generated_at,
                    dry_run_only: true,
                    reason: stale_reason,
                    last_attempt_at: current_state.last_attempt_at.map(format_ts),
                    next_allowed_at: current_state.next_allowed_at.map(format_ts),
                    failure_count: current_state.failure_count,
                    audit_event_seq: current_state.last_audit_event_seq,
                }),
            ));
        }
    }

    current_state.status = RegistryAutoUpdateStatus::Running;
    current_state.last_attempt_at = Some(now);
    current_state.last_error = None;
    current_state.last_extract_digest = Some(extract_digest.clone());

    let actor = actor.resolve("api");
    let manual_required = "stored registry provenance contains only the masked access code; run a manual import with a fresh code or add a secure code vault before live auto-refresh";
    let payload = serde_json::to_vec(&json!({
        "entity_id": eid.to_string(),
        "entity_name": entity_name,
        "entity_profile": entity_profile_name,
        "attempted_at": generated_at,
        "mode": if req.dry_run { "dry_run" } else { "worker" },
        "outcome": "manual_required",
        "reason": manual_required,
        "operator_reason": req.reason,
        "stale_reason": stale_reason,
        "previous_retrieved_at": retrieved_at,
        "previous_extract_digest": extract_digest,
        "code_masked": code_masked,
        "frontend_result_accepted": false
    }))?;
    let seq = {
        let mut ledger = state.ledger.write().await;
        ledger.append(
            &actor,
            &eid.to_string(),
            "registry.auto_update.attempted",
            Some("registry auto-update attempt"),
            &payload,
        );
        let seq = ledger.events().last().map(|e| e.seq);
        if let Err(e) = state
            .persist_write_through(&mut ledger, 1, |_tx| Ok(()))
            .await
        {
            current_state.status = RegistryAutoUpdateStatus::Failed;
            current_state.last_error = Some(format!("failed to persist audit event: {e:?}"));
            return Err(e);
        }
        state.attest_latest(&attestor, &ledger).await;
        seq
    };

    let failure_count = current_state.failure_count.saturating_add(1);
    current_state.failure_count = failure_count;
    current_state.status = RegistryAutoUpdateStatus::ManualRequired;
    current_state.last_error = Some(manual_required.to_owned());
    current_state.last_audit_event_seq = seq;
    current_state.next_allowed_at = Some(now + backoff_duration(&settings, failure_count));

    Ok((
        StatusCode::ACCEPTED,
        Json(RegistryAutoUpdateAttemptView {
            accepted: true,
            entity_id: eid.to_string(),
            status: current_state.status,
            generated_at,
            dry_run_only: true,
            reason: manual_required.to_owned(),
            last_attempt_at: current_state.last_attempt_at.map(format_ts),
            next_allowed_at: current_state.next_allowed_at.map(format_ts),
            failure_count: current_state.failure_count,
            audit_event_seq: current_state.last_audit_event_seq,
        }),
    ))
}

/// `POST /v1/entities/{id}/registry/import` — enrich an existing entity from the extract, store
/// it with provenance, and append a `registry.imported` audit event (LEG-22).
pub async fn import_into_entity(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<RegistryImportRequest>,
) -> Result<Json<RegistryImportReport>, ApiError> {
    let eid = EntityId(id);
    // RBAC (t64-E3): importing registry data into an entity is scoped to that entity.
    require_permission(
        &state,
        &actor,
        Permission::EntityRegistryImport,
        scope_of_entity(eid),
    )
    .await?;
    // Consult BEFORE taking any lock — the fetch is blocking and runs off the runtime.
    let extract = consult(&state, &req.code, req.email.as_deref()).await?;

    // Lock order: entities → registry_extracts → ledger.
    let _search_source_mutation = crate::search::begin_source_mutation(&state).await;
    let mut entities = state.entities.write().await;
    let entity = entities.get_mut(&eid).ok_or(ApiError::NotFound)?;
    // t60 (D3): re-importing the registry extract rewrites the entity's own content — firma, seat,
    // legal form. An archived entity is frozen against content edits, mirroring the `CompanyGroup`
    // precedent's "archived groups cannot be edited". This is `import_into_entity`, which MUTATES an
    // existing entity; the sibling `import_from_registry` CREATES one and is deliberately untouched,
    // since an entity that does not exist yet cannot be archived.
    crate::books::ensure_entity_not_archived(entity, "its content is frozen while archived")?;

    // Cross-check a clone, so the enriched entity + stored extract are committed to the read model
    // only after the durable write (event + both aggregate rows) commits.
    let mut next = entity.clone();
    let (applied, conflicts) = cross_check(&mut next, &extract, req.overwrite);
    let entity_view = EntityView::from(&next);

    let payload = imported_payload(&extract)?;
    let actor = actor.resolve("api");
    {
        let mut extracts = state.registry_extracts.write().await;
        let mut ledger = state.ledger.write().await;
        ledger.append(
            &actor,
            &eid.to_string(),
            "registry.imported",
            Some("registry import"),
            &payload,
        );
        let next_for_store = next.clone();
        let extract_for_store = extract.clone();
        state
            .persist_write_through(&mut ledger, 1, move |tx| {
                tx.upsert_entity(&next_for_store)?;
                tx.upsert_registry_extract(eid, &extract_for_store)
            })
            .await?;
        state.attest_latest(&attestor, &ledger).await;
        *entity = next;
        extracts.insert(eid, extract.clone());
    }

    let warnings = import_warnings(&extract);
    let cae = state.cae.read().await;
    Ok(Json(RegistryImportReport {
        entity: entity_view,
        extract: RegistryExtractView::build(&extract, &cae),
        applied,
        conflicts,
        warnings,
    }))
}

/// `POST /v1/entities/import-from-registry` — create a new entity from the extract (needs a
/// valid NIPC, a firma, and a mappable legal form), store the extract, and append
/// `entity.created` then `registry.imported`.
pub async fn import_from_registry(
    State(state): State<AppState>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<RegistryCreateRequest>,
) -> Result<(StatusCode, Json<RegistryImportReport>), ApiError> {
    // Tenancy (wp27-e3): the imported entity is created **inside a tenant** (mirrors e1's
    // `create_entity`). Absent an explicit `tenant_id` the singleton default tenant is used, so
    // single-tenant deployments stay byte-identical. Authorization narrows to that tenant (it was
    // `Global`): a Global holder still covers every tenant, while a tenant-scoped holder may only
    // import within its own tenant — the cross-tenant write guard.
    let tenant_id = req.tenant_id.map_or(DEFAULT_TENANT_ID, TenantId);
    require_permission(
        &state,
        &actor,
        Permission::EntityCreate,
        scope_of_tenant(tenant_id),
    )
    .await?;
    // An explicitly-named tenant must exist — a `404` **after** the authz check (a caller outside
    // the tenant already got a non-enumerating `403`). The implicit default tenant is always
    // present, so a body without `tenant_id` skips this check and never regresses single-tenant.
    if req.tenant_id.is_some() && !state.tenants.read().await.contains_key(&tenant_id) {
        return Err(ApiError::NotFound);
    }
    let extract = consult(&state, &req.code, req.email.as_deref()).await?;

    // Collect everything the certidão lacked so the 422 explains exactly what was missing.
    let mut lacking: Vec<String> = Vec::new();

    // Backfill identity from the constitution body when the matrícula summary block is absent
    // (t21 §3.3). `kind` still needs the extract-level `legal_form` (normalized only from the
    // matrícula block) — an unmapped natureza jurídica keeps the entity uncreatable, honestly.
    let eff_firma = extract.effective_firma();
    let eff_nipc = extract.effective_nipc();
    let eff_sede = extract.effective_sede();

    let firma = eff_firma
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if firma.is_none() {
        lacking.push("a firma (name)".to_owned());
    }

    // Registry creation stays strict: a certidão is an official record, so an entity minted from
    // one must carry a control-digit-valid NIPC. The `allow_invalid_nipc` override is a MANUAL
    // `POST /v1/entities` affordance for foreign/legacy entities that lack one — it deliberately
    // does not apply to this path, where the NIPC comes from the registry itself.
    let nipc = match eff_nipc.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(raw) => match Nipc::parse(raw) {
            Ok(n) => Some(n),
            Err(_) => {
                lacking.push("a valid NIPC".to_owned());
                None
            }
        },
        None => {
            lacking.push("a NIPC".to_owned());
            None
        }
    };

    let kind = match extract.legal_form.as_ref().map(legal_form_to_kind) {
        Some(Some(k)) => Some(k),
        _ => {
            let raw = extract.forma_juridica.as_deref().unwrap_or("(absent)");
            lacking.push(format!(
                "a mappable legal form (natureza jurídica {raw:?} is not supported)"
            ));
            None
        }
    };

    let (firma, nipc, kind) = match (firma, nipc, kind) {
        (Some(f), Some(n), Some(k)) => (f.to_owned(), n, k),
        _ => {
            return Err(ApiError::Unprocessable(format!(
                "cannot create an entity from this certidão: it lacked {}",
                lacking.join(", ")
            )));
        }
    };

    // The instance's entity-type allowlist (t54 §6.3) gates **every** creation path, not just the
    // manual `POST /v1/entities`. A certidão naming a legal type this instance has narrowed away is
    // still a valid certidão — it just is not an entity this instance registers, and saying so is
    // better than a control with a second door left open.
    crate::entities::ensure_entity_kind_enabled(&state, kind).await?;

    let seat = eff_sede.clone().unwrap_or_default();
    let entity = Entity::new(firma, nipc, seat, kind).in_tenant(tenant_id);
    let eid = entity.id;

    // Every populated field of a fresh entity was sourced from the extract (matrícula or body).
    let mut applied = vec!["name".to_owned(), "nipc".to_owned(), "kind".to_owned()];
    if eff_sede
        .as_deref()
        .map(str::trim)
        .is_some_and(|s| !s.is_empty())
    {
        applied.push("seat".to_owned());
    }

    let entity_payload = serde_json::to_vec(&entity)?;
    let imported = imported_payload(&extract)?;

    let actor = actor.resolve("api");

    // Lock order: entities → registry_extracts → ledger. Both events + both new aggregate rows
    // persist in one transaction, and the read model is committed only after that succeeds.
    let _search_source_mutation = crate::search::begin_source_mutation(&state).await;
    let mut entities = state.entities.write().await;
    let mut extracts = state.registry_extracts.write().await;
    {
        let mut ledger = state.ledger.write().await;
        // A non-default tenant joins the imported entity to its tenant chain (ChainId::Tenant);
        // the default tenant keeps the exact pre-tenancy bare-entity genesis scope (single-tenant
        // byte-identical). Mirrors e3's book/act create-path emission.
        let entity_scope = if tenant_id == DEFAULT_TENANT_ID {
            eid.to_string()
        } else {
            format!("tenant:{tenant_id}/entity:{eid}")
        };
        ledger.append(
            &actor,
            &entity_scope,
            "entity.created",
            None,
            &entity_payload,
        );
        ledger.append(
            &actor,
            &eid.to_string(),
            "registry.imported",
            Some("registry import"),
            &imported,
        );
        let entity_for_store = entity.clone();
        let extract_for_store = extract.clone();
        state
            .persist_write_through(&mut ledger, 2, move |tx| {
                tx.upsert_entity(&entity_for_store)?;
                tx.upsert_registry_extract(eid, &extract_for_store)
            })
            .await?;
        state.attest_latest(&attestor, &ledger).await;
        entities.insert(eid, entity.clone());
        extracts.insert(eid, extract.clone());
    }

    let warnings = import_warnings(&extract);
    let cae = state.cae.read().await;
    Ok((
        StatusCode::CREATED,
        Json(RegistryImportReport {
            entity: EntityView::from(&entity),
            extract: RegistryExtractView::build(&extract, &cae),
            applied,
            conflicts: Vec::new(),
            warnings,
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::http::Request;
    use chancela_registry::MockRegistryTransport;
    use serde_json::Value;
    use tower::ServiceExt; // for `oneshot`

    /// Build a small but structurally faithful certidão HTML with the given identity fields,
    /// so tests can inject a control-digit-valid NIPC (the shipped fixtures use fake NIPCs).
    fn certidao_html(firma: &str, nipc: &str, natureza: &str, sede: &str) -> String {
        format!(
            "<!DOCTYPE html><html lang=\"pt-PT\"><body><div class=\"matricula\">\
             <p>MATRÍCULA</p><table>\
             <tr><td>Matrícula:</td><td>99999/20200101</td></tr>\
             <tr><td>NIF/NIPC:</td><td>{nipc}</td></tr>\
             <tr><td>Firma:</td><td>{firma}</td></tr>\
             <tr><td>Natureza Jurídica:</td><td>{natureza}</td></tr>\
             <tr><td>Sede:</td><td>{sede}</td></tr>\
             <tr><td>Capital:</td><td>5.000,00 EUR</td></tr>\
             <tr><td>CAE:</td><td>70220</td></tr>\
             <tr><td>Data de constituição:</td><td>2020-01-01</td></tr>\
             </table></div>\
             <div class=\"inscricoes\"><p>Inscrições - Averbamentos - Anotações</p>\
             <div><p>Insc. 1 AP. 1/20200101</p><p>CONSTITUIÇÃO DE SOCIEDADE</p></div>\
             </div></body></html>"
        )
    }

    fn state_with(transport: MockRegistryTransport) -> AppState {
        AppState {
            registry: Some(Arc::new(transport)),
            ..Default::default()
        }
    }

    async fn send(state: AppState, req: Request<Body>) -> (StatusCode, Value) {
        // t41: auto-seed a session for requests that don't carry one (mutations require auth).
        if req.headers().get("x-chancela-session").is_none() {
            let token = auth_token(&state).await;
            return send_raw(state, with_session(req, &token)).await;
        }
        send_raw(state, req).await
    }

    async fn send_raw(state: AppState, req: Request<Body>) -> (StatusCode, Value) {
        let response = crate::router(state)
            .oneshot(req)
            .await
            .expect("router responds");
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

    fn with_session(mut req: Request<Body>, token: &str) -> Request<Body> {
        req.headers_mut().insert(
            "x-chancela-session",
            token.parse().expect("valid header value"),
        );
        req
    }

    async fn auth_token(state: &AppState) -> String {
        use crate::users::{User, UserId};
        use chancela_authz::{OWNER_ROLE_ID, RoleAssignment, RoleCatalog, Scope};
        use time::format_description::well_known::Rfc3339;
        // RBAC (t64-E3): seed the catalog + make the test actor Owner\@Global so gated endpoints pass.
        {
            let mut roles = state.roles.write().await;
            if roles.is_empty() {
                *roles = RoleCatalog::seeded_defaults();
            }
        }
        let uid = UserId(uuid::Uuid::new_v4());
        let user = User {
            id: uid,
            username: "test.actor".to_owned(),
            display_name: "Test Actor".to_owned(),
            email: None,
            created_at: time::OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .unwrap_or_default(),
            active: true,
            password_hash: Some(crate::attestation::hash_secret("Teste-Forte7!X").unwrap()),
            attestation_key: None,
            retired_attestation_keys: Vec::new(),
            totp: None,
            two_factor_required: false,
            force_password_change: false,
            secret_source: Default::default(),
            recovery_hash: None,
            role_assignments: vec![RoleAssignment::new(OWNER_ROLE_ID, Scope::Global)],
            language: Default::default(),
        };
        state.users.write().await.insert(uid, user);
        let token = uuid::Uuid::new_v4().to_string();
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

    async fn auth_token_for_role(
        state: &AppState,
        username: &str,
        role_id: chancela_authz::RoleId,
    ) -> String {
        use crate::users::{User, UserId};
        use chancela_authz::{RoleAssignment, RoleCatalog, Scope};
        use time::format_description::well_known::Rfc3339;

        {
            let mut roles = state.roles.write().await;
            if roles.is_empty() {
                *roles = RoleCatalog::seeded_defaults();
            }
        }

        let uid = UserId(uuid::Uuid::new_v4());
        let user = User {
            id: uid,
            username: username.to_owned(),
            display_name: username.to_owned(),
            email: None,
            created_at: time::OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .unwrap_or_default(),
            active: true,
            password_hash: Some(crate::attestation::hash_secret("Teste-Forte7!X").unwrap()),
            attestation_key: None,
            retired_attestation_keys: Vec::new(),
            totp: None,
            two_factor_required: false,
            force_password_change: false,
            secret_source: Default::default(),
            recovery_hash: None,
            role_assignments: vec![RoleAssignment::new(role_id, Scope::Global)],
            language: Default::default(),
        };
        state.users.write().await.insert(uid, user);

        let token = uuid::Uuid::new_v4().to_string();
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

    /// Seed a **custom** função with an exact permission set and return a session token for it.
    ///
    /// Needed because t95's `entity.registry.lookup` split created a principal shape no seeded role
    /// occupies: read-only *and* able to look up. That shape is the redaction-restricted subject of
    /// the lookup endpoint (see `ReadRedaction::for_effective_permissions` — it is an ALL-of test
    /// over a read-only allowlist that `EntityRegistryLookup` is a member of), so without it the
    /// redaction coverage on this path would have nothing to run against.
    async fn auth_token_for_permissions(
        state: &AppState,
        username: &str,
        permissions: &[Permission],
    ) -> String {
        use chancela_authz::{Role, RoleCatalog, RoleId};

        let role_id = RoleId(uuid::Uuid::new_v4());
        {
            let mut roles = state.roles.write().await;
            if roles.is_empty() {
                *roles = RoleCatalog::seeded_defaults();
            }
            roles.insert(Role {
                id: role_id,
                name: username.to_owned(),
                permission_set: permissions.iter().copied().collect(),
                protected: false,
            });
        }
        auth_token_for_role(state, username, role_id).await
    }

    fn get(uri: &str) -> Request<Body> {
        Request::builder()
            .uri(uri)
            .body(Body::empty())
            .expect("request builds")
    }

    fn post_json(uri: &str, body: Value) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("request builds")
    }

    /// Create an entity and return its id string.
    async fn create_entity(
        state: &AppState,
        name: &str,
        nipc: &str,
        seat: &str,
        kind: &str,
    ) -> String {
        let (status, e) = send(
            state.clone(),
            post_json(
                "/v1/entities",
                json!({ "name": name, "nipc": nipc, "seat": seat, "kind": kind }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        e["id"].as_str().expect("entity id").to_owned()
    }

    async fn enable_registry_auto_update(state: &AppState, stale_threshold_hours: u16) {
        let mut settings = crate::settings::Settings::default();
        settings.registry_auto_update = crate::settings::RegistryAutoUpdateSettings {
            enabled: true,
            stale_threshold_hours,
            min_backoff_minutes: 30,
            max_backoff_minutes: 60,
            max_attempts_per_run: 10,
            entity_defaults: crate::settings::RegistryAutoUpdateEntityDefaults {
                enabled: true,
                enabled_profiles: Vec::new(),
            },
            ..Default::default()
        };
        *state.settings.write().await = settings;
    }

    async fn insert_entity_with_registry_extract(
        state: &AppState,
        name: &str,
        retrieved_at: time::OffsetDateTime,
    ) -> EntityId {
        let entity = Entity::new(
            name.to_owned(),
            Nipc::parse("503004642").expect("valid NIPC"),
            "Lisboa",
            EntityKind::SociedadePorQuotas,
        );
        let eid = entity.id;
        let retrieved = format_ts(retrieved_at);
        let extract = parse_certidao(
            &certidao_html(name, "503004642", "Sociedade por quotas", "Lisboa"),
            "****-****-9012",
            "mock://registry/certidao",
            &retrieved,
        )
        .expect("fixture certidao parses");
        state.entities.write().await.insert(eid, entity);
        state.registry_extracts.write().await.insert(eid, extract);
        eid
    }

    #[tokio::test]
    async fn auto_update_due_plan_defaults_disabled_safe() {
        let state = AppState::default();
        let _stale = insert_entity_with_registry_extract(
            &state,
            "Stale Default, Lda",
            time::OffsetDateTime::now_utc() - time::Duration::days(60),
        )
        .await;

        let (status, plan) = send(state, get("/v1/registry/lookup")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(plan["config"]["enabled"], false);
        assert_eq!(plan["config"]["entity_defaults"]["enabled"], false);
        assert_eq!(plan["dry_run_only"], true);
        assert_eq!(plan["due"].as_array().expect("due").len(), 0);
        assert_eq!(plan["skipped"]["disabled"], 1);
    }

    #[tokio::test]
    async fn auto_update_due_plan_selects_stale_and_ignores_fresh_and_disabled() {
        let state = AppState::default();
        enable_registry_auto_update(&state, 24).await;
        let now = time::OffsetDateTime::now_utc();
        let stale = insert_entity_with_registry_extract(
            &state,
            "Stale Due, Lda",
            now - time::Duration::hours(48),
        )
        .await;
        let _fresh = insert_entity_with_registry_extract(
            &state,
            "Fresh Ignored, Lda",
            now - time::Duration::hours(1),
        )
        .await;
        let disabled = insert_entity_with_registry_extract(
            &state,
            "Disabled Ignored, Lda",
            now - time::Duration::hours(72),
        )
        .await;
        state.registry_auto_updates.write().await.insert(
            disabled,
            RegistryAutoUpdateState {
                enabled_override: Some(false),
                ..Default::default()
            },
        );

        let (status, plan) = send(state, get("/v1/registry/lookup")).await;
        assert_eq!(status, StatusCode::OK);
        let due = plan["due"].as_array().expect("due");
        assert_eq!(due.len(), 1, "plan: {plan}");
        assert_eq!(due[0]["entity_id"], stale.to_string());
        assert_eq!(due[0]["status"], "due");
        assert_eq!(plan["skipped"]["fresh"], 1);
        assert_eq!(plan["skipped"]["disabled"], 1);
    }

    #[tokio::test]
    async fn auto_update_attempt_audits_only_accepted_and_records_status_evidence() {
        let state = AppState::default();
        let entity = insert_entity_with_registry_extract(
            &state,
            "Attempt Evidence, Lda",
            time::OffsetDateTime::now_utc() - time::Duration::hours(48),
        )
        .await;

        let (status, rejected) = send(
            state.clone(),
            post_json(&format!("/v1/entities/{entity}/registry"), json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(rejected["accepted"], false);
        assert_eq!(state.ledger.read().await.events().len(), 0);

        enable_registry_auto_update(&state, 24).await;
        let (status, accepted) = send(
            state.clone(),
            post_json(
                &format!("/v1/entities/{entity}/registry"),
                json!({ "reason": "nightly worker slice" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED, "accepted body: {accepted}");
        assert_eq!(accepted["accepted"], true);
        assert_eq!(accepted["status"], "manual_required");
        assert_eq!(accepted["failure_count"], 1);
        assert!(accepted["audit_event_seq"].is_number());
        assert!(accepted["next_allowed_at"].is_string());

        let events = state.ledger.read().await.events().to_vec();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "registry.auto_update.attempted");
        assert_eq!(events[0].scope, entity.to_string());

        {
            let statuses = state.registry_auto_updates.read().await;
            let evidence = statuses.get(&entity).expect("status evidence stored");
            assert_eq!(evidence.status, RegistryAutoUpdateStatus::ManualRequired);
            assert_eq!(evidence.failure_count, 1);
            assert!(evidence.last_attempt_at.is_some());
            assert!(evidence.next_allowed_at.is_some());
            assert_eq!(evidence.last_audit_event_seq, Some(events[0].seq));
            assert!(evidence.last_extract_digest.is_some());
        }

        let (status, backed_off) = send(
            state.clone(),
            post_json(&format!("/v1/entities/{entity}/registry"), json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(backed_off["accepted"], false);
        assert!(
            backed_off["reason"]
                .as_str()
                .expect("reason")
                .contains("backoff")
        );
        assert_eq!(
            state
                .ledger
                .read()
                .await
                .events()
                .iter()
                .filter(|e| e.kind == "registry.auto_update.attempted")
                .count(),
            1,
            "backoff rejection must not append a second audit event"
        );
    }

    #[tokio::test]
    async fn auto_update_rejects_frontend_supplied_result_data() {
        let state = AppState::default();
        enable_registry_auto_update(&state, 24).await;
        let entity = insert_entity_with_registry_extract(
            &state,
            "Raw Payload Rejected, Lda",
            time::OffsetDateTime::now_utc() - time::Duration::hours(48),
        )
        .await;

        let (status, body) = send(
            state.clone(),
            post_json(
                &format!("/v1/entities/{entity}/registry"),
                json!({
                    "status": "completed",
                    "extract": { "firma": "Frontend Result, Lda" },
                    "raw_html": "<html></html>"
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            body["error"]
                .as_str()
                .expect("error")
                .contains("unknown field")
        );
        assert_eq!(state.ledger.read().await.events().len(), 0);
        assert!(
            state
                .registry_auto_updates
                .read()
                .await
                .get(&entity)
                .is_none(),
            "rejected raw result must not store worker status"
        );
    }

    #[tokio::test]
    async fn lookup_returns_view_with_masked_provenance_and_no_ledger_event() {
        let html = certidao_html(
            "Encosto Estratégico, Lda",
            "503004642",
            "Sociedade por quotas",
            "Lisboa",
        );
        let state = state_with(MockRegistryTransport::empty().with_html(html));

        let (status, view) = send(
            state.clone(),
            post_json("/v1/registry/lookup", json!({ "code": "1234-5678-9012" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(view["firma"], "Encosto Estratégico, Lda");
        assert_eq!(view["nipc"], "503004642");
        assert_eq!(view["legal_form"], "SociedadePorQuotas");
        assert_eq!(view["provenance"]["access_code_masked"], "****-****-9012");
        assert_eq!(view["provenance"]["source_url"], "mock://registry/certidao");
        assert_eq!(
            view["provenance"]["raw_digest"]
                .as_str()
                .expect("digest")
                .len(),
            64
        );

        // A preview lookup stores nothing and appends no ledger event.
        let (_, events) = send(state, get("/v1/ledger/events")).await;
        assert_eq!(events.as_array().expect("events").len(), 0);
    }

    /// **The security property the t95 verb split exists to create.**
    ///
    /// Before the split this endpoint was gated on `entity.read`, which Guest holds — so a Guest got
    /// HTTP 200 and could make this installation fire live outbound requests at a government
    /// service, using a purchased código de acesso, against *any* Portuguese company, including ones
    /// this instance has no relationship with. `entity.read` means "read entities in this instance";
    /// it never described that blast radius.
    ///
    /// Reader is asserted alongside Guest because the split narrowed the endpoint to registry
    /// verb-holders, not merely to non-guests — a fix that only stopped Guest would leave every
    /// read-only função still able to spend the quota.
    #[tokio::test]
    async fn guest_is_refused_the_registry_lookup_after_the_verb_split() {
        for (label, role) in [
            ("guest", chancela_authz::GUEST_ROLE_ID),
            ("leitor", chancela_authz::READER_ROLE_ID),
        ] {
            let state = state_with(MockRegistryTransport::from_fixture_spq());
            let token = auth_token_for_role(&state, label, role).await;
            let (status, _) = send_raw(
                state.clone(),
                with_session(
                    post_json("/v1/registry/lookup", json!({ "code": "1234-5678-9012" })),
                    &token,
                ),
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{label} reached the lookup");

            // Refused before the transport was touched: no outbound consultation was spent. This is
            // the whole point — a 403 after the request would still have cost a metered lookup.
            assert!(
                state.registry_extracts.read().await.is_empty(),
                "{label} caused a stored extract"
            );
        }
    }

    /// The split must narrow the lookup **without** stripping anyone who could already import — an
    /// import consults the registry as its first step, so a role able to import and unable to look
    /// up would be incoherent.
    #[tokio::test]
    async fn every_role_that_can_import_from_the_registry_can_also_look_up() {
        use chancela_authz::{Permission, default_roles};
        for role in default_roles() {
            if role.permission_set.contains(&Permission::EntityRegistryImport) {
                assert!(
                    role.permission_set
                        .contains(&Permission::EntityRegistryLookup),
                    "{} can import from the registry but cannot look up",
                    role.name
                );
            }
        }
    }

    /// **The load-bearing test for the lookup tool (t95): a lookup writes nothing, anywhere.**
    ///
    /// Asserting that a result rendered would prove nothing — the whole point of a lookup-only tool
    /// is the writes that must be *absent*. So this asserts absence directly, across every sink the
    /// import path touches, and then asserts idempotence by running it twice.
    ///
    /// The `registry_extracts` map matters as much as the ledger here: it is the only thing
    /// resembling a cache on this path, and a lookup that quietly populated it would be a side
    /// effect even though no entity changed.
    #[tokio::test]
    async fn a_lookup_creates_no_entity_no_extract_and_no_ledger_event_and_is_repeatable() {
        let state = state_with(MockRegistryTransport::from_fixture_spq());

        let before_entities = state.entities.read().await.len();
        let before_extracts = state.registry_extracts.read().await.len();
        let before_events = state.ledger.read().await.events().len();

        for _ in 0..2 {
            let (status, _) = send(
                state.clone(),
                post_json("/v1/registry/lookup", json!({ "code": "1234-5678-9012" })),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
        }

        assert_eq!(
            state.entities.read().await.len(),
            before_entities,
            "a lookup must create or match no entity"
        );
        assert_eq!(
            state.registry_extracts.read().await.len(),
            before_extracts,
            "a lookup must not store an extract — there is no cache for it to warm"
        );
        assert_eq!(
            state.ledger.read().await.events().len(),
            before_events,
            "a lookup must append no domain-ledger event"
        );
        // Nothing resembling an import event, under any kind.
        assert!(
            state
                .ledger
                .read()
                .await
                .events()
                .iter()
                .all(|e| !e.kind.starts_with("registry.") && !e.kind.starts_with("entity.")),
            "a lookup must not append a registry or entity event"
        );
        // The worker-state map is not a lookup's business either.
        assert!(
            state.registry_auto_updates.read().await.is_empty(),
            "a lookup must not touch registry auto-update worker state"
        );
    }

    /// A lookup must not modify an entity that already exists and matches the certidão — the
    /// "match-and-update" behaviour is `import_into_entity`'s, and must not leak into the lookup.
    #[tokio::test]
    async fn a_lookup_does_not_modify_an_existing_matching_entity() {
        let html = certidao_html(
            "Encosto Estratégico, Lda",
            "503004642",
            "Sociedade por quotas",
            "Porto",
        );
        let state = state_with(MockRegistryTransport::empty().with_html(html));
        // Deliberately divergent from the certidão (a blank seat and a different name) — exactly
        // the shape `cross_check` would have filled in and overwritten on an import.
        let id = create_entity(
            &state,
            "Nome Original, Lda",
            "503004642",
            "",
            "SociedadePorQuotas",
        )
        .await;

        let events_before = state.ledger.read().await.events().len();

        let (status, _) = send(
            state.clone(),
            post_json("/v1/registry/lookup", json!({ "code": "1234-5678-9012" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, entity) = send(state.clone(), get(&format!("/v1/entities/{id}"))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(entity["name"], "Nome Original, Lda", "name was rewritten");
        assert_eq!(entity["seat"], "", "blank seat was backfilled from the certidão");
        assert_eq!(
            state.ledger.read().await.events().len(),
            events_before,
            "a lookup appended an event for an existing entity"
        );
        // And still nothing stored for it.
        let (status, _) = send(state, get(&format!("/v1/entities/{id}/registry"))).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "a lookup stored an extract against the entity"
        );
    }

    /// Redaction on the **lookup** path still hides nested identifiers and provenance.
    ///
    /// The redacted subject used to be the seeded Guest. t95 moved this endpoint onto
    /// `entity.registry.lookup`, which Guest does not hold, so Guest is now refused here
    /// (`guest_is_refused_the_registry_lookup_after_the_verb_split` covers that) — and this test
    /// would have quietly become a test that a 403 happens, proving nothing about redaction.
    ///
    /// It is therefore retargeted onto a função that is *still* redaction-restricted **and** still
    /// reaches the endpoint: read-only grants plus the lookup verb. That combination is redacted
    /// because `ReadRedaction::for_effective_permissions` is an ALL-of test over a read-only
    /// allowlist which `EntityRegistryLookup` deliberately belongs to. Every assertion below is the
    /// original one — none was dropped in the move.
    #[tokio::test]
    async fn read_only_lookup_role_redaction_hides_nested_identifiers_and_provenance() {
        let state = state_with(MockRegistryTransport::from_fixture_constituicao());

        let guest = auth_token_for_permissions(
            &state,
            "consulta.restrita",
            &[
                Permission::EntityRead,
                Permission::EntityRegistryLookup,
                Permission::BookRead,
                Permission::ActRead,
            ],
        )
        .await;
        let (status, guest_view) = send_raw(
            state.clone(),
            with_session(
                post_json("/v1/registry/lookup", json!({ "code": "1234-5678-9012" })),
                &guest,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(guest_view["nipc"].is_null());
        assert!(guest_view["sede"].is_null());
        assert_eq!(
            guest_view["provenance"]["access_code_masked"],
            crate::dto::REDACTED
        );
        assert_eq!(guest_view["provenance"]["source_url"], crate::dto::REDACTED);
        assert_eq!(guest_view["provenance"]["raw_digest"], crate::dto::REDACTED);
        assert!(guest_view["provenance"]["oficial"].is_null());
        assert_eq!(guest_view["provenance"]["valid_until"], "2027-07-05");
        assert_eq!(guest_view["inscricoes"][0]["text"], crate::dto::REDACTED);
        assert_eq!(guest_view["anotacoes"][0]["number"], "1");
        assert_eq!(guest_view["anotacoes"][0]["text"], crate::dto::REDACTED);

        let payload = &guest_view["inscricoes"][0]["detail"]["payload"];
        assert!(payload["nipc"].is_null());
        assert!(payload["sede"].is_null());
        assert_eq!(payload["capital"]["amount_text"], "100,00");
        assert_eq!(
            payload["socios"][0]["titular"]["name"],
            crate::dto::REDACTED
        );
        assert!(payload["socios"][0]["titular"]["nif"].is_null());
        assert!(payload["socios"][0]["titular"]["estado_civil"].is_null());
        assert!(payload["socios"][0]["titular"]["nacionalidade"].is_null());
        assert!(
            payload["socios"][0]["titular"]["residencia"].is_null(),
            "residencia redacted: {payload}"
        );
        assert_eq!(
            payload["orgaos"][0]["members"][0]["name"],
            crate::dto::REDACTED
        );
        assert!(payload["orgaos"][0]["members"][0]["nif"].is_null());
        assert!(payload["orgaos"][0]["members"][0]["nacionalidade"].is_null());
        assert!(payload["orgaos"][0]["members"][0]["residencia"].is_null());
        assert_eq!(payload["orgaos"][0]["members"][0]["cargo"], "Gerente");

        let redacted = guest_view.to_string();
        assert!(!redacted.contains("503004642"), "NIPC leaked: {redacted}");
        assert!(
            !redacted.contains("999999990"),
            "shareholder NIF leaked: {redacted}"
        );
        assert!(
            !redacted.contains("Rui Tavares Nogueira"),
            "shareholder name leaked: {redacted}"
        );
        assert!(
            !redacted.contains("Portuguesa"),
            "nationality leaked: {redacted}"
        );
        assert!(
            !redacted.contains("casado"),
            "marital status leaked: {redacted}"
        );
        assert!(
            !redacted.contains("****-****-9012"),
            "masked access code leaked: {redacted}"
        );
        assert!(
            !redacted.contains("1234-5678-9012"),
            "grouped access code leaked: {redacted}"
        );
        assert!(
            !redacted.contains("123456789012"),
            "bare access code leaked: {redacted}"
        );

        // The unredacted half. This was the seeded Reader, which also lost the endpoint in the
        // split (it holds no registry verb). Company Owner is the seeded role that both holds
        // `entity.registry.lookup` and — carrying write verbs — resolves to `ReadRedaction::None`,
        // so it is the faithful replacement for "a principal who sees the whole certidão".
        let leitor =
            auth_token_for_role(&state, "leitor", chancela_authz::COMPANY_OWNER_ROLE_ID).await;
        let (status, reader_view) = send_raw(
            state,
            with_session(
                post_json("/v1/registry/lookup", json!({ "code": "1234-5678-9012" })),
                &leitor,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            reader_view["provenance"]["access_code_masked"],
            "****-****-9012"
        );
        assert_eq!(
            reader_view["provenance"]["source_url"],
            "mock://registry/certidao"
        );
        assert_eq!(
            reader_view["provenance"]["raw_digest"]
                .as_str()
                .expect("digest")
                .len(),
            64
        );
        assert_eq!(reader_view["provenance"]["oficial"], "Amélia Marques");
        assert_eq!(
            reader_view["inscricoes"][0]["detail"]["payload"]["nipc"],
            "503004642"
        );
        assert_eq!(
            reader_view["inscricoes"][0]["detail"]["payload"]["socios"][0]["titular"]["estado_civil"],
            "casado"
        );
        assert_eq!(
            reader_view["inscricoes"][0]["detail"]["payload"]["socios"][0]["titular"]["nacionalidade"],
            "Portuguesa"
        );
        let annotation = reader_view["anotacoes"][0]["text"]
            .as_str()
            .expect("reader annotation text");
        assert!(
            annotation.starts_with("An. 1 - 20260501 - Publicado em http://publicacoes.mj.pt."),
            "reader annotation keeps publication line: {annotation}"
        );
        assert!(
            annotation.contains("Amélia Marques"),
            "reader annotation keeps official footer: {annotation}"
        );
        assert!(
            reader_view.to_string().contains("503004642"),
            "normal reader keeps the NIPC"
        );
    }

    #[tokio::test]
    async fn guest_stored_registry_redaction_handles_missing_optional_detail() {
        let html = certidao_html(
            "Encosto Estratégico, Lda",
            "503004642",
            "Sociedade por quotas",
            "Avenida da Liberdade, Lisboa",
        );
        let state = state_with(MockRegistryTransport::empty().with_html(html));
        let id = create_entity(
            &state,
            "Encosto Estratégico, Lda",
            "503004642",
            "Avenida da Liberdade, Lisboa",
            "SociedadePorQuotas",
        )
        .await;

        let (status, _) = send(
            state.clone(),
            post_json(
                &format!("/v1/entities/{id}/registry/import"),
                json!({ "code": "1234-5678-9012" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let guest =
            auth_token_for_role(&state, "guest.stored", chancela_authz::GUEST_ROLE_ID).await;
        let (status, guest_view) = send_raw(
            state.clone(),
            with_session(get(&format!("/v1/entities/{id}/registry")), &guest),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(guest_view["nipc"].is_null());
        assert!(guest_view["sede"].is_null());
        assert_eq!(
            guest_view["provenance"]["access_code_masked"],
            crate::dto::REDACTED
        );
        assert_eq!(guest_view["provenance"]["source_url"], crate::dto::REDACTED);
        assert_eq!(guest_view["provenance"]["raw_digest"], crate::dto::REDACTED);
        let redacted = guest_view.to_string();
        assert!(!redacted.contains("503004642"), "NIPC leaked: {redacted}");
        assert!(
            !redacted.contains("****-****-9012"),
            "masked access code leaked: {redacted}"
        );
        assert!(
            !redacted.contains("1234-5678-9012"),
            "grouped access code leaked: {redacted}"
        );
        assert!(
            !redacted.contains("123456789012"),
            "bare access code leaked: {redacted}"
        );

        let leitor =
            auth_token_for_role(&state, "leitor.stored", chancela_authz::READER_ROLE_ID).await;
        let (status, reader_view) = send_raw(
            state,
            with_session(get(&format!("/v1/entities/{id}/registry")), &leitor),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(reader_view["nipc"], "503004642");
        assert_eq!(reader_view["sede"], "Avenida da Liberdade, Lisboa");
        assert_eq!(
            reader_view["provenance"]["access_code_masked"],
            "****-****-9012"
        );
        assert_eq!(
            reader_view["provenance"]["raw_digest"]
                .as_str()
                .expect("digest")
                .len(),
            64
        );
        assert!(
            reader_view.to_string().contains("503004642"),
            "normal reader keeps the NIPC"
        );
    }

    #[tokio::test]
    async fn import_fills_blanks_and_reports_a_kept_conflict() {
        let html = certidao_html(
            "Encosto Estratégico, Lda",
            "503004642",
            "Sociedade por quotas",
            "Avenida da Liberdade, Lisboa",
        );
        let state = state_with(MockRegistryTransport::empty().with_html(html));
        // Blank seat (to be filled), a divergent name, matching NIPC and kind.
        let id = create_entity(
            &state,
            "Nome Original, Lda",
            "503004642",
            "",
            "SociedadePorQuotas",
        )
        .await;

        let (status, report) = send(
            state,
            post_json(
                &format!("/v1/entities/{id}/registry/import"),
                json!({ "code": "1234-5678-9012" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let applied: Vec<&str> = report["applied"]
            .as_array()
            .expect("applied")
            .iter()
            .map(|v| v.as_str().expect("field"))
            .collect();
        assert!(applied.contains(&"seat"), "blank seat filled: {applied:?}");
        assert!(!applied.contains(&"name"), "divergent name not applied");

        let conflicts = report["conflicts"].as_array().expect("conflicts");
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0]["field"], "name");
        assert_eq!(conflicts[0]["current"], "Nome Original, Lda");
        assert_eq!(conflicts[0]["incoming"], "Encosto Estratégico, Lda");

        // The entity's seat was filled; its name kept (no overwrite).
        assert_eq!(report["entity"]["seat"], "Avenida da Liberdade, Lisboa");
        assert_eq!(report["entity"]["name"], "Nome Original, Lda");
    }

    #[tokio::test]
    async fn import_with_overwrite_applies_a_divergent_field() {
        let html = certidao_html(
            "Encosto Estratégico, Lda",
            "503004642",
            "Sociedade por quotas",
            "Lisboa",
        );
        let state = state_with(MockRegistryTransport::empty().with_html(html));
        // Both name and seat diverge from the extract.
        let id = create_entity(
            &state,
            "Nome Original, Lda",
            "503004642",
            "Porto",
            "SociedadePorQuotas",
        )
        .await;

        let (status, report) = send(
            state,
            post_json(
                &format!("/v1/entities/{id}/registry/import"),
                json!({ "code": "1234-5678-9012", "overwrite": true }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let applied: Vec<&str> = report["applied"]
            .as_array()
            .expect("applied")
            .iter()
            .map(|v| v.as_str().expect("field"))
            .collect();
        assert!(applied.contains(&"name"));
        assert!(applied.contains(&"seat"));
        assert_eq!(report["conflicts"].as_array().expect("conflicts").len(), 0);

        // Both fields now carry the extract's values.
        assert_eq!(report["entity"]["name"], "Encosto Estratégico, Lda");
        assert_eq!(report["entity"]["seat"], "Lisboa");
    }

    #[tokio::test]
    async fn import_appends_one_masked_event_and_never_the_full_code() {
        let html = certidao_html(
            "Encosto Estratégico, Lda",
            "503004642",
            "Sociedade por quotas",
            "Lisboa",
        );
        let state = state_with(MockRegistryTransport::empty().with_html(html));
        let id = create_entity(
            &state,
            "Nome Original, Lda",
            "503004642",
            "",
            "SociedadePorQuotas",
        )
        .await;

        let (status, _) = send(
            state.clone(),
            post_json(
                &format!("/v1/entities/{id}/registry/import"),
                json!({ "code": "1234-5678-9012" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (_, events) = send(state, get("/v1/ledger/events")).await;
        let imported: Vec<&Value> = events
            .as_array()
            .expect("events")
            .iter()
            .filter(|e| e["kind"] == "registry.imported")
            .collect();
        assert_eq!(imported.len(), 1, "exactly one registry.imported event");
        assert_eq!(imported[0]["scope"], id);
        assert_eq!(imported[0]["justification"], "registry import");

        // The full código de acesso must appear NOWHERE in the whole ledger dump.
        let dump = events.to_string();
        assert!(!dump.contains("1234-5678-9012"), "grouped code leaked");
        assert!(!dump.contains("123456789012"), "bare code leaked");
    }

    #[tokio::test]
    async fn import_from_registry_creates_a_consistent_entity_with_both_events() {
        let html = certidao_html(
            "Encosto Estratégico, S.A.",
            "503004642",
            "Sociedade Anónima",
            "Lisboa",
        );
        let state = state_with(MockRegistryTransport::empty().with_html(html));

        let (status, report) = send(
            state.clone(),
            post_json(
                "/v1/entities/import-from-registry",
                json!({ "code": "1234-5678-9012" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(report["entity"]["name"], "Encosto Estratégico, S.A.");
        assert_eq!(report["entity"]["nipc"], "503004642");
        assert_eq!(report["entity"]["kind"], "SociedadeAnonima");
        assert_eq!(report["entity"]["family"], "CommercialCompany");
        assert_eq!(report["conflicts"].as_array().expect("conflicts").len(), 0);
        let id = report["entity"]["id"].as_str().expect("id").to_owned();

        // The entity is queryable.
        let (status, _) = send(state.clone(), get(&format!("/v1/entities/{id}"))).await;
        assert_eq!(status, StatusCode::OK);

        // entity.created precedes registry.imported.
        let (_, events) = send(state, get("/v1/ledger/events")).await;
        let kinds: Vec<&str> = events
            .as_array()
            .expect("events")
            .iter()
            .map(|e| e["kind"].as_str().expect("kind"))
            .collect();
        let created = kinds.iter().position(|k| *k == "entity.created");
        let imported = kinds.iter().position(|k| *k == "registry.imported");
        assert!(created.is_some() && imported.is_some());
        assert!(
            created < imported,
            "entity.created before registry.imported"
        );
    }

    /// wp27-e3 (Part 3): an import naming an explicit tenant creates the entity **in that tenant**
    /// (not the hard-stamped default) and emits `entity.created` on the `tenant:{t}/...` scope so the
    /// imported entity joins its tenant chain — the registry analogue of e1's `create_entity` fix.
    #[tokio::test]
    async fn import_from_registry_creates_the_entity_in_the_named_tenant() {
        let html = certidao_html(
            "Encosto Estratégico, S.A.",
            "503004642",
            "Sociedade Anónima",
            "Lisboa",
        );
        let state = state_with(MockRegistryTransport::empty().with_html(html));
        let tenant = TenantId::new();
        assert_ne!(tenant, DEFAULT_TENANT_ID);
        state
            .tenants
            .write()
            .await
            .insert(tenant, chancela_core::Tenant::new("Encosto Group"));

        let (status, report) = send(
            state.clone(),
            post_json(
                "/v1/entities/import-from-registry",
                json!({ "code": "1234-5678-9012", "tenant_id": tenant.to_string() }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{report}");
        let id = report["entity"]["id"].as_str().expect("id");
        let eid = EntityId(Uuid::parse_str(id).expect("entity id is uuid"));

        // The imported entity carries the named tenant, not the singleton default.
        let stored_tenant = state
            .entities
            .read()
            .await
            .get(&eid)
            .expect("entity stored")
            .tenant_id;
        assert_eq!(
            stored_tenant, tenant,
            "imported entity must be created in the named tenant"
        );

        // `entity.created` joins the tenant chain (ChainId::Tenant).
        let ledger = state.ledger.read().await;
        let event = ledger
            .events()
            .iter()
            .find(|e| e.kind == "entity.created")
            .expect("entity.created emitted");
        assert_eq!(event.scope, format!("tenant:{tenant}/entity:{eid}"));
        let memberships = chancela_ledger::Ledger::memberships(&event.scope, "entity.created");
        assert!(
            memberships.contains(&chancela_ledger::ChainId::Tenant(tenant.to_string())),
            "imported entity must join its tenant chain, got {memberships:?}"
        );
    }

    /// wp27-e3 (Part 3): naming an **unknown** tenant is a non-enumerating `404` (after the authz
    /// check), and a body without `tenant_id` still creates under the default tenant (byte-identical).
    #[tokio::test]
    async fn import_from_registry_unknown_tenant_is_404_and_absent_defaults() {
        let html = certidao_html(
            "Encosto Estratégico, S.A.",
            "503004642",
            "Sociedade Anónima",
            "Lisboa",
        );
        let state = state_with(MockRegistryTransport::empty().with_html(html));

        let (status, _) = send(
            state.clone(),
            post_json(
                "/v1/entities/import-from-registry",
                json!({ "code": "1234-5678-9012", "tenant_id": TenantId::new().to_string() }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "unknown tenant is a 404");

        // Absent tenant → default tenant, unchanged behaviour.
        let (status, report) = send(
            state.clone(),
            post_json(
                "/v1/entities/import-from-registry",
                json!({ "code": "1234-5678-9012" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{report}");
        let eid =
            EntityId(Uuid::parse_str(report["entity"]["id"].as_str().expect("id")).expect("uuid"));
        assert_eq!(
            state
                .entities
                .read()
                .await
                .get(&eid)
                .expect("entity stored")
                .tenant_id,
            DEFAULT_TENANT_ID
        );
    }

    #[tokio::test]
    async fn import_from_registry_without_a_valid_nipc_is_422() {
        // The shipped SPQ fixture's NIPC (500002020) fails the mod-11 control digit, so no
        // entity can be created from it — the 422 must say what the certidão lacked.
        let state = state_with(MockRegistryTransport::from_fixture_spq());
        let (status, body) = send(
            state,
            post_json(
                "/v1/entities/import-from-registry",
                json!({ "code": "1234-5678-9012" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            body["error"]
                .as_str()
                .expect("error")
                .contains("valid NIPC"),
            "422 explains the missing valid NIPC: {}",
            body["error"]
        );
    }

    #[tokio::test]
    async fn lookup_with_a_malformed_code_is_422_without_echoing_it() {
        let state = state_with(MockRegistryTransport::from_fixture_spq());
        let (status, body) = send(
            state,
            post_json("/v1/registry/lookup", json!({ "code": "12-34" })),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        let error = body["error"].as_str().expect("error");
        // The message must never echo the (mistyped) digits.
        assert!(!error.contains("1234"), "code echoed: {error}");
    }

    /// A code the registry rejects is the **caller's** problem, not a gateway failure.
    ///
    /// This previously answered `502` + `code: "http.upstream"` + the scrubbed body "erro de
    /// gateway" — telling an operator who mistyped their código de acesso that a government service
    /// was down.
    #[tokio::test]
    async fn lookup_with_a_registry_rejected_code_is_422_and_does_not_blame_the_registry() {
        let state = state_with(MockRegistryTransport::from_fixture_code_rejected());
        let (status, body) = send(
            state,
            post_json("/v1/registry/lookup", json!({ "code": "1234-5678-9012" })),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body["code"], "registry.code_rejected");
        // The disjunction the registry actually stated is preserved, not resolved into "expired".
        let error = body["error"].as_str().expect("error");
        assert!(error.contains("invalid or expired"), "error: {error}");
        assert!(!error.contains("1234"), "code echoed: {error}");
    }

    /// "No certidão for that number" is a definite answer from a working service, and must not read
    /// as the service having failed.
    #[tokio::test]
    async fn lookup_with_no_such_certidao_is_422_and_distinct_from_a_rejected_code() {
        let state = state_with(MockRegistryTransport::from_fixture_not_found());
        let (status, body) = send(
            state,
            post_json("/v1/registry/lookup", json!({ "code": "1234-5678-9012" })),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body["code"], "registry.certidao_not_found");
    }

    /// A page we cannot classify stays `502` + `registry.unrecognized` — honestly unknown, never
    /// guessed into a claim about the operator's code.
    #[tokio::test]
    async fn lookup_on_an_unclassifiable_page_is_502_unrecognized() {
        let state = state_with(MockRegistryTransport::empty().with_html(
            "<!DOCTYPE html><html lang=\"pt-PT\"><body><p>Manutencao.</p></body></html>",
        ));
        let (status, body) = send(
            state,
            post_json("/v1/registry/lookup", json!({ "code": "1234-5678-9012" })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(body["code"], "registry.unrecognized");
    }

    #[tokio::test]
    async fn lookup_on_an_upstream_failure_is_502() {
        // An empty mock has no canned document → RegistryError::Upstream.
        let state = state_with(MockRegistryTransport::empty());
        let (status, body) = send(
            state,
            post_json("/v1/registry/lookup", json!({ "code": "1234-5678-9012" })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(body["code"], "registry.upstream");
        assert!(body["error"].is_string());
    }

    /// The load-bearing distinctness assertion: **no two failure modes may share a wire
    /// signature**. The UI branches on `code` alone, so a duplicate here silently re-collapses the
    /// taxonomy no matter how carefully the variants are written.
    ///
    /// Note the pairs this pins apart. A rejected code and an unreachable registry differ in
    /// *status*, so an operator is never told the company has no record when we simply got no
    /// answer. A rejected code and a missing certidão share a status but differ in *code*, because
    /// "this code is not valid" and "there is no such certidão" are different facts.
    #[tokio::test]
    async fn every_lookup_failure_mode_has_its_own_wire_signature() {
        use chancela_registry::RegistryError;

        // Each `RegistryError` → the (status, code) an operator's client actually observes.
        let observed: Vec<(u16, &str)> = vec![
            RegistryError::InvalidCode("12 digits required".to_owned()),
            RegistryError::CodeRejected("rejected".to_owned()),
            RegistryError::CertidaoNotFound("no certidão".to_owned()),
            RegistryError::Unreachable("timeout".to_owned()),
            RegistryError::CredentialsRejected("HTTP 403".to_owned()),
            RegistryError::QuotaExceeded("HTTP 429".to_owned()),
            RegistryError::Upstream("HTTP 500".to_owned()),
            RegistryError::Unrecognized("unknown page".to_owned()),
            RegistryError::Config("bad base URL".to_owned()),
        ]
        .into_iter()
        .map(|e| {
            let api = ApiError::from(e);
            let code = api.code();
            // Observed the way a client observes it — through the rendered response, not a
            // crate-private accessor.
            let status = axum::response::IntoResponse::into_response(api).status();
            (status.as_u16(), code)
        })
        .collect();

        let mut unique = observed.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(
            unique.len(),
            observed.len(),
            "two failure modes collapsed onto one wire signature: {observed:?}"
        );

        // Our own misconfiguration is a 500 — never a 502 blaming the registry for our defect.
        assert_eq!(
            observed[8],
            (500, "registry.config"),
            "a local misconfiguration must not be reported as a bad gateway"
        );
        // An unreachable service is a 502, and is NOT the 422 that would imply a bad code.
        assert_eq!(observed[3], (502, "registry.unreachable"));
        assert_eq!(observed[5], (502, "registry.quota_exceeded"));
        assert_eq!(observed[4], (502, "registry.credentials_rejected"));
    }

    #[tokio::test]
    async fn get_entity_registry_is_404_before_import_and_200_after() {
        let html = certidao_html(
            "Encosto Estratégico, Lda",
            "503004642",
            "Sociedade por quotas",
            "Lisboa",
        );
        let state = state_with(MockRegistryTransport::empty().with_html(html));
        let id = create_entity(
            &state,
            "Nome Original, Lda",
            "503004642",
            "",
            "SociedadePorQuotas",
        )
        .await;

        let (status, _) = send(state.clone(), get(&format!("/v1/entities/{id}/registry"))).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let (status, _) = send(
            state.clone(),
            post_json(
                &format!("/v1/entities/{id}/registry/import"),
                json!({ "code": "1234-5678-9012" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, view) = send(state, get(&format!("/v1/entities/{id}/registry"))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(view["nipc"], "503004642");
        assert_eq!(view["provenance"]["access_code_masked"], "****-****-9012");
    }

    #[tokio::test]
    async fn lookup_view_enriches_role_tagged_cae_from_the_catalog() {
        // A certidão with a Principal (catalogued Rev.4 code) and a Secundário (uncatalogued).
        let html = "<!DOCTYPE html><html lang=\"pt-PT\"><body><div class=\"matricula\">\
             <p>MATRÍCULA</p><table>\
             <tr><td>Matrícula:</td><td>99999/20200101</td></tr>\
             <tr><td>NIF/NIPC:</td><td>503004642</td></tr>\
             <tr><td>Firma:</td><td>Encosto Estratégico, Lda</td></tr>\
             <tr><td>Natureza Jurídica:</td><td>Sociedade por quotas</td></tr>\
             <tr><td>Sede:</td><td>Lisboa</td></tr>\
             <tr><td>CAE Principal:</td><td>68110 - Compra e venda de bens imobiliários</td></tr>\
             <tr><td>CAE Secundário:</td><td>99999</td></tr>\
             </table></div></body></html>"
            .to_owned();
        let state = state_with(MockRegistryTransport::empty().with_html(html));

        let (status, view) = send(
            state,
            post_json("/v1/registry/lookup", json!({ "code": "1234-5678-9012" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let cae = view["cae"].as_array().expect("cae array");
        assert_eq!(cae.len(), 2);

        // Principal: catalogued → role + designation + level + revision present.
        assert_eq!(cae[0]["code"], "68110");
        assert_eq!(cae[0]["role"], "Principal");
        assert_eq!(
            cae[0]["designation"],
            "Compra e venda de bens imobiliários."
        );
        assert_eq!(cae[0]["level"], "Subclasse");
        assert_eq!(cae[0]["revision"], "Rev4");

        // Secundário: uncatalogued code → role kept, enrichment fields null (honest).
        assert_eq!(cae[1]["code"], "99999");
        assert_eq!(cae[1]["role"], "Secundario");
        assert_eq!(cae[1]["designation"], Value::Null);
        assert_eq!(cae[1]["level"], Value::Null);
        assert_eq!(cae[1]["revision"], Value::Null);
    }

    /// A structurally faithful certidão carrying a validity window in its trailer, so the
    /// expiry/warnings paths can be exercised with a chosen `válida até` date.
    fn certidao_html_with_validity(nipc: &str, subscribed: &str, valid_until: &str) -> String {
        format!(
            "<!DOCTYPE html><html lang=\"pt-PT\"><body><div class=\"matricula\">\
             <p>MATRÍCULA</p><table>\
             <tr><td>Matrícula:</td><td>99999/20200101</td></tr>\
             <tr><td>NIF/NIPC:</td><td>{nipc}</td></tr>\
             <tr><td>Firma:</td><td>Encosto Estratégico, Lda</td></tr>\
             <tr><td>Natureza Jurídica:</td><td>Sociedade por quotas</td></tr>\
             <tr><td>Sede:</td><td>Lisboa</td></tr>\
             </table></div>\
             <div class=\"inscricoes\"><p>Inscrições - Averbamentos - Anotações</p>\
             <div><p>Insc. 1 AP. 1/20200101</p><p>CONSTITUIÇÃO DE SOCIEDADE</p></div>\
             <div class=\"trailer\">\
             <p>Conservatória do Registo Comercial do Porto</p>\
             <p>O(A) Oficial de Registos, Amélia Marques</p>\
             <p>Certidão permanente subscrita em {subscribed} e válida até {valid_until}.</p>\
             <p>Fim da Certidão</p></div>\
             </div></body></html>"
        )
    }

    #[test]
    fn compute_expired_is_true_only_for_a_parseable_past_date() {
        use time::macros::date;
        let today = date!(2026 - 07 - 07);
        assert_eq!(compute_expired(Some("2021-01-01"), today), Some(true));
        assert_eq!(compute_expired(Some("2099-01-01"), today), Some(false));
        // Today itself is not "before today" → not expired.
        assert_eq!(compute_expired(Some("2026-07-07"), today), Some(false));
        // Absent or unparseable → we do not claim an expiry we cannot compute.
        assert_eq!(compute_expired(None, today), None);
        assert_eq!(compute_expired(Some("not-a-date"), today), None);
    }

    #[tokio::test]
    async fn lookup_surfaces_the_structured_constitution_payload_and_meta() {
        // The rich constitution specimen: minimal matrícula block, full constitution body.
        let state = state_with(MockRegistryTransport::from_fixture_constituicao());
        let (status, view) = send(
            state,
            post_json("/v1/registry/lookup", json!({ "code": "1234-5678-9012" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // The structured layer renders per the frozen internally-tagged encoding.
        let detail = &view["inscricoes"][0]["detail"];
        assert_eq!(detail["payload"]["type"], "Constitution");
        assert_eq!(detail["payload"]["firma"], "Encosto Estratégico, Lda");
        assert_eq!(detail["payload"]["nipc"], "503004642");
        assert_eq!(detail["payload"]["sede"]["freguesia"], "Cedofeita");
        assert_eq!(detail["payload"]["sede"]["postal_code"], "4000-111");
        assert_eq!(detail["payload"]["capital"]["amount_text"], "100,00");
        assert_eq!(view["matricula"], "C-9001/20260501");
        assert_eq!(view["data_constituicao"], "2026-05-11");
        let socios = detail["payload"]["socios"].as_array().expect("socios");
        assert_eq!(socios.len(), 2);
        assert_eq!(socios[0]["titular"]["name"], "Rui Tavares Nogueira");
        assert_eq!(socios[0]["titular"]["estado_civil"], "casado");
        assert_eq!(socios[0]["titular"]["nacionalidade"], "Portuguesa");
        let orgaos = detail["payload"]["orgaos"].as_array().expect("orgaos");
        assert!(
            orgaos[0]["name"]
                .as_str()
                .expect("organ name")
                .contains("GER")
        );
        assert_eq!(orgaos[0]["members"][0]["cargo"], "Gerente");

        // Multi-act apresentação: both act kinds + the UTC timestamp.
        let ap = &detail["apresentacao"];
        assert_eq!(ap["number"], "1");
        assert_eq!(ap["time"], "00:55:25 UTC");
        assert_eq!(ap["act_kinds"].as_array().expect("act_kinds").len(), 2);

        // Anotações + conservatória/oficial + validity surface on the view.
        let anot = view["anotacoes"].as_array().expect("anotacoes");
        assert_eq!(anot.len(), 1);
        assert!(
            anot[0]["publication_url"]
                .as_str()
                .expect("url")
                .contains("publicacoes.mj.pt")
        );
        let prov = &view["provenance"];
        assert!(
            prov["conservatoria"]
                .as_str()
                .expect("conservatoria")
                .contains("Porto")
        );
        assert_eq!(prov["oficial"], "Amélia Marques");
        assert_eq!(prov["subscribed_on"], "2026-07-05");
        assert_eq!(prov["valid_until"], "2027-07-05");
        // The specimen is valid past today's fixed anchor → not expired.
        assert_eq!(prov["expired"], false);
    }

    #[tokio::test]
    async fn import_backfills_blank_identity_from_the_constitution_body() {
        // The constituição specimen's matrícula block is blank; identity lives in the body.
        let state = state_with(MockRegistryTransport::from_fixture_constituicao());
        // Existing entity: matching NIPC, a divergent name, a blank seat to be backfilled.
        let id = create_entity(
            &state,
            "Nome Original, Lda",
            "503004642",
            "",
            "SociedadePorQuotas",
        )
        .await;

        let (status, report) = send(
            state,
            post_json(
                &format!("/v1/entities/{id}/registry/import"),
                json!({ "code": "1234-5678-9012" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let applied: Vec<&str> = report["applied"]
            .as_array()
            .expect("applied")
            .iter()
            .map(|v| v.as_str().expect("field"))
            .collect();
        // Seat was blank → backfilled from the constitution body's SEDE.
        assert!(applied.contains(&"seat"), "seat backfilled: {applied:?}");
        assert!(
            report["entity"]["seat"]
                .as_str()
                .expect("seat")
                .contains("Rua do Comércio")
        );
        // The divergent name is kept as a conflict, sourced from the body's FIRMA.
        let conflicts = report["conflicts"].as_array().expect("conflicts");
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0]["field"], "name");
        assert_eq!(conflicts[0]["incoming"], "Encosto Estratégico, Lda");
    }

    #[tokio::test]
    async fn expired_certidao_surfaces_expired_flag_and_import_warning() {
        let html = certidao_html_with_validity("503004642", "01/01/2020", "01/01/2021");
        let state = state_with(MockRegistryTransport::empty().with_html(html));

        // Lookup computes `expired: true` against today.
        let (status, view) = send(
            state.clone(),
            post_json("/v1/registry/lookup", json!({ "code": "1234-5678-9012" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(view["provenance"]["valid_until"], "2021-01-01");
        assert_eq!(view["provenance"]["expired"], true);

        // Create-from-registry still succeeds (201) but carries the expiry warning.
        let (status, report) = send(
            state,
            post_json(
                "/v1/entities/import-from-registry",
                json!({ "code": "1234-5678-9012" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let warnings: Vec<&str> = report["warnings"]
            .as_array()
            .expect("warnings")
            .iter()
            .map(|v| v.as_str().expect("warning"))
            .collect();
        assert_eq!(warnings, vec!["certidão expirada em 2021-01-01"]);
    }

    #[tokio::test]
    async fn a_valid_certidao_import_reports_no_warnings() {
        let html = certidao_html_with_validity("503004642", "01/01/2099", "31/12/2099");
        let state = state_with(MockRegistryTransport::empty().with_html(html));
        let (status, report) = send(
            state,
            post_json(
                "/v1/entities/import-from-registry",
                json!({ "code": "1234-5678-9012" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(report["extract"]["provenance"]["expired"], false);
        assert_eq!(report["warnings"].as_array().expect("warnings").len(), 0);
    }

    #[tokio::test]
    async fn import_into_a_missing_entity_is_404() {
        let html = certidao_html("X, Lda", "503004642", "Sociedade por quotas", "Lisboa");
        let state = state_with(MockRegistryTransport::empty().with_html(html));
        let missing = Uuid::new_v4();
        let (status, _) = send(
            state,
            post_json(
                &format!("/v1/entities/{missing}/registry/import"),
                json!({ "code": "1234-5678-9012" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    /// t60-e3 (D3): re-importing the extract rewrites the entity's own content — firma, seat, legal
    /// form. An archived entity is frozen against that, mirroring the `CompanyGroup` precedent's
    /// *"archived groups cannot be edited"*. Unarchive → edit → re-archive is the escape hatch, and
    /// it is fully audited, which is why freezing costs nothing an operator cannot undo.
    ///
    /// This is `import_into_entity`. Its sibling `import_from_registry` **creates** an entity and is
    /// deliberately unguarded: an entity that does not exist yet cannot be archived, so the check
    /// would be meaningless there. The two are different handlers on different routes.
    #[tokio::test]
    async fn registry_import_into_an_archived_entity_is_refused() {
        let html = certidao_html(
            "Encosto Estratégico, Lda",
            "503004642",
            "Sociedade por quotas",
            "Avenida da Liberdade, Lisboa",
        );
        let state = state_with(MockRegistryTransport::empty().with_html(html));
        let id = create_entity(
            &state,
            "Encosto Estratégico, Lda",
            "503004642",
            "Avenida da Liberdade, Lisboa",
            "SociedadePorQuotas",
        )
        .await;

        // Archive through the core transition (the route is t60-e2's, landing in parallel).
        let eid = EntityId(Uuid::parse_str(&id).expect("entity uuid"));
        let before = {
            let mut entities = state.entities.write().await;
            let entity = entities.get_mut(&eid).expect("entity in the read model");
            entity
                .archive(time::OffsetDateTime::now_utc())
                .expect("an active entity archives");
            entity.clone()
        };

        let (status, body) = send(
            state.clone(),
            post_json(
                &format!("/v1/entities/{id}/registry/import"),
                json!({ "code": "1234-5678-9012" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        let error = body["error"].as_str().unwrap_or_default();
        assert!(
            error.contains("is archived")
                && error.contains("Encosto Estratégico, Lda")
                && error.contains("Unarchive it first"),
            "the refusal must name the entity and the remedy: {body}"
        );

        // Refused before the cross-check, so not one field moved.
        let after = state
            .entities
            .read()
            .await
            .get(&eid)
            .expect("an archived entity is never removed from the read model")
            .clone();
        assert_eq!(
            serde_json::to_value(&before).expect("serializes"),
            serde_json::to_value(&after).expect("serializes"),
            "a refused import must leave the entity byte-identical"
        );
    }
}
