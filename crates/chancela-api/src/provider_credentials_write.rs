//! Write / management HTTP API for provider-credential **entries** (wp13 Phase B).
//!
//! These handlers sit on top of the Phase A store ([`crate::secretstore_persist`]) and give
//! operators a create / update / delete / reorder / enable-disable surface over the ordered
//! per-`(mode, provider_id)` [`CredentialEntry`](crate::CredentialEntry) list. They live in a module
//! separate from the read-only [`crate::provider_credentials`] status endpoint.
//!
//! ## Security posture (plan §3/§6)
//!
//! - **Secrets are write-only.** A secret value (client secret, access token, HTTP-Basic password,
//!   PKCS#12 blob + passphrase, …) can only ever be *sent in*. No response type carries a secret,
//!   ciphertext, `last4`, or the PFX — only entry id / label / priority / enabled / endpoint /
//!   selectors and a per-field `configured` flag. The response DTOs are metadata-only *by
//!   construction* (there is no secret-typed field anywhere in [`EntryView`]).
//! - **Fail closed.** Storing a secret with no key source, or in strict mode with a non-confidential
//!   protection level, is refused with an actionable 409 before anything is persisted (the store's
//!   `wrap` enforces this; [`map_store_err`] renders the clean message). A server with no data
//!   directory is a 422 instead, because the operator's next step is persistence, not a key.
//! - **Sanitized audit.** Every mutation appends a ledger event carrying only mode / provider_id /
//!   entry_id / action / changed field NAMES / enabled / priority — never a secret value.
//! - **Gating.** Mutations require `settings.manage`; the management list requires `settings.read`
//!   (the same gate the status endpoint uses). No new permission is introduced.

use std::collections::BTreeMap;
use std::fmt;

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use chancela_authz::{Permission, Scope};
use serde::{Deserialize, Deserializer, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::actor::{CurrentActor, CurrentAttestor};
use crate::authz::require_permission;
use crate::error::ApiError;
use crate::secretstore::SecretStoreError;
use crate::secretstore_persist::CredentialEntryMetadataView;
use crate::{AppState, CredentialMode, EntryMetadata, EntrySelectors, ProviderCredentialError};

/// The ledger scope every provider-credential mutation is recorded under.
const AUDIT_SCOPE: &str = "provider_credentials";

/// Offload a blocking provider-credential store mutation onto the blocking pool (wp28). The write
/// helpers (`put_entry`/`delete_entry`/`reorder_entries`) reconcile the encrypted records into the
/// shared `provider_credentials` table via a **synchronous** store write; under the `postgres`
/// backend that drives its connector — and `postgres::Client::Drop` — through an internal
/// `Runtime::block_on`, which panics and aborts the process when run directly on a tokio runtime
/// worker. `spawn_blocking` moves it off the worker; the cloned `Arc` handle is dropped inside the
/// blocking thread. A panic in the closure is re-raised on the caller (matching the previous inline
/// synchronous call). The closure returns owned data (a `Result`), never a borrow of the store.
async fn offload_credentials<T, F>(state: &AppState, f: F) -> T
where
    T: Send + 'static,
    F: FnOnce(&crate::ProviderCredentialStore) -> T + Send + 'static,
{
    let credentials = state.provider_credentials.clone();
    match tokio::task::spawn_blocking(move || f(&credentials)).await {
        Ok(result) => result,
        Err(join_error) => std::panic::resume_unwind(join_error.into_panic()),
    }
}

// --- Request DTOs (secret fields are write-only, redacted from `Debug`) --------------------------

/// A write-only secret value. Deserializes from a JSON string, holds the plaintext only in a
/// [`Zeroizing`] buffer, and redacts itself from `Debug` so a request struct can never leak a secret
/// through a log line or panic message.
struct SecretField(Zeroizing<String>);

impl<'de> Deserialize<'de> for SecretField {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Ok(SecretField(Zeroizing::new(value)))
    }
}

impl fmt::Debug for SecretField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretField(***)")
    }
}

/// `POST …/entries` body — create a new entry. A new entry must set at least one secret field (an
/// entry with no fields is not persisted).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateEntryRequest {
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    priority: Option<i32>,
    #[serde(default)]
    endpoint: Option<String>,
    #[serde(default)]
    selectors: Option<BTreeMap<String, String>>,
    #[serde(default)]
    set: BTreeMap<String, SecretField>,
}

/// `PATCH …/entries/{entry_id}` body — partial update. Every field is optional; an absent field is
/// left unchanged. `set` writes/replaces secret fields, `clear` removes them; toggling `enabled`
/// enables/disables the entry, and `priority` sets its failover order.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateEntryRequest {
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    priority: Option<i32>,
    #[serde(default)]
    endpoint: Option<String>,
    #[serde(default)]
    selectors: Option<BTreeMap<String, String>>,
    #[serde(default)]
    set: BTreeMap<String, SecretField>,
    #[serde(default)]
    clear: Vec<String>,
}

/// `POST …/entries/reorder` body — the new priority order. Must be a permutation of the record's
/// current entry ids; the server writes contiguous `priority` values in this order.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReorderRequest {
    order: Vec<String>,
}

// --- Response DTOs (metadata only — no secret-typed field anywhere) ------------------------------

/// One non-secret credential field in a response: its name and whether a value is configured. There
/// is deliberately no value/`last4`/ciphertext field — secrets are write-only.
#[derive(Debug, Serialize)]
pub struct FieldView {
    pub field_name: String,
    pub configured: bool,
}

/// Metadata-only view of one entry returned by every write handler and the management list.
#[derive(Debug, Serialize)]
pub struct EntryView {
    pub entry_id: String,
    pub label: String,
    pub priority: i32,
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    pub selectors: BTreeMap<String, String>,
    pub fields: Vec<FieldView>,
    pub created_at: String,
    pub updated_at: String,
}

impl From<CredentialEntryMetadataView> for EntryView {
    fn from(view: CredentialEntryMetadataView) -> Self {
        EntryView {
            entry_id: view.entry_id,
            label: view.label,
            priority: view.priority,
            enabled: view.enabled,
            endpoint: view.endpoint,
            selectors: view.selectors,
            // Surface only the field NAME + a configured flag; never the `last4` hint or any value.
            fields: view
                .fields
                .into_iter()
                .map(|(field_name, _last4)| FieldView {
                    field_name,
                    configured: true,
                })
                .collect(),
            created_at: view.created_at,
            updated_at: view.updated_at,
        }
    }
}

/// The result of a single-entry mutation (create/update/delete). Secrets never appear.
#[derive(Debug, Serialize)]
pub struct EntryMutationResponse {
    pub mode: &'static str,
    pub provider_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry: Option<EntryView>,
    pub deleted: bool,
}

/// The entries of one `(mode, provider_id)` record after a bulk operation (reorder).
#[derive(Debug, Serialize)]
pub struct EntryListResponse {
    pub mode: &'static str,
    pub provider_id: String,
    pub entries: Vec<EntryView>,
}

/// One provider's entries in the management list.
#[derive(Debug, Serialize)]
pub struct ProviderEntriesView {
    pub mode: &'static str,
    pub provider_id: String,
    pub entries: Vec<EntryView>,
}

/// `GET …/provider-credentials` management list (metadata only).
///
/// The three storage fields are what the settings UI renders its banner from, and they hold one
/// invariant: **`protection_level` is `Some` exactly when `can_store` is true.** Before t36 the
/// field was simply the *current* root's level, so it went absent whenever no root key could be
/// resolved — and the UI, reading "not confidential", told the operator their secrets were kept
/// with weaker "obfuscation" protection in precisely the case where nothing could be stored at
/// all. See [`storage_status`].
#[derive(Debug, Serialize)]
pub struct ProviderCredentialsListResponse {
    pub strict: bool,
    /// The protection a secret stored through this store *would receive*, or `None` when no secret
    /// can be stored at all.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protection_level: Option<crate::secretstore::ProtectionLevel>,
    /// Whether the store can accept a secret right now.
    pub can_store: bool,
    /// Sanitized reason it cannot, when `can_store` is false. Same vocabulary as the `key_failure`
    /// of the read-only status endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_failure: Option<&'static str>,
    pub providers: Vec<ProviderEntriesView>,
}

/// Resolve the honest storage triple from a read-only key-status probe.
///
/// The one case that is neither "available" nor "cannot store" is a Windows host whose DPAPI root
/// envelope has not been written yet (`MissingRootEnvelope`): the key *source* is present and the
/// first write seals the root, so storing works and the resulting protection is `Confidential`.
/// Reporting that prospectively is what lets `protection_level.is_none()` mean exactly one thing.
fn storage_status(
    key_status: &crate::secretstore::CredentialKeyReadOnlyStatus,
) -> (
    Option<crate::secretstore::ProtectionLevel>,
    bool,
    Option<&'static str>,
) {
    use crate::secretstore::{CredentialKeySource, CredentialKeyStatusFailure, ProtectionLevel};

    if key_status.available {
        return (key_status.protection_level, true, None);
    }
    let pending_os_root = matches!(
        key_status.failure,
        Some(CredentialKeyStatusFailure::MissingRootEnvelope)
    ) && matches!(
        key_status.key_source,
        Some(CredentialKeySource::OsProtected { .. })
    );
    if pending_os_root {
        return (Some(ProtectionLevel::Confidential), true, None);
    }
    (
        None,
        false,
        key_status
            .failure
            .map(crate::provider_credentials::key_failure_code),
    )
}

// --- Handlers ------------------------------------------------------------------------------------

/// `POST /v1/signature/provider-credentials/{mode}/{provider_id}/entries` — create an entry.
pub async fn create_entry(
    State(state): State<AppState>,
    Path((mode_raw, provider_raw)): Path<(String, String)>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    body: Bytes,
) -> Result<(StatusCode, Json<EntryMutationResponse>), ApiError> {
    require_permission(&state, &actor, Permission::SettingsManage, Scope::Global).await?;
    let mode = parse_mode(&mode_raw)?;
    let provider_id = resolve_provider(mode, &provider_raw)?;
    let req: CreateEntryRequest = parse_body(&body)?;

    if req.set.is_empty() {
        return Err(ApiError::Unprocessable(
            "a new credential entry must set at least one secret field".to_owned(),
        ));
    }
    let set_names: Vec<String> = req.set.keys().cloned().collect();
    let set = build_set(mode, req.set)?;

    let priority = match req.priority {
        Some(p) => p,
        None => next_priority(&state, mode, &provider_id)?,
    };
    let entry_id = Uuid::new_v4().to_string();
    let metadata = EntryMetadata {
        label: req.label.unwrap_or_default(),
        priority,
        enabled: req.enabled.unwrap_or(true),
        endpoint: req.endpoint,
        selectors: req.selectors.map(into_selectors).unwrap_or_default(),
    };
    let (audit_priority, audit_enabled) = (metadata.priority, metadata.enabled);

    let write_provider = provider_id.clone();
    let write_entry = entry_id.clone();
    offload_credentials(&state, move |creds| {
        creds.put_entry(
            mode,
            &write_provider,
            &write_entry,
            Some(metadata),
            set,
            &[],
        )
    })
    .await
    .map_err(map_store_err)?;

    audit(
        &state,
        &actor,
        &attestor,
        "provider.credentials.entry.created",
        mutation_audit_payload(
            mode,
            &provider_id,
            &entry_id,
            "created",
            &set_names,
            &[],
            audit_enabled,
            audit_priority,
        ),
    )
    .await?;

    let entry = fetch_entry(&state, mode, &provider_id, &entry_id)?;
    Ok((
        StatusCode::CREATED,
        Json(EntryMutationResponse {
            mode: mode.as_str(),
            provider_id,
            entry,
            deleted: false,
        }),
    ))
}

/// `PATCH /v1/signature/provider-credentials/{mode}/{provider_id}/entries/{entry_id}` — update.
pub async fn update_entry(
    State(state): State<AppState>,
    Path((mode_raw, provider_raw, entry_id)): Path<(String, String, String)>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    body: Bytes,
) -> Result<Json<EntryMutationResponse>, ApiError> {
    require_permission(&state, &actor, Permission::SettingsManage, Scope::Global).await?;
    let mode = parse_mode(&mode_raw)?;
    let provider_id = resolve_provider(mode, &provider_raw)?;
    let req: UpdateEntryRequest = parse_body(&body)?;

    // Merge over the current (non-decrypting) metadata so an absent field is left unchanged.
    let current =
        fetch_entry_metadata(&state, mode, &provider_id, &entry_id)?.ok_or(ApiError::NotFound)?;

    let set_names: Vec<String> = req.set.keys().cloned().collect();
    let set = build_set(mode, req.set)?;
    let clear = build_clear(mode, &req.clear)?;

    let metadata = EntryMetadata {
        label: req.label.unwrap_or(current.label),
        priority: req.priority.unwrap_or(current.priority),
        enabled: req.enabled.unwrap_or(current.enabled),
        endpoint: req.endpoint.or(current.endpoint),
        selectors: req
            .selectors
            .map(into_selectors)
            .unwrap_or(current.selectors),
    };
    let (audit_priority, audit_enabled) = (metadata.priority, metadata.enabled);

    let write_provider = provider_id.clone();
    let write_entry = entry_id.clone();
    offload_credentials(&state, move |creds| {
        creds.put_entry(
            mode,
            &write_provider,
            &write_entry,
            Some(metadata),
            set,
            &clear,
        )
    })
    .await
    .map_err(map_store_err)?;

    audit(
        &state,
        &actor,
        &attestor,
        "provider.credentials.entry.updated",
        mutation_audit_payload(
            mode,
            &provider_id,
            &entry_id,
            "updated",
            &set_names,
            &req.clear,
            audit_enabled,
            audit_priority,
        ),
    )
    .await?;

    let entry = fetch_entry(&state, mode, &provider_id, &entry_id)?;
    // If every field was cleared the entry is dropped by the store; report it as removed.
    let deleted = entry.is_none();
    Ok(Json(EntryMutationResponse {
        mode: mode.as_str(),
        provider_id,
        entry,
        deleted,
    }))
}

/// `DELETE /v1/signature/provider-credentials/{mode}/{provider_id}/entries/{entry_id}` — remove one.
pub async fn delete_entry(
    State(state): State<AppState>,
    Path((mode_raw, provider_raw, entry_id)): Path<(String, String, String)>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
) -> Result<Json<EntryMutationResponse>, ApiError> {
    require_permission(&state, &actor, Permission::SettingsManage, Scope::Global).await?;
    let mode = parse_mode(&mode_raw)?;
    let provider_id = resolve_provider(mode, &provider_raw)?;

    let write_provider = provider_id.clone();
    let write_entry = entry_id.clone();
    let removed = offload_credentials(&state, move |creds| {
        creds.delete_entry(mode, &write_provider, &write_entry)
    })
    .await
    .map_err(map_store_err)?;
    if !removed {
        return Err(ApiError::NotFound);
    }

    audit(
        &state,
        &actor,
        &attestor,
        "provider.credentials.entry.deleted",
        mutation_audit_payload(mode, &provider_id, &entry_id, "deleted", &[], &[], false, 0),
    )
    .await?;

    Ok(Json(EntryMutationResponse {
        mode: mode.as_str(),
        provider_id,
        entry: None,
        deleted: true,
    }))
}

/// `POST /v1/signature/provider-credentials/{mode}/{provider_id}/entries/reorder` — set priority.
pub async fn reorder_entries(
    State(state): State<AppState>,
    Path((mode_raw, provider_raw)): Path<(String, String)>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    body: Bytes,
) -> Result<Json<EntryListResponse>, ApiError> {
    require_permission(&state, &actor, Permission::SettingsManage, Scope::Global).await?;
    let mode = parse_mode(&mode_raw)?;
    let provider_id = resolve_provider(mode, &provider_raw)?;
    let req: ReorderRequest = parse_body(&body)?;

    let current = state
        .provider_credentials
        .entry_metadata(mode, &provider_id)
        .map_err(map_store_err)?;
    if current.is_empty() {
        return Err(ApiError::NotFound);
    }

    // The order must be a permutation of the current entry ids (no missing, no extra, no dupes).
    let mut existing: Vec<String> = current.iter().map(|e| e.entry_id.clone()).collect();
    let mut requested = req.order.clone();
    existing.sort();
    requested.sort();
    if existing != requested {
        return Err(ApiError::Unprocessable(
            "reorder `order` must be a permutation of the record's current entry ids".to_owned(),
        ));
    }

    // Apply the whole reorder under a single records-lock acquisition (L2): atomic all-or-nothing,
    // rather than a sequence of per-entry `put_entry` writes that could persist a partially-applied
    // ordering if a later write failed mid-loop. The permutation was validated against `current` above;
    // each entry keeps its label/enabled/endpoint/selectors/fields and only its priority is updated.
    let write_provider = provider_id.clone();
    let write_order = req.order.clone();
    offload_credentials(&state, move |creds| {
        creds.reorder_entries(mode, &write_provider, &write_order)
    })
    .await
    .map_err(map_store_err)?;

    audit(
        &state,
        &actor,
        &attestor,
        "provider.credentials.entries.reordered",
        serde_json::json!({
            "mode": mode.as_str(),
            "provider_id": provider_id,
            "action": "reordered",
            "order": req.order,
        }),
    )
    .await?;

    let entries = state
        .provider_credentials
        .entry_metadata(mode, &provider_id)
        .map_err(map_store_err)?
        .into_iter()
        .map(EntryView::from)
        .collect();
    Ok(Json(EntryListResponse {
        mode: mode.as_str(),
        provider_id,
        entries,
    }))
}

/// `GET /v1/signature/provider-credentials` — management list of every provider's entries (metadata
/// only). Gated `settings.read`.
pub async fn list_provider_credentials(
    State(state): State<AppState>,
    actor: CurrentActor,
) -> Result<Json<ProviderCredentialsListResponse>, ApiError> {
    require_permission(&state, &actor, Permission::SettingsRead, Scope::Global).await?;

    let statuses = state
        .provider_credentials
        .statuses()
        .map_err(map_store_err)?;
    let mut providers = Vec::with_capacity(statuses.len());
    for record in &statuses {
        // The SMTP relay account rides the same store but is not a signing provider; it belongs to
        // the mail settings screen, so it must not appear in the Assinaturas list.
        if record.mode == CredentialMode::Smtp {
            continue;
        }
        let entries = state
            .provider_credentials
            .entry_metadata(record.mode, &record.provider_id)
            .map_err(map_store_err)?
            .into_iter()
            .map(EntryView::from)
            .collect();
        providers.push(ProviderEntriesView {
            mode: record.mode.as_str(),
            provider_id: record.provider_id.clone(),
            entries,
        });
    }

    let (protection_level, can_store, storage_failure) =
        storage_status(&state.provider_credentials.key_status());
    Ok(Json(ProviderCredentialsListResponse {
        strict: state.provider_credentials.strict(),
        protection_level,
        can_store,
        storage_failure,
        providers,
    }))
}

// --- Helpers -------------------------------------------------------------------------------------

fn parse_body<T: for<'de> Deserialize<'de>>(body: &Bytes) -> Result<T, ApiError> {
    serde_json::from_slice(body)
        .map_err(|e| ApiError::Unprocessable(format!("invalid request body: {e}")))
}

fn parse_mode(raw: &str) -> Result<CredentialMode, ApiError> {
    let mode = CredentialMode::from_wire(raw)
        .ok_or_else(|| ApiError::Unprocessable(format!("unknown credential mode {raw:?}")))?;
    // `smtp` shares the credential store but is NOT a signing provider: it is owned by the mail
    // settings (`PUT /v1/settings/email`), which enforces its own shape. Rejecting it here keeps the
    // two surfaces from writing the same record with different validation.
    if mode == CredentialMode::Smtp {
        return Err(ApiError::Unprocessable(format!(
            "unknown credential mode {raw:?}"
        )));
    }
    Ok(mode)
}

/// Resolve the path provider segment. The literal `_` denotes the single-instance provider (`""`).
/// CMD/SCAP are single-instance (must be `_`); CSC/PKCS#12 require a non-empty provider id.
fn resolve_provider(mode: CredentialMode, raw: &str) -> Result<String, ApiError> {
    let provider_id = if raw == "_" {
        String::new()
    } else {
        raw.to_owned()
    };
    match mode {
        // `Smtp` is unreachable here — `parse_mode` refuses it before this point — but it is
        // single-instance, so it groups with the other single-instance modes rather than widening
        // the match to a catch-all that would silently absorb a future mode.
        CredentialMode::Cmd | CredentialMode::Scap | CredentialMode::Smtp => {
            if !provider_id.is_empty() {
                return Err(ApiError::Unprocessable(format!(
                    "mode {} is single-instance; use \"_\" as the provider id",
                    mode.as_str()
                )));
            }
        }
        CredentialMode::CscQtsp | CredentialMode::LocalPkcs12 => {
            if provider_id.is_empty() {
                return Err(ApiError::Unprocessable(format!(
                    "mode {} requires a non-empty provider id",
                    mode.as_str()
                )));
            }
        }
    }
    Ok(provider_id)
}

/// Resolve a request field name to its stable `&'static str` constant for `mode`, rejecting any
/// field that is not valid for that mode.
fn resolve_field(mode: CredentialMode, name: &str) -> Result<&'static str, ApiError> {
    mode.field_names()
        .iter()
        .copied()
        .find(|field| *field == name)
        .ok_or_else(|| {
            ApiError::Unprocessable(format!(
                "{name:?} is not a valid credential field for mode {}",
                mode.as_str()
            ))
        })
}

fn build_set(
    mode: CredentialMode,
    set: BTreeMap<String, SecretField>,
) -> Result<Vec<(&'static str, Zeroizing<String>)>, ApiError> {
    let mut pairs = Vec::with_capacity(set.len());
    for (name, value) in set {
        let field = resolve_field(mode, &name)?;
        pairs.push((field, value.0));
    }
    Ok(pairs)
}

fn build_clear(mode: CredentialMode, clear: &[String]) -> Result<Vec<&'static str>, ApiError> {
    clear.iter().map(|name| resolve_field(mode, name)).collect()
}

fn into_selectors(map: BTreeMap<String, String>) -> EntrySelectors {
    map.into_iter().collect()
}

/// The next priority to append at: one past the current maximum, or 0 when the record is empty.
fn next_priority(
    state: &AppState,
    mode: CredentialMode,
    provider_id: &str,
) -> Result<i32, ApiError> {
    let entries = state
        .provider_credentials
        .entry_metadata(mode, provider_id)
        .map_err(map_store_err)?;
    Ok(entries
        .iter()
        .map(|e| e.priority)
        .max()
        .map(|max| max.saturating_add(1))
        .unwrap_or(0))
}

fn fetch_entry_metadata(
    state: &AppState,
    mode: CredentialMode,
    provider_id: &str,
    entry_id: &str,
) -> Result<Option<CredentialEntryMetadataView>, ApiError> {
    Ok(state
        .provider_credentials
        .entry_metadata(mode, provider_id)
        .map_err(map_store_err)?
        .into_iter()
        .find(|e| e.entry_id == entry_id))
}

fn fetch_entry(
    state: &AppState,
    mode: CredentialMode,
    provider_id: &str,
    entry_id: &str,
) -> Result<Option<EntryView>, ApiError> {
    Ok(fetch_entry_metadata(state, mode, provider_id, entry_id)?.map(EntryView::from))
}

/// Build the sanitized ledger payload for a single-entry mutation. Carries only field NAMES and
/// non-secret ordering/enabled deltas — never a secret value.
#[allow(clippy::too_many_arguments)]
fn mutation_audit_payload(
    mode: CredentialMode,
    provider_id: &str,
    entry_id: &str,
    action: &str,
    fields_set: &[String],
    fields_cleared: &[String],
    enabled: bool,
    priority: i32,
) -> serde_json::Value {
    serde_json::json!({
        "mode": mode.as_str(),
        "provider_id": provider_id,
        "entry_id": entry_id,
        "action": action,
        "fields_set": fields_set,
        "fields_cleared": fields_cleared,
        "enabled": enabled,
        "priority": priority,
    })
}

/// Append a sanitized audit event, persist it through the durable store, and best-effort attest it
/// (mirrors [`crate::settings::put_settings`]).
async fn audit(
    state: &AppState,
    actor: &CurrentActor,
    attestor: &CurrentAttestor,
    kind: &str,
    payload: serde_json::Value,
) -> Result<(), ApiError> {
    let actor_label = actor.resolve("system");
    let bytes = serde_json::to_vec(&payload).unwrap_or_default();
    let mut ledger = state.ledger.write().await;
    ledger.append(&actor_label, AUDIT_SCOPE, kind, None, &bytes);
    state
        .persist_write_through(&mut ledger, 1, |_tx| Ok(()))
        .await?;
    state.attest_latest(attestor, &ledger).await;
    Ok(())
}

/// Render a store error as a clean HTTP status. Never echoes secret material.
fn map_store_err(err: ProviderCredentialError) -> ApiError {
    map_store_err_for("provider-credential secrets", err)
}

/// [`map_store_err`] with the subject named, so the store's other owner (t23's SMTP relay password)
/// gets the same fail-closed messages without saying "provider credential" to an operator who is
/// configuring mail.
pub(crate) fn map_store_err_for(subject: &str, err: ProviderCredentialError) -> ApiError {
    match err {
        ProviderCredentialError::Secret(SecretStoreError::NoKeySource) => {
            ApiError::Conflict(format!(
                "cannot store {subject}: {}",
                crate::secretstore::no_key_source_guidance()
            ))
        }
        // Mirrors the register of the other "this server has no data dir" refusals (`backup.rs`,
        // `data_status.rs`, `connector_jobs.rs`): a 422 naming the variable to set.
        ProviderCredentialError::NotPersistent => ApiError::Unprocessable(format!(
            "cannot store {subject}: this server is running in-memory, so there is nowhere to \
             persist them or to seal a credential key. Set {} to a writable directory and restart.",
            crate::DATA_DIR_ENV
        )),
        ProviderCredentialError::Secret(SecretStoreError::StrictModeUnprotected { level }) => {
            ApiError::Conflict(format!(
                "strict credential storage is enabled but the protection level is {level} (not \
                 confidential); enable SQLCipher or OS sealing before storing secrets"
            ))
        }
        ProviderCredentialError::RuntimeStrictModeUnprotected { level } => {
            ApiError::Conflict(format!(
                "strict credential storage requires confidential protection (current: {level})"
            ))
        }
        ProviderCredentialError::CorruptSidecar(_) => ApiError::Conflict(
            "the provider-credential store is failing closed until its sidecar is repaired"
                .to_owned(),
        ),
        ProviderCredentialError::UnknownField { mode, field } => ApiError::Unprocessable(format!(
            "{field:?} is not a valid credential field for mode {mode}"
        )),
        ProviderCredentialError::Secret(_)
        | ProviderCredentialError::Io { .. }
        | ProviderCredentialError::Poisoned => {
            ApiError::Internal("failed to persist the provider-credential entry".to_owned())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProviderCredentialStore;
    use crate::actor::SESSION_TTL_SECS;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode};
    use chancela_authz::{LEITOR_ROLE_ID, OWNER_ROLE_ID, RoleAssignment, RoleCatalog, RoleId};
    use serde_json::{Value, json};
    use std::path::{Path as StdPath, PathBuf};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tower::ServiceExt;

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    /// A fixed DB key so the derived-root key source resolves deterministically (mirrors the
    /// `secretstore_persist` unit tests).
    const TEST_DB_KEY: &[u8] = b"wp13-phase-b-write-api-test-db-key-01";

    struct TempDir {
        dir: PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            let seq = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir()
                .join(format!("chancela-credwrite-{}-{seq}", std::process::id()));
            std::fs::create_dir_all(&dir).expect("create temp dir");
            Self { dir }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn state_with_store(dir: &StdPath) -> AppState {
        AppState {
            provider_credentials: Arc::new(ProviderCredentialStore::load_with_db_key(
                dir,
                TEST_DB_KEY,
                false,
            )),
            ..AppState::default()
        }
    }

    async fn seed_token(state: &AppState, role: RoleId) -> String {
        use crate::users::{User, UserId};
        use time::format_description::well_known::Rfc3339;
        {
            let mut roles = state.roles.write().await;
            if roles.is_empty() {
                *roles = RoleCatalog::seeded_defaults();
            }
        }
        let uid = UserId(Uuid::new_v4());
        let user = User {
            id: uid,
            username: format!("amelia.marques.{}", Uuid::new_v4()),
            display_name: "Amélia Marques".to_owned(),
            email: None,
            created_at: time::OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .unwrap_or_default(),
            active: true,
            password_hash: Some(crate::attestation::hash_secret("Teste-Forte7!X").unwrap()),
            attestation_key: None,
            secret_source: Default::default(),
            recovery_hash: None,
            role_assignments: vec![RoleAssignment::new(role, Scope::Global)],
            language: Default::default(),
        };
        state.users.write().await.insert(uid, user);
        let token = Uuid::new_v4().to_string();
        let now = time::OffsetDateTime::now_utc();
        state.sessions.write().await.insert(
            token.clone(),
            crate::session::SessionEntry {
                user_id: uid,
                unlocked_key: None,
                expires_at: now + time::Duration::seconds(SESSION_TTL_SECS),
            },
        );
        token
    }

    async fn send_with(
        state: AppState,
        req: Request<Body>,
        token: Option<&str>,
    ) -> (StatusCode, Value) {
        let req = match token {
            Some(t) => {
                let mut r = req;
                r.headers_mut()
                    .insert("x-chancela-session", t.parse().unwrap());
                r
            }
            None => req,
        };
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

    fn body_req(method: &str, uri: &str, body: Value) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("request builds")
    }

    fn get(uri: &str) -> Request<Body> {
        Request::builder()
            .uri(uri)
            .body(Body::empty())
            .expect("request builds")
    }

    fn del(uri: &str) -> Request<Body> {
        Request::builder()
            .method("DELETE")
            .uri(uri)
            .body(Body::empty())
            .expect("request builds")
    }

    #[tokio::test]
    async fn create_entry_requires_settings_manage() {
        let tmp = TempDir::new();
        let state = state_with_store(&tmp.dir);
        let uri = "/v1/signature/provider-credentials/csc/encosto-qtsp/entries";
        let body = json!({ "label": "Primária", "set": { "client_secret": "sk_live_zzz" } });

        // No session → 401 (the CurrentActor extractor rejects before the handler).
        let (status, _) = send_with(state.clone(), body_req("POST", uri, body.clone()), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        // settings.read but not settings.manage (LEITOR) → 403.
        let leitor = seed_token(&state, LEITOR_ROLE_ID).await;
        let (status, b) = send_with(
            state.clone(),
            body_req("POST", uri, body.clone()),
            Some(&leitor),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{b}");

        // settings.manage (OWNER) → 201.
        let owner = seed_token(&state, OWNER_ROLE_ID).await;
        let (status, b) = send_with(state, body_req("POST", uri, body), Some(&owner)).await;
        assert_eq!(status, StatusCode::CREATED, "{b}");
    }

    /// The reported bug: saving a credential on a server with no data directory. The refusal must
    /// point at persistence — the previous message blamed the credential key, which sent operators
    /// off to set `CHANCELA_CREDENTIAL_KEY` and left them just as stuck.
    #[tokio::test]
    async fn create_entry_without_persistence_explains_the_data_dir() {
        let state = AppState::default();
        let token = seed_token(&state, OWNER_ROLE_ID).await;
        let uri = "/v1/signature/provider-credentials/csc/encosto-qtsp/entries";
        let body = json!({ "label": "Primária", "set": { "client_secret": "sk_live_zzz" } });

        let (status, b) = send_with(state, body_req("POST", uri, body), Some(&token)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{b}");
        let message = b.to_string();
        assert!(message.contains("CHANCELA_DATA_DIR"), "{message}");
        assert!(message.contains("in-memory"), "{message}");
        assert!(!message.contains("CHANCELA_CREDENTIAL_KEY"), "{message}");
        assert!(!message.contains("sk_live_zzz"), "{message}");
    }

    /// The settings banner reads its whole story from three fields, and it may only claim a
    /// protection level when a secret can actually be stored. An in-memory server stores nothing,
    /// so it must report `can_store: false` and NO `protection_level` — the old response omitted
    /// the level alone, which the UI read as "not confidential" and rendered as the weaker
    /// obfuscation warning, telling operators their secrets were merely obfuscated when in truth
    /// none could be saved at all.
    #[tokio::test]
    async fn list_never_claims_a_protection_level_it_cannot_deliver() {
        let state = AppState::default();
        let token = seed_token(&state, OWNER_ROLE_ID).await;
        let uri = "/v1/signature/provider-credentials";

        let (status, body) = send_with(state, get(uri), Some(&token)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["can_store"], false, "{body}");
        assert!(body["protection_level"].is_null(), "{body}");
        assert_eq!(body["storage_failure"], "not_persistent", "{body}");
    }

    /// The mirror case: a real store with a usable key source reports the level it will deliver,
    /// and says nothing about a failure.
    #[tokio::test]
    async fn list_reports_the_protection_level_a_usable_store_delivers() {
        let tmp = TempDir::new();
        let state = state_with_store(&tmp.dir);
        let token = seed_token(&state, OWNER_ROLE_ID).await;

        let (status, body) = send_with(
            state,
            get("/v1/signature/provider-credentials"),
            Some(&token),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["can_store"], true, "{body}");
        assert_eq!(body["protection_level"], "confidential", "{body}");
        assert!(body["storage_failure"].is_null(), "{body}");
    }

    #[tokio::test]
    async fn create_update_delete_round_trip() {
        let tmp = TempDir::new();
        let state = state_with_store(&tmp.dir);
        let token = seed_token(&state, OWNER_ROLE_ID).await;
        let base = "/v1/signature/provider-credentials/csc/encosto-qtsp/entries";

        let (status, created) = send_with(
            state.clone(),
            body_req(
                "POST",
                base,
                json!({
                    "label": "Primária",
                    "set": { "client_id": "client-encosto", "client_secret": "sk_live_9f8e7d6c" }
                }),
            ),
            Some(&token),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let entry_id = created["entry"]["entry_id"]
            .as_str()
            .expect("entry id")
            .to_owned();
        assert_eq!(created["entry"]["label"], "Primária");
        assert_eq!(created["deleted"], false);
        let names: Vec<&str> = created["entry"]["fields"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["field_name"].as_str().unwrap())
            .collect();
        assert!(
            names.contains(&"client_id") && names.contains(&"client_secret"),
            "{created}"
        );

        // Management list shows the entry.
        let (status, list) = send_with(
            state.clone(),
            get("/v1/signature/provider-credentials"),
            Some(&token),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{list}");
        let providers = list["providers"].as_array().unwrap();
        assert_eq!(providers.len(), 1, "{list}");
        assert_eq!(providers[0]["provider_id"], "encosto-qtsp");
        assert_eq!(providers[0]["entries"].as_array().unwrap().len(), 1);

        // Update: relabel, disable, and clear one field.
        let update_uri = format!("{base}/{entry_id}");
        let (status, updated) = send_with(
            state.clone(),
            body_req(
                "PATCH",
                &update_uri,
                json!({ "label": "Secundária", "enabled": false, "clear": ["client_id"] }),
            ),
            Some(&token),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{updated}");
        assert_eq!(updated["entry"]["label"], "Secundária");
        assert_eq!(updated["entry"]["enabled"], false);
        let names: Vec<&str> = updated["entry"]["fields"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["field_name"].as_str().unwrap())
            .collect();
        assert!(
            !names.contains(&"client_id"),
            "cleared field is gone: {updated}"
        );
        assert!(names.contains(&"client_secret"));

        // Delete.
        let (status, deleted) = send_with(state.clone(), del(&update_uri), Some(&token)).await;
        assert_eq!(status, StatusCode::OK, "{deleted}");
        assert_eq!(deleted["deleted"], true);

        // The record is gone from the list, and a second delete is 404.
        let (status, list) = send_with(
            state.clone(),
            get("/v1/signature/provider-credentials"),
            Some(&token),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{list}");
        assert!(list["providers"].as_array().unwrap().is_empty(), "{list}");

        let (status, _) = send_with(state, del(&update_uri), Some(&token)).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn secrets_never_appear_in_responses() {
        let tmp = TempDir::new();
        let state = state_with_store(&tmp.dir);
        let token = seed_token(&state, OWNER_ROLE_ID).await;
        let secret = "sk_live_TOP_SECRET_do_not_echo_123456";
        let base = "/v1/signature/provider-credentials/csc/encosto-qtsp/entries";

        let (status, created) = send_with(
            state.clone(),
            body_req("POST", base, json!({ "set": { "client_secret": secret } })),
            Some(&token),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        assert!(
            !created.to_string().contains(secret),
            "create response must not echo the secret"
        );

        let (status, list) = send_with(
            state,
            get("/v1/signature/provider-credentials"),
            Some(&token),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{list}");
        let rendered = list.to_string();
        assert!(!rendered.contains(secret), "list must not echo the secret");
        assert!(
            !rendered.contains("do_not_echo"),
            "no secret fragment leaks"
        );
    }

    #[tokio::test]
    async fn reorder_sets_contiguous_priority() {
        let tmp = TempDir::new();
        let state = state_with_store(&tmp.dir);
        let token = seed_token(&state, OWNER_ROLE_ID).await;
        let base = "/v1/signature/provider-credentials/csc/p/entries";

        let (_, a) = send_with(
            state.clone(),
            body_req(
                "POST",
                base,
                json!({ "label": "A", "priority": 10, "set": { "client_secret": "sa" } }),
            ),
            Some(&token),
        )
        .await;
        let (_, b) = send_with(
            state.clone(),
            body_req(
                "POST",
                base,
                json!({ "label": "B", "priority": 20, "set": { "client_secret": "sb" } }),
            ),
            Some(&token),
        )
        .await;
        let a_id = a["entry"]["entry_id"].as_str().unwrap().to_owned();
        let b_id = b["entry"]["entry_id"].as_str().unwrap().to_owned();

        // Reorder B ahead of A.
        let (status, list) = send_with(
            state.clone(),
            body_req(
                "POST",
                &format!("{base}/reorder"),
                json!({ "order": [b_id.clone(), a_id.clone()] }),
            ),
            Some(&token),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{list}");
        let entries = list["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 2, "{list}");
        assert_eq!(entries[0]["entry_id"], b_id);
        assert_eq!(entries[0]["priority"], 0);
        assert_eq!(entries[1]["entry_id"], a_id);
        assert_eq!(entries[1]["priority"], 1);

        // A non-permutation order is rejected.
        let (status, _) = send_with(
            state,
            body_req(
                "POST",
                &format!("{base}/reorder"),
                json!({ "order": [a_id] }),
            ),
            Some(&token),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn invalid_mode_and_payload_rejected() {
        let tmp = TempDir::new();
        let state = state_with_store(&tmp.dir);
        let token = seed_token(&state, OWNER_ROLE_ID).await;

        // Unknown mode.
        let (status, _) = send_with(
            state.clone(),
            body_req(
                "POST",
                "/v1/signature/provider-credentials/bogus/x/entries",
                json!({ "set": { "client_secret": "s" } }),
            ),
            Some(&token),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        // Unknown field for the mode.
        let (status, _) = send_with(
            state.clone(),
            body_req(
                "POST",
                "/v1/signature/provider-credentials/csc/p/entries",
                json!({ "set": { "nope": "s" } }),
            ),
            Some(&token),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        // A new entry with no secret field is rejected (it would persist nothing).
        let (status, _) = send_with(
            state.clone(),
            body_req(
                "POST",
                "/v1/signature/provider-credentials/csc/p/entries",
                json!({ "label": "x" }),
            ),
            Some(&token),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        // CMD is single-instance: a non-`_` provider segment is rejected.
        let (status, _) = send_with(
            state.clone(),
            body_req(
                "POST",
                "/v1/signature/provider-credentials/cmd/somebody/entries",
                json!({ "set": { "http_basic_password": "s" } }),
            ),
            Some(&token),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        // CSC requires a non-empty provider: the `_` sentinel is rejected.
        let (status, _) = send_with(
            state,
            body_req(
                "POST",
                "/v1/signature/provider-credentials/csc/_/entries",
                json!({ "set": { "client_secret": "s" } }),
            ),
            Some(&token),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn create_without_key_source_fails_closed() {
        // The default in-memory store cannot persist anything, so storing a secret must fail
        // closed. Since t16 split the two causes apart this is the NotPersistent branch (422 —
        // "set CHANCELA_DATA_DIR"), not the generic no-key-source 409: the operator's next step is
        // a data directory, not a key. `create_entry_without_persistence_explains_the_data_dir`
        // asserts the message; this asserts the status stays a refusal.
        let state = AppState::default();
        let token = seed_token(&state, OWNER_ROLE_ID).await;
        let (status, _) = send_with(
            state,
            body_req(
                "POST",
                "/v1/signature/provider-credentials/csc/p/entries",
                json!({ "set": { "client_secret": "s" } }),
            ),
            Some(&token),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn create_emits_sanitized_audit_event() {
        let tmp = TempDir::new();
        let state = state_with_store(&tmp.dir);
        let token = seed_token(&state, OWNER_ROLE_ID).await;
        let (status, _) = send_with(
            state.clone(),
            body_req(
                "POST",
                "/v1/signature/provider-credentials/csc/p/entries",
                json!({ "set": { "client_secret": "sk_live_audit_abcdef" } }),
            ),
            Some(&token),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);

        let ledger = state.ledger.read().await;
        let event = ledger.events().last().expect("an event was appended");
        assert_eq!(event.scope, "provider_credentials");
        assert_eq!(event.kind, "provider.credentials.entry.created");
    }
}
