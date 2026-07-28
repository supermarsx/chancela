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
//! - **Gating.** Mutations require `signing.configure` (t50 — the dedicated signing-configuration
//!   verb split off `settings.manage`, granted to every prior `settings.manage` holder by the
//!   grandfather migration, so no current operator loses access); the management list requires
//!   `settings.read` (the same gate the status endpoint uses).

use std::collections::BTreeMap;
use std::fmt;
use std::io::Read;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use chancela_authz::{Permission, Scope};
use chancela_csc::rest::Authorization as CscAuthorizationHeader;
use chancela_csc::{CscAuthorization, CscClient, CscConfig, CscError, CscSecrets, CscTransport};
use chancela_scap::{
    AmaScapConfig, AttributeProvider, CitizenRef, ProfessionalAttribute, ScapClient,
    ScapCredentials, ScapEnvironment, ScapError, ScapTransport, VerificationDecision,
};
use chancela_signing::{Pkcs12SigningSource, SignerProvider};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;
use x509_cert::Certificate;
use x509_cert::der::{Decode, Encode};
use zeroize::Zeroizing;

use crate::actor::{CurrentActor, CurrentAttestor};
use crate::authz::require_permission;
use crate::credential_resolve::assemble_pkcs12_input;
use crate::error::ApiError;
use crate::secretstore::SecretStoreError;
use crate::secretstore_persist::{
    CredentialEntryMetadataView, DecryptedCredentialEntry, FIELD_ACCESS_TOKEN,
    FIELD_APPLICATION_ID, FIELD_CLIENT_ID, FIELD_CLIENT_SECRET, FIELD_HTTP_BASIC_PASSWORD,
    FIELD_HTTP_BASIC_USERNAME, FIELD_SECRET,
};
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

/// `POST …/entries/{entry_id}/probe` deliberately accepts only an empty JSON object. Keeping an
/// explicit DTO (plus the route-local body limit) prevents this privileged diagnostic endpoint
/// from becoming an accidental upload sink.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderCredentialProbeRequest {
    #[serde(default)]
    confirm_private_key_operation: bool,
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

/// One sanitized assertion made by a provider-credential probe.
#[derive(Debug, Serialize)]
pub struct ProviderProbeCheck {
    pub name: &'static str,
    /// `passed`, `failed`, or `skipped`.
    pub status: &'static str,
    pub detail: String,
}

/// Honest result of testing one exact stored credential entry.
///
/// A probe never signs a document and never asks a signer to authorize a legally meaningful
/// signature. The fixed false markers are values (rather than omitted disclaimers) so clients cannot
/// accidentally interpret connectivity or a private-key challenge as a legal/qualified verdict.
#[derive(Debug, Serialize)]
pub struct ProviderCredentialProbeResponse {
    pub mode: &'static str,
    pub provider_id: String,
    pub entry_id: String,
    /// `ok`, `failed`, or `interactive_required`.
    pub status: &'static str,
    pub provider_contacted: bool,
    pub private_key_operation_performed: bool,
    pub signer_authorization_requested: bool,
    pub document_signed: bool,
    pub legal_validity_claimed: bool,
    pub qualified_status_determined: bool,
    pub checks: Vec<ProviderProbeCheck>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<&'static str>,
    pub tested_at: String,
    pub duration_ms: u64,
}

struct ProbeOutcome {
    status: &'static str,
    provider_contacted: bool,
    private_key_operation_performed: bool,
    checks: Vec<ProviderProbeCheck>,
    error: Option<&'static str>,
}

impl ProbeOutcome {
    fn failed(
        provider_contacted: bool,
        private_key_operation_performed: bool,
        checks: Vec<ProviderProbeCheck>,
        error: &'static str,
    ) -> Self {
        Self {
            status: "failed",
            provider_contacted,
            private_key_operation_performed,
            checks,
            error: Some(error),
        }
    }
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
    require_permission(&state, &actor, Permission::SigningConfigure, Scope::Global).await?;
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
    require_permission(&state, &actor, Permission::SigningConfigure, Scope::Global).await?;
    let mode = parse_mode(&mode_raw)?;
    let provider_id = resolve_provider(mode, &provider_raw)?;
    let req: UpdateEntryRequest = parse_body(&body)?;

    // Merge over the current (non-decrypting) metadata so an absent field is left unchanged.
    let current =
        fetch_entry_metadata(&state, mode, &provider_id, &entry_id)?.ok_or(ApiError::NotFound)?;

    let endpoint = req.endpoint.as_deref().map(str::trim);
    if matches!(mode, CredentialMode::CscQtsp | CredentialMode::Scap)
        && endpoint_origin_changed(current.endpoint.as_deref(), endpoint)?
    {
        let required = configured_endpoint_bound_fields(&current);
        let replaced: std::collections::BTreeSet<&str> =
            req.set.keys().map(String::as_str).collect();
        if required.iter().any(|field| !replaced.contains(field)) {
            return Err(ApiError::Unprocessable(
                "changing a credential-bearing provider endpoint requires re-entering every \
                 configured authorization secret in the same request"
                    .to_owned(),
            ));
        }
    }

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
    require_permission(&state, &actor, Permission::SigningConfigure, Scope::Global).await?;
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
    require_permission(&state, &actor, Permission::SigningConfigure, Scope::Global).await?;
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

/// `POST …/entries/{entry_id}/probe` — test one exact stored credential entry without signing a
/// document or requesting signer authorization.
pub async fn probe_entry(
    State(state): State<AppState>,
    Path((mode_raw, provider_raw, entry_id)): Path<(String, String, String)>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    body: Bytes,
) -> Result<Json<ProviderCredentialProbeResponse>, ApiError> {
    require_permission(&state, &actor, Permission::SigningConfigure, Scope::Global).await?;
    let mode = parse_mode(&mode_raw)?;
    let request: ProviderCredentialProbeRequest = parse_body(&body)?;
    // A PKCS#12 probe performs a real private-key operation over a random, domain-separated
    // non-document challenge. Configuration authority alone must never authorize key use.
    if mode == CredentialMode::LocalPkcs12 {
        require_permission(&state, &actor, Permission::SigningPerform, Scope::Global).await?;
        if !request.confirm_private_key_operation {
            return Err(ApiError::Unprocessable(
                "confirm_private_key_operation must be true for a PKCS#12 probe".to_owned(),
            ));
        }
    }
    let provider_id = resolve_provider(mode, &provider_raw)?;

    // Persist intent before decrypting a field, contacting a provider, or touching a private key.
    // If the durable ledger is unavailable, the probe does not happen.
    audit(
        &state,
        &actor,
        &attestor,
        "provider.credentials.entry.probe_requested",
        serde_json::json!({
            "mode": mode.as_str(),
            "provider_id": provider_id.clone(),
            "entry_id": entry_id.clone(),
            "private_key_operation_requested": mode == CredentialMode::LocalPkcs12,
        }),
    )
    .await?;

    let read_provider = provider_id.clone();
    let read_entry = entry_id.clone();
    let entry = offload_credentials(&state, move |creds| {
        creds.read_entry_runtime(mode, &read_provider, &read_entry)
    })
    .await
    .map_err(map_store_err)?
    .ok_or(ApiError::NotFound)?;

    let started = Instant::now();
    let probe_provider = provider_id.clone();
    // The CMD preflight must judge the entry against the environment the deployment is actually
    // configured for (prod demands the AMA certificate and BasicAuth that preprod does not), so the
    // settings slice is read here and moved into the blocking probe rather than re-read inside it.
    let cmd_settings = { state.settings.read().await.signing.cmd.clone() };
    // Resolved out here for the same reason: it needs the async settings lock, and the trusted-list
    // anchor state is what decides whether a qualified signature can be authenticated at all.
    let cmd_trust = resolve_cmd_trust_anchor_preflight(&state).await;
    let outcome = tokio::task::spawn_blocking(move || {
        probe_stored_entry(mode, &probe_provider, &cmd_settings, &cmd_trust, entry)
    })
    .await
    .map_err(|_| ApiError::Internal("provider credential probe task failed".to_owned()))?;
    let tested_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default();
    let response = ProviderCredentialProbeResponse {
        mode: mode.as_str(),
        provider_id: provider_id.clone(),
        entry_id: entry_id.clone(),
        status: outcome.status,
        provider_contacted: outcome.provider_contacted,
        private_key_operation_performed: outcome.private_key_operation_performed,
        // No implemented probe invokes credentials/sendOTP, credentials/authorize, CMD initiation,
        // or any equivalent signer-consent step.
        signer_authorization_requested: false,
        document_signed: false,
        legal_validity_claimed: false,
        qualified_status_determined: false,
        checks: outcome.checks,
        error: outcome.error,
        tested_at,
        duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
    };
    audit(
        &state,
        &actor,
        &attestor,
        "provider.credentials.entry.probed",
        serde_json::json!({
            "mode": mode.as_str(),
            "provider_id": provider_id,
            "entry_id": entry_id,
            "status": response.status,
            "provider_contacted": response.provider_contacted,
            "private_key_operation_performed": response.private_key_operation_performed,
            "error": response.error,
        }),
    )
    .await?;
    Ok(Json(response))
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
        // The SMTP relay account and the per-user TOTP secrets ride the same store but are not
        // signing providers; they belong to the mail-settings and user-security screens, so they
        // must not appear in the Assinaturas list.
        if matches!(
            record.mode,
            CredentialMode::Smtp | CredentialMode::TwoFactorTotp
        ) {
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

const PROBE_HTTP_TIMEOUT: Duration = Duration::from_secs(15);
const PROBE_RESPONSE_LIMIT: u64 = 1024 * 1024;
const PKCS12_PROBE_DOMAIN: &[u8] = b"chancela-provider-credential-probe-v1\0";

fn check(name: &'static str, passed: bool, detail: impl Into<String>) -> ProviderProbeCheck {
    ProviderProbeCheck {
        name,
        status: if passed { "passed" } else { "failed" },
        detail: detail.into(),
    }
}

fn skipped(name: &'static str, detail: impl Into<String>) -> ProviderProbeCheck {
    ProviderProbeCheck {
        name,
        status: "skipped",
        detail: detail.into(),
    }
}

fn probe_stored_entry(
    mode: CredentialMode,
    provider_id: &str,
    cmd_settings: &crate::settings::SigningCmdSettings,
    cmd_trust: &CmdTrustAnchorPreflight,
    entry: DecryptedCredentialEntry,
) -> ProbeOutcome {
    if !entry.enabled {
        return ProbeOutcome::failed(
            false,
            false,
            vec![check(
                "entry_enabled",
                false,
                "The stored credential entry is disabled.",
            )],
            "entry_disabled",
        );
    }
    match mode {
        CredentialMode::Cmd => probe_cmd(cmd_settings, cmd_trust, entry),
        CredentialMode::CscQtsp => probe_csc(provider_id, entry),
        CredentialMode::Scap => probe_scap(entry),
        CredentialMode::LocalPkcs12 => probe_pkcs12(entry),
        CredentialMode::Smtp | CredentialMode::TwoFactorTotp => ProbeOutcome::failed(
            false,
            false,
            vec![check(
                "mode_supported",
                false,
                "This is not a signing-provider credential mode.",
            )],
            "unsupported_mode",
        ),
    }
}

/// How long the endpoint-reachability check waits for the TLS handshake before giving up.
const CMD_REACHABILITY_TIMEOUT: Duration = Duration::from_secs(8);

/// Production preflight for one stored Chave Móvel Digital entry (t51-e3 §4.2).
///
/// # Why this is a preflight and not a health check
///
/// CMD's protocol is `GetCertificate → CCMovelSign → ValidateOtp`. There is no ping: the first
/// call that would prove the provider answers is the one that dispatches an SMS OTP to a real
/// citizen and starts a real qualified signature. So `live_provider_operation` stays **skipped**
/// with its original wording, and `provider_contacted` stays `false` — no SCMD protocol operation
/// is invoked here, ever.
///
/// What this *does* answer is "is production CMD wired up?", and it answers it against **the same
/// material a signature would use**: the entry is assembled through
/// [`crate::signature::cmd_config_from_entry`], the identical function the signing path calls, so a
/// preflight cannot pass over a config that would then fail to sign. A partial entry surfaces the
/// missing **admin-panel field names** (`application_id`, `http_basic_username`,
/// `http_basic_password`, `ama_cert_pem`) that the operator can go and fill, rather than
/// environment-variable names they never set.
///
/// The one network touch is an optional TLS handshake against the fixed AMA **production**
/// endpoint constant. A handshake is not a protocol operation — it starts nothing, signs nothing
/// and needs no citizen — so it is reported as its own `endpoint_reachable` check and does not
/// flip `provider_contacted`. It runs only when the deployment is configured for production,
/// because "can this server reach AMA production?" is the question the preflight exists to answer.
fn probe_cmd(
    cmd: &crate::settings::SigningCmdSettings,
    cmd_trust: &CmdTrustAnchorPreflight,
    entry: DecryptedCredentialEntry,
) -> ProbeOutcome {
    let is_prod = matches!(cmd.env, crate::settings::CmdEnvSetting::Prod);
    let mut checks = vec![
        check(
            "entry_enabled",
            true,
            "The stored credential entry is enabled.",
        ),
        check(
            "configured_environment",
            true,
            format!(
                "The deployment resolves Chave Móvel Digital to the {} environment.",
                if is_prod { "prod" } else { "preprod" }
            ),
        ),
        // Deployment-wide, not a property of this entry, and reported before the credential checks
        // so it survives every early return below: an operator with a perfectly filled CMD form and
        // no trust anchor would otherwise see only green until a real signature refused.
        cmd_trust_anchor_check(cmd_trust),
    ];

    // Assemble through the SIGNING path's own resolver, so what the preflight reports is what a
    // signature would actually use. Its error already names the admin-panel fields that are missing.
    let cfg = match crate::signature::cmd_config_from_entry(cmd, &entry) {
        Ok(cfg) => cfg,
        Err(err) => {
            checks.push(check(
                "stored_credential_fields",
                false,
                credential_assembly_detail(err),
            ));
            checks.push(cmd_live_operation_skipped());
            return ProbeOutcome::failed(false, false, checks, "configuration_incomplete");
        }
    };
    checks.push(check(
        "stored_credential_fields",
        true,
        "Every credential field this environment requires is present in the stored entry.",
    ));

    // Field encryption. `cmd_config_from_entry` already refuses a config whose encryptor cannot be
    // built, so reaching here means the AMA certificate parsed; report which mode that implies.
    checks.push(match (&cfg.ama_cert_pem, is_prod) {
        (Some(_), _) => check(
            "ama_certificate_parseable",
            true,
            "The stored AMA field-encryption certificate parsed and the field encryptor was built.",
        ),
        (None, false) => check(
            "ama_certificate_parseable",
            true,
            "No AMA field-encryption certificate is stored; preprod accepts cleartext fields.",
        ),
        // Unreachable: prod without a certificate fails assembly above. Kept as a fail-closed arm
        // rather than an `unreachable!()` so a future change in the assembler degrades honestly.
        (None, true) => check(
            "ama_certificate_parseable",
            false,
            "Production requires the AMA field-encryption certificate (ama_cert_pem).",
        ),
    });

    // HTTP BasicAuth. Optional in preprod, mandatory for the real production transport.
    let has_basic_auth = cfg.basic_auth.is_some();
    checks.push(check(
        "http_basic_configured",
        has_basic_auth || !is_prod,
        match (has_basic_auth, is_prod) {
            (true, _) => "HTTP BasicAuth credentials are configured.".to_owned(),
            (false, false) => {
                "No HTTP BasicAuth credentials are stored; preprod may accept unauthenticated calls."
                    .to_owned()
            }
            (false, true) => format!(
                "Production requires HTTP BasicAuth: fill {FIELD_HTTP_BASIC_USERNAME} and \
                 {FIELD_HTTP_BASIC_PASSWORD} on this credential entry."
            ),
        },
    ));

    // The transport-level gate the real HTTP client applies before it will talk to AMA at all.
    match cfg.validate_http_transport() {
        Ok(()) => checks.push(check(
            "http_transport_ready",
            true,
            "The resolved configuration satisfies the real AMA HTTP transport's requirements.",
        )),
        Err(_) => {
            checks.push(check(
                "http_transport_ready",
                false,
                "The resolved configuration cannot drive the real AMA HTTP transport.",
            ));
            checks.push(cmd_live_operation_skipped());
            return ProbeOutcome::failed(false, false, checks, "configuration_incomplete");
        }
    }

    // The endpoint is a compiled-in constant per environment, never operator-supplied. Assert it is
    // the one this environment names, over HTTPS, and acceptable to the outbound-network policy.
    let endpoint = cfg.endpoint();
    let expected_endpoint = if is_prod {
        chancela_cmd::PROD_ENDPOINT
    } else {
        chancela_cmd::PREPROD_ENDPOINT
    };
    let vetted = match crate::trust::validate_outbound_http_url(endpoint) {
        Ok(vetted) if endpoint == expected_endpoint => vetted,
        _ => {
            checks.push(check(
                "endpoint_matches_environment",
                false,
                "The resolved SCMD endpoint is not the constant this environment names, or it \
                 failed the outbound-network safety policy.",
            ));
            checks.push(cmd_live_operation_skipped());
            return ProbeOutcome::failed(false, false, checks, "unsafe_endpoint");
        }
    };
    if let Err(detail) = require_https_probe_endpoint(&vetted, "CMD") {
        checks.push(check("endpoint_matches_environment", false, detail));
        checks.push(cmd_live_operation_skipped());
        return ProbeOutcome::failed(false, false, checks, "insecure_endpoint");
    }
    checks.push(check(
        "endpoint_matches_environment",
        true,
        format!("The SCMD endpoint is the pinned {expected_endpoint} constant, over HTTPS."),
    ));

    // Reachability. Production only, and explicitly NOT a protocol operation.
    let reachable = if is_prod {
        match cmd_endpoint_reachable(&vetted) {
            Ok(()) => {
                checks.push(check(
                    "endpoint_reachable",
                    true,
                    "A TLS connection to the AMA production endpoint succeeded. No SCMD operation \
                     was invoked: nothing was signed and no OTP was dispatched.",
                ));
                true
            }
            Err(detail) => {
                checks.push(check("endpoint_reachable", false, detail));
                false
            }
        }
    } else {
        checks.push(skipped(
            "endpoint_reachable",
            "Reachability is probed only for the AMA production endpoint; this deployment is \
             configured for preprod.",
        ));
        true
    };

    checks.push(cmd_live_operation_skipped());
    if reachable {
        ProbeOutcome {
            status: "interactive_required",
            provider_contacted: false,
            private_key_operation_performed: false,
            checks,
            error: Some("interactive_required"),
        }
    } else {
        ProbeOutcome::failed(false, false, checks, "endpoint_unreachable")
    }
}

/// What the preflight could determine, offline, about the trusted-list anchors a CMD signature
/// would be authenticated against.
///
/// **Why this check exists.** Three distinct trust failures decide whether a qualified signature can
/// be authenticated at all:
///
/// - **(A)** no trust anchor is configured anywhere, so no list can ever authenticate;
/// - **(B)** anchors are configured but the list does not authenticate against them — the shape of a
///   Trusted-List signer rotation where the new signer is not yet anchored;
/// - **(C)** the list authenticates and the service genuinely is not `Granted`.
///
/// Only **(C)** is about the signer. **(B)** is the one that hits real operators mid-rotation.
///
/// **All three are now discriminated at signing time** (t61-e2): `SigningError` carries
/// `TrustAnchorNotConfigured` for (A) and `TrustedListNotAnchored { configured_in, anchor_count }`
/// for (B), and `UntrustedService` — which previously absorbed all three and named the *signer's*
/// service for every one of them — now means (C) alone. Both new variants map to **422**, a local
/// configuration fault rather than a provider one.
///
/// So this preflight is not the diagnosis and never was. Its job is **earliness**: it settles **(A)**
/// offline and reports which anchor source resolved, so an operator learns their CMD configuration is
/// incomplete *before* pressing a button that produces a real, legally binding qualified signature —
/// rather than from an error afterwards. It structurally **cannot** see (B): it never fetches or
/// authenticates a list. A signature attempt that gets past it surfaces (B) honestly on its own, and
/// nothing here special-cases that.
pub(crate) enum CmdTrustAnchorPreflight {
    /// No Trusted List is selected at all — there is nothing to authenticate. State **(A)**.
    NoListSelected,
    /// The list *selection* is itself misconfigured; `configured_tsl_source` refused it.
    SelectionInvalid(String),
    /// Anchors are configured but cannot be parsed. The policy build fails closed at signing time
    /// (422) rather than degrading to "unanchored", so this is a hard stop, not a downgrade.
    AnchorsInvalid(String),
    /// A list is selected and the resolved anchor set is **empty**. State **(A)**: an empty set
    /// authenticates no list, so a signature refuses while naming the signer's service.
    Unanchored,
    /// A list is selected and `total` distinct anchors resolved, `from_env` of which the
    /// environment supplied. The remainder came from the admin panel's `signing.tsl_trust_anchor_*`
    /// fields. A union only ever *adds*, so `from_env <= total`.
    Anchored { total: usize, from_env: usize },
}

/// Resolve [`CmdTrustAnchorPreflight`] through the **signing path's own** source selector and anchor
/// fold, so what the preflight reports is what a signature would actually authenticate against.
///
/// Read-only and offline: it selects the source and resolves anchors, and deliberately does **not**
/// fetch or authenticate the list. Authenticating it is what separates (B) from (C), and that
/// happens at signing time, where t61-e2 discriminates both. A preflight that reached out to
/// authenticate a list would be doing the trust boundary's job on a different surface.
pub(crate) async fn resolve_cmd_trust_anchor_preflight(
    state: &AppState,
) -> CmdTrustAnchorPreflight {
    let source = match crate::signature::configured_tsl_source(state).await {
        Ok(Some(source)) => source,
        Ok(None) => return CmdTrustAnchorPreflight::NoListSelected,
        Err(err) => {
            return CmdTrustAnchorPreflight::SelectionInvalid(credential_assembly_detail(err));
        }
    };
    // The same union the signing-time policy builds: settings anchors ∪ environment anchors.
    let anchors = match crate::trust::resolve_lotl_trust_anchors(
        &source.trust_anchor_certs,
        &source.trust_anchor_sha256,
    ) {
        Ok(anchors) => anchors,
        Err(e) => return CmdTrustAnchorPreflight::AnchorsInvalid(e.to_string()),
    };
    if anchors.is_empty() {
        return CmdTrustAnchorPreflight::Unanchored;
    }
    // The environment-only baseline, so the report can say which source supplied the anchors rather
    // than only how many there are. A failure to read the environment is reported as zero from it:
    // the union above already succeeded, so the anchors are real regardless of this attribution.
    //
    // `resolve_lotl_trust_anchors` is a **deduplicating** union: an anchor provisioned in both
    // settings and the environment is counted once. So `total - from_env` is a lower bound on the
    // settings contribution, not an exact count, and the wording below says "at least" for that
    // reason. A strict subtraction presented as exact would be wrong whenever the two overlap.
    let from_env = chancela_tsl::TslTrustAnchors::from_env()
        .map(|env| env.len())
        .unwrap_or(0);
    CmdTrustAnchorPreflight::Anchored {
        total: anchors.len(),
        from_env: from_env.min(anchors.len()),
    }
}

/// Render the trust-anchor verdict as a probe check. Failing arms name the admin-panel fields the
/// operator can go and fill, never environment-variable names.
fn cmd_trust_anchor_check(preflight: &CmdTrustAnchorPreflight) -> ProviderProbeCheck {
    match preflight {
        CmdTrustAnchorPreflight::NoListSelected => check(
            "trusted_list_anchors",
            false,
            "No Trusted List is selected, so no qualified signature can be authenticated. A CMD \
             signature will refuse. Select a Trusted List source in the signing settings.",
        ),
        CmdTrustAnchorPreflight::SelectionInvalid(detail) => check(
            "trusted_list_anchors",
            false,
            format!("The Trusted List selection is invalid: {detail}"),
        ),
        CmdTrustAnchorPreflight::AnchorsInvalid(detail) => check(
            "trusted_list_anchors",
            false,
            format!(
                "A configured trust anchor could not be parsed, so the trust policy fails closed: \
                 {detail}. Check signing.tsl_trust_anchor_certs and \
                 signing.tsl_trust_anchor_sha256."
            ),
        ),
        CmdTrustAnchorPreflight::Unanchored => check(
            "trusted_list_anchors",
            false,
            // t61-e2: this used to say a signature would "refuse with an error naming the signer's
            // trust service, though the fault is here". That was true, and is no longer: state (A)
            // now has its own `SigningError::TrustAnchorNotConfigured`, which names the anchor
            // configuration rather than the signer. Leaving the old sentence would have made this
            // check a documented claim about behaviour that no longer exists.
            "A Trusted List is selected but no trust anchor is configured, and an empty anchor set \
             authenticates no list. A CMD signature will refuse, naming this missing anchor rather \
             than the signer's trust service. Provision an anchor in \
             signing.tsl_trust_anchor_certs or signing.tsl_trust_anchor_sha256.",
        ),
        CmdTrustAnchorPreflight::Anchored { total, from_env } => {
            let provenance = match (*from_env, total - *from_env) {
                (0, _) => "all of them from the signing settings".to_owned(),
                (_, 0) => "all of them from the environment".to_owned(),
                (env, settings) => format!(
                    "{env} from the environment and at least {settings} from the signing settings"
                ),
            };
            check(
                "trusted_list_anchors",
                true,
                format!(
                    "{total} Trusted List trust anchor(s) resolved — {provenance}. Whether the \
                     selected list actually authenticates against them, and whether the signer's \
                     service is Granted, are determined at signing time and are not probed here."
                ),
            )
        }
    }
}

/// Surface the assembler's own message, which already names the missing **admin-panel credential
/// fields** an operator can go and fill. [`ApiError`] has no `Display`, and the messages that reach
/// here are the sanitized `stored_credentials_*` strings, which carry no secret value — only field
/// names. Any other variant degrades to a generic line rather than guessing at its content.
///
/// **`into_uncoded` first (t58).** A Tier-2 code wraps the real variant, so `ApiError::Unprocessable`
/// silently stops matching the moment any producer upstream attaches one — and this classifier's
/// `_` arm degrades to a generic line rather than failing, so the loss would be invisible: the
/// preflight would quietly stop naming the credential fields the operator has to fill in. Consuming
/// the peel is correct here because the return is a `String`; a classifier that returns an *error*
/// must pass the ORIGINAL through on its passthrough arm instead, or it strips the caller's code.
fn credential_assembly_detail(err: ApiError) -> String {
    match err.into_uncoded() {
        ApiError::Unprocessable(message) | ApiError::Conflict(message) => message,
        _ => "The stored credential entry could not be assembled into a usable CMD configuration."
            .to_owned(),
    }
}

/// The skipped-check text that states, verbatim, why no live CMD operation is ever performed by a
/// probe. Kept as one constant so every early return carries the identical explanation.
fn cmd_live_operation_skipped() -> ProviderProbeCheck {
    skipped(
        "live_provider_operation",
        "CMD has no safe non-signing health operation in this integration. A live attempt \
         would initiate the interactive signature flow, so it was not performed.",
    )
}

/// Open and immediately drop a bounded TLS connection to the AMA endpoint. Sends no SOAP body and
/// invokes no SCMD action; a `405`/`404`/any HTTP status all prove reachability equally well, so
/// only a transport-level failure is reported as unreachable.
fn cmd_endpoint_reachable(vetted: &crate::trust::VettedHttpUrl) -> Result<(), String> {
    let client = vetted
        .client(CMD_REACHABILITY_TIMEOUT)
        .map_err(|_| "The bounded outbound client could not be created.".to_owned())?;
    match client.head(vetted.as_str()).send() {
        Ok(_) => Ok(()),
        Err(_) => Err("The AMA production endpoint could not be reached from this server. No \
                       SCMD operation was invoked."
            .to_owned()),
    }
}

fn take_nonblank(
    fields: &mut BTreeMap<String, Zeroizing<String>>,
    name: &str,
) -> Option<Zeroizing<String>> {
    fields.remove(name).filter(|value| !value.trim().is_empty())
}

fn selector_bool(entry: &DecryptedCredentialEntry, name: &str, default: bool) -> bool {
    match entry.selectors.get(name).map(|value| value.trim()) {
        Some("true" | "1" | "yes" | "on") => true,
        Some("false" | "0" | "no" | "off") => false,
        _ => default,
    }
}

fn endpoint_origin_changed(
    current: Option<&str>,
    replacement: Option<&str>,
) -> Result<bool, ApiError> {
    let Some(replacement) = replacement else {
        return Ok(false);
    };
    let replacement = reqwest::Url::parse(replacement).map_err(|_| {
        ApiError::Unprocessable("provider endpoint must be an absolute HTTP(S) URL".to_owned())
    })?;
    let Some(current) = current.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(true);
    };
    let Ok(current) = reqwest::Url::parse(current) else {
        return Ok(true);
    };
    Ok(current.origin() != replacement.origin())
}

fn configured_endpoint_bound_fields(current: &CredentialEntryMetadataView) -> Vec<&str> {
    current
        .fields
        .iter()
        .map(|(name, _)| name.as_str())
        .collect()
}

fn require_https_probe_endpoint(
    vetted: &crate::trust::VettedHttpUrl,
    provider: &'static str,
) -> Result<(), &'static str> {
    if reqwest::Url::parse(vetted.as_str()).is_ok_and(|url| url.scheme() == "https") {
        Ok(())
    } else {
        Err(match provider {
            "CSC" => "The CSC base URL must use HTTPS before stored credentials can be sent.",
            "CMD" => "The SCMD endpoint must use HTTPS before stored credentials can be sent.",
            _ => "The SCAP base URL must use HTTPS before stored credentials can be sent.",
        })
    }
}

fn probe_csc(provider_id: &str, mut entry: DecryptedCredentialEntry) -> ProbeOutcome {
    let mut checks = vec![check(
        "entry_enabled",
        true,
        "The stored credential entry is enabled.",
    )];
    let Some(base_url) = entry
        .endpoint
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        checks.push(check(
            "endpoint_safe",
            false,
            "A CSC base URL is required for this entry.",
        ));
        return ProbeOutcome::failed(false, false, checks, "configuration_incomplete");
    };
    let vetted = match crate::trust::validate_outbound_http_url(base_url) {
        Ok(vetted) => vetted,
        Err(_) => {
            checks.push(check(
                "endpoint_safe",
                false,
                "The CSC base URL failed the outbound-network safety policy.",
            ));
            return ProbeOutcome::failed(false, false, checks, "unsafe_endpoint");
        }
    };
    if let Err(detail) = require_https_probe_endpoint(&vetted, "CSC") {
        checks.push(check("endpoint_https", false, detail));
        return ProbeOutcome::failed(false, false, checks, "insecure_endpoint");
    }
    checks.push(check(
        "endpoint_https",
        true,
        "The CSC base URL passed the outbound-network safety policy and uses HTTPS.",
    ));

    let authorization = match entry
        .selectors
        .get("authorization")
        .map(|value| value.trim())
        .unwrap_or("service")
    {
        "service" => CscAuthorization::Service,
        "user" => CscAuthorization::User,
        _ => {
            checks.push(check(
                "authorization_configuration",
                false,
                "The CSC authorization selector must be service or user.",
            ));
            return ProbeOutcome::failed(false, false, checks, "configuration_invalid");
        }
    };
    let secrets = match authorization {
        CscAuthorization::Service => {
            let client_id = take_nonblank(&mut entry.fields, FIELD_CLIENT_ID);
            let client_secret = take_nonblank(&mut entry.fields, FIELD_CLIENT_SECRET);
            match (client_id, client_secret) {
                (Some(client_id), Some(client_secret)) => CscSecrets::new(
                    client_id.as_str().to_owned(),
                    client_secret.as_str().to_owned(),
                ),
                _ => {
                    checks.push(check(
                        "authorization_configuration",
                        false,
                        "Service authorization requires client_id and client_secret.",
                    ));
                    return ProbeOutcome::failed(false, false, checks, "configuration_incomplete");
                }
            }
        }
        CscAuthorization::User => {
            let Some(token) = take_nonblank(&mut entry.fields, FIELD_ACCESS_TOKEN) else {
                checks.push(check(
                    "authorization_configuration",
                    false,
                    "User authorization requires an access_token.",
                ));
                return ProbeOutcome::failed(false, false, checks, "configuration_incomplete");
            };
            CscSecrets::with_access_token(token.as_str().to_owned())
        }
        _ => {
            return ProbeOutcome::failed(false, false, checks, "configuration_invalid");
        }
    };
    checks.push(check(
        "authorization_configuration",
        true,
        "The stored fields satisfy the selected CSC authorization model.",
    ));

    let config = CscConfig {
        provider_id: provider_id.to_owned(),
        display_name: entry.label.clone(),
        base_url: vetted.as_str().to_owned(),
        authorization,
        sandbox: selector_bool(&entry, "sandbox", true),
        credential_id: entry
            .selectors
            .get("credential_id")
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .map(str::to_owned),
        scope: entry
            .selectors
            .get("scope")
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .unwrap_or(chancela_csc::DEFAULT_SCOPE)
            .to_owned(),
    };
    if config.validate().is_err() {
        checks.push(check(
            "provider_configuration",
            false,
            "The CSC provider configuration is invalid.",
        ));
        return ProbeOutcome::failed(false, false, checks, "configuration_invalid");
    }

    let contacted = Arc::new(AtomicBool::new(false));
    let transport = match ProbeCscTransport::new(vetted, contacted.clone()) {
        Ok(transport) => transport,
        Err(_) => {
            checks.push(check(
                "outbound_client",
                false,
                "The bounded outbound client could not be created.",
            ));
            return ProbeOutcome::failed(false, false, checks, "outbound_client_unavailable");
        }
    };
    let client = CscClient::new(transport, config, secrets);
    let token = match client.authenticate() {
        Ok(token) => {
            checks.push(check(
                "authentication",
                true,
                "CSC authentication completed without requesting signer authorization.",
            ));
            token
        }
        Err(error) => {
            checks.push(check("authentication", false, csc_error_detail(&error)));
            return ProbeOutcome::failed(
                contacted.load(Ordering::Relaxed),
                false,
                checks,
                "provider_authentication_failed",
            );
        }
    };
    let credential_ids = match client.list_credentials(token.as_str()) {
        Ok(ids) => {
            checks.push(check(
                "credentials_list",
                !ids.is_empty(),
                format!("CSC returned {} signing credential(s).", ids.len()),
            ));
            ids
        }
        Err(error) => {
            checks.push(check("credentials_list", false, csc_error_detail(&error)));
            return ProbeOutcome::failed(
                contacted.load(Ordering::Relaxed),
                false,
                checks,
                "provider_credential_list_failed",
            );
        }
    };
    if credential_ids.is_empty() {
        return ProbeOutcome::failed(
            contacted.load(Ordering::Relaxed),
            false,
            checks,
            "no_signing_credentials",
        );
    }
    let credential_id = match client.config().credential_id.as_deref() {
        Some(configured) if credential_ids.iter().any(|id| id == configured) => {
            configured.to_owned()
        }
        Some(_) => {
            checks.push(check(
                "credential_selection",
                false,
                "The configured credential_id was not returned by credentials/list.",
            ));
            return ProbeOutcome::failed(
                contacted.load(Ordering::Relaxed),
                false,
                checks,
                "configured_credential_not_found",
            );
        }
        None if credential_ids.len() == 1 => credential_ids[0].clone(),
        None => {
            checks.push(check(
                "credential_selection",
                false,
                "More than one credential is available; configure credential_id.",
            ));
            return ProbeOutcome::failed(
                contacted.load(Ordering::Relaxed),
                false,
                checks,
                "credential_selection_required",
            );
        }
    };
    checks.push(check(
        "credential_selection",
        true,
        "A single configured signing credential was selected.",
    ));
    match client.credential_info(token.as_str(), &credential_id) {
        Ok(info) => {
            checks.push(check(
                "credentials_info",
                true,
                format!(
                    "CSC returned a parseable signing certificate and {} issuer certificate(s); \
                     activation requirements were inspected but not invoked.",
                    info.chain_der.len()
                ),
            ));
            ProbeOutcome {
                status: "ok",
                provider_contacted: contacted.load(Ordering::Relaxed),
                private_key_operation_performed: false,
                checks,
                error: None,
            }
        }
        Err(error) => {
            checks.push(check("credentials_info", false, csc_error_detail(&error)));
            ProbeOutcome::failed(
                contacted.load(Ordering::Relaxed),
                false,
                checks,
                "provider_credential_info_failed",
            )
        }
    }
}

fn csc_error_detail(error: &CscError) -> &'static str {
    match error {
        CscError::Transport(_) => {
            "The CSC endpoint could not be reached within the bounded request."
        }
        CscError::ResponseTooLarge { .. } => "The CSC response exceeded the safety limit.",
        CscError::HttpStatus { .. } => "The CSC endpoint returned an unsuccessful HTTP status.",
        CscError::Service { .. } => "The CSC service rejected the safe probe operation.",
        CscError::ResponseParse(_) => "The CSC response did not match the expected protocol shape.",
        CscError::Config(_) => "The CSC probe configuration is incomplete or invalid.",
        CscError::NoCredential { .. } => "The CSC account exposes no signing credential.",
        CscError::NoSignature => "The CSC service returned no signature.",
        CscError::Certificate(_) => "The CSC credential certificate could not be parsed.",
        CscError::Base64(_) => "The CSC response contained malformed base64 data.",
        _ => "The CSC probe failed.",
    }
}

struct ProbeCscTransport {
    base_url: String,
    client: reqwest::blocking::Client,
    contacted: Arc<AtomicBool>,
    deadline: Instant,
}

impl ProbeCscTransport {
    fn new(
        vetted: crate::trust::VettedHttpUrl,
        contacted: Arc<AtomicBool>,
    ) -> Result<Self, reqwest::Error> {
        let base_url = vetted.as_str().to_owned();
        let client = vetted.client(PROBE_HTTP_TIMEOUT)?;
        Ok(Self {
            base_url,
            client,
            contacted,
            deadline: Instant::now() + PROBE_HTTP_TIMEOUT,
        })
    }

    fn url_for(&self, path: &str) -> String {
        format!(
            "{}/{}",
            self.base_url.trim_end_matches('/'),
            path.trim_start_matches('/')
        )
    }
}

fn remaining_csc_probe_timeout(deadline: Instant) -> Result<Duration, CscError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        Err(CscError::Transport(
            "cumulative probe deadline elapsed".to_owned(),
        ))
    } else {
        Ok(remaining)
    }
}

impl CscTransport for ProbeCscTransport {
    fn post_json(
        &self,
        path: &str,
        auth: CscAuthorizationHeader<'_>,
        body: &str,
    ) -> Result<String, CscError> {
        let remaining = remaining_csc_probe_timeout(self.deadline)?;
        let mut request = self
            .client
            .post(self.url_for(path))
            .timeout(remaining)
            .header("User-Agent", "chancela-provider-probe")
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .body(body.to_owned());
        request = match auth {
            CscAuthorizationHeader::None => request,
            CscAuthorizationHeader::Basic {
                client_id,
                client_secret,
            } => request.basic_auth(client_id, Some(client_secret)),
            CscAuthorizationHeader::Bearer(token) => request.bearer_auth(token),
        };
        // Mark the external attempt before DNS/TCP/TLS so a timeout or connection refusal is not
        // misreported as "no provider contact attempted".
        self.contacted.store(true, Ordering::Relaxed);
        let response = request
            .send()
            .map_err(|_| CscError::Transport("bounded request failed".to_owned()))?;
        let status = response.status();
        if !status.is_success() {
            return Err(CscError::HttpStatus {
                status: status.as_u16(),
            });
        }
        if response
            .content_length()
            .is_some_and(|length| length > PROBE_RESPONSE_LIMIT)
        {
            return Err(CscError::ResponseTooLarge {
                content_length: response.content_length().unwrap_or_default(),
                limit: PROBE_RESPONSE_LIMIT,
            });
        }
        let mut bytes = Vec::new();
        response
            .take(PROBE_RESPONSE_LIMIT + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| CscError::Transport("failed to read response".to_owned()))?;
        if bytes.len() as u64 > PROBE_RESPONSE_LIMIT {
            return Err(CscError::ResponseTooLarge {
                content_length: bytes.len() as u64,
                limit: PROBE_RESPONSE_LIMIT,
            });
        }
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }
}

fn probe_scap(mut entry: DecryptedCredentialEntry) -> ProbeOutcome {
    let mut checks = vec![check(
        "entry_enabled",
        true,
        "The stored credential entry is enabled.",
    )];
    let application_id = take_nonblank(&mut entry.fields, FIELD_APPLICATION_ID);
    let secret = take_nonblank(&mut entry.fields, FIELD_SECRET);
    let (Some(application_id), Some(secret)) = (application_id, secret) else {
        checks.push(check(
            "authorization_configuration",
            false,
            "SCAP provider listing requires application_id and secret.",
        ));
        return ProbeOutcome::failed(false, false, checks, "configuration_incomplete");
    };
    checks.push(check(
        "authorization_configuration",
        true,
        "The stored SCAP application credentials are configured.",
    ));
    let environment = match entry
        .selectors
        .get("environment")
        .map(|value| value.trim())
        .unwrap_or("prod")
    {
        "prod" => ScapEnvironment::Prod,
        "preprod" => ScapEnvironment::Preprod,
        _ => {
            checks.push(check(
                "environment_configuration",
                false,
                "The SCAP environment selector must be prod or preprod.",
            ));
            return ProbeOutcome::failed(false, false, checks, "configuration_invalid");
        }
    };
    let base_url = entry
        .endpoint
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| environment.default_base_url());
    let vetted = match crate::trust::validate_outbound_http_url(base_url) {
        Ok(vetted) => vetted,
        Err(_) => {
            checks.push(check(
                "endpoint_safe",
                false,
                "The SCAP base URL failed the outbound-network safety policy.",
            ));
            return ProbeOutcome::failed(false, false, checks, "unsafe_endpoint");
        }
    };
    if let Err(detail) = require_https_probe_endpoint(&vetted, "SCAP") {
        checks.push(check("endpoint_https", false, detail));
        return ProbeOutcome::failed(false, false, checks, "insecure_endpoint");
    }
    checks.push(check(
        "endpoint_https",
        true,
        "The SCAP base URL passed the outbound-network safety policy and uses HTTPS.",
    ));
    let config = AmaScapConfig {
        environment,
        base_url: vetted.as_str().to_owned(),
        credentials: Some(ScapCredentials::new(
            application_id.as_str().to_owned(),
            secret.as_str().to_owned(),
        )),
        provider_filter: None,
    };
    let contacted = Arc::new(AtomicBool::new(false));
    let transport = match ProbeScapTransport::new(&config, vetted, contacted.clone()) {
        Ok(transport) => transport,
        Err(_) => {
            checks.push(check(
                "outbound_client",
                false,
                "The bounded outbound client could not be created.",
            ));
            return ProbeOutcome::failed(false, false, checks, "outbound_client_unavailable");
        }
    };
    let client = match ScapClient::new(config, transport) {
        Ok(client) => client,
        Err(_) => {
            checks.push(check(
                "provider_configuration",
                false,
                "The SCAP provider configuration is invalid.",
            ));
            return ProbeOutcome::failed(false, false, checks, "configuration_invalid");
        }
    };
    match client.list_providers() {
        Ok(providers) => {
            checks.push(check(
                "providers_list",
                true,
                format!(
                    "SCAP returned {} attribute provider(s); no citizen data or signature was requested.",
                    providers.len()
                ),
            ));
            ProbeOutcome {
                status: "ok",
                provider_contacted: contacted.load(Ordering::Relaxed),
                private_key_operation_performed: false,
                checks,
                error: None,
            }
        }
        Err(_) => {
            checks.push(check(
                "providers_list",
                false,
                "The SCAP provider-list operation failed or returned an invalid response.",
            ));
            ProbeOutcome::failed(
                contacted.load(Ordering::Relaxed),
                false,
                checks,
                "provider_list_failed",
            )
        }
    }
}

struct ProbeScapTransport {
    base_url: String,
    authorization: Zeroizing<String>,
    client: reqwest::blocking::Client,
    contacted: Arc<AtomicBool>,
}

impl ProbeScapTransport {
    fn new(
        config: &AmaScapConfig,
        vetted: crate::trust::VettedHttpUrl,
        contacted: Arc<AtomicBool>,
    ) -> Result<Self, ScapError> {
        config.validate_http_transport()?;
        let credentials = config
            .credentials
            .as_ref()
            .ok_or_else(|| ScapError::Config("SCAP credentials are required".to_owned()))?;
        let raw_authorization = Zeroizing::new(format!(
            "{}:{}",
            credentials.application_id,
            credentials.secret.as_str()
        ));
        let authorization = Zeroizing::new(B64.encode(raw_authorization.as_bytes()));
        let base_url = vetted.as_str().to_owned();
        let client = vetted
            .client(PROBE_HTTP_TIMEOUT)
            .map_err(|_| ScapError::Transport("failed to build bounded client".to_owned()))?;
        Ok(Self {
            base_url,
            authorization,
            client,
            contacted,
        })
    }

    fn unsupported<T>() -> Result<T, ScapError> {
        Err(ScapError::Config(
            "the provider probe transport only permits provider listing".to_owned(),
        ))
    }
}

impl ScapTransport for ProbeScapTransport {
    fn list_providers(&self) -> Result<Vec<AttributeProvider>, ScapError> {
        // See the CSC transport: this marker means an outbound provider contact was attempted,
        // including attempts that fail during DNS/TCP/TLS setup.
        self.contacted.store(true, Ordering::Relaxed);
        let response = self
            .client
            .get(format!("{}/providers", self.base_url.trim_end_matches('/')))
            .header("User-Agent", "chancela-provider-probe")
            .header("Accept", "application/json")
            .header(
                "Authorization",
                Zeroizing::new(format!("Basic {}", self.authorization.as_str())).as_str(),
            )
            .send()
            .map_err(|_| ScapError::Transport("bounded request failed".to_owned()))?;
        if !response.status().is_success() {
            return Err(ScapError::Transport(format!(
                "SCAP endpoint returned HTTP {}",
                response.status().as_u16()
            )));
        }
        if response
            .content_length()
            .is_some_and(|length| length > PROBE_RESPONSE_LIMIT)
        {
            return Err(ScapError::Transport(
                "SCAP response exceeded the safety limit".to_owned(),
            ));
        }
        let mut bytes = Vec::new();
        response
            .take(PROBE_RESPONSE_LIMIT + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| ScapError::Transport("failed to read response".to_owned()))?;
        if bytes.len() as u64 > PROBE_RESPONSE_LIMIT {
            return Err(ScapError::Transport(
                "SCAP response exceeded the safety limit".to_owned(),
            ));
        }
        serde_json::from_slice(&bytes)
            .map_err(|_| ScapError::Transport("invalid SCAP provider-list response".to_owned()))
    }

    fn fetch_attributes(
        &self,
        _citizen: &CitizenRef,
    ) -> Result<Vec<ProfessionalAttribute>, ScapError> {
        Self::unsupported()
    }

    fn verify_attribute(
        &self,
        _attribute: &ProfessionalAttribute,
        _citizen: &CitizenRef,
    ) -> Result<VerificationDecision, ScapError> {
        Self::unsupported()
    }
}

fn probe_pkcs12(entry: DecryptedCredentialEntry) -> ProbeOutcome {
    let mut checks = vec![check(
        "entry_enabled",
        true,
        "The stored credential entry is enabled.",
    )];
    let input = match assemble_pkcs12_input(&entry) {
        Ok(input) => input,
        Err(_) => {
            checks.push(check(
                "pkcs12_loaded",
                false,
                "The stored PKCS#12 material or identity selector is incomplete or malformed.",
            ));
            return ProbeOutcome::failed(false, false, checks, "pkcs12_load_failed");
        }
    };
    let source = match Pkcs12SigningSource::from_der_with_selector(
        &input.pfx_der,
        &input.passphrase,
        &input.selector,
    ) {
        Ok(source) => source,
        Err(_) => {
            checks.push(check(
                "pkcs12_loaded",
                false,
                "The stored PKCS#12 identity could not be decrypted and selected.",
            ));
            return ProbeOutcome::failed(false, false, checks, "pkcs12_load_failed");
        }
    };
    checks.push(check(
        "pkcs12_loaded",
        true,
        "The stored PKCS#12 identity was decrypted and selected.",
    ));

    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    let mut hasher = Sha256::new();
    hasher.update(PKCS12_PROBE_DOMAIN);
    hasher.update(nonce);
    hasher.update(entry.entry_id.as_bytes());
    let challenge: [u8; 32] = hasher.finalize().into();
    let raw = match source.sign_signed_attributes(&challenge) {
        Ok(raw) => raw,
        Err(_) => {
            checks.push(check(
                "challenge_signed",
                false,
                "The private key could not sign the non-document probe challenge.",
            ));
            return ProbeOutcome::failed(false, false, checks, "private_key_operation_failed");
        }
    };
    checks.push(check(
        "challenge_signed",
        true,
        "The private key signed a random domain-separated non-document challenge.",
    ));
    match verify_pkcs12_probe_signature(&challenge, &raw) {
        Ok(()) => {
            checks.push(check(
                "challenge_verified",
                true,
                "The challenge signature verified locally against the selected certificate.",
            ));
            ProbeOutcome {
                status: "ok",
                provider_contacted: false,
                private_key_operation_performed: true,
                checks,
                error: None,
            }
        }
        Err(()) => {
            checks.push(check(
                "challenge_verified",
                false,
                "The challenge signature did not verify against the selected certificate.",
            ));
            ProbeOutcome::failed(false, true, checks, "local_verification_failed")
        }
    }
}

fn verify_pkcs12_probe_signature(
    digest: &[u8; 32],
    raw: &chancela_csc::RawSignature,
) -> Result<(), ()> {
    let certificate = Certificate::from_der(&raw.signing_cert_der).map_err(|_| ())?;
    match raw.algorithm {
        chancela_csc::SignatureAlgorithm::RsaPkcs1Sha256 => {
            use rsa::{Pkcs1v15Sign, RsaPublicKey};
            use x509_cert::der::referenced::OwnedToRef;
            const PREFIX: [u8; 19] = [
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x01, 0x05, 0x00, 0x04, 0x20,
            ];
            let public = RsaPublicKey::try_from(
                certificate
                    .tbs_certificate
                    .subject_public_key_info
                    .owned_to_ref(),
            )
            .map_err(|_| ())?;
            let mut digest_info = Vec::with_capacity(PREFIX.len() + digest.len());
            digest_info.extend_from_slice(&PREFIX);
            digest_info.extend_from_slice(digest);
            public
                .verify(Pkcs1v15Sign::new_unprefixed(), &digest_info, &raw.signature)
                .map_err(|_| ())
        }
        chancela_csc::SignatureAlgorithm::EcdsaP256Sha256 => {
            use p256::ecdsa::signature::hazmat::PrehashVerifier;
            use p256::ecdsa::{Signature, VerifyingKey};
            use p256::pkcs8::DecodePublicKey;
            let spki = certificate
                .tbs_certificate
                .subject_public_key_info
                .to_der()
                .map_err(|_| ())?;
            let key = VerifyingKey::from_public_key_der(&spki).map_err(|_| ())?;
            let signature = Signature::from_der(&raw.signature).map_err(|_| ())?;
            key.verify_prehash(digest, &signature).map_err(|_| ())
        }
        _ => Err(()),
    }
}

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
    // `smtp` and `totp` share the credential store but are NOT signing providers: SMTP is owned by
    // the mail settings, TOTP by the self-service second-factor enrolment endpoints. Both enforce
    // their own shape, so neither may be written through this generic signing-provider surface.
    if matches!(mode, CredentialMode::Smtp | CredentialMode::TwoFactorTotp) {
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
        // `Smtp` and `TwoFactorTotp` are unreachable here — `parse_mode` refuses both before this
        // point — but they are listed so the match stays exhaustive without a catch-all that would
        // silently absorb a future mode. `Smtp` is single-instance; `TwoFactorTotp` is per-user but
        // never routed here.
        CredentialMode::Cmd
        | CredentialMode::Scap
        | CredentialMode::Smtp
        | CredentialMode::TwoFactorTotp => {
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
    use chancela_authz::{
        OWNER_ROLE_ID, Permission, READER_ROLE_ID, Role, RoleAssignment, RoleCatalog, RoleId,
    };
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
            retired_attestation_keys: Vec::new(),
            totp: None,
            two_factor_required: false,
            force_password_change: false,
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

    async fn seed_configure_only_token(state: &AppState) -> String {
        let role_id = RoleId(Uuid::new_v4());
        state.roles.write().await.insert(Role {
            id: role_id,
            name: "Signing configuration probe test".to_owned(),
            permission_set: [Permission::SigningConfigure].into_iter().collect(),
            protected: false,
        });
        seed_token(state, role_id).await
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
    async fn create_entry_requires_signing_configure() {
        let tmp = TempDir::new();
        let state = state_with_store(&tmp.dir);
        let uri = "/v1/signature/provider-credentials/csc/encosto-qtsp/entries";
        let body = json!({ "label": "Primária", "set": { "client_secret": "sk_live_zzz" } });

        // No session → 401 (the CurrentActor extractor rejects before the handler).
        let (status, _) = send_with(state.clone(), body_req("POST", uri, body.clone()), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        // settings.read but not signing.configure (LEITOR) → 403 (t50 gate).
        let leitor = seed_token(&state, READER_ROLE_ID).await;
        let (status, b) = send_with(
            state.clone(),
            body_req("POST", uri, body.clone()),
            Some(&leitor),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{b}");

        // signing.configure (OWNER holds it via Permission::ALL) → 201.
        let owner = seed_token(&state, OWNER_ROLE_ID).await;
        let (status, b) = send_with(state, body_req("POST", uri, body), Some(&owner)).await;
        assert_eq!(status, StatusCode::CREATED, "{b}");
    }

    /// The CMD preflight judges an entry against the environment the deployment is configured for,
    /// and reports what a signature would actually need — using the **admin-panel field names** an
    /// operator can go and fill, never the environment variables they never set.
    ///
    /// This stays entirely offline: a production entry missing its AMA certificate fails at
    /// assembly, long before the endpoint-reachability check that only a complete production
    /// config reaches.
    #[tokio::test]
    async fn cmd_preflight_names_the_admin_panel_field_a_production_entry_is_missing() {
        let tmp = TempDir::new();
        let state = state_with_store(&tmp.dir);
        state.settings.write().await.signing.cmd.env = crate::settings::CmdEnvSetting::Prod;
        let owner = seed_token(&state, OWNER_ROLE_ID).await;
        let (status, created) = send_with(
            state.clone(),
            body_req(
                "POST",
                "/v1/signature/provider-credentials/cmd/_/entries",
                json!({
                    "label": "CMD produção",
                    "set": {
                        "application_id": "CHANCELA-PROD-0001",
                        "http_basic_username": "ama-user",
                        "http_basic_password": "ama-password",
                    },
                }),
            ),
            Some(&owner),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let entry_id = created["entry"]["entry_id"].as_str().expect("entry id");

        let (status, body) = send_with(
            state.clone(),
            body_req(
                "POST",
                &format!("/v1/signature/provider-credentials/cmd/_/entries/{entry_id}/probe"),
                json!({}),
            ),
            Some(&owner),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["status"], "failed", "{body}");
        assert_eq!(body["error"], "configuration_incomplete", "{body}");
        // No SCMD operation, ever — the honest negatives are unchanged by the preflight.
        assert_eq!(body["provider_contacted"], false, "{body}");
        assert_eq!(body["document_signed"], false, "{body}");
        assert_eq!(body["qualified_status_determined"], false, "{body}");

        let checks = body["checks"].as_array().expect("checks");
        let named = |name: &str| -> &Value {
            checks
                .iter()
                .find(|check| check["name"] == name)
                .unwrap_or_else(|| panic!("check {name} is reported: {body}"))
        };
        assert_eq!(named("configured_environment")["status"], "passed", "{body}");
        assert!(
            named("configured_environment")["detail"]
                .as_str()
                .unwrap_or_default()
                .contains("prod"),
            "the preflight says which environment it judged against: {body}"
        );
        let missing = named("stored_credential_fields");
        assert_eq!(missing["status"], "failed", "{body}");
        let detail = missing["detail"].as_str().unwrap_or_default();
        assert!(
            detail.contains(crate::secretstore_persist::FIELD_AMA_CERT_PEM),
            "the preflight names the admin-panel field that is missing: {body}"
        );
        assert!(
            !detail.contains("CHANCELA_CMD_"),
            "an operator who filled a form must not be pointed at environment variables: {body}"
        );
        // The reason CMD has no health check is unchanged and still reported on every path.
        let live = named("live_provider_operation");
        assert_eq!(live["status"], "skipped", "{body}");
        assert!(
            live["detail"]
                .as_str()
                .unwrap_or_default()
                .contains("no safe non-signing health operation"),
            "{body}"
        );
    }

    #[tokio::test]
    async fn probe_requires_signing_configure_and_cmd_is_honestly_interactive_only() {
        let tmp = TempDir::new();
        let state = state_with_store(&tmp.dir);
        let owner = seed_token(&state, OWNER_ROLE_ID).await;
        let reader = seed_token(&state, READER_ROLE_ID).await;
        let create_uri = "/v1/signature/provider-credentials/cmd/_/entries";
        let (status, created) = send_with(
            state.clone(),
            body_req(
                "POST",
                create_uri,
                json!({ "label": "CMD principal", "set": { "application_id": "configured" } }),
            ),
            Some(&owner),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let entry_id = created["entry"]["entry_id"].as_str().expect("entry id");
        let probe_uri =
            format!("/v1/signature/provider-credentials/cmd/_/entries/{entry_id}/probe");

        let (status, body) = send_with(
            state.clone(),
            body_req("POST", &probe_uri, json!({})),
            Some(&reader),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

        let (status, body) = send_with(
            state.clone(),
            body_req("POST", &probe_uri, json!({})),
            Some(&owner),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["status"], "interactive_required", "{body}");
        assert_eq!(body["provider_contacted"], false, "{body}");
        assert_eq!(body["private_key_operation_performed"], false, "{body}");
        assert_eq!(body["signer_authorization_requested"], false, "{body}");
        assert_eq!(body["document_signed"], false, "{body}");
        assert_eq!(body["legal_validity_claimed"], false, "{body}");
        assert_eq!(body["qualified_status_determined"], false, "{body}");
        assert_eq!(body["error"], "interactive_required", "{body}");
        {
            let ledger = state.ledger.read().await;
            let kinds: Vec<&str> = ledger
                .events()
                .iter()
                .rev()
                .take(2)
                .map(|event| event.kind.as_str())
                .collect();
            assert_eq!(
                kinds,
                [
                    "provider.credentials.entry.probed",
                    "provider.credentials.entry.probe_requested"
                ]
            );
        }

        let (status, body) = send_with(
            state.clone(),
            body_req("POST", &probe_uri, json!({ "unexpected": true })),
            Some(&owner),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");

        let oversized = "x".repeat(256);
        let mut request = body_req("POST", &probe_uri, json!({ "unexpected": oversized }));
        request
            .headers_mut()
            .insert("x-chancela-session", owner.parse().unwrap());
        let response = crate::router(state)
            .oneshot(request)
            .await
            .expect("router responds");
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn csc_probe_fails_closed_before_contacting_an_unsafe_endpoint() {
        let tmp = TempDir::new();
        let state = state_with_store(&tmp.dir);
        let owner = seed_token(&state, OWNER_ROLE_ID).await;
        let create_uri = "/v1/signature/provider-credentials/csc/example-qtsp/entries";
        let (status, created) = send_with(
            state.clone(),
            body_req(
                "POST",
                create_uri,
                json!({
                    "endpoint": "http://169.254.169.254/latest/meta-data",
                    "selectors": { "authorization": "service" },
                    "set": { "client_id": "client", "client_secret": "secret" }
                }),
            ),
            Some(&owner),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let entry_id = created["entry"]["entry_id"].as_str().expect("entry id");
        let probe_uri =
            format!("/v1/signature/provider-credentials/csc/example-qtsp/entries/{entry_id}/probe");
        let (status, body) =
            send_with(state, body_req("POST", &probe_uri, json!({})), Some(&owner)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["status"], "failed", "{body}");
        assert_eq!(body["error"], "unsafe_endpoint", "{body}");
        assert_eq!(body["provider_contacted"], false, "{body}");
        assert_eq!(body["document_signed"], false, "{body}");
    }

    #[test]
    fn csc_probe_uses_one_cumulative_deadline() {
        let future = Instant::now() + PROBE_HTTP_TIMEOUT;
        let remaining = remaining_csc_probe_timeout(future).expect("deadline remains");
        assert!(remaining <= PROBE_HTTP_TIMEOUT);
        assert!(remaining > Duration::ZERO);

        let elapsed = Instant::now() - Duration::from_millis(1);
        assert!(remaining_csc_probe_timeout(elapsed).is_err());
    }

    #[tokio::test]
    async fn credential_bearing_probes_refuse_plain_http_before_sending_secrets() {
        for (mode, provider, selectors, fields) in [
            (
                "csc",
                "public-http",
                json!({ "authorization": "service" }),
                json!({ "client_id": "client", "client_secret": "secret" }),
            ),
            (
                "scap",
                "_",
                json!({ "environment": "prod" }),
                json!({ "application_id": "application", "secret": "secret" }),
            ),
        ] {
            let tmp = TempDir::new();
            let state = state_with_store(&tmp.dir);
            let owner = seed_token(&state, OWNER_ROLE_ID).await;
            let create_uri =
                format!("/v1/signature/provider-credentials/{mode}/{provider}/entries");
            let (status, created) = send_with(
                state.clone(),
                body_req(
                    "POST",
                    &create_uri,
                    json!({
                        "endpoint": "http://example.com/provider-api",
                        "selectors": selectors,
                        "set": fields
                    }),
                ),
                Some(&owner),
            )
            .await;
            assert_eq!(status, StatusCode::CREATED, "{created}");
            let entry_id = created["entry"]["entry_id"].as_str().expect("entry id");
            let probe_uri = format!("{create_uri}/{entry_id}/probe");
            let (status, body) =
                send_with(state, body_req("POST", &probe_uri, json!({})), Some(&owner)).await;
            assert_eq!(status, StatusCode::OK, "{body}");
            assert_eq!(body["status"], "failed", "{body}");
            assert_eq!(body["error"], "insecure_endpoint", "{body}");
            assert_eq!(body["provider_contacted"], false, "{body}");
            assert_eq!(body["private_key_operation_performed"], false, "{body}");
        }
    }

    #[tokio::test]
    async fn pkcs12_probe_requires_perform_permission_and_explicit_confirmation() {
        let tmp = TempDir::new();
        let state = state_with_store(&tmp.dir);
        let owner = seed_token(&state, OWNER_ROLE_ID).await;
        let configure_only = seed_configure_only_token(&state).await;
        let create_uri = "/v1/signature/provider-credentials/pkcs12/local/entries";
        let (status, created) = send_with(
            state.clone(),
            body_req(
                "POST",
                create_uri,
                json!({ "set": { "pfx_der": "AQID", "passphrase": "secret" } }),
            ),
            Some(&owner),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let entry_id = created["entry"]["entry_id"].as_str().expect("entry id");
        let probe_uri = format!("{create_uri}/{entry_id}/probe");

        let (status, body) = send_with(
            state.clone(),
            body_req(
                "POST",
                &probe_uri,
                json!({ "confirm_private_key_operation": true }),
            ),
            Some(&configure_only),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

        let (status, body) =
            send_with(state, body_req("POST", &probe_uri, json!({})), Some(&owner)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert!(
            body.to_string().contains("confirm_private_key_operation"),
            "{body}"
        );
    }

    #[tokio::test]
    async fn changing_endpoint_origin_requires_replacing_every_stored_field() {
        let tmp = TempDir::new();
        let state = state_with_store(&tmp.dir);
        let owner = seed_token(&state, OWNER_ROLE_ID).await;
        let base = "/v1/signature/provider-credentials/scap/_/entries";
        let (status, created) = send_with(
            state.clone(),
            body_req(
                "POST",
                base,
                json!({
                    "endpoint": "https://old.example/scap",
                    "set": {
                        "application_id": "app",
                        "secret": "secret",
                        "http_basic_username": "gateway",
                        "http_basic_password": "gateway-secret"
                    }
                }),
            ),
            Some(&owner),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let entry_id = created["entry"]["entry_id"].as_str().expect("entry id");
        let update_uri = format!("{base}/{entry_id}");
        let (status, body) = send_with(
            state.clone(),
            body_req(
                "PATCH",
                &update_uri,
                json!({
                    "endpoint": "https://new.example/scap",
                    "set": { "application_id": "new-app", "secret": "new-secret" }
                }),
            ),
            Some(&owner),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert!(body.to_string().contains("re-entering every"), "{body}");
        assert!(!body.to_string().contains("gateway-secret"), "{body}");

        let (status, body) = send_with(
            state,
            body_req(
                "PATCH",
                &update_uri,
                json!({
                    "endpoint": "https://new.example/scap",
                    "set": {
                        "application_id": "new-app",
                        "secret": "new-secret",
                        "http_basic_username": "new-gateway",
                        "http_basic_password": "new-gateway-secret"
                    }
                }),
            ),
            Some(&owner),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["entry"]["endpoint"], "https://new.example/scap");
        assert!(!body.to_string().contains("new-gateway-secret"), "{body}");
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

    /// Signing time discriminates all three trust-failure states since t61-e2 —
    /// `TrustAnchorNotConfigured` for (A), `TrustedListNotAnchored` for (B), `UntrustedService` for
    /// (C) alone. This check is not that diagnosis; it exists so state (A) is settled *before* a
    /// real qualified signature is attempted, and so the operator is pointed at their own
    /// configuration rather than at the signer.
    #[test]
    fn the_trust_anchor_check_separates_unconfigured_from_the_signers_service() {
        // (A), both shapes: no list at all, and a list with an empty anchor set. Each must fail,
        // and each must point at the operator's own configuration.
        for preflight in [
            CmdTrustAnchorPreflight::NoListSelected,
            CmdTrustAnchorPreflight::Unanchored,
        ] {
            let result = cmd_trust_anchor_check(&preflight);
            assert_eq!(result.status, "failed", "{}", result.detail);
            assert!(
                !result.detail.contains("CHANCELA_"),
                "an operator who filled the admin panel must never be shown an env var name: {}",
                result.detail
            );
        }

        // The unanchored arm is the one that would otherwise be misread as a signer problem, so it
        // must say plainly that the fault is local — and, since t61-e2, it must say so about the
        // error the operator will actually see. This text once promised an error "naming the
        // signer's trust service, though the fault is here"; state (A) now raises
        // `SigningError::TrustAnchorNotConfigured`, which names the anchor. The claim about the
        // signer had to move with the behaviour, so pinning the old phrase would pin a promise the
        // code no longer keeps.
        let unanchored = cmd_trust_anchor_check(&CmdTrustAnchorPreflight::Unanchored);
        assert!(
            unanchored
                .detail
                .contains("naming this missing anchor rather than the signer's trust service"),
            "{}",
            unanchored.detail
        );
        assert!(
            unanchored
                .detail
                .contains("signing.tsl_trust_anchor_certs"),
            "{}",
            unanchored.detail
        );

        // Anchored: passes, reports which source resolved, and does NOT claim the list
        // authenticates or that the signer's service is Granted — neither is probed here.
        let both = cmd_trust_anchor_check(&CmdTrustAnchorPreflight::Anchored {
            total: 3,
            from_env: 1,
        });
        assert_eq!(both.status, "passed", "{}", both.detail);
        assert!(both.detail.contains("1 from the environment"), "{}", both.detail);
        assert!(
            both.detail.contains("at least 2 from the signing settings"),
            "{}",
            both.detail
        );
        assert!(
            both.detail.contains("determined at signing time"),
            "the check must not overclaim what it verified: {}",
            both.detail
        );

        let settings_only = cmd_trust_anchor_check(&CmdTrustAnchorPreflight::Anchored {
            total: 2,
            from_env: 0,
        });
        assert!(
            settings_only
                .detail
                .contains("all of them from the signing settings"),
            "{}",
            settings_only.detail
        );

        let env_only = cmd_trust_anchor_check(&CmdTrustAnchorPreflight::Anchored {
            total: 2,
            from_env: 2,
        });
        assert!(
            env_only.detail.contains("all of them from the environment"),
            "{}",
            env_only.detail
        );

        // A malformed anchor fails closed rather than degrading to "unanchored".
        let invalid =
            cmd_trust_anchor_check(&CmdTrustAnchorPreflight::AnchorsInvalid("bad hex".to_owned()));
        assert_eq!(invalid.status, "failed", "{}", invalid.detail);
        assert!(invalid.detail.contains("fails closed"), "{}", invalid.detail);
    }
}
