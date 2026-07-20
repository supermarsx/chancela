//! Read-only provider credential storage status.
//!
//! This endpoint reports only metadata from the encrypted credential sidecar and the root-key source
//! classification. It never decrypts fields, returns ciphertext, creates/rotates/clears credentials,
//! returns credential-derived suffixes or raw provider IDs, or calls live CMD/CSC/SCAP providers.

use axum::Json;
use axum::extract::State;
use chancela_authz::{Permission, Scope};
use serde::Serialize;

use crate::actor::CurrentActor;
use crate::authz::require_permission;
use crate::error::ApiError;
use crate::secretstore::{
    CredentialKeyReadOnlyStatus, CredentialKeySource, CredentialKeyStatusFailure, ProtectionLevel,
};
use crate::{AppState, CredentialMode, CredentialRecordStatus, ProviderCredentialError};

#[derive(Debug, Serialize)]
pub struct ProviderCredentialStorageStatusResponse {
    pub report_kind: &'static str,
    pub scope: &'static str,
    pub read_only: bool,
    pub live_provider_calls: bool,
    pub production_or_legal_use_claimed: bool,
    pub redaction: ProviderCredentialRedactionStatus,
    pub storage: ProviderCredentialStorageStatus,
    pub records: Vec<ProviderCredentialRecordStatusView>,
}

#[derive(Debug, Serialize)]
pub struct ProviderCredentialRedactionStatus {
    pub plaintext_secrets_returned: bool,
    pub ciphertext_returned: bool,
    pub raw_key_material_returned: bool,
    pub tokens_returned: bool,
    pub field_values_redacted: bool,
    pub secret_identifiers_returned: bool,
}

#[derive(Debug, Serialize)]
pub struct ProviderCredentialStorageStatus {
    pub sidecar_status: &'static str,
    pub crypto_status: &'static str,
    pub strict: bool,
    pub protection_level: Option<ProtectionLevel>,
    pub key_source_class: Option<&'static str>,
    pub key_source_provider: Option<&'static str>,
    pub key_version: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sidecar_failure: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_failure: Option<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct ProviderCredentialRecordStatusView {
    pub mode: &'static str,
    pub provider_id: Option<String>,
    pub provider_id_redacted: bool,
    pub key_version: u32,
    pub fields: Vec<ProviderCredentialFieldStatusView>,
}

#[derive(Debug, Serialize)]
pub struct ProviderCredentialFieldStatusView {
    pub field_name: String,
    pub configured: bool,
    pub last4: Option<String>,
    pub plaintext_redacted: bool,
    pub ciphertext_redacted: bool,
    pub raw_value_returned: bool,
}

/// `GET /v1/signature/provider-credentials/status` - read-only credential storage metadata.
pub async fn provider_credential_status(
    State(state): State<AppState>,
    actor: CurrentActor,
) -> Result<Json<ProviderCredentialStorageStatusResponse>, ApiError> {
    require_permission(&state, &actor, Permission::SettingsRead, Scope::Global).await?;

    let key_status = state.provider_credentials.key_status();
    let (sidecar_status, sidecar_failure, records) = match state.provider_credentials.statuses() {
        Ok(records) => (
            "available",
            None,
            records
                .into_iter()
                .map(record_status_view)
                .collect::<Vec<_>>(),
        ),
        Err(err) => ("fail_closed", Some(sidecar_failure_code(&err)), Vec::new()),
    };

    Ok(Json(ProviderCredentialStorageStatusResponse {
        report_kind: "provider_credential_storage_status",
        scope: "provider_credential_storage_metadata_only",
        read_only: true,
        live_provider_calls: false,
        production_or_legal_use_claimed: false,
        redaction: ProviderCredentialRedactionStatus {
            plaintext_secrets_returned: false,
            ciphertext_returned: false,
            raw_key_material_returned: false,
            tokens_returned: false,
            field_values_redacted: true,
            secret_identifiers_returned: false,
        },
        storage: storage_status(
            sidecar_status,
            sidecar_failure,
            state.provider_credentials.strict(),
            key_status,
        ),
        records,
    }))
}

fn storage_status(
    sidecar_status: &'static str,
    sidecar_failure: Option<&'static str>,
    strict: bool,
    key_status: CredentialKeyReadOnlyStatus,
) -> ProviderCredentialStorageStatus {
    let key_source_class = key_status.key_source.as_ref().map(key_source_class);
    let key_source_provider = key_status.key_source.as_ref().and_then(key_source_provider);
    ProviderCredentialStorageStatus {
        sidecar_status,
        crypto_status: if key_status.available {
            "available"
        } else {
            "unavailable_fail_closed"
        },
        strict,
        protection_level: key_status.protection_level,
        key_source_class,
        key_source_provider,
        key_version: key_status.key_version,
        sidecar_failure,
        key_failure: key_status.failure.map(key_failure_code),
    }
}

fn record_status_view(record: CredentialRecordStatus) -> ProviderCredentialRecordStatusView {
    ProviderCredentialRecordStatusView {
        mode: mode_wire(record.mode),
        provider_id: None,
        provider_id_redacted: true,
        key_version: record.key_version,
        fields: record.fields.into_iter().map(field_status_view).collect(),
    }
}

fn field_status_view(
    (field_name, _last4): (String, Option<String>),
) -> ProviderCredentialFieldStatusView {
    ProviderCredentialFieldStatusView {
        field_name,
        configured: true,
        last4: None,
        plaintext_redacted: true,
        ciphertext_redacted: true,
        raw_value_returned: false,
    }
}

fn mode_wire(mode: CredentialMode) -> &'static str {
    mode.as_str()
}

fn key_source_class(source: &CredentialKeySource) -> &'static str {
    match source {
        CredentialKeySource::OsProtected { .. } => "os_protected",
        CredentialKeySource::DerivedFromDbKey => "derived_from_db_key",
        CredentialKeySource::OperatorEnv => "operator_env",
    }
}

fn key_source_provider(source: &CredentialKeySource) -> Option<&'static str> {
    match source {
        CredentialKeySource::OsProtected { provider } => Some(*provider),
        CredentialKeySource::DerivedFromDbKey | CredentialKeySource::OperatorEnv => None,
    }
}

/// Sanitized wire code for a key-status failure. Shared with the management list
/// ([`crate::provider_credentials_write`]) so both surfaces name the same cause identically.
pub(crate) fn key_failure_code(failure: CredentialKeyStatusFailure) -> &'static str {
    match failure {
        CredentialKeyStatusFailure::NoKeySource => "missing_key_source",
        CredentialKeyStatusFailure::NotPersistent => "not_persistent",
        CredentialKeyStatusFailure::AmbiguousOperatorKey => "ambiguous_operator_key",
        CredentialKeyStatusFailure::InvalidOperatorKey => "invalid_operator_key",
        CredentialKeyStatusFailure::MissingRootEnvelope => "missing_root_envelope",
        CredentialKeyStatusFailure::InvalidRootEnvelope => "invalid_root_envelope",
        CredentialKeyStatusFailure::StoreUnavailable => "store_unavailable",
    }
}

fn sidecar_failure_code(err: &ProviderCredentialError) -> &'static str {
    match err {
        ProviderCredentialError::CorruptSidecar(_) => "corrupt_sidecar",
        ProviderCredentialError::Poisoned => "store_unavailable",
        ProviderCredentialError::NotPersistent => "not_persistent",
        ProviderCredentialError::Secret(_)
        | ProviderCredentialError::RuntimeStrictModeUnprotected { .. }
        | ProviderCredentialError::UnknownField { .. }
        | ProviderCredentialError::Io { .. } => "status_unavailable",
    }
}
