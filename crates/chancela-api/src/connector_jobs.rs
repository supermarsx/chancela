//! Tenant-scoped connector targets and audited durable worker jobs (ARC-20/21, WFL-40).
//!
//! Callers never submit host filesystem paths. A run request selects a server-owned immutable act
//! document or the latest whole-instance backup; the API materializes a copy below its fixed worker
//! source root and stages the queue entry. Target configuration stores only the connector crate's
//! validated credential references. The worker resolves those references from its environment or a
//! symlink-free file beneath `CHANCELA_CONNECTOR_SECRETS_DIR`.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use axum::Json;
use axum::extract::{Path as AxumPath, Query, State};
use axum::http::StatusCode;
use chancela_authz::{IntegrationId, Permission, RepositoryId, Scope};
use chancela_connectors::{
    EnvSecretProvider, JobPurpose, TargetConfig, build_connector, validate_destination,
};
use chancela_core::{ActId, TenantId};
use chancela_worker::{DurableQueue, JobSnapshot, JobState, WorkerError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use crate::actor::{CurrentActor, CurrentAttestor};
use crate::authz::{authorizer, require_permission, scope_of_act, scope_of_tenant};
use crate::settings::effective_network_policy;
use crate::{ApiError, AppState};

pub(crate) const CONNECTOR_TARGETS_FILE: &str = "connector-targets.json";
const MAX_TARGETS_PER_TENANT: usize = 128;
const MAX_TARGET_NAME_CHARS: usize = 160;
const MAX_TARGETS_FILE_BYTES: u64 = 1024 * 1024;
const DEFAULT_JOB_LIMIT: usize = 50;
const MAX_JOB_LIMIT: usize = 100;
const QUEUE_SCAN_LIMIT: usize = 500;
pub(crate) const CONNECTOR_REQUEST_BYTES: usize = 64 * 1024;

pub type ConnectorTargetMap = HashMap<Uuid, ConnectorTargetRecord>;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorTargetRecord {
    schema_version: u32,
    pub(crate) id: Uuid,
    pub(crate) repository_id: Uuid,
    pub(crate) tenant_id: TenantId,
    name: String,
    enabled: bool,
    purposes: BTreeSet<JobPurpose>,
    config: TargetConfig,
    created_at: String,
    updated_at: String,
    archived_at: Option<String>,
}

impl ConnectorTargetRecord {
    pub(crate) fn is_active(&self) -> bool {
        self.archived_at.is_none()
    }

    fn integration_scope(&self) -> Scope {
        Scope::Integration(IntegrationId(self.id))
    }

    fn repository_scope(&self) -> Scope {
        Scope::Repository(RepositoryId(self.repository_id))
    }

    fn permits(&self, purpose: JobPurpose) -> bool {
        self.enabled && self.is_active() && self.purposes.contains(&purpose)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateTargetBody {
    name: String,
    #[serde(default = "default_enabled")]
    enabled: bool,
    purposes: BTreeSet<JobPurpose>,
    config: TargetConfig,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PatchTargetBody {
    name: Option<String>,
    enabled: Option<bool>,
    purposes: Option<BTreeSet<JobPurpose>>,
    config: Option<TargetConfig>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ConnectorTargetView {
    schema_version: u32,
    id: Uuid,
    repository_id: Uuid,
    tenant_id: TenantId,
    name: String,
    enabled: bool,
    purposes: BTreeSet<JobPurpose>,
    kind: chancela_connectors::ConnectorKind,
    config: TargetConfig,
    credential_storage: &'static str,
    created_at: String,
    updated_at: String,
    archived_at: Option<String>,
}

impl From<&ConnectorTargetRecord> for ConnectorTargetView {
    fn from(record: &ConnectorTargetRecord) -> Self {
        Self {
            schema_version: record.schema_version,
            id: record.id,
            repository_id: record.repository_id,
            tenant_id: record.tenant_id,
            name: record.name.clone(),
            enabled: record.enabled,
            purposes: record.purposes.clone(),
            kind: record.config.kind(),
            config: record.config.clone(),
            credential_storage: "environment_or_confined_file_reference",
            created_at: record.created_at.clone(),
            updated_at: record.updated_at.clone(),
            archived_at: record.archived_at.clone(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum RunArtifact {
    ActDocument {
        act_id: Uuid,
        #[serde(default)]
        variant: ActDocumentVariant,
    },
    LatestInstanceBackup,
}

#[derive(Clone, Copy, Debug, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ActDocumentVariant {
    #[default]
    Canonical,
    Signed,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RunTargetBody {
    request_id: Uuid,
    purpose: JobPurpose,
    artifact: RunArtifact,
    destination: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ListJobsQuery {
    limit: Option<usize>,
    before_created_unix_millis: Option<u64>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ConnectorJobListView {
    jobs: Vec<ConnectorJobView>,
    next_before_created_unix_millis: Option<u64>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ConnectorJobView {
    id: String,
    tenant_id: String,
    target_id: Uuid,
    repository_id: Uuid,
    purpose: JobPurpose,
    destination: String,
    content_type: String,
    source_sha256: String,
    bytes: u64,
    created_unix_millis: u64,
    state: JobState,
    attempt: u32,
    not_before_unix_millis: Option<u64>,
    error_class: Option<chancela_connectors::ErrorClass>,
    detail: String,
    receipt: Option<ConnectorJobReceiptView>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ConnectorJobReceiptView {
    completed_unix_millis: u64,
    connector: chancela_connectors::ConnectorKind,
    provider_object_id: Option<String>,
    provider_revision: Option<String>,
    etag: Option<String>,
    remote_bytes: u64,
    checksum_evidence: chancela_connectors::ChecksumEvidence,
}

#[derive(Debug, Serialize)]
pub(crate) struct ConnectorProbeView {
    target_id: Uuid,
    checked_at: String,
    status: Option<chancela_connectors::ConnectorStatus>,
    error_class: Option<chancela_connectors::ErrorClass>,
    error: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct DashboardJobCounts {
    pub failed_sync_jobs: usize,
    pub pending_backup_jobs: usize,
}

fn default_enabled() -> bool {
    true
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
}

fn normalized_name(value: String) -> Result<String, ApiError> {
    let value = value.trim().to_owned();
    if value.is_empty() || value.chars().count() > MAX_TARGET_NAME_CHARS {
        return Err(ApiError::Unprocessable(format!(
            "connector target name must contain 1 to {MAX_TARGET_NAME_CHARS} characters"
        )));
    }
    Ok(value)
}

fn validate_purposes(
    purposes: &BTreeSet<JobPurpose>,
    config: &TargetConfig,
) -> Result<(), ApiError> {
    if purposes.is_empty() {
        return Err(ApiError::Unprocessable(
            "connector target must allow at least one purpose".to_owned(),
        ));
    }
    if purposes.contains(&JobPurpose::Sync) && matches!(config, TargetConfig::S3(_)) {
        return Err(ApiError::Unprocessable(
            "S3 targets are backup-only and cannot be enabled for sync".to_owned(),
        ));
    }
    Ok(())
}

async fn validate_api_target(state: &AppState, config: &TargetConfig) -> Result<(), ApiError> {
    if matches!(config, TargetConfig::Local(_)) {
        return Err(ApiError::Unprocessable(
            "local filesystem connector targets are deployment-only and cannot be created through the API"
                .to_owned(),
        ));
    }
    config
        .validate()
        .map_err(|error| ApiError::Unprocessable(error.to_string()))?;
    // The effective boundary: the deployment ceiling narrowed by whatever an administrator saved
    // in Settings. Resolved from live state, so a target accepted before a narrowing is re-checked
    // against the current allowlist on every subsequent probe/run, not only at creation.
    let policy = effective_network_policy(state)
        .await
        .map_err(|error| ApiError::Unprocessable(error.to_string()))?;
    config
        .validate_network_policy(&policy)
        .await
        .map_err(|error| ApiError::Unprocessable(error.to_string()))
}

fn target_for_path(
    targets: &ConnectorTargetMap,
    tenant_id: TenantId,
    target_id: Uuid,
) -> Result<&ConnectorTargetRecord, ApiError> {
    targets
        .get(&target_id)
        .filter(|target| target.tenant_id == tenant_id)
        .ok_or(ApiError::NotFound)
}

fn require_persistent_targets_path(state: &AppState) -> Result<&Path, ApiError> {
    state
        .connector_targets_path
        .as_deref()
        .map(PathBuf::as_path)
        .ok_or_else(|| {
            ApiError::Unprocessable(
                "connector target management requires CHANCELA_DATA_DIR".to_owned(),
            )
        })
}

pub(crate) fn load_targets(path: &Path) -> ConnectorTargetMap {
    let Ok(metadata) = std::fs::metadata(path) else {
        return HashMap::new();
    };
    if !metadata.is_file() || metadata.len() > MAX_TARGETS_FILE_BYTES {
        eprintln!(
            "warning: {} is not a bounded connector target document; ignoring it",
            path.display()
        );
        return HashMap::new();
    }
    let Ok(bytes) = std::fs::read(path) else {
        return HashMap::new();
    };
    let Ok(records) = serde_json::from_slice::<Vec<ConnectorTargetRecord>>(&bytes) else {
        eprintln!(
            "warning: {} is not valid connector target JSON; ignoring it",
            path.display()
        );
        return HashMap::new();
    };
    let mut targets = HashMap::new();
    for record in records {
        let valid = record.schema_version == 1
            && record.config.id() == record.id.to_string()
            && record.config.validate().is_ok()
            && !matches!(record.config, TargetConfig::Local(_))
            && validate_purposes(&record.purposes, &record.config).is_ok();
        if !valid || targets.insert(record.id, record).is_some() {
            eprintln!(
                "warning: {} contains an invalid or duplicate connector target; ignoring the entire document",
                path.display()
            );
            return HashMap::new();
        }
    }
    targets
}

fn write_targets_atomic(path: &Path, targets: &ConnectorTargetMap) -> std::io::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let mut records = targets.values().collect::<Vec<_>>();
    records.sort_by(|left, right| {
        left.tenant_id
            .cmp(&right.tenant_id)
            .then(left.created_at.cmp(&right.created_at))
            .then(left.id.cmp(&right.id))
    });
    let bytes = serde_json::to_vec_pretty(&records).map_err(std::io::Error::other)?;
    let temporary = path.with_file_name(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|value| value.to_str())
            .unwrap_or(CONNECTOR_TARGETS_FILE),
        Uuid::new_v4()
    ));
    std::fs::write(&temporary, bytes)?;
    match std::fs::rename(&temporary, path) {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = std::fs::remove_file(temporary);
            Err(error)
        }
    }
}

async fn persist_target_registry_change(
    state: &AppState,
    attestor: &CurrentAttestor,
    actor: &str,
    previous: &ConnectorTargetMap,
    next: &ConnectorTargetMap,
    kind: &str,
    target: &ConnectorTargetRecord,
) -> Result<(), ApiError> {
    let path = require_persistent_targets_path(state)?.to_path_buf();
    let payload = serde_json::to_vec(&serde_json::json!({
        "target_id": target.id,
        "repository_id": target.repository_id,
        "tenant_id": target.tenant_id,
        "kind": target.config.kind(),
        "enabled": target.enabled,
        "purposes": target.purposes,
        "archived": target.archived_at.is_some(),
    }))?;
    let scope = format!("tenant:{}", target.tenant_id);
    let object = format!("connector-target:{}", target.id);
    let mut ledger = state.ledger.write().await;
    crate::try_append_event(&mut ledger, actor, &scope, kind, Some(&object), &payload)?;
    if let Err(error) = write_targets_atomic(&path, next) {
        AppState::rollback_ledger_events(&mut ledger, 1);
        return Err(ApiError::Internal(format!(
            "failed to persist connector target registry: {}",
            error.kind()
        )));
    }
    if let Err(error) = state
        .persist_write_through(&mut ledger, 1, |_tx| Ok(()))
        .await
    {
        if let Err(rollback_error) = write_targets_atomic(&path, previous) {
            eprintln!(
                "connector target sidecar rollback failed after ledger persistence failure: {}",
                rollback_error.kind()
            );
        }
        return Err(error);
    }
    state.attest_latest(attestor, &ledger).await;
    Ok(())
}

pub(crate) fn scope_parents(
    targets: &ConnectorTargetMap,
) -> (
    HashMap<IntegrationId, chancela_authz::TenantId>,
    HashMap<RepositoryId, chancela_authz::TenantId>,
) {
    let integrations = targets
        .values()
        .map(|target| {
            (
                IntegrationId(target.id),
                chancela_authz::TenantId(target.tenant_id.0),
            )
        })
        .collect();
    let repositories = targets
        .values()
        .map(|target| {
            (
                RepositoryId(target.repository_id),
                chancela_authz::TenantId(target.tenant_id.0),
            )
        })
        .collect();
    (integrations, repositories)
}

pub(crate) async fn list_targets(
    State(state): State<AppState>,
    AxumPath(tenant): AxumPath<Uuid>,
    actor: CurrentActor,
) -> Result<Json<Vec<ConnectorTargetView>>, ApiError> {
    let tenant_id = TenantId(tenant);
    require_permission(
        &state,
        &actor,
        Permission::SettingsRead,
        scope_of_tenant(tenant_id),
    )
    .await?;
    let mut records = state
        .connector_targets
        .read()
        .await
        .values()
        .filter(|target| target.tenant_id == tenant_id && target.is_active())
        .cloned()
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.name.cmp(&right.name).then(left.id.cmp(&right.id)));
    Ok(Json(
        records.iter().map(ConnectorTargetView::from).collect(),
    ))
}

pub(crate) async fn create_target(
    State(state): State<AppState>,
    AxumPath(tenant): AxumPath<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(body): Json<CreateTargetBody>,
) -> Result<(StatusCode, Json<ConnectorTargetView>), ApiError> {
    let tenant_id = TenantId(tenant);
    require_permission(
        &state,
        &actor,
        Permission::SettingsManage,
        scope_of_tenant(tenant_id),
    )
    .await?;
    if !state.tenants.read().await.contains_key(&tenant_id) {
        return Err(ApiError::NotFound);
    }
    let name = normalized_name(body.name)?;
    let id = Uuid::new_v4();
    let config = body.config.with_id(id.to_string());
    validate_api_target(&state, &config).await?;
    validate_purposes(&body.purposes, &config)?;
    let now = now_rfc3339();
    let record = ConnectorTargetRecord {
        schema_version: 1,
        id,
        repository_id: Uuid::new_v4(),
        tenant_id,
        name,
        enabled: body.enabled,
        purposes: body.purposes,
        config,
        created_at: now.clone(),
        updated_at: now,
        archived_at: None,
    };
    let mut targets = state.connector_targets.write().await;
    if targets
        .values()
        .filter(|target| target.tenant_id == tenant_id && target.is_active())
        .count()
        >= MAX_TARGETS_PER_TENANT
    {
        return Err(ApiError::Conflict(format!(
            "a tenant may configure at most {MAX_TARGETS_PER_TENANT} active connector targets"
        )));
    }
    if targets.values().any(|target| {
        target.tenant_id == tenant_id
            && target.is_active()
            && target.name.eq_ignore_ascii_case(&record.name)
    }) {
        return Err(ApiError::Conflict(
            "an active connector target with that name already exists".to_owned(),
        ));
    }
    let previous = targets.clone();
    let mut next = previous.clone();
    next.insert(record.id, record.clone());
    persist_target_registry_change(
        &state,
        &attestor,
        &actor.resolve("api"),
        &previous,
        &next,
        "connector_target.created",
        &record,
    )
    .await?;
    *targets = next;
    Ok((
        StatusCode::CREATED,
        Json(ConnectorTargetView::from(&record)),
    ))
}

pub(crate) async fn get_target(
    State(state): State<AppState>,
    AxumPath((tenant, target)): AxumPath<(Uuid, Uuid)>,
    actor: CurrentActor,
) -> Result<Json<ConnectorTargetView>, ApiError> {
    let tenant_id = TenantId(tenant);
    let record =
        target_for_path(&*state.connector_targets.read().await, tenant_id, target)?.clone();
    require_permission(
        &state,
        &actor,
        Permission::SettingsRead,
        record.integration_scope(),
    )
    .await?;
    Ok(Json(ConnectorTargetView::from(&record)))
}

pub(crate) async fn patch_target(
    State(state): State<AppState>,
    AxumPath((tenant, target)): AxumPath<(Uuid, Uuid)>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(body): Json<PatchTargetBody>,
) -> Result<Json<ConnectorTargetView>, ApiError> {
    let tenant_id = TenantId(tenant);
    let current =
        target_for_path(&*state.connector_targets.read().await, tenant_id, target)?.clone();
    require_permission(
        &state,
        &actor,
        Permission::SettingsManage,
        current.integration_scope(),
    )
    .await?;
    if !current.is_active() {
        return Err(ApiError::Conflict(
            "archived connector targets cannot be edited".to_owned(),
        ));
    }
    let mut updated = current.clone();
    if let Some(name) = body.name {
        updated.name = normalized_name(name)?;
    }
    if let Some(enabled) = body.enabled {
        updated.enabled = enabled;
    }
    if let Some(purposes) = body.purposes {
        updated.purposes = purposes;
    }
    if let Some(config) = body.config {
        updated.config = config.with_id(updated.id.to_string());
        validate_api_target(&state, &updated.config).await?;
    }
    validate_purposes(&updated.purposes, &updated.config)?;
    updated.updated_at = now_rfc3339();
    let mut targets = state.connector_targets.write().await;
    if targets.values().any(|candidate| {
        candidate.id != updated.id
            && candidate.tenant_id == tenant_id
            && candidate.is_active()
            && candidate.name.eq_ignore_ascii_case(&updated.name)
    }) {
        return Err(ApiError::Conflict(
            "an active connector target with that name already exists".to_owned(),
        ));
    }
    let previous = targets.clone();
    let mut next = previous.clone();
    next.insert(updated.id, updated.clone());
    persist_target_registry_change(
        &state,
        &attestor,
        &actor.resolve("api"),
        &previous,
        &next,
        "connector_target.updated",
        &updated,
    )
    .await?;
    *targets = next;
    Ok(Json(ConnectorTargetView::from(&updated)))
}

pub(crate) async fn archive_target(
    State(state): State<AppState>,
    AxumPath((tenant, target)): AxumPath<(Uuid, Uuid)>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
) -> Result<StatusCode, ApiError> {
    let tenant_id = TenantId(tenant);
    let current =
        target_for_path(&*state.connector_targets.read().await, tenant_id, target)?.clone();
    require_permission(
        &state,
        &actor,
        Permission::SettingsManage,
        current.integration_scope(),
    )
    .await?;
    if !current.is_active() {
        return Ok(StatusCode::NO_CONTENT);
    }
    let mut archived = current;
    archived.enabled = false;
    archived.updated_at = now_rfc3339();
    archived.archived_at = Some(archived.updated_at.clone());
    let mut targets = state.connector_targets.write().await;
    let previous = targets.clone();
    let mut next = previous.clone();
    next.insert(archived.id, archived.clone());
    persist_target_registry_change(
        &state,
        &attestor,
        &actor.resolve("api"),
        &previous,
        &next,
        "connector_target.archived",
        &archived,
    )
    .await?;
    *targets = next;
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn probe_target(
    State(state): State<AppState>,
    AxumPath((tenant, target)): AxumPath<(Uuid, Uuid)>,
    actor: CurrentActor,
) -> Result<Json<ConnectorProbeView>, ApiError> {
    let tenant_id = TenantId(tenant);
    let record =
        target_for_path(&*state.connector_targets.read().await, tenant_id, target)?.clone();
    require_permission(
        &state,
        &actor,
        Permission::SettingsRead,
        record.integration_scope(),
    )
    .await?;
    if !record.enabled || !record.is_active() {
        return Err(ApiError::Conflict(
            "connector target is disabled or archived".to_owned(),
        ));
    }
    validate_api_target(&state, &record.config).await?;
    let connector = build_connector(&record.config, std::sync::Arc::new(EnvSecretProvider))
        .map_err(|error| ApiError::Unprocessable(error.to_string()))?;
    let checked_at = now_rfc3339();
    let response = match connector.probe().await {
        Ok(status) => ConnectorProbeView {
            target_id: record.id,
            checked_at,
            status: Some(status),
            error_class: None,
            error: None,
        },
        Err(error) => ConnectorProbeView {
            target_id: record.id,
            checked_at,
            status: None,
            error_class: Some(error.class),
            error: Some(error.message),
        },
    };
    Ok(Json(response))
}

struct MaterializedArtifact {
    relative: PathBuf,
    content_type: String,
    created: bool,
}

enum ArtifactSource {
    Bytes(Vec<u8>),
    File(PathBuf),
}

async fn sha256_file(path: &Path) -> Result<[u8; 32], ApiError> {
    use tokio::io::AsyncReadExt;

    let mut file = tokio::fs::File::open(path).await.map_err(|error| {
        ApiError::Internal(format!(
            "failed to open worker source for verification: {}",
            error.kind()
        ))
    })?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).await.map_err(|error| {
            ApiError::Internal(format!("failed to verify worker source: {}", error.kind()))
        })?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(digest.finalize().into())
}

async fn materialize_artifact(
    state: &AppState,
    actor: &CurrentActor,
    tenant_id: TenantId,
    request_id: Uuid,
    purpose: JobPurpose,
    artifact: RunArtifact,
) -> Result<MaterializedArtifact, ApiError> {
    let source_root = state.worker_source_root.as_deref().ok_or_else(|| {
        ApiError::Unprocessable("connector jobs require CHANCELA_DATA_DIR".to_owned())
    })?;
    let (source, content_type, extension) = match artifact {
        RunArtifact::ActDocument { act_id, variant } => {
            let act_id = ActId(act_id);
            require_permission(
                state,
                actor,
                Permission::ActRead,
                scope_of_act(state, act_id).await,
            )
            .await?;
            let book_id = {
                let acts = state.acts.read().await;
                acts.get(&act_id)
                    .map(|act| act.book_id)
                    .ok_or(ApiError::NotFound)?
            };
            let entity_id = {
                let books = state.books.read().await;
                books
                    .get(&book_id)
                    .map(|book| book.entity_id)
                    .ok_or(ApiError::NotFound)?
            };
            let tenant_matches = {
                let entities = state.entities.read().await;
                entities
                    .get(&entity_id)
                    .is_some_and(|entity| entity.tenant_id == tenant_id)
            };
            if !tenant_matches {
                return Err(ApiError::NotFound);
            }
            let bytes = match variant {
                ActDocumentVariant::Canonical => {
                    crate::documents::load_document(state, act_id)
                        .await?
                        .ok_or(ApiError::NotFound)?
                        .pdf_bytes
                }
                ActDocumentVariant::Signed => {
                    crate::signature::load_signed(state, act_id)
                        .await?
                        .ok_or(ApiError::NotFound)?
                        .signed_pdf_bytes
                }
            };
            (
                ArtifactSource::Bytes(bytes),
                "application/pdf".to_owned(),
                "pdf",
            )
        }
        RunArtifact::LatestInstanceBackup => {
            if purpose != JobPurpose::Backup {
                return Err(ApiError::Unprocessable(
                    "latest_instance_backup requires purpose=backup".to_owned(),
                ));
            }
            require_permission(state, actor, Permission::DataBackup, Scope::Global).await?;
            let data_dir = state.data_dir().ok_or_else(|| {
                ApiError::Unprocessable("instance backup requires CHANCELA_DATA_DIR".to_owned())
            })?;
            let latest = latest_backup_candidate(&data_dir.join("backups")).await?;
            let extension =
                if latest.extension().and_then(|value| value.to_str()) == Some("cbackup") {
                    "cbackup"
                } else {
                    "zip"
                };
            (
                ArtifactSource::File(latest),
                "application/octet-stream".to_owned(),
                extension,
            )
        }
    };
    let tenant_component = tenant_id.to_string();
    let relative = PathBuf::from(&tenant_component).join(format!("{request_id}.{extension}"));
    let destination = source_root.join(&relative);
    if let Some(parent) = destination.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(|error| {
            ApiError::Internal(format!(
                "failed to create worker source directory: {}",
                error.kind()
            ))
        })?;
    }
    let created = match tokio::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&destination)
        .await
    {
        Ok(mut file) => {
            let write_result = match &source {
                ArtifactSource::Bytes(bytes) => {
                    use tokio::io::AsyncWriteExt;
                    file.write_all(bytes).await.map(|_| ())
                }
                ArtifactSource::File(path) => match tokio::fs::File::open(path).await {
                    Ok(mut source_file) => tokio::io::copy(&mut source_file, &mut file)
                        .await
                        .map(|_| ()),
                    Err(error) => Err(error),
                },
            };
            if let Err(error) = write_result {
                drop(file);
                let _ = tokio::fs::remove_file(&destination).await;
                return Err(ApiError::Internal(format!(
                    "failed to materialize worker source: {}",
                    error.kind()
                )));
            }
            if let Err(error) = file.sync_all().await {
                drop(file);
                let _ = tokio::fs::remove_file(&destination).await;
                return Err(ApiError::Internal(format!(
                    "failed to sync worker source: {}",
                    error.kind()
                )));
            }
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing_digest = sha256_file(&destination).await?;
            let source_digest: [u8; 32] = match &source {
                ArtifactSource::Bytes(bytes) => Sha256::digest(bytes).into(),
                ArtifactSource::File(path) => sha256_file(path).await?,
            };
            if existing_digest != source_digest {
                return Err(ApiError::Conflict(
                    "request_id already identifies different source content".to_owned(),
                ));
            }
            false
        }
        Err(error) => {
            return Err(ApiError::Internal(format!(
                "failed to materialize worker source: {}",
                error.kind()
            )));
        }
    };
    Ok(MaterializedArtifact {
        relative,
        content_type,
        created,
    })
}

async fn latest_backup_candidate(directory: &Path) -> Result<PathBuf, ApiError> {
    let canonical_directory = tokio::fs::canonicalize(directory)
        .await
        .map_err(|_| ApiError::NotFound)?;
    let mut entries = tokio::fs::read_dir(&canonical_directory)
        .await
        .map_err(|error| ApiError::Internal(format!("failed to list backups: {}", error.kind())))?;
    let mut latest: Option<(std::time::SystemTime, PathBuf)> = None;
    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|error| ApiError::Internal(format!("failed to list backups: {}", error.kind())))?
    {
        let metadata = entry.metadata().await.map_err(|error| {
            ApiError::Internal(format!("failed to inspect backup: {}", error.kind()))
        })?;
        if !metadata.is_file() || entry.file_type().await.is_ok_and(|kind| kind.is_symlink()) {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with("chancela-backup-")
            || !(name.ends_with(".zip") || name.ends_with(".cbackup"))
        {
            continue;
        }
        let canonical = tokio::fs::canonicalize(entry.path())
            .await
            .map_err(|error| {
                ApiError::Internal(format!("failed to resolve backup: {}", error.kind()))
            })?;
        if !canonical.starts_with(&canonical_directory) {
            continue;
        }
        let modified = metadata.modified().unwrap_or(std::time::UNIX_EPOCH);
        if latest
            .as_ref()
            .is_none_or(|(current, _)| modified > *current)
        {
            latest = Some((modified, canonical));
        }
    }
    latest.map(|(_, path)| path).ok_or(ApiError::NotFound)
}

fn queue_and_source_roots(state: &AppState) -> Result<(PathBuf, PathBuf), ApiError> {
    let queue = state.worker_queue_root.as_deref().ok_or_else(|| {
        ApiError::Unprocessable("connector jobs require CHANCELA_DATA_DIR".to_owned())
    })?;
    let sources = state.worker_source_root.as_deref().ok_or_else(|| {
        ApiError::Unprocessable("connector jobs require CHANCELA_DATA_DIR".to_owned())
    })?;
    Ok((queue.to_path_buf(), sources.to_path_buf()))
}

pub(crate) async fn run_target(
    State(state): State<AppState>,
    AxumPath((tenant, target)): AxumPath<(Uuid, Uuid)>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(body): Json<RunTargetBody>,
) -> Result<(StatusCode, Json<ConnectorJobView>), ApiError> {
    if body.destination.len() > 2_048 {
        return Err(ApiError::Unprocessable(
            "connector destination exceeds 2048 bytes".to_owned(),
        ));
    }
    validate_destination(&body.destination)
        .map_err(|error| ApiError::Unprocessable(error.to_string()))?;
    let tenant_id = TenantId(tenant);
    let record =
        target_for_path(&*state.connector_targets.read().await, tenant_id, target)?.clone();
    if !record.permits(body.purpose) {
        return Err(ApiError::Conflict(
            "connector target is disabled, archived, or not enabled for this purpose".to_owned(),
        ));
    }
    let permission = match body.purpose {
        JobPurpose::Sync => Permission::DataExport,
        JobPurpose::Backup => Permission::DataBackup,
    };
    require_permission(&state, &actor, permission, record.repository_scope()).await?;
    validate_api_target(&state, &record.config).await?;
    let materialized = materialize_artifact(
        &state,
        &actor,
        tenant_id,
        body.request_id,
        body.purpose,
        body.artifact,
    )
    .await?;
    let (queue_root, source_root) = queue_and_source_roots(&state)?;
    let queue = DurableQueue::open(queue_root)
        .await
        .map_err(map_worker_error)?;
    let idempotency_key = format!("api:{}:{}:{}", tenant_id, record.id, body.request_id);
    let staged = queue
        .stage_for_target(
            &source_root,
            body.purpose,
            materialized.relative.clone(),
            body.destination,
            materialized.content_type,
            idempotency_key,
            tenant_id.to_string(),
            record.config.clone(),
        )
        .await
        .map_err(map_worker_error)?;
    let payload = serde_json::to_vec(&serde_json::json!({
        "job_id": staged.job.id,
        "tenant_id": tenant_id,
        "target_id": record.id,
        "repository_id": record.repository_id,
        "purpose": body.purpose,
        "source_sha256": staged.job.source_sha256,
        "bytes": staged.job.bytes,
    }))?;
    let actor_name = actor.resolve("api");
    let scope = format!("tenant:{tenant_id}");
    let object = format!("connector-job:{}", staged.job.id);
    let audit_result = {
        let mut ledger = state.ledger.write().await;
        let append = crate::try_append_event(
            &mut ledger,
            &actor_name,
            &scope,
            if staged.created {
                "connector_job.queued"
            } else {
                "connector_job.replayed"
            },
            Some(&object),
            &payload,
        );
        match append {
            Err(error) => Err(error),
            Ok(()) => match state
                .persist_write_through(&mut ledger, 1, |_tx| Ok(()))
                .await
            {
                Ok(()) => {
                    state.attest_latest(&attestor, &ledger).await;
                    Ok(())
                }
                Err(error) => Err(error),
            },
        }
    };
    if let Err(error) = audit_result {
        let _ = queue.discard_staged(&staged.job.id).await;
        if materialized.created {
            let _ = tokio::fs::remove_file(source_root.join(&materialized.relative)).await;
        }
        return Err(error);
    }
    if let Err(error) = queue.publish_staged(&staged.job.id).await {
        return Err(ApiError::Internal(format!(
            "audited connector job could not be published: {error}"
        )));
    }
    let snapshot = queue
        .snapshot(&staged.job.id)
        .await
        .map_err(map_worker_error)?;
    Ok((
        if staged.created {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        },
        Json(job_view(&snapshot, &record)?),
    ))
}

fn job_view(
    snapshot: &JobSnapshot,
    target: &ConnectorTargetRecord,
) -> Result<ConnectorJobView, ApiError> {
    if snapshot.job.tenant_id.as_deref() != Some(target.tenant_id.to_string().as_str())
        || snapshot.job.target.as_ref().map(TargetConfig::id)
            != Some(target.id.to_string().as_str())
    {
        return Err(ApiError::NotFound);
    }
    Ok(ConnectorJobView {
        id: snapshot.job.id.clone(),
        tenant_id: target.tenant_id.to_string(),
        target_id: target.id,
        repository_id: target.repository_id,
        purpose: snapshot.job.purpose,
        destination: snapshot.job.destination.clone(),
        content_type: snapshot.job.content_type.clone(),
        source_sha256: snapshot.job.source_sha256.clone(),
        bytes: snapshot.job.bytes,
        created_unix_millis: snapshot.job.created_unix_millis,
        state: snapshot.latest_event.state,
        attempt: snapshot.latest_event.attempt,
        not_before_unix_millis: snapshot.latest_event.not_before_unix_millis,
        error_class: snapshot.latest_event.error_class,
        detail: snapshot.latest_event.detail.clone(),
        receipt: snapshot
            .receipt
            .as_ref()
            .map(|receipt| ConnectorJobReceiptView {
                completed_unix_millis: receipt.completed_unix_millis,
                connector: receipt.upload.connector,
                provider_object_id: receipt.upload.provider_object_id.clone(),
                provider_revision: receipt.upload.provider_revision.clone(),
                etag: receipt.upload.etag.clone(),
                remote_bytes: receipt.upload.bytes,
                checksum_evidence: receipt.upload.checksum_evidence,
            }),
    })
}

fn target_for_snapshot<'a>(
    targets: &'a ConnectorTargetMap,
    tenant_id: TenantId,
    snapshot: &JobSnapshot,
) -> Option<&'a ConnectorTargetRecord> {
    let id = snapshot.job.target.as_ref()?.id().parse::<Uuid>().ok()?;
    targets
        .get(&id)
        .filter(|target| target.tenant_id == tenant_id)
}

pub(crate) async fn list_jobs(
    State(state): State<AppState>,
    AxumPath(tenant): AxumPath<Uuid>,
    actor: CurrentActor,
    Query(query): Query<ListJobsQuery>,
) -> Result<Json<ConnectorJobListView>, ApiError> {
    let tenant_id = TenantId(tenant);
    let authz = authorizer(&state, &actor).await?;
    let limit = query.limit.unwrap_or(DEFAULT_JOB_LIMIT);
    if !(1..=MAX_JOB_LIMIT).contains(&limit) {
        return Err(ApiError::Unprocessable(format!(
            "limit must be between 1 and {MAX_JOB_LIMIT}"
        )));
    }
    let (queue_root, _) = queue_and_source_roots(&state)?;
    let snapshots = DurableQueue::open(queue_root)
        .await
        .map_err(map_worker_error)?
        .list_snapshots(QUEUE_SCAN_LIMIT)
        .await
        .map_err(map_worker_error)?;
    let targets = state.connector_targets.read().await;
    let mut jobs = Vec::new();
    for snapshot in snapshots {
        if query
            .before_created_unix_millis
            .is_some_and(|before| snapshot.job.created_unix_millis >= before)
        {
            continue;
        }
        let Some(target) = target_for_snapshot(&targets, tenant_id, &snapshot) else {
            continue;
        };
        let permission = match snapshot.job.purpose {
            JobPurpose::Sync => Permission::DataExport,
            JobPurpose::Backup => Permission::DataBackup,
        };
        if !authz.permits(permission, target.repository_scope()) {
            continue;
        }
        jobs.push(job_view(&snapshot, target)?);
        if jobs.len() > limit {
            break;
        }
    }
    let has_more = jobs.len() > limit;
    jobs.truncate(limit);
    let next = has_more
        .then(|| jobs.last().map(|job| job.created_unix_millis))
        .flatten();
    Ok(Json(ConnectorJobListView {
        jobs,
        next_before_created_unix_millis: next,
    }))
}

async fn authorized_job(
    state: &AppState,
    actor: &CurrentActor,
    tenant_id: TenantId,
    job_id: &str,
) -> Result<(DurableQueue, JobSnapshot, ConnectorTargetRecord), ApiError> {
    let (queue_root, _) = queue_and_source_roots(state)?;
    let queue = DurableQueue::open(queue_root)
        .await
        .map_err(map_worker_error)?;
    let snapshot = queue.snapshot(job_id).await.map_err(map_worker_error)?;
    let targets = state.connector_targets.read().await;
    let target = target_for_snapshot(&targets, tenant_id, &snapshot)
        .ok_or(ApiError::NotFound)?
        .clone();
    let permission = match snapshot.job.purpose {
        JobPurpose::Sync => Permission::DataExport,
        JobPurpose::Backup => Permission::DataBackup,
    };
    require_permission(state, actor, permission, target.repository_scope()).await?;
    Ok((queue, snapshot, target))
}

pub(crate) async fn get_job(
    State(state): State<AppState>,
    AxumPath((tenant, job)): AxumPath<(Uuid, String)>,
    actor: CurrentActor,
) -> Result<Json<ConnectorJobView>, ApiError> {
    let (_, snapshot, target) = authorized_job(&state, &actor, TenantId(tenant), &job).await?;
    Ok(Json(job_view(&snapshot, &target)?))
}

async fn audit_staged_job_action(
    state: &AppState,
    actor: &CurrentActor,
    attestor: &CurrentAttestor,
    snapshot: &JobSnapshot,
    target: &ConnectorTargetRecord,
    kind: &str,
) -> Result<(), ApiError> {
    let payload = serde_json::to_vec(&serde_json::json!({
        "job_id": snapshot.job.id,
        "tenant_id": target.tenant_id,
        "target_id": target.id,
        "repository_id": target.repository_id,
        "purpose": snapshot.job.purpose,
        "prior_state": snapshot.latest_event.state,
        "attempt": snapshot.latest_event.attempt,
    }))?;
    let mut ledger = state.ledger.write().await;
    crate::try_append_event(
        &mut ledger,
        &actor.resolve("api"),
        &format!("tenant:{}", target.tenant_id),
        kind,
        Some(&format!("connector-job:{}", snapshot.job.id)),
        &payload,
    )?;
    state
        .persist_write_through(&mut ledger, 1, |_tx| Ok(()))
        .await?;
    state.attest_latest(attestor, &ledger).await;
    Ok(())
}

pub(crate) async fn cancel_job(
    State(state): State<AppState>,
    AxumPath((tenant, job)): AxumPath<(Uuid, String)>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
) -> Result<StatusCode, ApiError> {
    let (queue, snapshot, target) = authorized_job(&state, &actor, TenantId(tenant), &job).await?;
    queue.stage_cancel(&job).await.map_err(map_worker_error)?;
    if let Err(error) = audit_staged_job_action(
        &state,
        &actor,
        &attestor,
        &snapshot,
        &target,
        "connector_job.cancel_requested",
    )
    .await
    {
        let _ = queue.discard_staged_cancel(&job).await;
        return Err(error);
    }
    queue
        .publish_staged_cancel(&job)
        .await
        .map_err(map_worker_error)?;
    Ok(StatusCode::ACCEPTED)
}

pub(crate) async fn retry_job(
    State(state): State<AppState>,
    AxumPath((tenant, job)): AxumPath<(Uuid, String)>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
) -> Result<StatusCode, ApiError> {
    let (queue, snapshot, target) = authorized_job(&state, &actor, TenantId(tenant), &job).await?;
    queue.stage_retry(&job).await.map_err(map_worker_error)?;
    if let Err(error) = audit_staged_job_action(
        &state,
        &actor,
        &attestor,
        &snapshot,
        &target,
        "connector_job.retry_requested",
    )
    .await
    {
        let _ = queue.discard_staged_retry(&job).await;
        return Err(error);
    }
    queue
        .publish_staged_retry(&job)
        .await
        .map_err(map_worker_error)?;
    Ok(StatusCode::ACCEPTED)
}

pub(crate) async fn dashboard_job_counts(state: &AppState) -> DashboardJobCounts {
    let Some(queue_root) = state.worker_queue_root.as_deref() else {
        return DashboardJobCounts::default();
    };
    let Ok(queue) = DurableQueue::open(queue_root).await else {
        return DashboardJobCounts::default();
    };
    let Ok(snapshots) = queue.list_snapshots(QUEUE_SCAN_LIMIT).await else {
        return DashboardJobCounts::default();
    };
    let mut counts = DashboardJobCounts::default();
    for snapshot in snapshots {
        match (snapshot.job.purpose, snapshot.latest_event.state) {
            (JobPurpose::Sync, JobState::Failed) => counts.failed_sync_jobs += 1,
            (
                JobPurpose::Backup,
                JobState::Queued
                | JobState::Running
                | JobState::RetryScheduled
                | JobState::Recovered,
            ) => counts.pending_backup_jobs += 1,
            _ => {}
        }
    }
    counts
}

fn map_worker_error(error: WorkerError) -> ApiError {
    match error {
        WorkerError::JobNotFound(_) => ApiError::NotFound,
        WorkerError::IdempotencyConflict => ApiError::Conflict(error.to_string()),
        WorkerError::Configuration(_) | WorkerError::Connector(_) => {
            ApiError::Unprocessable(error.to_string())
        }
        WorkerError::Io { .. } | WorkerError::Json(_) => {
            ApiError::Internal(format!("connector worker state failure: {error}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chancela_connectors::{GraphTarget, LocalTarget};

    #[test]
    fn target_loader_rejects_local_api_targets_and_plaintext_unknown_fields() {
        let local = ConnectorTargetRecord {
            schema_version: 1,
            id: Uuid::new_v4(),
            repository_id: Uuid::new_v4(),
            tenant_id: TenantId::default(),
            name: "bad".to_owned(),
            enabled: true,
            purposes: BTreeSet::from([JobPurpose::Sync]),
            config: TargetConfig::Local(LocalTarget {
                id: "bad".to_owned(),
                root: PathBuf::from("/tmp"),
            }),
            created_at: now_rfc3339(),
            updated_at: now_rfc3339(),
            archived_at: None,
        };
        assert!(validate_purposes(&local.purposes, &local.config).is_ok());
        let with_plaintext = serde_json::json!({
            "name": "Graph",
            "enabled": true,
            "purposes": ["sync"],
            "config": {
                "kind": "microsoft_graph",
                "id": "ignored",
                "drive_id": "drive",
                "parent_item_id": "root",
                "token_ref": "CHANCELA_CONNECTOR_SECRET_GRAPH",
                "password": "must-not-be-ignored"
            }
        });
        assert!(serde_json::from_value::<CreateTargetBody>(with_plaintext).is_err());
    }

    #[test]
    fn graph_secret_refs_are_namespace_restricted() {
        let unsafe_config = TargetConfig::MicrosoftGraph(GraphTarget {
            id: "graph".to_owned(),
            drive_id: "drive".to_owned(),
            parent_item_id: "root".to_owned(),
            token_ref: "GRAPH_TOKEN".to_owned(),
            api_base_url: "https://graph.microsoft.com/v1.0".to_owned(),
            timeout_seconds: 60,
            allow_insecure_http: false,
        });
        assert!(unsafe_config.validate().is_err());
    }

    #[test]
    fn job_view_never_contains_source_path_or_idempotency_key() {
        let source = include_str!("connector_jobs.rs");
        let view_start = source.find("pub(crate) struct ConnectorJobView").unwrap();
        let view_end = source[view_start..]
            .find("pub(crate) struct ConnectorJobReceiptView")
            .unwrap()
            + view_start;
        let view = &source[view_start..view_end];
        assert!(!view.contains("source_relative"));
        assert!(!view.contains("idempotency_key"));
    }
}
