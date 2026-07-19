//! Durable, opt-in zero-knowledge repository HTTP boundary (ARC-30..33 / SCP-D3 / LEG-13).
//!
//! The server never receives an unwrapped content-encryption key and has no decrypt operation. A
//! trusted client first registers a strict [`OpaqueBlobManifest`], then uploads opaque ciphertext as
//! a separate `application/octet-stream` request. Commit verifies length, digest, immutable version
//! sequencing, and nonce/key-reference uniqueness before publishing a traversal-safe blob path and
//! atomically replacing the index.
//!
//! Storage is deliberately a data-dir object sidecar rather than a relational BLOB table:
//! `<data_dir>/zk-repositories/{index.json,objects/,uploads/,staging/}`. The complete root is included
//! in verified whole-instance backup/restore. A crash after blob rename but before index replacement
//! can leave only an unreferenced blob; startup removes such orphans. PostgreSQL/HA stays fail-closed
//! unless the operator explicitly configures the same shared-mounted root on every node.

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path as FsPath, PathBuf};

use axum::Json;
use axum::body::{Body, Bytes};
use axum::extract::{Path, State};
use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chancela_archive::{
    PackageBuildInput, PackageFileInput, PackageFileRole, ProducerMetadata, ReadabilityExport,
    RetentionInstructions, RightsMetadata, build_archive_package, validate_package,
};
use chancela_authz::{
    ArchiveId as AuthzArchiveId, Permission, RepositoryId as AuthzRepositoryId, Scope,
};
use chancela_core::{BookId, TenantId};
use chancela_zk::{
    KeyCustodyPolicy, ObjectId, OpaqueBlobManifest, RepositoryEncryptionMode, RepositoryId,
    RepositoryPolicy, ZeroKnowledgeScope, ensure_nonce_is_unique,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::actor::{CurrentActor, CurrentAttestor};
use crate::authz::{require_permission, scope_of_book, scope_of_tenant};
use crate::data::{ReAuth, require_step_up};
use crate::{ApiError, AppState};

pub(crate) const ZK_REPOSITORY_DIR: &str = "zk-repositories";
pub(crate) const ZK_SHARED_OBJECT_ROOT_ENV: &str = "CHANCELA_ZK_SHARED_OBJECT_ROOT";
pub(crate) const ZK_BLOB_MAX_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const ZK_READABILITY_REQUEST_MAX_BYTES: usize = (ZK_BLOB_MAX_BYTES * 4 / 3) + 256 * 1024;

const INDEX_FILE: &str = "index.json";
const INDEX_BACKUP_FILE: &str = "index.json.bak";
const OBJECTS_DIR: &str = "objects";
const UPLOADS_DIR: &str = "uploads";
const STAGING_DIR: &str = "staging";
const INDEX_SCHEMA_VERSION: u16 = 1;
const PENDING_UPLOAD_SCHEMA_VERSION: u16 = 1;
const MAX_REPOSITORY_NAME_CHARS: usize = 200;
const CLIENT_ARCHIVE_PATH: &str = "source/client-decrypted-archive.zip";
const ENCRYPTED_ARCHIVE_PATH: &str = "source/encrypted-archive.bin";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RepositoryPolicySource {
    Tenant,
    Repository,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TenantRepositoryPolicy {
    pub tenant_id: Uuid,
    pub encryption_mode: RepositoryEncryptionMode,
    pub custody: KeyCustodyPolicy,
    pub gdpr_obligations_remain: bool,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl TenantRepositoryPolicy {
    fn validate(&self) -> Result<(), ApiError> {
        let synthetic_repository = RepositoryId(Uuid::from_u128(1));
        RepositoryPolicy {
            repository_id: synthetic_repository,
            tenant_id: self.tenant_id,
            name: "tenant inherited policy".to_owned(),
            encryption_mode: self.encryption_mode,
            zk_scope: match self.encryption_mode {
                RepositoryEncryptionMode::Standard => None,
                RepositoryEncryptionMode::ZeroKnowledge => Some(ZeroKnowledgeScope::Tenant {
                    tenant_id: self.tenant_id,
                }),
            },
            custody: self.custody.clone(),
            gdpr_obligations_remain: self.gdpr_obligations_remain,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
        .validate()
        .map_err(contract_error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredRepositoryPolicy {
    pub policy: RepositoryPolicy,
    pub policy_source: RepositoryPolicySource,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredObjectVersion {
    pub archive_id: Uuid,
    pub tenant_id: Uuid,
    pub manifest: OpaqueBlobManifest,
    pub blob_relative_path: String,
    pub committed_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ObjectVersionView {
    pub archive_id: Uuid,
    pub tenant_id: Uuid,
    pub manifest: OpaqueBlobManifest,
    pub ciphertext_url: String,
    pub committed_at: OffsetDateTime,
}

impl ObjectVersionView {
    fn from_stored(value: &StoredObjectVersion) -> Self {
        let ad = value.manifest.associated_data;
        Self {
            archive_id: value.archive_id,
            tenant_id: value.tenant_id,
            manifest: value.manifest.clone(),
            ciphertext_url: format!(
                "/v1/tenants/{}/repositories/{}/objects/{}/versions/{}/ciphertext",
                value.tenant_id, ad.repository_id, ad.object_id, ad.version
            ),
            committed_at: value.committed_at,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ZkRepositoryIndex {
    schema_version: u16,
    tenant_policies: Vec<TenantRepositoryPolicy>,
    repositories: Vec<StoredRepositoryPolicy>,
    object_versions: Vec<StoredObjectVersion>,
}

impl Default for ZkRepositoryIndex {
    fn default() -> Self {
        Self {
            schema_version: INDEX_SCHEMA_VERSION,
            tenant_policies: Vec::new(),
            repositories: Vec::new(),
            object_versions: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingUpload {
    schema_version: u16,
    upload_id: Uuid,
    tenant_id: Uuid,
    repository_id: RepositoryId,
    manifest: OpaqueBlobManifest,
    created_at: OffsetDateTime,
}

#[derive(Debug, Clone, Default)]
enum RepositoryStoreAvailability {
    Ready,
    #[default]
    NotPersistent,
    FailClosed(String),
}

/// In-memory projection plus the authoritative object-root path. Mutations are serialized by the
/// enclosing `AppState` write lock; a clone of the index is written before it becomes visible.
#[derive(Debug, Clone, Default)]
pub struct ZkRepositoryStore {
    root: Option<PathBuf>,
    index: ZkRepositoryIndex,
    availability: RepositoryStoreAvailability,
}

impl ZkRepositoryStore {
    pub(crate) fn open(data_dir: &FsPath, postgres_or_ha: bool) -> Self {
        let shared_root = std::env::var_os(ZK_SHARED_OBJECT_ROOT_ENV)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from);
        Self::open_with_shared_root(data_dir, postgres_or_ha, shared_root)
    }

    fn open_with_shared_root(
        data_dir: &FsPath,
        postgres_or_ha: bool,
        shared_root: Option<PathBuf>,
    ) -> Self {
        let expected_root = data_dir.join(ZK_REPOSITORY_DIR);
        let root = if postgres_or_ha {
            let configured = match shared_root {
                Some(value) => value,
                _ => {
                    return Self::fail_closed(
                        expected_root,
                        format!(
                            "zero-knowledge repository storage is disabled on PostgreSQL/HA until \
                             {ZK_SHARED_OBJECT_ROOT_ENV} explicitly names the shared mounted \
                             <data_dir>/{ZK_REPOSITORY_DIR} root"
                        ),
                    );
                }
            };
            let configured = match normalized_absolute(&configured) {
                Ok(path) => path,
                Err(message) => return Self::fail_closed(expected_root, message),
            };
            let expected = match normalized_absolute(&expected_root) {
                Ok(path) => path,
                Err(message) => return Self::fail_closed(expected_root, message),
            };
            if configured != expected {
                return Self::fail_closed(
                    expected_root,
                    format!(
                        "{ZK_SHARED_OBJECT_ROOT_ENV} must resolve exactly to the shared mounted {} \
                         so verified backup/restore covers the same object root",
                        expected.display()
                    ),
                );
            }
            configured
        } else {
            match normalized_absolute(&expected_root) {
                Ok(path) => path,
                Err(message) => return Self::fail_closed(expected_root, message),
            }
        };

        match load_index_and_reconcile(&root) {
            Ok(index) => Self {
                root: Some(root),
                index,
                availability: RepositoryStoreAvailability::Ready,
            },
            Err(message) => Self::fail_closed(root, message),
        }
    }

    fn fail_closed(root: PathBuf, message: String) -> Self {
        eprintln!("zero-knowledge repository store is fail-closed: {message}");
        Self {
            root: Some(root),
            index: ZkRepositoryIndex::default(),
            availability: RepositoryStoreAvailability::FailClosed(message),
        }
    }

    fn ready_root(&self) -> Result<&FsPath, ApiError> {
        match &self.availability {
            RepositoryStoreAvailability::Ready => self.root.as_deref().ok_or_else(|| {
                ApiError::Internal("ZK repository root is unexpectedly absent".to_owned())
            }),
            RepositoryStoreAvailability::NotPersistent => Err(ApiError::Unprocessable(
                "zero-knowledge repositories require CHANCELA_DATA_DIR persistence".to_owned(),
            )),
            RepositoryStoreAvailability::FailClosed(message) => {
                Err(ApiError::Unavailable(message.clone()))
            }
        }
    }

    pub(crate) fn repository_parents(&self) -> Vec<(Uuid, Uuid)> {
        if !matches!(self.availability, RepositoryStoreAvailability::Ready) {
            return Vec::new();
        }
        self.index
            .repositories
            .iter()
            .map(|record| (record.policy.repository_id.0, record.policy.tenant_id))
            .collect()
    }

    pub(crate) fn archive_parents(&self) -> Vec<(Uuid, Uuid)> {
        if !matches!(self.availability, RepositoryStoreAvailability::Ready) {
            return Vec::new();
        }
        self.index
            .object_versions
            .iter()
            .map(|version| {
                (
                    version.archive_id,
                    version.manifest.associated_data.repository_id.0,
                )
            })
            .collect()
    }

    pub(crate) fn reload(&mut self) -> Result<(), ApiError> {
        let root = self.ready_root()?.to_path_buf();
        self.index = load_index_and_reconcile(&root).map_err(|message| {
            self.availability = RepositoryStoreAvailability::FailClosed(message.clone());
            ApiError::Unavailable(message)
        })?;
        Ok(())
    }

    pub(crate) fn clear_persisted(&mut self) -> Result<(), ApiError> {
        let root = self.ready_root()?.to_path_buf();
        if root.exists() {
            validate_object_root_path(&root)?;
            fs::remove_dir_all(&root).map_err(|e| storage_error("remove ZK repository root", e))?;
            sync_parent(&root)?;
        }
        self.index = ZkRepositoryIndex::default();
        Ok(())
    }

    fn persist_index(&mut self, mut next: ZkRepositoryIndex) -> Result<(), ApiError> {
        let root = self.ready_root()?.to_path_buf();
        sort_index(&mut next);
        validate_index_structure(&next)?;
        ensure_store_dirs(&root)?;
        let json = serde_json::to_vec_pretty(&next)
            .map_err(|e| ApiError::Internal(format!("serialize ZK repository index: {e}")))?;
        write_atomic_synced(&root.join(INDEX_FILE), &json)?;
        self.index = next;
        Ok(())
    }

    fn tenant_policy(&self, tenant_id: Uuid) -> Option<&TenantRepositoryPolicy> {
        self.index
            .tenant_policies
            .iter()
            .find(|policy| policy.tenant_id == tenant_id)
    }

    fn repository(
        &self,
        tenant_id: Uuid,
        repository_id: RepositoryId,
    ) -> Option<&StoredRepositoryPolicy> {
        self.index.repositories.iter().find(|record| {
            record.policy.repository_id == repository_id && record.policy.tenant_id == tenant_id
        })
    }

    fn object_version(
        &self,
        tenant_id: Uuid,
        repository_id: RepositoryId,
        object_id: ObjectId,
        version: u64,
    ) -> Option<&StoredObjectVersion> {
        self.index.object_versions.iter().find(|record| {
            let ad = record.manifest.associated_data;
            record.tenant_id == tenant_id
                && ad.repository_id == repository_id
                && ad.object_id == object_id
                && ad.version == version
        })
    }

    fn create_upload(
        &self,
        tenant_id: Uuid,
        repository_id: RepositoryId,
        manifest: OpaqueBlobManifest,
    ) -> Result<PendingUpload, ApiError> {
        let root = self.ready_root()?;
        let repository = self
            .repository(tenant_id, repository_id)
            .ok_or(ApiError::NotFound)?;
        if repository.policy.encryption_mode != RepositoryEncryptionMode::ZeroKnowledge {
            return Err(ApiError::Conflict(
                "opaque ciphertext uploads require a zero-knowledge repository policy".to_owned(),
            ));
        }
        if manifest.associated_data.repository_id != repository_id {
            return Err(ApiError::Unprocessable(
                "manifest associated_data.repository_id does not match the route".to_owned(),
            ));
        }
        manifest.validate().map_err(contract_error)?;
        validate_candidate_version(&self.index, &manifest)?;
        ensure_nonce_is_unique(
            &manifest,
            self.index
                .object_versions
                .iter()
                .map(|value| &value.manifest),
        )
        .map_err(contract_conflict)?;

        let pending = PendingUpload {
            schema_version: PENDING_UPLOAD_SCHEMA_VERSION,
            upload_id: Uuid::new_v4(),
            tenant_id,
            repository_id,
            manifest,
            created_at: OffsetDateTime::now_utc(),
        };
        ensure_store_dirs(root)?;
        let json = serde_json::to_vec_pretty(&pending)
            .map_err(|e| ApiError::Internal(format!("serialize pending ZK upload: {e}")))?;
        write_new_synced(&pending_path(root, pending.upload_id), &json)?;
        Ok(pending)
    }

    fn commit_upload(
        &mut self,
        tenant_id: Uuid,
        repository_id: RepositoryId,
        upload_id: Uuid,
        ciphertext: &[u8],
    ) -> Result<(StoredObjectVersion, PendingUpload), ApiError> {
        let root = self.ready_root()?.to_path_buf();
        if ciphertext.len() > ZK_BLOB_MAX_BYTES {
            return Err(ApiError::Unprocessable(format!(
                "opaque ciphertext exceeds the {ZK_BLOB_MAX_BYTES}-byte limit"
            )));
        }
        let pending_path = pending_path(&root, upload_id);
        let pending = read_pending(&pending_path)?;
        if pending.tenant_id != tenant_id || pending.repository_id != repository_id {
            return Err(ApiError::NotFound);
        }
        let repository = self
            .repository(tenant_id, repository_id)
            .ok_or(ApiError::NotFound)?;
        if repository.policy.encryption_mode != RepositoryEncryptionMode::ZeroKnowledge {
            return Err(ApiError::Conflict(
                "the repository no longer accepts opaque ciphertext uploads".to_owned(),
            ));
        }
        pending
            .manifest
            .verify_ciphertext(ciphertext)
            .map_err(contract_error)?;
        validate_candidate_version(&self.index, &pending.manifest)?;
        ensure_nonce_is_unique(
            &pending.manifest,
            self.index
                .object_versions
                .iter()
                .map(|value| &value.manifest),
        )
        .map_err(contract_conflict)?;

        ensure_store_dirs(&root)?;
        let ad = pending.manifest.associated_data;
        let relative = blob_relative_path(repository_id, ad.object_id, ad.version);
        let final_path = safe_join(&root, &relative)?;
        if final_path.exists() {
            return Err(ApiError::Conflict(
                "this immutable object version already has ciphertext".to_owned(),
            ));
        }
        let parent = final_path
            .parent()
            .ok_or_else(|| ApiError::Internal("generated ZK blob path has no parent".to_owned()))?;
        create_safe_dir_all(&root, parent)?;
        let staging = root.join(STAGING_DIR).join(format!("{upload_id}.blob.tmp"));
        ensure_path_components(&root, &staging, true)?;
        write_new_synced(&staging, ciphertext)?;
        ensure_path_components(&root, &final_path, true)?;
        if let Err(e) = fs::rename(&staging, &final_path) {
            let _ = fs::remove_file(&staging);
            return Err(storage_error("publish immutable ZK ciphertext", e));
        }
        sync_dir(parent)?;

        let stored = StoredObjectVersion {
            archive_id: Uuid::new_v4(),
            tenant_id,
            manifest: pending.manifest.clone(),
            blob_relative_path: relative,
            committed_at: OffsetDateTime::now_utc(),
        };
        let mut next = self.index.clone();
        next.object_versions.push(stored.clone());
        if let Err(error) = self.persist_index(next) {
            let _ = fs::remove_file(&final_path);
            let _ = sync_dir(parent);
            return Err(error);
        }
        if let Err(e) = fs::remove_file(&pending_path) {
            eprintln!(
                "warning: committed ZK upload {upload_id}, but could not remove its pending record: {e}"
            );
        } else {
            let _ = sync_dir(pending_path.parent().unwrap_or(&root));
        }
        Ok((stored, pending))
    }

    fn remove_pending(&self, upload_id: Uuid) -> Result<(), ApiError> {
        let root = self.ready_root()?;
        let path = pending_path(root, upload_id);
        ensure_path_components(root, &path, true)?;
        match fs::remove_file(&path) {
            Ok(()) => sync_dir(path.parent().unwrap_or(root)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(storage_error("remove pending ZK upload", error)),
        }
    }

    fn rollback_index(&mut self, previous: ZkRepositoryIndex) -> Result<(), ApiError> {
        self.persist_index(previous)
    }

    fn rollback_committed_upload(
        &mut self,
        previous: ZkRepositoryIndex,
        stored: &StoredObjectVersion,
        pending: &PendingUpload,
    ) -> Result<(), ApiError> {
        let root = self.ready_root()?.to_path_buf();
        self.persist_index(previous)?;
        let pending_file = pending_path(&root, pending.upload_id);
        if !pending_file.exists() {
            let json = serde_json::to_vec_pretty(pending).map_err(|e| {
                ApiError::Internal(format!("serialize rolled-back pending ZK upload: {e}"))
            })?;
            write_new_synced(&pending_file, &json)?;
        }
        let blob = safe_join(&root, &stored.blob_relative_path)?;
        if blob.exists() {
            fs::remove_file(&blob)
                .map_err(|e| storage_error("remove rolled-back ZK ciphertext", e))?;
            sync_parent(&blob)?;
        }
        Ok(())
    }

    fn read_ciphertext(&self, record: &StoredObjectVersion) -> Result<Vec<u8>, ApiError> {
        let root = self.ready_root()?;
        let expected = blob_relative_path(
            record.manifest.associated_data.repository_id,
            record.manifest.associated_data.object_id,
            record.manifest.associated_data.version,
        );
        if record.blob_relative_path != expected {
            return Err(ApiError::Unavailable(
                "zero-knowledge repository index contains an unsafe blob path".to_owned(),
            ));
        }
        let path = safe_join(root, &record.blob_relative_path)?;
        ensure_no_symlink(&path)?;
        let bytes = read_bounded(&path, ZK_BLOB_MAX_BYTES)?;
        record.manifest.verify_ciphertext(&bytes).map_err(|e| {
            ApiError::Unavailable(format!("stored opaque ciphertext failed fixity: {e}"))
        })?;
        Ok(bytes)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PutTenantPolicyBody {
    encryption_mode: RepositoryEncryptionMode,
    custody: KeyCustodyPolicy,
    gdpr_obligations_remain: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateRepositoryBody {
    name: String,
    #[serde(default = "default_true")]
    inherit_tenant_policy: bool,
    #[serde(default)]
    encryption_mode: Option<RepositoryEncryptionMode>,
    #[serde(default)]
    custody: Option<KeyCustodyPolicy>,
    #[serde(default)]
    gdpr_obligations_remain: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PatchRepositoryBody {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    inherit_tenant_policy: Option<bool>,
    #[serde(default)]
    encryption_mode: Option<RepositoryEncryptionMode>,
    #[serde(default)]
    custody: Option<KeyCustodyPolicy>,
    #[serde(default)]
    gdpr_obligations_remain: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateUploadBody {
    manifest: OpaqueBlobManifest,
}

#[derive(Debug, Serialize)]
pub(crate) struct PendingUploadView {
    upload_id: Uuid,
    repository_id: RepositoryId,
    object_id: ObjectId,
    version: u64,
    ciphertext_upload_url: String,
    created_at: OffsetDateTime,
}

#[derive(Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum ReadabilityPackageBody {
    ClientDecryptedArchive {
        book_id: Uuid,
        archive_base64: String,
        archive_sha256: String,
        #[serde(default)]
        reauth: ReAuth,
    },
    EncryptedArchiveWithPortableKeyPackage {
        book_id: Uuid,
        portable_key_package_jwe: String,
        recipient_instructions: String,
        #[serde(default)]
        reauth: ReAuth,
    },
}

fn default_true() -> bool {
    true
}

fn require_content_type(headers: &HeaderMap, expected: &str) -> Result<(), ApiError> {
    let actual = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim);
    if actual != Some(expected) {
        return Err(ApiError::Unprocessable(format!(
            "Content-Type must be {expected}"
        )));
    }
    Ok(())
}

fn audit_scope(
    tenant_id: Uuid,
    repository_id: Option<RepositoryId>,
    archive_id: Option<Uuid>,
) -> String {
    let mut scope = format!("tenant:{tenant_id}");
    if let Some(repository_id) = repository_id {
        scope.push_str(&format!("/repository:{repository_id}"));
    }
    if let Some(archive_id) = archive_id {
        scope.push_str(&format!("/archive:{archive_id}"));
    }
    scope
}

async fn append_audit(
    state: &AppState,
    actor: &CurrentActor,
    attestor: &CurrentAttestor,
    scope: &str,
    kind: &str,
    justification: &str,
    metadata: serde_json::Value,
) -> Result<(), ApiError> {
    let payload = serde_json::to_vec(&metadata)?;
    let actor = actor.resolve("api");
    let mut ledger = state.ledger.write().await;
    crate::try_append_event(
        &mut ledger,
        &actor,
        scope,
        kind,
        Some(justification),
        &payload,
    )?;
    state
        .persist_write_through(&mut ledger, 1, |_tx| Ok(()))
        .await?;
    state.attest_latest(attestor, &ledger).await;
    Ok(())
}

fn manifest_audit_metadata(manifest: &OpaqueBlobManifest) -> serde_json::Value {
    let ad = manifest.associated_data;
    serde_json::json!({
        "repository_id": ad.repository_id,
        "object_id": ad.object_id,
        "version": ad.version,
        "algorithm": manifest.algorithm,
        "ciphertext_sha256": manifest.ciphertext_sha256,
        "ciphertext_len": manifest.ciphertext_len,
        "encrypted_metadata_present": manifest.encrypted_metadata.is_some(),
        "wrapped_key_slot_count": manifest.wrapped_keys.len(),
    })
}

fn rollback_failure(original: ApiError, rollback: Result<(), ApiError>) -> ApiError {
    match rollback {
        Ok(()) => original,
        Err(rollback) => ApiError::Internal(format!(
            "ZK mutation audit failed ({original:?}) and compensating storage rollback also failed ({rollback:?})"
        )),
    }
}

fn normalized_name(value: String) -> Result<String, ApiError> {
    let value = value.trim().to_owned();
    if value.is_empty() || value.chars().count() > MAX_REPOSITORY_NAME_CHARS {
        return Err(ApiError::Unprocessable(format!(
            "repository name must contain 1 to {MAX_REPOSITORY_NAME_CHARS} characters"
        )));
    }
    Ok(value)
}

fn ensure_unique_repository_name(
    index: &ZkRepositoryIndex,
    tenant_id: Uuid,
    excluding: Option<RepositoryId>,
    name: &str,
) -> Result<(), ApiError> {
    let key = name.trim().to_lowercase();
    if index.repositories.iter().any(|record| {
        record.policy.tenant_id == tenant_id
            && Some(record.policy.repository_id) != excluding
            && record.policy.name.trim().to_lowercase() == key
    }) {
        Err(ApiError::Conflict(
            "a repository with that name already exists in this tenant".to_owned(),
        ))
    } else {
        Ok(())
    }
}

fn policy_from_tenant(
    repository_id: RepositoryId,
    name: String,
    policy: &TenantRepositoryPolicy,
    created_at: OffsetDateTime,
) -> RepositoryPolicy {
    RepositoryPolicy {
        repository_id,
        tenant_id: policy.tenant_id,
        name,
        encryption_mode: policy.encryption_mode,
        zk_scope: match policy.encryption_mode {
            RepositoryEncryptionMode::Standard => None,
            RepositoryEncryptionMode::ZeroKnowledge => Some(ZeroKnowledgeScope::Tenant {
                tenant_id: policy.tenant_id,
            }),
        },
        custody: policy.custody.clone(),
        gdpr_obligations_remain: policy.gdpr_obligations_remain,
        created_at,
        updated_at: policy.updated_at,
    }
}

fn explicit_policy(
    repository_id: RepositoryId,
    tenant_id: Uuid,
    name: String,
    encryption_mode: RepositoryEncryptionMode,
    custody: KeyCustodyPolicy,
    gdpr_obligations_remain: bool,
    timestamps: (OffsetDateTime, OffsetDateTime),
) -> RepositoryPolicy {
    let (created_at, updated_at) = timestamps;
    RepositoryPolicy {
        repository_id,
        tenant_id,
        name,
        encryption_mode,
        zk_scope: match encryption_mode {
            RepositoryEncryptionMode::Standard => None,
            RepositoryEncryptionMode::ZeroKnowledge => {
                Some(ZeroKnowledgeScope::Repository { repository_id })
            }
        },
        custody,
        gdpr_obligations_remain,
        created_at,
        updated_at,
    }
}

fn scope_of_repository(repository_id: RepositoryId) -> Scope {
    Scope::Repository(AuthzRepositoryId(repository_id.0))
}

fn scope_of_archive(archive_id: Uuid) -> Scope {
    Scope::Archive(AuthzArchiveId(archive_id))
}

async fn require_known_tenant(state: &AppState, tenant_id: TenantId) -> Result<(), ApiError> {
    if state.tenants.read().await.contains_key(&tenant_id) {
        Ok(())
    } else {
        Err(ApiError::NotFound)
    }
}

pub(crate) async fn get_tenant_repository_policy(
    State(state): State<AppState>,
    Path(tenant): Path<Uuid>,
    actor: CurrentActor,
) -> Result<Json<TenantRepositoryPolicy>, ApiError> {
    let tenant_id = TenantId(tenant);
    require_permission(
        &state,
        &actor,
        Permission::SettingsRead,
        scope_of_tenant(tenant_id),
    )
    .await?;
    require_known_tenant(&state, tenant_id).await?;
    let store = state.zk_repositories.read().await;
    store.ready_root()?;
    store
        .tenant_policy(tenant)
        .cloned()
        .map(Json)
        .ok_or(ApiError::NotFound)
}

pub(crate) async fn put_tenant_repository_policy(
    State(state): State<AppState>,
    Path(tenant): Path<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(body): Json<PutTenantPolicyBody>,
) -> Result<Json<TenantRepositoryPolicy>, ApiError> {
    let tenant_id = TenantId(tenant);
    require_permission(
        &state,
        &actor,
        Permission::SettingsManage,
        scope_of_tenant(tenant_id),
    )
    .await?;
    require_known_tenant(&state, tenant_id).await?;
    let now = OffsetDateTime::now_utc();
    let mut store = state.zk_repositories.write().await;
    store.ready_root()?;
    let previous = store.index.clone();
    let existing = store.tenant_policy(tenant).cloned();
    if body.encryption_mode == RepositoryEncryptionMode::Standard
        && store.index.repositories.iter().any(|repository| {
            repository.policy.tenant_id == tenant
                && repository.policy_source == RepositoryPolicySource::Tenant
                && store.index.object_versions.iter().any(|version| {
                    version.manifest.associated_data.repository_id
                        == repository.policy.repository_id
                })
        })
    {
        return Err(ApiError::Conflict(
            "cannot downgrade an inherited tenant policy while its repositories contain immutable ciphertext"
                .to_owned(),
        ));
    }
    let policy = TenantRepositoryPolicy {
        tenant_id: tenant,
        encryption_mode: body.encryption_mode,
        custody: body.custody,
        gdpr_obligations_remain: body.gdpr_obligations_remain,
        created_at: existing.as_ref().map_or(now, |value| value.created_at),
        updated_at: now,
    };
    policy.validate()?;
    let mut next = previous.clone();
    next.tenant_policies
        .retain(|value| value.tenant_id != tenant);
    next.tenant_policies.push(policy.clone());
    for repository in next.repositories.iter_mut().filter(|record| {
        record.policy.tenant_id == tenant && record.policy_source == RepositoryPolicySource::Tenant
    }) {
        repository.policy = policy_from_tenant(
            repository.policy.repository_id,
            repository.policy.name.clone(),
            &policy,
            repository.policy.created_at,
        );
        repository.policy.updated_at = now;
        repository.policy.validate().map_err(contract_error)?;
    }
    store.persist_index(next)?;
    if let Err(error) = append_audit(
        &state,
        &actor,
        &attestor,
        &audit_scope(tenant, None, None),
        "zk.tenant_policy.upserted",
        &format!("tenant_repository_policy:{tenant}"),
        serde_json::json!({
            "tenant_id": tenant,
            "encryption_mode": policy.encryption_mode,
            "gdpr_obligations_remain": policy.gdpr_obligations_remain,
            "custody_methods": {
                "bring_your_own_key": policy.custody.bring_your_own_key,
                "webauthn_prf_unsealing": policy.custody.webauthn_prf_unsealing,
                "split_key_recovery_configured": policy.custody.split_key_recovery.is_some()
            }
        }),
    )
    .await
    {
        return Err(rollback_failure(error, store.rollback_index(previous)));
    }
    Ok(Json(policy))
}

pub(crate) async fn delete_tenant_repository_policy(
    State(state): State<AppState>,
    Path(tenant): Path<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
) -> Result<StatusCode, ApiError> {
    let tenant_id = TenantId(tenant);
    require_permission(
        &state,
        &actor,
        Permission::SettingsManage,
        scope_of_tenant(tenant_id),
    )
    .await?;
    require_known_tenant(&state, tenant_id).await?;
    let mut store = state.zk_repositories.write().await;
    store.ready_root()?;
    if store.index.repositories.iter().any(|record| {
        record.policy.tenant_id == tenant && record.policy_source == RepositoryPolicySource::Tenant
    }) {
        return Err(ApiError::Conflict(
            "convert inherited repositories to explicit policies before deleting the tenant policy"
                .to_owned(),
        ));
    }
    if store.tenant_policy(tenant).is_none() {
        return Err(ApiError::NotFound);
    }
    let previous = store.index.clone();
    let mut next = previous.clone();
    next.tenant_policies
        .retain(|value| value.tenant_id != tenant);
    store.persist_index(next)?;
    if let Err(error) = append_audit(
        &state,
        &actor,
        &attestor,
        &audit_scope(tenant, None, None),
        "zk.tenant_policy.deleted",
        &format!("tenant_repository_policy:{tenant}"),
        serde_json::json!({"tenant_id": tenant}),
    )
    .await
    {
        return Err(rollback_failure(error, store.rollback_index(previous)));
    }
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn list_repositories(
    State(state): State<AppState>,
    Path(tenant): Path<Uuid>,
    actor: CurrentActor,
) -> Result<Json<Vec<StoredRepositoryPolicy>>, ApiError> {
    let tenant_id = TenantId(tenant);
    require_permission(
        &state,
        &actor,
        Permission::SettingsRead,
        scope_of_tenant(tenant_id),
    )
    .await?;
    require_known_tenant(&state, tenant_id).await?;
    let store = state.zk_repositories.read().await;
    store.ready_root()?;
    let mut repositories = store
        .index
        .repositories
        .iter()
        .filter(|record| record.policy.tenant_id == tenant)
        .cloned()
        .collect::<Vec<_>>();
    repositories.sort_by(|a, b| {
        a.policy
            .name
            .cmp(&b.policy.name)
            .then(a.policy.repository_id.cmp(&b.policy.repository_id))
    });
    Ok(Json(repositories))
}

pub(crate) async fn create_repository(
    State(state): State<AppState>,
    Path(tenant): Path<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(body): Json<CreateRepositoryBody>,
) -> Result<(StatusCode, Json<StoredRepositoryPolicy>), ApiError> {
    let tenant_id = TenantId(tenant);
    require_permission(
        &state,
        &actor,
        Permission::SettingsManage,
        scope_of_tenant(tenant_id),
    )
    .await?;
    require_known_tenant(&state, tenant_id).await?;
    let name = normalized_name(body.name)?;
    let now = OffsetDateTime::now_utc();
    let repository_id = RepositoryId::new();
    let mut store = state.zk_repositories.write().await;
    store.ready_root()?;
    ensure_unique_repository_name(&store.index, tenant, None, &name)?;
    let record = if body.inherit_tenant_policy {
        let tenant_policy = store.tenant_policy(tenant).ok_or_else(|| {
            ApiError::Unprocessable(
                "inherit_tenant_policy=true requires an existing tenant repository policy"
                    .to_owned(),
            )
        })?;
        if body.encryption_mode.is_some()
            || body.custody.is_some()
            || body.gdpr_obligations_remain.is_some()
        {
            return Err(ApiError::Unprocessable(
                "inherited repository policies cannot override encryption, custody, or GDPR fields"
                    .to_owned(),
            ));
        }
        StoredRepositoryPolicy {
            policy: policy_from_tenant(repository_id, name, tenant_policy, now),
            policy_source: RepositoryPolicySource::Tenant,
        }
    } else {
        let encryption_mode = body.encryption_mode.ok_or_else(|| {
            ApiError::Unprocessable(
                "an explicit repository policy requires encryption_mode".to_owned(),
            )
        })?;
        let custody = body.custody.ok_or_else(|| {
            ApiError::Unprocessable("an explicit repository policy requires custody".to_owned())
        })?;
        StoredRepositoryPolicy {
            policy: explicit_policy(
                repository_id,
                tenant,
                name,
                encryption_mode,
                custody,
                body.gdpr_obligations_remain.unwrap_or(true),
                (now, now),
            ),
            policy_source: RepositoryPolicySource::Repository,
        }
    };
    record.policy.validate().map_err(contract_error)?;
    let previous = store.index.clone();
    let mut next = previous.clone();
    next.repositories.push(record.clone());
    store.persist_index(next)?;
    if let Err(error) = append_audit(
        &state,
        &actor,
        &attestor,
        &audit_scope(tenant, Some(repository_id), None),
        "zk.repository.created",
        &format!("repository:{repository_id}"),
        serde_json::json!({
            "tenant_id": tenant,
            "repository_id": repository_id,
            "policy_source": record.policy_source,
            "encryption_mode": record.policy.encryption_mode,
            "gdpr_obligations_remain": record.policy.gdpr_obligations_remain
        }),
    )
    .await
    {
        return Err(rollback_failure(error, store.rollback_index(previous)));
    }
    Ok((StatusCode::CREATED, Json(record)))
}

async fn repository_for_route(
    state: &AppState,
    actor: &CurrentActor,
    tenant: Uuid,
    repository_id: RepositoryId,
    permission: Permission,
) -> Result<StoredRepositoryPolicy, ApiError> {
    let record = {
        let store = state.zk_repositories.read().await;
        store.ready_root()?;
        store.repository(tenant, repository_id).cloned()
    };
    match record {
        Some(record) => {
            require_permission(state, actor, permission, scope_of_repository(repository_id))
                .await?;
            Ok(record)
        }
        None => {
            require_permission(state, actor, permission, scope_of_tenant(TenantId(tenant))).await?;
            Err(ApiError::NotFound)
        }
    }
}

pub(crate) async fn get_repository(
    State(state): State<AppState>,
    Path((tenant, repository)): Path<(Uuid, Uuid)>,
    actor: CurrentActor,
) -> Result<Json<StoredRepositoryPolicy>, ApiError> {
    repository_for_route(
        &state,
        &actor,
        tenant,
        RepositoryId(repository),
        Permission::SettingsRead,
    )
    .await
    .map(Json)
}

pub(crate) async fn patch_repository(
    State(state): State<AppState>,
    Path((tenant, repository)): Path<(Uuid, Uuid)>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(body): Json<PatchRepositoryBody>,
) -> Result<Json<StoredRepositoryPolicy>, ApiError> {
    let repository_id = RepositoryId(repository);
    let current = repository_for_route(
        &state,
        &actor,
        tenant,
        repository_id,
        Permission::SettingsManage,
    )
    .await?;
    let mut store = state.zk_repositories.write().await;
    let previous = store.index.clone();
    let now = OffsetDateTime::now_utc();
    let name = match body.name {
        Some(value) => normalized_name(value)?,
        None => current.policy.name.clone(),
    };
    ensure_unique_repository_name(&store.index, tenant, Some(repository_id), &name)?;
    let inherit = body
        .inherit_tenant_policy
        .unwrap_or(current.policy_source == RepositoryPolicySource::Tenant);
    let record = if inherit {
        let tenant_policy = store.tenant_policy(tenant).ok_or_else(|| {
            ApiError::Unprocessable(
                "inherit_tenant_policy=true requires an existing tenant repository policy"
                    .to_owned(),
            )
        })?;
        if body.encryption_mode.is_some()
            || body.custody.is_some()
            || body.gdpr_obligations_remain.is_some()
        {
            return Err(ApiError::Unprocessable(
                "inherited repository policies cannot override encryption, custody, or GDPR fields"
                    .to_owned(),
            ));
        }
        StoredRepositoryPolicy {
            policy: policy_from_tenant(
                repository_id,
                name,
                tenant_policy,
                current.policy.created_at,
            ),
            policy_source: RepositoryPolicySource::Tenant,
        }
    } else {
        StoredRepositoryPolicy {
            policy: explicit_policy(
                repository_id,
                tenant,
                name,
                body.encryption_mode
                    .unwrap_or(current.policy.encryption_mode),
                body.custody.unwrap_or(current.policy.custody),
                body.gdpr_obligations_remain
                    .unwrap_or(current.policy.gdpr_obligations_remain),
                (current.policy.created_at, now),
            ),
            policy_source: RepositoryPolicySource::Repository,
        }
    };
    record.policy.validate().map_err(contract_error)?;
    if current.policy.encryption_mode == RepositoryEncryptionMode::ZeroKnowledge
        && record.policy.encryption_mode == RepositoryEncryptionMode::Standard
        && store
            .index
            .object_versions
            .iter()
            .any(|version| version.manifest.associated_data.repository_id == repository_id)
    {
        return Err(ApiError::Conflict(
            "cannot downgrade a repository that contains immutable ciphertext".to_owned(),
        ));
    }
    let mut next = previous.clone();
    let target = next
        .repositories
        .iter_mut()
        .find(|value| value.policy.repository_id == repository_id)
        .ok_or(ApiError::NotFound)?;
    *target = record.clone();
    store.persist_index(next)?;
    if let Err(error) = append_audit(
        &state,
        &actor,
        &attestor,
        &audit_scope(tenant, Some(repository_id), None),
        "zk.repository.updated",
        &format!("repository:{repository_id}"),
        serde_json::json!({
            "tenant_id": tenant,
            "repository_id": repository_id,
            "policy_source": record.policy_source,
            "encryption_mode": record.policy.encryption_mode,
            "gdpr_obligations_remain": record.policy.gdpr_obligations_remain
        }),
    )
    .await
    {
        return Err(rollback_failure(error, store.rollback_index(previous)));
    }
    Ok(Json(record))
}

pub(crate) async fn delete_repository(
    State(state): State<AppState>,
    Path((tenant, repository)): Path<(Uuid, Uuid)>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
) -> Result<StatusCode, ApiError> {
    let repository_id = RepositoryId(repository);
    repository_for_route(
        &state,
        &actor,
        tenant,
        repository_id,
        Permission::SettingsManage,
    )
    .await?;
    let mut store = state.zk_repositories.write().await;
    if store
        .index
        .object_versions
        .iter()
        .any(|version| version.manifest.associated_data.repository_id == repository_id)
    {
        return Err(ApiError::Conflict(
            "a repository containing immutable object versions cannot be deleted".to_owned(),
        ));
    }
    let previous = store.index.clone();
    let mut next = previous.clone();
    next.repositories
        .retain(|value| value.policy.repository_id != repository_id);
    store.persist_index(next)?;
    if let Err(error) = append_audit(
        &state,
        &actor,
        &attestor,
        &audit_scope(tenant, Some(repository_id), None),
        "zk.repository.deleted",
        &format!("repository:{repository_id}"),
        serde_json::json!({"tenant_id": tenant, "repository_id": repository_id}),
    )
    .await
    {
        return Err(rollback_failure(error, store.rollback_index(previous)));
    }
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn create_object_upload(
    State(state): State<AppState>,
    Path((tenant, repository)): Path<(Uuid, Uuid)>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(body): Json<CreateUploadBody>,
) -> Result<(StatusCode, Json<PendingUploadView>), ApiError> {
    let repository_id = RepositoryId(repository);
    repository_for_route(
        &state,
        &actor,
        tenant,
        repository_id,
        Permission::DataBackup,
    )
    .await?;
    let store = state.zk_repositories.write().await;
    let pending = store.create_upload(tenant, repository_id, body.manifest)?;
    let ad = pending.manifest.associated_data;
    let view = PendingUploadView {
        upload_id: pending.upload_id,
        repository_id,
        object_id: ad.object_id,
        version: ad.version,
        ciphertext_upload_url: format!(
            "/v1/tenants/{tenant}/repositories/{repository}/uploads/{}/ciphertext",
            pending.upload_id
        ),
        created_at: pending.created_at,
    };
    if let Err(error) = append_audit(
        &state,
        &actor,
        &attestor,
        &audit_scope(tenant, Some(repository_id), None),
        "zk.manifest.registered",
        &format!("zk_upload:{}", pending.upload_id),
        manifest_audit_metadata(&pending.manifest),
    )
    .await
    {
        return Err(rollback_failure(
            error,
            store.remove_pending(pending.upload_id),
        ));
    }
    Ok((StatusCode::CREATED, Json(view)))
}

pub(crate) async fn upload_object_ciphertext(
    State(state): State<AppState>,
    Path((tenant, repository, upload)): Path<(Uuid, Uuid, Uuid)>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<ObjectVersionView>), ApiError> {
    require_content_type(&headers, "application/octet-stream")?;
    let repository_id = RepositoryId(repository);
    repository_for_route(
        &state,
        &actor,
        tenant,
        repository_id,
        Permission::DataBackup,
    )
    .await?;
    let mut store = state.zk_repositories.write().await;
    let previous = store.index.clone();
    let (version, pending) = store.commit_upload(tenant, repository_id, upload, &body)?;
    let mut metadata = manifest_audit_metadata(&version.manifest);
    if let Some(object) = metadata.as_object_mut() {
        object.insert(
            "archive_id".to_owned(),
            serde_json::json!(version.archive_id),
        );
    }
    if let Err(error) = append_audit(
        &state,
        &actor,
        &attestor,
        &audit_scope(tenant, Some(repository_id), Some(version.archive_id)),
        "zk.ciphertext.committed",
        &format!("archive:{}", version.archive_id),
        metadata,
    )
    .await
    {
        let rollback = store.rollback_committed_upload(previous, &version, &pending);
        return Err(rollback_failure(error, rollback));
    }
    Ok((
        StatusCode::CREATED,
        Json(ObjectVersionView::from_stored(&version)),
    ))
}

pub(crate) async fn list_object_versions(
    State(state): State<AppState>,
    Path((tenant, repository)): Path<(Uuid, Uuid)>,
    actor: CurrentActor,
) -> Result<Json<Vec<ObjectVersionView>>, ApiError> {
    let repository_id = RepositoryId(repository);
    repository_for_route(
        &state,
        &actor,
        tenant,
        repository_id,
        Permission::DataExport,
    )
    .await?;
    let store = state.zk_repositories.read().await;
    let mut versions = store
        .index
        .object_versions
        .iter()
        .filter(|value| {
            value.tenant_id == tenant
                && value.manifest.associated_data.repository_id == repository_id
        })
        .map(ObjectVersionView::from_stored)
        .collect::<Vec<_>>();
    versions.sort_by_key(|value| {
        (
            value.manifest.associated_data.object_id,
            value.manifest.associated_data.version,
        )
    });
    Ok(Json(versions))
}

async fn object_for_route(
    state: &AppState,
    actor: &CurrentActor,
    tenant: Uuid,
    repository_id: RepositoryId,
    object_id: ObjectId,
    version: u64,
) -> Result<StoredObjectVersion, ApiError> {
    let record = {
        let store = state.zk_repositories.read().await;
        store.ready_root()?;
        store
            .object_version(tenant, repository_id, object_id, version)
            .cloned()
    };
    match record {
        Some(record) => {
            require_permission(
                state,
                actor,
                Permission::DataExport,
                scope_of_archive(record.archive_id),
            )
            .await?;
            Ok(record)
        }
        None => {
            require_permission(
                state,
                actor,
                Permission::DataExport,
                scope_of_repository(repository_id),
            )
            .await?;
            Err(ApiError::NotFound)
        }
    }
}

pub(crate) async fn get_object_manifest(
    State(state): State<AppState>,
    Path((tenant, repository, object, version)): Path<(Uuid, Uuid, Uuid, u64)>,
    actor: CurrentActor,
) -> Result<Json<ObjectVersionView>, ApiError> {
    let record = object_for_route(
        &state,
        &actor,
        tenant,
        RepositoryId(repository),
        ObjectId(object),
        version,
    )
    .await?;
    Ok(Json(ObjectVersionView::from_stored(&record)))
}

pub(crate) async fn get_object_ciphertext(
    State(state): State<AppState>,
    Path((tenant, repository, object, version)): Path<(Uuid, Uuid, Uuid, u64)>,
    actor: CurrentActor,
) -> Result<Response, ApiError> {
    let record = object_for_route(
        &state,
        &actor,
        tenant,
        RepositoryId(repository),
        ObjectId(object),
        version,
    )
    .await?;
    let bytes = state
        .zk_repositories
        .read()
        .await
        .read_ciphertext(&record)?;
    let mut response = Response::new(Body::from(bytes));
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    response.headers_mut().insert(
        "x-content-sha256",
        HeaderValue::from_str(&record.manifest.ciphertext_sha256)
            .map_err(|e| ApiError::Internal(format!("invalid stored digest header: {e}")))?,
    );
    Ok(response)
}

pub(crate) async fn create_readability_package(
    State(state): State<AppState>,
    Path((tenant, repository, object, version)): Path<(Uuid, Uuid, Uuid, u64)>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(body): Json<ReadabilityPackageBody>,
) -> Result<Response, ApiError> {
    let repository_id = RepositoryId(repository);
    let record = object_for_route(
        &state,
        &actor,
        tenant,
        repository_id,
        ObjectId(object),
        version,
    )
    .await?;
    let (book_id, reauth) = match &body {
        ReadabilityPackageBody::ClientDecryptedArchive {
            book_id, reauth, ..
        }
        | ReadabilityPackageBody::EncryptedArchiveWithPortableKeyPackage {
            book_id, reauth, ..
        } => (*book_id, reauth),
    };
    require_step_up(&state, &actor, reauth).await?;
    let book_id = BookId(book_id);
    require_permission(
        &state,
        &actor,
        Permission::BookExport,
        scope_of_book(book_id),
    )
    .await?;
    let entity_id = {
        let books = state.books.read().await;
        let book = books.get(&book_id).ok_or(ApiError::NotFound)?;
        let entities = state.entities.read().await;
        let entity = entities.get(&book.entity_id).ok_or(ApiError::NotFound)?;
        if entity.tenant_id.0 != tenant {
            return Err(ApiError::NotFound);
        }
        entity.id
    };

    let now = OffsetDateTime::now_utc();
    let mut input = PackageBuildInput::new(Uuid::new_v4(), now, entity_id.0, book_id.0);
    input.producer = ProducerMetadata {
        name: "Trusted Chancela client".to_owned(),
        system: "Chancela zero-knowledge readability transfer".to_owned(),
    };
    input.rights = RightsMetadata {
        holder: None,
        license: None,
        access_note: Some(
            "Internal transfer only; this package does not certify a legal archive".to_owned(),
        ),
    };
    input.languages = vec!["pt-PT".to_owned()];
    input.retention = RetentionInstructions::default();

    let readability_mode;
    match body {
        ReadabilityPackageBody::ClientDecryptedArchive {
            archive_base64,
            archive_sha256,
            ..
        } => {
            readability_mode = "client_decrypted_archive";
            let bytes = BASE64.decode(archive_base64.as_bytes()).map_err(|_| {
                ApiError::Unprocessable("archive_base64 is not valid base64".to_owned())
            })?;
            if bytes.is_empty() || bytes.len() > ZK_BLOB_MAX_BYTES {
                return Err(ApiError::Unprocessable(format!(
                    "client-decrypted archive must contain 1 to {ZK_BLOB_MAX_BYTES} bytes"
                )));
            }
            verify_declared_digest(&archive_sha256, &bytes)?;
            validate_package(&bytes).map_err(|e| {
                ApiError::Unprocessable(format!(
                    "client-decrypted archive is not a validated Chancela preservation package: {e}"
                ))
            })?;
            input.files.push(PackageFileInput::new(
                CLIENT_ARCHIVE_PATH,
                PackageFileRole::Other,
                "application/zip",
                bytes,
            ));
            input.readability = ReadabilityExport::ClientDecryptedTransfer {
                source_repository_id: repository_id.0,
            };
        }
        ReadabilityPackageBody::EncryptedArchiveWithPortableKeyPackage {
            portable_key_package_jwe,
            recipient_instructions,
            ..
        } => {
            readability_mode = "encrypted_archive_with_portable_key_package";
            let ciphertext = state
                .zk_repositories
                .read()
                .await
                .read_ciphertext(&record)?;
            input.files.push(PackageFileInput::new(
                ENCRYPTED_ARCHIVE_PATH,
                PackageFileRole::Other,
                "application/octet-stream",
                ciphertext,
            ));
            input.readability = ReadabilityExport::EncryptedTransferWithPortableKeyPackage {
                source_repository_id: repository_id.0,
                portable_key_package_jwe,
                recipient_instructions,
            };
        }
    }

    let package = build_archive_package(input).map_err(|e| {
        ApiError::Unprocessable(format!("readability package request is invalid: {e}"))
    })?;
    validate_package(&package.bytes).map_err(|e| {
        ApiError::Internal(format!("readability package self-validation failed: {e}"))
    })?;
    append_audit(
        &state,
        &actor,
        &attestor,
        &audit_scope(tenant, Some(repository_id), Some(record.archive_id)),
        "zk.readability.exported",
        &format!("archive:{}", record.archive_id),
        serde_json::json!({
            "tenant_id": tenant,
            "repository_id": repository_id,
            "archive_id": record.archive_id,
            "object_id": record.manifest.associated_data.object_id,
            "version": record.manifest.associated_data.version,
            "book_id": book_id,
            "mode": readability_mode,
            "gdpr_obligations_remain": true,
            "legal_archive_certified": false
        }),
    )
    .await?;
    Response::builder()
        .header(CONTENT_TYPE, "application/zip")
        .header(
            CONTENT_DISPOSITION,
            format!(
                "attachment; filename=\"chancela-readability-archive-{}.zip\"",
                record.archive_id
            ),
        )
        .body(Body::from(package.bytes))
        .map_err(|e| ApiError::Internal(format!("build readability response: {e}")))
}

fn validate_candidate_version(
    index: &ZkRepositoryIndex,
    candidate: &OpaqueBlobManifest,
) -> Result<(), ApiError> {
    let ad = candidate.associated_data;
    let mut existing = index.object_versions.iter().filter(|value| {
        value.manifest.associated_data.repository_id == ad.repository_id
            && value.manifest.associated_data.object_id == ad.object_id
    });
    let max = existing
        .by_ref()
        .map(|value| value.manifest.associated_data.version)
        .max();
    let expected = max.map_or(1, |value| value.saturating_add(1));
    if ad.version != expected {
        return Err(ApiError::Conflict(format!(
            "immutable object version must be the next contiguous version ({expected})"
        )));
    }
    Ok(())
}

fn contract_error(error: chancela_zk::ContractError) -> ApiError {
    ApiError::Unprocessable(error.to_string())
}

fn contract_conflict(error: chancela_zk::ContractError) -> ApiError {
    ApiError::Conflict(error.to_string())
}

fn verify_declared_digest(expected: &str, bytes: &[u8]) -> Result<(), ApiError> {
    if expected.len() != 64
        || !expected
            .bytes()
            .all(|value| value.is_ascii_digit() || (b'a'..=b'f').contains(&value))
    {
        return Err(ApiError::Unprocessable(
            "archive_sha256 must be 64 lower-case hexadecimal characters".to_owned(),
        ));
    }
    let actual = format!("{:x}", Sha256::digest(bytes));
    if actual != expected {
        return Err(ApiError::Unprocessable(
            "archive_sha256 does not match the client-decrypted archive".to_owned(),
        ));
    }
    Ok(())
}

fn blob_relative_path(repository: RepositoryId, object: ObjectId, version: u64) -> String {
    format!("{OBJECTS_DIR}/{repository}/{object}/{version}.bin")
}

fn pending_path(root: &FsPath, upload_id: Uuid) -> PathBuf {
    root.join(UPLOADS_DIR).join(format!("{upload_id}.json"))
}

fn normalized_absolute(path: &FsPath) -> Result<PathBuf, String> {
    let raw = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| format!("resolve current directory for ZK object root: {e}"))?
            .join(path)
    };
    let mut normalized = PathBuf::new();
    for component in raw.components() {
        match component {
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                normalized.push(component.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return Err("ZK object root escapes its filesystem root".to_owned());
                }
            }
        }
    }
    Ok(resolve_existing_prefix(normalized))
}

/// Replace the longest *existing* prefix of `path` with its real (fully symlink-resolved) path,
/// re-appending the components that do not exist yet.
///
/// This is what makes the configured object root a **real** path before anything else in this
/// module touches it. It deliberately does **not** relax [`ensure_existing_components`]: every
/// component at or below the root is still rejected outright if it is a symbolic link, so the
/// traversal protection that guard exists for — an attacker swapping `objects/<repo>` for a link
/// pointing outside the root — is completely unchanged.
///
/// What it does fix is that the guard was also walking the components *above* the root, i.e. the
/// host's own filesystem layout, which the deployment does not control and the repository has no
/// standing to veto. On macOS `$TMPDIR` lives under `/var`, which is a symlink to `/private/var`,
/// so every path under it was refused before the repository looked at a single byte it owns. The
/// same shape appears on real hosts (`/home` under autofs, container bind mounts). Resolving the
/// root up front means the walk asks about real directories rather than about that ancestry —
/// nothing is exempted from the check, the check is simply asked the right question.
///
/// Unix only: on Windows `fs::canonicalize` returns `\\?\`-verbatim paths, which would change the
/// `starts_with` / `strip_prefix` containment arithmetic every caller here depends on. Windows has
/// no equivalent of the `/var` case, so it keeps the previous, byte-identical behaviour.
#[cfg(unix)]
fn resolve_existing_prefix(path: PathBuf) -> PathBuf {
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    let mut probe = path.as_path();
    loop {
        if let Ok(mut resolved) = fs::canonicalize(probe) {
            for component in tail.iter().rev() {
                resolved.push(component.as_os_str());
            }
            return resolved;
        }
        // Nothing on this path exists yet (or it is unreadable): leave it lexically normalized.
        let (Some(name), Some(parent)) = (probe.file_name(), probe.parent()) else {
            return path;
        };
        tail.push(name.to_owned());
        probe = parent;
    }
}

/// Windows keeps the previous, byte-identical behaviour — see the `#[cfg(unix)]` twin above.
#[cfg(not(unix))]
fn resolve_existing_prefix(path: PathBuf) -> PathBuf {
    path
}

fn safe_join(root: &FsPath, relative: &str) -> Result<PathBuf, ApiError> {
    let relative = FsPath::new(relative);
    if relative.is_absolute()
        || relative.components().any(|component| {
            !matches!(component, Component::Normal(_))
                || component
                    .as_os_str()
                    .to_string_lossy()
                    .contains(['/', '\\'])
        })
    {
        return Err(ApiError::Unavailable(
            "ZK repository index contains a traversal-unsafe path".to_owned(),
        ));
    }
    let path = root.join(relative);
    if !path.starts_with(root) {
        return Err(ApiError::Unavailable(
            "ZK repository path escaped its configured root".to_owned(),
        ));
    }
    ensure_path_components(root, &path, true)?;
    Ok(path)
}

fn ensure_no_symlink(path: &FsPath) -> Result<(), ApiError> {
    ensure_existing_components(path, true)
}

/// Reject a symbolic link or non-directory at every existing intermediate component. Lexical
/// `starts_with` checks are insufficient: `objects/<repo>` itself could otherwise be swapped for a
/// link that points outside the configured root.
fn ensure_existing_components(path: &FsPath, final_may_be_file: bool) -> Result<(), ApiError> {
    let mut current = PathBuf::new();
    let components = path.components().collect::<Vec<_>>();
    for (index, component) in components.iter().enumerate() {
        current.push(component.as_os_str());
        if matches!(component, Component::Prefix(_) | Component::RootDir) {
            continue;
        }
        let metadata = match fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(storage_error("inspect ZK repository path component", error)),
        };
        if metadata.file_type().is_symlink() {
            return Err(ApiError::Unavailable(format!(
                "ZK repository refuses symbolic-link path component {}",
                current.display()
            )));
        }
        let is_final = index + 1 == components.len();
        if !metadata.is_dir() && !(is_final && final_may_be_file && metadata.is_file()) {
            return Err(ApiError::Unavailable(format!(
                "ZK repository path has a non-directory intermediate component {}",
                current.display()
            )));
        }
    }
    Ok(())
}

fn ensure_path_components(
    root: &FsPath,
    target: &FsPath,
    final_may_be_file: bool,
) -> Result<(), ApiError> {
    if !root.is_absolute() || !target.starts_with(root) {
        return Err(ApiError::Unavailable(
            "ZK repository path escaped its configured root".to_owned(),
        ));
    }
    ensure_existing_components(root, false)?;
    ensure_existing_components(target, final_may_be_file)
}

fn create_safe_dir_all(root: &FsPath, target: &FsPath) -> Result<(), ApiError> {
    if !target.starts_with(root) {
        return Err(ApiError::Unavailable(
            "ZK repository directory escaped its configured root".to_owned(),
        ));
    }
    ensure_existing_components(root, false)?;
    fs::create_dir_all(root).map_err(|e| storage_error("create ZK repository root", e))?;
    ensure_path_components(root, root, false)?;
    let relative = target.strip_prefix(root).map_err(|_| {
        ApiError::Unavailable("ZK repository directory escaped its root".to_owned())
    })?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        if !matches!(component, Component::Normal(_)) {
            return Err(ApiError::Unavailable(
                "ZK repository directory contains an unsafe component".to_owned(),
            ));
        }
        current.push(component.as_os_str());
        if current.exists() {
            ensure_no_symlink(&current)?;
            if !current.is_dir() {
                return Err(ApiError::Unavailable(
                    "ZK repository directory path is occupied by a non-directory".to_owned(),
                ));
            }
        } else {
            fs::create_dir(&current)
                .map_err(|e| storage_error("create ZK repository directory", e))?;
            sync_parent(&current)?;
        }
    }
    Ok(())
}

fn ensure_store_dirs(root: &FsPath) -> Result<(), ApiError> {
    create_safe_dir_all(root, &root.join(OBJECTS_DIR))?;
    create_safe_dir_all(root, &root.join(UPLOADS_DIR))?;
    create_safe_dir_all(root, &root.join(STAGING_DIR))?;
    Ok(())
}

fn write_new_synced(path: &FsPath, bytes: &[u8]) -> Result<(), ApiError> {
    let parent = path
        .parent()
        .ok_or_else(|| ApiError::Internal("ZK storage path has no parent".to_owned()))?;
    ensure_existing_components(parent, false)?;
    fs::create_dir_all(parent).map_err(|e| storage_error("create ZK storage directory", e))?;
    ensure_existing_components(parent, false)?;
    ensure_existing_components(path, true)?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|e| storage_error("create immutable ZK storage file", e))?;
    if let Err(e) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(storage_error("write and sync ZK storage file", e));
    }
    sync_dir(parent)
}

fn write_atomic_synced(path: &FsPath, bytes: &[u8]) -> Result<(), ApiError> {
    let parent = path
        .parent()
        .ok_or_else(|| ApiError::Internal("ZK index path has no parent".to_owned()))?;
    ensure_existing_components(parent, false)?;
    fs::create_dir_all(parent).map_err(|e| storage_error("create ZK index directory", e))?;
    ensure_existing_components(parent, false)?;
    ensure_existing_components(path, true)?;
    let tmp = parent.join(format!(".{}.{}.tmp", INDEX_FILE, Uuid::new_v4()));
    write_new_synced(&tmp, bytes)?;

    #[cfg(not(windows))]
    {
        if let Err(e) = fs::rename(&tmp, path) {
            let _ = fs::remove_file(&tmp);
            return Err(storage_error("atomically replace ZK repository index", e));
        }
    }

    #[cfg(windows)]
    {
        let backup = parent.join(INDEX_BACKUP_FILE);
        if backup.exists() {
            fs::remove_file(&backup)
                .map_err(|e| storage_error("remove stale ZK index backup", e))?;
        }
        if path.exists() {
            fs::rename(path, &backup)
                .map_err(|e| storage_error("stage existing ZK repository index", e))?;
        }
        if let Err(e) = fs::rename(&tmp, path) {
            let _ = if backup.exists() {
                fs::rename(&backup, path)
            } else {
                Ok(())
            };
            let _ = fs::remove_file(&tmp);
            return Err(storage_error("publish replacement ZK repository index", e));
        }
        if backup.exists() {
            fs::remove_file(&backup)
                .map_err(|e| storage_error("remove committed ZK index backup", e))?;
        }
    }

    sync_dir(parent)
}

fn recover_interrupted_index_replace(root: &FsPath) -> Result<(), ApiError> {
    let index = root.join(INDEX_FILE);
    let backup = root.join(INDEX_BACKUP_FILE);
    ensure_path_components(root, &index, true)?;
    ensure_path_components(root, &backup, true)?;
    if !index.exists() && backup.exists() {
        fs::rename(&backup, &index)
            .map_err(|e| storage_error("recover interrupted ZK index replacement", e))?;
        sync_dir(root)?;
    } else if index.exists() && backup.exists() {
        fs::remove_file(&backup)
            .map_err(|e| storage_error("remove stale committed ZK index backup", e))?;
        sync_dir(root)?;
    }
    Ok(())
}

fn load_index_and_reconcile(root: &FsPath) -> Result<ZkRepositoryIndex, String> {
    if !root.exists() {
        return Ok(ZkRepositoryIndex::default());
    }
    validate_object_root_path(root).map_err(api_error_message)?;
    recover_interrupted_index_replace(root).map_err(api_error_message)?;
    let index_path = root.join(INDEX_FILE);
    let mut index = if index_path.exists() {
        ensure_no_symlink(&index_path).map_err(api_error_message)?;
        let bytes = read_bounded(&index_path, 16 * 1024 * 1024).map_err(api_error_message)?;
        serde_json::from_slice::<ZkRepositoryIndex>(&bytes)
            .map_err(|e| format!("ZK repository index is malformed: {e}"))?
    } else {
        ZkRepositoryIndex::default()
    };
    sort_index(&mut index);
    validate_index_structure(&index).map_err(api_error_message)?;
    validate_committed_blobs(root, &index).map_err(api_error_message)?;
    reconcile_orphans(root, &index).map_err(api_error_message)?;
    reconcile_pending_uploads(root, &index).map_err(api_error_message)?;
    Ok(index)
}

fn validate_index_structure(index: &ZkRepositoryIndex) -> Result<(), ApiError> {
    if index.schema_version != INDEX_SCHEMA_VERSION {
        return Err(ApiError::Unavailable(format!(
            "unsupported ZK repository index schema {}",
            index.schema_version
        )));
    }
    let mut tenant_ids = HashSet::new();
    for policy in &index.tenant_policies {
        policy.validate()?;
        if !tenant_ids.insert(policy.tenant_id) {
            return Err(ApiError::Unavailable(
                "duplicate tenant repository policy in durable index".to_owned(),
            ));
        }
    }
    let mut repository_ids = HashSet::new();
    let mut repository_names = HashSet::new();
    for record in &index.repositories {
        record.policy.validate().map_err(contract_error)?;
        if !repository_ids.insert(record.policy.repository_id) {
            return Err(ApiError::Unavailable(
                "duplicate repository id in durable index".to_owned(),
            ));
        }
        if !repository_names.insert((
            record.policy.tenant_id,
            record.policy.name.trim().to_lowercase(),
        )) {
            return Err(ApiError::Unavailable(
                "duplicate repository name in durable index".to_owned(),
            ));
        }
        if record.policy_source == RepositoryPolicySource::Tenant {
            let inherited = index
                .tenant_policies
                .iter()
                .find(|policy| policy.tenant_id == record.policy.tenant_id)
                .ok_or_else(|| {
                    ApiError::Unavailable(
                        "repository references an absent inherited tenant policy".to_owned(),
                    )
                })?;
            let expected = policy_from_tenant(
                record.policy.repository_id,
                record.policy.name.clone(),
                inherited,
                record.policy.created_at,
            );
            if expected.encryption_mode != record.policy.encryption_mode
                || expected.zk_scope != record.policy.zk_scope
                || expected.custody != record.policy.custody
                || expected.gdpr_obligations_remain != record.policy.gdpr_obligations_remain
            {
                return Err(ApiError::Unavailable(
                    "repository drifted from its inherited tenant policy".to_owned(),
                ));
            }
        }
    }
    let mut keys = HashSet::new();
    let mut archives = HashSet::new();
    for version in &index.object_versions {
        version.manifest.validate().map_err(contract_error)?;
        let ad = version.manifest.associated_data;
        let repository = index
            .repositories
            .iter()
            .find(|record| record.policy.repository_id == ad.repository_id)
            .ok_or_else(|| {
                ApiError::Unavailable("object version references an absent repository".to_owned())
            })?;
        if repository.policy.tenant_id != version.tenant_id {
            return Err(ApiError::Unavailable(
                "object version tenant does not match its repository".to_owned(),
            ));
        }
        if !keys.insert((ad.repository_id, ad.object_id, ad.version)) {
            return Err(ApiError::Unavailable(
                "duplicate immutable object version in durable index".to_owned(),
            ));
        }
        if !archives.insert(version.archive_id) {
            return Err(ApiError::Unavailable(
                "duplicate archive scope id in durable index".to_owned(),
            ));
        }
        let expected = blob_relative_path(ad.repository_id, ad.object_id, ad.version);
        if version.blob_relative_path != expected {
            return Err(ApiError::Unavailable(
                "object version has a non-canonical blob path".to_owned(),
            ));
        }
    }
    // A key reference can intentionally be reused across repositories (for example, one tenant
    // BYOK root wrapping several repository CEKs). AES-GCM nonce reuse is unsafe for the same key
    // regardless of repository/AAD boundaries, so enforce the nonce+key-reference invariant over
    // the complete durable index rather than only within one repository.
    let manifests = index
        .object_versions
        .iter()
        .map(|version| &version.manifest)
        .collect::<Vec<_>>();
    for (offset, manifest) in manifests.iter().enumerate() {
        ensure_nonce_is_unique(manifest, manifests.iter().take(offset).copied())
            .map_err(|e| ApiError::Unavailable(format!("durable nonce invariant failed: {e}")))?;
    }
    Ok(())
}

fn validate_committed_blobs(root: &FsPath, index: &ZkRepositoryIndex) -> Result<(), ApiError> {
    for version in &index.object_versions {
        let path = safe_join(root, &version.blob_relative_path)?;
        if !path.is_file() {
            return Err(ApiError::Unavailable(format!(
                "committed ZK ciphertext is missing: {}",
                version.blob_relative_path
            )));
        }
        ensure_no_symlink(&path)?;
        let bytes = read_bounded(&path, ZK_BLOB_MAX_BYTES)?;
        version.manifest.verify_ciphertext(&bytes).map_err(|e| {
            ApiError::Unavailable(format!(
                "committed ZK ciphertext failed length/digest verification: {e}"
            ))
        })?;
    }
    Ok(())
}

fn reconcile_orphans(root: &FsPath, index: &ZkRepositoryIndex) -> Result<(), ApiError> {
    let referenced = index
        .object_versions
        .iter()
        .map(|value| value.blob_relative_path.clone())
        .collect::<HashSet<_>>();
    let objects = root.join(OBJECTS_DIR);
    if objects.exists() {
        walk_files(&objects, &mut |path| {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| ApiError::Unavailable("orphan path escaped ZK root".to_owned()))?
                .to_string_lossy()
                .replace('\\', "/");
            if !referenced.contains(&relative) {
                fs::remove_file(path)
                    .map_err(|e| storage_error("remove unreferenced ZK blob", e))?;
            }
            Ok(())
        })?;
    }
    let staging = root.join(STAGING_DIR);
    if staging.exists() {
        walk_files(&staging, &mut |path| {
            fs::remove_file(path).map_err(|e| storage_error("remove crashed ZK staging file", e))
        })?;
    }
    Ok(())
}

fn reconcile_pending_uploads(root: &FsPath, index: &ZkRepositoryIndex) -> Result<(), ApiError> {
    let uploads = root.join(UPLOADS_DIR);
    if !uploads.exists() {
        return Ok(());
    }
    walk_files(&uploads, &mut |path| {
        let pending = match read_pending(path) {
            Ok(pending) => pending,
            Err(_) => {
                fs::remove_file(path)
                    .map_err(|e| storage_error("remove malformed pending ZK upload", e))?;
                return Ok(());
            }
        };
        let ad = pending.manifest.associated_data;
        if index.object_versions.iter().any(|version| {
            version.manifest.associated_data.repository_id == ad.repository_id
                && version.manifest.associated_data.object_id == ad.object_id
                && version.manifest.associated_data.version == ad.version
        }) {
            fs::remove_file(path)
                .map_err(|e| storage_error("remove already-committed pending ZK upload", e))?;
        }
        Ok(())
    })
}

fn read_pending(path: &FsPath) -> Result<PendingUpload, ApiError> {
    if !path.is_file() {
        return Err(ApiError::NotFound);
    }
    ensure_no_symlink(path)?;
    let bytes = read_bounded(path, 2 * 1024 * 1024)?;
    let pending: PendingUpload = serde_json::from_slice(&bytes)
        .map_err(|_| ApiError::Unprocessable("pending ZK upload is malformed".to_owned()))?;
    if pending.schema_version != PENDING_UPLOAD_SCHEMA_VERSION
        || pending_path(
            path.parent()
                .and_then(FsPath::parent)
                .unwrap_or(FsPath::new("")),
            pending.upload_id,
        )
        .file_name()
            != path.file_name()
    {
        return Err(ApiError::Unprocessable(
            "pending ZK upload identity/schema mismatch".to_owned(),
        ));
    }
    pending.manifest.validate().map_err(contract_error)?;
    Ok(pending)
}

fn read_bounded(path: &FsPath, max: usize) -> Result<Vec<u8>, ApiError> {
    let metadata = fs::metadata(path).map_err(|e| storage_error("inspect ZK storage file", e))?;
    if metadata.len() > max as u64 {
        return Err(ApiError::Unavailable(format!(
            "ZK storage file exceeds its {max}-byte bound"
        )));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)
        .and_then(|mut file| file.read_to_end(&mut bytes))
        .map_err(|e| storage_error("read ZK storage file", e))?;
    if bytes.len() > max {
        return Err(ApiError::Unavailable(format!(
            "ZK storage file exceeds its {max}-byte bound"
        )));
    }
    Ok(bytes)
}

fn walk_files(
    root: &FsPath,
    action: &mut impl FnMut(&FsPath) -> Result<(), ApiError>,
) -> Result<(), ApiError> {
    ensure_no_symlink(root)?;
    for entry in fs::read_dir(root).map_err(|e| storage_error("list ZK storage directory", e))? {
        let entry = entry.map_err(|e| storage_error("read ZK storage directory entry", e))?;
        let file_type = entry
            .file_type()
            .map_err(|e| storage_error("inspect ZK storage entry", e))?;
        let path = entry.path();
        if file_type.is_symlink() {
            return Err(ApiError::Unavailable(format!(
                "ZK repository refuses symbolic-link storage entry {}",
                path.display()
            )));
        } else if file_type.is_dir() {
            walk_files(&path, action)?;
        } else if file_type.is_file() {
            action(&path)?;
        }
    }
    Ok(())
}

/// Validate the complete existing object-root tree before backup, restore, wipe, or startup
/// reconciliation. Missing roots are valid (there is simply no ZK sidecar to include).
pub(crate) fn validate_object_root_path(root: &FsPath) -> Result<(), ApiError> {
    let root = normalized_absolute(root).map_err(ApiError::Unavailable)?;
    ensure_existing_components(&root, false)?;
    if root.exists() {
        walk_files(&root, &mut |_path| Ok(()))?;
    }
    Ok(())
}

fn sort_index(index: &mut ZkRepositoryIndex) {
    index.tenant_policies.sort_by_key(|policy| policy.tenant_id);
    index
        .repositories
        .sort_by_key(|record| (record.policy.tenant_id, record.policy.repository_id));
    index.object_versions.sort_by_key(|record| {
        let ad = record.manifest.associated_data;
        (ad.repository_id, ad.object_id, ad.version)
    });
}

fn storage_error(context: &str, error: std::io::Error) -> ApiError {
    ApiError::Internal(format!("{context}: {error}"))
}

fn api_error_message(error: ApiError) -> String {
    match error {
        ApiError::Unavailable(message)
        | ApiError::Unprocessable(message)
        | ApiError::Internal(message)
        | ApiError::Conflict(message) => message,
        _ => "zero-knowledge repository storage validation failed".to_owned(),
    }
}

#[cfg(unix)]
fn sync_dir(path: &FsPath) -> Result<(), ApiError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|e| storage_error("sync ZK storage directory", e))
}

#[cfg(not(unix))]
fn sync_dir(_path: &FsPath) -> Result<(), ApiError> {
    // Windows does not let stable `std::fs::File::open` obtain a directory handle. Every file is
    // still `sync_all`'d before rename; directory fsync is performed on platforms that support it.
    Ok(())
}

fn sync_parent(path: &FsPath) -> Result<(), ApiError> {
    match path.parent() {
        Some(parent) if parent.exists() => sync_dir(parent),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::http::{Method, Request};
    use chancela_archive::LegalArchiveReadabilityMode;
    use chancela_authz::{OWNER_ROLE_ID, RoleAssignment, RoleCatalog};
    use chancela_core::{Book, BookKind, DEFAULT_TENANT_ID, Entity, EntityKind, Nipc, Tenant};
    use chancela_zk::{
        AssociatedData, ContentEncryptionAlgorithm, KeyRecipientKind, KeySlotId,
        KeyWrappingAlgorithm, WrappedContentEncryptionKey,
    };
    use tower::ServiceExt;
    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> std::io::Result<Self> {
            let path = std::env::temp_dir().join(format!("chancela-zk-test-{}", Uuid::new_v4()));
            fs::create_dir_all(&path)?;
            Ok(Self(path))
        }

        fn path(&self) -> &FsPath {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn custody() -> KeyCustodyPolicy {
        KeyCustodyPolicy {
            bring_your_own_key: true,
            webauthn_prf_unsealing: false,
            split_key_recovery: None,
        }
    }

    fn manifest(
        repository_id: RepositoryId,
        object_id: ObjectId,
        version: u64,
        nonce_byte: u8,
        bytes: &[u8],
    ) -> OpaqueBlobManifest {
        OpaqueBlobManifest {
            schema_version: chancela_zk::MANIFEST_SCHEMA_VERSION,
            associated_data: AssociatedData {
                repository_id,
                object_id,
                version,
            },
            algorithm: ContentEncryptionAlgorithm::Aes256Gcm,
            nonce_base64: BASE64.encode([nonce_byte; 12]),
            ciphertext_sha256: format!("{:x}", Sha256::digest(bytes)),
            ciphertext_len: bytes.len() as u64,
            encrypted_metadata: None,
            wrapped_keys: vec![WrappedContentEncryptionKey {
                slot_id: KeySlotId::new(),
                recipient_kind: KeyRecipientKind::BringYourOwnKey,
                recipient_id: "owner".to_owned(),
                algorithm: KeyWrappingAlgorithm::Aes256KwByok,
                key_reference: "byok-key-1".to_owned(),
                wrapped_cek_base64: BASE64.encode([7_u8; 40]),
                created_at: OffsetDateTime::now_utc(),
            }],
            created_at: OffsetDateTime::now_utc(),
        }
    }

    fn store_with_repository(temp: &TempDir) -> (ZkRepositoryStore, Uuid, RepositoryId) {
        let tenant = Uuid::new_v4();
        let repository_id = RepositoryId::new();
        let mut store = ZkRepositoryStore::open(temp.path(), false);
        let now = OffsetDateTime::now_utc();
        let record = StoredRepositoryPolicy {
            policy: explicit_policy(
                repository_id,
                tenant,
                "Encrypted evidence".to_owned(),
                RepositoryEncryptionMode::ZeroKnowledge,
                custody(),
                true,
                (now, now),
            ),
            policy_source: RepositoryPolicySource::Repository,
        };
        let mut next = store.index.clone();
        next.repositories.push(record);
        store.persist_index(next).expect("persist repository");
        (store, tenant, repository_id)
    }

    async fn token_for_scope(state: &AppState, username: &str, scope: Scope) -> String {
        use crate::users::{User, UserId};
        use time::format_description::well_known::Rfc3339;

        if state.roles.read().await.is_empty() {
            *state.roles.write().await = RoleCatalog::seeded_defaults();
        }
        let user_id = UserId(Uuid::new_v4());
        state.users.write().await.insert(
            user_id,
            User {
                id: user_id,
                username: username.to_owned(),
                display_name: username.to_owned(),
                email: None,
                created_at: OffsetDateTime::now_utc()
                    .format(&Rfc3339)
                    .unwrap_or_default(),
                active: true,
                password_hash: Some(crate::attestation::hash_secret("Zk-Teste-Forte7!").unwrap()),
                attestation_key: None,
                secret_source: Default::default(),
                recovery_hash: None,
                role_assignments: vec![RoleAssignment::new(OWNER_ROLE_ID, scope)],
            },
        );
        let token = Uuid::new_v4().to_string();
        state.sessions.write().await.insert(
            token.clone(),
            crate::session::SessionEntry {
                user_id,
                unlocked_key: None,
                expires_at: OffsetDateTime::now_utc()
                    + time::Duration::seconds(crate::actor::SESSION_TTL_SECS),
            },
        );
        token
    }

    fn json_request(
        method: Method,
        uri: &str,
        token: &str,
        body: serde_json::Value,
    ) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header("x-chancela-session", token)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    fn raw_request(
        method: Method,
        uri: &str,
        token: &str,
        content_type: &str,
        body: &[u8],
    ) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header("x-chancela-session", token)
            .header(CONTENT_TYPE, content_type)
            .body(Body::from(body.to_vec()))
            .unwrap()
    }

    async fn send(state: AppState, request: Request<Body>) -> (StatusCode, Bytes) {
        let response = crate::router(state).oneshot(request).await.unwrap();
        let status = response.status();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        (status, body)
    }

    #[test]
    fn immutable_ciphertext_survives_restart_and_tamper_fails_closed() {
        let temp = TempDir::new().unwrap();
        let (mut store, tenant, repository_id) = store_with_repository(&temp);
        let object_id = ObjectId::new();
        let bytes = b"opaque AES-GCM ciphertext plus tag";
        let pending = store
            .create_upload(
                tenant,
                repository_id,
                manifest(repository_id, object_id, 1, 1, bytes),
            )
            .unwrap();
        let (committed, _) = store
            .commit_upload(tenant, repository_id, pending.upload_id, bytes)
            .unwrap();
        let reopened = ZkRepositoryStore::open(temp.path(), false);
        assert!(matches!(
            reopened.availability,
            RepositoryStoreAvailability::Ready
        ));
        assert_eq!(reopened.read_ciphertext(&committed).unwrap(), bytes);

        let blob = safe_join(
            reopened.root.as_deref().unwrap(),
            &committed.blob_relative_path,
        )
        .unwrap();
        fs::write(blob, b"tampered same-ish bytes").unwrap();
        let failed = ZkRepositoryStore::open(temp.path(), false);
        assert!(matches!(
            failed.availability,
            RepositoryStoreAvailability::FailClosed(_)
        ));
    }

    #[test]
    fn digest_length_nonce_reuse_and_version_rewrite_are_rejected() {
        let temp = TempDir::new().unwrap();
        let (mut store, tenant, repository_id) = store_with_repository(&temp);
        let object = ObjectId::new();
        let bytes = b"ciphertext-1";
        let pending = store
            .create_upload(
                tenant,
                repository_id,
                manifest(repository_id, object, 1, 2, bytes),
            )
            .unwrap();
        assert!(
            store
                .commit_upload(tenant, repository_id, pending.upload_id, b"wrong")
                .is_err()
        );
        store
            .commit_upload(tenant, repository_id, pending.upload_id, bytes)
            .unwrap();
        assert!(
            store
                .create_upload(
                    tenant,
                    repository_id,
                    manifest(repository_id, object, 1, 3, bytes),
                )
                .is_err(),
            "an immutable version cannot be rewritten"
        );
        assert!(
            store
                .create_upload(
                    tenant,
                    repository_id,
                    manifest(repository_id, object, 2, 2, b"ciphertext-2"),
                )
                .is_err(),
            "same nonce plus same key reference is refused"
        );
    }

    #[test]
    fn nonce_reuse_is_rejected_across_repository_boundaries_for_the_same_key_reference() {
        let temp = TempDir::new().unwrap();
        let (mut store, tenant, first_repository) = store_with_repository(&temp);
        let now = OffsetDateTime::now_utc();
        let second_repository = RepositoryId::new();
        let mut next = store.index.clone();
        next.repositories.push(StoredRepositoryPolicy {
            policy: explicit_policy(
                second_repository,
                tenant,
                "Second encrypted evidence repository".to_owned(),
                RepositoryEncryptionMode::ZeroKnowledge,
                custody(),
                true,
                (now, now),
            ),
            policy_source: RepositoryPolicySource::Repository,
        });
        store.persist_index(next).unwrap();

        let first_bytes = b"first repository ciphertext";
        let first = store
            .create_upload(
                tenant,
                first_repository,
                manifest(first_repository, ObjectId::new(), 1, 9, first_bytes),
            )
            .unwrap();
        store
            .commit_upload(tenant, first_repository, first.upload_id, first_bytes)
            .unwrap();

        let error = store
            .create_upload(
                tenant,
                second_repository,
                manifest(
                    second_repository,
                    ObjectId::new(),
                    1,
                    9,
                    b"second repository ciphertext",
                ),
            )
            .expect_err(
                "the same AES-GCM nonce/key reference must be global, not repository-local",
            );
        assert!(matches!(error, ApiError::Conflict(_)));
    }

    #[test]
    fn startup_removes_crash_orphan_but_preserves_referenced_blob() {
        let temp = TempDir::new().unwrap();
        let (mut store, tenant, repository_id) = store_with_repository(&temp);
        let bytes = b"committed ciphertext";
        let pending = store
            .create_upload(
                tenant,
                repository_id,
                manifest(repository_id, ObjectId::new(), 1, 4, bytes),
            )
            .unwrap();
        let (committed, _) = store
            .commit_upload(tenant, repository_id, pending.upload_id, bytes)
            .unwrap();
        let root = store.root.as_deref().unwrap();
        let orphan = root
            .join(OBJECTS_DIR)
            .join(repository_id.to_string())
            .join(ObjectId::new().to_string())
            .join("1.bin");
        fs::create_dir_all(orphan.parent().unwrap()).unwrap();
        fs::write(&orphan, b"crash orphan").unwrap();
        let reopened = ZkRepositoryStore::open(temp.path(), false);
        assert!(!orphan.exists());
        assert_eq!(reopened.read_ciphertext(&committed).unwrap(), bytes);
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn intermediate_directory_symlink_is_rejected_before_blob_publish() {
        let temp = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let (mut store, tenant, repository_id) = store_with_repository(&temp);
        let bytes = b"opaque ciphertext";
        let pending = store
            .create_upload(
                tenant,
                repository_id,
                manifest(repository_id, ObjectId::new(), 1, 9, bytes),
            )
            .unwrap();
        let root = store.root.as_deref().unwrap();
        let repository_dir = root.join(OBJECTS_DIR).join(repository_id.to_string());

        #[cfg(unix)]
        std::os::unix::fs::symlink(outside.path(), &repository_dir).unwrap();
        #[cfg(windows)]
        if let Err(error) = std::os::windows::fs::symlink_dir(outside.path(), &repository_dir) {
            // Creating a Windows symlink can require Developer Mode/elevation. Linux CI executes
            // the mandatory path; on restricted Windows hosts, avoid turning an OS privilege into
            // a product-test failure.
            eprintln!("skipping Windows symlink assertion: {error}");
            return;
        }

        let error = store
            .commit_upload(tenant, repository_id, pending.upload_id, bytes)
            .expect_err("intermediate symlink must fail closed");
        assert!(matches!(error, ApiError::Unavailable(_)));
        assert_eq!(
            fs::read_dir(outside.path()).unwrap().count(),
            0,
            "no ciphertext may be written through the symlink"
        );
    }

    #[test]
    fn strict_wire_types_reject_plaintext_key_and_recovery_fields() {
        let temp = TempDir::new().unwrap();
        let (_, _, repository_id) = store_with_repository(&temp);
        let raw = serde_json::json!({
            "manifest": {
                "schema_version": 1,
                "associated_data": {
                    "repository_id": repository_id,
                    "object_id": ObjectId::new(),
                    "version": 1
                },
                "algorithm": "aes256_gcm",
                "nonce_base64": BASE64.encode([1_u8; 12]),
                "ciphertext_sha256": "a".repeat(64),
                "ciphertext_len": 10,
                "encrypted_metadata": null,
                "wrapped_keys": [],
                "created_at": "2026-07-16T00:00:00Z",
                "plaintext": "never",
                "cek": "never",
                "private_key": "never",
                "recovery_share": "never"
            }
        });
        assert!(serde_json::from_value::<CreateUploadBody>(raw).is_err());
    }

    #[test]
    fn ha_without_explicit_shared_root_is_hard_fail_closed() {
        let temp = TempDir::new().unwrap();
        let store = ZkRepositoryStore::open_with_shared_root(temp.path(), true, None);
        assert!(matches!(
            store.availability,
            RepositoryStoreAvailability::FailClosed(_)
        ));
        assert!(matches!(store.ready_root(), Err(ApiError::Unavailable(_))));
    }

    #[test]
    fn compensating_rollback_restores_pending_manifest_and_removes_blob() {
        let temp = TempDir::new().unwrap();
        let (mut store, tenant, repository_id) = store_with_repository(&temp);
        let previous = store.index.clone();
        let bytes = b"rollback ciphertext";
        let pending = store
            .create_upload(
                tenant,
                repository_id,
                manifest(repository_id, ObjectId::new(), 1, 11, bytes),
            )
            .unwrap();
        let (stored, pending) = store
            .commit_upload(tenant, repository_id, pending.upload_id, bytes)
            .unwrap();
        let blob = safe_join(store.root.as_deref().unwrap(), &stored.blob_relative_path).unwrap();
        assert!(blob.is_file());
        store
            .rollback_committed_upload(previous, &stored, &pending)
            .unwrap();
        assert!(!blob.exists());
        assert!(pending_path(store.root.as_deref().unwrap(), pending.upload_id).is_file());
        assert!(store.index.object_versions.is_empty());
    }

    #[test]
    fn audit_metadata_never_contains_wrapped_key_or_plaintext_material() {
        let repository_id = RepositoryId::new();
        let wrapped_secret = BASE64.encode([7_u8; 40]);
        let mut manifest = manifest(repository_id, ObjectId::new(), 1, 12, b"opaque ciphertext");
        manifest.wrapped_keys[0].wrapped_cek_base64 = wrapped_secret.clone();
        let rendered = manifest_audit_metadata(&manifest).to_string();
        assert!(!rendered.contains(&wrapped_secret));
        for forbidden in [
            "wrapped_cek_base64",
            "plaintext",
            "private_key",
            "recovery_share",
        ] {
            assert!(!rendered.contains(forbidden));
        }
        assert!(rendered.contains("ciphertext_sha256"));
        assert!(rendered.contains("wrapped_key_slot_count"));
    }

    #[tokio::test]
    async fn routes_are_tenant_safe_audited_content_typed_and_backup_restorable() {
        let temp = TempDir::new().unwrap();
        let state = AppState::with_data_dir(temp.path());
        let tenant = DEFAULT_TENANT_ID.0;
        let owner = token_for_scope(&state, "zk.owner", Scope::Global).await;
        let repositories_uri = format!("/v1/tenants/{tenant}/repositories");
        let (status, body) = send(
            state.clone(),
            json_request(
                Method::POST,
                &repositories_uri,
                &owner,
                serde_json::json!({
                    "name": "Encrypted evidence",
                    "inherit_tenant_policy": false,
                    "encryption_mode": "zero_knowledge",
                    "custody": {
                        "bring_your_own_key": true,
                        "webauthn_prf_unsealing": false,
                        "split_key_recovery": null
                    },
                    "gdpr_obligations_remain": true
                }),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "{}",
            String::from_utf8_lossy(&body)
        );
        let repository: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let repository_id = RepositoryId(
            Uuid::parse_str(repository["policy"]["repository_id"].as_str().unwrap()).unwrap(),
        );

        let ciphertext = b"opaque route ciphertext";
        let object_id = ObjectId::new();
        let object_manifest = manifest(repository_id, object_id, 1, 21, ciphertext);
        let uploads_uri = format!("{repositories_uri}/{repository_id}/uploads");
        let mut forbidden_outer = serde_json::json!({"manifest": object_manifest.clone()});
        forbidden_outer.as_object_mut().unwrap().insert(
            "plaintext".to_owned(),
            serde_json::json!("must be rejected"),
        );
        let (status, _) = send(
            state.clone(),
            json_request(Method::POST, &uploads_uri, &owner, forbidden_outer),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        let (status, body) = send(
            state.clone(),
            json_request(
                Method::POST,
                &uploads_uri,
                &owner,
                serde_json::json!({"manifest": object_manifest}),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "{}",
            String::from_utf8_lossy(&body)
        );
        let upload: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let upload_uri = upload["ciphertext_upload_url"].as_str().unwrap();

        let (status, _) = send(
            state.clone(),
            raw_request(Method::PUT, upload_uri, &owner, "text/plain", ciphertext),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        let (status, body) = send(
            state.clone(),
            raw_request(
                Method::PUT,
                upload_uri,
                &owner,
                "application/octet-stream",
                ciphertext,
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "{}",
            String::from_utf8_lossy(&body)
        );
        let committed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let ciphertext_uri = committed["ciphertext_url"].as_str().unwrap();
        let manifest_uri = ciphertext_uri.replace("/ciphertext", "/manifest");

        let entity = Entity::new(
            "ZK Evidence Company",
            Nipc::parse("503004642").unwrap(),
            "Lisboa",
            EntityKind::SociedadePorQuotas,
        )
        .in_tenant(TenantId(tenant));
        let book = Book::new(entity.id, BookKind::AssembleiaGeral);
        state
            .entities
            .write()
            .await
            .insert(entity.id, entity.clone());
        state.books.write().await.insert(book.id, book.clone());

        let mut trusted_input = PackageBuildInput::new(
            Uuid::new_v4(),
            OffsetDateTime::now_utc(),
            entity.id.0,
            book.id.0,
        );
        trusted_input.languages = vec!["pt-PT".to_owned()];
        let document_id = Uuid::new_v4();
        trusted_input.files = vec![
            PackageFileInput::pdfa_document(document_id, None, b"%PDF-1.7\n%PDF-A fixture\n"),
            PackageFileInput::evidence_report(document_id, br#"{"status":"client-verified"}"#),
        ];
        let trusted_archive = build_archive_package(trusted_input).unwrap().bytes;
        let readability_uri = ciphertext_uri.replace("/ciphertext", "/readability-package");
        let (status, client_readability) = send(
            state.clone(),
            json_request(
                Method::POST,
                &readability_uri,
                &owner,
                serde_json::json!({
                    "mode": "client_decrypted_archive",
                    "book_id": book.id,
                    "archive_base64": BASE64.encode(&trusted_archive),
                    "archive_sha256": format!("{:x}", Sha256::digest(&trusted_archive)),
                    "reauth": {"password": "Zk-Teste-Forte7!"}
                }),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "{}",
            String::from_utf8_lossy(&client_readability)
        );
        let client_manifest = validate_package(&client_readability).unwrap();
        assert_eq!(
            client_manifest
                .preservation_interchange
                .readability_caveats
                .legal_archive_readability_mode,
            LegalArchiveReadabilityMode::ClientDecryptedTransfer
        );
        assert!(
            !client_manifest
                .preservation_interchange
                .readability_caveats
                .legal_archive_certified
        );
        assert!(
            !client_manifest
                .preservation_interchange
                .readability_caveats
                .zk_removes_gdpr_obligations
        );

        let (status, encrypted_readability) = send(
            state.clone(),
            json_request(
                Method::POST,
                &readability_uri,
                &owner,
                serde_json::json!({
                    "mode": "encrypted_archive_with_portable_key_package",
                    "book_id": book.id,
                    "portable_key_package_jwe": "e30.eA.eA.eA.eA",
                    "recipient_instructions": "Obtain the recipient private key through the separately authenticated custody channel.",
                    "reauth": {"password": "Zk-Teste-Forte7!"}
                }),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "{}",
            String::from_utf8_lossy(&encrypted_readability)
        );
        let encrypted_manifest = validate_package(&encrypted_readability).unwrap();
        let caveats = encrypted_manifest
            .preservation_interchange
            .readability_caveats;
        assert_eq!(
            caveats.legal_archive_readability_mode,
            LegalArchiveReadabilityMode::EncryptedTransferWithPortableKeyPackage
        );
        assert!(caveats.decryption_material_included);
        assert!(!caveats.external_import_verified);
        assert!(!caveats.legal_archive_certified);

        let tenant_b = Tenant::new("Tenant B");
        state
            .tenants
            .write()
            .await
            .insert(tenant_b.id, tenant_b.clone());
        let tenant_b_owner =
            token_for_scope(&state, "tenant.b", scope_of_tenant(tenant_b.id)).await;
        let (status, _) = send(
            state.clone(),
            Request::builder()
                .uri(&manifest_uri)
                .header("x-chancela-session", tenant_b_owner)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let kinds = state
            .ledger
            .read()
            .await
            .events()
            .iter()
            .map(|event| event.kind.clone())
            .collect::<Vec<_>>();
        assert!(kinds.iter().any(|kind| kind == "zk.repository.created"));
        assert!(kinds.iter().any(|kind| kind == "zk.manifest.registered"));
        assert!(kinds.iter().any(|kind| kind == "zk.ciphertext.committed"));
        assert_eq!(
            kinds
                .iter()
                .filter(|kind| kind.as_str() == "zk.readability.exported")
                .count(),
            2,
            "both trusted-client readability modes are audited"
        );
        assert_eq!(
            kinds
                .iter()
                .filter(|kind| kind.as_str() == "zk.manifest.registered")
                .count(),
            1,
            "rejected unknown fields must not be audited as a successful registration"
        );

        let store = state.store.clone().expect("data-dir store");
        let sidecars = state.instance_sidecars().unwrap();
        let backup = store.backup(temp.path(), &sidecars).unwrap();
        assert!(
            backup
                .files
                .iter()
                .any(|file| file.name.replace('\\', "/") == "zk-repositories/index.json")
        );
        assert!(backup.files.iter().any(|file| {
            file.name
                .replace('\\', "/")
                .starts_with("zk-repositories/objects/")
        }));

        fs::remove_dir_all(temp.path().join(ZK_REPOSITORY_DIR)).unwrap();
        {
            let mut ledger = state.ledger.write().await;
            store
                .restore_with_sidecars(
                    &mut ledger,
                    FsPath::new(&backup.path),
                    temp.path(),
                    "zk.restore.test",
                    OffsetDateTime::now_utc(),
                    &sidecars,
                )
                .unwrap();
        }
        state.zk_repositories.write().await.reload().unwrap();
        let restarted = AppState::with_data_dir(temp.path());
        let restarted_owner = token_for_scope(&restarted, "zk.restart", Scope::Global).await;
        let (status, restored_ciphertext) = send(
            restarted,
            Request::builder()
                .uri(ciphertext_uri)
                .header("x-chancela-session", restarted_owner)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(&restored_ciphertext[..], ciphertext);
    }
}
