//! Non-destructive backup recovery drill receipts.
//!
//! This module records an operator custody receipt from the existing restore preflight path. It
//! never executes restore, never stages sidecars, and persists only bounded, whitelisted evidence.

use std::path::{Path, PathBuf};

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use chancela_authz::{Permission, Scope};
use chancela_store::recovery::{
    RestorePreflightIsolatedRestoreEvidence, RestorePreflightManifestEvidence,
    RestorePreflightOutcome,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use crate::AppState;
use crate::actor::CurrentActor;
use crate::authz::require_permission;
use crate::error::ApiError;
use crate::settings::BackupRecoveryPolicySettings;

pub(crate) const BACKUP_RECOVERY_DRILLS_FILE: &str = "backup-recovery-drills.json";

const MAX_RECEIPTS: usize = 50;
const MAX_ARCHIVE_REF_BYTES: usize = 1024;
const MAX_OPERATOR_NOTES_BYTES: usize = 2000;
const MAX_CUSTODY_LOCATION_BYTES: usize = 512;
const MAX_VERIFICATION_MESSAGES: usize = 8;
const MAX_VERIFICATION_MESSAGE_BYTES: usize = 512;
const ISOLATED_RESTORE_STATUS_VERIFIED: &str = "verified";
const ISOLATED_RESTORE_STATUS_FAILED: &str = "failed";
const ISOLATED_RESTORE_STATUS_NOT_RECORDED: &str = "not_recorded";

/// Secret-free manifest evidence persisted in a recovery-drill receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupRecoveryDrillManifestEvidence {
    pub schema: String,
    pub version: u32,
    pub store_schema_version: i64,
    pub ledger_length: u64,
    pub ledger_verified: bool,
    pub member_count: usize,
    pub sidecar_member_count: usize,
    pub db_member_present: bool,
    pub total_member_bytes: u64,
}

impl From<RestorePreflightManifestEvidence> for BackupRecoveryDrillManifestEvidence {
    fn from(m: RestorePreflightManifestEvidence) -> Self {
        BackupRecoveryDrillManifestEvidence {
            schema: m.schema,
            version: m.version,
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

/// Secret-free isolated snapshot verification evidence for a recovery-drill receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupRecoveryDrillIsolatedRestoreVerification {
    #[serde(default = "default_isolated_restore_status")]
    pub status: String,
    #[serde(default)]
    pub db_snapshot_materialized: bool,
    #[serde(default)]
    pub db_snapshot_opened: bool,
    #[serde(default)]
    pub state_loaded: bool,
    #[serde(default)]
    pub ledger_verified: bool,
    #[serde(default)]
    pub cleanup_verified: bool,
    #[serde(default)]
    pub entity_count: usize,
    #[serde(default)]
    pub book_count: usize,
    #[serde(default)]
    pub act_count: usize,
    #[serde(default)]
    pub sidecar_root_count: usize,
    #[serde(default)]
    pub sidecar_materialized_file_count: usize,
    #[serde(default)]
    pub sidecar_materialized_bytes: u64,
    #[serde(default)]
    pub sqlcipher_encryption_verified: Option<bool>,
    #[serde(default)]
    pub findings: Vec<String>,
    #[serde(default)]
    pub errors: Vec<String>,
    #[serde(default = "default_isolated_restore_not_recorded_next_step")]
    pub next_step: String,
}

impl BackupRecoveryDrillIsolatedRestoreVerification {
    fn from_preflight_outcome(outcome: &RestorePreflightOutcome) -> Self {
        match outcome.isolated_restore.as_ref() {
            Some(isolated) => Self::from_isolated_evidence(outcome, isolated),
            None if !outcome.ok => Self {
                status: ISOLATED_RESTORE_STATUS_FAILED.to_owned(),
                findings: bounded_verification_messages(&outcome.findings),
                errors: generic_preflight_errors(outcome),
                next_step: failure_next_step(outcome),
                ..Self::default()
            },
            None => Self {
                status: ISOLATED_RESTORE_STATUS_FAILED.to_owned(),
                errors: vec!["isolated snapshot verification evidence was not produced".to_owned()],
                next_step: "run the recovery drill again before relying on this receipt".to_owned(),
                ..Self::default()
            },
        }
    }

    fn from_isolated_evidence(
        outcome: &RestorePreflightOutcome,
        isolated: &RestorePreflightIsolatedRestoreEvidence,
    ) -> Self {
        let verified = preflight_and_isolated_snapshot_verified(outcome, isolated);
        let status = if verified {
            ISOLATED_RESTORE_STATUS_VERIFIED
        } else {
            ISOLATED_RESTORE_STATUS_FAILED
        };
        Self {
            status: status.to_owned(),
            db_snapshot_materialized: isolated.db_materialized,
            db_snapshot_opened: isolated.db_opened,
            state_loaded: isolated.state_loaded,
            ledger_verified: isolated.ledger_verified,
            cleanup_verified: isolated.cleanup_verified,
            entity_count: isolated.entity_count,
            book_count: isolated.book_count,
            act_count: isolated.act_count,
            sidecar_root_count: isolated.sidecar_root_count,
            sidecar_materialized_file_count: isolated.sidecar_materialized_file_count,
            sidecar_materialized_bytes: isolated.sidecar_materialized_bytes,
            sqlcipher_encryption_verified: isolated.sqlcipher_encryption_verified,
            findings: isolated_verification_findings(outcome, isolated),
            errors: if verified {
                Vec::new()
            } else {
                generic_preflight_errors(outcome)
            },
            next_step: if verified {
                "record as preflight-only isolated snapshot evidence; authorize any recovery execution separately".to_owned()
            } else {
                failure_next_step(outcome)
            },
        }
    }

    fn is_verified(&self) -> bool {
        self.status == ISOLATED_RESTORE_STATUS_VERIFIED
            && self.db_snapshot_materialized
            && self.db_snapshot_opened
            && self.state_loaded
            && self.ledger_verified
            && self.cleanup_verified
    }
}

impl Default for BackupRecoveryDrillIsolatedRestoreVerification {
    fn default() -> Self {
        Self {
            status: ISOLATED_RESTORE_STATUS_NOT_RECORDED.to_owned(),
            db_snapshot_materialized: false,
            db_snapshot_opened: false,
            state_loaded: false,
            ledger_verified: false,
            cleanup_verified: false,
            entity_count: 0,
            book_count: 0,
            act_count: 0,
            sidecar_root_count: 0,
            sidecar_materialized_file_count: 0,
            sidecar_materialized_bytes: 0,
            sqlcipher_encryption_verified: None,
            findings: Vec::new(),
            errors: Vec::new(),
            next_step: default_isolated_restore_not_recorded_next_step(),
        }
    }
}

/// Persisted operator receipt for a non-destructive backup recovery drill.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupRecoveryDrillReceipt {
    pub id: String,
    pub created_at: String,
    pub archive: String,
    pub preflight_ok: bool,
    pub preflight_ready: bool,
    pub encrypted: Option<bool>,
    pub ledger_verified: bool,
    pub manifest: Option<BackupRecoveryDrillManifestEvidence>,
    #[serde(default)]
    pub isolated_restore_verified: bool,
    #[serde(default)]
    pub isolated_restore_verification: BackupRecoveryDrillIsolatedRestoreVerification,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operator_notes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custody_location: Option<String>,
    #[serde(default)]
    pub restore_executed: bool,
    #[serde(default)]
    pub live_db_swapped: bool,
    #[serde(default)]
    pub sidecars_staged: bool,
    #[serde(default)]
    pub ledger_restored_appended: bool,
    #[serde(default)]
    pub data_deleted: bool,
    #[serde(default)]
    pub offsite_custody_proven: bool,
    #[serde(default)]
    pub legal_archive_certified: bool,
}

/// Body of `POST /v1/backup/recovery-drills`.
#[derive(Debug, Deserialize)]
pub struct BackupRecoveryDrillRequest {
    pub archive: String,
    pub passphrase: Option<String>,
    #[serde(default)]
    pub operator_notes: Option<String>,
    #[serde(default)]
    pub custody_location: Option<String>,
    #[serde(default)]
    pub restore_executed: Option<bool>,
    #[serde(default)]
    pub live_db_swapped: Option<bool>,
    #[serde(default)]
    pub sidecars_staged: Option<bool>,
    #[serde(default)]
    pub ledger_restored_appended: Option<bool>,
    #[serde(default)]
    pub data_deleted: Option<bool>,
    #[serde(default)]
    pub offsite_custody_proven: Option<bool>,
    #[serde(default)]
    pub legal_archive_certified: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct BackupRecoveryDrillList {
    pub receipts: Vec<BackupRecoveryDrillReceipt>,
    pub durable: bool,
    pub max_receipts: usize,
    pub freshness: BackupRecoveryFreshnessReview,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupRecoveryFreshnessStatus {
    NoReceipt,
    Fresh,
    Stale,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BackupRecoveryFreshnessReview {
    pub generated_at: String,
    pub policy: BackupRecoveryPolicySettings,
    pub status: BackupRecoveryFreshnessStatus,
    pub latest_receipt_id: Option<String>,
    pub latest_receipt_at: Option<String>,
    pub latest_receipt_age_days: Option<u32>,
    pub latest_receipt_preflight_ready: Option<bool>,
    pub latest_receipt_isolated_restore_verified: Option<bool>,
    pub restore_performed: bool,
    pub db_swap_performed: bool,
    pub offsite_custody_verified: bool,
    pub rpo_rto_certified: bool,
    pub production_backup_policy_certified: bool,
}

/// `GET /v1/backup/recovery-drills` — list persisted non-destructive drill receipts.
pub async fn list_backup_recovery_drills(
    State(state): State<AppState>,
    actor: CurrentActor,
) -> Result<Json<BackupRecoveryDrillList>, ApiError> {
    require_permission(&state, &actor, Permission::LedgerRecover, Scope::Global).await?;
    let mut receipts = state.backup_recovery_drill_receipts.read().await.clone();
    sort_backup_recovery_drill_receipts(&mut receipts);
    let policy = state
        .settings
        .read()
        .await
        .data_management
        .backup_recovery
        .clone();
    let now = OffsetDateTime::now_utc();
    Ok(Json(BackupRecoveryDrillList {
        freshness: backup_recovery_freshness_review(&receipts, policy, now),
        receipts,
        durable: state.backup_recovery_drill_receipts_path.is_some(),
        max_receipts: MAX_RECEIPTS,
    }))
}

pub(crate) fn sort_backup_recovery_drill_receipts(receipts: &mut [BackupRecoveryDrillReceipt]) {
    receipts.sort_by(|a, b| b.created_at.cmp(&a.created_at).then(a.id.cmp(&b.id)));
}

pub(crate) fn backup_recovery_freshness_review(
    receipts: &[BackupRecoveryDrillReceipt],
    policy: BackupRecoveryPolicySettings,
    now: OffsetDateTime,
) -> BackupRecoveryFreshnessReview {
    let latest = receipts.first();
    let latest_receipt_age_days = latest
        .and_then(|receipt| OffsetDateTime::parse(&receipt.created_at, &Rfc3339).ok())
        .map(|created_at| {
            let age_days = (now - created_at).whole_days().max(0);
            age_days.min(u32::MAX as i64) as u32
        });
    let status = match latest {
        None => BackupRecoveryFreshnessStatus::NoReceipt,
        Some(receipt)
            if !receipt.preflight_ready
                || !receipt.preflight_ok
                || !receipt.isolated_restore_verified
                || receipt.isolated_restore_verification.status
                    != ISOLATED_RESTORE_STATUS_VERIFIED =>
        {
            BackupRecoveryFreshnessStatus::Failed
        }
        Some(_) if latest_receipt_age_days.is_none() => BackupRecoveryFreshnessStatus::Failed,
        Some(_)
            if latest_receipt_age_days.unwrap_or(u32::MAX) > policy.max_drill_age_days as u32 =>
        {
            BackupRecoveryFreshnessStatus::Stale
        }
        Some(_) => BackupRecoveryFreshnessStatus::Fresh,
    };

    BackupRecoveryFreshnessReview {
        generated_at: now.format(&Rfc3339).unwrap_or_default(),
        policy,
        status,
        latest_receipt_id: latest.map(|receipt| receipt.id.clone()),
        latest_receipt_at: latest.map(|receipt| receipt.created_at.clone()),
        latest_receipt_age_days,
        latest_receipt_preflight_ready: latest.map(|receipt| receipt.preflight_ready),
        latest_receipt_isolated_restore_verified: latest
            .map(|receipt| receipt.isolated_restore_verified),
        restore_performed: false,
        db_swap_performed: false,
        offsite_custody_verified: false,
        rpo_rto_certified: false,
        production_backup_policy_certified: false,
    }
}

/// `POST /v1/backup/recovery-drills` — run restore preflight and persist a bounded receipt.
pub async fn create_backup_recovery_drill(
    State(state): State<AppState>,
    actor: CurrentActor,
    Json(req): Json<BackupRecoveryDrillRequest>,
) -> Result<(StatusCode, Json<BackupRecoveryDrillReceipt>), ApiError> {
    require_permission(&state, &actor, Permission::LedgerRecover, Scope::Global).await?;
    reject_true_flag("restore_executed", req.restore_executed)?;
    reject_true_flag("live_db_swapped", req.live_db_swapped)?;
    reject_true_flag("sidecars_staged", req.sidecars_staged)?;
    reject_true_flag("ledger_restored_appended", req.ledger_restored_appended)?;
    reject_true_flag("data_deleted", req.data_deleted)?;
    reject_true_flag("offsite_custody_proven", req.offsite_custody_proven)?;
    reject_true_flag("legal_archive_certified", req.legal_archive_certified)?;

    let archive_ref = normalize_text(
        req.archive,
        "archive",
        MAX_ARCHIVE_REF_BYTES,
        TextMode::SingleLine,
    )?;
    let operator_notes = normalize_optional_text(
        req.operator_notes,
        "operator_notes",
        MAX_OPERATOR_NOTES_BYTES,
        TextMode::MultiLine,
    )?;
    let custody_location = normalize_optional_text(
        req.custody_location,
        "custody_location",
        MAX_CUSTODY_LOCATION_BYTES,
        TextMode::SingleLine,
    )?;

    let Some(store) = state.store.clone() else {
        return Err(ApiError::Unprocessable(
            "ensaio de recuperação requer persistência em disco".to_owned(),
        ));
    };
    let data_dir = state
        .data_dir()
        .ok_or_else(|| ApiError::Internal("durable store without a data directory".to_owned()))?;
    let archive = resolve_backup_archive(&data_dir, &archive_ref)?;

    // Offload the sync preflight (postgres in-memory verify + `Client` `Drop`) off the async worker
    // (wp28); it routes through pg_backup on the Postgres backend.
    let passphrase = req.passphrase;
    let outcome = store
        .read_blocking_async(move |s| {
            s.restore_preflight(&archive, &data_dir, passphrase.as_deref())
        })
        .await
        .map_err(crate::recovery::map_store_error)?;
    let isolated_restore_verification =
        BackupRecoveryDrillIsolatedRestoreVerification::from_preflight_outcome(&outcome);
    let isolated_restore_verified = isolated_restore_verification.is_verified();

    let receipt = BackupRecoveryDrillReceipt {
        id: Uuid::new_v4().to_string(),
        created_at: OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_default(),
        archive: outcome.archive.to_string_lossy().into_owned(),
        preflight_ok: outcome.ok,
        preflight_ready: outcome.ready,
        encrypted: outcome.encrypted,
        ledger_verified: outcome.ledger_verified,
        manifest: outcome
            .manifest
            .map(BackupRecoveryDrillManifestEvidence::from),
        isolated_restore_verified,
        isolated_restore_verification,
        operator_notes,
        custody_location,
        restore_executed: false,
        live_db_swapped: false,
        sidecars_staged: false,
        ledger_restored_appended: false,
        data_deleted: false,
        offsite_custody_proven: false,
        legal_archive_certified: false,
    };

    persist_receipt(&state, receipt.clone()).await?;
    Ok((StatusCode::CREATED, Json(receipt)))
}

pub(crate) fn load_backup_recovery_drill_receipts(
    path: &Path,
) -> Option<Vec<BackupRecoveryDrillReceipt>> {
    let bytes = std::fs::read(path).ok()?;
    match serde_json::from_slice::<Vec<BackupRecoveryDrillReceipt>>(&bytes) {
        Ok(mut receipts) => {
            receipts = receipts
                .into_iter()
                .filter_map(normalize_loaded_receipt)
                .collect();
            prune_receipts(&mut receipts);
            Some(receipts)
        }
        Err(e) => {
            eprintln!(
                "warning: {} is not a valid backup recovery drill receipt document ({e}); ignoring it",
                path.display()
            );
            None
        }
    }
}

pub(crate) fn write_backup_recovery_drill_receipts_atomic(
    path: &Path,
    receipts: &[BackupRecoveryDrillReceipt],
) -> std::io::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let mut list = receipts.to_vec();
    list.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.cmp(&b.id)));
    let json = serde_json::to_vec_pretty(&list).map_err(std::io::Error::other)?;
    let tmp = tmp_path(path);
    std::fs::write(&tmp, &json)?;
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

async fn persist_receipt(
    state: &AppState,
    receipt: BackupRecoveryDrillReceipt,
) -> Result<(), ApiError> {
    let mut receipts = state.backup_recovery_drill_receipts.write().await;
    let mut next = receipts.clone();
    next.push(receipt);
    prune_receipts(&mut next);
    if let Some(path) = &state.backup_recovery_drill_receipts_path {
        write_backup_recovery_drill_receipts_atomic(path, &next).map_err(|e| {
            ApiError::Internal(format!(
                "failed to persist backup recovery drill receipts: {e}"
            ))
        })?;
    }
    *receipts = next;
    Ok(())
}

fn prune_receipts(receipts: &mut Vec<BackupRecoveryDrillReceipt>) {
    receipts.sort_by(|a, b| b.created_at.cmp(&a.created_at).then(a.id.cmp(&b.id)));
    receipts.truncate(MAX_RECEIPTS);
}

fn normalize_loaded_receipt(
    mut receipt: BackupRecoveryDrillReceipt,
) -> Option<BackupRecoveryDrillReceipt> {
    receipt.id = normalize_loaded_scalar(receipt.id, MAX_ARCHIVE_REF_BYTES)?;
    receipt.created_at = normalize_loaded_scalar(receipt.created_at, MAX_ARCHIVE_REF_BYTES)?;
    receipt.archive = normalize_loaded_scalar(receipt.archive, MAX_ARCHIVE_REF_BYTES)?;
    receipt.operator_notes =
        normalize_loaded_optional(receipt.operator_notes, MAX_OPERATOR_NOTES_BYTES);
    receipt.custody_location =
        normalize_loaded_optional(receipt.custody_location, MAX_CUSTODY_LOCATION_BYTES);
    receipt.isolated_restore_verification =
        normalize_loaded_isolated_restore_verification(receipt.isolated_restore_verification);
    receipt.isolated_restore_verified = receipt.isolated_restore_verification.is_verified();
    receipt.restore_executed = false;
    receipt.live_db_swapped = false;
    receipt.sidecars_staged = false;
    receipt.ledger_restored_appended = false;
    receipt.data_deleted = false;
    receipt.offsite_custody_proven = false;
    receipt.legal_archive_certified = false;
    Some(receipt)
}

fn normalize_loaded_isolated_restore_verification(
    mut verification: BackupRecoveryDrillIsolatedRestoreVerification,
) -> BackupRecoveryDrillIsolatedRestoreVerification {
    verification.status = match verification.status.as_str() {
        ISOLATED_RESTORE_STATUS_VERIFIED => ISOLATED_RESTORE_STATUS_VERIFIED.to_owned(),
        ISOLATED_RESTORE_STATUS_FAILED => ISOLATED_RESTORE_STATUS_FAILED.to_owned(),
        ISOLATED_RESTORE_STATUS_NOT_RECORDED => ISOLATED_RESTORE_STATUS_NOT_RECORDED.to_owned(),
        _ => ISOLATED_RESTORE_STATUS_NOT_RECORDED.to_owned(),
    };
    verification.findings = normalize_loaded_messages(verification.findings);
    verification.errors = normalize_loaded_messages(verification.errors);
    verification.next_step =
        normalize_loaded_scalar(verification.next_step, MAX_VERIFICATION_MESSAGE_BYTES)
            .unwrap_or_else(default_isolated_restore_not_recorded_next_step);
    if verification.status == ISOLATED_RESTORE_STATUS_NOT_RECORDED {
        return BackupRecoveryDrillIsolatedRestoreVerification::default();
    }
    if verification.status == ISOLATED_RESTORE_STATUS_VERIFIED && !verification.is_verified() {
        verification.status = ISOLATED_RESTORE_STATUS_FAILED.to_owned();
    }
    verification
}

fn normalize_loaded_messages(messages: Vec<String>) -> Vec<String> {
    messages
        .into_iter()
        .filter_map(|message| normalize_loaded_scalar(message, MAX_VERIFICATION_MESSAGE_BYTES))
        .take(MAX_VERIFICATION_MESSAGES)
        .collect()
}

fn normalize_loaded_scalar(value: String, max_bytes: usize) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > max_bytes || has_forbidden_control(trimmed, false) {
        return None;
    }
    Some(trimmed.to_owned())
}

fn normalize_loaded_optional(value: Option<String>, max_bytes: usize) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() || trimmed.len() > max_bytes || has_forbidden_control(trimmed, true) {
            None
        } else {
            Some(trimmed.to_owned())
        }
    })
}

fn tmp_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_else(|| BACKUP_RECOVERY_DRILLS_FILE.into());
    name.push(format!(".{}.tmp", Uuid::new_v4()));
    path.with_file_name(name)
}

fn resolve_backup_archive(data_dir: &Path, archive: &str) -> Result<PathBuf, ApiError> {
    let raw = PathBuf::from(archive);
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

fn reject_true_flag(name: &str, value: Option<bool>) -> Result<(), ApiError> {
    if value == Some(true) {
        return Err(ApiError::Unprocessable(format!(
            "{name} não pode ser declarado true num ensaio sem restauro"
        )));
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum TextMode {
    SingleLine,
    MultiLine,
}

fn normalize_optional_text(
    value: Option<String>,
    field: &str,
    max_bytes: usize,
    mode: TextMode,
) -> Result<Option<String>, ApiError> {
    value
        .map(|value| normalize_text(value, field, max_bytes, mode))
        .transpose()
        .map(|value| value.filter(|s| !s.is_empty()))
}

fn normalize_text(
    value: String,
    field: &str,
    max_bytes: usize,
    mode: TextMode,
) -> Result<String, ApiError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        if field == "archive" {
            return Err(ApiError::Unprocessable(
                "archive não pode estar vazio".to_owned(),
            ));
        }
        return Ok(String::new());
    }
    if trimmed.len() > max_bytes {
        return Err(ApiError::Unprocessable(format!(
            "{field} excede o limite de {max_bytes} bytes"
        )));
    }
    let allow_newlines = matches!(mode, TextMode::MultiLine);
    if has_forbidden_control(trimmed, allow_newlines) {
        return Err(ApiError::Unprocessable(format!(
            "{field} contém caracteres de controlo não permitidos"
        )));
    }
    Ok(trimmed.to_owned())
}

fn has_forbidden_control(value: &str, allow_newlines: bool) -> bool {
    value
        .chars()
        .any(|ch| ch.is_control() && !(allow_newlines && matches!(ch, '\n' | '\r' | '\t')))
}

fn preflight_and_isolated_snapshot_verified(
    outcome: &RestorePreflightOutcome,
    isolated: &RestorePreflightIsolatedRestoreEvidence,
) -> bool {
    outcome.ok
        && outcome.ready
        && outcome.ledger_verified
        && outcome.manifest.as_ref().is_some_and(|manifest| {
            manifest.ledger_verified && manifest.db_member_present && manifest.member_count > 0
        })
        && isolated.db_materialized
        && isolated.db_opened
        && isolated.state_loaded
        && isolated.ledger_verified
        && isolated.cleanup_verified
}

fn isolated_verification_findings(
    outcome: &RestorePreflightOutcome,
    isolated: &RestorePreflightIsolatedRestoreEvidence,
) -> Vec<String> {
    let mut findings = Vec::new();
    if outcome.manifest.is_some() {
        findings
            .push("archive manifest and listed members passed store preflight checks".to_owned());
    }
    if isolated.db_materialized && isolated.db_opened && isolated.state_loaded {
        findings.push("isolated database snapshot was materialized, opened, and loaded".to_owned());
    }
    if isolated.ledger_verified {
        findings.push("isolated snapshot ledger verified".to_owned());
    }
    if isolated.sidecar_materialized_file_count > 0 {
        findings.push(format!(
            "isolated sidecar readback covered {} file(s)",
            isolated.sidecar_materialized_file_count
        ));
    }
    if isolated.cleanup_verified {
        findings.push("isolated verification temp directory was removed".to_owned());
    }
    findings
}

fn generic_preflight_errors(outcome: &RestorePreflightOutcome) -> Vec<String> {
    if outcome.errors.is_empty() {
        return vec!["restore preflight did not verify the isolated snapshot".to_owned()];
    }
    vec![format!(
        "restore preflight failed before isolated snapshot verification completed ({} error(s))",
        outcome.errors.len()
    )]
}

fn bounded_verification_messages(messages: &[String]) -> Vec<String> {
    normalize_loaded_messages(messages.to_vec())
}

fn failure_next_step(outcome: &RestorePreflightOutcome) -> String {
    normalize_loaded_scalar(outcome.next_step.clone(), MAX_VERIFICATION_MESSAGE_BYTES)
        .unwrap_or_else(|| {
            "fix the archive material or passphrase and run the recovery drill again".to_owned()
        })
}

fn default_isolated_restore_status() -> String {
    ISOLATED_RESTORE_STATUS_NOT_RECORDED.to_owned()
}

fn default_isolated_restore_not_recorded_next_step() -> String {
    "run a new recovery drill to record isolated snapshot verification".to_owned()
}
