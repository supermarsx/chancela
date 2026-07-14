//! Local sync/handoff preflight readiness report.
//!
//! This is a read-only composition endpoint. It does not implement active sync, connector
//! protocols, background jobs, provider calls, uploads/downloads, imports, or record mutation.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use axum::Json;
use axum::extract::State;
use chancela_authz::{Permission, Scope};
use chancela_core::{ActState, BookState};
use serde::Serialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::actor::CurrentActor;
use crate::authz::require_permission;
use crate::backup_recovery::BackupRecoveryDrillReceipt;
use crate::error::ApiError;
use crate::{AppState, bundles};

const ENDPOINT: &str = "/v1/sync/handoff-preflight";
const REPORT_KIND: &str = "sync_handoff_preflight";
const BACKUP_ROUTE: &str = "/v1/backup";
const BACKUP_RECOVERY_DRILLS_ROUTE: &str = "/v1/backup/recovery-drills";
const BOOK_EXPORT_ROUTE: &str = "/v1/books/{id}/export";
const BOOK_IMPORT_PREFLIGHT_ROUTE: &str = "/v1/books/import/preflight";
const BOOK_IMPORT_ROUTE: &str = "/v1/books/import";
const ARCHIVE_PACKAGE_ROUTE: &str = "/v1/books/{id}/archive/package";
const LOCAL_DGLAB_MANIFEST_ROUTE: &str = "/v1/books/{id}/archive/local-dglab-interchange-manifest";

#[derive(Debug, Clone, Serialize)]
pub struct SyncHandoffPreflightReport {
    pub report_kind: &'static str,
    pub endpoint: &'static str,
    pub generated_at: String,
    pub readiness: SyncHandoffReadiness,
    pub data_status: SyncHandoffDataStatus,
    pub backup: SyncHandoffBackupEvidence,
    pub book_bundles: SyncHandoffBookBundleEvidence,
    pub archive_dglab: SyncHandoffArchiveDglabEvidence,
    pub no_claims: SyncHandoffNoClaims,
    pub blockers: Vec<String>,
    pub missing_evidence: Vec<String>,
    pub operator_actions: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SyncHandoffReadiness {
    pub status: &'static str,
    pub local_handoff_review_ready: bool,
    pub production_sync_ready: bool,
    pub external_connector_ready: bool,
    pub active_sync_performed: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SyncHandoffDataStatus {
    pub data_dir_configured: bool,
    pub durable_store_open: bool,
    pub ledger_length: u64,
    pub ledger_healthy: bool,
    pub ledger_degraded: bool,
    pub global_chain_verified: bool,
    pub global_chain_first_break: Option<String>,
    pub boot_chain_status_ok: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SyncHandoffBackupEvidence {
    pub backup_route: &'static str,
    pub recovery_drill_route: &'static str,
    pub durable_receipts: bool,
    pub backup_directory: SyncHandoffBackupDirectoryEvidence,
    pub recovery_drill_receipt_count: usize,
    pub verified_recovery_drill_evidence: bool,
    pub latest_recovery_drill: Option<SyncHandoffRecoveryDrillSummary>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SyncHandoffBackupDirectoryEvidence {
    pub relative_path: &'static str,
    pub scanned: bool,
    pub present: bool,
    pub untrusted_candidate_file_count: usize,
    pub total_candidate_bytes: u64,
    pub latest_candidate_file: Option<SyncHandoffBackupCandidateSummary>,
    pub validation_performed: bool,
    pub validated_manifest_evidence_present: bool,
    pub scan_error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SyncHandoffBackupCandidateSummary {
    pub file_name: String,
    pub bytes: u64,
    pub modified_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SyncHandoffRecoveryDrillSummary {
    pub id: String,
    pub created_at: String,
    pub archive_label: String,
    pub preflight_ok: bool,
    pub preflight_ready: bool,
    pub encrypted: Option<bool>,
    pub ledger_verified: bool,
    pub manifest_evidence_present: bool,
    pub manifest_ledger_verified: Option<bool>,
    pub manifest_ledger_length: Option<u64>,
    pub manifest_member_count: Option<usize>,
    pub manifest_db_member_present: Option<bool>,
    pub manifest_sidecar_member_count: Option<usize>,
    pub manifest_total_member_bytes: Option<u64>,
    pub isolated_restore_verified: bool,
    pub isolated_restore_status: String,
    pub isolated_snapshot_ledger_verified: bool,
    pub isolated_snapshot_cleanup_verified: bool,
    pub verified_manifest_and_isolated_snapshot: bool,
    pub restore_executed: bool,
    pub live_db_swapped: bool,
    pub sidecars_staged: bool,
    pub ledger_restored_appended: bool,
    pub data_deleted: bool,
    pub offsite_custody_proven: bool,
    pub legal_archive_certified: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SyncHandoffBookBundleEvidence {
    pub export_route: &'static str,
    pub import_preflight_route: &'static str,
    pub import_confirmation_route: &'static str,
    pub import_preflight_read_only: bool,
    pub max_import_bundle_bytes: usize,
    pub collision_policies: [&'static str; 2],
    pub durable_store_required: bool,
    pub durable_store_available: bool,
    pub retained_export_relative_path: &'static str,
    pub book_count: usize,
    pub open_book_count: usize,
    pub closed_book_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct SyncHandoffArchiveDglabEvidence {
    pub archive_package_route: &'static str,
    pub local_dglab_manifest_route: &'static str,
    pub local_dglab_manifest_read_only: bool,
    pub local_dglab_manifest_route_available: bool,
    pub book_count: usize,
    pub closed_book_count: usize,
    pub sealed_or_archived_act_count: usize,
    pub preserved_document_count: usize,
    pub signed_document_count: usize,
    pub external_validator_report_metadata_count: usize,
    pub dglab_certification_claimed: bool,
    pub archive_certification_claimed: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SyncHandoffNoClaims {
    pub active_sync_implemented: bool,
    pub connector_protocol_implemented: bool,
    pub background_job_configured: bool,
    pub upload_or_download_performed: bool,
    pub import_performed: bool,
    pub records_mutated: bool,
    pub production_sync_readiness_claimed: bool,
    pub external_connector_compatibility_claimed: bool,
    pub legal_validity_claimed: bool,
    pub dglab_certification_claimed: bool,
    pub archive_certification_claimed: bool,
    pub signing_notarization_attestation_claimed: bool,
    pub deployment_readiness_claimed: bool,
}

/// `GET /v1/sync/handoff-preflight` — compose local evidence into a read-only handoff report.
pub async fn get_sync_handoff_preflight(
    State(state): State<AppState>,
    actor: CurrentActor,
) -> Result<Json<SyncHandoffPreflightReport>, ApiError> {
    // RBAC: this summarizes recovery/backup evidence, so it stays on the recovery plane.
    require_permission(&state, &actor, Permission::LedgerRecover, Scope::Global).await?;
    Ok(Json(build_sync_handoff_preflight_report(&state).await))
}

pub(crate) async fn build_sync_handoff_preflight_report(
    state: &AppState,
) -> SyncHandoffPreflightReport {
    let generated_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default();
    let data_dir = state.data_dir();
    let durable_store_open = state.store.is_some();
    let backup_directory = backup_directory_evidence(data_dir.clone()).await;
    let data_status = data_status_evidence(state).await;
    let backup = backup_evidence(state, backup_directory).await;
    let book_bundles = book_bundle_evidence(state, durable_store_open).await;
    let archive_dglab = archive_dglab_evidence(state).await;
    let no_claims = no_claims();

    let mut blockers = Vec::new();
    if !data_status.data_dir_configured || !data_status.durable_store_open {
        blockers.push(
            "durable data directory/store is not available; backup, retained export, and import-preflight evidence remain incomplete".to_owned(),
        );
    }
    if !data_status.ledger_healthy || data_status.ledger_degraded {
        blockers.push(
            "ledger integrity is unhealthy or the instance is degraded; inspect recovery before handoff".to_owned(),
        );
    }

    let mut missing_evidence = Vec::new();
    if !backup.verified_recovery_drill_evidence
        && !backup.backup_directory.validated_manifest_evidence_present
    {
        missing_evidence.push(
            "no validated whole-instance backup manifest or verified recovery-drill evidence is available; local backup files are only untrusted candidates in this read-only report".to_owned(),
        );
    }
    match &backup.latest_recovery_drill {
        None => missing_evidence
            .push("no non-destructive backup recovery drill receipt is recorded".to_owned()),
        Some(drill) => {
            if !drill.verified_manifest_and_isolated_snapshot {
                missing_evidence.push(
                    "latest backup recovery drill lacks verified manifest, ledger, database-member, and isolated-snapshot evidence".to_owned(),
                );
            }
            if !drill.manifest_evidence_present
                || drill.manifest_ledger_verified != Some(true)
                || drill.manifest_db_member_present != Some(true)
                || drill.manifest_member_count.unwrap_or_default() == 0
            {
                missing_evidence.push(
                    "latest backup recovery drill has no verified backup manifest/member evidence summary".to_owned(),
                );
            }
        }
    }
    if book_bundles.book_count == 0 {
        missing_evidence
            .push("no local books are available for export/import preflight review".to_owned());
    }
    if book_bundles.closed_book_count == 0 {
        missing_evidence
            .push("no closed books are present for archive/DGLAB manifest review".to_owned());
    }
    if archive_dglab.sealed_or_archived_act_count == 0 {
        missing_evidence
            .push("no sealed or archived acts are present for archive evidence review".to_owned());
    }
    if archive_dglab.preserved_document_count == 0 {
        missing_evidence.push(
            "no preserved PDF/A document records are present for archive evidence review"
                .to_owned(),
        );
    }

    let readiness_status = if !blockers.is_empty() {
        "blocked"
    } else if !missing_evidence.is_empty() {
        "missing_local_evidence"
    } else {
        "local_review_ready"
    };
    let readiness = SyncHandoffReadiness {
        status: readiness_status,
        local_handoff_review_ready: readiness_status == "local_review_ready",
        production_sync_ready: false,
        external_connector_ready: false,
        active_sync_performed: false,
    };
    let operator_actions = operator_actions(&blockers, &missing_evidence);

    SyncHandoffPreflightReport {
        report_kind: REPORT_KIND,
        endpoint: ENDPOINT,
        generated_at,
        readiness,
        data_status,
        backup,
        book_bundles,
        archive_dglab,
        no_claims,
        blockers,
        missing_evidence,
        operator_actions,
    }
}

async fn data_status_evidence(state: &AppState) -> SyncHandoffDataStatus {
    let report = state.ledger.read().await.integrity_report();
    let degraded = *state.degraded.read().await;
    SyncHandoffDataStatus {
        data_dir_configured: state.data_dir().is_some(),
        durable_store_open: state.store.is_some(),
        ledger_length: report.global.length,
        ledger_healthy: report.healthy,
        ledger_degraded: degraded,
        global_chain_verified: report.global.verified,
        global_chain_first_break: report
            .global
            .first_break
            .as_ref()
            .map(|break_| break_.message.clone()),
        boot_chain_status_ok: state.chain_status.as_ref().map(|status| status.is_ok()),
    }
}

async fn backup_evidence(
    state: &AppState,
    backup_directory: SyncHandoffBackupDirectoryEvidence,
) -> SyncHandoffBackupEvidence {
    let mut receipts = state.backup_recovery_drill_receipts.read().await.clone();
    receipts.sort_by(|a, b| b.created_at.cmp(&a.created_at).then(a.id.cmp(&b.id)));
    let verified_recovery_drill_evidence = receipts
        .first()
        .is_some_and(recovery_drill_has_verified_evidence);
    let latest_recovery_drill = receipts.first().map(recovery_drill_summary);

    SyncHandoffBackupEvidence {
        backup_route: BACKUP_ROUTE,
        recovery_drill_route: BACKUP_RECOVERY_DRILLS_ROUTE,
        durable_receipts: state.backup_recovery_drill_receipts_path.is_some(),
        backup_directory,
        recovery_drill_receipt_count: receipts.len(),
        verified_recovery_drill_evidence,
        latest_recovery_drill,
    }
}

async fn book_bundle_evidence(
    state: &AppState,
    durable_store_open: bool,
) -> SyncHandoffBookBundleEvidence {
    let books = state.books.read().await;
    let book_count = books.len();
    let open_book_count = books
        .values()
        .filter(|book| book.state == BookState::Open)
        .count();
    let closed_book_count = books
        .values()
        .filter(|book| book.state == BookState::Closed)
        .count();
    SyncHandoffBookBundleEvidence {
        export_route: BOOK_EXPORT_ROUTE,
        import_preflight_route: BOOK_IMPORT_PREFLIGHT_ROUTE,
        import_confirmation_route: BOOK_IMPORT_ROUTE,
        import_preflight_read_only: true,
        max_import_bundle_bytes: bundles::BOOK_IMPORT_BUNDLE_MAX_BYTES,
        collision_policies: ["refuse", "quarantine_copy"],
        durable_store_required: true,
        durable_store_available: durable_store_open,
        retained_export_relative_path: "exports",
        book_count,
        open_book_count,
        closed_book_count,
    }
}

async fn archive_dglab_evidence(state: &AppState) -> SyncHandoffArchiveDglabEvidence {
    let books = state.books.read().await;
    let book_count = books.len();
    let closed_book_count = books
        .values()
        .filter(|book| book.state == BookState::Closed)
        .count();
    drop(books);

    let sealed_or_archived_act_count = state
        .acts
        .read()
        .await
        .values()
        .filter(|act| matches!(act.state, ActState::Sealed | ActState::Archived))
        .count();
    let preserved_document_count = state.documents.read().await.len();
    let signed_document_count = state.signed_documents.read().await.len();
    let external_validator_report_metadata_count =
        state.external_validator_report_metadata.read().await.len();

    SyncHandoffArchiveDglabEvidence {
        archive_package_route: ARCHIVE_PACKAGE_ROUTE,
        local_dglab_manifest_route: LOCAL_DGLAB_MANIFEST_ROUTE,
        local_dglab_manifest_read_only: true,
        local_dglab_manifest_route_available: true,
        book_count,
        closed_book_count,
        sealed_or_archived_act_count,
        preserved_document_count,
        signed_document_count,
        external_validator_report_metadata_count,
        dglab_certification_claimed: false,
        archive_certification_claimed: false,
    }
}

async fn backup_directory_evidence(
    data_dir: Option<PathBuf>,
) -> SyncHandoffBackupDirectoryEvidence {
    let Some(data_dir) = data_dir else {
        return SyncHandoffBackupDirectoryEvidence {
            relative_path: "backups",
            scanned: false,
            present: false,
            untrusted_candidate_file_count: 0,
            total_candidate_bytes: 0,
            latest_candidate_file: None,
            validation_performed: false,
            validated_manifest_evidence_present: false,
            scan_error: None,
        };
    };
    match tokio::task::spawn_blocking(move || inspect_backup_directory(&data_dir)).await {
        Ok(evidence) => evidence,
        Err(e) => SyncHandoffBackupDirectoryEvidence {
            relative_path: "backups",
            scanned: false,
            present: false,
            untrusted_candidate_file_count: 0,
            total_candidate_bytes: 0,
            latest_candidate_file: None,
            validation_performed: false,
            validated_manifest_evidence_present: false,
            scan_error: Some(format!("backup directory scan task failed: {e}")),
        },
    }
}

fn inspect_backup_directory(data_dir: &Path) -> SyncHandoffBackupDirectoryEvidence {
    let backups = data_dir.join("backups");
    let mut evidence = SyncHandoffBackupDirectoryEvidence {
        relative_path: "backups",
        scanned: true,
        present: backups.is_dir(),
        untrusted_candidate_file_count: 0,
        total_candidate_bytes: 0,
        latest_candidate_file: None,
        validation_performed: false,
        validated_manifest_evidence_present: false,
        scan_error: None,
    };
    if !evidence.present {
        return evidence;
    }
    let entries = match std::fs::read_dir(&backups) {
        Ok(entries) => entries,
        Err(e) => {
            evidence.scanned = false;
            evidence.scan_error = Some(e.to_string());
            return evidence;
        }
    };
    let mut latest: Option<(SystemTime, SyncHandoffBackupCandidateSummary)> = None;
    for entry in entries {
        let Ok(entry) = entry else {
            continue;
        };
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_file() {
            continue;
        }
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        let file_name = entry.file_name().to_string_lossy().into_owned();
        if !is_backup_archive_candidate(&file_name) {
            continue;
        }
        let modified = metadata.modified().ok();
        let summary = SyncHandoffBackupCandidateSummary {
            file_name,
            bytes: metadata.len(),
            modified_at: modified.and_then(format_system_time),
        };
        evidence.untrusted_candidate_file_count += 1;
        evidence.total_candidate_bytes += summary.bytes;
        if let Some(modified) = modified {
            let replace = latest
                .as_ref()
                .is_none_or(|(current_modified, _)| modified > *current_modified);
            if replace {
                latest = Some((modified, summary));
            }
        } else if latest.is_none() {
            latest = Some((SystemTime::UNIX_EPOCH, summary));
        }
    }
    evidence.latest_candidate_file = latest.map(|(_, summary)| summary);
    evidence
}

fn is_backup_archive_candidate(file_name: &str) -> bool {
    file_name.starts_with("chancela-backup-")
        && (file_name.ends_with(".zip") || file_name.ends_with(".cbackup"))
}

fn format_system_time(value: SystemTime) -> Option<String> {
    OffsetDateTime::from(value).format(&Rfc3339).ok()
}

fn recovery_drill_summary(receipt: &BackupRecoveryDrillReceipt) -> SyncHandoffRecoveryDrillSummary {
    let verified_manifest_and_isolated_snapshot = recovery_drill_has_verified_evidence(receipt);
    SyncHandoffRecoveryDrillSummary {
        id: receipt.id.clone(),
        created_at: receipt.created_at.clone(),
        archive_label: local_file_label(&receipt.archive),
        preflight_ok: receipt.preflight_ok,
        preflight_ready: receipt.preflight_ready,
        encrypted: receipt.encrypted,
        ledger_verified: receipt.ledger_verified,
        manifest_evidence_present: receipt.manifest.is_some(),
        manifest_ledger_verified: receipt.manifest.as_ref().map(|m| m.ledger_verified),
        manifest_ledger_length: receipt.manifest.as_ref().map(|m| m.ledger_length),
        manifest_member_count: receipt.manifest.as_ref().map(|m| m.member_count),
        manifest_db_member_present: receipt.manifest.as_ref().map(|m| m.db_member_present),
        manifest_sidecar_member_count: receipt.manifest.as_ref().map(|m| m.sidecar_member_count),
        manifest_total_member_bytes: receipt.manifest.as_ref().map(|m| m.total_member_bytes),
        isolated_restore_verified: receipt.isolated_restore_verified,
        isolated_restore_status: receipt.isolated_restore_verification.status.clone(),
        isolated_snapshot_ledger_verified: receipt.isolated_restore_verification.ledger_verified,
        isolated_snapshot_cleanup_verified: receipt.isolated_restore_verification.cleanup_verified,
        verified_manifest_and_isolated_snapshot,
        restore_executed: receipt.restore_executed,
        live_db_swapped: receipt.live_db_swapped,
        sidecars_staged: receipt.sidecars_staged,
        ledger_restored_appended: receipt.ledger_restored_appended,
        data_deleted: receipt.data_deleted,
        offsite_custody_proven: receipt.offsite_custody_proven,
        legal_archive_certified: receipt.legal_archive_certified,
    }
}

fn recovery_drill_has_verified_evidence(receipt: &BackupRecoveryDrillReceipt) -> bool {
    receipt.preflight_ok
        && receipt.preflight_ready
        && receipt.ledger_verified
        && receipt.isolated_restore_verified
        && receipt.manifest.as_ref().is_some_and(|manifest| {
            manifest.ledger_verified
                && manifest.db_member_present
                && manifest.member_count > 0
                && manifest.total_member_bytes > 0
        })
        && receipt.isolated_restore_verification.status == "verified"
        && receipt
            .isolated_restore_verification
            .db_snapshot_materialized
        && receipt.isolated_restore_verification.db_snapshot_opened
        && receipt.isolated_restore_verification.state_loaded
        && receipt.isolated_restore_verification.ledger_verified
        && receipt.isolated_restore_verification.cleanup_verified
}

fn local_file_label(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    Path::new(trimmed)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| trimmed.to_owned())
}

fn no_claims() -> SyncHandoffNoClaims {
    SyncHandoffNoClaims {
        active_sync_implemented: false,
        connector_protocol_implemented: false,
        background_job_configured: false,
        upload_or_download_performed: false,
        import_performed: false,
        records_mutated: false,
        production_sync_readiness_claimed: false,
        external_connector_compatibility_claimed: false,
        legal_validity_claimed: false,
        dglab_certification_claimed: false,
        archive_certification_claimed: false,
        signing_notarization_attestation_claimed: false,
        deployment_readiness_claimed: false,
    }
}

fn operator_actions(blockers: &[String], missing_evidence: &[String]) -> Vec<String> {
    let mut actions = Vec::new();
    if blockers
        .iter()
        .any(|blocker| blocker.contains("durable data directory"))
    {
        actions.push("configure a local data directory and reopen the app before relying on backup/export evidence".to_owned());
    }
    if blockers
        .iter()
        .any(|blocker| blocker.contains("ledger integrity"))
    {
        actions.push(
            "inspect /v1/ledger/integrity and run the existing recovery preflight before handoff"
                .to_owned(),
        );
    }
    if missing_evidence
        .iter()
        .any(|missing| missing.contains("backup manifest") || missing.contains("backup files"))
    {
        actions.push(
            "take a local hot backup through /v1/backup and record a verified recovery-drill receipt before relying on backup evidence".to_owned(),
        );
    }
    if missing_evidence
        .iter()
        .any(|missing| missing.contains("recovery drill"))
    {
        actions.push(
            "record a non-destructive backup recovery drill receipt before handoff".to_owned(),
        );
    }
    if missing_evidence
        .iter()
        .any(|missing| missing.contains("books") || missing.contains("acts"))
    {
        actions.push("review local books, sealed acts, and preserved documents before any handoff package review".to_owned());
    }
    actions.push(
        "use explicit existing confirmation endpoints for any later export/import/recovery action; this report itself is read-only".to_owned(),
    );
    actions
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup_recovery::{
        BackupRecoveryDrillIsolatedRestoreVerification, BackupRecoveryDrillManifestEvidence,
    };
    use chancela_core::{Act, Book, BookKind, EntityId, MeetingChannel, TermoDeAbertura};
    use chancela_store::StoredDocument;
    use time::macros::date;
    use uuid::Uuid;

    struct TempDir {
        dir: PathBuf,
    }

    impl TempDir {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "chancela-sync-handoff-preflight-{name}-{}",
                Uuid::new_v4()
            ));
            std::fs::create_dir_all(&dir).expect("create temp dir");
            Self { dir }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[tokio::test]
    async fn sync_handoff_preflight_in_memory_reports_read_only_blockers() {
        let state = AppState::default();
        let before_ledger_len = state.ledger.read().await.len();

        let report = build_sync_handoff_preflight_report(&state).await;

        assert_eq!(report.report_kind, REPORT_KIND);
        assert_eq!(report.endpoint, ENDPOINT);
        assert_eq!(report.readiness.status, "blocked");
        assert!(!report.readiness.production_sync_ready);
        assert!(!report.no_claims.active_sync_implemented);
        assert!(!report.no_claims.records_mutated);
        assert!(!report.data_status.data_dir_configured);
        assert!(!report.backup.backup_directory.scanned);
        assert!(
            report
                .blockers
                .iter()
                .any(|blocker| blocker.contains("durable data directory"))
        );
        assert_eq!(state.ledger.read().await.len(), before_ledger_len);
    }

    #[tokio::test]
    async fn sync_handoff_preflight_summarizes_local_evidence_without_mutation() {
        let tmp = TempDir::new("local-evidence");
        let state = AppState::with_data_dir(tmp.dir.clone());
        let backups = tmp.dir.join("backups");
        std::fs::create_dir_all(&backups).expect("backup dir");
        std::fs::write(backups.join("chancela-backup-test.zip"), b"backup").expect("backup file");
        std::fs::write(backups.join("operator-note.txt"), b"not a backup")
            .expect("non-backup file");
        seed_closed_book_with_document(&state).await;
        state
            .backup_recovery_drill_receipts
            .write()
            .await
            .push(verified_recovery_drill_receipt());
        let before = snapshot_counts(&state).await;

        let report = build_sync_handoff_preflight_report(&state).await;

        assert_eq!(report.readiness.status, "local_review_ready");
        assert!(
            report.blockers.is_empty(),
            "blockers: {:?}",
            report.blockers
        );
        assert!(
            report.missing_evidence.is_empty(),
            "missing evidence: {:?}",
            report.missing_evidence
        );
        assert!(report.data_status.durable_store_open);
        assert_eq!(
            report
                .backup
                .backup_directory
                .untrusted_candidate_file_count,
            1
        );
        assert!(!report.backup.backup_directory.validation_performed);
        assert!(
            !report
                .backup
                .backup_directory
                .validated_manifest_evidence_present
        );
        assert!(report.backup.verified_recovery_drill_evidence);
        assert_eq!(
            report
                .backup
                .backup_directory
                .latest_candidate_file
                .as_ref()
                .expect("latest candidate")
                .file_name,
            "chancela-backup-test.zip"
        );
        let drill = report
            .backup
            .latest_recovery_drill
            .as_ref()
            .expect("drill summary");
        assert!(drill.preflight_ready);
        assert!(drill.manifest_evidence_present);
        assert_eq!(drill.manifest_ledger_verified, Some(true));
        assert_eq!(drill.manifest_db_member_present, Some(true));
        assert!(drill.verified_manifest_and_isolated_snapshot);
        assert!(drill.isolated_restore_verified);
        assert_eq!(report.book_bundles.closed_book_count, 1);
        assert_eq!(report.archive_dglab.sealed_or_archived_act_count, 1);
        assert_eq!(report.archive_dglab.preserved_document_count, 1);
        assert!(report.archive_dglab.local_dglab_manifest_route_available);
        assert!(!report.archive_dglab.dglab_certification_claimed);
        assert_eq!(snapshot_counts(&state).await, before);
    }

    #[tokio::test]
    async fn sync_handoff_preflight_rejects_untrusted_backup_file_and_unverified_drill() {
        let tmp = TempDir::new("untrusted-backup");
        let state = AppState::with_data_dir(tmp.dir.clone());
        let backups = tmp.dir.join("backups");
        std::fs::create_dir_all(&backups).expect("backup dir");
        std::fs::write(backups.join("not-a-backup.txt"), b"not a backup").expect("non-backup file");
        seed_closed_book_with_document(&state).await;
        state
            .backup_recovery_drill_receipts
            .write()
            .await
            .push(unverified_recovery_drill_receipt());

        let report = build_sync_handoff_preflight_report(&state).await;

        assert_eq!(report.readiness.status, "missing_local_evidence");
        assert!(!report.readiness.local_handoff_review_ready);
        assert_eq!(
            report
                .backup
                .backup_directory
                .untrusted_candidate_file_count,
            0
        );
        assert!(!report.backup.verified_recovery_drill_evidence);
        let drill = report
            .backup
            .latest_recovery_drill
            .as_ref()
            .expect("drill summary");
        assert!(drill.preflight_ok);
        assert!(drill.preflight_ready);
        assert!(drill.manifest_evidence_present);
        assert_eq!(drill.manifest_ledger_verified, Some(false));
        assert_eq!(drill.manifest_db_member_present, Some(false));
        assert!(!drill.verified_manifest_and_isolated_snapshot);
        assert!(
            report
                .missing_evidence
                .iter()
                .any(|missing| missing.contains("no validated whole-instance backup manifest"))
        );
        assert!(
            report
                .missing_evidence
                .iter()
                .any(|missing| missing.contains("latest backup recovery drill lacks verified"))
        );
    }

    async fn seed_closed_book_with_document(state: &AppState) {
        let entity_id = EntityId::new();
        let mut book = Book::new(entity_id, BookKind::AssembleiaGeral);
        let termo = TermoDeAbertura {
            entity_name: "Encosto Estratégico, S.A.".to_owned(),
            entity_nipc: "503004642".to_owned(),
            entity_seat: "Lisboa".to_owned(),
            purpose: "livro de atas".to_owned(),
            numbering_scheme: chancela_core::NumberingScheme::Sequential,
            opening_date: date!(2026 - 01 - 15),
            required_signatories: vec!["Administrador".to_owned()],
            required_signatory_records: Vec::new(),
        };
        book.termo_abertura = Some(termo);
        book.state = BookState::Closed;
        let book_id = book.id;
        state.books.write().await.insert(book_id, book);

        let mut act = Act::draft(book_id, "Ata", MeetingChannel::Physical);
        act.state = ActState::Sealed;
        act.ata_number = Some(1);
        let act_id = act.id;
        state.acts.write().await.insert(act_id, act);

        state.documents.write().await.insert(
            act_id,
            StoredDocument {
                id: "doc-1".to_owned(),
                act_id,
                template_id: "csc-ata-ag/v1".to_owned(),
                pdf_digest: "0".repeat(64),
                profile: "csc-sa-ag/v1".to_owned(),
                created_at: OffsetDateTime::now_utc(),
                pdf_bytes: b"%PDF-1.7\n".to_vec(),
            },
        );
    }

    fn verified_recovery_drill_receipt() -> BackupRecoveryDrillReceipt {
        BackupRecoveryDrillReceipt {
            id: "drill-1".to_owned(),
            created_at: "2026-07-14T12:00:00Z".to_owned(),
            archive: r"C:\chancela\backups\chancela-backup-test.zip".to_owned(),
            preflight_ok: true,
            preflight_ready: true,
            encrypted: Some(false),
            ledger_verified: true,
            manifest: Some(BackupRecoveryDrillManifestEvidence {
                schema: "chancela-backup/v1".to_owned(),
                version: 1,
                store_schema_version: 1,
                ledger_length: 3,
                ledger_verified: true,
                member_count: 3,
                sidecar_member_count: 1,
                db_member_present: true,
                total_member_bytes: 128,
            }),
            isolated_restore_verified: true,
            isolated_restore_verification: BackupRecoveryDrillIsolatedRestoreVerification {
                status: "verified".to_owned(),
                db_snapshot_materialized: true,
                db_snapshot_opened: true,
                state_loaded: true,
                ledger_verified: true,
                cleanup_verified: true,
                entity_count: 1,
                book_count: 1,
                act_count: 1,
                sidecar_root_count: 1,
                sidecar_materialized_file_count: 1,
                sidecar_materialized_bytes: 32,
                sqlcipher_encryption_verified: Some(false),
                findings: vec!["isolated snapshot ledger verified".to_owned()],
                errors: Vec::new(),
                next_step:
                    "record as preflight-only isolated snapshot evidence; authorize separately"
                        .to_owned(),
            },
            operator_notes: None,
            custody_location: None,
            restore_executed: false,
            live_db_swapped: false,
            sidecars_staged: false,
            ledger_restored_appended: false,
            data_deleted: false,
            offsite_custody_proven: false,
            legal_archive_certified: false,
        }
    }

    fn unverified_recovery_drill_receipt() -> BackupRecoveryDrillReceipt {
        let mut receipt = verified_recovery_drill_receipt();
        receipt.id = "drill-unverified".to_owned();
        receipt.manifest = Some(BackupRecoveryDrillManifestEvidence {
            schema: "chancela-backup/v1".to_owned(),
            version: 1,
            store_schema_version: 1,
            ledger_length: 3,
            ledger_verified: false,
            member_count: 0,
            sidecar_member_count: 0,
            db_member_present: false,
            total_member_bytes: 0,
        });
        receipt.isolated_restore_verification.status = "failed".to_owned();
        receipt.isolated_restore_verification.ledger_verified = false;
        receipt.isolated_restore_verification.cleanup_verified = false;
        receipt
    }

    async fn snapshot_counts(state: &AppState) -> (usize, usize, usize, usize, usize, usize) {
        (
            state.books.read().await.len(),
            state.acts.read().await.len(),
            state.documents.read().await.len(),
            state.backup_recovery_drill_receipts.read().await.len(),
            state.ledger.read().await.len(),
            state.signed_documents.read().await.len(),
        )
    }
}
