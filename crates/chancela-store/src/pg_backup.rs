//! **Portable logical backup / restore / recovery for the PostgreSQL backend** (wp15).
//!
//! The default SQLite backend snapshots the whole database *file* (`VACUUM INTO`) and restores it by
//! an atomic file-swap. That shape is meaningless for a networked Postgres — and the distroless
//! server image ships **no `pg_dump` binary** — so this module implements a self-contained,
//! app-driven **logical** export instead: it reads every application table through the pooled
//! connection and serializes it into a portable `.zip` bundle carrying the same integrity guarantees
//! the SQLite bundle provides (per-member fixity digests + the ledger head hash + a self-verifying
//! manifest).
//!
//! ## Bundle format — `chancela-pg-logical-backup/v1`
//!
//! A `.zip` with:
//! - `manifest.json` — a [`PgBackupManifest`]: format + `backend: "postgres"` tag, per-table
//!   `{sha256, rows, bytes}` fixity, the ledger `{length, head, verified}` summary, the source
//!   `instance_id`, and a `bundle_digest` self-digest over the manifest;
//! - `tables/<name>.jsonl` — one member per application table, one canonical `to_jsonb(row)` JSON
//!   text per line (deterministically ordered so the digest is reproducible across a round-trip);
//! - the instance sidecars (`settings.json`, `users.json`, …) verbatim, exactly like the SQLite
//!   bundle, so an export-first safety archive is complete on both backends.
//!
//! ## Guarantees (matching the SQLite path, t54 §2.5 / §4.1)
//!
//! - **consistent snapshot** — the export runs inside a `REPEATABLE READ`, `READ ONLY` transaction,
//!   so every table reflects one coherent point-in-time.
//! - **verify-before-trust** — [`verify_pg_backup_bundle`] validates the manifest self-digest, every
//!   per-table digest, AND re-runs the ledger hash-chain from the exported `events` (rejecting a
//!   flipped digest, a reordered/removed event, or a broken chain) *before* a single row is touched.
//! - **atomic restore** — [`PostgresBackend::logical_restore`] `TRUNCATE`s and re-`INSERT`s every
//!   table inside **one** transaction that re-verifies the loaded ledger head before `COMMIT`; any
//!   failure (or a re-verify mismatch) rolls the whole restore back, leaving the prior database
//!   intact — never a partial apply.
//! - **cross-backend** — a bundle is explicitly backend-tagged. A SQLite `.zip` (whose `manifest.json`
//!   is a file-swap [`crate::BackupManifest`], not a logical one) is rejected by
//!   [`verify_pg_backup_bundle`], and a Postgres logical bundle is rejected by the SQLite restore
//!   (its `manifest.json` does not deserialize as a file-swap manifest). The two are deliberately not
//!   interchangeable: the SQLite bundle carries an opaque binary `chancela.db`, the Postgres bundle
//!   carries logical rows.

use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use chancela_ledger::{Event, Ledger};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::pg::PostgresBackend;
use crate::recovery::{
    RECOVERY_ZIP_MAX_MEMBERS, RECOVERY_ZIP_MEMBER_UNCOMPRESSED_MAX_BYTES,
    RECOVERY_ZIP_TOTAL_UNCOMPRESSED_MAX_BYTES,
};
use crate::{BackupFile, BackupManifest, RawEventRow, StoreError, decode_hex, hex, schema};

/// The Postgres logical-backup bundle format tag.
pub const PG_BACKUP_FORMAT: &str = "chancela-pg-logical-backup/v1";
/// The backend tag a Postgres logical bundle carries (so restore can reject a foreign bundle).
pub const PG_BACKUP_BACKEND: &str = "postgres";

/// Every application table exported by a logical backup, in a stable order. `meta` is included so a
/// restore adopts the SOURCE instance's `instance_id`/`schema_version` (mirroring how a SQLite
/// restore swaps in the source DB file). Index-only objects are not tables and are not listed.
pub(crate) const PG_BACKUP_TABLES: &[&str] = &[
    "meta",
    "events",
    "entities",
    "books",
    "acts",
    "registry_extracts",
    "documents",
    "imported_books",
    "signed_documents",
    "pending_cmd_sessions",
    "imported_documents",
    "imported_document_review_history",
    "generated_document_dispatch_evidence",
    "paper_book_imports",
    "paper_book_ocr_drafts",
    "paper_book_ocr_conversion_dossiers",
    "paper_book_ocr_conversion_execution_artifacts",
    "follow_ups",
];

/// The one table whose surrogate `id` is a Postgres `GENERATED ALWAYS AS IDENTITY` column, so its
/// rows must be re-inserted with `OVERRIDING SYSTEM VALUE` to preserve the exact ids and its
/// identity sequence realigned afterwards.
const IDENTITY_TABLE: &str = "imported_document_review_history";

/// Per-table fixity recorded in a [`PgBackupManifest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PgBackupTable {
    /// The application table name.
    pub name: String,
    /// Lowercase-hex sha256 over the table's `tables/<name>.jsonl` member bytes.
    pub sha256: String,
    /// Number of rows (JSONL lines) exported for the table.
    pub rows: u64,
    /// Byte length of the `tables/<name>.jsonl` member.
    pub bytes: u64,
}

/// The integrity root of a `chancela-pg-logical-backup/v1` bundle. Three layers verify it:
/// (a) the manifest `bundle_digest` self-covers the manifest; (b) each `tables[].sha256` covers its
/// member; (c) the exported `events` re-run the ledger hash-chain and match `ledger_head`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PgBackupManifest {
    /// The format tag, [`PG_BACKUP_FORMAT`].
    pub format: String,
    /// The producing backend, [`PG_BACKUP_BACKEND`].
    pub backend: String,
    /// When the backup was taken (UTC, RFC 3339 on the wire).
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// The app version that produced the bundle.
    pub app_version: String,
    /// The store schema version of the exported database.
    pub store_schema_version: i64,
    /// The exporting install's stable id (provenance; adopted on restore).
    pub source_instance_id: String,
    /// Number of events in the exported ledger.
    pub ledger_length: u64,
    /// The exported chain head hash as lowercase hex, or `None` for an empty ledger.
    pub ledger_head: Option<String>,
    /// Whether the exported chain verified `Ok` at backup time.
    pub ledger_verified: bool,
    /// Per-table fixity for every member in [`PG_BACKUP_TABLES`].
    pub tables: Vec<PgBackupTable>,
    /// Per-member fixity for the bundled instance sidecars (verbatim files/dirs).
    pub sidecars: Vec<BackupFile>,
    /// sha256 (lowercase hex) over the canonical manifest with this field empty.
    pub bundle_digest: String,
}

impl PgBackupManifest {
    /// The self-digest preimage: this manifest with `bundle_digest` cleared.
    fn compute_digest(&self) -> Result<String, StoreError> {
        let mut m = self.clone();
        m.bundle_digest = String::new();
        Ok(hex(&Sha256::digest(serde_json::to_vec(&m)?)))
    }
}

/// The raw table dump produced by [`PostgresBackend::export_tables`], before the facade wraps it
/// with sidecars into the final bundle.
pub(crate) struct PgTablesExport {
    /// `("tables/<name>.jsonl", bytes)` members, one per table, in [`PG_BACKUP_TABLES`] order.
    pub members: Vec<(String, Vec<u8>)>,
    /// Per-table fixity.
    pub tables: Vec<PgBackupTable>,
    /// Reconstructed ledger length.
    pub ledger_length: u64,
    /// Reconstructed ledger head, lowercase hex.
    pub ledger_head: Option<String>,
    /// Whether the reconstructed ledger verified `Ok`.
    pub ledger_verified: bool,
    /// The `meta.instance_id` read from the snapshot.
    pub source_instance_id: String,
}

/// A bundle that passed [`verify_pg_backup_bundle`] verify-before-trust and is safe to load.
#[derive(Debug)]
pub(crate) struct VerifiedPgBackup {
    /// The verified manifest.
    pub manifest: PgBackupManifest,
    /// Table name → its rows as canonical JSON text (one per row), ready for `jsonb_populate_record`.
    pub table_rows: BTreeMap<String, Vec<String>>,
    /// Every raw zip member (used to materialize sidecars on restore).
    pub members: HashMap<String, Vec<u8>>,
}

// =================================================================================================
// Export (backend) + facade wrapping
// =================================================================================================

impl PostgresBackend {
    /// Read every application table into a coherent logical dump inside a `REPEATABLE READ`,
    /// `READ ONLY` transaction. Each row is captured as canonical `to_jsonb(row)` text so the dump is
    /// portable and its digest reproducible; `events` are additionally reconstructed to compute the
    /// ledger head/length/verified summary from the very same snapshot.
    pub(crate) fn export_tables(&self) -> Result<PgTablesExport, StoreError> {
        let mut client = self.checkout()?;
        let mut txn = client.transaction()?;
        // Coherent point-in-time snapshot: set REPEATABLE READ, READ ONLY as the first statement of
        // the transaction (expressed in SQL so this stays independent of the driver's builder API).
        txn.batch_execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")?;

        let mut members = Vec::with_capacity(PG_BACKUP_TABLES.len());
        let mut tables = Vec::with_capacity(PG_BACKUP_TABLES.len());
        let mut events: Vec<Event> = Vec::new();
        let mut source_instance_id = String::new();

        for &table in PG_BACKUP_TABLES {
            // `events` must be seq-ordered for the ledger replay; every other table orders by its
            // canonical json text so the export is deterministic regardless of physical row order.
            let order_by = if table == "events" {
                "seq".to_owned()
            } else {
                "to_jsonb(t)::text".to_owned()
            };
            let sql = format!("SELECT to_jsonb(t)::text AS j FROM {table} t ORDER BY {order_by}");
            let rows = txn.query(&sql, &[])?;
            let row_jsons: Vec<String> = rows.iter().map(|r| r.get::<_, String>(0)).collect();

            if table == "events" {
                for j in &row_jsons {
                    events.push(pg_event_json_to_event(j)?);
                }
            }
            if table == "meta" {
                for j in &row_jsons {
                    if let Some((key, value)) = parse_meta_kv(j) {
                        if key == "instance_id" {
                            source_instance_id = value;
                        }
                    }
                }
            }

            let mut buf = Vec::new();
            for j in &row_jsons {
                buf.extend_from_slice(j.as_bytes());
                buf.push(b'\n');
            }
            tables.push(PgBackupTable {
                name: table.to_owned(),
                sha256: hex(&Sha256::digest(&buf)),
                rows: row_jsons.len() as u64,
                bytes: buf.len() as u64,
            });
            members.push((format!("tables/{table}.jsonl"), buf));
        }
        // Read-only: committing simply ends the snapshot (nothing was written).
        txn.commit()?;

        let (ledger, chain_status) = Ledger::try_from_events(events);
        Ok(PgTablesExport {
            members,
            tables,
            ledger_length: ledger.len() as u64,
            ledger_head: ledger.head().map(|h| hex(&h)),
            ledger_verified: chain_status.is_ok(),
            source_instance_id,
        })
    }

    /// Load a verified logical bundle into this backend **transactionally and atomically**.
    ///
    /// One transaction `TRUNCATE`s every table, re-`INSERT`s each dumped row via
    /// `jsonb_populate_record` (with `OVERRIDING SYSTEM VALUE` for the IDENTITY-keyed table so the
    /// original surrogate ids survive), realigns that table's identity sequence, then re-reads and
    /// re-verifies the ledger head **before** `COMMIT`. Any error — including a post-load ledger
    /// re-verify mismatch — drops the transaction, rolling every change back so the prior database is
    /// left untouched (never a partial restore).
    pub(crate) fn logical_restore(&self, verified: &VerifiedPgBackup) -> Result<(), StoreError> {
        let mut writer = self.writer();
        let mut txn = writer.transaction()?;

        // TRUNCATE all tables in one statement; RESTART IDENTITY resets the review-history sequence.
        let truncate = format!("TRUNCATE {} RESTART IDENTITY", PG_BACKUP_TABLES.join(", "));
        txn.batch_execute(&truncate)?;

        for &table in PG_BACKUP_TABLES {
            let overriding = if table == IDENTITY_TABLE {
                "OVERRIDING SYSTEM VALUE "
            } else {
                ""
            };
            let insert = format!(
                // `postgres` binds `String` as TEXT, so cast through text before jsonb.
                "INSERT INTO {table} {overriding}SELECT \
                 (jsonb_populate_record(NULL::{table}, $1::text::jsonb)).*"
            );
            if let Some(rows) = verified.table_rows.get(table) {
                for row_json in rows {
                    txn.execute(&insert, &[&row_json])?;
                }
            }
        }

        // Realign the IDENTITY sequence so future inserts never collide with a restored id.
        txn.batch_execute(&format!(
            "SELECT setval(pg_get_serial_sequence('{IDENTITY_TABLE}', 'id'), \
             GREATEST(COALESCE((SELECT MAX(id) FROM {IDENTITY_TABLE}), 0), 1), \
             (SELECT COUNT(*) FROM {IDENTITY_TABLE}) > 0)"
        ))?;

        // Re-verify the ledger from the freshly-loaded rows BEFORE committing (atomic guarantee).
        let mut loaded_events = Vec::new();
        for row in txn.query(
            "SELECT to_jsonb(t)::text AS j FROM events t ORDER BY seq",
            &[],
        )? {
            loaded_events.push(pg_event_json_to_event(&row.get::<_, String>(0))?);
        }
        let (ledger, chain_status) = Ledger::try_from_events(loaded_events);
        if chain_status.is_err() {
            return Err(StoreError::BadBackup(
                "restored ledger failed to re-verify after load; rolling the restore back"
                    .to_owned(),
            ));
        }
        let head = ledger.head().map(|h| hex(&h));
        if head != verified.manifest.ledger_head
            || ledger.len() as u64 != verified.manifest.ledger_length
        {
            return Err(StoreError::BadBackup(
                "restored ledger head/length does not match the manifest after load; rolling back"
                    .to_owned(),
            ));
        }

        txn.commit()?;
        Ok(())
    }
}

impl crate::Store {
    /// Produce a portable logical backup of the Postgres backend and retain it under
    /// `<data_dir>/backups/`, returning the frozen [`BackupManifest`] shape so the api/facade is
    /// unchanged. The archive bundles every table dump plus the instance sidecars.
    pub(crate) fn pg_backup(
        &self,
        backend: &PostgresBackend,
        data_dir: &Path,
        sidecars: &[PathBuf],
    ) -> Result<BackupManifest, StoreError> {
        let created_at = OffsetDateTime::now_utc();
        let stamp = crate::utc_stamp(created_at);
        let backups_dir = data_dir.join("backups");
        std::fs::create_dir_all(&backups_dir)?;

        let export = backend.export_tables()?;

        // Sidecars verbatim (files or directory trees), read into memory with per-member fixity.
        let mut sidecar_members: Vec<(String, Vec<u8>)> = Vec::new();
        let mut sidecar_files: Vec<BackupFile> = Vec::new();
        for sidecar in sidecars {
            if let Some(base) = sidecar
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
            {
                collect_sidecar_members(&base, sidecar, &mut sidecar_members, &mut sidecar_files)?;
            }
        }

        let mut manifest = PgBackupManifest {
            format: PG_BACKUP_FORMAT.to_owned(),
            backend: PG_BACKUP_BACKEND.to_owned(),
            created_at,
            app_version: env!("CARGO_PKG_VERSION").to_owned(),
            store_schema_version: schema::SCHEMA_VERSION,
            source_instance_id: export.source_instance_id,
            ledger_length: export.ledger_length,
            ledger_head: export.ledger_head.clone(),
            ledger_verified: export.ledger_verified,
            tables: export.tables.clone(),
            sidecars: sidecar_files.clone(),
            bundle_digest: String::new(),
        };
        manifest.bundle_digest = manifest.compute_digest()?;

        let mut all_members = export.members;
        all_members.extend(sidecar_members);
        let bundle = assemble_pg_bundle(&manifest, &all_members)?;

        // Write via a temp file + atomic rename, mirroring the SQLite backup.
        let final_path = backups_dir.join(format!("chancela-backup-{stamp}.zip"));
        let tmp_path = backups_dir.join(format!(".chancela-backup-{stamp}.zip.tmp"));
        std::fs::write(&tmp_path, &bundle)?;
        std::fs::rename(&tmp_path, &final_path).inspect_err(|_| {
            let _ = std::fs::remove_file(&tmp_path);
        })?;
        let bytes = std::fs::metadata(&final_path)?.len();

        // Map to the frozen BackupManifest: `files` lists the table members + sidecars with digests.
        let mut files: Vec<BackupFile> = export
            .tables
            .iter()
            .map(|t| BackupFile {
                name: format!("tables/{}.jsonl", t.name),
                sha256: t.sha256.clone(),
                bytes: t.bytes,
            })
            .collect();
        files.extend(sidecar_files);

        Ok(BackupManifest {
            path: final_path.to_string_lossy().into_owned(),
            bytes,
            created_at,
            app_version: env!("CARGO_PKG_VERSION").to_string(),
            store_schema_version: schema::SCHEMA_VERSION,
            ledger_length: manifest.ledger_length,
            ledger_head: manifest.ledger_head,
            ledger_verified: manifest.ledger_verified,
            files,
        })
    }
}

// =================================================================================================
// Verify-before-trust (pure — no live database needed, so it is unit-testable)
// =================================================================================================

/// Verify a Postgres logical bundle end-to-end WITHOUT touching any database: manifest self-digest,
/// backend/format tag, every per-table digest, and the ledger hash-chain re-run from the exported
/// `events` (which must verify `Ok` and match the manifest head/length). Any failure is a
/// [`StoreError::BadBackup`] and nothing is loaded. A SQLite file-swap bundle is rejected here
/// because its `manifest.json` does not deserialize as a [`PgBackupManifest`].
pub(crate) fn verify_pg_backup_bundle(bytes: &[u8]) -> Result<VerifiedPgBackup, StoreError> {
    let (manifest, members) = read_pg_bundle(bytes)?;

    if manifest.format != PG_BACKUP_FORMAT || manifest.backend != PG_BACKUP_BACKEND {
        return Err(StoreError::BadBackup(format!(
            "not a {PG_BACKUP_FORMAT} postgres bundle (format {:?}, backend {:?})",
            manifest.format, manifest.backend
        )));
    }
    if manifest.compute_digest()? != manifest.bundle_digest {
        return Err(StoreError::BadBackup(
            "bundle_digest does not match the manifest (tampered manifest)".to_owned(),
        ));
    }

    // Every table listed in the manifest must be present with a matching digest, and every listed
    // table name must be a known application table (no smuggled member).
    let mut table_rows: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut seen: BTreeMap<&str, ()> = BTreeMap::new();
    for t in &manifest.tables {
        if !PG_BACKUP_TABLES.contains(&t.name.as_str()) {
            return Err(StoreError::BadBackup(format!(
                "manifest lists unknown table {}",
                t.name
            )));
        }
        seen.insert(t.name.as_str(), ());
        let member_name = format!("tables/{}.jsonl", t.name);
        let member = members.get(&member_name).ok_or_else(|| {
            StoreError::BadBackup(format!("bundle is missing table member {member_name}"))
        })?;
        if hex(&Sha256::digest(member)) != t.sha256 {
            return Err(StoreError::BadBackup(format!(
                "table {} digest mismatch (tampered dump)",
                t.name
            )));
        }
        let rows = parse_table_jsonl(member).map_err(|e| {
            StoreError::BadBackup(format!("table {} member is not valid JSONL: {e}", t.name))
        })?;
        if rows.len() as u64 != t.rows {
            return Err(StoreError::BadBackup(format!(
                "table {} row count mismatch (manifest {}, member {})",
                t.name,
                t.rows,
                rows.len()
            )));
        }
        table_rows.insert(t.name.clone(), rows);
    }
    for &table in PG_BACKUP_TABLES {
        if !seen.contains_key(table) {
            return Err(StoreError::BadBackup(format!(
                "manifest does not cover required table {table}"
            )));
        }
    }

    // Every non-table/non-manifest member is a restorable sidecar. Require each one to be named in
    // the manifest with matching fixity, and reject manifest sidecars that are absent or unsafe, so
    // restore never installs bytes that were outside the verified integrity root.
    let mut expected_sidecars: BTreeMap<&str, &BackupFile> = BTreeMap::new();
    for sidecar in &manifest.sidecars {
        validate_pg_sidecar_member_name(&sidecar.name)?;
        if expected_sidecars
            .insert(sidecar.name.as_str(), sidecar)
            .is_some()
        {
            return Err(StoreError::BadBackup(format!(
                "manifest lists duplicate sidecar {}",
                sidecar.name
            )));
        }
        let member = members.get(&sidecar.name).ok_or_else(|| {
            StoreError::BadBackup(format!("bundle is missing sidecar member {}", sidecar.name))
        })?;
        if member.len() as u64 != sidecar.bytes {
            return Err(StoreError::BadBackup(format!(
                "sidecar {} byte count mismatch (manifest {}, member {})",
                sidecar.name,
                sidecar.bytes,
                member.len()
            )));
        }
        if hex(&Sha256::digest(member)) != sidecar.sha256 {
            return Err(StoreError::BadBackup(format!(
                "sidecar {} digest mismatch (tampered sidecar)",
                sidecar.name
            )));
        }
    }
    for name in members.keys() {
        if name == "manifest.json" || name.starts_with("tables/") {
            continue;
        }
        if !expected_sidecars.contains_key(name.as_str()) {
            return Err(StoreError::BadBackup(format!(
                "bundle contains unmanifested sidecar member {name}"
            )));
        }
    }

    // Re-run the ledger hash-chain from the exported events — catches a reordered/removed event or a
    // broken chain even when every per-member digest is internally consistent.
    let events = table_rows
        .get("events")
        .map(|rows| {
            rows.iter()
                .map(|j| pg_event_json_to_event(j))
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?
        .unwrap_or_default();
    let (ledger, chain_status) = Ledger::try_from_events(events);
    if chain_status.is_err() {
        return Err(StoreError::BadBackup(
            "bundle ledger does not verify — refusing to restore a broken chain".to_owned(),
        ));
    }
    if ledger.len() as u64 != manifest.ledger_length
        || ledger.head().map(|h| hex(&h)) != manifest.ledger_head
    {
        return Err(StoreError::BadBackup(
            "bundle ledger head/length does not match the manifest".to_owned(),
        ));
    }

    Ok(VerifiedPgBackup {
        manifest,
        table_rows,
        members,
    })
}

// =================================================================================================
// Zip / member helpers
// =================================================================================================

/// Assemble the bundle `.zip` (manifest first, then members) into an in-memory buffer.
fn assemble_pg_bundle(
    manifest: &PgBackupManifest,
    members: &[(String, Vec<u8>)],
) -> Result<Vec<u8>, StoreError> {
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts = zip::write::SimpleFileOptions::default();
    zip.start_file("manifest.json", opts)?;
    zip.write_all(&serde_json::to_vec_pretty(manifest)?)?;
    for (name, bytes) in members {
        if name.contains("..") {
            continue;
        }
        zip.start_file(name.as_str(), opts)?;
        zip.write_all(bytes)?;
    }
    Ok(zip.finish()?.into_inner())
}

/// Read a Postgres logical bundle `.zip` into (manifest, member-name → bytes), under the shared
/// zip-bomb ceilings. A missing/unreadable `manifest.json` — including a SQLite file-swap manifest —
/// is a hard [`StoreError::BadBackup`].
fn read_pg_bundle(
    bytes: &[u8],
) -> Result<(PgBackupManifest, HashMap<String, Vec<u8>>), StoreError> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes))
        .map_err(|e| StoreError::BadBackup(format!("not a readable zip: {e}")))?;
    if archive.len() > RECOVERY_ZIP_MAX_MEMBERS {
        return Err(StoreError::BadBackup(format!(
            "bundle has {} members, exceeding the {RECOVERY_ZIP_MAX_MEMBERS}-member limit",
            archive.len()
        )));
    }
    let mut members = HashMap::new();
    let mut consumed: u64 = 0;
    for i in 0..archive.len() {
        let mut f = archive.by_index(i)?;
        let name = f.name().to_owned();
        if name.contains("..") {
            return Err(StoreError::BadBackup(format!(
                "path-traversal in member name {name:?}"
            )));
        }
        let mut buf = Vec::new();
        f.by_ref()
            .take(RECOVERY_ZIP_MEMBER_UNCOMPRESSED_MAX_BYTES + 1)
            .read_to_end(&mut buf)?;
        if buf.len() as u64 > RECOVERY_ZIP_MEMBER_UNCOMPRESSED_MAX_BYTES {
            return Err(StoreError::BadBackup(format!(
                "bundle member {name} exceeds the per-member decompression limit (possible zip bomb)"
            )));
        }
        consumed = consumed.saturating_add(buf.len() as u64);
        if consumed > RECOVERY_ZIP_TOTAL_UNCOMPRESSED_MAX_BYTES {
            return Err(StoreError::BadBackup(
                "bundle members exceed the total decompression limit (possible zip bomb)"
                    .to_owned(),
            ));
        }
        members.insert(name, buf);
    }
    let manifest_bytes = members
        .get("manifest.json")
        .ok_or_else(|| StoreError::BadBackup("bundle is missing manifest.json".to_owned()))?;
    let manifest: PgBackupManifest = serde_json::from_slice(manifest_bytes).map_err(|e| {
        StoreError::BadBackup(format!("not a postgres logical backup manifest: {e}"))
    })?;
    Ok((manifest, members))
}

/// Read one sidecar path into `(member_name, bytes)` entries with per-member fixity: a file becomes
/// one member named `base`; a directory recurses (member names carry the relative sub-path);
/// symlinks and missing paths are skipped. Mirrors the SQLite backup's `add_path_to_zip`.
fn collect_sidecar_members(
    name: &str,
    path: &Path,
    members: &mut Vec<(String, Vec<u8>)>,
    files: &mut Vec<BackupFile>,
) -> Result<(), StoreError> {
    if name.contains("..") {
        return Ok(());
    }
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(StoreError::Io(e)),
    };
    if meta.file_type().is_symlink() {
        return Ok(());
    }
    if meta.is_dir() {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let child = format!("{name}/{}", entry.file_name().to_string_lossy());
            collect_sidecar_members(&child, &entry.path(), members, files)?;
        }
    } else if meta.is_file() {
        let bytes = std::fs::read(path)?;
        files.push(BackupFile {
            name: name.to_owned(),
            sha256: hex(&Sha256::digest(&bytes)),
            bytes: bytes.len() as u64,
        });
        members.push((name.to_owned(), bytes));
    }
    Ok(())
}

fn validate_pg_sidecar_member_name(name: &str) -> Result<(), StoreError> {
    if name.is_empty()
        || name.contains('\\')
        || name == "manifest.json"
        || name.starts_with("tables/")
    {
        return Err(StoreError::BadBackup(format!(
            "unsafe sidecar member name {name:?}"
        )));
    }
    let path = Path::new(name);
    if path.is_absolute() {
        return Err(StoreError::BadBackup(format!(
            "unsafe sidecar member name {name:?}"
        )));
    }
    let mut saw_component = false;
    for component in path.components() {
        match component {
            std::path::Component::Normal(_) => saw_component = true,
            _ => {
                return Err(StoreError::BadBackup(format!(
                    "unsafe sidecar member name {name:?}"
                )));
            }
        }
    }
    if !saw_component {
        return Err(StoreError::BadBackup(format!(
            "unsafe sidecar member name {name:?}"
        )));
    }
    Ok(())
}

/// Split a bundle's members into the sidecar members (everything that is neither a `tables/…` dump
/// nor the manifest), so a restore can materialize them exactly like the SQLite path.
pub(crate) fn sidecar_members(members: &HashMap<String, Vec<u8>>) -> BTreeMap<String, Vec<u8>> {
    members
        .iter()
        .filter(|(name, _)| name.as_str() != "manifest.json" && !name.starts_with("tables/"))
        .map(|(name, bytes)| (name.clone(), bytes.clone()))
        .collect()
}

// =================================================================================================
// Row / event decoding
// =================================================================================================

/// Parse a `tables/<name>.jsonl` member into one canonical JSON text per row.
fn parse_table_jsonl(bytes: &[u8]) -> Result<Vec<String>, StoreError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|e| StoreError::BadBackup(format!("table member is not utf-8: {e}")))?;
    let mut rows = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // Validate it is JSON (so a corrupt member is caught before it reaches Postgres).
        serde_json::from_str::<serde_json::Value>(line)
            .map_err(|e| StoreError::BadBackup(format!("bad table row json: {e}")))?;
        rows.push(line.to_owned());
    }
    Ok(rows)
}

/// The `to_jsonb(events_row)` shape, with the three digest columns as Postgres `\x…` bytea text.
#[derive(Deserialize)]
struct PgEventRowJson {
    seq: i64,
    id: String,
    actor: String,
    justification: Option<String>,
    timestamp: String,
    scope: String,
    kind: String,
    payload_digest: String,
    prev_hash: String,
    hash: String,
    links: String,
}

/// Rebuild a full-fidelity [`Event`] from one exported `events` row json (used for verify-time and
/// post-load ledger re-verification only; the restore itself feeds the json straight back into
/// `jsonb_populate_record`, so it is never lossy).
fn pg_event_json_to_event(json: &str) -> Result<Event, StoreError> {
    let row: PgEventRowJson = serde_json::from_str(json)
        .map_err(|e| StoreError::BadBackup(format!("bad events row json: {e}")))?;
    let raw = RawEventRow {
        seq: row.seq,
        id: row.id,
        actor: row.actor,
        justification: row.justification,
        timestamp: row.timestamp,
        scope: row.scope,
        kind: row.kind,
        payload_digest: decode_pg_bytea(&row.payload_digest, "payload_digest")?,
        prev_hash: decode_pg_bytea(&row.prev_hash, "prev_hash")?,
        hash: decode_pg_bytea(&row.hash, "hash")?,
        links: row.links,
    };
    raw.into_event()
}

/// Decode Postgres bytea `\x`-hex text (as produced by `to_jsonb(bytea)`) into bytes.
fn decode_pg_bytea(value: &str, what: &str) -> Result<Vec<u8>, StoreError> {
    let hexpart = value
        .strip_prefix("\\x")
        .ok_or_else(|| StoreError::BadBackup(format!("{what} is not \\x-prefixed bytea text")))?;
    decode_hex(hexpart, what)
}

/// Extract `(key, value)` from a `to_jsonb(meta_row)` json (`{"key":…, "value":…}`).
fn parse_meta_kv(json: &str) -> Option<(String, String)> {
    #[derive(Deserialize)]
    struct Meta {
        key: String,
        value: String,
    }
    serde_json::from_str::<Meta>(json)
        .ok()
        .map(|m| (m.key, m.value))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal, VALID logical bundle for a one-event ledger, entirely in-memory (no DB).
    fn sample_bundle() -> (Vec<u8>, PgBackupManifest) {
        let mut ledger = Ledger::new();
        let ev = ledger
            .append(
                "amelia.marques",
                "application",
                "app.started",
                None,
                b"seed",
            )
            .clone();

        // The `events` row json as Postgres `to_jsonb` would render it.
        let event_json = serde_json::json!({
            "seq": ev.seq as i64,
            "id": ev.id.to_string(),
            "actor": ev.actor,
            "justification": ev.justification,
            "timestamp": crate::format_event_timestamp(ev.timestamp),
            "scope": ev.scope,
            "kind": ev.kind,
            "payload_digest": format!("\\x{}", hex(&ev.payload_digest)),
            "prev_hash": format!("\\x{}", hex(&ev.prev_hash)),
            "hash": format!("\\x{}", hex(&ev.hash)),
            "links": serde_json::to_string(&ev.links).unwrap(),
        })
        .to_string();
        let meta_json = serde_json::json!({"key": "instance_id", "value": "inst-1"}).to_string();

        let mut members: Vec<(String, Vec<u8>)> = Vec::new();
        let mut tables = Vec::new();
        for &table in PG_BACKUP_TABLES {
            let mut buf = Vec::new();
            match table {
                "events" => {
                    buf.extend_from_slice(event_json.as_bytes());
                    buf.push(b'\n');
                }
                "meta" => {
                    buf.extend_from_slice(meta_json.as_bytes());
                    buf.push(b'\n');
                }
                _ => {}
            }
            let rows = if buf.is_empty() { 0 } else { 1 };
            tables.push(PgBackupTable {
                name: table.to_owned(),
                sha256: hex(&Sha256::digest(&buf)),
                rows,
                bytes: buf.len() as u64,
            });
            members.push((format!("tables/{table}.jsonl"), buf));
        }

        let mut manifest = PgBackupManifest {
            format: PG_BACKUP_FORMAT.to_owned(),
            backend: PG_BACKUP_BACKEND.to_owned(),
            created_at: OffsetDateTime::UNIX_EPOCH,
            app_version: "test".to_owned(),
            store_schema_version: schema::SCHEMA_VERSION,
            source_instance_id: "inst-1".to_owned(),
            ledger_length: 1,
            ledger_head: Some(hex(&ev.hash)),
            ledger_verified: true,
            tables,
            sidecars: Vec::new(),
            bundle_digest: String::new(),
        };
        manifest.bundle_digest = manifest.compute_digest().unwrap();
        let bundle = assemble_pg_bundle(&manifest, &members).unwrap();
        (bundle, manifest)
    }

    #[test]
    fn verifies_a_wellformed_bundle() {
        let (bundle, manifest) = sample_bundle();
        let verified = verify_pg_backup_bundle(&bundle).expect("valid bundle verifies");
        assert_eq!(verified.manifest.ledger_head, manifest.ledger_head);
        assert_eq!(verified.table_rows.get("events").map(Vec::len), Some(1));
        assert_eq!(verified.manifest.source_instance_id, "inst-1");
    }

    #[test]
    fn verifies_manifested_sidecars_and_extracts_them() {
        let (bundle, mut manifest) = sample_bundle();
        let (_, mut members) = read_pg_bundle(&bundle).unwrap();
        let sidecar_bytes = br#"{"theme":"light"}"#.to_vec();
        manifest.sidecars = vec![BackupFile {
            name: "settings.json".to_owned(),
            sha256: hex(&Sha256::digest(&sidecar_bytes)),
            bytes: sidecar_bytes.len() as u64,
        }];
        manifest.bundle_digest = manifest.compute_digest().unwrap();
        members.insert("settings.json".to_owned(), sidecar_bytes.clone());
        let mut member_vec: Vec<(String, Vec<u8>)> = members
            .into_iter()
            .filter(|(n, _)| n != "manifest.json")
            .collect();
        member_vec.sort_by(|a, b| a.0.cmp(&b.0));
        let bundle = assemble_pg_bundle(&manifest, &member_vec).unwrap();

        let verified = verify_pg_backup_bundle(&bundle).expect("manifested sidecar verifies");
        let sidecars = sidecar_members(&verified.members);
        assert_eq!(sidecars.get("settings.json"), Some(&sidecar_bytes));
    }

    #[test]
    fn rejects_unmanifested_sidecar_members() {
        let (bundle, mut manifest) = sample_bundle();
        let (_, mut members) = read_pg_bundle(&bundle).unwrap();
        members.insert("api-keys.json".to_owned(), b"attacker".to_vec());
        manifest.bundle_digest = manifest.compute_digest().unwrap();
        let mut member_vec: Vec<(String, Vec<u8>)> = members
            .into_iter()
            .filter(|(n, _)| n != "manifest.json")
            .collect();
        member_vec.sort_by(|a, b| a.0.cmp(&b.0));
        let bundle = assemble_pg_bundle(&manifest, &member_vec).unwrap();

        let err = verify_pg_backup_bundle(&bundle).unwrap_err();
        assert!(
            matches!(err, StoreError::BadBackup(ref m) if m.contains("unmanifested sidecar")),
            "{err:?}"
        );
    }

    #[test]
    fn rejects_tampered_manifested_sidecar_members() {
        let (bundle, mut manifest) = sample_bundle();
        let (_, mut members) = read_pg_bundle(&bundle).unwrap();
        let benign = b"benign".to_vec();
        let attacker = b"attacker".to_vec();
        manifest.sidecars = vec![BackupFile {
            name: "users.json".to_owned(),
            sha256: hex(&Sha256::digest(&benign)),
            bytes: benign.len() as u64,
        }];
        manifest.bundle_digest = manifest.compute_digest().unwrap();
        members.insert("users.json".to_owned(), attacker);
        let mut member_vec: Vec<(String, Vec<u8>)> = members
            .into_iter()
            .filter(|(n, _)| n != "manifest.json")
            .collect();
        member_vec.sort_by(|a, b| a.0.cmp(&b.0));
        let bundle = assemble_pg_bundle(&manifest, &member_vec).unwrap();

        let err = verify_pg_backup_bundle(&bundle).unwrap_err();
        assert!(
            matches!(err, StoreError::BadBackup(ref m) if m.contains("sidecar users.json byte count mismatch") || m.contains("sidecar users.json digest mismatch")),
            "{err:?}"
        );
    }

    #[test]
    fn rejects_a_flipped_table_digest() {
        let (bundle, _) = sample_bundle();
        // Re-open, corrupt the events member digest in the manifest, re-seal the bundle_digest.
        let (mut manifest, members) = read_pg_bundle(&bundle).unwrap();
        for t in &mut manifest.tables {
            if t.name == "events" {
                t.sha256 = "0".repeat(64);
            }
        }
        manifest.bundle_digest = manifest.compute_digest().unwrap();
        let mut member_vec: Vec<(String, Vec<u8>)> = members
            .into_iter()
            .filter(|(n, _)| n != "manifest.json")
            .collect();
        member_vec.sort_by(|a, b| a.0.cmp(&b.0));
        let tampered = assemble_pg_bundle(&manifest, &member_vec).unwrap();
        let err = verify_pg_backup_bundle(&tampered).unwrap_err();
        assert!(matches!(err, StoreError::BadBackup(_)), "{err:?}");
    }

    #[test]
    fn rejects_a_reordered_event_that_breaks_the_chain() {
        // A two-event ledger dumped in the WRONG seq order must fail the chain re-verification.
        let mut ledger = Ledger::new();
        let e0 = ledger
            .append("amelia.marques", "application", "app.started", None, b"a")
            .clone();
        let e1 = ledger
            .append("amelia.marques", "application", "app.next", None, b"b")
            .clone();

        let to_row = |ev: &Event| {
            serde_json::json!({
                "seq": ev.seq as i64, "id": ev.id.to_string(), "actor": ev.actor,
                "justification": ev.justification,
                "timestamp": crate::format_event_timestamp(ev.timestamp),
                "scope": ev.scope, "kind": ev.kind,
                "payload_digest": format!("\\x{}", hex(&ev.payload_digest)),
                "prev_hash": format!("\\x{}", hex(&ev.prev_hash)),
                "hash": format!("\\x{}", hex(&ev.hash)),
                "links": serde_json::to_string(&ev.links).unwrap(),
            })
            .to_string()
        };

        // Reversed order in the dump — try_from_events reads in file order, so the chain breaks.
        let mut events_buf = Vec::new();
        for ev in [&e1, &e0] {
            events_buf.extend_from_slice(to_row(ev).as_bytes());
            events_buf.push(b'\n');
        }

        let mut members: Vec<(String, Vec<u8>)> = Vec::new();
        let mut tables = Vec::new();
        for &table in PG_BACKUP_TABLES {
            let buf = if table == "events" {
                events_buf.clone()
            } else {
                Vec::new()
            };
            tables.push(PgBackupTable {
                name: table.to_owned(),
                sha256: hex(&Sha256::digest(&buf)),
                rows: if table == "events" { 2 } else { 0 },
                bytes: buf.len() as u64,
            });
            members.push((format!("tables/{table}.jsonl"), buf));
        }
        let mut manifest = PgBackupManifest {
            format: PG_BACKUP_FORMAT.to_owned(),
            backend: PG_BACKUP_BACKEND.to_owned(),
            created_at: OffsetDateTime::UNIX_EPOCH,
            app_version: "test".to_owned(),
            store_schema_version: schema::SCHEMA_VERSION,
            source_instance_id: String::new(),
            ledger_length: 2,
            ledger_head: Some(hex(&e1.hash)),
            ledger_verified: true,
            tables,
            sidecars: Vec::new(),
            bundle_digest: String::new(),
        };
        manifest.bundle_digest = manifest.compute_digest().unwrap();
        let bundle = assemble_pg_bundle(&manifest, &members).unwrap();

        let err = verify_pg_backup_bundle(&bundle).unwrap_err();
        assert!(matches!(err, StoreError::BadBackup(_)), "{err:?}");
    }

    #[test]
    fn rejects_a_sqlite_file_swap_bundle() {
        // A SQLite backup manifest (no format/backend/tables) must not pass PG verification.
        let sqlite_manifest = serde_json::json!({
            "path": "/x/chancela-backup.zip",
            "bytes": 10u64,
            "created_at": "1970-01-01T00:00:00Z",
            "app_version": "test",
            "store_schema_version": schema::SCHEMA_VERSION,
            "ledger_length": 0u64,
            "ledger_head": serde_json::Value::Null,
            "ledger_verified": true,
            "files": []
        });
        let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let opts = zip::write::SimpleFileOptions::default();
        zip.start_file("manifest.json", opts).unwrap();
        zip.write_all(sqlite_manifest.to_string().as_bytes())
            .unwrap();
        zip.start_file("chancela.db", opts).unwrap();
        zip.write_all(b"SQLite format 3\0").unwrap();
        let bundle = zip.finish().unwrap().into_inner();

        let err = verify_pg_backup_bundle(&bundle).unwrap_err();
        assert!(
            matches!(err, StoreError::BadBackup(ref m) if m.contains("postgres logical backup manifest")),
            "{err:?}"
        );
    }

    /// Reverse cross-backend direction (no live DB needed): the default SQLite restore refuses a
    /// Postgres logical bundle, because its `manifest.json` is not a file-swap `BackupManifest`.
    #[test]
    fn sqlite_restore_rejects_a_postgres_logical_bundle() {
        let (bundle, _) = sample_bundle();
        let dir =
            std::env::temp_dir().join(format!("chancela-wp15-xrestore-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let bundle_path = dir.join("pg-bundle.zip");
        std::fs::write(&bundle_path, &bundle).unwrap();

        let store = crate::Store::open(&dir).unwrap();
        let mut ledger = store.load().unwrap().ledger;
        let err = store
            .restore(
                &mut ledger,
                &bundle_path,
                &dir,
                "amelia.marques",
                OffsetDateTime::UNIX_EPOCH,
            )
            .unwrap_err();
        assert!(matches!(err, StoreError::BadBackup(_)), "{err:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Live-PG atomic-failure proof: a bundle that PASSES verify (valid JSON, matching digests,
    /// coherent chain) but whose load fails partway (a NOT NULL violation in a poisoned row) rolls
    /// the WHOLE restore back — the pre-restore rows all survive, never a partial apply.
    #[test]
    #[ignore = "requires a live PostgreSQL at DATABASE_URL"]
    fn a_mid_load_failure_rolls_the_whole_restore_back() {
        let Some(database_url) = std::env::var("DATABASE_URL").ok().filter(|s| !s.is_empty())
        else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let store =
            crate::Store::open_backend(crate::StoreBackendSelection::Postgres { database_url })
                .expect("open postgres backend");

        let dir =
            std::env::temp_dir().join(format!("chancela-wp15-atomic-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();

        // Blank slate + one event + follow-up F1.
        let mut ledger = store.load().unwrap().ledger;
        store
            .reset(
                &mut ledger,
                &dir,
                crate::recovery::ResetScope::BackendFactory,
                false,
                &[],
                "amelia.marques",
                OffsetDateTime::UNIX_EPOCH,
            )
            .unwrap();
        let ev = ledger
            .append(
                "amelia.marques",
                "application",
                "app.started",
                None,
                b"seed",
            )
            .clone();
        store.persist(|tx| tx.append_event(&ev)).unwrap();

        let act = chancela_core::ActId(uuid::Uuid::new_v4());
        let f1 = sample_follow_up(act, "f1");
        store.persist(|tx| tx.upsert_follow_up(&f1)).unwrap();

        // Backup at {F1}, then add F2 past the backup.
        let manifest = store.backup(&dir, &[]).expect("logical backup");
        let f2 = sample_follow_up(act, "f2");
        store.persist(|tx| tx.upsert_follow_up(&f2)).unwrap();

        // Poison the bundle's follow_ups dump with a NOT NULL-violating row that still verifies.
        let bundle = std::fs::read(&manifest.path).unwrap();
        let (mut manifest_obj, mut members) = read_pg_bundle(&bundle).unwrap();
        let member_name = "tables/follow_ups.jsonl".to_owned();
        let poison = serde_json::json!({
            "id": format!("poison-{}", uuid::Uuid::new_v4()),
            "act_id": act.to_string(),
            "agenda_number": serde_json::Value::Null,
            "deliberation_index": serde_json::Value::Null,
            "title": serde_json::Value::Null, // NOT NULL → INSERT fails mid-load
            "detail": serde_json::Value::Null,
            "due_date": serde_json::Value::Null,
            "assignee": serde_json::Value::Null,
            "assignee_display": serde_json::Value::Null,
            "status": "Open",
            "created_at": "2020-01-01T00:00:00Z",
            "created_by": "x",
        })
        .to_string();
        {
            let buf = members.get_mut(&member_name).unwrap();
            buf.extend_from_slice(poison.as_bytes());
            buf.push(b'\n');
            let new_bytes = buf.clone();
            for t in &mut manifest_obj.tables {
                if t.name == "follow_ups" {
                    t.sha256 = hex(&Sha256::digest(&new_bytes));
                    t.rows += 1;
                    t.bytes = new_bytes.len() as u64;
                }
            }
        }
        manifest_obj.bundle_digest = manifest_obj.compute_digest().unwrap();
        let member_vec: Vec<(String, Vec<u8>)> = members
            .into_iter()
            .filter(|(n, _)| n != "manifest.json")
            .collect();
        let poisoned = assemble_pg_bundle(&manifest_obj, &member_vec).unwrap();
        // Sanity: the poisoned bundle still passes verify-before-trust.
        verify_pg_backup_bundle(&poisoned).expect("poisoned bundle verifies (failure is at load)");
        let poisoned_path = dir.join("poisoned.zip");
        std::fs::write(&poisoned_path, &poisoned).unwrap();

        // Restore must fail AND roll back entirely → both F1 and F2 survive.
        let mut restore_ledger = ledger.clone();
        let err = store
            .restore(
                &mut restore_ledger,
                &poisoned_path,
                &dir,
                "amelia.marques",
                OffsetDateTime::UNIX_EPOCH,
            )
            .expect_err("mid-load failure must error");
        eprintln!("expected mid-load restore failure: {err:?}");
        assert!(
            store.follow_up(&f1.id).unwrap().is_some(),
            "F1 survives the rolled-back restore"
        );
        assert!(
            store.follow_up(&f2.id).unwrap().is_some(),
            "F2 (post-backup) survives — proves nothing was partially applied"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(test)]
    fn sample_follow_up(act_id: chancela_core::ActId, tag: &str) -> crate::StoredFollowUp {
        crate::StoredFollowUp {
            id: format!("fu-{tag}-{}", uuid::Uuid::new_v4()),
            act_id,
            agenda_number: None,
            deliberation_index: None,
            title: format!("task {tag}"),
            detail: None,
            due_date: None,
            assignee: None,
            assignee_display: None,
            status: crate::StoredFollowUpStatus::Open,
            created_at: OffsetDateTime::UNIX_EPOCH,
            created_by: "amelia.marques".to_owned(),
            completed_at: None,
            completed_by: None,
        }
    }
}
