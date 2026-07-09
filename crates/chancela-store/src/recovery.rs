//! Chain-integrity **recovery**, per-book **portability**, and **data management** (t54-E2).
//!
//! This module layers the recovery/lifecycle plane onto the durable [`Store`](crate::Store): it
//! never touches the frozen ledger preimage nor the existing persist/backup paths, and every
//! operation here honours four absolutes:
//!
//! - **verify-before-trust** — an imported bundle or a restore archive is verified *before* it is
//!   ever persisted or swapped in; a broken/forged bundle is **quarantined** (isolated, read-only,
//!   under its ORIGINAL ids), a bad backup is **refused** (the live store untouched);
//! - **no-secrets export** — a bundle carries only entity/book/act/document/signed-document/event
//!   data; the store crate has no access to `users.json`, sessions, or attestation-private
//!   material, so a secret *cannot structurally* enter a bundle (test-enforced);
//! - **atomic wipe** — a destructive reset is all-or-rollback (one transaction), never a partial
//!   half-wipe, and always after the export-first safety rail when requested;
//! - **nothing silently erased** — every recovery/lifecycle op emits a chained audit event
//!   (`ledger.{exported,imported,restored,reinitialized}` / `data.wiped`, scope `recovery`), or —
//!   for a true factory reset that destroys the ledger — the retained export-first archive *is* the
//!   record.
//!
//! ## Import isolation — why a foreign book chain is never merged onto the live spine
//!
//! Every event's global `seq`/`prev_hash` is part of its hash preimage, and a book chain carries
//! its own global sequence from the exporting instance. Re-inserting those events onto *this*
//! instance's contiguous global spine would force a re-numbering — i.e. a re-hash of every event —
//! which destroys the tamper-evidence (the same reason id-rename/merge is forbidden, §2.5). So an
//! imported book is held in the read-only `imported_books` namespace under its ORIGINAL ids and
//! verified *in isolation* via [`chancela_ledger::Ledger::verify_bundle_chain`]; the verdict marks
//! whether that chain re-verified clean. A per-book import is therefore a **verified historical
//! record / restore vehicle**, not a re-activation onto the live, appendable spine.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use chancela_core::{Act, Book, BookId};
use chancela_ledger::{BreakKind, ChainBreak, ChainId, Event, Ledger, RECOVERY_SCOPE};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::{
    BackupFile, BackupManifest, DB_FILE, Store, StoreError, Tx, decrypt_backup_envelope, hex,
    is_encrypted_backup, open_connection, utc_stamp,
};

/// The frozen portable-bundle format tag (a `.zip`); see the module docs and plan §2.4.
pub const BUNDLE_FORMAT: &str = "chancela-book-bundle/v1";

/// Audit-event kinds emitted by this module (all scope [`RECOVERY_SCOPE`] ⇒ the Application chain).
pub const EXPORTED_EVENT_KIND: &str = "ledger.exported";
/// See [`EXPORTED_EVENT_KIND`].
pub const IMPORTED_EVENT_KIND: &str = "ledger.imported";
/// See [`EXPORTED_EVENT_KIND`].
pub const RESTORED_EVENT_KIND: &str = "ledger.restored";
/// See [`EXPORTED_EVENT_KIND`].
pub const REINITIALIZED_EVENT_KIND: &str = "ledger.reinitialized";
/// Sole NEW audit-event kind (§2.11): a domain-wipe that PRESERVES the ledger records itself here.
pub const DATA_WIPED_EVENT_KIND: &str = "data.wiped";
const PDF_CONTENT_TYPE: &str = "application/pdf";
const SIGNED_PDF_B_B_PROFILE: &str = "application/pdf; profile=PAdES-B-B";
const SIGNED_PDF_B_T_PROFILE: &str = "application/pdf; profile=PAdES-B-T";

// =================================================================================================
// Bundle format (export) — §2.4
// =================================================================================================

/// What a bundle contains. `Instance` is reserved for a future whole-store export.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BundleKind {
    /// One book + its entity + acts + documents + the book chain's member events.
    Book,
}

/// A compact summary of the exported book chain, verifiable independently of the bundle members.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainSummary {
    /// Number of member events in the book chain.
    pub length: u64,
    /// Hash of the chain's genesis (`book.opened`) member, lowercase hex, or `None` when empty.
    pub genesis_hash: Option<String>,
    /// Hash of the chain's head member, lowercase hex, or `None` when empty.
    pub head_hash: Option<String>,
    /// Whether the book chain re-verified cleanly at export time.
    pub verified: bool,
}

/// An OPTIONAL exporter attestation over [`BundleManifest::bundle_digest`]. Always `None` in v1;
/// reserved so a signed bundle can be added without a format bump.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleSignature {
    /// The signature algorithm identifier.
    pub algo: String,
    /// The signer's public key (encoding is algorithm-defined).
    pub public_key: String,
    /// The detached signature over `bundle_digest`.
    pub signature: String,
}

/// The integrity root of a `chancela-book-bundle/v1` (§2.4). Three layers verify a bundle:
/// (a) each event self-hashes; (b) the book chain links verify end-to-end
/// ([`chancela_ledger::Ledger::verify_bundle_chain`]); (c) `files[].sha256` + `bundle_digest` cover
/// the members + the manifest itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleManifest {
    /// The format tag, [`BUNDLE_FORMAT`].
    pub format: String,
    /// What the bundle carries.
    pub bundle_kind: BundleKind,
    /// When the bundle was exported (UTC, RFC 3339 on the wire).
    #[serde(with = "time::serde::rfc3339")]
    pub exported_at: OffsetDateTime,
    /// The app version that produced the bundle.
    pub app_version: String,
    /// The exporting install's stable id (provenance).
    pub source_instance_id: String,
    /// The exported book's owning entity id (ORIGINAL).
    pub entity_id: String,
    /// The exported book id (ORIGINAL).
    pub book_id: String,
    /// The book chain summary (length / genesis / head / verified).
    pub book_chain: ChainSummary,
    /// Per-member `{name, sha256, bytes}` for every file in the bundle (except `manifest.json`).
    pub files: Vec<BackupFile>,
    /// sha256 (lowercase hex) over the canonical manifest with this field empty + `signature: None`.
    pub bundle_digest: String,
    /// An optional exporter attestation over `bundle_digest` (always `None` in v1).
    pub signature: Option<BundleSignature>,
}

#[derive(Debug, Serialize)]
struct BundleDocumentMetadata {
    format: &'static str,
    sidecar: &'static str,
    owner: BundleDocumentOwner,
    document: BundleBaseDocumentMetadata,
    final_artifact: BundleFinalArtifact,
    signed: Option<BundleSignedDocumentRef>,
}

#[derive(Debug, Serialize)]
struct BundleDocumentOwner {
    kind: &'static str,
    id: String,
    book_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    act_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct BundleBaseDocumentMetadata {
    id: String,
    role: &'static str,
    template_id: String,
    profile: String,
    created_at: String,
    pdf_digest: String,
    pdf_path: String,
    content_type: &'static str,
}

#[derive(Debug, Serialize)]
struct BundleFinalArtifact {
    kind: &'static str,
    path: String,
    sha256: String,
    content_type: &'static str,
}

#[derive(Debug, Serialize)]
struct BundleSignedDocumentRef {
    signed_pdf_digest: String,
    signature_family: String,
    evidentiary_level: String,
    signing_time: String,
    signed_at: String,
    signed_pdf_path: String,
    signing_metadata_path: String,
    timestamp_token_present: bool,
}

#[derive(Debug, Serialize)]
struct BundleSigningMetadata {
    format: &'static str,
    sidecar: &'static str,
    act_id: String,
    document_id: String,
    source_document_present: bool,
    source_document_path: String,
    signed_pdf_path: String,
    signed_pdf_digest: String,
    signature_family: String,
    evidentiary_level: String,
    trusted_list_status: Option<String>,
    signer_cert_subject: Option<String>,
    signing_time: String,
    signed_at: String,
    signer_certificate_sha256: String,
    timestamp_token_present: bool,
    timestamp_token_sha256: Option<String>,
}

/// The result of [`Store::export_book`]: the retained archive path, the raw bytes (for download),
/// and the manifest (the integrity root).
#[derive(Debug, Clone)]
pub struct ExportOutcome {
    /// Absolute path of the retained bundle under `<data_dir>/exports/`.
    pub path: PathBuf,
    /// The bundle `.zip` bytes (returned for immediate download).
    pub bytes: Vec<u8>,
    /// The bundle manifest.
    pub manifest: BundleManifest,
}

// =================================================================================================
// Import — §2.5
// =================================================================================================

/// What to do when an imported book's id collides with an existing (live or imported) book id.
///
/// Ids are hashed into every event, so renaming on import would re-hash the chain and destroy its
/// tamper-evidence — a rename/merge is therefore **not offered**. The only integrity-preserving
/// choices are to refuse, or to keep an isolated read-only copy under the ORIGINAL ids.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum CollisionPolicy {
    /// Refuse the import on any id collision (the safe default).
    #[default]
    Refuse,
    /// Keep an isolated, read-only copy under the ORIGINAL ids (never merged as a live chain).
    QuarantineCopy,
}

/// The verify-before-trust verdict of a per-book import.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImportVerdict {
    /// The bundle's members and book chain verified cleanly.
    Verified,
    /// The bundle was broken/forged/tampered: isolated, read-only, never trusted as valid.
    Quarantined {
        /// The precise first break (or the tamper detail) that quarantined the bundle.
        break_: ChainBreak,
    },
}

/// The result of [`Store::import_book`].
#[derive(Debug, Clone)]
pub struct ImportOutcome {
    /// The fresh id minted for this import (primary key of the isolation record).
    pub import_id: String,
    /// The bundle's original entity id.
    pub entity_id: String,
    /// The bundle's original book id.
    pub book_id: String,
    /// Verified, or Quarantined with the break.
    pub verdict: ImportVerdict,
    /// The exporting install's stable id (provenance).
    pub source_instance_id: String,
    /// The manifest's self-digest.
    pub bundle_digest: String,
    /// Whether the book id collided with an existing (live or imported) book.
    pub collided: bool,
}

/// One row of the import isolation namespace, for the api's import feed (`imported_books`).
#[derive(Debug, Clone)]
pub struct ImportRecord {
    /// The import's id.
    pub import_id: String,
    /// The bundle's original entity id.
    pub entity_id: String,
    /// The bundle's original book id.
    pub book_id: String,
    /// The exporting install's stable id.
    pub source_instance_id: String,
    /// The manifest's self-digest.
    pub bundle_digest: String,
    /// The verify-before-trust verdict.
    pub verdict: ImportVerdict,
    /// Whether the book id collided at import time.
    pub collided: bool,
    /// When the import happened (UTC).
    pub imported_at: OffsetDateTime,
}

// =================================================================================================
// Whole-store restore — §2.5
// =================================================================================================

/// The result of [`Store::restore`].
#[derive(Debug, Clone)]
pub struct RestoreOutcome {
    /// The archive the store was restored from.
    pub restored_from: PathBuf,
    /// The restored ledger length (including the appended `ledger.restored`).
    pub ledger_length: u64,
    /// The restored ledger head, lowercase hex.
    pub ledger_head: Option<String>,
    /// Always `true` on success (the snapshot verified `Ok` before the swap).
    pub chain_verified: bool,
}

struct VerifiedRestoreZip<'a> {
    ledger: &'a mut Ledger,
    archive: &'a Path,
    data_dir: &'a Path,
    actor: &'a str,
    at: OffsetDateTime,
    archive_bytes: &'a [u8],
    sidecars: &'a [PathBuf],
}

// =================================================================================================
// Start-over — §2.7
// =================================================================================================

/// Which start-over granularity was performed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StartOverScope {
    /// One book: archive + `ledger.reinitialized` + a fresh successor book shell.
    Book,
    /// The whole instance: archive + clear + a fresh ledger whose genesis is `ledger.reinitialized`.
    Instance,
}

/// The result of a start-over (archive-then-fresh, non-destructive to the archive).
#[derive(Debug, Clone)]
pub struct ReinitOutcome {
    /// Book or Instance.
    pub scope: StartOverScope,
    /// The retained archive taken before reinitialization.
    pub archive_path: PathBuf,
    /// The archive's identifying digest.
    pub archived_bundle_digest: String,
    /// The archived (old) book id, for a per-book start-over.
    pub old_book_id: Option<String>,
    /// The fresh successor book id (in `Created` state), for a per-book start-over. The api opens it
    /// with a termo de abertura via the existing `open_and_seal_book` path (which needs domain input
    /// the store must not fabricate).
    pub new_book_id: Option<String>,
}

// =================================================================================================
// Data management: wipe / factory reset — §2.11
// =================================================================================================

/// The scope of a destructive [`Store::reset`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResetScope {
    /// Clear domain data (entities/books/acts/documents/registry_extracts/imported) but PRESERVE the
    /// append-only ledger and emit a chained `data.wiped` — the wipe stays auditable.
    BackendDomain,
    /// Clear EVERYTHING (store rows incl. the ledger + the sidecar files) to a blank first-run
    /// instance. The ledger is gone, so the export-first archive IS the record.
    BackendFactory,
}

/// The result of [`Store::reset`].
#[derive(Debug, Clone)]
pub struct ResetOutcome {
    /// The scope that was reset.
    pub scope: ResetScope,
    /// The export-first archive taken before clearing (present when `export_first`).
    pub export_archive: Option<PathBuf>,
    /// What was cleared (table + sidecar-file names), for the operator-facing receipt.
    pub cleared: Vec<String>,
}

// =================================================================================================
// Chained audit-event payload records (serialized into each event's justification + payload_digest)
// =================================================================================================

/// Payload of a `ledger.exported` event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportRecord {
    /// Who exported.
    pub actor: String,
    /// When (caller-supplied).
    #[serde(with = "time::serde::rfc3339")]
    pub at: OffsetDateTime,
    /// The exported entity id.
    pub entity_id: String,
    /// The exported book id.
    pub book_id: String,
    /// The bundle's self-digest.
    pub bundle_digest: String,
    /// The retained archive path.
    pub archive: String,
}

/// Payload of a `ledger.imported` event (verdict + provenance; NEVER any secret material).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportProvenanceRecord {
    /// Who imported.
    pub actor: String,
    /// When.
    #[serde(with = "time::serde::rfc3339")]
    pub at: OffsetDateTime,
    /// The import id.
    pub import_id: String,
    /// The bundle's original entity id.
    pub entity_id: String,
    /// The bundle's original book id.
    pub book_id: String,
    /// The exporting install's stable id.
    pub source_instance_id: String,
    /// The bundle's self-digest.
    pub bundle_digest: String,
    /// `"verified"` or `"quarantined"`.
    pub verdict: String,
    /// Whether the book id collided.
    pub collided: bool,
}

/// Payload of a `ledger.restored` event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreRecord {
    /// Who restored.
    pub actor: String,
    /// When.
    #[serde(with = "time::serde::rfc3339")]
    pub at: OffsetDateTime,
    /// The archive restored from.
    pub archive: String,
    /// The restored snapshot's source instance id, if readable.
    pub source_instance_id: Option<String>,
    /// The restored ledger length (before the `ledger.restored` event was appended).
    pub restored_length: u64,
    /// The restored head hash before the `ledger.restored` event.
    pub restored_head: Option<String>,
}

/// Payload of a `ledger.reinitialized` event (start-over, §2.7).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReinitRecord {
    /// Who reinitialized.
    pub actor: String,
    /// When.
    #[serde(with = "time::serde::rfc3339")]
    pub at: OffsetDateTime,
    /// The operator's reason.
    pub reason: String,
    /// `"book"` or `"instance"`.
    pub scope: String,
    /// The digest of the archive taken before reinitialization.
    pub archived_bundle_digest: String,
    /// The old book id (per-book start-over).
    pub old_book_id: Option<String>,
    /// The old head hash (book head for per-book, global head for whole-instance).
    pub old_head: Option<String>,
    /// The fresh successor book id (per-book start-over).
    pub new_book_id: Option<String>,
}

/// Payload of a `data.wiped` event (domain wipe that preserved the ledger, §2.11).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WipeRecord {
    /// Who wiped.
    pub actor: String,
    /// When.
    #[serde(with = "time::serde::rfc3339")]
    pub at: OffsetDateTime,
    /// The reset scope string (`"backend_domain"`).
    pub scope: String,
    /// What was cleared.
    pub cleared: Vec<String>,
    /// The export-first archive path, if one was taken.
    pub export_archive: Option<String>,
    /// The export-first archive digest, if one was taken.
    pub archive_digest: Option<String>,
}

// =================================================================================================
// Store impl — the recovery/lifecycle plane
// =================================================================================================

impl Store {
    /// **Export** one book to a self-verifying `chancela-book-bundle/v1` `.zip` (§2.4).
    ///
    /// Gathers the book, its entity, its acts, the latest generated document per act, and the BOOK
    /// chain's member events (full fidelity, so their hashes recompute), builds the manifest with
    /// per-member sha256 + a `bundle_digest`, retains the archive under `<data_dir>/exports/`, emits
    /// a chained `ledger.exported`, and returns the bytes for download.
    ///
    /// **No-secrets guard:** only entity/book/act/document/event data is serialized — this crate
    /// has no access to `users.json`/sessions/attestation-private material, so a secret cannot enter
    /// a bundle (test-enforced).
    ///
    /// `at` is caller-supplied (no clock in core). Appends the audit event via the passed `ledger`
    /// (kept in sync) and persists it write-through.
    pub fn export_book(
        &self,
        ledger: &mut Ledger,
        book_id: BookId,
        data_dir: &Path,
        actor: &str,
        at: OffsetDateTime,
    ) -> Result<ExportOutcome, StoreError> {
        let export = self.build_book_bundle(ledger, book_id, at)?;

        // Retain under <data_dir>/exports/ (§8-C) and keep the bytes for download.
        let exports = data_dir.join("exports");
        std::fs::create_dir_all(&exports)?;
        let path = exports.join(format!("book-{book_id}-{}.zip", utc_stamp(at)));
        std::fs::write(&path, &export.bytes)?;

        // Chained ledger.exported (scope recovery ⇒ Application chain; keeps the book sign-chain pure).
        let record = ExportRecord {
            actor: actor.to_owned(),
            at,
            entity_id: export.manifest.entity_id.clone(),
            book_id: export.manifest.book_id.clone(),
            bundle_digest: export.manifest.bundle_digest.clone(),
            archive: path.to_string_lossy().into_owned(),
        };
        self.append_recovery_event(ledger, EXPORTED_EVENT_KIND, actor, &record)?;

        Ok(ExportOutcome {
            path,
            bytes: export.bytes,
            manifest: export.manifest,
        })
    }

    /// **Import** a per-book bundle with **verify-before-trust** (§2.5).
    ///
    /// Verifies the manifest self-digest, every member's sha256, and the BOOK chain
    /// ([`Ledger::verify_bundle_chain`]) BEFORE persisting. A clean bundle ⇒ `Verified`; any
    /// break/tamper ⇒ `Quarantined { break_ }` (isolated, read-only, under ORIGINAL ids, never
    /// merged as a live chain). On an id collision, [`CollisionPolicy::Refuse`] errors and imports
    /// nothing; [`CollisionPolicy::QuarantineCopy`] keeps the isolated copy. Records provenance +
    /// verdict for both outcomes and emits a chained `ledger.imported`.
    pub fn import_book(
        &self,
        ledger: &mut Ledger,
        bundle: &Path,
        policy: CollisionPolicy,
        actor: &str,
        at: OffsetDateTime,
    ) -> Result<ImportOutcome, StoreError> {
        let bundle_bytes = std::fs::read(bundle)?;
        // Parse enough to record provenance; a truly-unparseable input is a hard error (no record).
        let (manifest, members) = read_bundle(&bundle_bytes)?;
        let entity_id = manifest.entity_id.clone();
        let book_id = manifest.book_id.clone();
        let source_instance_id = manifest.source_instance_id.clone();
        let bundle_digest = manifest.bundle_digest.clone();

        // VERIFY-BEFORE-TRUST. Any failure quarantines (never trusted), it does not error.
        let mut verdict_break: Option<ChainBreak> = None;
        if compute_bundle_digest(&manifest)? != manifest.bundle_digest {
            verdict_break = Some(tamper_break(
                &book_id,
                "bundle_digest does not match the manifest",
            ));
        }
        if verdict_break.is_none() {
            for f in &manifest.files {
                let ok = members
                    .get(&f.name)
                    .is_some_and(|bytes| hex(&Sha256::digest(bytes)) == f.sha256);
                if !ok {
                    verdict_break = Some(tamper_break(
                        &book_id,
                        &format!(
                            "bundle member {} is missing or its digest does not match",
                            f.name
                        ),
                    ));
                    break;
                }
            }
        }
        if verdict_break.is_none() {
            let events = parse_events_jsonl(members.get("events.jsonl").map_or(&[][..], |v| v))?;
            let chain = ChainId::Book(book_id.clone());
            if let Err(b) = Ledger::verify_bundle_chain(&events, &chain) {
                verdict_break = Some(b);
            }
        }
        let verdict = match &verdict_break {
            None => ImportVerdict::Verified,
            Some(b) => ImportVerdict::Quarantined { break_: b.clone() },
        };
        let verdict_str = if verdict_break.is_none() {
            "verified"
        } else {
            "quarantined"
        };

        // Collision: Refuse (default) touches nothing; QuarantineCopy keeps the isolated copy.
        let collided = self.book_exists_anywhere(&book_id)?;
        if collided && matches!(policy, CollisionPolicy::Refuse) {
            return Err(StoreError::ImportCollision { book_id });
        }

        // Persist the isolated import record + the chained ledger.imported in ONE transaction.
        let import_id = uuid::Uuid::new_v4().to_string();
        let break_json = verdict_break
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        let imported_at = at.format(&Rfc3339).unwrap_or_default();
        let provenance = ImportProvenanceRecord {
            actor: actor.to_owned(),
            at,
            import_id: import_id.clone(),
            entity_id: entity_id.clone(),
            book_id: book_id.clone(),
            source_instance_id: source_instance_id.clone(),
            bundle_digest: bundle_digest.clone(),
            verdict: verdict_str.to_owned(),
            collided,
        };
        let prov_json = serde_json::to_string(&provenance)?;

        let snapshot = ledger.clone();
        let ev = ledger
            .append(
                actor,
                RECOVERY_SCOPE,
                IMPORTED_EVENT_KIND,
                Some(&prov_json),
                prov_json.as_bytes(),
            )
            .clone();
        let persisted = self.persist(|tx| {
            tx.raw().execute(
                "INSERT INTO imported_books \
                 (import_id, entity_id, book_id, source_instance_id, bundle_digest, verdict, \
                  break_json, collided, imported_at, bundle_bytes) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    import_id,
                    entity_id,
                    book_id,
                    source_instance_id,
                    bundle_digest,
                    verdict_str,
                    break_json,
                    collided as i64,
                    imported_at,
                    bundle_bytes,
                ],
            )?;
            tx.append_event(&ev)?;
            Ok(())
        });
        if let Err(e) = persisted {
            *ledger = snapshot;
            return Err(e);
        }

        Ok(ImportOutcome {
            import_id,
            entity_id,
            book_id,
            verdict,
            source_instance_id,
            bundle_digest,
            collided,
        })
    }

    /// List the isolated import namespace (verified + quarantined), newest first — the api's import
    /// feed. Read-only; the bundle bytes are fetched separately via [`Store::imported_bundle`].
    pub fn imported_books(&self) -> Result<Vec<ImportRecord>, StoreError> {
        let guard = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = guard.prepare(
            "SELECT import_id, entity_id, book_id, source_instance_id, bundle_digest, verdict, \
             break_json, collided, imported_at FROM imported_books ORDER BY imported_at DESC, rowid DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, String>(8)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (
                import_id,
                entity_id,
                book_id,
                source,
                digest,
                verdict_str,
                break_json,
                collided,
                at,
            ) = row?;
            let verdict = reconstruct_verdict(&verdict_str, break_json.as_deref(), &book_id)?;
            out.push(ImportRecord {
                import_id,
                entity_id,
                book_id,
                source_instance_id: source,
                bundle_digest: digest,
                verdict,
                collided: collided != 0,
                imported_at: OffsetDateTime::parse(&at, &Rfc3339)
                    .unwrap_or(OffsetDateTime::UNIX_EPOCH),
            });
        }
        Ok(out)
    }

    /// Fetch the retained, read-only `.zip` bytes of one import (for inspection / re-export /
    /// compare), or `None` if the import id is unknown.
    pub fn imported_bundle(&self, import_id: &str) -> Result<Option<Vec<u8>>, StoreError> {
        let guard = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt =
            guard.prepare("SELECT bundle_bytes FROM imported_books WHERE import_id = ?1")?;
        Ok(stmt
            .query_row(params![import_id], |row| row.get::<_, Vec<u8>>(0))
            .optional()?)
    }

    /// **Whole-store restore** from a full backup archive (§2.5) — verify-before-swap.
    ///
    /// Reads the archive manifest, verifies EVERY member's sha256 AND that the snapshot's ledger
    /// verifies `Ok`, BEFORE the atomic swap. A bad archive ⇒ [`StoreError::BadBackup`] and the live
    /// store is left untouched. On success the db file + the in-process connection are swapped
    /// atomically, the restored ledger is loaded, a chained `ledger.restored` is appended, and
    /// `*ledger` is replaced with the restored chain.
    pub fn restore(
        &self,
        ledger: &mut Ledger,
        archive: &Path,
        data_dir: &Path,
        actor: &str,
        at: OffsetDateTime,
    ) -> Result<RestoreOutcome, StoreError> {
        self.restore_with_sidecars(ledger, archive, data_dir, actor, at, &[])
    }

    /// Whole-store restore from a plaintext legacy zip, also replacing the supplied instance
    /// sidecars. Sidecar replacements are staged only after the archive and snapshot verify.
    pub fn restore_with_sidecars(
        &self,
        ledger: &mut Ledger,
        archive: &Path,
        data_dir: &Path,
        actor: &str,
        at: OffsetDateTime,
        sidecars: &[PathBuf],
    ) -> Result<RestoreOutcome, StoreError> {
        let archive_bytes = std::fs::read(archive)?;
        if is_encrypted_backup(&archive_bytes) {
            return Err(StoreError::BadBackup(
                "encrypted backup requires an explicit passphrase".to_owned(),
            ));
        }
        self.restore_from_verified_zip_bytes(VerifiedRestoreZip {
            ledger,
            archive,
            data_dir,
            actor,
            at,
            archive_bytes: &archive_bytes,
            sidecars,
        })
    }

    /// Whole-store restore from an encrypted backup envelope. The passphrase is supplied
    /// explicitly by the caller; no local sidecar or account recovery phrase is consulted.
    pub fn restore_encrypted(
        &self,
        ledger: &mut Ledger,
        archive: &Path,
        data_dir: &Path,
        actor: &str,
        at: OffsetDateTime,
        passphrase: &str,
    ) -> Result<RestoreOutcome, StoreError> {
        self.restore_encrypted_with_sidecars(ledger, archive, data_dir, actor, at, passphrase, &[])
    }

    /// Whole-store restore from an encrypted backup envelope, replacing the supplied sidecars after
    /// decryption, member-digest verification, and snapshot ledger verification all succeed.
    // Keep parity with the plaintext sidecar restore plus explicit caller-supplied passphrase; the
    // shared restore implementation below receives a compact context struct.
    #[allow(clippy::too_many_arguments)]
    pub fn restore_encrypted_with_sidecars(
        &self,
        ledger: &mut Ledger,
        archive: &Path,
        data_dir: &Path,
        actor: &str,
        at: OffsetDateTime,
        passphrase: &str,
        sidecars: &[PathBuf],
    ) -> Result<RestoreOutcome, StoreError> {
        let envelope_bytes = std::fs::read(archive)?;
        let archive_bytes = decrypt_backup_envelope(&envelope_bytes, passphrase)?;
        self.restore_from_verified_zip_bytes(VerifiedRestoreZip {
            ledger,
            archive,
            data_dir,
            actor,
            at,
            archive_bytes: &archive_bytes,
            sidecars,
        })
    }

    fn restore_from_verified_zip_bytes(
        &self,
        restore: VerifiedRestoreZip<'_>,
    ) -> Result<RestoreOutcome, StoreError> {
        let VerifiedRestoreZip {
            ledger,
            archive,
            data_dir,
            actor,
            at,
            archive_bytes,
            sidecars,
        } = restore;
        let mut zip = zip::ZipArchive::new(std::io::Cursor::new(archive_bytes))
            .map_err(|e| StoreError::BadBackup(format!("not a readable zip: {e}")))?;

        // Manifest.
        let manifest: BackupManifest = {
            let mut m = zip
                .by_name("manifest.json")
                .map_err(|e| StoreError::BadBackup(format!("no manifest.json: {e}")))?;
            let mut s = String::new();
            m.read_to_string(&mut s)?;
            serde_json::from_str(&s)
                .map_err(|e| StoreError::BadBackup(format!("bad manifest: {e}")))?
        };

        // Verify every member digest BEFORE trusting the archive, and keep the verified bytes for
        // the later db/sidecar staging phase.
        let mut verified_members = BTreeMap::<String, Vec<u8>>::new();
        for f in &manifest.files {
            validate_backup_member_name(&f.name)?;
            let mut member = zip
                .by_name(&f.name)
                .map_err(|_| StoreError::BadBackup(format!("archive missing member {}", f.name)))?;
            let mut bytes = Vec::new();
            member.read_to_end(&mut bytes)?;
            if hex(&Sha256::digest(&bytes)) != f.sha256 {
                return Err(StoreError::BadBackup(format!(
                    "member {} digest mismatch",
                    f.name
                )));
            }
            if verified_members.insert(f.name.clone(), bytes).is_some() {
                return Err(StoreError::BadBackup(format!(
                    "manifest lists duplicate member {}",
                    f.name
                )));
            }
        }

        // Extract the snapshot db and verify its ledger verifies Ok BEFORE the swap.
        let db_bytes = verified_members
            .get(DB_FILE)
            .ok_or_else(|| StoreError::BadBackup(format!("archive has no {DB_FILE}")))?
            .clone();
        let verify_dir = data_dir.join(format!(".restore-verify-{}", utc_stamp(at)));
        let _ = std::fs::remove_dir_all(&verify_dir);
        std::fs::create_dir_all(&verify_dir)?;
        std::fs::write(verify_dir.join(DB_FILE), &db_bytes)?;
        let snapshot_ok = {
            let verify_store = Store::open(&verify_dir)?;
            verify_store.load()?.chain_status.is_ok()
        };
        let _ = std::fs::remove_dir_all(&verify_dir);
        if !snapshot_ok {
            return Err(StoreError::BadBackup(
                "snapshot ledger does not verify — refusing to restore a broken backup".to_owned(),
            ));
        }

        // Stage sidecar bytes after all archive verification and before touching live state. If
        // this fails, the live DB and sidecars are still untouched.
        let sidecar_stage = data_dir.join(format!(".restore-sidecars-{}", utc_stamp(at)));
        let _ = std::fs::remove_dir_all(&sidecar_stage);
        let staged_roots = stage_backup_sidecars(&sidecar_stage, &verified_members)?;

        // Atomic db swap plus sidecar replacement: free the live file, write the verified snapshot,
        // replace sidecar roots from the staging dir, then reopen the connection.
        {
            let mut guard = self.conn.lock().unwrap_or_else(|e| e.into_inner());
            let placeholder = rusqlite::Connection::open_in_memory()?;
            let old = std::mem::replace(&mut *guard, placeholder);
            drop(old); // release the OS handle so the file can be replaced (Windows-safe)
            let db = data_dir.join(DB_FILE);
            let _ = std::fs::remove_file(&db);
            let _ = std::fs::remove_file(data_dir.join(format!("{DB_FILE}-wal")));
            let _ = std::fs::remove_file(data_dir.join(format!("{DB_FILE}-shm")));
            std::fs::write(&db, &db_bytes)?;
            replace_live_sidecars(data_dir, &sidecar_stage, &staged_roots, sidecars)?;
            *guard = open_connection(data_dir)?;
        }
        let _ = std::fs::remove_dir_all(&sidecar_stage);

        // Load the restored chain, record the restore (chained), and hand the caller the new ledger.
        let restored = self.load()?;
        let mut restored_ledger = restored.ledger;
        let record = RestoreRecord {
            actor: actor.to_owned(),
            at,
            archive: archive.to_string_lossy().into_owned(),
            source_instance_id: self.instance_id().ok(),
            restored_length: restored_ledger.len() as u64,
            restored_head: restored_ledger.head().map(|h| hex(&h)),
        };
        self.append_recovery_event(&mut restored_ledger, RESTORED_EVENT_KIND, actor, &record)?;

        let ledger_length = restored_ledger.len() as u64;
        let ledger_head = restored_ledger.head().map(|h| hex(&h));
        *ledger = restored_ledger;
        Ok(RestoreOutcome {
            restored_from: archive.to_path_buf(),
            ledger_length,
            ledger_head,
            chain_verified: true,
        })
    }

    /// **Per-book start-over** (archive-then-fresh, non-destructive; §2.7).
    ///
    /// Archives the current book+chain first (retained, `ledger.exported`), then appends a chained
    /// `ledger.reinitialized`, then persists a fresh SUCCESSOR book shell (new id, `Created` state,
    /// referencing the old book). The old book's events remain append-only; nothing is erased. The
    /// api then opens the successor with a termo de abertura (`book.opened` genesis) via the existing
    /// `open_and_seal_book` path — that needs domain input the store must not fabricate.
    pub fn start_over_book(
        &self,
        ledger: &mut Ledger,
        book_id: BookId,
        reason: &str,
        actor: &str,
        at: OffsetDateTime,
        data_dir: &Path,
    ) -> Result<ReinitOutcome, StoreError> {
        let book = self
            .book_by_id(book_id)?
            .ok_or_else(|| StoreError::NotFound(format!("book {book_id}")))?;
        let old_head = ledger
            .chain_head(&ChainId::Book(book_id.to_string()))
            .map(|h| hex(&h));

        // 1. Archive-first (retained + chained ledger.exported).
        let export = self.export_book(ledger, book_id, data_dir, actor, at)?;

        // 2. The fresh successor shell (Created; opened later by the api).
        let new_book = Book::new_successor(book.entity_id, book.kind, book_id);
        let new_book_id = new_book.id;

        // 3. Chained ledger.reinitialized + the new book shell, atomically.
        let record = ReinitRecord {
            actor: actor.to_owned(),
            at,
            reason: reason.to_owned(),
            scope: "book".to_owned(),
            archived_bundle_digest: export.manifest.bundle_digest.clone(),
            old_book_id: Some(book_id.to_string()),
            old_head,
            new_book_id: Some(new_book_id.to_string()),
        };
        let json = serde_json::to_string(&record)?;
        let snapshot = ledger.clone();
        let ev = ledger
            .append(
                actor,
                RECOVERY_SCOPE,
                REINITIALIZED_EVENT_KIND,
                Some(&json),
                json.as_bytes(),
            )
            .clone();
        let persisted = self.persist(|tx| {
            tx.append_event(&ev)?;
            tx.upsert_book(&new_book)?;
            Ok(())
        });
        if let Err(e) = persisted {
            *ledger = snapshot;
            return Err(e);
        }

        Ok(ReinitOutcome {
            scope: StartOverScope::Book,
            archive_path: export.path,
            archived_bundle_digest: export.manifest.bundle_digest,
            old_book_id: Some(book_id.to_string()),
            new_book_id: Some(new_book_id.to_string()),
        })
    }

    /// **Whole-instance start-over** (archive-then-fresh; §2.7 / user decision).
    ///
    /// Archives the whole instance first (retained full backup), then clears all domain + event +
    /// imported rows and seeds a FRESH ledger whose genesis (seq 0) IS a `ledger.reinitialized`
    /// referencing the archive. Everything old is preserved in the retained archive; the live
    /// instance starts clean with a chained record of the reinitialization.
    pub fn start_over_instance(
        &self,
        ledger: &mut Ledger,
        reason: &str,
        actor: &str,
        at: OffsetDateTime,
        data_dir: &Path,
        sidecars: &[PathBuf],
    ) -> Result<ReinitOutcome, StoreError> {
        let (archive_path, archive_digest) = self.archive_instance(data_dir, sidecars)?;

        let mut fresh = Ledger::new();
        let record = ReinitRecord {
            actor: actor.to_owned(),
            at,
            reason: reason.to_owned(),
            scope: "instance".to_owned(),
            archived_bundle_digest: archive_digest.clone(),
            old_book_id: None,
            old_head: ledger.head().map(|h| hex(&h)),
            new_book_id: None,
        };
        let json = serde_json::to_string(&record)?;
        let ev = fresh
            .append(
                actor,
                RECOVERY_SCOPE,
                REINITIALIZED_EVENT_KIND,
                Some(&json),
                json.as_bytes(),
            )
            .clone();
        self.persist(|tx| {
            clear_domain(tx)?;
            clear_imported(tx)?;
            clear_events(tx)?;
            tx.append_event(&ev)?;
            Ok(())
        })?;
        *ledger = fresh;

        Ok(ReinitOutcome {
            scope: StartOverScope::Instance,
            archive_path,
            archived_bundle_digest: archive_digest,
            old_book_id: None,
            new_book_id: None,
        })
    }

    /// **Destructive data-management reset** (§2.11) — atomic, with an export-first safety rail.
    ///
    /// If `export_first`, a whole-instance archive is taken and retained BEFORE anything is cleared;
    /// a failure to archive aborts before any destruction. Then:
    /// - [`ResetScope::BackendDomain`]: clears domain data but KEEPS the append-only ledger and emits
    ///   a chained `data.wiped` (the wipe stays auditable) — all in one transaction.
    /// - [`ResetScope::BackendFactory`]: clears EVERYTHING (all rows incl. the ledger, in one
    ///   transaction) then removes the sidecar files to a blank first-run instance — the retained
    ///   export-first archive IS the record (no `data.wiped` into a ledger being destroyed).
    ///
    /// Never a partial half-wipe: the row-clearing is a single all-or-rollback transaction.
    // The parameter set is the frozen §2.11 contract (scope + export-first rail + sidecars +
    // caller-supplied actor/at). Splitting it into a struct would only obscure the call sites.
    #[allow(clippy::too_many_arguments)]
    pub fn reset(
        &self,
        ledger: &mut Ledger,
        data_dir: &Path,
        scope: ResetScope,
        export_first: bool,
        sidecars: &[PathBuf],
        actor: &str,
        at: OffsetDateTime,
    ) -> Result<ResetOutcome, StoreError> {
        // Export-first safety rail — archive the whole instance BEFORE clearing anything.
        let (export_archive, archive_digest) = if export_first {
            let (path, digest) = self.archive_instance(data_dir, sidecars)?;
            (Some(path), Some(digest))
        } else {
            (None, None)
        };

        match scope {
            ResetScope::BackendDomain => {
                let cleared = domain_table_names();
                let record = WipeRecord {
                    actor: actor.to_owned(),
                    at,
                    scope: "backend_domain".to_owned(),
                    cleared: cleared.clone(),
                    export_archive: export_archive
                        .as_ref()
                        .map(|p| p.to_string_lossy().into_owned()),
                    archive_digest,
                };
                let json = serde_json::to_string(&record)?;
                let snapshot = ledger.clone();
                let ev = ledger
                    .append(
                        actor,
                        RECOVERY_SCOPE,
                        DATA_WIPED_EVENT_KIND,
                        Some(&json),
                        json.as_bytes(),
                    )
                    .clone();
                let persisted = self.persist(|tx| {
                    clear_domain(tx)?;
                    clear_imported(tx)?;
                    tx.append_event(&ev)?;
                    Ok(())
                });
                if let Err(e) = persisted {
                    *ledger = snapshot;
                    return Err(e);
                }
                Ok(ResetOutcome {
                    scope,
                    export_archive,
                    cleared,
                })
            }
            ResetScope::BackendFactory => {
                // Clear ALL rows (incl. the ledger) atomically → blank first-run.
                self.persist(|tx| {
                    clear_domain(tx)?;
                    clear_imported(tx)?;
                    clear_events(tx)?;
                    Ok(())
                })?;
                *ledger = Ledger::new();

                // Remove the sidecar files (users.json / settings / caches). Best-effort AFTER the
                // atomic db-blank; the retained archive already preserved everything.
                let mut cleared = domain_table_names();
                cleared.push("events".to_owned());
                for s in sidecars {
                    if s.exists() {
                        let removed = if s.is_dir() {
                            std::fs::remove_dir_all(s)
                        } else {
                            std::fs::remove_file(s)
                        };
                        if removed.is_ok() {
                            cleared.push(
                                s.file_name()
                                    .map(|n| n.to_string_lossy().into_owned())
                                    .unwrap_or_else(|| s.to_string_lossy().into_owned()),
                            );
                        }
                    }
                }
                Ok(ResetOutcome {
                    scope,
                    export_archive,
                    cleared,
                })
            }
        }
    }

    /// **Re-anchor persistence** (§2.2 / deliverable #7): durably persist a ledger whose hashes were
    /// rebuilt in place by [`chancela_ledger::Ledger::reanchor`] (which already appended the chained
    /// `ledger.reanchored` disclosure and re-verified). The whole `events` table is atomically
    /// replaced with the current in-memory log, so the durable store matches the re-anchored chain.
    ///
    /// The api calls `ledger.reanchor(actor, reason, at)` (E1) then this, under the ledger lock.
    pub fn persist_reanchored_ledger(&self, ledger: &Ledger) -> Result<(), StoreError> {
        self.persist(|tx| {
            tx.raw().execute("DELETE FROM events", [])?;
            for event in ledger.events() {
                tx.append_event(event)?;
            }
            Ok(())
        })
    }

    // --- internals ------------------------------------------------------------------------------

    /// Build the in-memory bundle (manifest + zip bytes) for `book_id` WITHOUT touching the store
    /// (no file write, no audit event). Shared by [`Store::export_book`] and start-over.
    fn build_book_bundle(
        &self,
        ledger: &Ledger,
        book_id: BookId,
        at: OffsetDateTime,
    ) -> Result<BuiltBundle, StoreError> {
        let book = self
            .book_by_id(book_id)?
            .ok_or_else(|| StoreError::NotFound(format!("book {book_id}")))?;
        let entity = self
            .entity_json(book.entity_id.to_string())?
            .ok_or_else(|| StoreError::NotFound(format!("entity {}", book.entity_id)))?;
        let acts = self.acts_for_book(book_id)?;

        // The BOOK chain's member events, in chain-seq order (full fidelity so hashes recompute).
        let chain = ChainId::Book(book_id.to_string());
        let mut events: Vec<Event> = ledger
            .events_in_chain(&chain)
            .into_iter()
            .cloned()
            .collect();
        events.sort_by_key(|e| book_chain_seq(e, &chain));

        let verified = Ledger::verify_bundle_chain(&events, &chain).is_ok();
        let book_chain = ChainSummary {
            length: events.len() as u64,
            genesis_hash: events.first().map(|e| hex(&e.hash)),
            head_hash: events.last().map(|e| hex(&e.hash)),
            verified,
        };

        // Deterministic member set. entity.json is stored verbatim from its row json (PUBLIC fields
        // only — an Entity carries no secret material).
        let mut members: Vec<(String, Vec<u8>)> = Vec::new();
        members.push(("entity.json".to_owned(), entity.into_bytes()));
        members.push(("book.json".to_owned(), serde_json::to_vec_pretty(&book)?));
        for act in &acts {
            members.push((
                format!("acts/{}.json", act.id),
                serde_json::to_vec_pretty(act)?,
            ));
        }
        let mut events_jsonl = Vec::new();
        for e in &events {
            events_jsonl.extend_from_slice(&serde_json::to_vec(e)?);
            events_jsonl.push(b'\n');
        }
        members.push(("events.jsonl".to_owned(), events_jsonl));
        // Book-level instruments (termo de abertura / encerramento) are keyed by the book id cast
        // to ActId in the documents table. Include every such preserved PDF, oldest first, so the
        // opening term is never lost when a later closing term also exists.
        let mut exported_document_ids = BTreeSet::new();
        let book_document_scope = chancela_core::ActId(book_id.0);
        let book_signed = self.signed_document_for_act(book_document_scope)?;
        for doc in self.documents_for_act(book_document_scope)? {
            let matching_signed = book_signed
                .as_ref()
                .filter(|signed| signed.document_id == doc.id)
                .cloned();
            append_document_members(
                &mut members,
                &mut exported_document_ids,
                "book",
                book_id.to_string(),
                book_id.to_string(),
                None,
                doc,
                matching_signed,
            )?;
        }
        if let Some(signed) = book_signed {
            if !exported_document_ids.contains(&signed.document_id) {
                match self.document_by_id(&signed.document_id)? {
                    Some(doc) => append_document_members(
                        &mut members,
                        &mut exported_document_ids,
                        "book",
                        book_id.to_string(),
                        book_id.to_string(),
                        None,
                        doc,
                        Some(signed),
                    )?,
                    None => append_signed_members(&mut members, &signed, false)?,
                }
            }
        }

        // Latest generated document per act (deterministic by act id). If a signed row references
        // a different source document, include that signed base document as well so the final PAdES
        // artifact and the base artifact metadata travel together.
        for act in &acts {
            let signed = self.signed_document_for_act(act.id)?;
            if let Some(doc) = self.document_for_act(act.id)? {
                let matching_signed = signed
                    .as_ref()
                    .filter(|signed| signed.document_id == doc.id)
                    .cloned();
                append_document_members(
                    &mut members,
                    &mut exported_document_ids,
                    "act",
                    act.id.to_string(),
                    book_id.to_string(),
                    Some(act.id.to_string()),
                    doc,
                    matching_signed,
                )?;
            }
            if let Some(signed) = signed {
                if exported_document_ids.contains(&signed.document_id) {
                    continue;
                }
                match self.document_by_id(&signed.document_id)? {
                    Some(doc) => append_document_members(
                        &mut members,
                        &mut exported_document_ids,
                        "act",
                        act.id.to_string(),
                        book_id.to_string(),
                        Some(act.id.to_string()),
                        doc,
                        Some(signed),
                    )?,
                    None => append_signed_members(&mut members, &signed, false)?,
                }
            }
        }

        let files: Vec<BackupFile> = members
            .iter()
            .map(|(name, bytes)| BackupFile {
                name: name.clone(),
                sha256: hex(&Sha256::digest(bytes)),
                bytes: bytes.len() as u64,
            })
            .collect();

        let mut manifest = BundleManifest {
            format: BUNDLE_FORMAT.to_owned(),
            bundle_kind: BundleKind::Book,
            exported_at: at,
            app_version: env!("CARGO_PKG_VERSION").to_owned(),
            source_instance_id: self.instance_id()?,
            entity_id: book.entity_id.to_string(),
            book_id: book_id.to_string(),
            book_chain,
            files,
            bundle_digest: String::new(),
            signature: None,
        };
        manifest.bundle_digest = compute_bundle_digest(&manifest)?;

        let bytes = write_bundle_zip(&manifest, &members)?;
        Ok(BuiltBundle { manifest, bytes })
    }

    /// Take a whole-instance archive (reusing the hot-backup mechanism) and return its path + the
    /// sha256 of the archive file (its identifying digest).
    fn archive_instance(
        &self,
        data_dir: &Path,
        sidecars: &[PathBuf],
    ) -> Result<(PathBuf, String), StoreError> {
        let manifest = self.backup(data_dir, sidecars)?;
        let path = PathBuf::from(&manifest.path);
        let digest = hex(&Sha256::digest(std::fs::read(&path)?));
        Ok((path, digest))
    }

    /// Append a single chained recovery audit event (scope `recovery`) and persist it write-through,
    /// rolling the in-memory `ledger` back on a persist failure. Uses infallible `append` (not
    /// `try_append`): recovery meta-ops must record even when the live chain is degraded, and they
    /// join the Application chain, not the book sign-chains.
    fn append_recovery_event<T: Serialize>(
        &self,
        ledger: &mut Ledger,
        kind: &str,
        actor: &str,
        record: &T,
    ) -> Result<Event, StoreError> {
        let json = serde_json::to_string(record)?;
        let snapshot = ledger.clone();
        let ev = ledger
            .append(actor, RECOVERY_SCOPE, kind, Some(&json), json.as_bytes())
            .clone();
        if let Err(e) = self.persist(|tx| tx.append_event(&ev)) {
            *ledger = snapshot;
            return Err(e);
        }
        Ok(ev)
    }

    /// Read one book aggregate by id.
    fn book_by_id(&self, id: BookId) -> Result<Option<Book>, StoreError> {
        let guard = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = guard.prepare("SELECT json FROM books WHERE id = ?1")?;
        stmt.query_row(params![id.to_string()], |row| row.get::<_, String>(0))
            .optional()?
            .map(|j| serde_json::from_str(&j).map_err(StoreError::from))
            .transpose()
    }

    /// Read one entity's raw row json by id (kept as-is so the bundle stores the exact PUBLIC bytes).
    fn entity_json(&self, id: String) -> Result<Option<String>, StoreError> {
        let guard = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = guard.prepare("SELECT json FROM entities WHERE id = ?1")?;
        Ok(stmt
            .query_row(params![id], |row| row.get::<_, String>(0))
            .optional()?)
    }

    /// Read all acts of a book, ordered by id (deterministic bundle order).
    fn acts_for_book(&self, book_id: BookId) -> Result<Vec<Act>, StoreError> {
        let guard = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = guard.prepare("SELECT json FROM acts WHERE book_id = ?1 ORDER BY id")?;
        let rows = stmt.query_map(params![book_id.to_string()], |row| row.get::<_, String>(0))?;
        let mut acts = Vec::new();
        for j in rows {
            acts.push(serde_json::from_str::<Act>(&j?)?);
        }
        acts.sort_by_key(|a| a.id.to_string());
        Ok(acts)
    }

    /// Whether `book_id` already exists as a live book OR an imported book (collision detection).
    fn book_exists_anywhere(&self, book_id: &str) -> Result<bool, StoreError> {
        let guard = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let live: i64 = guard.query_row(
            "SELECT COUNT(*) FROM books WHERE id = ?1",
            params![book_id],
            |r| r.get(0),
        )?;
        let imported: i64 = guard.query_row(
            "SELECT COUNT(*) FROM imported_books WHERE book_id = ?1",
            params![book_id],
            |r| r.get(0),
        )?;
        Ok(live + imported > 0)
    }
}

/// The in-memory product of [`Store::build_book_bundle`].
struct BuiltBundle {
    manifest: BundleManifest,
    bytes: Vec<u8>,
}

// =================================================================================================
// Free helpers
// =================================================================================================

fn append_document_members(
    members: &mut Vec<(String, Vec<u8>)>,
    exported_document_ids: &mut BTreeSet<String>,
    owner_kind: &'static str,
    owner_id: String,
    book_id: String,
    act_id: Option<String>,
    doc: crate::StoredDocument,
    signed: Option<crate::StoredSignedDocument>,
) -> Result<(), StoreError> {
    if !exported_document_ids.insert(doc.id.clone()) {
        return Ok(());
    }

    let metadata =
        document_metadata_bytes(owner_kind, owner_id, book_id, act_id, &doc, signed.as_ref())?;
    let doc_id = doc.id.clone();
    members.push((format!("documents/{doc_id}.pdf"), doc.pdf_bytes));
    members.push((format!("documents/{doc_id}.json"), metadata));
    if let Some(signed) = signed {
        append_signed_members(members, &signed, true)?;
    }
    Ok(())
}

fn append_signed_members(
    members: &mut Vec<(String, Vec<u8>)>,
    signed: &crate::StoredSignedDocument,
    source_document_present: bool,
) -> Result<(), StoreError> {
    let doc_id = &signed.document_id;
    members.push((
        format!("signed/{doc_id}.pdf"),
        signed.signed_pdf_bytes.clone(),
    ));
    members.push((
        format!("signed/{doc_id}.json"),
        signing_metadata_bytes(signed, source_document_present)?,
    ));
    Ok(())
}

fn document_metadata_bytes(
    owner_kind: &'static str,
    owner_id: String,
    book_id: String,
    act_id: Option<String>,
    doc: &crate::StoredDocument,
    signed: Option<&crate::StoredSignedDocument>,
) -> Result<Vec<u8>, StoreError> {
    let pdf_path = format!("documents/{}.pdf", doc.id);
    let final_artifact = match signed {
        Some(signed) => BundleFinalArtifact {
            kind: "signed_pdf",
            path: format!("signed/{}.pdf", doc.id),
            sha256: signed.signed_pdf_digest.clone(),
            content_type: signed_pdf_profile(signed),
        },
        None => BundleFinalArtifact {
            kind: "base_pdf",
            path: pdf_path.clone(),
            sha256: doc.pdf_digest.clone(),
            content_type: PDF_CONTENT_TYPE,
        },
    };
    let signed = signed.map(|signed| BundleSignedDocumentRef {
        signed_pdf_digest: signed.signed_pdf_digest.clone(),
        signature_family: signed.signature_family.clone(),
        evidentiary_level: signed.evidentiary_level.clone(),
        signing_time: format_rfc3339(signed.signing_time),
        signed_at: format_rfc3339(signed.signed_at),
        signed_pdf_path: format!("signed/{}.pdf", doc.id),
        signing_metadata_path: format!("signed/{}.json", doc.id),
        timestamp_token_present: signed.timestamp_token_der.is_some(),
    });
    serde_json::to_vec_pretty(&BundleDocumentMetadata {
        format: BUNDLE_FORMAT,
        sidecar: "document",
        owner: BundleDocumentOwner {
            kind: owner_kind,
            id: owner_id,
            book_id,
            act_id,
        },
        document: BundleBaseDocumentMetadata {
            id: doc.id.clone(),
            role: document_role(owner_kind, &doc.template_id),
            template_id: doc.template_id.clone(),
            profile: doc.profile.clone(),
            created_at: format_rfc3339(doc.created_at),
            pdf_digest: doc.pdf_digest.clone(),
            pdf_path,
            content_type: PDF_CONTENT_TYPE,
        },
        final_artifact,
        signed,
    })
    .map_err(StoreError::from)
}

fn signing_metadata_bytes(
    signed: &crate::StoredSignedDocument,
    source_document_present: bool,
) -> Result<Vec<u8>, StoreError> {
    serde_json::to_vec_pretty(&BundleSigningMetadata {
        format: BUNDLE_FORMAT,
        sidecar: "signed_document",
        act_id: signed.act_id.to_string(),
        document_id: signed.document_id.clone(),
        source_document_present,
        source_document_path: format!("documents/{}.pdf", signed.document_id),
        signed_pdf_path: format!("signed/{}.pdf", signed.document_id),
        signed_pdf_digest: signed.signed_pdf_digest.clone(),
        signature_family: signed.signature_family.clone(),
        evidentiary_level: signed.evidentiary_level.clone(),
        trusted_list_status: signed.trusted_list_status.clone(),
        signer_cert_subject: signed.signer_cert_subject.clone(),
        signing_time: format_rfc3339(signed.signing_time),
        signed_at: format_rfc3339(signed.signed_at),
        signer_certificate_sha256: hex(&Sha256::digest(&signed.signer_cert_der)),
        timestamp_token_present: signed.timestamp_token_der.is_some(),
        timestamp_token_sha256: signed
            .timestamp_token_der
            .as_ref()
            .map(|token| hex(&Sha256::digest(token))),
    })
    .map_err(StoreError::from)
}

fn document_role(owner_kind: &str, template_id: &str) -> &'static str {
    if owner_kind == "book" {
        let id = template_id.to_ascii_lowercase();
        if id.contains("termo-abertura") {
            return "opening_term";
        }
        if id.contains("termo-encerramento") {
            return "closing_term";
        }
        return "book_document";
    }
    "act_document"
}

fn signed_pdf_profile(signed: &crate::StoredSignedDocument) -> &'static str {
    if signed.timestamp_token_der.is_some() {
        SIGNED_PDF_B_T_PROFILE
    } else {
        SIGNED_PDF_B_B_PROFILE
    }
}

fn format_rfc3339(at: OffsetDateTime) -> String {
    at.format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
}

/// The domain aggregate table names cleared by a wipe/factory reset (excludes `events`).
fn domain_table_names() -> Vec<String> {
    [
        "entities",
        "books",
        "acts",
        "registry_extracts",
        "documents",
        "follow_ups",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

/// Clear the domain aggregate tables (not the ledger).
fn clear_domain(tx: &Tx<'_>) -> Result<(), StoreError> {
    tx.raw().execute("DELETE FROM entities", [])?;
    tx.raw().execute("DELETE FROM books", [])?;
    tx.raw().execute("DELETE FROM acts", [])?;
    tx.raw().execute("DELETE FROM registry_extracts", [])?;
    tx.raw().execute("DELETE FROM documents", [])?;
    tx.raw().execute("DELETE FROM follow_ups", [])?;
    Ok(())
}

/// Clear the import isolation namespace.
fn clear_imported(tx: &Tx<'_>) -> Result<(), StoreError> {
    tx.raw().execute("DELETE FROM imported_books", [])?;
    Ok(())
}

/// Clear the append-only ledger table (factory reset / whole-instance start-over only).
fn clear_events(tx: &Tx<'_>) -> Result<(), StoreError> {
    tx.raw().execute("DELETE FROM events", [])?;
    Ok(())
}

/// The per-book-chain seq of `event` within `chain` (for deterministic bundle ordering).
fn book_chain_seq(event: &Event, chain: &ChainId) -> u64 {
    event
        .links
        .iter()
        .find(|l| &l.chain == chain)
        .map(|l| l.seq)
        .unwrap_or(0)
}

/// The sha256 (lowercase hex) of the canonical manifest with `bundle_digest` empty + `signature`
/// cleared — the same preimage on export (to set it) and import (to verify it).
fn compute_bundle_digest(manifest: &BundleManifest) -> Result<String, StoreError> {
    let mut m = manifest.clone();
    m.bundle_digest = String::new();
    m.signature = None;
    Ok(hex(&Sha256::digest(serde_json::to_vec(&m)?)))
}

fn validate_backup_member_name(name: &str) -> Result<(), StoreError> {
    if name.is_empty() || name.contains('\\') {
        return Err(StoreError::BadBackup(format!(
            "unsafe archive member name {name:?}"
        )));
    }
    let path = Path::new(name);
    if path.is_absolute() {
        return Err(StoreError::BadBackup(format!(
            "unsafe archive member name {name:?}"
        )));
    }
    let mut saw_component = false;
    for component in path.components() {
        match component {
            std::path::Component::Normal(_) => saw_component = true,
            _ => {
                return Err(StoreError::BadBackup(format!(
                    "unsafe archive member name {name:?}"
                )));
            }
        }
    }
    if !saw_component {
        return Err(StoreError::BadBackup(format!(
            "unsafe archive member name {name:?}"
        )));
    }
    Ok(())
}

fn stage_backup_sidecars(
    stage: &Path,
    members: &BTreeMap<String, Vec<u8>>,
) -> Result<BTreeSet<PathBuf>, StoreError> {
    let mut roots = BTreeSet::new();
    for (name, bytes) in members {
        if name == DB_FILE || name == "manifest.json" {
            continue;
        }
        validate_backup_member_name(name)?;
        let mut components = Path::new(name).components();
        let Some(std::path::Component::Normal(root)) = components.next() else {
            return Err(StoreError::BadBackup(format!(
                "unsafe archive member name {name:?}"
            )));
        };
        roots.insert(PathBuf::from(root));
        let dest = stage.join(name);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(dest, bytes)?;
    }
    Ok(roots)
}

fn replace_live_sidecars(
    data_dir: &Path,
    stage: &Path,
    staged_roots: &BTreeSet<PathBuf>,
    sidecars: &[PathBuf],
) -> Result<(), StoreError> {
    let mut roots = staged_roots.clone();
    for sidecar in sidecars {
        if let Some(name) = sidecar.file_name() {
            roots.insert(PathBuf::from(name));
            remove_path_if_exists(sidecar)?;
        }
    }
    for root in roots {
        if root.as_os_str().is_empty() || root.as_path() == Path::new(DB_FILE) {
            continue;
        }
        let src = stage.join(&root);
        if !src.exists() {
            continue;
        }
        let dst = data_dir.join(&root);
        remove_path_if_exists(&dst)?;
        if let Some(parent) = dst.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::rename(&src, &dst)?;
    }
    Ok(())
}

fn remove_path_if_exists(path: &Path) -> Result<(), StoreError> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => {
            std::fs::remove_dir_all(path)?;
        }
        Ok(_) => {
            std::fs::remove_file(path)?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(StoreError::Io(e)),
    }
    Ok(())
}

/// Write the bundle `.zip` (manifest.json first, then members in the given deterministic order) to
/// an in-memory buffer.
fn write_bundle_zip(
    manifest: &BundleManifest,
    members: &[(String, Vec<u8>)],
) -> Result<Vec<u8>, StoreError> {
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts = zip::write::SimpleFileOptions::default();
    zip.start_file("manifest.json", opts)?;
    zip.write_all(&serde_json::to_vec_pretty(manifest)?)?;
    for (name, bytes) in members {
        // Zip-slip defense (member names are internally generated, but keep the guard).
        if name.contains("..") {
            continue;
        }
        zip.start_file(name.as_str(), opts)?;
        zip.write_all(bytes)?;
    }
    Ok(zip.finish()?.into_inner())
}

/// Parse a bundle `.zip`'s bytes into (manifest, member-name → bytes). A truly-unparseable input
/// (not a zip, no manifest, wrong format) is a hard [`StoreError::InvalidBundle`]; a *tampered*
/// bundle whose manifest parses is caught later by digest/chain verification and quarantined.
fn read_bundle(bytes: &[u8]) -> Result<(BundleManifest, HashMap<String, Vec<u8>>), StoreError> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes))
        .map_err(|e| StoreError::InvalidBundle(format!("not a readable zip: {e}")))?;
    let mut members = HashMap::new();
    for i in 0..archive.len() {
        let mut f = archive.by_index(i)?;
        let name = f.name().to_owned();
        if name.contains("..") {
            return Err(StoreError::InvalidBundle(format!(
                "path-traversal in member name {name:?}"
            )));
        }
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)?;
        members.insert(name, buf);
    }
    let manifest_bytes = members
        .get("manifest.json")
        .ok_or_else(|| StoreError::InvalidBundle("missing manifest.json".to_owned()))?;
    let manifest: BundleManifest = serde_json::from_slice(manifest_bytes)
        .map_err(|e| StoreError::InvalidBundle(format!("unreadable manifest: {e}")))?;
    if manifest.format != BUNDLE_FORMAT {
        return Err(StoreError::InvalidBundle(format!(
            "unexpected bundle format {:?} (want {BUNDLE_FORMAT:?})",
            manifest.format
        )));
    }
    Ok((manifest, members))
}

/// Parse `events.jsonl` (one full-fidelity [`Event`] JSON per line) back into a vector.
fn parse_events_jsonl(bytes: &[u8]) -> Result<Vec<Event>, StoreError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|e| StoreError::InvalidBundle(format!("events.jsonl is not utf-8: {e}")))?;
    let mut events = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        events.push(
            serde_json::from_str::<Event>(line)
                .map_err(|e| StoreError::InvalidBundle(format!("bad event line: {e}")))?,
        );
    }
    Ok(events)
}

/// Synthesize a [`ChainBreak`] for a bundle-level tamper (bad digest / missing member) that is not a
/// specific event-chain break — used to quarantine a forged bundle.
fn tamper_break(book_id: &str, message: &str) -> ChainBreak {
    ChainBreak {
        chain: ChainId::Book(book_id.to_owned()),
        kind: BreakKind::HashMismatch,
        global_seq: None,
        chain_seq: None,
        event_id: None,
        expected_hash: None,
        actual_hash: None,
        message: message.to_owned(),
    }
}

/// Reconstruct an [`ImportVerdict`] from a stored verdict string + optional break json.
fn reconstruct_verdict(
    verdict_str: &str,
    break_json: Option<&str>,
    book_id: &str,
) -> Result<ImportVerdict, StoreError> {
    if verdict_str == "verified" {
        return Ok(ImportVerdict::Verified);
    }
    let break_ = match break_json {
        Some(j) => serde_json::from_str(j)?,
        None => tamper_break(book_id, "quarantined (break detail unavailable)"),
    };
    Ok(ImportVerdict::Quarantined { break_ })
}
