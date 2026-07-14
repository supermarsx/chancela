//! The **PostgreSQL backend arm** (wp14 Phase 1, feature = `postgres`, OFF by default).
//!
//! This is the concrete backend behind [`crate::Backend::Postgres`]. It exists so the self-hosted
//! `chancela-server` edition can run its durability sink on a managed, networked Postgres while the
//! embedded desktop/browser editions keep the default SQLite/SQLCipher backend untouched (plan
//! §1.7, §2.4). The public [`crate::Store`]/[`crate::Tx`] facade is byte-identical across backends,
//! so no `chancela-api` call site changes.
//!
//! ## Shape
//!
//! - a **read pool** (`r2d2` over the synchronous `postgres` crate) for the boot [`load`] path, and
//! - a **single advisory-locked writer connection** that mirrors today's one mutex-guarded SQLite
//!   connection. The `persist(|tx| …)` closure runs one Postgres transaction on this writer, so the
//!   ledger's **atomic append** and **single-writer** invariants (§4) are preserved: the `events`
//!   INSERT and the aggregate upsert commit together, and a duplicate application-assigned
//!   `seq` trips the primary key and rolls the whole transaction back (fail-closed).
//!
//! The `seq` is allocated in-memory by the API/ledger layer and passed through verbatim — Postgres
//! is a faithful row sink, never a `SERIAL`/`IDENTITY` source (§4).
//!
//! ## Single-writer enforcement
//!
//! At [`PostgresBackend::open`] the writer connection takes a **session-level advisory lock**
//! ([`WRITER_ADVISORY_LOCK_KEY`]) and holds it for the process lifetime. Because that one
//! connection is never returned to a pool, the lock is never released while the server runs, so a
//! second instance pointed at the same database blocks on the lock — a hard runtime guard for the
//! single-writer invariant. Compose additionally pins `deploy.replicas: 1` (Phase 2/§6). This is a
//! *best-effort* Phase-1 guard: it is taken and held, but the fast-fail-with-a-clear-message
//! ergonomics (statement timeout / `pg_try_advisory_lock`) and TLS (`sslmode=verify-full` via
//! `postgres-rustls`, §3) are Phase 2/compose items.
//!
//! ## What the Postgres backend supports vs defers (all deferrals fail closed, never silently)
//!
//! This backend now covers the store reads and writes used by the request-serving facade:
//! opening + schema DDL (derived from [`crate::schema::ALL`] via
//! [`crate::dialect::sqlite_ddl_to_pg`], including the `meta` `schema_version`/`instance_id`
//! stamp), the boot [`load`] replay, the full core + non-core `Tx` write surface
//! (`append_event`, all aggregate/document/signed-document/follow-up/imported-document/paper-book
//! OCR/dispatch-evidence upserts and reviews — with the `imported_document_review_history` surrogate
//! id served by a Postgres `GENERATED ALWAYS AS IDENTITY` column), and every runtime `Store` read
//! (paged `ledger_events_page`, the blob/by-id document reads, and the signed-document / pending-CMD
//! / follow-up / imported-document / paper-book projections).
//!
//! Deferred **by design** (fail closed with [`crate::StoreError::UnsupportedOnPostgres`], pointing at
//! PG-native tooling): the SQLite-file-shaped operator paths — `backup` (`VACUUM INTO` + zip),
//! whole-store `restore`, and the [`crate::recovery`] domain-wipe / factory-blank / start-over /
//! imported-book paths. Those paths require explicit Postgres-native backup/restore procedures and
//! are not part of the request-serving runtime. They still funnel through the SQLite-only
//! `Tx::raw` / `Store::locked_conn` accessors, which return `UnsupportedOnPostgres`.

use std::sync::{Arc, Mutex};

use chancela_core::{Act, ActId, Book, Entity, EntityId};
use chancela_ledger::Ledger;
use chancela_registry::RegistryExtract;
use postgres::types::ToSql;
use postgres::{Client, NoTls, Row};
use r2d2_postgres::PostgresConnectionManager;
use rusqlite::types::Value;

use crate::{
    LedgerEventPage, LedgerEventPageQuery, LoadedState, PendingCmdSession, RawEventRow, StoreError,
    StoredDocument, StoredFollowUp, StoredFollowUpStatus, StoredGeneratedDocumentDispatchEvidence,
    StoredImportedDocument, StoredImportedDocumentMeta, StoredImportedDocumentReviewHistoryEntry,
    StoredImportedDocumentReviewStatus, StoredPaperBookImport, StoredPaperBookImportMeta,
    StoredPaperBookOcrConversionDossier, StoredPaperBookOcrConversionExecutionArtifact,
    StoredPaperBookOcrDraft, StoredPaperBookOcrReviewStatus, StoredPaperBookOcrStatus,
    StoredSignedDocument, int_to_u32, parse_date, parse_rfc3339, parse_uuid_newtype,
};

/// Fixed key for the process-wide writer advisory lock (§4). An arbitrary, stable 64-bit constant
/// derived from "chancela-writer"; two instances contend on the same key.
pub(crate) const WRITER_ADVISORY_LOCK_KEY: i64 = 0x0C_1A_17_CE_1A_17_CE_11u64 as i64;

/// Additive guard matching SQLite's `configure_and_migrate` column repair for databases opened by
/// earlier builds before the column was folded into the fresh-table DDL.
pub(crate) const ADD_IMPORTED_DOCUMENTS_GUARDRAIL_ACK_COLUMN: &str = "ALTER TABLE imported_documents ADD COLUMN IF NOT EXISTS \
     operator_acknowledged_guardrail_ids_json TEXT NOT NULL DEFAULT '[]';";

/// The `r2d2` connection manager type for the read pool.
type PgManager = PostgresConnectionManager<NoTls>;

/// The PostgreSQL backend: a read pool plus a single advisory-locked writer connection.
#[derive(Clone)]
pub(crate) struct PostgresBackend {
    /// Pooled read connections (boot `load`; future paged/blob reads).
    pool: r2d2::Pool<PgManager>,
    /// The single writer connection (holds the advisory lock; serves `persist`). Mutex-guarded so
    /// the synchronous `persist` path takes it for the duration of one transaction — the direct
    /// analogue of the SQLite backend's one mutex-guarded connection.
    writer: Arc<Mutex<Client>>,
}

impl std::fmt::Debug for PostgresBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The underlying `postgres::Client` is not `Debug`; report the pool state only.
        f.debug_struct("PostgresBackend")
            .field("pool_state", &self.pool.state().connections)
            .field("writer", &"<advisory-locked postgres client>")
            .finish()
    }
}

impl PostgresBackend {
    /// Connect to `database_url`, take the writer advisory lock, and run the per-backend DDL.
    ///
    /// `database_url` is a libpq connection string (`postgres://user:pass@host:5432/db`). TLS is
    /// `NoTls` in this lane; `sslmode=verify-full` via `postgres-rustls` remains a later hardening
    /// item.
    pub(crate) fn open(database_url: &str) -> Result<Self, StoreError> {
        let config: postgres::Config = database_url
            .parse()
            .map_err(|e: postgres::Error| StoreError::Postgres(e))?;

        // Read pool.
        let manager = PostgresConnectionManager::new(config, NoTls);
        let pool = r2d2::Pool::builder().build(manager)?;

        // Dedicated writer connection: hold the advisory lock for the process lifetime, then run
        // the idempotent DDL (derived from the SQLite schema so both dialects stay in lock-step).
        let mut writer = Client::connect(database_url, NoTls)?;
        writer.batch_execute(&format!(
            "SELECT pg_advisory_lock({WRITER_ADVISORY_LOCK_KEY})"
        ))?;
        for stmt in crate::schema::ALL {
            writer.batch_execute(&crate::dialect::sqlite_ddl_to_pg(stmt))?;
        }
        Self::ensure_additive_columns(&mut writer)?;
        Self::stamp_meta(&mut writer)?;

        Ok(Self {
            pool,
            writer: Arc::new(Mutex::new(writer)),
        })
    }

    /// Keep Postgres in step with SQLite's idempotent additive column guards before metadata is
    /// stamped current.
    fn ensure_additive_columns(writer: &mut Client) -> Result<(), StoreError> {
        writer.batch_execute(ADD_IMPORTED_DOCUMENTS_GUARDRAIL_ACK_COLUMN)?;
        Ok(())
    }

    /// Gate the `schema_version` and mint the stable `instance_id`, mirroring the SQLite
    /// [`crate::configure_and_migrate`] boot stamp so `Store::instance_id`, bundle provenance, and
    /// the import feed all resolve on Postgres. A database written by a *newer* build is rejected
    /// (we don't know its layout); an older stamp is advanced forward (the additive DDL already ran).
    fn stamp_meta(writer: &mut Client) -> Result<(), StoreError> {
        let found: Option<i64> = writer
            .query_opt("SELECT value FROM meta WHERE key = 'schema_version'", &[])?
            .and_then(|row| row.get::<_, String>(0).parse::<i64>().ok());
        match found {
            Some(v) if v > crate::schema::SCHEMA_VERSION => {
                return Err(StoreError::UnsupportedSchemaVersion {
                    found: v,
                    supported: crate::schema::SCHEMA_VERSION,
                });
            }
            Some(_) => {
                writer.execute(
                    "UPDATE meta SET value = $1 WHERE key = 'schema_version'",
                    &[&crate::schema::SCHEMA_VERSION.to_string()],
                )?;
            }
            None => {
                writer.execute(
                    "INSERT INTO meta (key, value) VALUES ('schema_version', $1)",
                    &[&crate::schema::SCHEMA_VERSION.to_string()],
                )?;
            }
        }
        // Minted once, then immutable: `ON CONFLICT DO NOTHING` preserves a restored/source id.
        writer.execute(
            "INSERT INTO meta (key, value) VALUES ('instance_id', $1) ON CONFLICT (key) DO NOTHING",
            &[&uuid::Uuid::new_v4().to_string()],
        )?;
        Ok(())
    }

    /// Read the stable per-install `instance_id` from `meta` (present after [`stamp_meta`]).
    pub(crate) fn instance_id(&self) -> Result<String, StoreError> {
        let mut client = self.pool.get()?;
        client
            .query_opt("SELECT value FROM meta WHERE key = 'instance_id'", &[])?
            .map(|row| row.get::<_, String>(0))
            .ok_or_else(|| {
                StoreError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "instance_id missing from meta",
                ))
            })
    }

    /// Borrow the writer connection for the single-writer `persist` transaction (§4).
    pub(crate) fn writer(&self) -> std::sync::MutexGuard<'_, Client> {
        self.writer.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Boot replay: read the aggregate rows and all `events` (ordered by `seq`) into a
    /// [`LoadedState`], byte-for-byte the same reconstruction as the SQLite [`crate::Store::load`]
    /// path (the `events` rows feed `Ledger::try_from_events`, which re-verifies the chain).
    pub(crate) fn load(&self) -> Result<LoadedState, StoreError> {
        use std::collections::HashMap;

        let mut client = self.pool.get()?;

        let mut entities = HashMap::new();
        for row in client.query("SELECT json FROM entities", &[])? {
            let json: String = row.get(0);
            let entity: Entity = serde_json::from_str(&json)?;
            entities.insert(entity.id, entity);
        }

        let mut books = HashMap::new();
        for row in client.query("SELECT json FROM books", &[])? {
            let json: String = row.get(0);
            let book: Book = serde_json::from_str(&json)?;
            books.insert(book.id, book);
        }

        let mut acts = HashMap::new();
        for row in client.query("SELECT json FROM acts", &[])? {
            let json: String = row.get(0);
            let act: Act = serde_json::from_str(&json)?;
            acts.insert(act.id, act);
        }

        let mut registry_extracts = HashMap::new();
        for row in client.query("SELECT entity_id, json FROM registry_extracts", &[])? {
            let entity_id_raw: String = row.get(0);
            let json: String = row.get(1);
            let entity_id: EntityId = parse_uuid_newtype(&entity_id_raw)?;
            let extract: RegistryExtract = serde_json::from_str(&json)?;
            registry_extracts.insert(entity_id, extract);
        }

        let mut follow_ups = HashMap::new();
        for row in client.query(
            "SELECT id, act_id, agenda_number, deliberation_index, title, detail, due_date, \
             assignee, assignee_display, status, created_at, created_by, completed_at, \
             completed_by FROM follow_ups",
            &[],
        )? {
            let agenda_number_raw: Option<i64> = row.get(2);
            let deliberation_index_raw: Option<i64> = row.get(3);
            let due_date_raw: Option<String> = row.get(6);
            let status_raw: String = row.get(9);
            let created_at_raw: String = row.get(10);
            let completed_at_raw: Option<String> = row.get(12);
            let follow_up = StoredFollowUp {
                id: row.get(0),
                act_id: parse_uuid_newtype(&row.get::<_, String>(1))?,
                agenda_number: agenda_number_raw.map(int_to_u32).transpose()?,
                deliberation_index: deliberation_index_raw.map(int_to_u32).transpose()?,
                title: row.get(4),
                detail: row.get(5),
                due_date: due_date_raw.as_deref().map(parse_date).transpose()?,
                assignee: row.get(7),
                assignee_display: row.get(8),
                status: StoredFollowUpStatus::parse(&status_raw)?,
                created_at: parse_rfc3339(&created_at_raw)?,
                created_by: row.get(11),
                completed_at: completed_at_raw.as_deref().map(parse_rfc3339).transpose()?,
                completed_by: row.get(13),
            };
            follow_ups.insert(follow_up.id.clone(), follow_up);
        }

        let mut events = Vec::new();
        for row in client.query(
            "SELECT seq, id, actor, justification, timestamp, scope, kind, payload_digest, \
             prev_hash, hash, links FROM events ORDER BY seq",
            &[],
        )? {
            let raw = RawEventRow {
                seq: row.get(0),
                id: row.get(1),
                actor: row.get(2),
                justification: row.get(3),
                timestamp: row.get(4),
                scope: row.get(5),
                kind: row.get(6),
                payload_digest: row.get(7),
                prev_hash: row.get(8),
                hash: row.get(9),
                links: row.get(10),
            };
            events.push(raw.into_event()?);
        }

        let (ledger, chain_status) = Ledger::try_from_events(events);
        let integrity = ledger.integrity_report();
        Ok(LoadedState {
            entities,
            books,
            acts,
            registry_extracts,
            follow_ups,
            ledger,
            chain_status,
            integrity,
        })
    }

    /// Borrow a pooled read connection for the runtime `Store` read projections.
    fn read(&self) -> Result<r2d2::PooledConnection<PgManager>, StoreError> {
        Ok(self.pool.get()?)
    }

    /// Newest-first persisted event page (the Postgres twin of [`crate::Store::ledger_events_page`]).
    ///
    /// The cheap row predicates are pushed into Postgres via the shared
    /// [`crate::ledger_events_page_sql`] builder (translated by
    /// [`crate::dialect::ledger_page_sql_to_pg`]); chain-membership / free-text residual filters are
    /// applied on reconstructed [`chancela_ledger::Event`] values exactly as on SQLite.
    pub(crate) fn ledger_events_page(
        &self,
        query: &LedgerEventPageQuery,
    ) -> Result<LedgerEventPage, StoreError> {
        let limit = query.limit.max(1);
        let target = limit.saturating_add(1);
        let filters = crate::NormalizedLedgerEventPageFilters::from_query(query);
        let batch_limit =
            crate::ledger_event_page_batch_limit(limit, filters.has_residual_filters());
        let mut before_seq = query.before_seq;
        let mut accepted = Vec::with_capacity(target);
        let mut client = self.read()?;

        loop {
            let (sql, values) = crate::ledger_events_page_sql(&filters, before_seq, batch_limit);
            let sql = crate::dialect::ledger_page_sql_to_pg(&sql);
            let owned: Vec<Box<dyn ToSql + Sync>> = values.iter().map(value_to_pg_param).collect();
            let params: Vec<&(dyn ToSql + Sync)> = owned.iter().map(AsRef::as_ref).collect();
            let rows = client.query(&sql, &params)?;

            let row_count = rows.len();
            let raw_events: Vec<RawEventRow> = rows.iter().map(raw_event_row).collect();
            let oldest_seq = raw_events.last().map(|row| row.seq);
            if row_count == 0 {
                break;
            }

            for raw in raw_events {
                let event = raw.into_event()?;
                if !filters.matches(&event) {
                    continue;
                }
                accepted.push(event);
                if accepted.len() >= target {
                    break;
                }
            }

            if accepted.len() >= target || row_count < batch_limit {
                break;
            }
            let Some(oldest_seq) = oldest_seq else {
                break;
            };
            if oldest_seq <= 0 {
                break;
            }
            before_seq = Some(oldest_seq as u64);
        }

        let has_more = accepted.len() > limit;
        if has_more {
            accepted.truncate(limit);
        }
        let next_cursor = has_more
            .then(|| accepted.last().map(|event| event.seq))
            .flatten();
        Ok(LedgerEventPage {
            events: accepted,
            next_cursor,
            has_more,
            limit,
        })
    }

    pub(crate) fn document_for_act(
        &self,
        act_id: ActId,
    ) -> Result<Option<StoredDocument>, StoreError> {
        let mut client = self.read()?;
        let row = client.query_opt(
            "SELECT id, act_id, template_id, pdf_digest, profile, created_at, pdf_bytes \
             FROM documents WHERE act_id = $1 ORDER BY created_at DESC, ctid DESC LIMIT 1",
            &[&act_id.to_string()],
        )?;
        row.as_ref().map(row_to_document).transpose()
    }

    pub(crate) fn documents_for_act(
        &self,
        act_id: ActId,
    ) -> Result<Vec<StoredDocument>, StoreError> {
        let mut client = self.read()?;
        let rows = client.query(
            "SELECT id, act_id, template_id, pdf_digest, profile, created_at, pdf_bytes \
             FROM documents WHERE act_id = $1 ORDER BY created_at ASC, ctid ASC",
            &[&act_id.to_string()],
        )?;
        rows.iter().map(row_to_document).collect()
    }

    pub(crate) fn document_by_id(&self, id: &str) -> Result<Option<StoredDocument>, StoreError> {
        let mut client = self.read()?;
        let row = client.query_opt(
            "SELECT id, act_id, template_id, pdf_digest, profile, created_at, pdf_bytes \
             FROM documents WHERE id = $1",
            &[&id],
        )?;
        row.as_ref().map(row_to_document).transpose()
    }

    pub(crate) fn generated_document_dispatch_evidence(
        &self,
        document_id: &str,
    ) -> Result<Vec<StoredGeneratedDocumentDispatchEvidence>, StoreError> {
        let mut client = self.read()?;
        let rows = client.query(
            "SELECT document_id, idempotency_key, act_id, template_id, actor, dispatched_at, \
             channel, reference, evidence_reference, imported_document_id, recipients_json, \
             operator_note, recorded_at \
             FROM generated_document_dispatch_evidence \
             WHERE document_id = $1 ORDER BY recorded_at ASC, ctid ASC",
            &[&document_id],
        )?;
        rows.iter()
            .map(row_to_generated_dispatch_evidence)
            .collect()
    }

    pub(crate) fn generated_document_dispatch_evidence_by_key(
        &self,
        document_id: &str,
        idempotency_key: &str,
    ) -> Result<Option<StoredGeneratedDocumentDispatchEvidence>, StoreError> {
        let mut client = self.read()?;
        let row = client.query_opt(
            "SELECT document_id, idempotency_key, act_id, template_id, actor, dispatched_at, \
             channel, reference, evidence_reference, imported_document_id, recipients_json, \
             operator_note, recorded_at \
             FROM generated_document_dispatch_evidence \
             WHERE document_id = $1 AND idempotency_key = $2",
            &[&document_id, &idempotency_key],
        )?;
        row.as_ref()
            .map(row_to_generated_dispatch_evidence)
            .transpose()
    }

    pub(crate) fn imported_documents(
        &self,
        act_id: Option<ActId>,
    ) -> Result<Vec<StoredImportedDocumentMeta>, StoreError> {
        let mut client = self.read()?;
        let rows = if let Some(act_id) = act_id {
            client.query(
                "SELECT id, act_id, filename, declared_content_type, detected_content_type, \
                 sha256, size_bytes, imported_at, imported_by, operator_review_status, \
                 operator_reviewed_at, operator_reviewed_by, operator_review_note, \
                 operator_acknowledged_guardrail_ids_json \
                 FROM imported_documents \
                 WHERE act_id = $1 ORDER BY imported_at DESC, ctid DESC",
                &[&act_id.to_string()],
            )?
        } else {
            client.query(
                "SELECT id, act_id, filename, declared_content_type, detected_content_type, \
                 sha256, size_bytes, imported_at, imported_by, operator_review_status, \
                 operator_reviewed_at, operator_reviewed_by, operator_review_note, \
                 operator_acknowledged_guardrail_ids_json \
                 FROM imported_documents \
                 ORDER BY imported_at DESC, ctid DESC",
                &[],
            )?
        };
        rows.iter().map(row_to_imported_document_meta).collect()
    }

    pub(crate) fn imported_document(
        &self,
        id: &str,
    ) -> Result<Option<StoredImportedDocument>, StoreError> {
        let mut client = self.read()?;
        let row = client.query_opt(
            "SELECT id, act_id, filename, declared_content_type, detected_content_type, sha256, \
             size_bytes, imported_at, imported_by, operator_review_status, operator_reviewed_at, \
             operator_reviewed_by, operator_review_note, operator_acknowledged_guardrail_ids_json, \
             bytes FROM imported_documents WHERE id = $1",
            &[&id],
        )?;
        row.as_ref().map(row_to_imported_document).transpose()
    }

    pub(crate) fn imported_document_review_history(
        &self,
        imported_document_id: &str,
    ) -> Result<Vec<StoredImportedDocumentReviewHistoryEntry>, StoreError> {
        let mut client = self.read()?;
        let rows = client.query(
            "SELECT id, imported_document_id, review_status, reviewed_at, reviewed_by, \
             review_note, acknowledged_guardrail_ids_json \
             FROM imported_document_review_history \
             WHERE imported_document_id = $1 ORDER BY id ASC",
            &[&imported_document_id],
        )?;
        rows.iter()
            .map(row_to_imported_document_review_history_entry)
            .collect()
    }

    pub(crate) fn paper_book_import(
        &self,
        import_id: &str,
    ) -> Result<Option<StoredPaperBookImport>, StoreError> {
        let mut client = self.read()?;
        let row = client.query_opt(
            "SELECT import_id, entity_ref, entity_name, entity_nipc, book_ref, date_from, date_to, \
             page_count, page_from, page_to, original_number_from, original_number_to, sha256, \
             size_bytes, content_type, source_filename, notes, imported_at, imported_by, \
             ocr_status, bytes FROM paper_book_imports WHERE import_id = $1",
            &[&import_id],
        )?;
        row.as_ref().map(row_to_paper_book_import).transpose()
    }

    pub(crate) fn paper_book_imports(
        &self,
        book_ref: Option<&str>,
    ) -> Result<Vec<StoredPaperBookImportMeta>, StoreError> {
        let mut client = self.read()?;
        let rows = if let Some(book_ref) = book_ref {
            client.query(
                "SELECT import_id, entity_ref, entity_name, entity_nipc, book_ref, date_from, \
                 date_to, page_count, page_from, page_to, original_number_from, \
                 original_number_to, sha256, size_bytes, content_type, source_filename, notes, \
                 imported_at, imported_by, ocr_status FROM paper_book_imports \
                 WHERE book_ref = $1 ORDER BY imported_at DESC, ctid DESC",
                &[&book_ref],
            )?
        } else {
            client.query(
                "SELECT import_id, entity_ref, entity_name, entity_nipc, book_ref, date_from, \
                 date_to, page_count, page_from, page_to, original_number_from, \
                 original_number_to, sha256, size_bytes, content_type, source_filename, notes, \
                 imported_at, imported_by, ocr_status FROM paper_book_imports \
                 ORDER BY imported_at DESC, ctid DESC",
                &[],
            )?
        };
        rows.iter().map(row_to_paper_book_import_meta).collect()
    }

    pub(crate) fn update_paper_book_import_ocr_status(
        &self,
        import_id: &str,
        status: StoredPaperBookOcrStatus,
    ) -> Result<bool, StoreError> {
        let mut writer = self.writer();
        let changed = writer.execute(
            "UPDATE paper_book_imports SET ocr_status = $1 WHERE import_id = $2",
            &[&status.as_str(), &import_id],
        )?;
        Ok(changed > 0)
    }

    pub(crate) fn paper_book_ocr_draft(
        &self,
        draft_id: &str,
    ) -> Result<Option<StoredPaperBookOcrDraft>, StoreError> {
        let mut client = self.read()?;
        let row = client.query_opt(
            "SELECT draft_id, import_id, extracted_text, text_digest, page_spans_json, confidence, \
             engine_name, engine_version, created_at, created_by, review_status, reviewed_at, \
             reviewed_by, review_note, superseded_by FROM paper_book_ocr_drafts WHERE draft_id = $1",
            &[&draft_id],
        )?;
        row.as_ref().map(row_to_paper_book_ocr_draft).transpose()
    }

    pub(crate) fn paper_book_ocr_drafts(
        &self,
        import_id: &str,
    ) -> Result<Vec<StoredPaperBookOcrDraft>, StoreError> {
        let mut client = self.read()?;
        let rows = client.query(
            "SELECT draft_id, import_id, extracted_text, text_digest, page_spans_json, confidence, \
             engine_name, engine_version, created_at, created_by, review_status, reviewed_at, \
             reviewed_by, review_note, superseded_by FROM paper_book_ocr_drafts \
             WHERE import_id = $1 ORDER BY created_at DESC, ctid DESC",
            &[&import_id],
        )?;
        rows.iter().map(row_to_paper_book_ocr_draft).collect()
    }

    pub(crate) fn paper_book_ocr_conversion_dossier_for_draft(
        &self,
        import_id: &str,
        draft_id: &str,
    ) -> Result<Option<StoredPaperBookOcrConversionDossier>, StoreError> {
        let mut client = self.read()?;
        let row = client.query_opt(
            "SELECT dossier_id, import_id, draft_id, source_text_digest, \
             source_page_spans_json, source_review_status, source_reviewed_at, \
             source_reviewed_by, created_at, created_by \
             FROM paper_book_ocr_conversion_dossiers WHERE import_id = $1 AND draft_id = $2",
            &[&import_id, &draft_id],
        )?;
        row.as_ref()
            .map(row_to_paper_book_ocr_conversion_dossier)
            .transpose()
    }

    pub(crate) fn paper_book_ocr_conversion_dossiers(
        &self,
        import_id: &str,
    ) -> Result<Vec<StoredPaperBookOcrConversionDossier>, StoreError> {
        let mut client = self.read()?;
        let rows = client.query(
            "SELECT dossier_id, import_id, draft_id, source_text_digest, \
             source_page_spans_json, source_review_status, source_reviewed_at, \
             source_reviewed_by, created_at, created_by \
             FROM paper_book_ocr_conversion_dossiers \
             WHERE import_id = $1 ORDER BY created_at DESC, ctid DESC",
            &[&import_id],
        )?;
        rows.iter()
            .map(row_to_paper_book_ocr_conversion_dossier)
            .collect()
    }

    pub(crate) fn paper_book_ocr_conversion_execution_artifact(
        &self,
        import_id: &str,
        draft_id: &str,
        target_act_id: &str,
    ) -> Result<Option<StoredPaperBookOcrConversionExecutionArtifact>, StoreError> {
        let mut client = self.read()?;
        let row = client.query_opt(
            &format!(
                "SELECT {ARTIFACT_COLUMNS} \
                 FROM paper_book_ocr_conversion_execution_artifacts \
                 WHERE import_id = $1 AND draft_id = $2 AND target_act_id = $3"
            ),
            &[&import_id, &draft_id, &target_act_id],
        )?;
        row.as_ref()
            .map(row_to_paper_book_ocr_conversion_execution_artifact)
            .transpose()
    }

    pub(crate) fn paper_book_ocr_conversion_execution_artifacts_for_draft(
        &self,
        import_id: &str,
        draft_id: &str,
    ) -> Result<Vec<StoredPaperBookOcrConversionExecutionArtifact>, StoreError> {
        let mut client = self.read()?;
        let rows = client.query(
            &format!(
                "SELECT {ARTIFACT_COLUMNS} \
                 FROM paper_book_ocr_conversion_execution_artifacts \
                 WHERE import_id = $1 AND draft_id = $2 ORDER BY created_at DESC, ctid DESC"
            ),
            &[&import_id, &draft_id],
        )?;
        rows.iter()
            .map(row_to_paper_book_ocr_conversion_execution_artifact)
            .collect()
    }

    pub(crate) fn follow_ups_for_act(
        &self,
        act_id: ActId,
    ) -> Result<Vec<StoredFollowUp>, StoreError> {
        let mut client = self.read()?;
        let rows = client.query(
            "SELECT id, act_id, agenda_number, deliberation_index, title, detail, due_date, \
             assignee, assignee_display, status, created_at, created_by, completed_at, \
             completed_by FROM follow_ups WHERE act_id = $1 \
             ORDER BY CASE status WHEN 'Open' THEN 0 ELSE 1 END, created_at ASC, ctid ASC",
            &[&act_id.to_string()],
        )?;
        rows.iter().map(row_to_follow_up).collect()
    }

    pub(crate) fn follow_up(&self, id: &str) -> Result<Option<StoredFollowUp>, StoreError> {
        let mut client = self.read()?;
        let row = client.query_opt(
            "SELECT id, act_id, agenda_number, deliberation_index, title, detail, due_date, \
             assignee, assignee_display, status, created_at, created_by, completed_at, \
             completed_by FROM follow_ups WHERE id = $1",
            &[&id],
        )?;
        row.as_ref().map(row_to_follow_up).transpose()
    }

    pub(crate) fn signed_document_for_act(
        &self,
        act_id: ActId,
    ) -> Result<Option<StoredSignedDocument>, StoreError> {
        let mut client = self.read()?;
        let row = client.query_opt(
            &format!("SELECT {SIGNED_DOCUMENT_COLUMNS} FROM signed_documents WHERE act_id = $1"),
            &[&act_id.to_string()],
        )?;
        row.as_ref().map(row_to_signed_document).transpose()
    }

    pub(crate) fn all_signed_documents(
        &self,
    ) -> Result<std::collections::HashMap<ActId, StoredSignedDocument>, StoreError> {
        let mut client = self.read()?;
        let rows = client.query(
            &format!("SELECT {SIGNED_DOCUMENT_COLUMNS} FROM signed_documents"),
            &[],
        )?;
        let mut out = std::collections::HashMap::new();
        for row in &rows {
            let doc = row_to_signed_document(row)?;
            out.insert(doc.act_id, doc);
        }
        Ok(out)
    }

    pub(crate) fn pending_cmd_session(
        &self,
        session_id: &str,
    ) -> Result<Option<PendingCmdSession>, StoreError> {
        let mut client = self.read()?;
        let row = client.query_opt(
            "SELECT session_id, act_id, actor, status, masked_phone, doc_name, session_json, \
             prepared_json, created_at, expires_at, signer_capacity_evidence_json \
             FROM pending_cmd_sessions WHERE session_id = $1",
            &[&session_id],
        )?;
        row.as_ref().map(row_to_pending_session).transpose()
    }

    pub(crate) fn all_pending_cmd_sessions(
        &self,
    ) -> Result<std::collections::HashMap<String, PendingCmdSession>, StoreError> {
        let mut client = self.read()?;
        let rows = client.query(
            "SELECT session_id, act_id, actor, status, masked_phone, doc_name, session_json, \
             prepared_json, created_at, expires_at, signer_capacity_evidence_json \
             FROM pending_cmd_sessions",
            &[],
        )?;
        let mut out = std::collections::HashMap::new();
        for row in &rows {
            let session = row_to_pending_session(row)?;
            out.insert(session.session_id.clone(), session);
        }
        Ok(out)
    }
}

/// The `paper_book_ocr_conversion_execution_artifacts` column list, shared by the by-key read, the
/// list read, and the in-transaction read-back so their projection stays in lock-step.
pub(crate) const ARTIFACT_COLUMNS: &str = "artifact_id, import_id, draft_id, dossier_id, \
    source_text_digest, source_page_spans_json, source_review_status, source_reviewed_at, \
    source_reviewed_by, target_act_id, target_act_state, mutable_draft_act_created, created_at, \
    created_by, canonical_conversion_claimed, canonical_minutes_claimed, canonical_act_created, \
    canonical_document_created, signed_document_created, archive_package_created, pdfa_created, \
    pdfua_created, signature_created, seal_created, archive_certification_claimed, \
    legal_validity_claimed, source_extracted_text_in_artifact, source_extracted_text_in_ledger_event";

/// The `signed_documents` column list, shared by the by-act and boot-rehydrate reads.
pub(crate) const SIGNED_DOCUMENT_COLUMNS: &str = "act_id, document_id, signed_pdf_digest, \
    signature_family, evidentiary_level, trusted_list_status, signer_cert_subject, signing_time, \
    signed_at, signer_cert_der, timestamp_token_der, timestamp_trust_report_json, \
    signer_capacity_evidence_json, signed_pdf_bytes";

/// Convert one `rusqlite::types::Value` (only `Integer`/`Text` appear in the ledger-page predicate
/// builder) into an owned Postgres parameter.
fn value_to_pg_param(value: &Value) -> Box<dyn ToSql + Sync> {
    match value {
        Value::Integer(i) => Box::new(*i),
        Value::Text(s) => Box::new(s.clone()),
        // The ledger-page SQL builder never emits other variants; bind NULL defensively.
        _ => Box::new(Option::<i64>::None),
    }
}

/// Read one `events` row (as pooled/`postgres` types) into a [`RawEventRow`], matching the boot
/// [`PostgresBackend::load`] projection so `into_event` rebuilds an identical [`chancela_ledger::Event`].
pub(crate) fn raw_event_row(row: &Row) -> RawEventRow {
    RawEventRow {
        seq: row.get(0),
        id: row.get(1),
        actor: row.get(2),
        justification: row.get(3),
        timestamp: row.get(4),
        scope: row.get(5),
        kind: row.get(6),
        payload_digest: row.get(7),
        prev_hash: row.get(8),
        hash: row.get(9),
        links: row.get(10),
    }
}

/// Read a `BIGINT` boolean-flag column (SQLite stores `bool` as `INTEGER` 0/1, which the DDL
/// translator maps to `BIGINT`) back into a Rust `bool`.
fn pg_flag(row: &Row, idx: usize) -> bool {
    row.get::<_, i64>(idx) != 0
}

pub(crate) fn row_to_document(row: &Row) -> Result<StoredDocument, StoreError> {
    Ok(StoredDocument {
        id: row.get(0),
        act_id: parse_uuid_newtype::<ActId>(&row.get::<_, String>(1))?,
        template_id: row.get(2),
        pdf_digest: row.get(3),
        profile: row.get(4),
        created_at: parse_rfc3339(&row.get::<_, String>(5))?,
        pdf_bytes: row.get(6),
    })
}

pub(crate) fn row_to_generated_dispatch_evidence(
    row: &Row,
) -> Result<StoredGeneratedDocumentDispatchEvidence, StoreError> {
    let recipients_json: String = row.get(10);
    Ok(StoredGeneratedDocumentDispatchEvidence {
        document_id: row.get(0),
        idempotency_key: row.get(1),
        act_id: parse_uuid_newtype::<ActId>(&row.get::<_, String>(2))?,
        template_id: row.get(3),
        actor: row.get(4),
        dispatched_at: parse_rfc3339(&row.get::<_, String>(5))?,
        channel: row.get(6),
        reference: row.get(7),
        evidence_reference: row.get(8),
        imported_document_id: row.get(9),
        recipients: serde_json::from_str(&recipients_json)?,
        operator_note: row.get(11),
        recorded_at: parse_rfc3339(&row.get::<_, String>(12))?,
    })
}

pub(crate) fn row_to_imported_document_meta(
    row: &Row,
) -> Result<StoredImportedDocumentMeta, StoreError> {
    crate::imported_document_meta_from_raw(
        row.get(0),
        row.get(1),
        row.get(2),
        row.get(3),
        row.get(4),
        row.get(5),
        row.get(6),
        row.get(7),
        row.get(8),
        row.get(9),
        row.get(10),
        row.get(11),
        row.get(12),
        row.get(13),
    )
}

pub(crate) fn row_to_imported_document(row: &Row) -> Result<StoredImportedDocument, StoreError> {
    Ok(StoredImportedDocument {
        meta: crate::imported_document_meta_from_raw(
            row.get(0),
            row.get(1),
            row.get(2),
            row.get(3),
            row.get(4),
            row.get(5),
            row.get(6),
            row.get(7),
            row.get(8),
            row.get(9),
            row.get(10),
            row.get(11),
            row.get(12),
            row.get(13),
        )?,
        bytes: row.get(14),
    })
}

pub(crate) fn row_to_imported_document_review_history_entry(
    row: &Row,
) -> Result<StoredImportedDocumentReviewHistoryEntry, StoreError> {
    let review_status_raw: String = row.get(2);
    let reviewed_at_raw: Option<String> = row.get(3);
    let acknowledged_guardrail_ids_json: String = row.get(6);
    Ok(StoredImportedDocumentReviewHistoryEntry {
        id: row.get(0),
        imported_document_id: row.get(1),
        review_status: StoredImportedDocumentReviewStatus::parse(&review_status_raw)?,
        reviewed_at: reviewed_at_raw.as_deref().map(parse_rfc3339).transpose()?,
        reviewed_by: row.get(4),
        review_note: row.get(5),
        acknowledged_guardrail_ids: serde_json::from_str(&acknowledged_guardrail_ids_json)?,
    })
}

pub(crate) fn row_to_paper_book_import_meta(
    row: &Row,
) -> Result<StoredPaperBookImportMeta, StoreError> {
    crate::paper_book_import_meta_from_raw(
        row.get(0),
        row.get(1),
        row.get(2),
        row.get(3),
        row.get(4),
        row.get(5),
        row.get(6),
        row.get(7),
        row.get(8),
        row.get(9),
        row.get(10),
        row.get(11),
        row.get(12),
        row.get(13),
        row.get(14),
        row.get(15),
        row.get(16),
        row.get(17),
        row.get(18),
        row.get(19),
    )
}

pub(crate) fn row_to_paper_book_import(row: &Row) -> Result<StoredPaperBookImport, StoreError> {
    Ok(StoredPaperBookImport {
        meta: row_to_paper_book_import_meta(row)?,
        bytes: row.get(20),
    })
}

pub(crate) fn row_to_paper_book_ocr_draft(
    row: &Row,
) -> Result<StoredPaperBookOcrDraft, StoreError> {
    let page_spans_json: String = row.get(4);
    let review_status_raw: String = row.get(10);
    let reviewed_at_raw: Option<String> = row.get(11);
    Ok(StoredPaperBookOcrDraft {
        draft_id: row.get(0),
        import_id: row.get(1),
        extracted_text: row.get(2),
        text_digest: row.get(3),
        page_spans: serde_json::from_str(&page_spans_json)?,
        confidence: row.get(5),
        engine_name: row.get(6),
        engine_version: row.get(7),
        created_at: parse_rfc3339(&row.get::<_, String>(8))?,
        created_by: row.get(9),
        review_status: StoredPaperBookOcrReviewStatus::parse(&review_status_raw)?,
        reviewed_at: reviewed_at_raw.as_deref().map(parse_rfc3339).transpose()?,
        reviewed_by: row.get(12),
        review_note: row.get(13),
        superseded_by: row.get(14),
    })
}

pub(crate) fn row_to_paper_book_ocr_conversion_dossier(
    row: &Row,
) -> Result<StoredPaperBookOcrConversionDossier, StoreError> {
    let source_page_spans_json: String = row.get(4);
    let source_review_status_raw: String = row.get(5);
    let source_reviewed_at_raw: Option<String> = row.get(6);
    Ok(StoredPaperBookOcrConversionDossier {
        dossier_id: row.get(0),
        import_id: row.get(1),
        draft_id: row.get(2),
        source_text_digest: row.get(3),
        source_page_spans: serde_json::from_str(&source_page_spans_json)?,
        source_review_status: StoredPaperBookOcrReviewStatus::parse(&source_review_status_raw)?,
        source_reviewed_at: source_reviewed_at_raw
            .as_deref()
            .map(parse_rfc3339)
            .transpose()?,
        source_reviewed_by: row.get(7),
        created_at: parse_rfc3339(&row.get::<_, String>(8))?,
        created_by: row.get(9),
    })
}

pub(crate) fn row_to_paper_book_ocr_conversion_execution_artifact(
    row: &Row,
) -> Result<StoredPaperBookOcrConversionExecutionArtifact, StoreError> {
    let source_page_spans_json: String = row.get(5);
    let source_review_status_raw: String = row.get(6);
    let source_reviewed_at_raw: Option<String> = row.get(7);
    let artifact = StoredPaperBookOcrConversionExecutionArtifact {
        artifact_id: row.get(0),
        import_id: row.get(1),
        draft_id: row.get(2),
        dossier_id: row.get(3),
        source_text_digest: row.get(4),
        source_page_spans: serde_json::from_str(&source_page_spans_json)?,
        source_review_status: StoredPaperBookOcrReviewStatus::parse(&source_review_status_raw)?,
        source_reviewed_at: source_reviewed_at_raw
            .as_deref()
            .map(parse_rfc3339)
            .transpose()?,
        source_reviewed_by: row.get(8),
        target_act_id: row.get(9),
        target_act_state: row.get(10),
        mutable_draft_act_created: pg_flag(row, 11),
        created_at: parse_rfc3339(&row.get::<_, String>(12))?,
        created_by: row.get(13),
        canonical_conversion_claimed: pg_flag(row, 14),
        canonical_minutes_claimed: pg_flag(row, 15),
        canonical_act_created: pg_flag(row, 16),
        canonical_document_created: pg_flag(row, 17),
        signed_document_created: pg_flag(row, 18),
        archive_package_created: pg_flag(row, 19),
        pdfa_created: pg_flag(row, 20),
        pdfua_created: pg_flag(row, 21),
        signature_created: pg_flag(row, 22),
        seal_created: pg_flag(row, 23),
        archive_certification_claimed: pg_flag(row, 24),
        legal_validity_claimed: pg_flag(row, 25),
        source_extracted_text_in_artifact: pg_flag(row, 26),
        source_extracted_text_in_ledger_event: pg_flag(row, 27),
    };
    crate::validate_paper_book_ocr_conversion_execution_artifact(&artifact)?;
    Ok(artifact)
}

pub(crate) fn row_to_follow_up(row: &Row) -> Result<StoredFollowUp, StoreError> {
    let agenda_number_raw: Option<i64> = row.get(2);
    let deliberation_index_raw: Option<i64> = row.get(3);
    let due_date_raw: Option<String> = row.get(6);
    let status_raw: String = row.get(9);
    let completed_at_raw: Option<String> = row.get(12);
    Ok(StoredFollowUp {
        id: row.get(0),
        act_id: parse_uuid_newtype::<ActId>(&row.get::<_, String>(1))?,
        agenda_number: agenda_number_raw.map(int_to_u32).transpose()?,
        deliberation_index: deliberation_index_raw.map(int_to_u32).transpose()?,
        title: row.get(4),
        detail: row.get(5),
        due_date: due_date_raw.as_deref().map(parse_date).transpose()?,
        assignee: row.get(7),
        assignee_display: row.get(8),
        status: StoredFollowUpStatus::parse(&status_raw)?,
        created_at: parse_rfc3339(&row.get::<_, String>(10))?,
        created_by: row.get(11),
        completed_at: completed_at_raw.as_deref().map(parse_rfc3339).transpose()?,
        completed_by: row.get(13),
    })
}

pub(crate) fn row_to_signed_document(row: &Row) -> Result<StoredSignedDocument, StoreError> {
    Ok(StoredSignedDocument {
        act_id: parse_uuid_newtype::<ActId>(&row.get::<_, String>(0))?,
        document_id: row.get(1),
        signed_pdf_digest: row.get(2),
        signature_family: row.get(3),
        evidentiary_level: row.get(4),
        trusted_list_status: row.get(5),
        signer_cert_subject: row.get(6),
        signing_time: parse_rfc3339(&row.get::<_, String>(7))?,
        signed_at: parse_rfc3339(&row.get::<_, String>(8))?,
        signer_cert_der: row.get(9),
        timestamp_token_der: row.get(10),
        timestamp_trust_report_json: row.get(11),
        signer_capacity_evidence_json: row.get(12),
        signed_pdf_bytes: row.get(13),
    })
}

pub(crate) fn row_to_pending_session(row: &Row) -> Result<PendingCmdSession, StoreError> {
    Ok(PendingCmdSession {
        session_id: row.get(0),
        act_id: parse_uuid_newtype::<ActId>(&row.get::<_, String>(1))?,
        actor: row.get(2),
        status: row.get(3),
        masked_phone: row.get(4),
        doc_name: row.get(5),
        session_json: row.get(6),
        prepared_json: row.get(7),
        created_at: parse_rfc3339(&row.get::<_, String>(8))?,
        expires_at: parse_rfc3339(&row.get::<_, String>(9))?,
        signer_capacity_evidence_json: row.get(10),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imported_documents_guardrail_ack_column_is_in_fresh_and_additive_ddl() {
        let column = "operator_acknowledged_guardrail_ids_json TEXT NOT NULL DEFAULT '[]'";
        let fresh_pg = crate::dialect::sqlite_ddl_to_pg(crate::schema::CREATE_IMPORTED_DOCUMENTS);

        assert!(
            fresh_pg.contains(column),
            "fresh Postgres imported_documents DDL must include guardrail acknowledgements: {fresh_pg}"
        );
        assert!(
            ADD_IMPORTED_DOCUMENTS_GUARDRAIL_ACK_COLUMN.contains("ADD COLUMN IF NOT EXISTS"),
            "additive guard must be idempotent: {ADD_IMPORTED_DOCUMENTS_GUARDRAIL_ACK_COLUMN}"
        );
        assert!(
            ADD_IMPORTED_DOCUMENTS_GUARDRAIL_ACK_COLUMN.contains(column),
            "additive guard must add the same column contract: {ADD_IMPORTED_DOCUMENTS_GUARDRAIL_ACK_COLUMN}"
        );
    }
}
