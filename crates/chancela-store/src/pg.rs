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
//! connection is never returned to a pool, the lock is never released while the server runs normally,
//! so a second instance pointed at the same database fails this backend's write gate unless it later
//! acquires the advisory lock. wp16 P0 promotes this from a blocking second-instance guard into a
//! bounded leader-election primitive: `open` now `pg_try_advisory_lock`s instead of blocking, so a
//! node that loses the race comes up as a read-only FOLLOWER and polls for promotion rather than
//! hanging (see [`crate::pg_cluster`] for the election / step-down / handoff /
//! `leader_epoch`-fence machinery). Compose additionally pins `deploy.replicas: 1` for the
//! single-writer profile (§6). TLS is now enforced (wp25 hardening): the connection requires
//! certificate-verified `sslmode=verify-full` (from `DATABASE_URL` or `CHANCELA_PG_SSLMODE`, with
//! `verify-ca` hardened to `verify-full`) through a rustls connector for the sync `postgres` stack —
//! see [`crate::pg_tls`].
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
//! The operator paths that were SQLite-file-shaped are now covered by a **portable logical**
//! implementation in [`crate::pg_backup`] (wp15): whole-store `backup` (an app-driven table export,
//! no `pg_dump`/`VACUUM INTO`), verify-before-trust whole-store `restore` (one atomic
//! `TRUNCATE`/`INSERT` transaction that re-verifies the ledger head), and the [`crate::recovery`]
//! domain-wipe / factory-blank / whole-instance start-over / re-anchor paths (the row-clearing runs
//! through the backend-agnostic [`crate::Tx::execute_recovery_batch`]).
//!
//! wp21 completes the operator surface: the **per-book** portability paths — `export_book`
//! (logical per-book bundle: the book + entity + acts + book-chain events + documents, same
//! `chancela-book-bundle/v1` contract as SQLite), `import_book` / `preflight_import_book_bytes`
//! (verify-before-trust, then the retained bundle + verdict + chained `ledger.imported` written in
//! one transaction via the backend-agnostic [`crate::Tx::insert_imported_book`]), `imported_books`,
//! `imported_bundle`, and per-book `start_over_book` — now run on Postgres through the pooled reads
//! and the portable `Tx` writer above rather than the SQLite-only `Tx::raw` / `Store::locked_conn`
//! accessors. The `restore_preflight` drill also runs: because there is no SQLite `chancela.db` to
//! materialize into a temp workspace, the Postgres preflight instead performs the full in-memory
//! verify-before-trust of the logical bundle (manifest fixity + every per-table digest + a ledger
//! hash-chain re-run) — the same non-destructive evidence, never touching the live database.
//!
//! Nothing operator-facing now fails closed with [`crate::StoreError::UnsupportedOnPostgres`]; the
//! only remaining arms are the genuinely SQLite-only internals — direct `rusqlite::Connection`
//! access ([`crate::Store::locked_conn`]) and the raw-SQL escape hatch ([`crate::Tx::raw`]) — which
//! exist so the SQLite backend's bespoke `PRAGMA`/file paths compile; every portable operation is
//! routed around them on Postgres.

use std::sync::atomic::{AtomicBool, AtomicI64};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chancela_core::{
    Act, ActId, Book, CompanyGroup, Entity, EntityId, GroupTemplateLibrary,
    GroupTemplateLibraryRevision,
};
use chancela_ledger::Ledger;
use chancela_registry::RegistryExtract;
use chancela_search::{
    IndexOperation as SearchIndexOperation, SearchIndexState, SearchProjectionCheckpoint,
    SearchProjectionControl, SearchProjectionPublishOutcome, SearchProjectorLease,
};
use postgres::types::ToSql;
use postgres::{Client, Row};
use r2d2_postgres::PostgresConnectionManager;
use rusqlite::types::Value;
use time::format_description::well_known::Rfc3339;

use crate::{
    LedgerEventPage, LedgerEventPageQuery, LoadedState, PendingCmdSession, RawEventRow,
    SearchCorpusSnapshot, StoreError, StoredCredentialRecord, StoredDocument,
    StoredDocumentSearchMetadata, StoredEmailDelivery, StoredFollowUp, StoredFollowUpStatus,
    StoredGeneratedDocumentDispatchEvidence, StoredImportedDocument, StoredImportedDocumentMeta,
    StoredImportedDocumentReviewHistoryEntry, StoredImportedDocumentReviewStatus,
    StoredPaperBookImport, StoredPaperBookImportMeta, StoredPaperBookOcrConversionDossier,
    StoredPaperBookOcrConversionExecutionArtifact, StoredPaperBookOcrDraft,
    StoredPaperBookOcrReviewStatus, StoredPaperBookOcrStatus, StoredSignedDocument,
    StoredUserTemplateVersion, int_to_u32, parse_date, parse_rfc3339, parse_uuid_newtype,
};

/// Fixed key for the process-wide writer advisory lock (§4). An arbitrary, stable 64-bit constant
/// derived from "chancela-writer"; two instances contend on the same key.
pub(crate) const WRITER_ADVISORY_LOCK_KEY: i64 = 0x0C_1A_17_CE_1A_17_CE_11u64 as i64;
const FOLLOWER_SCHEMA_READY_TIMEOUT: Duration = Duration::from_secs(30);
const FOLLOWER_SCHEMA_READY_POLL: Duration = Duration::from_millis(100);
const LOCK_SCHEMA_MARKER_TABLE: &str = "LOCK TABLE meta IN ACCESS EXCLUSIVE MODE";
const INVALIDATE_SCHEMA_VERSION_MARKER: &str = "DELETE FROM meta WHERE key = 'schema_version'";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LeaderSchemaSetupStep {
    PreflightAndInvalidateMarker,
    BaseDdl,
    AdditiveColumns,
    SeedSingletons,
    ClusterEpoch,
    PublishMarker,
}

const LEADER_SCHEMA_SETUP_ORDER: [LeaderSchemaSetupStep; 6] = [
    LeaderSchemaSetupStep::PreflightAndInvalidateMarker,
    LeaderSchemaSetupStep::BaseDdl,
    LeaderSchemaSetupStep::AdditiveColumns,
    LeaderSchemaSetupStep::SeedSingletons,
    LeaderSchemaSetupStep::ClusterEpoch,
    LeaderSchemaSetupStep::PublishMarker,
];

#[derive(Debug, Clone, PartialEq, Eq)]
enum SchemaMarkerState {
    Ready,
    Retry { observed: String },
    Newer(i64),
    Invalid(String),
}

fn classify_schema_marker(raw: Option<&str>) -> SchemaMarkerState {
    let Some(raw) = raw else {
        return SchemaMarkerState::Retry {
            observed: "missing".to_owned(),
        };
    };
    let trimmed = raw.trim();
    let Ok(version) = trimmed.parse::<i64>() else {
        return SchemaMarkerState::Invalid(trimmed.chars().take(64).collect());
    };
    if version == crate::schema::SCHEMA_VERSION {
        SchemaMarkerState::Ready
    } else if version < crate::schema::SCHEMA_VERSION {
        SchemaMarkerState::Retry {
            observed: version.to_string(),
        }
    } else {
        SchemaMarkerState::Newer(version)
    }
}

/// Additive guard matching SQLite's `configure_and_migrate` column repair for databases opened by
/// earlier builds before the column was folded into the fresh-table DDL.
pub(crate) const ADD_IMPORTED_DOCUMENTS_GUARDRAIL_ACK_COLUMN: &str = "ALTER TABLE imported_documents ADD COLUMN IF NOT EXISTS \
     operator_acknowledged_guardrail_ids_json TEXT NOT NULL DEFAULT '[]';";
pub(crate) const ADD_IMPORTED_DOCUMENTS_TECHNICAL_VALIDATION_REPORT_COLUMN: &str = "ALTER TABLE imported_documents ADD COLUMN IF NOT EXISTS \
     technical_validation_report_json TEXT NOT NULL DEFAULT '{}';";
/// t74 §8: the producing template spec beside the produced bytes. **Deliberately nullable with no
/// default** — unlike the two guards above, a pre-v24 document genuinely has no spec body, and a
/// `DEFAULT` here would manufacture one and erase the distinction between "written before this
/// existed" and "written wrong".
pub(crate) const ADD_DOCUMENTS_TEMPLATE_SPEC_COLUMN: &str =
    "ALTER TABLE documents ADD COLUMN IF NOT EXISTS template_spec_json TEXT;";
/// v28: the concrete resolved layout beside the produced bytes. Nullable with no default so old
/// rows remain honestly unbound instead of inheriting a value invented during migration.
pub(crate) const ADD_DOCUMENTS_LAYOUT_COLUMN: &str =
    "ALTER TABLE documents ADD COLUMN IF NOT EXISTS document_layout_json TEXT;";

/// wp16 P1 change-feed tail query. Kept as a named contract so tests can pin the ordering and
/// strict `seq > after_seq` semantics the follower's fail-closed delta seam depends on.
pub(crate) const EVENTS_SINCE_SQL: &str = "SELECT seq, id, actor, justification, timestamp, scope, kind, payload_digest, \
     prev_hash, hash, links FROM events WHERE seq > $1 ORDER BY seq";
pub(crate) const DOCUMENT_SEARCH_METADATA_SELECT: &str = "SELECT id, act_id, template_id, pdf_digest, profile, created_at \
     FROM documents ORDER BY created_at ASC, id ASC";
pub(crate) const GENERATED_DOCUMENT_DISPATCH_EVIDENCE_ALL_SELECT: &str = "SELECT document_id, idempotency_key, act_id, template_id, actor, dispatched_at, \
     channel, reference, evidence_reference, imported_document_id, recipients_json, \
     operator_note, recorded_at FROM generated_document_dispatch_evidence \
     ORDER BY recorded_at ASC, document_id ASC, idempotency_key ASC";
pub(crate) const IMPORTED_DOCUMENTS_ALL_SELECT: &str = "SELECT id, act_id, filename, declared_content_type, detected_content_type, \
     sha256, size_bytes, imported_at, imported_by, operator_review_status, \
     operator_reviewed_at, operator_reviewed_by, operator_review_note, \
     operator_acknowledged_guardrail_ids_json, technical_validation_report_json \
     FROM imported_documents ORDER BY imported_at DESC, id DESC";
pub(crate) const PAPER_BOOK_IMPORTS_ALL_SELECT: &str = "SELECT import_id, entity_ref, entity_name, entity_nipc, book_ref, date_from, \
     date_to, page_count, page_from, page_to, original_number_from, original_number_to, sha256, \
     size_bytes, content_type, source_filename, notes, imported_at, imported_by, ocr_status \
     FROM paper_book_imports ORDER BY imported_at DESC, import_id DESC";
pub(crate) const PAPER_BOOK_OCR_DRAFTS_ALL_SELECT: &str = "SELECT draft_id, import_id, extracted_text, text_digest, page_spans_json, confidence, \
     engine_name, engine_version, created_at, created_by, review_status, reviewed_at, \
     reviewed_by, review_note, superseded_by FROM paper_book_ocr_drafts \
     ORDER BY import_id ASC, created_at DESC, draft_id DESC";

pub(crate) fn decode_search_projection_control_row(
    row: &Row,
) -> Result<SearchProjectionControl, StoreError> {
    crate::decode_search_projection_control(crate::RawSearchProjectionControl {
        source_revision: row.get(0),
        fence_token: row.get(1),
        published_source_revision: row.get(2),
        published_fence_token: row.get(3),
        published_command_generation: row.get(4),
        command: row.get(5),
        command_generation: row.get(6),
        lease_id: row.get(7),
        lease_owner: row.get(8),
        lease_heartbeat_at: row.get(9),
        lease_expires_at_unix_ms: row.get(10),
        updated_at: row.get(11),
    })
}

fn pg_now_unix_millis(transaction: &mut postgres::Transaction<'_>) -> Result<i64, StoreError> {
    Ok(transaction
        .query_one(
            "SELECT (EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::BIGINT",
            &[],
        )?
        .get(0))
}

/// The `r2d2` connection manager type for the read pool. The TLS connector is always the
/// rustls-based [`crate::pg_tls::MakeRustlsConnect`]; whether TLS is actually negotiated is decided
/// by the connection's `ssl_mode` (resolved in [`crate::pg_tls::resolve`]); only certificate-verified
/// TLS is accepted, so plaintext and encrypt-only modes fail closed before any socket is opened.
type PgManager = PostgresConnectionManager<crate::pg_tls::MakeRustlsConnect>;

struct PostgresResources {
    pool: r2d2::Pool<PgManager>,
    writer: Mutex<Client>,
}

/// Own the synchronous driver's runtime-bearing resources and guarantee their final destruction
/// never happens from inside a Tokio runtime. `postgres::Client::drop` drives its private runtime
/// with `block_on`, so dropping the last `Store` clone in an async task would otherwise panic.
struct RuntimeSafePostgresResources {
    value: Option<PostgresResources>,
}

impl RuntimeSafePostgresResources {
    fn new(value: PostgresResources) -> Self {
        Self { value: Some(value) }
    }
}

impl std::ops::Deref for RuntimeSafePostgresResources {
    type Target = PostgresResources;

    fn deref(&self) -> &Self::Target {
        self.value
            .as_ref()
            .expect("Postgres resources are present until final drop")
    }
}

impl Drop for RuntimeSafePostgresResources {
    fn drop(&mut self) {
        let Some(value) = self.value.take() else {
            return;
        };
        drop_outside_tokio_runtime(value, "chancela-postgres-drop");
    }
}

fn drop_outside_tokio_runtime<T: Send + 'static>(value: T, thread_name: &'static str) {
    if tokio::runtime::Handle::try_current().is_err() {
        drop(value);
        return;
    }

    // Keep ownership outside the spawn closure so an OS thread creation failure cannot drop the
    // runtime-bearing clients back on the Tokio worker. In that exceptional condition, leaking at
    // process teardown is safer than a double-panic abort.
    let slot = Arc::new(Mutex::new(Some(value)));
    let worker_slot = slot.clone();
    match std::thread::Builder::new()
        .name(thread_name.to_owned())
        .spawn(move || {
            let value = worker_slot
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            drop(value);
        }) {
        Ok(_) => {}
        Err(error) => {
            let value = slot
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            std::mem::forget(value);
            eprintln!(
                "warning: failed to start safe PostgreSQL cleanup thread; resources were \
                 deliberately leaked to avoid nested-runtime teardown: {error}"
            );
        }
    }
}

/// The PostgreSQL backend: a read pool plus a single advisory-locked writer connection.
#[derive(Clone)]
pub(crate) struct PostgresBackend {
    /// Pooled reads plus the single advisory-locked writer, with final drop isolated from Tokio.
    resources: Arc<RuntimeSafePostgresResources>,
    /// wp16 P0 — leader-election state. `true` iff **this session** currently holds the writer
    /// advisory lock and is the cluster writer-leader. Flipped to `false` (fail-closed) the instant a
    /// liveness check finds the lock lost / the epoch stolen / the writer session broken. The
    /// [`crate::pg_cluster`] module owns every transition; see it for the invariants.
    pub(crate) leader: Arc<AtomicBool>,
    /// True only after a node may serve writes. A promoted follower holds the advisory lock and is
    /// `leader == true` while its API handoff reloads and verifies durable state, but this flag stays
    /// false until that handoff succeeds.
    pub(crate) writes_enabled: Arc<AtomicBool>,
    /// This node's stable identity, recorded in `cluster_leader` on promotion (env
    /// `CHANCELA_NODE_ADDRESS`, else a per-process uuid).
    pub(crate) node_id: Arc<str>,
    /// wp16 P2 — this node's externally-reachable base URL (env `CHANCELA_ADVERTISED_URL`, else
    /// empty). Heartbeated into `cluster_leader.advertised_addr` while this node is leader so
    /// followers can `307`-redirect writes here. Never client-derived (no open-redirect vector).
    pub(crate) advertised_addr: Arc<str>,
    /// The `leader_epoch` this node claimed on its last promotion (`-1` until it has ever led). Used
    /// as the defence-in-depth fence (§4.3): a write / heartbeat that no longer owns the current
    /// durable epoch fails closed.
    pub(crate) my_epoch: Arc<AtomicI64>,
    /// The libpq connection string this backend opened with. Retained so wp16 P1's follower
    /// change-feed can open its **own dedicated** `LISTEN chancela_ledger` connection without ever
    /// touching the writer session or the read pool (plan §2.2).
    pub(crate) dsn: Arc<str>,
}

impl std::fmt::Debug for PostgresBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The underlying `postgres::Client` is not `Debug`; report the pool state only.
        f.debug_struct("PostgresBackend")
            .field("pool_state", &self.resources.pool.state().connections)
            .field("writer", &"<advisory-locked postgres client>")
            .finish()
    }
}

impl PostgresBackend {
    /// Connect to `database_url`, take the writer advisory lock, and run the per-backend DDL.
    ///
    /// `database_url` is a libpq connection string (`postgres://user:pass@host:5432/db`). The TLS
    /// posture is resolved from `CHANCELA_PG_SSLMODE` or the URL's `sslmode=` (defaulting to
    /// `verify-full`) and applied through the rustls connector in [`crate::pg_tls`]; both the read pool
    /// and the writer share the same resolved [`postgres::Config`] + connector.
    pub(crate) fn open(database_url: &str) -> Result<Self, StoreError> {
        let crate::pg_tls::ResolvedPgTls {
            config,
            connector,
            mode: _mode,
        } = crate::pg_tls::resolve(database_url)?;

        // Read pool. The resolved config carries the wire `ssl_mode`; the connector encrypts when
        // that mode negotiates certificate-verified TLS; insecure modes fail in pg_tls::resolve.
        let manager = PostgresConnectionManager::new(config.clone(), connector.clone());
        let pool = r2d2::Pool::builder().build(manager)?;

        // Dedicated writer connection. wp16 P0 promotes the wp14 writer advisory lock from a blocking
        // second-instance guard into a **leader-election** primitive: instead of blocking, we
        // `pg_try_advisory_lock` (unless pinned `CHANCELA_NODE_ROLE=follower`, which never contends).
        // Winning the lock ⇒ this session is the (candidate) LEADER and the only writer; losing it ⇒
        // this node is a FOLLOWER that comes up read-only and polls for promotion (see
        // [`crate::pg_cluster`]). The lock stays on this one never-pooled connection so the ledger's
        // single-writer invariant is physically coupled to the write channel (plan §7.3).
        let mut writer = config.connect(connector)?;
        let mode = crate::pg_cluster::resolve_election_mode();
        let node_id: Arc<str> = Arc::from(crate::pg_cluster::resolve_node_id());
        let advertised_addr: Arc<str> = Arc::from(crate::pg_cluster::resolve_advertised_url());
        let is_leader = crate::pg_cluster::acquire_writer_lock(&mut writer, mode)?;
        let mut epoch: i64 = -1;
        if is_leader {
            for step in LEADER_SCHEMA_SETUP_ORDER {
                match step {
                    LeaderSchemaSetupStep::PreflightAndInvalidateMarker => {
                        Self::preflight_and_invalidate_schema_version(&mut writer)?;
                    }
                    LeaderSchemaSetupStep::BaseDdl => {
                        // Leader-only: run the idempotent DDL derived from SQLite so both dialects
                        // stay in lock-step. Followers skip DDL and wait for final publication.
                        for stmt in crate::schema::ALL {
                            writer.batch_execute(&crate::dialect::sqlite_ddl_to_pg(stmt))?;
                        }
                    }
                    LeaderSchemaSetupStep::AdditiveColumns => {
                        Self::ensure_additive_columns(&mut writer)?;
                    }
                    LeaderSchemaSetupStep::SeedSingletons => {
                        Self::seed_meta_and_search_control(&mut writer)?;
                    }
                    LeaderSchemaSetupStep::ClusterEpoch => {
                        // Bump the monotonic epoch while holding the advisory lock, fencing any
                        // deposed leader before the schema is advertised as ready.
                        epoch = crate::pg_cluster::ensure_cluster_table_and_bump_epoch(
                            &mut writer,
                            node_id.as_ref(),
                            advertised_addr.as_ref(),
                        )?;
                    }
                    LeaderSchemaSetupStep::PublishMarker => {
                        // Absolute final publication marker: a follower that observes the current
                        // version is guaranteed to see every setup step above.
                        Self::publish_schema_version(&mut writer)?;
                    }
                }
            }
        } else {
            Self::wait_for_schema_readiness(&pool)?;
        }

        Ok(Self {
            resources: Arc::new(RuntimeSafePostgresResources::new(PostgresResources {
                pool,
                writer: Mutex::new(writer),
            })),
            leader: Arc::new(AtomicBool::new(is_leader)),
            writes_enabled: Arc::new(AtomicBool::new(is_leader)),
            node_id,
            advertised_addr,
            my_epoch: Arc::new(AtomicI64::new(epoch)),
            dsn: Arc::from(database_url),
        })
    }

    /// Keep Postgres in step with SQLite's idempotent additive column guards before metadata is
    /// stamped current.
    fn ensure_additive_columns(writer: &mut Client) -> Result<(), StoreError> {
        writer.batch_execute(ADD_IMPORTED_DOCUMENTS_GUARDRAIL_ACK_COLUMN)?;
        writer.batch_execute(ADD_IMPORTED_DOCUMENTS_TECHNICAL_VALIDATION_REPORT_COLUMN)?;
        writer.batch_execute(ADD_DOCUMENTS_TEMPLATE_SPEC_COLUMN)?;
        writer.batch_execute(ADD_DOCUMENTS_LAYOUT_COLUMN)?;
        Ok(())
    }

    /// Fail closed on malformed/newer versions, then remove the readiness marker before any
    /// idempotent repair begins. The table lock makes validation + deletion atomic to followers:
    /// they either read the previously complete schema before this transaction starts, or block
    /// until the marker is absent and retry while setup is in progress.
    fn preflight_and_invalidate_schema_version(writer: &mut Client) -> Result<(), StoreError> {
        let mut transaction = writer.transaction()?;
        if let Err(error) = transaction.batch_execute(LOCK_SCHEMA_MARKER_TABLE) {
            if error.code() == Some(&postgres::error::SqlState::UNDEFINED_TABLE) {
                transaction.rollback()?;
                return Ok(());
            }
            return Err(error.into());
        }
        if let Some(row) =
            transaction.query_opt("SELECT value FROM meta WHERE key = 'schema_version'", &[])?
        {
            match classify_schema_marker(Some(&row.get::<_, String>(0))) {
                SchemaMarkerState::Ready | SchemaMarkerState::Retry { .. } => {}
                SchemaMarkerState::Newer(found) => {
                    return Err(StoreError::UnsupportedSchemaVersion {
                        found,
                        supported: crate::schema::SCHEMA_VERSION,
                    });
                }
                SchemaMarkerState::Invalid(observed) => {
                    return Err(StoreError::InvalidPostgresSchemaVersion { observed });
                }
            }
        }
        transaction.execute(INVALIDATE_SCHEMA_VERSION_MARKER, &[])?;
        transaction.commit()?;
        Ok(())
    }

    /// Mint non-version singleton metadata. The version marker is published only after cluster
    /// setup has also completed.
    fn seed_meta_and_search_control(writer: &mut Client) -> Result<(), StoreError> {
        // Minted once, then immutable: `ON CONFLICT DO NOTHING` preserves a restored/source id.
        writer.execute(
            "INSERT INTO meta (key, value) VALUES ('instance_id', $1) ON CONFLICT (key) DO NOTHING",
            &[&uuid::Uuid::new_v4().to_string()],
        )?;
        let updated_at = crate::now_rfc3339();
        writer.execute(
            "INSERT INTO search_projection_control \
             (id, source_revision, fence_token, command, command_generation, updated_at) \
             VALUES ($1, 0, 0, 'reconcile', 0, $2) ON CONFLICT (id) DO NOTHING",
            &[&crate::SEARCH_PROJECTION_CONTROL_SINGLETON_ID, &updated_at],
        )?;
        Ok(())
    }

    fn publish_schema_version(writer: &mut Client) -> Result<(), StoreError> {
        writer.execute(
            "INSERT INTO meta (key, value) VALUES ('schema_version', $1) \
             ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
            &[&crate::schema::SCHEMA_VERSION.to_string()],
        )?;
        Ok(())
    }

    fn wait_for_schema_readiness(pool: &r2d2::Pool<PgManager>) -> Result<(), StoreError> {
        let started = Instant::now();
        loop {
            let mut client = pool.get()?;
            let observed = match client
                .query_opt("SELECT value FROM meta WHERE key = 'schema_version'", &[])
            {
                Ok(row) => {
                    let raw = row.as_ref().map(|row| row.get::<_, String>(0));
                    match classify_schema_marker(raw.as_deref()) {
                        SchemaMarkerState::Ready => return Ok(()),
                        SchemaMarkerState::Retry { observed } => observed,
                        SchemaMarkerState::Newer(found) => {
                            return Err(StoreError::UnsupportedSchemaVersion {
                                found,
                                supported: crate::schema::SCHEMA_VERSION,
                            });
                        }
                        SchemaMarkerState::Invalid(current) => {
                            return Err(StoreError::InvalidPostgresSchemaVersion {
                                observed: current,
                            });
                        }
                    }
                }
                Err(error) if error.code() == Some(&postgres::error::SqlState::UNDEFINED_TABLE) => {
                    "meta table missing".to_owned()
                }
                Err(error) => return Err(error.into()),
            };
            let elapsed = started.elapsed();
            if elapsed >= FOLLOWER_SCHEMA_READY_TIMEOUT {
                return Err(StoreError::PostgresSchemaNotReady {
                    waited_ms: u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
                    expected: crate::schema::SCHEMA_VERSION,
                    observed,
                });
            }
            std::thread::sleep(
                FOLLOWER_SCHEMA_READY_POLL
                    .min(FOLLOWER_SCHEMA_READY_TIMEOUT.saturating_sub(elapsed)),
            );
        }
    }

    /// Read the stable per-install `instance_id` from `meta` (present after schema publication).
    pub(crate) fn instance_id(&self) -> Result<String, StoreError> {
        let mut client = self.resources.pool.get()?;
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
        self.resources
            .writer
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// **wp28 election-liveness fix — reconnect the writer session if its connection has broken.**
    ///
    /// The writer is a single, never-pooled `postgres::Client` (§4). The synchronous `postgres`
    /// crate does NOT auto-reconnect: once its TCP connection is dropped — e.g. Postgres is
    /// restarted / bounced under it — every subsequent query on that client returns
    /// `connection closed` **forever**. Because the advisory-lock election runs on this one client
    /// (`try_promote`'s `pg_try_advisory_lock`), a Postgres bounce would otherwise leave every node's
    /// writer session permanently dead: the lock is freed cluster-wide (sessions gone) yet no live
    /// session can grab it, and the cluster stays STUCK LEADERLESS (the observed wp28 liveness bug).
    /// The pooled read path recovers on its own (r2d2 `test_on_check_out`); only this un-pooled writer
    /// needs explicit re-establishment.
    ///
    /// This cheaply probes the session and, when it is broken, opens a fresh writer connection from
    /// the retained DSN (same resolved config + rustls connector as [`Self::open`]).
    ///
    /// **Safety:** a freshly opened session holds NO advisory lock, so re-contention still goes
    /// through `pg_try_advisory_lock`, which Postgres grants to at most one session — the
    /// single-writer invariant is fully preserved (no split-brain). MUST only be called on a node
    /// that is NOT the current leader (a follower holds no lock to lose by swapping its session); the
    /// sole caller, [`Self::try_promote`], guarantees this by early-returning for a leader.
    pub(crate) fn reconnect_writer_if_broken(&self) -> Result<(), StoreError> {
        // Cheap liveness probe on the writer session; a broken/closed connection errors here. A
        // healthy follower session answers immediately and we leave it untouched.
        {
            let mut writer = self.writer();
            if writer.simple_query("SELECT 1").is_ok() {
                return Ok(());
            }
        }
        // The writer connection is dead — open a replacement and swap it in. If Postgres is not back
        // yet this returns an error; the caller retries on the next election tick (self-healing).
        let crate::pg_tls::ResolvedPgTls {
            config, connector, ..
        } = crate::pg_tls::resolve(&self.dsn)?;
        let fresh = config.connect(connector)?;
        *self.writer() = fresh;
        Ok(())
    }

    /// Boot replay: read the aggregate rows and all `events` (ordered by `seq`) into a
    /// [`LoadedState`], byte-for-byte the same reconstruction as the SQLite [`crate::Store::load`]
    /// path (the `events` rows feed `Ledger::try_from_events`, which re-verifies the chain).
    pub(crate) fn load(&self) -> Result<LoadedState, StoreError> {
        let mut client = self.resources.pool.get()?;
        let aggregates = load_aggregate_maps(&mut client, true)?;

        let mut events = Vec::new();
        for row in client.query(
            "SELECT seq, id, actor, justification, timestamp, scope, kind, payload_digest, \
             prev_hash, hash, links FROM events ORDER BY seq",
            &[],
        )? {
            events.push(raw_event_row(&row).into_event()?);
        }

        let (ledger, chain_status) = Ledger::try_from_events(events);
        let integrity = ledger.integrity_report();
        Ok(LoadedState {
            company_groups: aggregates.company_groups,
            group_template_libraries: aggregates.group_template_libraries,
            group_template_library_revisions: aggregates.group_template_library_revisions,
            entities: aggregates.entities,
            books: aggregates.books,
            acts: aggregates.acts,
            registry_extracts: aggregates.registry_extracts,
            follow_ups: aggregates.follow_ups,
            ledger,
            chain_status,
            integrity,
        })
    }

    pub(crate) fn load_search_corpus_snapshot(&self) -> Result<SearchCorpusSnapshot, StoreError> {
        let mut client = self.resources.pool.get()?;
        let aggregates = load_aggregate_maps(&mut client, false)?;
        let mut events = Vec::new();
        for row in client.query(
            "SELECT seq, id, actor, justification, timestamp, scope, kind, payload_digest, \
             prev_hash, hash, links FROM events ORDER BY seq",
            &[],
        )? {
            events.push(raw_event_row(&row).into_event()?);
        }
        let (ledger, chain_status) = Ledger::try_from_events(events);
        let integrity = ledger.integrity_report();
        Ok(SearchCorpusSnapshot {
            group_template_libraries: aggregates.group_template_libraries,
            group_template_library_revisions: aggregates.group_template_library_revisions,
            entities: aggregates.entities,
            books: aggregates.books,
            acts: aggregates.acts,
            registry_extracts: aggregates.registry_extracts,
            follow_ups: aggregates.follow_ups,
            ledger,
            chain_status,
            integrity,
        })
    }

    /// wp16 P1 — re-read **only** the aggregate read-model tables (no `events` scan), the store-side
    /// half of a follower's incremental delta apply (plan §2.3). The follower applies the ledger tail
    /// incrementally (seam-verified) and refreshes the small, bounded aggregate maps through this —
    /// the plan's sanctioned "simple v1" aggregate refresh, `O(aggregates)` not `O(all-events)`.
    pub(crate) fn load_aggregates(&self) -> Result<crate::AggregateSnapshot, StoreError> {
        let mut client = self.resources.pool.get()?;
        load_aggregate_maps(&mut client, true)
    }

    /// wp16 P1 — the ordered ledger tail `seq > after_seq` (plan §2.2/§2.3). The follower change-feed
    /// pulls this delta on a NOTIFY wake or a seq-poll tick and appends it onto its in-memory ledger
    /// after a fail-closed continuity check. Passing `-1` returns the whole chain (`seq >= 0`).
    pub(crate) fn events_since(
        &self,
        after_seq: i64,
    ) -> Result<Vec<chancela_ledger::Event>, StoreError> {
        let mut client = self.resources.pool.get()?;
        let mut events = Vec::new();
        for row in client.query(EVENTS_SINCE_SQL, &[&after_seq])? {
            events.push(raw_event_row(&row).into_event()?);
        }
        Ok(events)
    }

    /// wp16 P1 — the leader's transactional-ish change signal (plan §2.2). After a durable append
    /// commits, the leader issues `NOTIFY chancela_ledger, '<max_seq>'` on the writer session so
    /// followers wake immediately; a missed notification is retried by the follower's seq-poll
    /// backstop once Postgres can be queried, so this is best-effort by design. `max_seq` is a plain
    /// integer (no injection risk).
    pub(crate) fn notify_append(&self, max_seq: i64) -> Result<(), StoreError> {
        let mut writer = self.writer();
        writer.batch_execute(&notify_append_sql(max_seq))?;
        Ok(())
    }

    /// wp16 P1 — the libpq DSN this backend opened with, so the follower change-feed can open its own
    /// dedicated `LISTEN` connection (never the writer / read pool). See [`Self::dsn`].
    pub(crate) fn listen_dsn(&self) -> String {
        self.dsn.to_string()
    }

    /// Borrow a pooled read connection for the runtime `Store` read projections.
    fn read(&self) -> Result<r2d2::PooledConnection<PgManager>, StoreError> {
        Ok(self.resources.pool.get()?)
    }

    /// Borrow a pooled connection for the logical backup/export path (wp15). Distinct from the
    /// runtime [`read`] only in name/visibility so [`crate::pg_backup`] can drive its
    /// `REPEATABLE READ`, `READ ONLY` export snapshot without reaching the private pool field.
    pub(crate) fn checkout(&self) -> Result<r2d2::PooledConnection<PgManager>, StoreError> {
        Ok(self.resources.pool.get()?)
    }

    pub(crate) fn search_projection_control(&self) -> Result<SearchProjectionControl, StoreError> {
        let mut client = self.read()?;
        let row = client.query_one(
            crate::SEARCH_PROJECTION_CONTROL_SELECT_PG,
            &[&crate::SEARCH_PROJECTION_CONTROL_SINGLETON_ID],
        )?;
        decode_search_projection_control_row(&row)
    }

    pub(crate) fn search_index_state_and_projection_control(
        &self,
    ) -> Result<
        (
            Option<SearchIndexState>,
            Result<SearchProjectionControl, StoreError>,
        ),
        StoreError,
    > {
        let mut client = self.read()?;
        let state = client
            .query_opt(
                "SELECT json FROM search_index_state WHERE id = $1",
                &[&crate::SEARCH_INDEX_STATE_SINGLETON_ID],
            )?
            .map(|row| serde_json::from_str::<SearchIndexState>(&row.get::<_, String>(0)))
            .transpose()?;
        let control = client
            .query_one(
                crate::SEARCH_PROJECTION_CONTROL_SELECT_PG,
                &[&crate::SEARCH_PROJECTION_CONTROL_SINGLETON_ID],
            )
            .map_err(StoreError::from)
            .and_then(|row| decode_search_projection_control_row(&row));
        Ok((state, control))
    }

    pub(crate) fn try_acquire_search_projector_lease(
        &self,
        owner: &str,
        ttl: std::time::Duration,
    ) -> Result<Option<SearchProjectorLease>, StoreError> {
        let mut client = self.read()?;
        let mut txn = client.transaction()?;
        let now_ms = pg_now_unix_millis(&mut txn)?;
        let expires_ms = now_ms.saturating_add(crate::lease_ttl_millis(ttl));
        let heartbeat_at = crate::now_rfc3339();
        let lease_id = uuid::Uuid::new_v4().to_string();
        let changed = txn.execute(
            "UPDATE search_projection_control SET lease_id = $1, lease_owner = $2, \
             lease_heartbeat_at = $3, lease_expires_at_unix_ms = $4, updated_at = $3 \
             WHERE id = $5 AND (lease_id IS NULL OR lease_expires_at_unix_ms <= $6)",
            &[
                &lease_id,
                &owner,
                &heartbeat_at,
                &expires_ms,
                &crate::SEARCH_PROJECTION_CONTROL_SINGLETON_ID,
                &now_ms,
            ],
        )?;
        if changed == 0 {
            txn.rollback()?;
            return Ok(None);
        }
        let row = txn.query_one(
            crate::SEARCH_PROJECTION_CONTROL_SELECT_PG,
            &[&crate::SEARCH_PROJECTION_CONTROL_SINGLETON_ID],
        )?;
        let control = decode_search_projection_control_row(&row)?;
        txn.commit()?;
        Ok(control.lease)
    }

    pub(crate) fn heartbeat_search_projector_lease(
        &self,
        lease: &SearchProjectorLease,
        ttl: std::time::Duration,
    ) -> Result<bool, StoreError> {
        let mut client = self.read()?;
        let mut txn = client.transaction()?;
        let now_ms = pg_now_unix_millis(&mut txn)?;
        let expires_ms = now_ms.saturating_add(crate::lease_ttl_millis(ttl));
        let heartbeat_at = crate::now_rfc3339();
        let changed = txn.execute(
            "UPDATE search_projection_control SET lease_heartbeat_at = $1, \
             lease_expires_at_unix_ms = $2, updated_at = $1 \
             WHERE id = $3 AND lease_id = $4 AND lease_owner = $5 \
                 AND lease_expires_at_unix_ms > $6",
            &[
                &heartbeat_at,
                &expires_ms,
                &crate::SEARCH_PROJECTION_CONTROL_SINGLETON_ID,
                &lease.lease_id,
                &lease.owner,
                &now_ms,
            ],
        )?;
        txn.commit()?;
        Ok(changed == 1)
    }

    pub(crate) fn release_search_projector_lease(
        &self,
        lease: &SearchProjectorLease,
    ) -> Result<bool, StoreError> {
        let mut client = self.read()?;
        let updated_at = crate::now_rfc3339();
        let changed = client.execute(
            "UPDATE search_projection_control SET lease_id = NULL, lease_owner = NULL, \
             lease_heartbeat_at = NULL, lease_expires_at_unix_ms = NULL, updated_at = $1 \
             WHERE id = $2 AND lease_id = $3 AND lease_owner = $4",
            &[
                &updated_at,
                &crate::SEARCH_PROJECTION_CONTROL_SINGLETON_ID,
                &lease.lease_id,
                &lease.owner,
            ],
        )?;
        Ok(changed == 1)
    }

    pub(crate) fn publish_search_projection(
        &self,
        lease: &SearchProjectorLease,
        checkpoint: SearchProjectionCheckpoint,
        operations: &[SearchIndexOperation],
        state: &SearchIndexState,
    ) -> Result<SearchProjectionPublishOutcome, StoreError> {
        let mut client = self.read()?;
        let mut txn = client.transaction()?;
        let now_ms = pg_now_unix_millis(&mut txn)?;
        let row = txn.query_one(
            &format!("{} FOR UPDATE", crate::SEARCH_PROJECTION_CONTROL_SELECT_PG),
            &[&crate::SEARCH_PROJECTION_CONTROL_SINGLETON_ID],
        )?;
        let control = decode_search_projection_control_row(&row)?;
        if let Some(reason) =
            crate::projection_publish_rejection(&control, lease, checkpoint, now_ms)
        {
            txn.rollback()?;
            return Ok(SearchProjectionPublishOutcome::Rejected { reason, control });
        }
        for operation in operations {
            match operation {
                SearchIndexOperation::Upsert(document) => {
                    let json = serde_json::to_string(document)?;
                    txn.execute(
                        "INSERT INTO search_documents (id, json) VALUES ($1, $2) \
                         ON CONFLICT (id) DO UPDATE SET json = EXCLUDED.json",
                        &[&document.id, &json],
                    )?;
                }
                SearchIndexOperation::Delete(id) => {
                    txn.execute("DELETE FROM search_documents WHERE id = $1", &[&id])?;
                }
            }
        }
        let state_json = serde_json::to_string(state)?;
        txn.execute(
            "INSERT INTO search_index_state (id, json) VALUES ($1, $2) \
             ON CONFLICT (id) DO UPDATE SET json = EXCLUDED.json",
            &[&crate::SEARCH_INDEX_STATE_SINGLETON_ID, &state_json],
        )?;
        let updated_at = crate::now_rfc3339();
        let published_source_revision =
            i64::try_from(checkpoint.source_revision).unwrap_or(i64::MAX);
        let published_fence_token = i64::try_from(checkpoint.fence_token).unwrap_or(i64::MAX);
        let published_command_generation =
            i64::try_from(checkpoint.command_generation).unwrap_or(i64::MAX);
        txn.execute(
            "UPDATE search_projection_control SET published_source_revision = $1, \
             published_fence_token = $2, published_command_generation = $3, \
             command = CASE WHEN command = 'rebuild' THEN 'reconcile' ELSE command END, \
             updated_at = $4 WHERE id = $5",
            &[
                &published_source_revision,
                &published_fence_token,
                &published_command_generation,
                &updated_at,
                &crate::SEARCH_PROJECTION_CONTROL_SINGLETON_ID,
            ],
        )?;
        txn.commit()?;
        Ok(SearchProjectionPublishOutcome::Published {
            checkpoint,
            generation: state.generation,
            document_count: state.document_count,
        })
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
            "SELECT id, act_id, template_id, pdf_digest, profile, created_at, pdf_bytes, template_spec_json, document_layout_json \
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
            "SELECT id, act_id, template_id, pdf_digest, profile, created_at, pdf_bytes, template_spec_json, document_layout_json \
             FROM documents WHERE act_id = $1 ORDER BY created_at ASC, ctid ASC",
            &[&act_id.to_string()],
        )?;
        rows.iter().map(row_to_document).collect()
    }

    pub(crate) fn document_search_metadata(
        &self,
    ) -> Result<Vec<StoredDocumentSearchMetadata>, StoreError> {
        let mut client = self.read()?;
        let rows = client.query(DOCUMENT_SEARCH_METADATA_SELECT, &[])?;
        rows.iter().map(row_to_document_search_metadata).collect()
    }

    pub(crate) fn document_by_id(&self, id: &str) -> Result<Option<StoredDocument>, StoreError> {
        let mut client = self.read()?;
        let row = client.query_opt(
            "SELECT id, act_id, template_id, pdf_digest, profile, created_at, pdf_bytes, template_spec_json, document_layout_json \
             FROM documents WHERE id = $1",
            &[&id],
        )?;
        row.as_ref().map(row_to_document).transpose()
    }

    // ── wp21 per-book portability reads (export / import / start-over) ──────────────────────────
    //
    // The per-book bundle paths in [`crate::recovery`] read the same aggregate/isolation rows the
    // SQLite backend reaches through `Store::locked_conn`. These pooled-read helpers give the
    // recovery plane a portable Postgres equivalent so `export_book` / `import_book` /
    // `imported_books` / `imported_bundle` / `start_over_book` no longer fail closed.

    /// Read one book's raw row `json` by id (parsed by the recovery plane into a `Book`).
    pub(crate) fn book_json(&self, id: &str) -> Result<Option<String>, StoreError> {
        let mut client = self.read()?;
        Ok(client
            .query_opt("SELECT json FROM books WHERE id = $1", &[&id])?
            .map(|row| row.get::<_, String>(0)))
    }

    /// Read one entity's raw row `json` by id (kept verbatim so the bundle stores exact PUBLIC bytes).
    pub(crate) fn entity_json(&self, id: &str) -> Result<Option<String>, StoreError> {
        let mut client = self.read()?;
        Ok(client
            .query_opt("SELECT json FROM entities WHERE id = $1", &[&id])?
            .map(|row| row.get::<_, String>(0)))
    }

    /// Read all acts of a book as raw row `json`, ordered by id (deterministic bundle order).
    pub(crate) fn acts_json_for_book(&self, book_id: &str) -> Result<Vec<String>, StoreError> {
        let mut client = self.read()?;
        let rows = client.query(
            "SELECT json FROM acts WHERE book_id = $1 ORDER BY id",
            &[&book_id],
        )?;
        Ok(rows.iter().map(|r| r.get::<_, String>(0)).collect())
    }

    /// Whether `book_id` already exists as a live book OR an imported book (collision detection).
    pub(crate) fn book_exists_anywhere(&self, book_id: &str) -> Result<bool, StoreError> {
        let mut client = self.read()?;
        let live: i64 = client
            .query_one("SELECT COUNT(*) FROM books WHERE id = $1", &[&book_id])?
            .get(0);
        let imported: i64 = client
            .query_one(
                "SELECT COUNT(*) FROM imported_books WHERE book_id = $1",
                &[&book_id],
            )?
            .get(0);
        Ok(live + imported > 0)
    }

    /// Read the isolated import namespace rows (newest first) for the per-book import feed. The
    /// recovery plane reconstructs each verdict/timestamp; here we return only the raw column tuple.
    pub(crate) fn imported_book_rows(
        &self,
    ) -> Result<Vec<crate::recovery::ImportedBookRow>, StoreError> {
        let mut client = self.read()?;
        let rows = client.query(
            "SELECT import_id, entity_id, book_id, source_instance_id, bundle_digest, verdict, \
             break_json, collided, imported_at FROM imported_books \
             ORDER BY imported_at DESC, ctid DESC",
            &[],
        )?;
        Ok(rows
            .iter()
            .map(|row| crate::recovery::ImportedBookRow {
                import_id: row.get(0),
                entity_id: row.get(1),
                book_id: row.get(2),
                source_instance_id: row.get(3),
                bundle_digest: row.get(4),
                verdict: row.get(5),
                break_json: row.get(6),
                collided: row.get(7),
                imported_at: row.get(8),
            })
            .collect())
    }

    /// Fetch the retained, read-only `.zip` bytes of one import, or `None` if the id is unknown.
    pub(crate) fn imported_bundle(&self, import_id: &str) -> Result<Option<Vec<u8>>, StoreError> {
        let mut client = self.read()?;
        Ok(client
            .query_opt(
                "SELECT bundle_bytes FROM imported_books WHERE import_id = $1",
                &[&import_id],
            )?
            .map(|row| row.get::<_, Vec<u8>>(0)))
    }

    /// Postgres twin of `Store::insert_email_delivery` (t108). A plain `INSERT` — each attempt is
    /// its own row, so no retry overwrites the outcome it retried.
    pub(crate) fn insert_email_delivery(
        &self,
        delivery: &StoredEmailDelivery,
    ) -> Result<(), StoreError> {
        let created_at = delivery
            .created_at
            .format(&Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned());
        // `tls` / `authenticated` are 0/1 in a BIGINT column on this backend; see the note in
        // `row_to_email_delivery`.
        let tls = delivery.tls.map(i64::from);
        let authenticated = delivery.authenticated.map(i64::from);
        let mut client = self.writer();
        client.execute(
            "INSERT INTO email_deliveries \
             (id, template_id, user_id, recipient, status, attempt, previous_id, token_subject, \
              token_purpose, tls, authenticated, failure_stage, failure_kind, failure_code, \
              failure_detail, created_at, event_seq, actor) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, \
                     $18)",
            &[
                &delivery.id,
                &delivery.template_id,
                &delivery.user_id,
                &delivery.recipient,
                &delivery.status,
                &delivery.attempt,
                &delivery.previous_id,
                &delivery.token_subject,
                &delivery.token_purpose,
                &tls,
                &authenticated,
                &delivery.failure_stage,
                &delivery.failure_kind,
                &delivery.failure_code,
                &delivery.failure_detail,
                &created_at,
                &delivery.event_seq,
                &delivery.actor,
            ],
        )?;
        Ok(())
    }

    /// Postgres twin of `Store::email_deliveries`.
    pub(crate) fn email_deliveries(
        &self,
        limit: i64,
    ) -> Result<Vec<StoredEmailDelivery>, StoreError> {
        let mut client = self.read()?;
        let rows = client.query(
            "SELECT id, template_id, user_id, recipient, status, attempt, previous_id, \
             token_subject, token_purpose, tls, authenticated, failure_stage, failure_kind, \
             failure_code, failure_detail, created_at, event_seq, actor \
             FROM email_deliveries ORDER BY created_at DESC, ctid DESC LIMIT $1",
            &[&limit],
        )?;
        rows.iter().map(row_to_email_delivery).collect()
    }

    /// Postgres twin of `Store::email_delivery`.
    pub(crate) fn email_delivery(
        &self,
        id: &str,
    ) -> Result<Option<StoredEmailDelivery>, StoreError> {
        let mut client = self.read()?;
        let row = client.query_opt(
            "SELECT id, template_id, user_id, recipient, status, attempt, previous_id, \
             token_subject, token_purpose, tls, authenticated, failure_stage, failure_kind, \
             failure_code, failure_detail, created_at, event_seq, actor \
             FROM email_deliveries WHERE id = $1",
            &[&id],
        )?;
        row.as_ref().map(row_to_email_delivery).transpose()
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
             WHERE document_id = $1 ORDER BY recorded_at ASC, idempotency_key ASC",
            &[&document_id],
        )?;
        rows.iter()
            .map(row_to_generated_dispatch_evidence)
            .collect()
    }

    pub(crate) fn generated_document_dispatch_evidence_all(
        &self,
    ) -> Result<Vec<StoredGeneratedDocumentDispatchEvidence>, StoreError> {
        let mut client = self.read()?;
        let rows = client.query(GENERATED_DOCUMENT_DISPATCH_EVIDENCE_ALL_SELECT, &[])?;
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
                 operator_acknowledged_guardrail_ids_json, technical_validation_report_json \
                 FROM imported_documents \
                 WHERE act_id = $1 ORDER BY imported_at DESC, id DESC",
                &[&act_id.to_string()],
            )?
        } else {
            client.query(IMPORTED_DOCUMENTS_ALL_SELECT, &[])?
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
             technical_validation_report_json, bytes FROM imported_documents WHERE id = $1",
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

    pub(crate) fn imported_document_review_history_all(
        &self,
    ) -> Result<Vec<StoredImportedDocumentReviewHistoryEntry>, StoreError> {
        let mut client = self.read()?;
        let rows = client.query(
            "SELECT id, imported_document_id, review_status, reviewed_at, reviewed_by, \
             review_note, acknowledged_guardrail_ids_json \
             FROM imported_document_review_history \
             ORDER BY imported_document_id ASC, id ASC",
            &[],
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
                 WHERE book_ref = $1 ORDER BY imported_at DESC, import_id DESC",
                &[&book_ref],
            )?
        } else {
            client.query(PAPER_BOOK_IMPORTS_ALL_SELECT, &[])?
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
             WHERE import_id = $1 ORDER BY created_at DESC, draft_id DESC",
            &[&import_id],
        )?;
        rows.iter().map(row_to_paper_book_ocr_draft).collect()
    }

    pub(crate) fn paper_book_ocr_drafts_all(
        &self,
    ) -> Result<Vec<StoredPaperBookOcrDraft>, StoreError> {
        let mut client = self.read()?;
        let rows = client.query(PAPER_BOOK_OCR_DRAFTS_ALL_SELECT, &[])?;
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

    // ── wp16 P3b — non-ledger sidecar reads (users / roles / delegations / settings / credentials) ──

    pub(crate) fn document_rows(&self, table: &str) -> Result<Vec<(String, String)>, StoreError> {
        // `table` is a fixed internal identifier (users/roles/delegations), never user input.
        let mut client = self.read()?;
        let rows = client.query(
            &format!("SELECT id, json FROM {table} ORDER BY id ASC"),
            &[],
        )?;
        rows.iter()
            .map(|row| Ok((row.get::<_, String>(0), row.get::<_, String>(1))))
            .collect()
    }

    pub(crate) fn document_row(&self, table: &str, id: &str) -> Result<Option<String>, StoreError> {
        // `table` is a fixed internal identifier (users/roles/delegations/user_templates), never
        // user input.
        let mut client = self.read()?;
        let row = client.query_opt(&format!("SELECT json FROM {table} WHERE id = $1"), &[&id])?;
        Ok(row.map(|row| row.get::<_, String>(0)))
    }

    pub(crate) fn user_template_versions(
        &self,
        template_id: &str,
    ) -> Result<Vec<StoredUserTemplateVersion>, StoreError> {
        let mut client = self.read()?;
        let rows = client.query(
            "SELECT version_id, template_id, name, template_json, created_at, created_by \
             FROM user_template_versions WHERE template_id = $1 \
             ORDER BY created_at_unix_nanos DESC, version_id DESC",
            &[&template_id],
        )?;
        rows.iter().map(row_to_user_template_version).collect()
    }

    pub(crate) fn user_template_versions_limited(
        &self,
        template_id: &str,
        history_limit: usize,
    ) -> Result<Vec<StoredUserTemplateVersion>, StoreError> {
        let limit = i64::try_from(history_limit.max(1)).unwrap_or(i64::MAX);
        let mut client = self.read()?;
        let rows = client.query(
            "SELECT version_id, template_id, name, template_json, created_at, created_by \
             FROM user_template_versions WHERE template_id = $1 \
             ORDER BY created_at_unix_nanos DESC, version_id DESC LIMIT $2",
            &[&template_id, &limit],
        )?;
        rows.iter().map(row_to_user_template_version).collect()
    }

    pub(crate) fn user_template_version(
        &self,
        template_id: &str,
        version_id: &str,
    ) -> Result<Option<StoredUserTemplateVersion>, StoreError> {
        let mut client = self.read()?;
        client
            .query_opt(
                "SELECT version_id, template_id, name, template_json, created_at, created_by \
                 FROM user_template_versions WHERE template_id = $1 AND version_id = $2",
                &[&template_id, &version_id],
            )?
            .as_ref()
            .map(row_to_user_template_version)
            .transpose()
    }

    pub(crate) fn settings(&self) -> Result<Option<String>, StoreError> {
        let mut client = self.read()?;
        let row = client.query_opt(
            "SELECT json FROM settings WHERE id = $1",
            &[&crate::SETTINGS_SINGLETON_ID],
        )?;
        Ok(row.map(|row| row.get::<_, String>(0)))
    }

    pub(crate) fn metadata_value(&self, key: &str) -> Result<Option<String>, StoreError> {
        let mut client = self.read()?;
        let row = client.query_opt("SELECT value FROM meta WHERE key = $1", &[&key])?;
        Ok(row.map(|row| row.get::<_, String>(0)))
    }

    pub(crate) fn read_credential_records(
        &self,
    ) -> Result<Vec<StoredCredentialRecord>, StoreError> {
        let mut client = self.read()?;
        let rows = client.query(
            "SELECT mode, provider_id, key_version, updated_at, record_blob \
             FROM provider_credentials ORDER BY mode ASC, provider_id ASC",
            &[],
        )?;
        Ok(rows
            .iter()
            .map(|row| StoredCredentialRecord {
                mode: row.get(0),
                provider_id: row.get(1),
                key_version: row.get(2),
                updated_at: row.get(3),
                record_blob: row.get(4),
            })
            .collect())
    }

    /// wp26 — read one `subject_keys` row (the Postgres twin of the non-tx
    /// [`crate::Store::get_subject_key`]). `wrapped_dek` (BYTEA) is returned verbatim.
    pub(crate) fn subject_key(
        &self,
        subject_id: &str,
    ) -> Result<Option<crate::SubjectKeyRow>, StoreError> {
        let mut client = self.read()?;
        let row = client.query_opt(
            "SELECT subject_id, wrapped_dek, key_version, created_at, erased_at \
             FROM subject_keys WHERE subject_id = $1",
            &[&subject_id],
        )?;
        Ok(row.map(|row| crate::SubjectKeyRow {
            subject_id: row.get(0),
            wrapped_dek: row.get(1),
            key_version: row.get(2),
            created_at: row.get(3),
            erased_at: row.get(4),
        }))
    }

    /// wp26 — `VACUUM (FULL, ANALYZE)` to return dead-tuple space (freed by an erasure's `DELETE`s)
    /// to the OS. Runs via a pooled connection's simple-query path so it executes in its own implicit
    /// transaction (`VACUUM` cannot run inside an explicit transaction block).
    pub(crate) fn vacuum_full(&self) -> Result<(), StoreError> {
        let mut client = self.read()?;
        client.batch_execute("VACUUM (FULL, ANALYZE)")?;
        Ok(())
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

    /// Every recorded signature for `subject_id`, in signing order (`seq` ascending). Mirrors the
    /// SQLite `Store::instrument_signatures_for_subject` projection exactly, including its
    /// `seq, slot_id`-first column order.
    pub(crate) fn instrument_signatures_for_subject(
        &self,
        subject_id: ActId,
    ) -> Result<Vec<crate::StoredInstrumentSignature>, StoreError> {
        let mut client = self.read()?;
        let rows = client.query(
            &format!(
                "SELECT {INSTRUMENT_SIGNATURE_COLUMNS} FROM instrument_signatures \
                 WHERE subject_id = $1 ORDER BY seq ASC"
            ),
            &[&subject_id.to_string()],
        )?;
        rows.iter().map(row_to_instrument_signature).collect()
    }

    /// Load one drafted termo instrument by id (the Postgres twin of the SQLite
    /// [`crate::Store::load_termo_instrument`], schema v26). `json` is the serialized
    /// `TermoInstrument`, reconstructed via the shared [`crate::row_to_termo_instrument`].
    pub(crate) fn termo_instrument(
        &self,
        id: chancela_core::TermoInstrumentId,
    ) -> Result<Option<chancela_core::TermoInstrument>, StoreError> {
        let mut client = self.read()?;
        let row = client.query_opt(
            "SELECT json FROM termo_instruments WHERE id = $1",
            &[&id.to_string()],
        )?;
        row.map(|row| crate::row_to_termo_instrument(&row.get::<_, String>(0)))
            .transpose()
    }

    /// Every drafted termo instrument for a book, in id order (the Postgres twin of the SQLite
    /// [`crate::Store::termo_instruments_for_book`], schema v26).
    pub(crate) fn termo_instruments_for_book(
        &self,
        book_id: chancela_core::BookId,
    ) -> Result<Vec<chancela_core::TermoInstrument>, StoreError> {
        let mut client = self.read()?;
        let rows = client.query(
            "SELECT json FROM termo_instruments WHERE book_id = $1 ORDER BY id ASC",
            &[&book_id.to_string()],
        )?;
        rows.iter()
            .map(|row| crate::row_to_termo_instrument(&row.get::<_, String>(0)))
            .collect()
    }

    /// Every drafted termo instrument in the store, in id order (the Postgres twin of the SQLite
    /// [`crate::Store::all_termo_instruments`], schema v26). The boot-time hydrate reads this once.
    pub(crate) fn all_termo_instruments(
        &self,
    ) -> Result<Vec<chancela_core::TermoInstrument>, StoreError> {
        let mut client = self.read()?;
        let rows = client.query("SELECT json FROM termo_instruments ORDER BY id ASC", &[])?;
        rows.iter()
            .map(|row| crate::row_to_termo_instrument(&row.get::<_, String>(0)))
            .collect()
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

/// The `instrument_signatures` column list. `seq, slot_id` lead, then the `signed_documents` column
/// order verbatim, so the shared signature payload maps identically in both tables.
pub(crate) const INSTRUMENT_SIGNATURE_COLUMNS: &str = "seq, slot_id, subject_id, document_id, \
    signed_pdf_digest, signature_family, evidentiary_level, trusted_list_status, \
    signer_cert_subject, signing_time, signed_at, signer_cert_der, timestamp_token_der, \
    timestamp_trust_report_json, signer_capacity_evidence_json, signed_pdf_bytes";

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

/// Read the four aggregate read-models (`entities`/`books`/`acts`/`registry_extracts`) plus
/// `follow_ups` on `client` into an [`crate::AggregateSnapshot`], byte-for-byte the same
/// reconstruction the boot [`PostgresBackend::load`] does. Shared by `load` (which then also scans
/// `events`) and by [`PostgresBackend::load_aggregates`] (the events-free follower refresh, §2.3).
fn load_aggregate_maps(
    client: &mut Client,
    include_company_groups: bool,
) -> Result<crate::AggregateSnapshot, StoreError> {
    use std::collections::HashMap;

    let mut company_groups = HashMap::new();
    if include_company_groups {
        for row in client.query("SELECT json FROM company_groups", &[])? {
            let json: String = row.get(0);
            let group: CompanyGroup = serde_json::from_str(&json)?;
            company_groups.insert(group.id, group);
        }
    }

    let mut group_template_libraries = HashMap::new();
    for row in client.query("SELECT json FROM group_template_libraries", &[])? {
        let json: String = row.get(0);
        let library: GroupTemplateLibrary = serde_json::from_str(&json)?;
        group_template_libraries.insert(library.id, library);
    }

    let mut group_template_library_revisions = HashMap::new();
    for row in client.query("SELECT json FROM group_template_library_revisions", &[])? {
        let json: String = row.get(0);
        let revision: GroupTemplateLibraryRevision = serde_json::from_str(&json)?;
        group_template_library_revisions.insert(
            (revision.group_id, revision.library_id, revision.revision),
            revision,
        );
    }

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

    Ok(crate::AggregateSnapshot {
        company_groups,
        group_template_libraries,
        group_template_library_revisions,
        entities,
        books,
        acts,
        registry_extracts,
        follow_ups,
    })
}

fn notify_append_sql(max_seq: i64) -> String {
    format!("NOTIFY {}, '{max_seq}'", crate::CLUSTER_CHANGE_CHANNEL)
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
        // NULL for rows written before schema v24 — `None` means "no spec was recorded".
        template_spec_json: row.get(7),
        // NULL for rows written before schema v28 — never substitute mutable current settings.
        document_layout_json: row.get(8),
    })
}

pub(crate) fn row_to_document_search_metadata(
    row: &Row,
) -> Result<StoredDocumentSearchMetadata, StoreError> {
    Ok(StoredDocumentSearchMetadata {
        id: row.get(0),
        act_id: parse_uuid_newtype::<ActId>(&row.get::<_, String>(1))?,
        template_id: row.get(2),
        pdf_digest: row.get(3),
        profile: row.get(4),
        created_at: parse_rfc3339(&row.get::<_, String>(5))?,
    })
}

/// Postgres twin of `crate::row_to_email_delivery` (t108).
pub(crate) fn row_to_email_delivery(row: &Row) -> Result<StoredEmailDelivery, StoreError> {
    Ok(StoredEmailDelivery {
        id: row.get(0),
        template_id: row.get(1),
        user_id: row.get(2),
        recipient: row.get(3),
        status: row.get(4),
        attempt: row.get(5),
        previous_id: row.get(6),
        token_subject: row.get(7),
        token_purpose: row.get(8),
        // 0/1 in a BIGINT column: the dialect maps SQLite `INTEGER` to `BIGINT`, so a column read
        // as `bool` here would diverge from the SQLite backend rather than fail loudly.
        tls: row.get::<_, Option<i64>>(9).map(|v| v != 0),
        authenticated: row.get::<_, Option<i64>>(10).map(|v| v != 0),
        failure_stage: row.get(11),
        failure_kind: row.get(12),
        failure_code: row.get(13),
        failure_detail: row.get(14),
        created_at: parse_rfc3339(&row.get::<_, String>(15))?,
        event_seq: row.get(16),
        actor: row.get(17),
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

fn row_to_user_template_version(row: &Row) -> Result<StoredUserTemplateVersion, StoreError> {
    Ok(StoredUserTemplateVersion {
        version_id: row.get(0),
        template_id: row.get(1),
        name: row.get(2),
        template_json: row.get(3),
        created_at: parse_rfc3339(&row.get::<_, String>(4))?,
        created_by: row.get(5),
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
        row.get(14),
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
            row.get(14),
        )?,
        bytes: row.get(15),
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

pub(crate) fn row_to_instrument_signature(
    row: &Row,
) -> Result<crate::StoredInstrumentSignature, StoreError> {
    Ok(crate::StoredInstrumentSignature {
        seq: row.get(0),
        slot_id: row.get(1),
        document: StoredSignedDocument {
            act_id: parse_uuid_newtype::<ActId>(&row.get::<_, String>(2))?,
            document_id: row.get(3),
            signed_pdf_digest: row.get(4),
            signature_family: row.get(5),
            evidentiary_level: row.get(6),
            trusted_list_status: row.get(7),
            signer_cert_subject: row.get(8),
            signing_time: parse_rfc3339(&row.get::<_, String>(9))?,
            signed_at: parse_rfc3339(&row.get::<_, String>(10))?,
            signer_cert_der: row.get(11),
            timestamp_token_der: row.get(12),
            timestamp_trust_report_json: row.get(13),
            signer_capacity_evidence_json: row.get(14),
            signed_pdf_bytes: row.get(15),
        },
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
    fn projector_bulk_reads_need_only_grantable_logical_columns() {
        for query in [
            DOCUMENT_SEARCH_METADATA_SELECT,
            GENERATED_DOCUMENT_DISPATCH_EVIDENCE_ALL_SELECT,
            IMPORTED_DOCUMENTS_ALL_SELECT,
            PAPER_BOOK_IMPORTS_ALL_SELECT,
            PAPER_BOOK_OCR_DRAFTS_ALL_SELECT,
        ] {
            assert!(
                !query.contains("ctid") && !query.contains("rowid"),
                "column-granted projector query must not reference physical row identity: {query}"
            );
        }
        assert!(DOCUMENT_SEARCH_METADATA_SELECT.ends_with("created_at ASC, id ASC"));
        assert!(
            GENERATED_DOCUMENT_DISPATCH_EVIDENCE_ALL_SELECT
                .ends_with("recorded_at ASC, document_id ASC, idempotency_key ASC")
        );
        assert!(IMPORTED_DOCUMENTS_ALL_SELECT.ends_with("imported_at DESC, id DESC"));
        assert!(PAPER_BOOK_IMPORTS_ALL_SELECT.ends_with("imported_at DESC, import_id DESC"));
        assert!(
            PAPER_BOOK_OCR_DRAFTS_ALL_SELECT
                .ends_with("import_id ASC, created_at DESC, draft_id DESC")
        );
    }

    #[test]
    fn runtime_safe_resource_drop_runs_outside_tokio_context() {
        struct DropProbe(std::sync::mpsc::Sender<bool>);

        impl Drop for DropProbe {
            fn drop(&mut self) {
                let _ = self.0.send(tokio::runtime::Handle::try_current().is_err());
            }
        }

        let (sender, receiver) = std::sync::mpsc::channel();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("test runtime");
        runtime.block_on(async {
            drop_outside_tokio_runtime(DropProbe(sender), "chancela-pg-drop-test");
        });
        assert!(
            receiver
                .recv_timeout(std::time::Duration::from_secs(1))
                .expect("drop probe completed"),
            "runtime-bearing resource was dropped inside Tokio context"
        );
    }

    #[test]
    fn follower_schema_marker_classification_is_fail_closed() {
        assert_eq!(
            classify_schema_marker(None),
            SchemaMarkerState::Retry {
                observed: "missing".to_owned()
            }
        );
        assert!(matches!(
            classify_schema_marker(Some(&(crate::schema::SCHEMA_VERSION - 1).to_string())),
            SchemaMarkerState::Retry { .. }
        ));
        assert_eq!(
            classify_schema_marker(Some(&crate::schema::SCHEMA_VERSION.to_string())),
            SchemaMarkerState::Ready
        );
        assert_eq!(
            classify_schema_marker(Some(&(crate::schema::SCHEMA_VERSION + 1).to_string())),
            SchemaMarkerState::Newer(crate::schema::SCHEMA_VERSION + 1)
        );
        assert!(matches!(
            classify_schema_marker(Some("not-a-version")),
            SchemaMarkerState::Invalid(_)
        ));
    }

    #[test]
    fn leader_invalidates_schema_marker_before_setup_and_publishes_it_last() {
        let invalidation = LEADER_SCHEMA_SETUP_ORDER
            .iter()
            .position(|step| *step == LeaderSchemaSetupStep::PreflightAndInvalidateMarker)
            .expect("schema plan invalidates the marker");
        let base_ddl = LEADER_SCHEMA_SETUP_ORDER
            .iter()
            .position(|step| *step == LeaderSchemaSetupStep::BaseDdl)
            .expect("schema plan includes base DDL");
        let additive_ddl = LEADER_SCHEMA_SETUP_ORDER
            .iter()
            .position(|step| *step == LeaderSchemaSetupStep::AdditiveColumns)
            .expect("schema plan includes additive DDL");
        let publication = LEADER_SCHEMA_SETUP_ORDER
            .iter()
            .position(|step| *step == LeaderSchemaSetupStep::PublishMarker)
            .expect("schema plan republishes the marker");

        assert!(invalidation < base_ddl);
        assert!(invalidation < additive_ddl);
        assert_eq!(publication, LEADER_SCHEMA_SETUP_ORDER.len() - 1);
        assert!(LOCK_SCHEMA_MARKER_TABLE.contains("ACCESS EXCLUSIVE"));
        assert_eq!(
            INVALIDATE_SCHEMA_VERSION_MARKER,
            "DELETE FROM meta WHERE key = 'schema_version'"
        );
    }

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

    #[test]
    fn imported_documents_technical_validation_column_is_in_fresh_and_additive_ddl() {
        let column = "technical_validation_report_json TEXT NOT NULL DEFAULT '{}'";
        let fresh_pg = crate::dialect::sqlite_ddl_to_pg(crate::schema::CREATE_IMPORTED_DOCUMENTS);

        assert!(
            fresh_pg.contains(column),
            "fresh Postgres imported_documents DDL must include technical validation evidence: {fresh_pg}"
        );
        assert!(
            ADD_IMPORTED_DOCUMENTS_TECHNICAL_VALIDATION_REPORT_COLUMN
                .contains("ADD COLUMN IF NOT EXISTS"),
            "additive guard must be idempotent: {ADD_IMPORTED_DOCUMENTS_TECHNICAL_VALIDATION_REPORT_COLUMN}"
        );
        assert!(
            ADD_IMPORTED_DOCUMENTS_TECHNICAL_VALIDATION_REPORT_COLUMN.contains(column),
            "additive guard must add the same column contract: {ADD_IMPORTED_DOCUMENTS_TECHNICAL_VALIDATION_REPORT_COLUMN}"
        );
    }

    #[test]
    fn document_layout_snapshot_is_nullable_in_fresh_and_additive_ddl() {
        let column = "document_layout_json TEXT";
        let fresh_pg = crate::dialect::sqlite_ddl_to_pg(crate::schema::CREATE_DOCUMENTS);

        assert!(
            fresh_pg.contains(column),
            "fresh Postgres documents DDL must include the resolved layout snapshot: {fresh_pg}"
        );
        assert!(
            ADD_DOCUMENTS_LAYOUT_COLUMN.contains("ADD COLUMN IF NOT EXISTS"),
            "additive guard must be idempotent: {ADD_DOCUMENTS_LAYOUT_COLUMN}"
        );
        assert!(
            ADD_DOCUMENTS_LAYOUT_COLUMN.contains(column),
            "additive guard must add the same nullable column: {ADD_DOCUMENTS_LAYOUT_COLUMN}"
        );
        assert!(
            !ADD_DOCUMENTS_LAYOUT_COLUMN.contains("DEFAULT"),
            "historical rows must stay unbound: {ADD_DOCUMENTS_LAYOUT_COLUMN}"
        );
    }

    #[test]
    fn change_feed_tail_query_is_strictly_ordered_after_seq() {
        assert!(
            EVENTS_SINCE_SQL.contains("WHERE seq > $1"),
            "tail fetch must be strictly after the applied seq: {EVENTS_SINCE_SQL}"
        );
        assert!(
            EVENTS_SINCE_SQL.ends_with("ORDER BY seq"),
            "tail fetch must be oldest-first for delta continuity checks: {EVENTS_SINCE_SQL}"
        );
        assert!(
            EVENTS_SINCE_SQL.contains("prev_hash, hash, links"),
            "tail fetch must include the hash-chain material needed to rebuild ledger events"
        );
    }

    #[test]
    fn notify_append_uses_the_shared_change_channel_and_plain_seq_payload() {
        let sql = notify_append_sql(42);
        assert_eq!(
            sql,
            format!("NOTIFY {}, '42'", crate::CLUSTER_CHANGE_CHANNEL)
        );
        assert_eq!(
            crate::CLUSTER_CHANGE_CHANNEL,
            "chancela_ledger",
            "API LISTEN and store NOTIFY must share the same channel"
        );
    }
}
