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
//! ## What Phase 1 supports vs defers (all deferrals fail closed, never silently)
//!
//! Supported natively on Postgres: opening + schema DDL (derived from [`crate::schema::ALL`] via
//! [`crate::dialect::sqlite_ddl_to_pg`]), the boot [`load`] replay, and the **core write path** —
//! `append_event` + the aggregate upserts (`upsert_entity`/`_book`/`_act`/`_registry_extract`/
//! `_document`). Every other `Tx` write method and every bespoke `Store` read/recovery/backup path
//! returns [`crate::StoreError::UnsupportedOnPostgres`] (they still funnel through the SQLite-only
//! `Tx::raw` / `Store::locked_conn` accessors). Ported under the testcontainers lane (Phase 3):
//! signed-document / follow-up / paper-book / imported-document writes, blob + paging reads, and
//! backup/restore (`pg_dump`/`COPY` replacing `VACUUM INTO`/file-swap — plan §1.6).

use std::sync::{Arc, Mutex};

use chancela_core::{Act, Book, Entity, EntityId};
use chancela_ledger::Ledger;
use chancela_registry::RegistryExtract;
use postgres::{Client, NoTls};
use r2d2_postgres::PostgresConnectionManager;

use crate::{
    LoadedState, RawEventRow, StoreError, StoredFollowUp, StoredFollowUpStatus, int_to_u32,
    parse_date, parse_rfc3339, parse_uuid_newtype,
};

/// Fixed key for the process-wide writer advisory lock (§4). An arbitrary, stable 64-bit constant
/// derived from "chancela-writer"; two instances contend on the same key.
pub(crate) const WRITER_ADVISORY_LOCK_KEY: i64 = 0x0C_1A_17_CE_1A_17_CE_11u64 as i64;

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
    /// `NoTls` in Phase 1; production `sslmode=verify-full` via `postgres-rustls` is a Phase 2/§3
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

        Ok(Self {
            pool,
            writer: Arc::new(Mutex::new(writer)),
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
}
