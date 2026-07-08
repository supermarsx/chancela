//! # chancela-store
//!
//! The **durable system of record** for Chancela (t30, Wave A). It makes a process restart
//! never lose an entity, book, act, or ledger event, and provides the minimum trustworthy
//! hot-backup escape hatch.
//!
//! The store is an embedded single-file SQLite database (`<data_dir>/chancela.db`, WAL mode)
//! holding the four durable domain aggregates (`entity` / `book` / `act` / `registry_extract`)
//! as document-in-relational rows plus the append-only, hash-chained `events` table (the
//! integrity chain from [`chancela_ledger`], which today evaporates on restart). See
//! `.orchestration/plans/t30.md` for the full design (rulings D1–D6, §2 architecture).
//!
//! ## Position in the workspace DAG
//!
//! `chancela-core`, `chancela-ledger`, `chancela-registry` → **`chancela-store`** →
//! `chancela-api` → `chancela-server` / desktop. The store owns the data plane so `chancela-core`
//! stays pure (ARC-01) and `chancela-api` stays thin (ARC-02); it **must not** depend on
//! `chancela-api` (no cycle).
//!
//! ## Usage shape (bodies filled by t30-e1; this crate freezes the §3.1 API surface)
//!
//! ```ignore
//! let store = Store::open(data_dir)?;             // opens chancela.db, WAL, runs migration
//! let loaded = store.load()?;                     // aggregates + ledger + boot-verify outcome
//! store.persist(|tx| {                            // one transaction: event + changed aggregate
//!     tx.append_event(&event)?;
//!     tx.upsert_entity(&entity)?;
//!     Ok(())
//! })?;
//! let manifest = store.backup(data_dir, &sidecars)?; // VACUUM INTO + zip + manifest
//! ```

pub mod schema;

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use chancela_core::{Act, ActId, Book, BookId, Entity, EntityId};
use chancela_ledger::{ChainLink, Event, EventId, Ledger, LedgerError};
use chancela_registry::RegistryExtract;
use rusqlite::{OptionalExtension, params};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// The database file created inside the data directory passed to [`Store::open`].
pub const DB_FILE: &str = "chancela.db";

/// Errors surfaced by the durable store.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// An error from the underlying SQLite engine (open, migrate, query, transaction).
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// A filesystem error (creating the data dir, the backup archive, reading a sidecar).
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    /// Serializing a domain aggregate to / from its `json` column, or a manifest.
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    /// Writing the hot-backup zip archive.
    #[error("backup archive error: {0}")]
    Zip(#[from] zip::result::ZipError),
    /// The on-disk database was written by an incompatible (usually newer) schema version.
    #[error("unsupported store schema version {found} (this build supports {supported})")]
    UnsupportedSchemaVersion {
        /// The `schema_version` read from the database's `meta` table.
        found: i64,
        /// The `schema_version` this build knows how to operate ([`schema::SCHEMA_VERSION`]).
        supported: i64,
    },
    /// A backup was requested but the store has no on-disk location to snapshot (in-memory mode).
    #[error("backup requires on-disk persistence")]
    NotPersistent,
}

/// A handle to the durable store. Cheap to clone (shares one connection via `Arc`) and lives in
/// `chancela_api::AppState`.
///
/// The single connection runs in WAL mode; a connection pool is a later optimization behind this
/// same seam (t30.md §2 "Async/blocking note").
#[derive(Debug, Clone)]
pub struct Store {
    /// The one SQLite connection, shared and mutex-guarded. rusqlite is synchronous, so a mutation
    /// takes this lock for the (tiny, local) duration of its transaction.
    conn: Arc<Mutex<rusqlite::Connection>>,
}

/// Everything [`Store::load`] reconstructs from disk on boot: the four aggregate read-models, the
/// rehydrated ledger, and the boot-time chain verification outcome (§D-boot).
///
/// `chain_status` is the `verify()` result of the rehydrated chain: `Ok(len)` when the chain is
/// intact, or the first [`LedgerError`] when it is broken. A broken chain is surfaced loudly but
/// **never** refuses startup — `chancela-api` records it and the server still boots so the operator
/// can inspect and restore.
#[derive(Debug)]
pub struct LoadedState {
    /// All entities, keyed by id — loaded into `AppState.entities`.
    pub entities: HashMap<EntityId, Entity>,
    /// All books, keyed by id — loaded into `AppState.books`.
    pub books: HashMap<BookId, Book>,
    /// All acts, keyed by id — loaded into `AppState.acts`.
    pub acts: HashMap<ActId, Act>,
    /// All imported certidão extracts, keyed by the owning entity id.
    pub registry_extracts: HashMap<EntityId, RegistryExtract>,
    /// The rehydrated hash-chained ledger (events in `seq` order).
    pub ledger: Ledger,
    /// The boot-time `verify()` outcome of the rehydrated chain (§D-boot).
    pub chain_status: Result<u64, LedgerError>,
}

/// A description of one backup archive, returned by [`Store::backup`] and by `POST /v1/backup`
/// (frozen contract, t30.md §3.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupManifest {
    /// Absolute path to the written `backups/chancela-backup-<utc>.zip`.
    pub path: String,
    /// Total size of the zip archive in bytes.
    pub bytes: u64,
    /// When the backup was taken (UTC, RFC 3339 on the wire).
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// The application version that produced the backup.
    pub app_version: String,
    /// The store schema version of the snapshotted database ([`schema::SCHEMA_VERSION`]).
    pub store_schema_version: i64,
    /// Number of events in the ledger at snapshot time.
    pub ledger_length: u64,
    /// The chain head hash as lowercase hex, or `None` for an empty ledger.
    pub ledger_head: Option<String>,
    /// Whether the snapshotted chain verified at backup time.
    pub ledger_verified: bool,
    /// Per-file digests of the archive members (the db plus each bundled sidecar).
    pub files: Vec<BackupFile>,
}

/// One member file inside a [`BackupManifest`], with its sha256 for integrity checking on restore.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupFile {
    /// The archive member name (e.g. `chancela.db`, `settings.json`).
    pub name: String,
    /// Lowercase-hex sha256 of the member's bytes.
    pub sha256: String,
    /// The member's size in bytes.
    pub bytes: u64,
}

impl Store {
    /// Open (creating if absent) `<data_dir>/chancela.db`, set `journal_mode=WAL` and
    /// `foreign_keys=ON`, run the idempotent [`schema::ALL`] migration, and record/read
    /// `meta.schema_version`.
    ///
    /// `data_dir` is the directory; the database file name is [`DB_FILE`]. (At-rest encryption,
    /// A3, issues `PRAGMA key` here behind a build feature — no signature change.)
    pub fn open(data_dir: &Path) -> Result<Store, StoreError> {
        std::fs::create_dir_all(data_dir)?;
        let conn = rusqlite::Connection::open(data_dir.join(DB_FILE))?;

        // WAL gives crash-safety on partial writes; foreign_keys keeps referential intent honest;
        // busy_timeout lets a concurrent reader wait out a writer instead of erroring immediately.
        // `execute_batch` tolerates the row `PRAGMA journal_mode=WAL` returns (`execute` would not).
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;\n\
             PRAGMA foreign_keys=ON;\n\
             PRAGMA busy_timeout=5000;",
        )?;

        // Idempotent migration: a fresh DB is created, an existing one left untouched.
        for stmt in schema::ALL {
            conn.execute_batch(stmt)?;
        }

        // Additive migration: the `links` column (multi-chain event links) was added after the
        // initial schema v1. `ALTER TABLE ... ADD COLUMN` is idempotent-safe via this guard.
        let has_links: bool = conn
            .prepare("SELECT COUNT(*) FROM pragma_table_info('events') WHERE name='links'")?
            .query_row([], |row| row.get::<_, i64>(0))
            .map(|n| n > 0)
            .unwrap_or(false);
        if !has_links {
            conn.execute_batch("ALTER TABLE events ADD COLUMN links TEXT NOT NULL DEFAULT '[]';")?;
        }

        // schema_version gate: reject a file written by a *newer* build (we don't know its layout);
        // stamp a fresh DB with our version. Older versions would key future real migrations.
        let found: Option<i64> = conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'schema_version'",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .and_then(|s| s.parse::<i64>().ok());
        match found {
            Some(v) if v > schema::SCHEMA_VERSION => {
                return Err(StoreError::UnsupportedSchemaVersion {
                    found: v,
                    supported: schema::SCHEMA_VERSION,
                });
            }
            Some(_) => {}
            None => {
                conn.execute(
                    "INSERT INTO meta (key, value) VALUES ('schema_version', ?1)",
                    params![schema::SCHEMA_VERSION.to_string()],
                )?;
            }
        }

        Ok(Store {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Read all aggregate rows into their maps and all event rows (ordered by `seq`) into a
    /// [`Ledger`] via `chancela_ledger::Ledger::try_from_events` (added by t30-e1a), then return
    /// the maps, the ledger, and the boot-verify outcome as [`LoadedState`].
    pub fn load(&self) -> Result<LoadedState, StoreError> {
        let guard = self.conn.lock().unwrap_or_else(|e| e.into_inner());

        // Aggregates: the `json` column is the full serde value; its own `id` field is the map key,
        // so the scope columns (entity_id/book_id) never need re-parsing on load.
        let mut entities = HashMap::new();
        {
            let mut stmt = guard.prepare("SELECT json FROM entities")?;
            let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
            for json in rows {
                let entity: Entity = serde_json::from_str(&json?)?;
                entities.insert(entity.id, entity);
            }
        }
        let mut books = HashMap::new();
        {
            let mut stmt = guard.prepare("SELECT json FROM books")?;
            let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
            for json in rows {
                let book: Book = serde_json::from_str(&json?)?;
                books.insert(book.id, book);
            }
        }
        let mut acts = HashMap::new();
        {
            let mut stmt = guard.prepare("SELECT json FROM acts")?;
            let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
            for json in rows {
                let act: Act = serde_json::from_str(&json?)?;
                acts.insert(act.id, act);
            }
        }

        // Registry extracts are keyed by the owning entity id, which the extract does not carry, so
        // the map key comes from the `entity_id` scope column.
        let mut registry_extracts = HashMap::new();
        {
            let mut stmt = guard.prepare("SELECT entity_id, json FROM registry_extracts")?;
            let rows = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            for row in rows {
                let (entity_id_raw, json) = row?;
                let entity_id: EntityId = parse_uuid_newtype(&entity_id_raw)?;
                let extract: RegistryExtract = serde_json::from_str(&json)?;
                registry_extracts.insert(entity_id, extract);
            }
        }

        // Events, in chain order. Read the columns as raw primitives inside the rusqlite closure
        // (which must yield `rusqlite::Result`), then rebuild each `Event` where the timestamp /
        // uuid / fixed-width-digest conversions can surface as `StoreError`.
        let mut raw_events: Vec<RawEventRow> = Vec::new();
        {
            let mut stmt = guard.prepare(
                "SELECT seq, id, actor, justification, timestamp, scope, kind, \
                 payload_digest, prev_hash, hash, links FROM events ORDER BY seq",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok(RawEventRow {
                    seq: row.get(0)?,
                    id: row.get(1)?,
                    actor: row.get(2)?,
                    justification: row.get(3)?,
                    timestamp: row.get(4)?,
                    scope: row.get(5)?,
                    kind: row.get(6)?,
                    payload_digest: row.get(7)?,
                    prev_hash: row.get(8)?,
                    hash: row.get(9)?,
                    links: row.get(10)?,
                })
            })?;
            for row in rows {
                raw_events.push(row?);
            }
        }
        let mut events = Vec::with_capacity(raw_events.len());
        for raw in raw_events {
            events.push(raw.into_event()?);
        }

        let (ledger, chain_status) = Ledger::try_from_events(events);
        Ok(LoadedState {
            entities,
            books,
            acts,
            registry_extracts,
            ledger,
            chain_status,
        })
    }

    /// Run a single transaction: append exactly one event row and upsert zero or more changed
    /// aggregate rows, committing on `Ok(())` and rolling back on `Err`.
    ///
    /// The closure receives a [`Tx`] handle over the open transaction; see the crate-level example.
    pub fn persist<F>(&self, f: F) -> Result<(), StoreError>
    where
        F: FnOnce(&Tx<'_>) -> Result<(), StoreError>,
    {
        let mut guard = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        // rusqlite's `Transaction` rolls back on drop by default, so any early return from `f`
        // (its `?`) or a mid-closure `Err` discards every statement already issued — nothing is
        // persisted unless the whole closure succeeds and we reach `commit`.
        let txn = guard.transaction()?;
        let tx = Tx { txn };
        f(&tx)?;
        tx.txn.commit()?;
        Ok(())
    }

    /// Snapshot the database with `VACUUM INTO` (transactionally consistent, no downtime), bundle
    /// it with the given `sidecars` and a `manifest.json` into a single zip under
    /// `<data_dir>/backups/`, and return the [`BackupManifest`] (frozen §3.2).
    ///
    /// Each `sidecars` entry is a path to an extra file or directory to include verbatim
    /// (`settings.json`, `users.json`, `cae-catalog.json`, `laws/`).
    pub fn backup(
        &self,
        data_dir: &Path,
        sidecars: &[PathBuf],
    ) -> Result<BackupManifest, StoreError> {
        // In-memory / anonymous databases have no on-disk snapshot to bundle → NotPersistent
        // (the api maps this to the §3.2 422). A real file store reports its path here.
        {
            let guard = self.conn.lock().unwrap_or_else(|e| e.into_inner());
            match guard.path() {
                Some(p) if !p.is_empty() && p != ":memory:" => {}
                _ => return Err(StoreError::NotPersistent),
            }
        }

        let created_at = OffsetDateTime::now_utc();
        let stamp = utc_stamp(created_at);
        let backups_dir = data_dir.join("backups");
        std::fs::create_dir_all(&backups_dir)?;

        // 1. Transactionally-consistent hot snapshot via VACUUM INTO (no downtime, plan §D6). The
        //    target must not pre-exist; the per-run stamp keeps it unique. Cleaned up after zipping.
        let snapshot = backups_dir.join(format!(".snapshot-{stamp}.db"));
        {
            let guard = self.conn.lock().unwrap_or_else(|e| e.into_inner());
            guard.execute(
                "VACUUM INTO ?1",
                params![snapshot.to_string_lossy().as_ref()],
            )?;
        }

        // 2. Ledger head/length/verified from a fresh load of the live DB (identical to the snapshot
        //    just taken). Done after releasing the lock — `load` re-locks the connection.
        let loaded = self.load()?;
        let ledger_length = loaded.ledger.len() as u64;
        let ledger_head = loaded.ledger.head().map(|h| hex(&h));
        let ledger_verified = loaded.chain_status.is_ok();

        // 3. Build the archive at a temp path, then atomically rename into place.
        let final_path = backups_dir.join(format!("chancela-backup-{stamp}.zip"));
        let tmp_path = backups_dir.join(format!(".chancela-backup-{stamp}.zip.tmp"));
        let mut files: Vec<BackupFile> = Vec::new();
        {
            let file = std::fs::File::create(&tmp_path)?;
            let mut zip = zip::ZipWriter::new(file);
            let opts = zip::write::SimpleFileOptions::default();

            add_file_to_zip(&mut zip, DB_FILE, &snapshot, opts, &mut files)?;
            for sidecar in sidecars {
                // Skip-missing is tolerated; a name comes from the sidecar's own file/dir name.
                if let Some(base) = sidecar
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                {
                    add_path_to_zip(&mut zip, &base, sidecar, opts, &mut files)?;
                }
            }

            // The manifest is embedded for the restore path (its per-file digests are what a restore
            // verifies). Its own `bytes` cannot include the enclosing archive's final size, so the
            // embedded copy carries `bytes: 0`; the returned/api manifest below carries the real size.
            let embedded = BackupManifest {
                path: final_path.to_string_lossy().into_owned(),
                bytes: 0,
                created_at,
                app_version: env!("CARGO_PKG_VERSION").to_string(),
                store_schema_version: schema::SCHEMA_VERSION,
                ledger_length,
                ledger_head: ledger_head.clone(),
                ledger_verified,
                files: files.clone(),
            };
            zip.start_file("manifest.json", opts)?;
            zip.write_all(serde_json::to_string_pretty(&embedded)?.as_bytes())?;
            zip.finish()?;
        }

        // Best-effort cleanup of the transient snapshot (VACUUM INTO yields a single standalone DB).
        let _ = std::fs::remove_file(&snapshot);

        std::fs::rename(&tmp_path, &final_path)?;
        let bytes = std::fs::metadata(&final_path)?.len();

        Ok(BackupManifest {
            path: final_path.to_string_lossy().into_owned(),
            bytes,
            created_at,
            app_version: env!("CARGO_PKG_VERSION").to_string(),
            store_schema_version: schema::SCHEMA_VERSION,
            ledger_length,
            ledger_head,
            ledger_verified,
            files,
        })
    }
}

/// A transactional write handle passed to the [`Store::persist`] closure. Each method appends or
/// upserts one row inside the enclosing transaction; the whole closure commits atomically.
///
/// The lifetime ties the handle to the open transaction borrowed from the store's connection.
pub struct Tx<'conn> {
    /// The open SQLite transaction. Every `Tx` method issues one statement against it; the whole
    /// closure commits (or, on any `Err`, rolls back) in [`Store::persist`]. Internal — not part of
    /// the frozen §3.1 API.
    txn: rusqlite::Transaction<'conn>,
}

impl Tx<'_> {
    /// Persist one ledger event row into the `events` table (append-only, keyed by `seq`).
    ///
    /// The hash-chain fields are stored directly: the ids/scope/kind/actor as text, the timestamp
    /// as RFC 3339 text (round-trips the instant), and the three 32-byte digests as BLOBs.
    pub fn append_event(&self, event: &Event) -> Result<(), StoreError> {
        let timestamp = event
            .timestamp
            .format(&Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned());
        let links_json = serde_json::to_string(&event.links)?;
        self.txn.execute(
            "INSERT INTO events \
             (seq, id, actor, justification, timestamp, scope, kind, payload_digest, prev_hash, hash, links) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                event.seq as i64,
                event.id.to_string(),
                event.actor,
                event.justification,
                timestamp,
                event.scope,
                event.kind,
                &event.payload_digest[..],
                &event.prev_hash[..],
                &event.hash[..],
                links_json,
            ],
        )?;
        Ok(())
    }

    /// Upsert an entity's row (`entities`, document-in-relational).
    pub fn upsert_entity(&self, entity: &Entity) -> Result<(), StoreError> {
        let json = serde_json::to_string(entity)?;
        self.txn.execute(
            "INSERT OR REPLACE INTO entities (id, json) VALUES (?1, ?2)",
            params![entity.id.to_string(), json],
        )?;
        Ok(())
    }

    /// Upsert a book's row (`books`, with the indexed `entity_id` scope column).
    pub fn upsert_book(&self, book: &Book) -> Result<(), StoreError> {
        let json = serde_json::to_string(book)?;
        self.txn.execute(
            "INSERT OR REPLACE INTO books (id, entity_id, json) VALUES (?1, ?2, ?3)",
            params![book.id.to_string(), book.entity_id.to_string(), json],
        )?;
        Ok(())
    }

    /// Upsert an act's row (`acts`, with the indexed `book_id` scope column).
    pub fn upsert_act(&self, act: &Act) -> Result<(), StoreError> {
        let json = serde_json::to_string(act)?;
        self.txn.execute(
            "INSERT OR REPLACE INTO acts (id, book_id, json) VALUES (?1, ?2, ?3)",
            params![act.id.to_string(), act.book_id.to_string(), json],
        )?;
        Ok(())
    }

    /// Upsert an imported certidão extract for an entity (`registry_extracts`, keyed by entity id).
    pub fn upsert_registry_extract(
        &self,
        entity_id: EntityId,
        extract: &RegistryExtract,
    ) -> Result<(), StoreError> {
        let json = serde_json::to_string(extract)?;
        self.txn.execute(
            "INSERT OR REPLACE INTO registry_extracts (entity_id, json) VALUES (?1, ?2)",
            params![entity_id.to_string(), json],
        )?;
        Ok(())
    }
}

/// One row of the `events` table read back as raw primitives (the shape rusqlite's row closure can
/// yield). [`RawEventRow::into_event`] then rebuilds a [`Event`], surfacing the timestamp / uuid /
/// digest-width conversions as [`StoreError`] rather than forcing them into the rusqlite closure.
struct RawEventRow {
    seq: i64,
    id: String,
    actor: String,
    justification: Option<String>,
    timestamp: String,
    scope: String,
    kind: String,
    payload_digest: Vec<u8>,
    prev_hash: Vec<u8>,
    hash: Vec<u8>,
    links: String,
}

impl RawEventRow {
    fn into_event(self) -> Result<Event, StoreError> {
        let links: Vec<ChainLink> = serde_json::from_str(&self.links).unwrap_or_default();
        Ok(Event {
            id: parse_uuid_newtype::<EventId>(&self.id)?,
            seq: self.seq as u64,
            actor: self.actor,
            justification: self.justification,
            timestamp: parse_rfc3339(&self.timestamp)?,
            scope: self.scope,
            kind: self.kind,
            payload_digest: blob32(self.payload_digest, "payload_digest")?,
            prev_hash: blob32(self.prev_hash, "prev_hash")?,
            links,
            hash: blob32(self.hash, "hash")?,
        })
    }
}

/// Reconstruct a uuid newtype id (e.g. [`EntityId`], [`EventId`]) stored as its plain uuid text.
///
/// These ids serialize transparently as their inner uuid (a JSON string), so quoting the stored
/// text and running it back through serde reconstructs the id without a direct `uuid` dependency.
fn parse_uuid_newtype<T: DeserializeOwned>(raw: &str) -> Result<T, StoreError> {
    Ok(serde_json::from_str(&format!("\"{raw}\""))?)
}

/// Parse an RFC 3339 timestamp stored in the `events.timestamp` column back to an [`OffsetDateTime`].
/// A malformed value means the row was corrupted after being written by [`Tx::append_event`].
fn parse_rfc3339(raw: &str) -> Result<OffsetDateTime, StoreError> {
    OffsetDateTime::parse(raw, &Rfc3339).map_err(|e| {
        StoreError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid stored timestamp {raw:?}: {e}"),
        ))
    })
}

/// Convert a BLOB column into a fixed 32-byte digest, treating a wrong-length value as corruption.
fn blob32(bytes: Vec<u8>, what: &str) -> Result<[u8; 32], StoreError> {
    let len = bytes.len();
    <[u8; 32]>::try_from(bytes).map_err(|_| {
        StoreError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("stored {what} is {len} bytes, expected 32"),
        ))
    })
}

/// Lowercase-hex encoding of a byte slice (sha256 digests and the ledger head hash).
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// A filesystem-safe compact UTC stamp (`YYYYMMDDTHHMMSSZ`) for backup archive names — no colons,
/// which Windows forbids in paths.
fn utc_stamp(t: OffsetDateTime) -> String {
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        t.year(),
        t.month() as u8,
        t.day(),
        t.hour(),
        t.minute(),
        t.second(),
    )
}

/// Add a single file to the zip, recording its sha256 and byte length in `files`.
fn add_file_to_zip<W: Write + std::io::Seek>(
    zip: &mut zip::ZipWriter<W>,
    name: &str,
    path: &Path,
    opts: zip::write::SimpleFileOptions,
    files: &mut Vec<BackupFile>,
) -> Result<(), StoreError> {
    // Zip-slip defense: reject member names containing path-traversal sequences.
    if name.contains("..") {
        return Ok(());
    }
    let bytes = std::fs::read(path)?;
    let digest = Sha256::digest(&bytes);
    zip.start_file(name, opts)?;
    zip.write_all(&bytes)?;
    files.push(BackupFile {
        name: name.to_string(),
        sha256: hex(&digest),
        bytes: bytes.len() as u64,
    });
    Ok(())
}

/// Add a sidecar path to the zip: a file directly, a directory recursively (member names carry the
/// relative sub-path), and a missing path is skipped (tolerated per the plan). Symlinks are skipped
/// and member names containing `..` are rejected (zip-slip defense, ZIP-01).
fn add_path_to_zip<W: Write + std::io::Seek>(
    zip: &mut zip::ZipWriter<W>,
    name: &str,
    path: &Path,
    opts: zip::write::SimpleFileOptions,
    files: &mut Vec<BackupFile>,
) -> Result<(), StoreError> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        // Skip missing paths (tolerated per the plan, mirrors the original is_dir/is_file behavior).
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(StoreError::Io(e)),
    };
    // Skip symlinks — they could point outside the intended directory tree (zip-slip).
    if meta.file_type().is_symlink() {
        return Ok(());
    }
    // Reject path-traversal sequences in the member name.
    if name.contains("..") {
        return Ok(());
    }
    if meta.is_dir() {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let child_name = format!("{name}/{}", entry.file_name().to_string_lossy());
            add_path_to_zip(zip, &child_name, &entry.path(), opts, files)?;
        }
    } else if meta.is_file() {
        add_file_to_zip(zip, name, path, opts, files)?;
    }
    Ok(())
}
