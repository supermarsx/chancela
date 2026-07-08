//! SQLite schema for the durable system of record (t30.md §2, "Tables").
//!
//! The DDL is expressed as idempotent `CREATE TABLE IF NOT EXISTS` / `CREATE INDEX IF NOT
//! EXISTS` statements so [`crate::Store::open`] can run it on every boot — a fresh database is
//! created and an existing one is left untouched. Real schema migrations (when the layout ever
//! changes) key off the `schema_version` row in `meta`.
//!
//! ## Model (t30.md §D2)
//!
//! Aggregates are stored **document-in-relational**: `(id, …scope cols…, json)` where `json` is
//! the serde serialization of the domain value. This keeps "relational" honest (real tables,
//! transactions, indices for scoped retrieval) while avoiding a brittle per-field column schema
//! that the fast-evolving ENT/LEG domain would force constant migrations on. The `events` table
//! stores the hash-chain fields directly so a per-`scope` / per-`kind` retrieval is indexed and
//! the chain order (`seq`) is the primary key (ARC-14 append-only event table).

/// The schema version recorded in `meta` and asserted by [`crate::Store::open`].
///
/// Bump this only alongside a real migration step.
/// - **v1** — the initial durable layout (meta/events/entities/books/acts/registry_extracts).
/// - **v2** — adds the `documents` table (Wave C, t48-e4): generated PDF/A documents preserved
///   alongside their sealed act (plan t48 §3.3/§3.4/D4). Forward-only: an existing v1 database
///   gains the table via the idempotent [`ALL`] DDL and has its stamp advanced on next open.
pub const SCHEMA_VERSION: i64 = 2;

/// `meta` — small key/value table for the `schema_version` stamp and the app version.
pub const CREATE_META: &str = "\
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;";

/// `events` — the append-only, hash-chained ledger (ARC-14). `seq` is the chain order and the
/// primary key; the chaining fields (`prev_hash`, `hash`, `payload_digest`) are stored as BLOBs.
/// `links` holds the serialized `Vec<ChainLink>` (multi-chain membership, t41).
pub const CREATE_EVENTS: &str = "\
CREATE TABLE IF NOT EXISTS events (
    seq            INTEGER PRIMARY KEY,
    id             TEXT NOT NULL,
    actor          TEXT NOT NULL,
    justification  TEXT,
    timestamp      TEXT NOT NULL,
    scope          TEXT NOT NULL,
    kind           TEXT NOT NULL,
    payload_digest BLOB NOT NULL,
    prev_hash      BLOB NOT NULL,
    hash           BLOB NOT NULL,
    links          TEXT NOT NULL DEFAULT '[]'
) STRICT;";

/// Index over `events.scope` — enables per-scope retrieval and verification-by-filter (D5: the
/// cheaper per-scope detection path, without the deferred independent per-scope chain).
pub const CREATE_EVENTS_SCOPE_IDX: &str =
    "CREATE INDEX IF NOT EXISTS idx_events_scope ON events (scope);";

/// Index over `events.kind` — feeds kind-filtered audit queries.
pub const CREATE_EVENTS_KIND_IDX: &str =
    "CREATE INDEX IF NOT EXISTS idx_events_kind ON events (kind);";

/// `entities` — one row per [`chancela_core::Entity`]; the value lives in `json`.
pub const CREATE_ENTITIES: &str = "\
CREATE TABLE IF NOT EXISTS entities (
    id   TEXT PRIMARY KEY,
    json TEXT NOT NULL
) STRICT;";

/// `books` — one row per [`chancela_core::Book`]; `entity_id` is indexed for the books-of-an-entity feed.
pub const CREATE_BOOKS: &str = "\
CREATE TABLE IF NOT EXISTS books (
    id        TEXT PRIMARY KEY,
    entity_id TEXT NOT NULL,
    json      TEXT NOT NULL
) STRICT;";

/// Index over `books.entity_id`.
pub const CREATE_BOOKS_ENTITY_IDX: &str =
    "CREATE INDEX IF NOT EXISTS idx_books_entity ON books (entity_id);";

/// `acts` — one row per [`chancela_core::Act`]; `book_id` is indexed for the acts-in-a-book feed.
pub const CREATE_ACTS: &str = "\
CREATE TABLE IF NOT EXISTS acts (
    id      TEXT PRIMARY KEY,
    book_id TEXT NOT NULL,
    json    TEXT NOT NULL
) STRICT;";

/// Index over `acts.book_id`.
pub const CREATE_ACTS_BOOK_IDX: &str =
    "CREATE INDEX IF NOT EXISTS idx_acts_book ON acts (book_id);";

/// `registry_extracts` — one row per imported certidão, keyed by the owning entity id.
pub const CREATE_REGISTRY_EXTRACTS: &str = "\
CREATE TABLE IF NOT EXISTS registry_extracts (
    entity_id TEXT PRIMARY KEY,
    json      TEXT NOT NULL
) STRICT;";

/// `documents` — one row per generated PDF/A document bound to a sealed act (schema v2, Wave C,
/// plan t48 §3.4/D4). Unlike the four aggregate tables this is **not** document-in-relational JSON:
/// the payload is opaque PDF bytes (`pdf_bytes` BLOB), so the metadata that the api's endpoints and
/// the seal response need is broken out into typed columns rather than a serde `json` blob.
///
/// - `id` — the document id (primary key; the upsert is idempotent on it).
/// - `act_id` — the owning act, indexed for the `GET /v1/acts/{id}/document` lookup (mirrors how
///   `acts.book_id` is the indexed scope column — one indexed scope column per table).
/// - `template_id` — the versioned spec id recorded verbatim (e.g. `csc-ata-ag/v1`).
/// - `pdf_digest` — lowercase-hex sha-256 of `pdf_bytes` (bound into the `document.generated` event).
/// - `profile` — the rule-pack / profile string the document was produced under.
/// - `created_at` — RFC 3339 text, the inscription-ordering field (mirrors `events.timestamp`);
///   the by-act read returns the most recent row.
/// - `pdf_bytes` — the PDF/A-2u bytes themselves.
pub const CREATE_DOCUMENTS: &str = "\
CREATE TABLE IF NOT EXISTS documents (
    id          TEXT PRIMARY KEY,
    act_id      TEXT NOT NULL,
    template_id TEXT NOT NULL,
    pdf_digest  TEXT NOT NULL,
    profile     TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    pdf_bytes   BLOB NOT NULL
) STRICT;";

/// Index over `documents.act_id` — feeds the by-act document retrieval (one act → its documents).
pub const CREATE_DOCUMENTS_ACT_IDX: &str =
    "CREATE INDEX IF NOT EXISTS idx_documents_act ON documents (act_id);";

/// Every DDL statement, in dependency order, for [`crate::Store::open`] to execute on boot.
pub const ALL: &[&str] = &[
    CREATE_META,
    CREATE_EVENTS,
    CREATE_EVENTS_SCOPE_IDX,
    CREATE_EVENTS_KIND_IDX,
    CREATE_ENTITIES,
    CREATE_BOOKS,
    CREATE_BOOKS_ENTITY_IDX,
    CREATE_ACTS,
    CREATE_ACTS_BOOK_IDX,
    CREATE_REGISTRY_EXTRACTS,
    CREATE_DOCUMENTS,
    CREATE_DOCUMENTS_ACT_IDX,
];
