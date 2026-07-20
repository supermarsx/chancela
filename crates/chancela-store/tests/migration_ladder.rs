//! Integration tests for the **v1…v23 schema upgrade path** (tg2).
//!
//! The rest of the suite proves the store behaves correctly once it is at the current schema. This
//! file proves it *gets there* — that a database written by an older build opens under the current
//! code with every row still readable and unchanged. A migration that silently succeeds by dropping
//! data is the failure being guarded against, so the assertions are on **content** (row equality,
//! bytes, digests, chain verification), never on "the open returned Ok".
//!
//! ## How the ladder actually works
//!
//! There is no per-version step function and no numbered migration files. The whole mechanism is:
//!
//! 1. `crates/chancela-store/src/lib.rs:7030` — every statement in `schema::ALL` runs on **every**
//!    boot. They are all `CREATE TABLE IF NOT EXISTS` / `CREATE INDEX IF NOT EXISTS`, so a fresh
//!    database is created and an existing one gains only the tables it lacks.
//! 2. `lib.rs:7036-7125` — a block of `table_has_column`-guarded `ALTER TABLE … ADD COLUMN`
//!    statements for the handful of columns added to tables that already shipped. `CREATE TABLE IF
//!    NOT EXISTS` cannot add a column to an existing table, so these are the only real per-column
//!    migrations, and two of them additionally **backfill** the new column from existing data.
//! 3. `lib.rs:7127-7161` — the `meta.schema_version` gate: a *newer* stamp is rejected
//!    (`UnsupportedSchemaVersion`), an *older* stamp is advanced to `schema::SCHEMA_VERSION`, a
//!    missing one is inserted. The stamp is a **record** of the migration, not its driver: nothing
//!    keys off the found version, so the DDL above is what actually upgrades the file.
//!
//! Consequently the upgrade is forward-only and additive: no table is dropped, no column retyped,
//! and every historical row is left exactly where it was.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use chancela_core::{Act, ActId, Book, BookKind, Entity, EntityKind, MeetingChannel, Nipc};
use chancela_ledger::Ledger;
use chancela_registry::{RegistryExtract, RegistryProvenance};
use chancela_store::schema::{LOGICAL_BACKUP_TABLES, SCHEMA_VERSION};
use chancela_store::{Store, StoreError, StoredImportedDocumentReviewStatus, StoredSignedDocument};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

// --- std-only tempdir (the crate's Cargo.toml is frozen; no `tempfile` dev-dep) -----------------

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new() -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut path = std::env::temp_dir();
        path.push(format!(
            "chancela-ladder-test-{}-{nanos}-{n}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create temp dir");
        TempDir { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn db(&self) -> PathBuf {
        self.path.join("chancela.db")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

// --- the ladder, declared -----------------------------------------------------------------------

/// Every table `schema::ALL` creates, paired with the schema version that introduced it (read off
/// the `SCHEMA_VERSION` doc comment in `crates/chancela-store/src/schema.rs:20-113`).
///
/// This is the fixture that makes "a database at version *v*" constructible: since the upgrade is
/// purely additive, a v*n* database is a current database with every table introduced after *n*
/// removed and the stamp rolled back. [`the_declared_ladder_covers_every_table_in_the_schema`] pins
/// the list against the schema so a new table added without a ladder entry fails here rather than
/// going quietly untested.
const TABLE_LADDER: &[(i64, &str)] = &[
    (1, "meta"),
    (1, "events"),
    (1, "entities"),
    (1, "books"),
    (1, "acts"),
    (1, "registry_extracts"),
    (2, "documents"),
    (3, "imported_books"),
    (4, "signed_documents"),
    (4, "pending_cmd_sessions"),
    (5, "imported_documents"),
    (6, "follow_ups"),
    (8, "paper_book_imports"),
    (9, "paper_book_ocr_drafts"),
    (12, "paper_book_ocr_conversion_dossiers"),
    (13, "generated_document_dispatch_evidence"),
    (14, "paper_book_ocr_conversion_execution_artifacts"),
    (15, "imported_document_review_history"),
    (16, "users"),
    (16, "roles"),
    (16, "delegations"),
    (16, "settings"),
    (16, "provider_credentials"),
    (17, "user_templates"),
    (18, "subject_keys"),
    (19, "tenants"),
    (20, "company_groups"),
    (20, "group_template_libraries"),
    (20, "group_template_library_revisions"),
    (22, "pairing_devices"),
    (23, "instrument_signatures"),
];

/// Every column added by an `ALTER TABLE … ADD COLUMN` guard in `configure_and_migrate`
/// (`crates/chancela-store/src/lib.rs:7036-7125`), as `(table, column)`.
///
/// These are the migrations the idempotent `CREATE TABLE IF NOT EXISTS` DDL cannot perform, so they
/// are the ones that can actually fail on an existing file. Not all carry a documented version
/// number — `events.links` and the two `signer_capacity_evidence_json` columns do not — so they are
/// exercised as a set by [`every_additive_column_guard_restores_its_column`] rather than being
/// pinned to a rung of [`TABLE_LADDER`].
const ADDITIVE_COLUMNS: &[(&str, &str)] = &[
    ("events", "links"),
    ("signed_documents", "timestamp_trust_report_json"),
    ("signed_documents", "signer_capacity_evidence_json"),
    ("pending_cmd_sessions", "signer_capacity_evidence_json"),
    ("imported_documents", "operator_review_status"),
    ("imported_documents", "operator_reviewed_at"),
    ("imported_documents", "operator_reviewed_by"),
    ("imported_documents", "operator_review_note"),
    (
        "imported_documents",
        "operator_acknowledged_guardrail_ids_json",
    ),
    ("imported_documents", "technical_validation_report_json"),
    ("paper_book_imports", "page_from"),
    ("paper_book_imports", "page_to"),
    ("paper_book_imports", "original_number_from"),
    ("paper_book_imports", "original_number_to"),
];

// --- fixtures -----------------------------------------------------------------------------------

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sample_entity() -> Entity {
    Entity::new(
        "Encosto Estrategico Lda",
        Nipc::unvalidated("500002020"),
        "Rua de Teste, Lisboa",
        EntityKind::SociedadePorQuotas,
    )
}

fn sample_extract() -> RegistryExtract {
    RegistryExtract {
        matricula: Some("12345".to_string()),
        nipc: Some("500002020".to_string()),
        firma: Some("Encosto Estrategico Lda".to_string()),
        forma_juridica: None,
        legal_form: None,
        sede: Some("Lisboa".to_string()),
        cae: Vec::new(),
        objeto: None,
        capital: None,
        data_constituicao: None,
        orgaos: Vec::new(),
        inscricoes: Vec::new(),
        anotacoes: Vec::new(),
        provenance: RegistryProvenance {
            access_code_masked: "****-****-1234".to_string(),
            retrieved_at: "2026-07-07T00:00:00Z".to_string(),
            source_url: "https://example.test/certidao".to_string(),
            raw_digest: "deadbeef".to_string(),
            conservatoria: None,
            oficial: None,
            subscribed_on: None,
            valid_until: None,
        },
    }
}

fn sample_signed(act_id: ActId, signer: &str, bytes: &[u8]) -> StoredSignedDocument {
    StoredSignedDocument {
        act_id,
        document_id: "doc-1".to_string(),
        signed_pdf_digest: hex(&Sha256::digest(bytes)),
        signature_family: "ChaveMovelDigital".to_string(),
        evidentiary_level: "Qualified".to_string(),
        trusted_list_status: Some("Granted".to_string()),
        signer_cert_subject: Some(format!("CN={signer}")),
        signing_time: OffsetDateTime::from_unix_timestamp(1_770_000_100).unwrap(),
        signed_at: OffsetDateTime::from_unix_timestamp(1_770_000_120).unwrap(),
        signer_cert_der: vec![0x30, 0x82, 0x01, 0x02],
        timestamp_token_der: Some(vec![0x30, 0x03, 0x01, 0x01, 0xff]),
        timestamp_trust_report_json: Some(r#"{"policy":"qtst"}"#.to_string()),
        signer_capacity_evidence_json: Some(
            r#"{"verification_status":"not_checked_by_scap"}"#.to_string(),
        ),
        signed_pdf_bytes: bytes.to_vec(),
    }
}

/// The rows every rung of the ladder can hold: they live in tables that exist at v1, so the same
/// assertions apply whether the fixture is downgraded to v1 or to v22.
struct V1Fixture {
    entity: Entity,
    book: Book,
    act: Act,
    extract: RegistryExtract,
    event_hashes: Vec<Vec<u8>>,
}

/// Seed one entity, one book, one act, one registry extract and a three-event hash chain.
fn seed_v1_rows(store: &Store) -> V1Fixture {
    let entity = sample_entity();
    let book = Book::new(entity.id, BookKind::AssembleiaGeral);
    let act = Act::draft(book.id, "Ata n.o 1", MeetingChannel::Physical);
    let extract = sample_extract();

    let mut ledger = Ledger::new();
    let scope_entity = format!("entity:{}", entity.id);
    let scope_book = format!("entity:{}/book:{}", entity.id, book.id);
    let e0 = ledger
        .append(
            "amelia.marques",
            &scope_entity,
            "entity.created",
            None,
            b"e",
        )
        .clone();
    let e1 = ledger
        .append("amelia.marques", &scope_book, "book.opened", None, b"b")
        .clone();
    let e2 = ledger
        .append("amelia.marques", &scope_book, "act.sealed", None, b"a")
        .clone();

    store
        .persist(|tx| {
            tx.append_event(&e0)?;
            tx.append_event(&e1)?;
            tx.append_event(&e2)?;
            tx.upsert_entity(&entity)?;
            tx.upsert_book(&book)?;
            tx.upsert_act(&act)?;
            tx.upsert_registry_extract(entity.id, &extract)
        })
        .expect("seed the v1 rows");

    V1Fixture {
        event_hashes: [&e0, &e1, &e2].iter().map(|e| e.hash.to_vec()).collect(),
        entity,
        book,
        act,
        extract,
    }
}

/// Assert every seeded aggregate row came back **unchanged**. Split out from
/// [`assert_v1_rows_intact`] because one fixture (the column-strip test) deliberately destroys the
/// ledger's chain-membership data and can only assert this half — see
/// [`every_additive_column_guard_restores_its_column`].
fn assert_v1_aggregates_intact(store: &Store, fixture: &V1Fixture, context: &str) {
    let loaded = store.load().expect("load after upgrade");
    assert_eq!(
        loaded.entities.get(&fixture.entity.id),
        Some(&fixture.entity),
        "{context}: the entity row was altered or lost by the upgrade"
    );
    assert_eq!(
        loaded.books.get(&fixture.book.id),
        Some(&fixture.book),
        "{context}: the book row was altered or lost by the upgrade"
    );
    assert_eq!(
        loaded.acts.get(&fixture.act.id),
        Some(&fixture.act),
        "{context}: the act row was altered or lost by the upgrade"
    );
    assert_eq!(
        loaded.registry_extracts.get(&fixture.entity.id),
        Some(&fixture.extract),
        "{context}: the registry extract was altered or lost by the upgrade"
    );
    assert_eq!(
        loaded.ledger.len(),
        3,
        "{context}: the upgrade changed the event count"
    );
}

/// Assert every seeded row came back **unchanged**, and that the ledger still verifies.
fn assert_v1_rows_intact(store: &Store, fixture: &V1Fixture, context: &str) {
    assert_v1_aggregates_intact(store, fixture, context);
    let loaded = store.load().expect("load after upgrade");
    assert_eq!(
        loaded
            .ledger
            .events()
            .iter()
            .map(|e| e.hash.to_vec())
            .collect::<Vec<_>>(),
        fixture.event_hashes,
        "{context}: an event's chain hash changed across the upgrade"
    );
    assert_eq!(
        loaded.chain_status,
        Ok(3),
        "{context}: the hash chain no longer verifies after the upgrade"
    );
}

// --- downgrade helpers --------------------------------------------------------------------------

fn stamped_version(db: &Path) -> String {
    let raw = rusqlite::Connection::open(db).expect("open raw sqlite");
    raw.query_row(
        "SELECT value FROM meta WHERE key = 'schema_version'",
        [],
        |row| row.get(0),
    )
    .expect("schema_version stamp")
}

fn table_exists(conn: &rusqlite::Connection, table: &str) -> bool {
    conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
        [table],
        |row| row.get::<_, i64>(0),
    )
    .expect("sqlite_master lookup")
        == 1
}

fn column_exists(conn: &rusqlite::Connection, table: &str, column: &str) -> bool {
    conn.query_row(
        &format!("SELECT COUNT(*) FROM pragma_table_info('{table}') WHERE name = ?1"),
        [column],
        |row| row.get::<_, i64>(0),
    )
    .expect("pragma_table_info lookup")
        == 1
}

/// Turn a current-schema database file into a plausible database at `version`: drop every table the
/// ladder says arrived later, then roll the stamp back. Because the upgrade path is additive-only
/// this is a faithful reconstruction — the surviving tables have exactly the shape they had then.
fn downgrade_to(db: &Path, version: i64) {
    let raw = rusqlite::Connection::open(db).expect("open raw sqlite");
    for (introduced, table) in TABLE_LADDER {
        if *introduced > version {
            raw.execute_batch(&format!("DROP TABLE IF EXISTS {table};"))
                .unwrap_or_else(|e| panic!("drop {table} for the v{version} fixture: {e}"));
        }
    }
    raw.execute(
        "UPDATE meta SET value = ?1 WHERE key = 'schema_version'",
        rusqlite::params![version.to_string()],
    )
    .expect("roll the stamp back");
}

// --- the ladder is declared completely ----------------------------------------------------------

/// The fixture list above is only as good as its coverage. `LOGICAL_BACKUP_TABLES` is the crate's
/// own public enumeration of every table, and `schema::tests::logical_backup_tables_cover_the_whole_schema`
/// already pins *it* against the DDL — so agreeing with it transitively pins this ladder against the
/// schema. A table added without a rung here would otherwise be silently exempt from every upgrade
/// test in this file.
#[test]
fn the_declared_ladder_covers_every_table_in_the_schema() {
    let mut ladder: Vec<&str> = TABLE_LADDER.iter().map(|(_, table)| *table).collect();
    ladder.sort_unstable();
    let deduped = {
        let mut d = ladder.clone();
        d.dedup();
        d
    };
    assert_eq!(ladder, deduped, "TABLE_LADDER names a table twice");

    let mut expected: Vec<&str> = LOGICAL_BACKUP_TABLES.to_vec();
    expected.sort_unstable();
    assert_eq!(
        ladder, expected,
        "TABLE_LADDER and the schema's own table list disagree — every table needs the version \
         that introduced it, or it is exempt from every migration test in this file"
    );

    let newest = TABLE_LADDER
        .iter()
        .map(|(version, _)| *version)
        .max()
        .expect("the ladder is non-empty");
    assert_eq!(
        newest, SCHEMA_VERSION,
        "the newest table in the ladder is from v{newest} but SCHEMA_VERSION is {SCHEMA_VERSION} \
         — either a version bumped without a table, or a table landed without a ladder entry"
    );
}

// --- 1. every rung of the ladder opens at current, with its data intact --------------------------

/// The headline guarantee: a database written by **any** older build opens under the current code
/// with every pre-existing row readable and byte-for-byte unchanged.
///
/// Every version from 1 to `SCHEMA_VERSION` is exercised, not a sampled few — the fixture is
/// constructed from the ladder rather than hand-written per version, so there is no gap to leave
/// untested. The seeded rows all live in tables that exist at v1, so the same content assertions
/// hold at every rung; the newer tables are asserted to have been *created*, which is what the
/// migration owes them.
#[test]
fn every_schema_version_from_v1_opens_at_current_with_its_data_intact() {
    for version in 1..=SCHEMA_VERSION {
        let dir = TempDir::new();
        let fixture = {
            let store = Store::open(dir.path()).expect("open at the current version");
            let fixture = seed_v1_rows(&store);
            drop(store);
            fixture
        };
        downgrade_to(&dir.db(), version);

        let store = Store::open(dir.path())
            .unwrap_or_else(|e| panic!("a v{version} database must open at current: {e}"));
        assert_v1_rows_intact(&store, &fixture, &format!("v{version} → v{SCHEMA_VERSION}"));

        // The stamp advanced, and every table the schema declares now exists — including the ones
        // the fixture removed.
        assert_eq!(
            stamped_version(&dir.db()),
            SCHEMA_VERSION.to_string(),
            "the v{version} stamp was not advanced"
        );
        let conn = rusqlite::Connection::open(dir.db()).expect("open raw sqlite");
        for (introduced, table) in TABLE_LADDER {
            assert!(
                table_exists(&conn, table),
                "upgrading from v{version} did not recreate {table} (introduced at v{introduced})"
            );
        }
    }
}

/// The upgraded database is not merely *openable* — the tables the migration created are usable.
/// A table recreated with the wrong shape would pass a `sqlite_master` check and fail on first
/// write, which is a worse failure because it happens in production rather than at boot.
#[test]
fn tables_created_by_the_upgrade_accept_writes() {
    let dir = TempDir::new();
    let fixture = {
        let store = Store::open(dir.path()).expect("open at the current version");
        let fixture = seed_v1_rows(&store);
        drop(store);
        fixture
    };
    downgrade_to(&dir.db(), 1);

    let store = Store::open(dir.path()).expect("upgrade v1 → current");
    assert_v1_rows_intact(&store, &fixture, "v1 → current");

    // `signed_documents` (v4) and `instrument_signatures` (v23) were both recreated by the upgrade.
    let signed = sample_signed(fixture.act.id, "Amélia Marques", b"%PDF-1.7 signed");
    store
        .persist(|tx| tx.upsert_signed_document(&signed))
        .expect("write into the recreated v4/v23 tables");
    assert_eq!(
        store.signed_document_for_act(fixture.act.id).unwrap(),
        Some(signed.clone())
    );
    let history = store
        .signature_history_for_subject(fixture.act.id)
        .expect("history from the recreated table");
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].seq, 1);
    assert_eq!(history[0].document, signed);
}

// --- 2. the v22 → v23 step ----------------------------------------------------------------------

/// The step this file exists for: a v22 database holds `signed_documents` rows and has no
/// `instrument_signatures` table at all. The upgrade must create the table, leave those rows
/// untouched, and report each of them as the single seq-1 signature it is (the documented pre-v23
/// fallback in `Store::signature_history_for_subject`).
#[test]
fn a_v22_database_with_signed_documents_upgrades_and_keeps_every_byte() {
    let dir = TempDir::new();
    let bytes = b"%PDF-1.7 the only evidence of what this signer assented to";
    let (fixture, signed) = {
        let store = Store::open(dir.path()).expect("open at the current version");
        let fixture = seed_v1_rows(&store);
        let signed = sample_signed(fixture.act.id, "Amélia Marques", bytes);
        store
            .persist(|tx| tx.upsert_signed_document(&signed))
            .expect("sign at v23, then pretend it happened at v22");
        drop(store);
        (fixture, signed)
    };
    downgrade_to(&dir.db(), 22);

    // Precondition: the fixture really is a v22 database — no history table, artifact row present.
    {
        let conn = rusqlite::Connection::open(dir.db()).expect("open raw sqlite");
        assert!(
            !table_exists(&conn, "instrument_signatures"),
            "the v22 fixture must not have the v23 table"
        );
        let artifacts: i64 = conn
            .query_row("SELECT COUNT(*) FROM signed_documents", [], |row| {
                row.get(0)
            })
            .expect("count signed_documents");
        assert_eq!(
            artifacts, 1,
            "the v22 fixture must hold its signed document"
        );
    }

    let store = Store::open(dir.path()).expect("upgrade v22 → v23");
    assert_v1_rows_intact(&store, &fixture, "v22 → v23");
    assert_eq!(
        stamped_version(&dir.db()),
        SCHEMA_VERSION.to_string(),
        "the v22 stamp was not advanced"
    );

    // The pre-existing signed document is unchanged — every column, and the bytes.
    let current = store
        .signed_document_for_act(fixture.act.id)
        .expect("read the pre-existing signed document")
        .expect("it must survive the upgrade");
    assert_eq!(current, signed, "the v22 signed document was altered");
    assert_eq!(current.signed_pdf_bytes, bytes.to_vec());
    assert_eq!(
        hex(&Sha256::digest(&current.signed_pdf_bytes)),
        current.signed_pdf_digest,
        "the retained bytes no longer match their recorded digest"
    );
    assert_eq!(
        store.all_signed_documents().unwrap().get(&fixture.act.id),
        Some(&signed)
    );

    // Nothing was backfilled: the raw history is genuinely empty, so the fallback is what makes the
    // row readable — not a hidden migrate-and-drop.
    assert!(
        store
            .instrument_signatures_for_subject(fixture.act.id)
            .expect("raw history")
            .is_empty(),
        "the v22 → v23 upgrade must not copy rows into instrument_signatures"
    );

    // …and the fallback reports it as the subject's single, first signature.
    let history = store
        .signature_history_for_subject(fixture.act.id)
        .expect("history");
    assert_eq!(
        history.len(),
        1,
        "a pre-v23 signature must not read as none"
    );
    assert_eq!(history[0].seq, 1);
    assert_eq!(history[0].slot_id, None);
    assert_eq!(history[0].document, signed);
}

/// **Characterization test for a live defect — this asserts what the code *does*, not what it
/// should do.** See `.orchestration/logs/tg2-migration.md`.
///
/// A subject signed before v23 has a `signed_documents` row and no history rows. When a *second*
/// signer signs that subject after the upgrade, `Tx::upsert_signed_document` runs
/// `INSERT OR REPLACE INTO signed_documents` (which destroys the pre-v23 signer's row **and its
/// bytes**) and then appends to a history that is empty, so the newcomer takes `MAX(seq)+1 = 1`.
///
/// The result is precisely the data loss schema v23 was created to prevent, still reachable for
/// every subject signed before the upgrade: the first signer's artifact is gone, and the chain now
/// claims the second signature is signature #1 — misstating sequential PAdES order, since signature
/// 2 actually covers signature 1's bytes.
///
/// The assertions below are deliberately the observed behaviour so the suite stays honest and green.
/// **When this test fails, the defect has been fixed** — replace it with the correct expectation:
/// the legacy artifact adopted as seq 1 and the new signature appended at seq 2.
#[test]
fn known_defect_a_new_signature_on_a_pre_v23_subject_destroys_the_legacy_one() {
    let dir = TempDir::new();
    let legacy_bytes = b"%PDF-1.7 signed by the first signer, before the upgrade";
    let (fixture, legacy) = {
        let store = Store::open(dir.path()).expect("open at the current version");
        let fixture = seed_v1_rows(&store);
        let legacy = sample_signed(fixture.act.id, "Amélia Marques", legacy_bytes);
        store
            .persist(|tx| tx.upsert_signed_document(&legacy))
            .expect("the pre-upgrade signature");
        drop(store);
        (fixture, legacy)
    };
    downgrade_to(&dir.db(), 22);

    let store = Store::open(dir.path()).expect("upgrade v22 → v23");
    assert_eq!(
        store.signature_history_for_subject(fixture.act.id).unwrap()[0].document,
        legacy,
        "precondition: the legacy signature is readable immediately after the upgrade"
    );

    // A genuinely different second signature on the same subject.
    let second = sample_signed(
        fixture.act.id,
        "Rui Ferreira",
        b"%PDF-1.7 countersigned by the second signer, after the upgrade",
    );
    assert_ne!(legacy.signed_pdf_digest, second.signed_pdf_digest);
    store
        .persist(|tx| tx.upsert_signed_document(&second))
        .expect("the post-upgrade signature");

    let history = store
        .signature_history_for_subject(fixture.act.id)
        .expect("history");
    assert_eq!(
        history.len(),
        1,
        "DEFECT: the legacy signature is not in the history — it should be, at seq 1, with the \
         new signature at seq 2"
    );
    assert_eq!(
        history[0].document, second,
        "DEFECT: the only surviving signature is the newcomer"
    );
    assert_eq!(
        history[0].seq, 1,
        "DEFECT: the second signature claims position 1, misstating sequential PAdES order"
    );
    assert_eq!(
        store.signed_document_for_act(fixture.act.id).unwrap(),
        Some(second),
        "DEFECT: the first signer's artifact row was replaced"
    );
    // The bytes are the loss that matters: a superseded signature's artifact is the only evidence
    // of what that signer actually assented to, and there is now no row anywhere holding them.
    let surviving: Vec<Vec<u8>> = store
        .signature_history_for_subject(fixture.act.id)
        .unwrap()
        .into_iter()
        .map(|s| s.document.signed_pdf_bytes)
        .collect();
    assert!(
        !surviving.contains(&legacy_bytes.to_vec()),
        "DEFECT: the first signer's bytes are unrecoverable after the second signature"
    );
}

// --- 3. idempotence ------------------------------------------------------------------------------

/// Opening an already-current database must be a no-op: the migration must not re-run destructively,
/// duplicate a row, re-stamp anything, or mint a second instance id. Three opens, everything stable.
#[test]
fn reopening_an_already_current_database_changes_nothing() {
    let dir = TempDir::new();
    let store = Store::open(dir.path()).expect("open");
    let fixture = seed_v1_rows(&store);
    let signed = sample_signed(fixture.act.id, "Amélia Marques", b"%PDF-1.7 signed");
    store
        .persist(|tx| tx.upsert_signed_document(&signed))
        .expect("sign");
    let instance_id = store.instance_id().expect("instance id");
    drop(store);

    let baseline = row_census(&dir.db());
    assert!(
        baseline
            .iter()
            .any(|(table, count)| *table == "events" && *count == 3),
        "the census must actually see the seeded rows: {baseline:?}"
    );

    for attempt in 1..=3 {
        let store = Store::open(dir.path())
            .unwrap_or_else(|e| panic!("reopen #{attempt} of a current database: {e}"));
        assert_v1_rows_intact(&store, &fixture, &format!("reopen #{attempt}"));
        assert_eq!(
            store.signed_document_for_act(fixture.act.id).unwrap(),
            Some(signed.clone()),
            "reopen #{attempt} altered the signed document"
        );
        assert_eq!(
            store
                .signature_history_for_subject(fixture.act.id)
                .unwrap()
                .len(),
            1,
            "reopen #{attempt} duplicated or dropped a signature history row"
        );
        assert_eq!(
            store.instance_id().expect("instance id"),
            instance_id,
            "reopen #{attempt} minted a second instance id"
        );
        drop(store);

        assert_eq!(
            stamped_version(&dir.db()),
            SCHEMA_VERSION.to_string(),
            "reopen #{attempt} moved the stamp"
        );
        assert_eq!(
            row_census(&dir.db()),
            baseline,
            "reopen #{attempt} changed the row counts — the migration is not idempotent"
        );
    }
}

/// `(table, row count)` for every table in the schema, in a stable order.
fn row_census(db: &Path) -> Vec<(&'static str, i64)> {
    let conn = rusqlite::Connection::open(db).expect("open raw sqlite");
    LOGICAL_BACKUP_TABLES
        .iter()
        .map(|table| {
            let count: i64 = conn
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap_or_else(|e| panic!("count {table}: {e}"));
            (*table, count)
        })
        .collect()
}

// --- 4. the additive column guards ---------------------------------------------------------------

/// `CREATE TABLE IF NOT EXISTS` cannot add a column to a table that already exists, so the
/// `ALTER TABLE … ADD COLUMN` guards in `configure_and_migrate` are the only part of the ladder that
/// can genuinely fail on an existing file. Strip every one of those columns from a populated
/// database and the next open must put them all back with the rows still there.
///
/// ## Why this one asserts aggregates rather than the verified chain
///
/// `events.links` is the one guarded column whose contents are load-bearing for tamper-evidence:
/// each event's hash commits to its per-chain links (`chancela-ledger/src/lib.rs:407-452`), so
/// re-adding the column with its `DEFAULT '[]'` cannot reconstruct what was there and the chain
/// reads as broken. That is correct rather than a defect — a genuinely pre-multi-chain (pre-t41)
/// event *had* no links, so `'[]'` is its true value and such a database verifies. It just means
/// this fixture, which strips links off modern link-bearing events, is not a faithful pre-t41
/// database and cannot assert the chain. The ladder tests above cover chain preservation.
#[test]
fn every_additive_column_guard_restores_its_column() {
    let dir = TempDir::new();
    let fixture = {
        let store = Store::open(dir.path()).expect("open");
        let fixture = seed_v1_rows(&store);
        drop(store);
        fixture
    };

    {
        let conn = rusqlite::Connection::open(dir.db()).expect("open raw sqlite");
        for (table, column) in ADDITIVE_COLUMNS {
            assert!(
                column_exists(&conn, table, column),
                "{table}.{column} is not in the current schema — ADDITIVE_COLUMNS is stale"
            );
            conn.execute_batch(&format!("ALTER TABLE {table} DROP COLUMN {column};"))
                .unwrap_or_else(|e| panic!("drop {table}.{column} for the fixture: {e}"));
        }
        conn.execute(
            "UPDATE meta SET value = '1' WHERE key = 'schema_version'",
            [],
        )
        .expect("roll the stamp back");
    }

    let store = Store::open(dir.path()).expect("the column guards must run");
    assert_v1_aggregates_intact(&store, &fixture, "columns stripped");
    drop(store);

    let conn = rusqlite::Connection::open(dir.db()).expect("open raw sqlite");
    for (table, column) in ADDITIVE_COLUMNS {
        assert!(
            column_exists(&conn, table, column),
            "the upgrade did not restore {table}.{column} — every read of {table} would fail"
        );
    }
}

/// Two of the column migrations **backfill**, and a backfill is where a migration most easily
/// corrupts data: it rewrites existing rows rather than only adding a default. `page_to` is derived
/// from `page_count`, and `operator_review_status` is a `CASE` over the detected content type.
///
/// The rows are written as raw SQL against a stripped schema because that is the only way to hold a
/// row that predates the column — the typed API cannot express one.
#[test]
fn the_backfilling_column_migrations_derive_the_right_value_per_row() {
    let dir = TempDir::new();
    Store::open(dir.path()).expect("create the current schema");

    {
        let conn = rusqlite::Connection::open(dir.db()).expect("open raw sqlite");
        for (table, column) in ADDITIVE_COLUMNS {
            conn.execute_batch(&format!("ALTER TABLE {table} DROP COLUMN {column};"))
                .unwrap_or_else(|e| panic!("drop {table}.{column}: {e}"));
        }
        // Three imports whose detected content types drive three different backfilled statuses.
        for (id, content_type) in [
            ("import-pdf", "application/pdf"),
            ("import-png", "image/png"),
            ("import-doc", "application/msword"),
        ] {
            conn.execute(
                "INSERT INTO imported_documents \
                 (id, act_id, filename, declared_content_type, detected_content_type, sha256, \
                  size_bytes, imported_at, imported_by, bytes) \
                 VALUES (?1, NULL, ?2, ?3, ?3, ?4, ?5, ?6, ?7, ?8)",
                rusqlite::params![
                    id,
                    format!("{id}.bin"),
                    content_type,
                    hex(&Sha256::digest(id.as_bytes())),
                    i64::try_from(id.len()).unwrap(),
                    "2026-05-29T01:46:41Z",
                    "amelia.marques",
                    id.as_bytes(),
                ],
            )
            .expect("insert a pre-v11 imported document");
        }
        conn.execute(
            "UPDATE meta SET value = '9' WHERE key = 'schema_version'",
            [],
        )
        .expect("roll the stamp back");
    }

    let store = Store::open(dir.path()).expect("run the backfilling migrations");

    for (id, expected) in [
        (
            "import-pdf",
            StoredImportedDocumentReviewStatus::OperatorReviewRequired,
        ),
        (
            "import-png",
            StoredImportedDocumentReviewStatus::OcrReviewRequired,
        ),
        (
            "import-doc",
            StoredImportedDocumentReviewStatus::CanonicalConversionReviewRequired,
        ),
    ] {
        let row = store
            .imported_document(id)
            .unwrap_or_else(|e| panic!("read the migrated {id}: {e}"))
            .unwrap_or_else(|| panic!("{id} did not survive the migration"));
        assert_eq!(
            row.meta.operator_review_status, expected,
            "{id} was backfilled with the wrong review status"
        );
        // The migration must add metadata, never touch the preserved evidence bytes.
        assert_eq!(row.bytes, id.as_bytes().to_vec());
        assert_eq!(row.meta.sha256, hex(&Sha256::digest(id.as_bytes())));
        // The v21 column arrives with its documented default, not NULL.
        assert_eq!(row.meta.technical_validation_report_json, "{}");
        assert!(row.meta.operator_acknowledged_guardrail_ids.is_empty());
        assert_eq!(row.meta.operator_reviewed_at, None);
    }
}

// --- 5. the stamp gate ---------------------------------------------------------------------------

/// The one direction the ladder refuses. A file written by a *newer* build has a layout this build
/// does not know, so opening it read-write could destroy data it cannot interpret; the gate is what
/// makes "forward-only" safe rather than merely optimistic.
#[test]
fn a_newer_stamp_is_refused_and_the_file_is_left_alone() {
    let dir = TempDir::new();
    let fixture = {
        let store = Store::open(dir.path()).expect("open");
        let fixture = seed_v1_rows(&store);
        drop(store);
        fixture
    };
    let baseline = row_census(&dir.db());

    {
        let conn = rusqlite::Connection::open(dir.db()).expect("open raw sqlite");
        conn.execute(
            "UPDATE meta SET value = ?1 WHERE key = 'schema_version'",
            rusqlite::params![(SCHEMA_VERSION + 1).to_string()],
        )
        .expect("stamp a future version");
    }

    match Store::open(dir.path()) {
        Err(StoreError::UnsupportedSchemaVersion { found, supported }) => {
            assert_eq!(found, SCHEMA_VERSION + 1);
            assert_eq!(supported, SCHEMA_VERSION);
        }
        other => panic!("a newer schema version must be refused, got {other:?}"),
    }

    assert_eq!(
        stamped_version(&dir.db()),
        (SCHEMA_VERSION + 1).to_string(),
        "the refused open must not rewrite the stamp"
    );
    assert_eq!(
        row_census(&dir.db()),
        baseline,
        "the refused open must not touch a single row"
    );

    // And once the stamp is honest again, the data is still all there.
    {
        let conn = rusqlite::Connection::open(dir.db()).expect("open raw sqlite");
        conn.execute(
            "UPDATE meta SET value = ?1 WHERE key = 'schema_version'",
            rusqlite::params![SCHEMA_VERSION.to_string()],
        )
        .expect("restore the stamp");
    }
    let store = Store::open(dir.path()).expect("reopen after the stamp is corrected");
    assert_v1_rows_intact(&store, &fixture, "after a refused open");
}

/// A database with no stamp at all — the shape a hand-repaired or very early file can have. The gate
/// inserts the current version rather than refusing, and the existing rows are left alone.
#[test]
fn a_database_with_no_stamp_is_adopted_at_the_current_version() {
    let dir = TempDir::new();
    let fixture = {
        let store = Store::open(dir.path()).expect("open");
        let fixture = seed_v1_rows(&store);
        drop(store);
        fixture
    };
    {
        let conn = rusqlite::Connection::open(dir.db()).expect("open raw sqlite");
        conn.execute("DELETE FROM meta WHERE key = 'schema_version'", [])
            .expect("remove the stamp");
    }

    let store = Store::open(dir.path()).expect("an unstamped database is adopted");
    assert_v1_rows_intact(&store, &fixture, "unstamped");
    assert_eq!(stamped_version(&dir.db()), SCHEMA_VERSION.to_string());
}
