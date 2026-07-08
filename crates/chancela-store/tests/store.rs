//! Integration tests for the durable system of record (t30-e1).
//!
//! This crate is the durability guard for the whole application, so the coverage here is
//! deliberately thorough: open/reopen idempotency, transactional atomicity (a mid-closure error
//! must persist *nothing*), a full drop-and-reload round trip with chain re-verification, raw-SQL
//! tamper detection, the schema-version-too-new rejection, and the `VACUUM INTO` hot backup
//! (archive present, per-file digests match, snapshot re-openable and self-verifying).

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use chancela_core::{
    Act, ActId, AttendanceWeight, Attendee, Book, BookKind, Convening, ConveningRecipient,
    DispatchChannel, Entity, EntityKind, MeetingChannel, Nipc, PresenceMode, SecondCall,
    SignatoryCapacity,
};
use chancela_ledger::{Event, Ledger, LedgerError};
use chancela_registry::{RegistryExtract, RegistryProvenance};
use chancela_store::{Store, StoreError, StoredDocument};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

// --- std-only tempdir (the crate's Cargo.toml is frozen; no `tempfile` dev-dep) -----------------

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// A unique scratch directory under the OS temp dir, removed on drop.
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
            "chancela-store-test-{}-{nanos}-{n}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create temp dir");
        TempDir { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

// --- fixtures -----------------------------------------------------------------------------------

fn sample_entity(name: &str) -> Entity {
    Entity::new(
        name,
        Nipc::unvalidated("500002020"),
        "Rua de Teste, Lisboa",
        EntityKind::SociedadePorQuotas,
    )
}

fn sample_extract(nipc: &str) -> RegistryExtract {
    RegistryExtract {
        matricula: Some("12345".to_string()),
        nipc: Some(nipc.to_string()),
        firma: Some("Firma de Teste, Lda".to_string()),
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

/// A small fake PDF/A-2u byte blob (not a real PDF — the store crate does not depend on the
/// document writer; it preserves whatever bytes it is handed).
const FAKE_PDF: &[u8] = b"%PDF-1.7\n%\xE2\xE3\xCF\xD3\nfake ata de Encosto Estrategico Lda\n%%EOF";

/// Build a [`StoredDocument`] for `act_id` with `bytes`, computing its hex sha-256 digest.
fn sample_document(id: &str, act_id: ActId, bytes: &[u8]) -> StoredDocument {
    StoredDocument {
        id: id.to_string(),
        act_id,
        template_id: "csc-ata-ag/v1".to_string(),
        pdf_digest: hex(&Sha256::digest(bytes)),
        profile: "csc/sq".to_string(),
        created_at: OffsetDateTime::from_unix_timestamp(1_770_000_000).unwrap(),
        pdf_bytes: bytes.to_vec(),
    }
}

/// Append an event to `ledger` and persist it (event-only), returning the appended event.
fn persist_event(store: &Store, ledger: &mut Ledger, scope: &str, kind: &str) -> Event {
    let event = ledger
        .append("amelia.marques", scope, kind, None, scope.as_bytes())
        .clone();
    store
        .persist(|tx| tx.append_event(&event))
        .expect("persist event");
    event
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// --- tests --------------------------------------------------------------------------------------

#[test]
fn open_creates_db_and_reopen_is_idempotent() {
    let dir = TempDir::new();
    {
        let store = Store::open(dir.path()).expect("open fresh");
        let loaded = store.load().expect("load fresh");
        assert!(loaded.entities.is_empty());
        assert!(loaded.books.is_empty());
        assert!(loaded.acts.is_empty());
        assert!(loaded.registry_extracts.is_empty());
        assert_eq!(loaded.chain_status, Ok(0));
        assert_eq!(loaded.ledger.len(), 0);
    }
    // The db file was created and reopening the same directory succeeds without wiping it.
    assert!(dir.path().join("chancela.db").exists());
    let reopened = Store::open(dir.path()).expect("reopen");
    assert_eq!(reopened.load().expect("reload").chain_status, Ok(0));
}

#[test]
fn persist_commits_event_and_aggregate_together() {
    let dir = TempDir::new();
    let store = Store::open(dir.path()).expect("open");
    let mut ledger = Ledger::new();
    let entity = sample_entity("Alfa, Lda");

    let event = ledger
        .append(
            "amelia.marques",
            "entity:alfa",
            "entity.created",
            None,
            b"alfa",
        )
        .clone();
    store
        .persist(|tx| {
            tx.append_event(&event)?;
            tx.upsert_entity(&entity)?;
            Ok(())
        })
        .expect("persist entity + event");

    let loaded = store.load().expect("load");
    assert_eq!(loaded.chain_status, Ok(1));
    assert_eq!(loaded.entities.get(&entity.id), Some(&entity));
}

#[test]
fn mid_closure_error_rolls_back_the_whole_transaction() {
    let dir = TempDir::new();
    let store = Store::open(dir.path()).expect("open");
    let mut ledger = Ledger::new();
    let entity = sample_entity("Beta, Lda");

    // The event is appended in-memory and the closure gets as far as upserting the aggregate, then
    // fails. Because the transaction rolls back on the `Err`, neither the event row nor the entity
    // row may survive.
    let event = ledger
        .append(
            "amelia.marques",
            "entity:beta",
            "entity.created",
            None,
            b"beta",
        )
        .clone();
    let result = store.persist(|tx| {
        tx.append_event(&event)?;
        tx.upsert_entity(&entity)?;
        Err(StoreError::NotPersistent)
    });
    assert!(matches!(result, Err(StoreError::NotPersistent)));

    let loaded = store.load().expect("load after rollback");
    assert_eq!(loaded.ledger.len(), 0, "event row must have rolled back");
    assert!(
        loaded.entities.is_empty(),
        "entity row must have rolled back"
    );
    assert_eq!(loaded.chain_status, Ok(0));

    // A subsequent good persist of seq 0 still works (the failed attempt left no phantom seq).
    store
        .persist(|tx| {
            tx.append_event(&event)?;
            tx.upsert_entity(&entity)?;
            Ok(())
        })
        .expect("retry persists cleanly");
    assert_eq!(store.load().expect("reload").chain_status, Ok(1));
}

#[test]
fn full_round_trip_survives_drop_and_reopen() {
    let dir = TempDir::new();
    let entity = sample_entity("Gama, Lda");
    let book = Book::new(entity.id, BookKind::AssembleiaGeral);
    let act = Act::draft(book.id, "Ata n.º 1", MeetingChannel::Physical);
    let extract = sample_extract("500002020");

    let mut expected_entities = HashMap::new();
    let mut expected_books = HashMap::new();
    let mut expected_acts = HashMap::new();
    let mut expected_extracts = HashMap::new();

    {
        let store = Store::open(dir.path()).expect("open");
        let mut ledger = Ledger::new();

        // Four mutations, each in its own transaction, each persisting its event + aggregate.
        let e0 = ledger
            .append(
                "amelia.marques",
                "entity:gama",
                "entity.created",
                None,
                b"gama",
            )
            .clone();
        store
            .persist(|tx| {
                tx.append_event(&e0)?;
                tx.upsert_entity(&entity)
            })
            .unwrap();
        expected_entities.insert(entity.id, entity.clone());

        let e1 = ledger
            .append("amelia.marques", "book:1", "book.opened", None, b"book")
            .clone();
        store
            .persist(|tx| {
                tx.append_event(&e1)?;
                tx.upsert_book(&book)
            })
            .unwrap();
        expected_books.insert(book.id, book.clone());

        let e2 = ledger
            .append("amelia.marques", "act:1", "act.drafted", None, b"act")
            .clone();
        store
            .persist(|tx| {
                tx.append_event(&e2)?;
                tx.upsert_act(&act)
            })
            .unwrap();
        expected_acts.insert(act.id, act.clone());

        let e3 = ledger
            .append(
                "amelia.marques",
                "entity:gama",
                "registry.imported",
                None,
                b"cert",
            )
            .clone();
        store
            .persist(|tx| {
                tx.append_event(&e3)?;
                tx.upsert_registry_extract(entity.id, &extract)
            })
            .unwrap();
        expected_extracts.insert(entity.id, extract.clone());
        // Store dropped here — the process "restarts".
    }

    let store = Store::open(dir.path()).expect("reopen");
    let loaded = store.load().expect("reload");
    assert_eq!(loaded.entities, expected_entities);
    assert_eq!(loaded.books, expected_books);
    assert_eq!(loaded.acts, expected_acts);
    assert_eq!(loaded.registry_extracts, expected_extracts);
    assert_eq!(loaded.chain_status, Ok(4));
    assert_eq!(loaded.ledger.len(), 4);
}

#[test]
fn upsert_replaces_the_previous_aggregate_row() {
    let dir = TempDir::new();
    let store = Store::open(dir.path()).expect("open");
    let mut ledger = Ledger::new();

    let mut entity = sample_entity("Delta, Lda");
    let e0 = ledger
        .append(
            "amelia.marques",
            "entity:delta",
            "entity.created",
            None,
            b"d",
        )
        .clone();
    store
        .persist(|tx| {
            tx.append_event(&e0)?;
            tx.upsert_entity(&entity)
        })
        .unwrap();

    // Rename the entity and upsert again under the same id — the row is replaced, not duplicated.
    entity.name = "Delta Renomeada, Lda".to_string();
    let e1 = ledger
        .append(
            "amelia.marques",
            "entity:delta",
            "entity.renamed",
            None,
            b"d2",
        )
        .clone();
    store
        .persist(|tx| {
            tx.append_event(&e1)?;
            tx.upsert_entity(&entity)
        })
        .unwrap();

    let loaded = store.load().expect("load");
    assert_eq!(loaded.entities.len(), 1);
    assert_eq!(loaded.entities.get(&entity.id), Some(&entity));
}

#[test]
fn tampering_with_an_event_row_is_detected_on_load() {
    let dir = TempDir::new();
    {
        let store = Store::open(dir.path()).expect("open");
        let mut ledger = Ledger::new();
        persist_event(&store, &mut ledger, "book:1", "book.opened");
        persist_event(&store, &mut ledger, "book:1", "act.sealed");
        assert_eq!(store.load().unwrap().chain_status, Ok(2));
    }

    // Flip a field of the seq-1 event row directly, leaving its stored `hash` stale. On reload the
    // recomputed hash no longer matches → HashMismatch at exactly that seq.
    {
        let raw = rusqlite::Connection::open(dir.path().join("chancela.db")).unwrap();
        let changed = raw
            .execute("UPDATE events SET actor = 'mallory' WHERE seq = 1", [])
            .unwrap();
        assert_eq!(changed, 1);
    }

    let store = Store::open(dir.path()).expect("reopen");
    let loaded = store
        .load()
        .expect("load still succeeds (never refuse to start)");
    assert_eq!(
        loaded.chain_status,
        Err(LedgerError::HashMismatch { seq: 1 })
    );
    // The events are still in hand so the operator can inspect them.
    assert_eq!(loaded.ledger.len(), 2);
}

#[test]
fn a_newer_schema_version_is_rejected() {
    let dir = TempDir::new();
    Store::open(dir.path()).expect("create at current schema");

    // Simulate a file written by a future build.
    {
        let raw = rusqlite::Connection::open(dir.path().join("chancela.db")).unwrap();
        raw.execute(
            "UPDATE meta SET value = '999' WHERE key = 'schema_version'",
            [],
        )
        .unwrap();
    }

    match Store::open(dir.path()) {
        Err(StoreError::UnsupportedSchemaVersion { found, supported }) => {
            assert_eq!(found, 999);
            assert_eq!(supported, chancela_store::schema::SCHEMA_VERSION);
        }
        other => panic!("expected UnsupportedSchemaVersion, got {other:?}"),
    }
}

#[test]
fn backup_bundles_a_verifiable_snapshot_and_sidecars() {
    let dir = TempDir::new();
    let store = Store::open(dir.path()).expect("open");
    let mut ledger = Ledger::new();
    let entity = sample_entity("Epsilon, Lda");

    let e0 = ledger
        .append(
            "amelia.marques",
            "entity:eps",
            "entity.created",
            None,
            b"eps",
        )
        .clone();
    store
        .persist(|tx| {
            tx.append_event(&e0)?;
            tx.upsert_entity(&entity)
        })
        .unwrap();
    persist_event(&store, &mut ledger, "book:1", "book.opened");

    // One real sidecar file, one sidecar directory (recursed), one missing path (skipped).
    let settings = dir.path().join("settings.json");
    std::fs::write(&settings, br#"{"default_actor":"amelia.marques"}"#).unwrap();
    let laws = dir.path().join("laws");
    std::fs::create_dir_all(&laws).unwrap();
    std::fs::write(laws.join("csc.pdf"), b"%PDF-1.7 fake").unwrap();
    let missing = dir.path().join("does-not-exist.json");

    let sidecars = vec![settings.clone(), laws.clone(), missing];
    let manifest = store.backup(dir.path(), &sidecars).expect("backup");

    // Archive is where the manifest says, with the reported size, and ledger metadata matches.
    let zip_path = Path::new(&manifest.path);
    assert!(zip_path.exists(), "zip archive must exist at manifest.path");
    assert_eq!(
        std::fs::metadata(zip_path).unwrap().len(),
        manifest.bytes,
        "manifest.bytes must equal the archive size"
    );
    assert_eq!(manifest.ledger_length, 2);
    assert!(manifest.ledger_verified);
    assert_eq!(
        manifest.store_schema_version,
        chancela_store::schema::SCHEMA_VERSION
    );
    assert!(manifest.ledger_head.is_some());

    // The manifest lists the db + both sidecar files (dir recursed), never the missing path.
    let names: Vec<&str> = manifest.files.iter().map(|f| f.name.as_str()).collect();
    assert!(names.contains(&"chancela.db"));
    assert!(names.contains(&"settings.json"));
    assert!(names.contains(&"laws/csc.pdf"));
    assert!(!names.iter().any(|n| n.contains("does-not-exist")));

    // Every manifest digest matches the actual archive member bytes.
    let file = std::fs::File::open(zip_path).unwrap();
    let mut archive = zip::ZipArchive::new(file).unwrap();
    for entry in &manifest.files {
        let mut member = archive.by_name(&entry.name).expect("member present");
        let mut bytes = Vec::new();
        member.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes.len() as u64, entry.bytes, "size for {}", entry.name);
        assert_eq!(
            hex(&Sha256::digest(&bytes)),
            entry.sha256,
            "digest for {}",
            entry.name
        );
    }

    // The embedded manifest.json is present for the restore path.
    assert!(archive.by_name("manifest.json").is_ok());

    // Extract the snapshot db into a clean data dir and prove a fresh Store opens + verifies it.
    let restore = TempDir::new();
    {
        let mut db_member = archive.by_name("chancela.db").unwrap();
        let mut db_bytes = Vec::new();
        db_member.read_to_end(&mut db_bytes).unwrap();
        std::fs::write(restore.path().join("chancela.db"), &db_bytes).unwrap();
    }
    let restored = Store::open(restore.path()).expect("open restored snapshot");
    let loaded = restored.load().expect("load restored");
    assert_eq!(loaded.chain_status, Ok(2));
    assert_eq!(loaded.entities.get(&entity.id), Some(&entity));
}

#[test]
fn backup_reflects_a_broken_chain_without_failing() {
    let dir = TempDir::new();
    {
        let store = Store::open(dir.path()).expect("open");
        let mut ledger = Ledger::new();
        persist_event(&store, &mut ledger, "book:1", "book.opened");
        persist_event(&store, &mut ledger, "book:1", "act.sealed");
    }
    // Corrupt seq 0 so the chain no longer verifies.
    {
        let raw = rusqlite::Connection::open(dir.path().join("chancela.db")).unwrap();
        raw.execute("UPDATE events SET actor = 'x' WHERE seq = 0", [])
            .unwrap();
    }

    let store = Store::open(dir.path()).expect("reopen");
    let manifest = store
        .backup(dir.path(), &[])
        .expect("backup still succeeds");
    assert!(
        !manifest.ledger_verified,
        "a broken chain reports unverified"
    );
    assert_eq!(manifest.ledger_length, 2);
}

// --- documents table (schema v2, t48-e4) --------------------------------------------------------

#[test]
fn schema_version_is_two() {
    // The documents table landed as schema v2; a fresh DB is stamped with it.
    assert_eq!(chancela_store::schema::SCHEMA_VERSION, 2);
    let dir = TempDir::new();
    Store::open(dir.path()).expect("open fresh");
    let raw = rusqlite::Connection::open(dir.path().join("chancela.db")).unwrap();
    let stamped: String = raw
        .query_row(
            "SELECT value FROM meta WHERE key = 'schema_version'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(stamped, "2");
}

#[test]
fn upsert_document_round_trips_bytes_and_metadata() {
    let dir = TempDir::new();
    let store = Store::open(dir.path()).expect("open");
    let mut ledger = Ledger::new();

    // Compose the write exactly as the seal transaction will: the act, its `act.sealed` event, the
    // `document.generated` event, and the document row all land in one durable commit.
    let entity = sample_entity("Encosto Estrategico Lda");
    let book = Book::new(entity.id, BookKind::AssembleiaGeral);
    let act = Act::draft(book.id, "Ata n.o 1", MeetingChannel::Physical);
    let doc = sample_document("doc-1", act.id, FAKE_PDF);

    let sealed = ledger
        .append("amelia.marques", "act:1", "act.sealed", None, b"act")
        .clone();
    let generated = ledger
        .append(
            "amelia.marques",
            "act:1",
            "document.generated",
            None,
            doc.pdf_digest.as_bytes(),
        )
        .clone();
    store
        .persist(|tx| {
            tx.append_event(&sealed)?;
            tx.append_event(&generated)?;
            tx.upsert_act(&act)?;
            tx.upsert_document(&doc)?;
            Ok(())
        })
        .expect("persist seal + document in one commit");

    // Read back by act id (the GET /v1/acts/{id}/document path) — bytes + metadata round-trip.
    let by_act = store
        .document_for_act(act.id)
        .expect("read by act")
        .expect("document present");
    assert_eq!(by_act, doc);
    assert_eq!(by_act.pdf_bytes, FAKE_PDF);
    assert_eq!(by_act.pdf_digest, hex(&Sha256::digest(FAKE_PDF)));
    assert_eq!(by_act.template_id, "csc-ata-ag/v1");

    // Read back by document id (the seal-response additive field path).
    let by_id = store
        .document_by_id("doc-1")
        .expect("read by id")
        .expect("document present");
    assert_eq!(by_id, doc);

    // Unknown lookups are a clean None (the api's 404-until-sealed).
    let other_act = Act::draft(book.id, "Ata n.o 2", MeetingChannel::Physical);
    assert!(store.document_for_act(other_act.id).unwrap().is_none());
    assert!(store.document_by_id("nope").unwrap().is_none());
}

#[test]
fn upsert_document_is_idempotent_on_id() {
    let dir = TempDir::new();
    let store = Store::open(dir.path()).expect("open");
    let act = Act::draft(
        Book::new(
            sample_entity("Encosto Estrategico Lda").id,
            BookKind::AssembleiaGeral,
        )
        .id,
        "Ata n.o 1",
        MeetingChannel::Physical,
    );

    let first = sample_document("doc-1", act.id, b"%PDF-1.7 first%%EOF");
    store
        .persist(|tx| tx.upsert_document(&first))
        .expect("first upsert");

    // Re-generate under the same document id: the row is replaced, not duplicated.
    let mut second = sample_document("doc-1", act.id, b"%PDF-1.7 regenerated%%EOF");
    second.template_id = "csc-ata-ag/v1".to_string();
    store
        .persist(|tx| tx.upsert_document(&second))
        .expect("idempotent re-upsert");

    let raw = rusqlite::Connection::open(dir.path().join("chancela.db")).unwrap();
    let count: i64 = raw
        .query_row(
            "SELECT COUNT(*) FROM documents WHERE act_id = ?1",
            [act.id.to_string()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 1, "same id replaces, never duplicates");
    let read = store.document_by_id("doc-1").unwrap().unwrap();
    assert_eq!(read, second);
}

#[test]
fn an_older_schema_version_upgrades_forward_cleanly() {
    let dir = TempDir::new();
    let entity = sample_entity("Encosto Estrategico Lda");

    // Land some real data at the current version, then simulate a database written by the old v1
    // build: roll the stamp back and drop the table v1 never had.
    {
        let store = Store::open(dir.path()).expect("open at v2");
        let mut ledger = Ledger::new();
        let e0 = ledger
            .append("amelia.marques", "entity:e", "entity.created", None, b"e")
            .clone();
        store
            .persist(|tx| {
                tx.append_event(&e0)?;
                tx.upsert_entity(&entity)
            })
            .unwrap();
    }
    {
        let raw = rusqlite::Connection::open(dir.path().join("chancela.db")).unwrap();
        raw.execute(
            "UPDATE meta SET value = '1' WHERE key = 'schema_version'",
            [],
        )
        .unwrap();
        raw.execute("DROP TABLE documents", []).unwrap();
    }

    // Reopening upgrades forward: the additive DDL recreates `documents`, the stamp advances to 2,
    // and the pre-existing entity row is untouched.
    let store = Store::open(dir.path()).expect("reopen upgrades v1 -> v2");
    {
        let raw = rusqlite::Connection::open(dir.path().join("chancela.db")).unwrap();
        let stamped: String = raw
            .query_row(
                "SELECT value FROM meta WHERE key = 'schema_version'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(stamped, "2", "stamp advanced forward");
    }
    let loaded = store.load().expect("load after upgrade");
    assert_eq!(loaded.entities.get(&entity.id), Some(&entity));

    // The recreated table is empty and usable.
    let act = Act::draft(
        Book::new(entity.id, BookKind::AssembleiaGeral).id,
        "Ata n.o 1",
        MeetingChannel::Physical,
    );
    assert!(store.document_for_act(act.id).unwrap().is_none());
    let doc = sample_document("doc-1", act.id, FAKE_PDF);
    store.persist(|tx| tx.upsert_document(&doc)).unwrap();
    assert_eq!(store.document_by_id("doc-1").unwrap().unwrap(), doc);
}

#[test]
fn a_document_survives_backup_and_restore() {
    let dir = TempDir::new();
    let store = Store::open(dir.path()).expect("open");
    let act = Act::draft(
        Book::new(
            sample_entity("Encosto Estrategico Lda").id,
            BookKind::AssembleiaGeral,
        )
        .id,
        "Ata n.o 1",
        MeetingChannel::Physical,
    );
    let doc = sample_document("doc-1", act.id, FAKE_PDF);
    store.persist(|tx| tx.upsert_document(&doc)).unwrap();

    // Whole-file VACUUM INTO snapshot carries the documents table along automatically.
    let manifest = store.backup(dir.path(), &[]).expect("backup");
    let restore = TempDir::new();
    {
        let file = std::fs::File::open(&manifest.path).unwrap();
        let mut archive = zip::ZipArchive::new(file).unwrap();
        let mut db_member = archive.by_name("chancela.db").unwrap();
        let mut db_bytes = Vec::new();
        db_member.read_to_end(&mut db_bytes).unwrap();
        std::fs::write(restore.path().join("chancela.db"), &db_bytes).unwrap();
    }
    let restored = Store::open(restore.path()).expect("open restored snapshot");
    let read = restored
        .document_for_act(act.id)
        .expect("read restored")
        .expect("document survived backup/restore");
    assert_eq!(read, doc);
    assert_eq!(read.pdf_bytes, FAKE_PDF);
}

#[test]
fn wal_mode_allows_a_concurrent_reader() {
    let dir = TempDir::new();
    let store = Store::open(dir.path()).expect("open");
    let mut ledger = Ledger::new();
    let entity = sample_entity("Zeta, Lda");
    let e0 = ledger
        .append(
            "amelia.marques",
            "entity:zeta",
            "entity.created",
            None,
            b"z",
        )
        .clone();
    store
        .persist(|tx| {
            tx.append_event(&e0)?;
            tx.upsert_entity(&entity)
        })
        .unwrap();

    // A second independent connection reads the committed rows while the Store is still open
    // (WAL lets a reader proceed without blocking on the writer connection).
    let reader = rusqlite::Connection::open(dir.path().join("chancela.db")).unwrap();
    let entity_count: i64 = reader
        .query_row("SELECT COUNT(*) FROM entities", [], |r| r.get(0))
        .unwrap();
    let event_count: i64 = reader
        .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
        .unwrap();
    assert_eq!(entity_count, 1);
    assert_eq!(event_count, 1);
}

// --- G1 (convening) + G2 (attendance) additive fields ride the acts json (t53-E2) --------------

/// Build an act populated with the G1 `convening` record and the G2 `attendees` list, so the
/// round-trip exercises every new nested type (channels, recipients, second call, weights, proxy).
fn populated_g1_g2_act(book_id: chancela_core::BookId) -> Act {
    // Split date/time built via the default `time` constructors (no `macros` feature needed here).
    let mar_10 = time::Date::from_calendar_date(2026, time::Month::March, 10).unwrap();
    let mar_30 = time::Date::from_calendar_date(2026, time::Month::March, 30).unwrap();
    let at_10_30 = time::Time::from_hms(10, 30, 0).unwrap();

    let mut act = Act::draft(
        book_id,
        "Ata n.o 1 (com convocatoria e presencas)",
        MeetingChannel::Physical,
    );
    act.convening = Some(Convening {
        convener: Some("Amélia Marques".to_string()),
        convener_capacity: Some(SignatoryCapacity::Chair),
        dispatch_date: Some(mar_10),
        antecedence_days: Some(15),
        channel: Some(DispatchChannel::RegisteredLetterAR),
        recipients: vec![ConveningRecipient {
            name: "Encosto Estratégico Lda".to_string(),
            channel: Some(DispatchChannel::Email),
            reference: Some("RR123456789PT".to_string()),
            dispatched_at: Some(mar_10),
        }],
        second_call: Some(SecondCall {
            date: Some(mar_30),
            time: Some(at_10_30),
            reduced_quorum: true,
        }),
    });
    act.attendees = vec![
        Attendee {
            name: "Amélia Marques".to_string(),
            quality: SignatoryCapacity::Member,
            presence: PresenceMode::InPerson,
            represented_by: None,
            weight: Some(AttendanceWeight::Capital(500_000)),
        },
        Attendee {
            name: "Encosto Estratégico Lda".to_string(),
            quality: SignatoryCapacity::CondoOwner,
            presence: PresenceMode::Represented,
            represented_by: Some("Amélia Marques".to_string()),
            weight: Some(AttendanceWeight::Permilage(250)),
        },
    ];
    act
}

/// The store persists acts as one opaque `json` column, so the additive G1/G2 fields ride inside
/// the same blob with no DDL and no `schema_version` bump. This drives the real durability path
/// (persist → drop → reopen → load) for both an act carrying the new fields and an old-shape act
/// that leaves them defaulted, asserting full round-trip equality for each — and confirms the
/// stamped schema version is unchanged (still v2) across the whole exercise.
#[test]
fn acts_carrying_convening_and_attendees_round_trip_through_the_store() {
    let dir = TempDir::new();
    let entity = sample_entity("Encosto Estratégico Lda");
    let book = Book::new(entity.id, BookKind::AssembleiaGeral);

    // (a) an act WITH the G1 convening record + the G2 attendance list populated,
    // (b) an act WITHOUT them — plain `draft()`, so `convening: None` / `attendees: []` (old shape).
    let full_act = populated_g1_g2_act(book.id);
    let bare_act = Act::draft(
        book.id,
        "Ata n.o 2 (sem convocatoria)",
        MeetingChannel::Physical,
    );
    // Precondition: the bare act really carries the additive defaults.
    assert_eq!(bare_act.convening, None);
    assert!(bare_act.attendees.is_empty());

    // No schema bump: the stamp is v2 before and after persisting acts carrying the new fields.
    let stamp = |path: &Path| -> String {
        let raw = rusqlite::Connection::open(path.join("chancela.db")).unwrap();
        raw.query_row(
            "SELECT value FROM meta WHERE key = 'schema_version'",
            [],
            |r| r.get(0),
        )
        .unwrap()
    };

    {
        let store = Store::open(dir.path()).expect("open");
        assert_eq!(stamp(dir.path()), "2", "fresh db stamped at v2");
        let mut ledger = Ledger::new();

        let e0 = ledger
            .append("amelia.marques", "book:1", "book.opened", None, b"book")
            .clone();
        store
            .persist(|tx| {
                tx.append_event(&e0)?;
                tx.upsert_book(&book)
            })
            .unwrap();

        let e1 = ledger
            .append("amelia.marques", "act:1", "act.drafted", None, b"full")
            .clone();
        store
            .persist(|tx| {
                tx.append_event(&e1)?;
                tx.upsert_act(&full_act)
            })
            .unwrap();

        let e2 = ledger
            .append("amelia.marques", "act:2", "act.drafted", None, b"bare")
            .clone();
        store
            .persist(|tx| {
                tx.append_event(&e2)?;
                tx.upsert_act(&bare_act)
            })
            .unwrap();
        // Store dropped here — the process "restarts". No migration ran; no DDL touched acts.
        assert_eq!(
            stamp(dir.path()),
            "2",
            "no schema bump after writing G1/G2 acts"
        );
    }

    // Reopen and reload: both acts survive byte-for-byte through the json column.
    let store = Store::open(dir.path()).expect("reopen");
    assert_eq!(
        stamp(dir.path()),
        "2",
        "reopen did not bump the schema version"
    );
    let loaded = store.load().expect("reload");

    let reloaded_full = loaded.acts.get(&full_act.id).expect("full act reloaded");
    assert_eq!(
        reloaded_full, &full_act,
        "G1/G2 fields survive the store's json round-trip"
    );
    // Spot-check the nested new datums explicitly (not just whole-struct equality).
    let convening = reloaded_full.convening.as_ref().expect("convening present");
    assert_eq!(convening.antecedence_days, Some(15));
    assert_eq!(convening.recipients.len(), 1);
    assert_eq!(
        convening.second_call.as_ref().map(|s| s.reduced_quorum),
        Some(true)
    );
    assert_eq!(reloaded_full.attendees.len(), 2);
    assert_eq!(
        reloaded_full.attendees[1].weight,
        Some(AttendanceWeight::Permilage(250))
    );
    assert_eq!(
        reloaded_full.attendees[1].represented_by.as_deref(),
        Some("Amélia Marques")
    );

    // The old-shape act round-trips too: the defaulted fields come back defaulted.
    let reloaded_bare = loaded.acts.get(&bare_act.id).expect("bare act reloaded");
    assert_eq!(
        reloaded_bare, &bare_act,
        "old-shape act round-trips (backward-compat)"
    );
    assert_eq!(reloaded_bare.convening, None);
    assert!(reloaded_bare.attendees.is_empty());
}
