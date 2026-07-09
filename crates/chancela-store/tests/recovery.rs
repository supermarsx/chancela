//! Integration tests for the t54-E2 recovery / portability / data-management plane.
//!
//! Coverage (the E2 build gate): export→import round-trip (Verified); a forged/tampered bundle →
//! Quarantined (never trusted); collision Refuse vs QuarantineCopy; whole-store restore
//! verifies-before-swap + rejects a bad archive; per-book + whole-instance start-over (old preserved,
//! new genesis, chained event); reset BackendDomain preserves the ledger + emits `data.wiped`; reset
//! BackendFactory blanks everything; export_first archives before clearing; **no secrets in any
//! export**; and the boot `IntegrityReport` surfacing a synthesized break.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use chancela_core::{Act, ActId, Book, BookKind, Entity, EntityKind, MeetingChannel, Nipc};
use chancela_ledger::{ChainId, Ledger};
use chancela_store::recovery::{CollisionPolicy, ImportVerdict, ResetScope, StartOverScope};
use chancela_store::{Store, StoreError, StoredDocument};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

// --- std-only tempdir ---------------------------------------------------------------------------

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
            "chancela-recovery-test-{}-{nanos}-{n}",
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

const FAKE_PDF: &[u8] = b"%PDF-1.7\n%\xE2\xE3\xCF\xD3\nfake ata de Encosto Estrategico Lda\n%%EOF";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn at() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_780_000_000).unwrap()
}

fn sample_entity() -> Entity {
    Entity::new(
        "Encosto Estrategico Lda",
        Nipc::unvalidated("500002020"),
        "Rua de Teste, Lisboa",
        EntityKind::SociedadePorQuotas,
    )
}

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

/// Seed one entity + one book with a valid book chain (`book.opened` genesis + one `act.sealed`),
/// an act, and a generated document. Returns the in-memory ledger and the domain aggregates.
fn seed(store: &Store) -> (Ledger, Entity, Book, Act) {
    let mut ledger = Ledger::new();
    let entity = sample_entity();
    let book = Book::new(entity.id, BookKind::AssembleiaGeral);
    let act = Act::draft(book.id, "Ata n.o 1", MeetingChannel::Physical);
    let doc = sample_document("doc-1", act.id, FAKE_PDF);

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
    store
        .persist(|tx| {
            tx.append_event(&e0)?;
            tx.upsert_entity(&entity)
        })
        .unwrap();

    let e1 = ledger
        .append("amelia.marques", &scope_book, "book.opened", None, b"open")
        .clone();
    store
        .persist(|tx| {
            tx.append_event(&e1)?;
            tx.upsert_book(&book)
        })
        .unwrap();

    let e2 = ledger
        .append("amelia.marques", &scope_book, "act.sealed", None, b"seal")
        .clone();
    store
        .persist(|tx| {
            tx.append_event(&e2)?;
            tx.upsert_act(&act)?;
            tx.upsert_document(&doc)
        })
        .unwrap();

    (ledger, entity, book, act)
}

/// Read one member's bytes out of a zip archive.
fn zip_member(archive_bytes: &[u8], name: &str) -> Option<Vec<u8>> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(archive_bytes)).ok()?;
    let mut f = archive.by_name(name).ok()?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).ok()?;
    Some(buf)
}

// --- tests --------------------------------------------------------------------------------------

#[test]
fn export_import_round_trip_is_verified() {
    let src_dir = TempDir::new();
    let src = Store::open(src_dir.path()).expect("open source");
    let (mut ledger, entity, book, _act) = seed(&src);

    let export = src
        .export_book(&mut ledger, book.id, src_dir.path(), "amelia.marques", at())
        .expect("export book");

    // The bundle is retained under exports/ and its manifest names the right ids + a verified chain.
    assert!(export.path.exists(), "bundle retained under exports/");
    assert!(export.path.starts_with(src_dir.path().join("exports")));
    assert_eq!(export.manifest.format, "chancela-book-bundle/v1");
    assert_eq!(export.manifest.book_id, book.id.to_string());
    assert_eq!(export.manifest.entity_id, entity.id.to_string());
    assert!(export.manifest.book_chain.verified);
    assert_eq!(
        export.manifest.book_chain.length, 2,
        "book.opened + act.sealed"
    );
    // A chained ledger.exported was appended.
    assert!(ledger.events().iter().any(|e| e.kind == "ledger.exported"));

    // Import into a FRESH instance → Verified, provenance recorded, isolated (not on the live spine).
    let dst_dir = TempDir::new();
    let dst = Store::open(dst_dir.path()).expect("open dest");
    let mut dst_ledger = Ledger::new();
    let outcome = dst
        .import_book(
            &mut dst_ledger,
            &export.path,
            CollisionPolicy::Refuse,
            "amelia.marques",
            at(),
        )
        .expect("import book");
    assert!(matches!(outcome.verdict, ImportVerdict::Verified));
    assert_eq!(outcome.book_id, book.id.to_string());
    assert!(!outcome.collided);
    assert_eq!(
        outcome.source_instance_id,
        export.manifest.source_instance_id
    );

    // The import is isolated: the live spine holds only the chained ledger.imported, NOT the foreign
    // book chain (which would have needed a re-hash to join this instance's global spine).
    assert!(
        dst_ledger
            .events()
            .iter()
            .any(|e| e.kind == "ledger.imported")
    );
    assert_eq!(
        dst.load().unwrap().books.len(),
        0,
        "not merged into live books"
    );
    let imports = dst.imported_books().expect("imported feed");
    assert_eq!(imports.len(), 1);
    assert!(matches!(imports[0].verdict, ImportVerdict::Verified));
    assert!(dst.imported_bundle(&outcome.import_id).unwrap().is_some());
}

#[test]
fn a_forged_bundle_is_quarantined_not_trusted() {
    // Seed, then corrupt the book chain in the store so the exported bundle carries a broken chain
    // whose member digests are self-consistent — verify_bundle_chain must catch it on import.
    let src_dir = TempDir::new();
    {
        let src = Store::open(src_dir.path()).expect("open");
        let _ = seed(&src);
    }
    {
        let raw = rusqlite::Connection::open(src_dir.path().join("chancela.db")).unwrap();
        // Flip the actor of the sealed act (seq 2) WITHOUT updating its stored hash → self-hash break.
        raw.execute("UPDATE events SET actor = 'mallory' WHERE seq = 2", [])
            .unwrap();
    }
    let src = Store::open(src_dir.path()).expect("reopen");
    let loaded = src.load().expect("load broken");
    let mut ledger = loaded.ledger;
    let book_id = loaded.books.keys().next().copied().expect("book present");

    let export = src
        .export_book(&mut ledger, book_id, src_dir.path(), "amelia.marques", at())
        .expect("export still succeeds on a broken chain");
    assert!(
        !export.manifest.book_chain.verified,
        "the manifest honestly reports the broken chain"
    );

    // Import into a fresh instance → Quarantined (never trusted), with the break located.
    let dst_dir = TempDir::new();
    let dst = Store::open(dst_dir.path()).expect("open dest");
    let mut dst_ledger = Ledger::new();
    let outcome = dst
        .import_book(
            &mut dst_ledger,
            &export.path,
            CollisionPolicy::Refuse,
            "amelia.marques",
            at(),
        )
        .expect("import records a quarantine (does not error)");
    match outcome.verdict {
        ImportVerdict::Quarantined { break_ } => {
            assert_eq!(break_.chain, ChainId::Book(book_id.to_string()));
        }
        ImportVerdict::Verified => panic!("a forged bundle must never be Verified"),
    }
    let imports = dst.imported_books().unwrap();
    assert_eq!(imports.len(), 1);
    assert!(matches!(
        imports[0].verdict,
        ImportVerdict::Quarantined { .. }
    ));
}

#[test]
fn a_tampered_member_is_quarantined() {
    // A bundle whose events.jsonl was altered after export (member digest no longer matches the
    // manifest) is caught by the verify-before-trust member-digest layer → Quarantined.
    let src_dir = TempDir::new();
    let src = Store::open(src_dir.path()).expect("open");
    let (mut ledger, _entity, book, _act) = seed(&src);
    let export = src
        .export_book(&mut ledger, book.id, src_dir.path(), "amelia.marques", at())
        .expect("export");

    // Rebuild the zip with a flipped byte in events.jsonl but the ORIGINAL manifest.json.
    let mut names_and_bytes: Vec<(String, Vec<u8>)> = Vec::new();
    {
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(&export.bytes)).unwrap();
        for i in 0..archive.len() {
            let mut f = archive.by_index(i).unwrap();
            let name = f.name().to_string();
            let mut buf = Vec::new();
            f.read_to_end(&mut buf).unwrap();
            if name == "events.jsonl" && !buf.is_empty() {
                buf[0] ^= 0xFF; // tamper
            }
            names_and_bytes.push((name, buf));
        }
    }
    let tampered_path = src_dir.path().join("tampered.zip");
    {
        let mut zip = zip::ZipWriter::new(std::fs::File::create(&tampered_path).unwrap());
        let opts = zip::write::SimpleFileOptions::default();
        for (name, bytes) in &names_and_bytes {
            zip.start_file(name.as_str(), opts).unwrap();
            zip.write_all(bytes).unwrap();
        }
        zip.finish().unwrap();
    }

    let dst_dir = TempDir::new();
    let dst = Store::open(dst_dir.path()).expect("open dest");
    let mut dst_ledger = Ledger::new();
    let outcome = dst
        .import_book(
            &mut dst_ledger,
            &tampered_path,
            CollisionPolicy::Refuse,
            "amelia.marques",
            at(),
        )
        .expect("import records a quarantine");
    assert!(matches!(outcome.verdict, ImportVerdict::Quarantined { .. }));
}

#[test]
fn collision_refuse_versus_quarantine_copy() {
    let dir = TempDir::new();
    let store = Store::open(dir.path()).expect("open");
    let (mut ledger, _entity, book, _act) = seed(&store);
    let export = store
        .export_book(&mut ledger, book.id, dir.path(), "amelia.marques", at())
        .expect("export");

    // Re-importing into the SAME store collides (the book id is live).
    let refused = store.import_book(
        &mut ledger,
        &export.path,
        CollisionPolicy::Refuse,
        "amelia.marques",
        at(),
    );
    assert!(
        matches!(refused, Err(StoreError::ImportCollision { .. })),
        "Refuse rejects a colliding import and imports nothing"
    );
    assert_eq!(store.imported_books().unwrap().len(), 0);

    // QuarantineCopy keeps an isolated read-only copy under the ORIGINAL ids, flagged collided.
    let copied = store
        .import_book(
            &mut ledger,
            &export.path,
            CollisionPolicy::QuarantineCopy,
            "amelia.marques",
            at(),
        )
        .expect("QuarantineCopy accepts the isolated copy");
    assert!(copied.collided);
    assert_eq!(copied.book_id, book.id.to_string(), "original id preserved");
    let imports = store.imported_books().unwrap();
    assert_eq!(imports.len(), 1);
    assert!(imports[0].collided);
}

#[test]
fn no_secrets_ever_enter_an_export_bundle() {
    let dir = TempDir::new();
    let store = Store::open(dir.path()).expect("open");
    let (mut ledger, _entity, book, _act) = seed(&store);

    // Plant secret-bearing sidecars in the data dir (as the real app would have).
    std::fs::write(
        dir.path().join("users.json"),
        br#"{"amelia.marques":{"password_hash":"SUPER_SECRET_HASH_ZZZ","recovery_hash":"RECOVERY_SECRET_ZZZ"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.path().join("attestation.key"),
        b"PRIVATE_ATTESTATION_KEY_ZZZ",
    )
    .unwrap();

    let export = store
        .export_book(&mut ledger, book.id, dir.path(), "amelia.marques", at())
        .expect("export");

    for needle in [
        b"SUPER_SECRET_HASH_ZZZ".as_slice(),
        b"RECOVERY_SECRET_ZZZ".as_slice(),
        b"PRIVATE_ATTESTATION_KEY_ZZZ".as_slice(),
        b"password_hash".as_slice(),
        b"recovery_hash".as_slice(),
    ] {
        assert!(
            !contains_subslice(&export.bytes, needle),
            "bundle must not contain secret material {:?}",
            String::from_utf8_lossy(needle)
        );
    }
    // Positive control: the bundle DOES carry the public entity name.
    assert!(contains_subslice(&export.bytes, b"Encosto Estrategico Lda"));
}

#[test]
fn whole_store_restore_verifies_before_swapping() {
    let dir = TempDir::new();
    let store = Store::open(dir.path()).expect("open");
    let (mut ledger, _entity, _book, _act) = seed(&store);

    // Take a good backup, then mutate the live store (a post-backup event).
    let backup = store.backup(dir.path(), &[]).expect("backup");
    let extra = ledger
        .append("amelia.marques", "settings", "settings.changed", None, b"x")
        .clone();
    store.persist(|tx| tx.append_event(&extra)).unwrap();
    assert_eq!(store.load().unwrap().ledger.len(), 4);

    // Restore rolls the store back to the backup snapshot and records a chained ledger.restored.
    let outcome = store
        .restore(
            &mut ledger,
            Path::new(&backup.path),
            dir.path(),
            "amelia.marques",
            at(),
        )
        .expect("restore a good backup");
    assert!(outcome.chain_verified);
    let reloaded = store.load().expect("reload after restore");
    assert!(reloaded.chain_status.is_ok());
    // 3 snapshot events + the appended ledger.restored; the post-backup settings.changed is gone.
    assert_eq!(reloaded.ledger.len(), 4);
    assert!(
        reloaded
            .ledger
            .events()
            .iter()
            .any(|e| e.kind == "ledger.restored")
    );
    assert!(
        !reloaded
            .ledger
            .events()
            .iter()
            .any(|e| e.kind == "settings.changed"),
        "the post-backup event is not in the restored snapshot"
    );
    // The caller's ledger was swapped to match.
    assert!(ledger.events().iter().any(|e| e.kind == "ledger.restored"));
}

#[test]
fn encrypted_backup_hides_zip_and_sqlite_and_restores_sidecars() {
    let dir = TempDir::new();
    let store = Store::open(dir.path()).expect("open");
    let (mut ledger, _entity, _book, _act) = seed(&store);

    let settings = dir.path().join("settings.json");
    let apikeys = dir.path().join("apikeys.json");
    let laws = dir.path().join("laws");
    std::fs::write(&settings, br#"{"restored":true}"#).unwrap();
    std::fs::write(&apikeys, br#"[{"prefix":"chk_restore"}]"#).unwrap();
    std::fs::create_dir_all(&laws).unwrap();
    std::fs::write(laws.join("csc.pdf"), b"%PDF restored law").unwrap();
    let sidecars = vec![settings.clone(), apikeys.clone(), laws.clone()];

    let backup = store
        .backup_encrypted(dir.path(), &sidecars, "correct horse battery staple")
        .expect("encrypted backup");
    assert!(backup.path.ends_with(".cbackup"), "encrypted extension");
    let encrypted_bytes = std::fs::read(&backup.path).unwrap();
    assert!(!contains_subslice(&encrypted_bytes, b"PK"));
    assert!(!contains_subslice(&encrypted_bytes, b"SQLite format 3"));
    assert!(
        !Path::new(&backup.path).with_extension("zip").exists(),
        "plaintext zip artifact is removed after wrapping"
    );

    let extra = ledger
        .append("amelia.marques", "settings", "settings.changed", None, b"x")
        .clone();
    store.persist(|tx| tx.append_event(&extra)).unwrap();
    std::fs::write(&settings, br#"{"restored":false}"#).unwrap();
    std::fs::write(&apikeys, br#"[{"prefix":"chk_live"}]"#).unwrap();
    std::fs::remove_dir_all(&laws).unwrap();
    std::fs::create_dir_all(&laws).unwrap();
    std::fs::write(laws.join("stale.pdf"), b"stale").unwrap();

    let outcome = store
        .restore_encrypted_with_sidecars(
            &mut ledger,
            Path::new(&backup.path),
            dir.path(),
            "amelia.marques",
            at(),
            "correct horse battery staple",
            &sidecars,
        )
        .expect("restore encrypted backup");
    assert!(outcome.chain_verified);
    let reloaded = store.load().unwrap();
    assert_eq!(
        reloaded.ledger.len(),
        4,
        "3 backed-up events + ledger.restored"
    );
    assert!(
        !reloaded
            .ledger
            .events()
            .iter()
            .any(|e| e.kind == "settings.changed"),
        "post-backup event is gone"
    );
    assert_eq!(std::fs::read(&settings).unwrap(), br#"{"restored":true}"#);
    assert_eq!(
        std::fs::read(&apikeys).unwrap(),
        br#"[{"prefix":"chk_restore"}]"#
    );
    assert_eq!(
        std::fs::read(laws.join("csc.pdf")).unwrap(),
        b"%PDF restored law"
    );
    assert!(!laws.join("stale.pdf").exists(), "stale sidecar removed");
}

#[test]
fn encrypted_restore_wrong_key_or_tamper_leaves_live_db_and_sidecars() {
    let dir = TempDir::new();
    let store = Store::open(dir.path()).expect("open");
    let (mut ledger, _entity, _book, _act) = seed(&store);
    let apikeys = dir.path().join("apikeys.json");
    std::fs::write(&apikeys, br#"[{"prefix":"chk_backup"}]"#).unwrap();
    let sidecars = vec![apikeys.clone()];
    let backup = store
        .backup_encrypted(dir.path(), &sidecars, "right passphrase")
        .expect("encrypted backup");

    let extra = ledger
        .append("amelia.marques", "settings", "settings.changed", None, b"x")
        .clone();
    store.persist(|tx| tx.append_event(&extra)).unwrap();
    std::fs::write(&apikeys, br#"[{"prefix":"chk_live"}]"#).unwrap();
    let live_len = store.load().unwrap().ledger.len();

    let wrong = store.restore_encrypted_with_sidecars(
        &mut ledger,
        Path::new(&backup.path),
        dir.path(),
        "amelia.marques",
        at(),
        "wrong passphrase",
        &sidecars,
    );
    assert!(matches!(wrong, Err(StoreError::BadBackup(_))));
    assert_eq!(store.load().unwrap().ledger.len(), live_len);
    assert_eq!(
        std::fs::read(&apikeys).unwrap(),
        br#"[{"prefix":"chk_live"}]"#
    );

    let mut tampered = std::fs::read(&backup.path).unwrap();
    let last = tampered
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .expect("non-empty envelope");
    tampered[last] ^= 1;
    let tampered_path = dir.path().join("tampered.cbackup");
    std::fs::write(&tampered_path, tampered).unwrap();
    let result = store.restore_encrypted_with_sidecars(
        &mut ledger,
        &tampered_path,
        dir.path(),
        "amelia.marques",
        at(),
        "right passphrase",
        &sidecars,
    );
    assert!(matches!(result, Err(StoreError::BadBackup(_))));
    assert_eq!(store.load().unwrap().ledger.len(), live_len);
    assert_eq!(
        std::fs::read(&apikeys).unwrap(),
        br#"[{"prefix":"chk_live"}]"#
    );
}

#[test]
fn restore_rejects_a_backup_whose_chain_does_not_verify() {
    let dir = TempDir::new();
    {
        let store = Store::open(dir.path()).expect("open");
        let _ = seed(&store);
    }
    // Corrupt the live chain, THEN back it up — the snapshot carries a broken ledger.
    {
        let raw = rusqlite::Connection::open(dir.path().join("chancela.db")).unwrap();
        raw.execute("UPDATE events SET actor = 'x' WHERE seq = 0", [])
            .unwrap();
    }
    let store = Store::open(dir.path()).expect("reopen");
    let mut ledger = store.load().unwrap().ledger;
    let bad_backup = store
        .backup(dir.path(), &[])
        .expect("backup a broken chain");
    assert!(!bad_backup.ledger_verified);

    // Verify-before-swap refuses it; the live store is untouched.
    let result = store.restore(
        &mut ledger,
        Path::new(&bad_backup.path),
        dir.path(),
        "amelia.marques",
        at(),
    );
    assert!(
        matches!(result, Err(StoreError::BadBackup(_))),
        "a backup whose snapshot ledger does not verify must be refused, got {result:?}"
    );
}

#[test]
fn per_book_start_over_archives_and_opens_a_fresh_successor() {
    let dir = TempDir::new();
    let store = Store::open(dir.path()).expect("open");
    let (mut ledger, _entity, book, _act) = seed(&store);
    let old_len = ledger.len();

    let outcome = store
        .start_over_book(
            &mut ledger,
            book.id,
            "livro corrompido; recomecar",
            "amelia.marques",
            at(),
            dir.path(),
        )
        .expect("per-book start-over");

    assert_eq!(outcome.scope, StartOverScope::Book);
    assert!(outcome.archive_path.exists(), "the old book was archived");
    assert_eq!(outcome.old_book_id, Some(book.id.to_string()));
    let new_book_id = outcome.new_book_id.expect("a fresh successor book id");
    assert_ne!(new_book_id, book.id.to_string());

    let loaded = store.load().expect("reload");
    // Nothing erased: the old book + its chain remain; a fresh successor shell was added.
    assert!(loaded.books.contains_key(&book.id), "old book preserved");
    assert!(
        loaded.books.keys().any(|b| b.to_string() == new_book_id),
        "successor book present"
    );
    // Chained ledger.exported (archive) + ledger.reinitialized (start-over) were appended.
    assert!(
        loaded
            .ledger
            .events()
            .iter()
            .any(|e| e.kind == "ledger.reinitialized")
    );
    assert!(loaded.ledger.len() > old_len);
    assert!(loaded.chain_status.is_ok(), "chain stays intact");
}

#[test]
fn whole_instance_start_over_archives_then_starts_a_fresh_genesis() {
    let dir = TempDir::new();
    let store = Store::open(dir.path()).expect("open");
    let (mut ledger, _entity, _book, _act) = seed(&store);

    let outcome = store
        .start_over_instance(
            &mut ledger,
            "recomecar instancia",
            "amelia.marques",
            at(),
            dir.path(),
            &[],
        )
        .expect("whole-instance start-over");
    assert_eq!(outcome.scope, StartOverScope::Instance);
    assert!(outcome.archive_path.exists(), "whole instance archived");

    let loaded = store.load().expect("reload");
    // A fresh instance: no domain data, and the ledger's genesis IS the reinitialization.
    assert!(loaded.entities.is_empty());
    assert!(loaded.books.is_empty());
    assert_eq!(
        loaded.ledger.len(),
        1,
        "fresh ledger with one genesis event"
    );
    assert_eq!(loaded.ledger.events()[0].kind, "ledger.reinitialized");
    assert!(loaded.chain_status.is_ok());
    assert!(
        ledger
            .events()
            .iter()
            .any(|e| e.kind == "ledger.reinitialized")
    );
}

#[test]
fn reset_backend_domain_preserves_the_ledger_and_emits_data_wiped() {
    let dir = TempDir::new();
    let store = Store::open(dir.path()).expect("open");
    let (mut ledger, _entity, _book, _act) = seed(&store);
    let events_before = ledger.len();

    let outcome = store
        .reset(
            &mut ledger,
            dir.path(),
            ResetScope::BackendDomain,
            false,
            &[],
            "amelia.marques",
            at(),
        )
        .expect("domain wipe");
    assert_eq!(outcome.scope, ResetScope::BackendDomain);
    assert!(
        outcome.export_archive.is_none(),
        "no export_first requested"
    );

    let loaded = store.load().expect("reload");
    // Domain data cleared; the ledger PRESERVED and grown by exactly one data.wiped event.
    assert!(loaded.entities.is_empty());
    assert!(loaded.books.is_empty());
    assert!(loaded.acts.is_empty());
    assert_eq!(loaded.ledger.len(), events_before + 1);
    assert!(
        loaded
            .ledger
            .events()
            .iter()
            .any(|e| e.kind == "data.wiped")
    );
    assert!(
        loaded.chain_status.is_ok(),
        "preserved ledger still verifies"
    );
}

#[test]
fn reset_backend_factory_blanks_everything() {
    let dir = TempDir::new();
    let store = Store::open(dir.path()).expect("open");
    let (mut ledger, _entity, _book, _act) = seed(&store);

    // A sidecar the factory reset should remove.
    let users = dir.path().join("users.json");
    std::fs::write(&users, b"{\"amelia.marques\":{}}").unwrap();

    let outcome = store
        .reset(
            &mut ledger,
            dir.path(),
            ResetScope::BackendFactory,
            false,
            std::slice::from_ref(&users),
            "amelia.marques",
            at(),
        )
        .expect("factory reset");
    assert_eq!(outcome.scope, ResetScope::BackendFactory);

    let loaded = store.load().expect("reload");
    assert!(loaded.entities.is_empty());
    assert!(loaded.books.is_empty());
    assert_eq!(loaded.ledger.len(), 0, "the ledger itself is blanked");
    assert!(ledger.is_empty(), "caller ledger blanked to first-run");
    assert!(!users.exists(), "the users.json sidecar was removed");
    assert!(outcome.cleared.iter().any(|c| c == "events"));
    assert!(outcome.cleared.iter().any(|c| c == "users.json"));
}

#[test]
fn export_first_archives_before_a_destructive_wipe() {
    let dir = TempDir::new();
    let store = Store::open(dir.path()).expect("open");
    let (mut ledger, entity, _book, _act) = seed(&store);

    let outcome = store
        .reset(
            &mut ledger,
            dir.path(),
            ResetScope::BackendDomain,
            true, // export-first MANDATORY archive
            &[],
            "amelia.marques",
            at(),
        )
        .expect("wipe with export-first");

    let archive = outcome
        .export_archive
        .expect("export-first archive present");
    assert!(archive.exists(), "the archive was written before clearing");

    // The archive captured the pre-wipe state (its db member still holds the entity row).
    let archive_bytes = std::fs::read(&archive).unwrap();
    let db_bytes = zip_member(&archive_bytes, "chancela.db").expect("db member");
    let restore_dir = TempDir::new();
    std::fs::write(restore_dir.path().join("chancela.db"), &db_bytes).unwrap();
    let snapshot = Store::open(restore_dir.path()).expect("open archived snapshot");
    assert!(
        snapshot.load().unwrap().entities.contains_key(&entity.id),
        "the pre-wipe entity survives in the export-first archive"
    );
    // And the live store really was cleared afterwards.
    assert!(store.load().unwrap().entities.is_empty());
}

#[test]
fn integrity_report_surfaces_a_synthesized_break_on_load() {
    let dir = TempDir::new();
    {
        let store = Store::open(dir.path()).expect("open");
        let _ = seed(&store);
        assert!(
            store.load().unwrap().integrity.healthy,
            "seeded chain is healthy"
        );
    }
    // Corrupt a mid-chain event row.
    {
        let raw = rusqlite::Connection::open(dir.path().join("chancela.db")).unwrap();
        raw.execute("UPDATE events SET actor = 'mallory' WHERE seq = 1", [])
            .unwrap();
    }
    let store = Store::open(dir.path()).expect("reopen");
    let loaded = store
        .load()
        .expect("load still succeeds — never refuse to start");
    assert!(
        !loaded.integrity.healthy,
        "the break is surfaced, not hidden"
    );
    assert!(loaded.chain_status.is_err());
    let has_break = loaded.integrity.global.first_break.is_some()
        || loaded
            .integrity
            .chains
            .iter()
            .any(|c| c.first_break.is_some());
    assert!(has_break, "the exact break location is exposed for the api");

    // The convenience getter returns the same picture.
    assert!(!store.integrity_report().unwrap().healthy);
}

/// Naive subslice search (no extra dev-deps).
fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}
