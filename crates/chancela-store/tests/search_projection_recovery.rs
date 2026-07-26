use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};

use chancela_ledger::Ledger;
use chancela_search::{
    IndexOperation as SearchIndexOperation, SearchDocument, SearchIndexPhase, SearchIndexState,
    SearchKind,
};
use chancela_store::{BackupFile, BackupManifest, DB_FILE, Store};
#[cfg(feature = "sqlcipher")]
use chancela_store::{StoreError, StoreOpenOptions};
use rusqlite::params;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let serial = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "chancela-search-recovery-{label}-{}-{serial}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create temp directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn search_document(id: &str, sentinel: &str) -> SearchDocument {
    SearchDocument {
        id: id.to_owned(),
        kind: SearchKind::Act,
        tenant_id: Some("tenant-recovery-test".to_owned()),
        entity_id: Some("entity-recovery-test".to_owned()),
        entity_name: Some("Entidade Recovery".to_owned()),
        book_id: Some("book-recovery-test".to_owned()),
        book_label: Some("Livro Recovery".to_owned()),
        act_id: Some("act-recovery-test".to_owned()),
        title: format!("Ata {sentinel}"),
        body: format!("Derived full-search body {sentinel}"),
        content_truncated: false,
        author: Some("recovery-test".to_owned()),
        law: None,
        status: Some("draft".to_owned()),
        required_permission: None,
        occurred_at: Some("2026-07-26T12:00:00Z".to_owned()),
        source_version: "test-v1".to_owned(),
        privileged: None,
    }
}

fn completed_state() -> SearchIndexState {
    SearchIndexState {
        phase: SearchIndexPhase::Idle,
        generation: 41,
        document_count: 1,
        processed: 1,
        total: 1,
        last_completed_at: Some("2026-07-26T12:00:00Z".to_owned()),
        updated_at: "2026-07-26T12:00:00Z".to_owned(),
        ..SearchIndexState::default()
    }
}

fn seed_projection(store: &Store, id: &str, sentinel: &str) {
    store
        .apply_search_index_batch(
            &[SearchIndexOperation::Upsert(Box::new(search_document(
                id, sentinel,
            )))],
            &completed_state(),
        )
        .expect("seed derived search projection");
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack.len() >= needle.len()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn zip_member(path: &Path, name: &str) -> Vec<u8> {
    let file = std::fs::File::open(path).expect("open backup");
    let mut archive = zip::ZipArchive::new(file).expect("read backup zip");
    let mut member = archive.by_name(name).expect("backup member");
    let mut bytes = Vec::new();
    member.read_to_end(&mut bytes).expect("read backup member");
    bytes
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Clone, Copy)]
enum DeleteFailure {
    Never,
    FirstSearchStateDelete,
    SecondSearchStateDelete,
}

/// Build the legacy SQLite backup shape that predates derived-projection sanitization. This lets
/// the restore tests prove that importing an old archive is fenced before its DB reaches the live
/// swap boundary.
fn legacy_backup_with_projection(
    dir: &TempDir,
    sentinel: &str,
    delete_failure: DeleteFailure,
) -> PathBuf {
    let store = Store::open(dir.path()).expect("open legacy source");
    seed_projection(&store, "act:legacy-projection", sentinel);
    drop(store);

    let source_db = dir.path().join(DB_FILE);
    let snapshot = dir.path().join("legacy-snapshot.db");
    let raw = rusqlite::Connection::open(&source_db).expect("open legacy source directly");
    if !matches!(delete_failure, DeleteFailure::Never) {
        let fail_at = match delete_failure {
            DeleteFailure::Never => unreachable!(),
            DeleteFailure::FirstSearchStateDelete => 1,
            DeleteFailure::SecondSearchStateDelete => 2,
        };
        raw.execute_batch(&format!(
            "CREATE TABLE search_delete_faults (delete_count INTEGER NOT NULL);
             INSERT INTO search_delete_faults (delete_count) VALUES (0);
             CREATE TRIGGER refuse_search_projection_delete
             BEFORE DELETE ON search_index_state
             BEGIN
                 UPDATE search_delete_faults SET delete_count = delete_count + 1;
                 SELECT CASE WHEN (SELECT delete_count FROM search_delete_faults) >= {fail_at}
                     THEN RAISE(ABORT, 'injected search projection delete failure')
                 END;
             END;"
        ))
        .expect("install injected failure trigger");
    }
    raw.execute(
        "VACUUM INTO ?1",
        params![snapshot.to_string_lossy().as_ref()],
    )
    .expect("snapshot legacy source");
    drop(raw);

    let db_bytes = std::fs::read(&snapshot).expect("read legacy snapshot");
    assert!(
        contains_subslice(&db_bytes, sentinel.as_bytes()),
        "legacy fixture must positively contain its unique projection sentinel"
    );
    let manifest = BackupManifest {
        path: "legacy-search-projection.zip".to_owned(),
        bytes: 0,
        created_at: OffsetDateTime::from_unix_timestamp(1_780_000_000).unwrap(),
        app_version: "legacy-test".to_owned(),
        store_schema_version: chancela_store::schema::SCHEMA_VERSION,
        ledger_length: 0,
        ledger_head: None,
        ledger_verified: true,
        files: vec![BackupFile {
            name: DB_FILE.to_owned(),
            sha256: hex(&Sha256::digest(&db_bytes)),
            bytes: db_bytes.len() as u64,
        }],
    };
    let archive_path = dir.path().join("legacy-search-projection.zip");
    let file = std::fs::File::create(&archive_path).expect("create legacy archive");
    let mut zip = zip::ZipWriter::new(file);
    let options = zip::write::SimpleFileOptions::default();
    zip.start_file(DB_FILE, options).expect("start db member");
    zip.write_all(&db_bytes).expect("write db member");
    zip.start_file("manifest.json", options)
        .expect("start manifest member");
    zip.write_all(
        serde_json::to_string_pretty(&manifest)
            .expect("serialize manifest")
            .as_bytes(),
    )
    .expect("write manifest");
    zip.finish().expect("finish legacy archive");
    archive_path
}

fn assert_fenced_tombstone(store: &Store) {
    assert!(
        store.search_documents().unwrap().is_empty(),
        "derived search documents must be absent"
    );
    let state = store
        .search_index_state()
        .unwrap()
        .expect("search tombstone is durable");
    assert_eq!(state.phase, SearchIndexPhase::Starting);
    assert!(state.projection_fenced);
    assert_eq!(state.document_count, 0);
    assert_eq!(state.generation, 0);
}

#[test]
fn sqlite_backup_archives_only_a_compacted_search_tombstone() {
    const SENTINEL: &str = "UNIQUE_BACKUP_SEARCH_SENTINEL_7A8E5B19";
    let source = TempDir::new("backup-source");
    let store = Store::open(source.path()).expect("open source");
    seed_projection(&store, "act:backup-projection", SENTINEL);

    let backup = store.backup(source.path(), &[]).expect("create backup");
    assert_eq!(
        store.search_documents().unwrap().len(),
        1,
        "backup sanitization must not mutate the live projection"
    );

    let archived_db = zip_member(Path::new(&backup.path), DB_FILE);
    assert!(
        !contains_subslice(&archived_db, SENTINEL.as_bytes()),
        "the second VACUUM must remove sentinel bytes from SQLite free pages"
    );
    let extracted = TempDir::new("backup-extracted");
    std::fs::write(extracted.path().join(DB_FILE), &archived_db).unwrap();
    let archived_store = Store::open(extracted.path()).expect("open archived database");
    assert_fenced_tombstone(&archived_store);
}

#[test]
fn concurrent_sqlite_backups_use_disjoint_staging_and_archive_names() {
    let source = TempDir::new("concurrent-backups");
    let store = Store::open(source.path()).expect("open source");
    seed_projection(
        &store,
        "act:concurrent-projection",
        "UNIQUE_CONCURRENT_BACKUP_SENTINEL_7DB12E94",
    );
    let barrier = Arc::new(Barrier::new(3));
    let mut workers = Vec::new();
    for _ in 0..2 {
        let worker_store = store.clone();
        let worker_dir = source.path().to_path_buf();
        let worker_barrier = Arc::clone(&barrier);
        workers.push(std::thread::spawn(move || {
            worker_barrier.wait();
            worker_store
                .backup(&worker_dir, &[])
                .expect("concurrent backup")
        }));
    }
    barrier.wait();
    let manifests: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().expect("backup worker joined"))
        .collect();

    assert_ne!(
        manifests[0].path, manifests[1].path,
        "a per-run nonce must keep same-second archives distinct"
    );
    for manifest in &manifests {
        assert!(
            Path::new(&manifest.path).is_file(),
            "neither concurrent backup may remove the other's archive"
        );
    }
    let staging_residue: Vec<_> = std::fs::read_dir(source.path().join("backups"))
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with(".snapshot-")
        })
        .collect();
    assert!(
        staging_residue.is_empty(),
        "each per-run staging cleanup removes only its own snapshots"
    );
}

#[test]
fn sqlite_restore_sanitizes_a_legacy_projection_before_swapping() {
    const SENTINEL: &str = "UNIQUE_LEGACY_RESTORE_SENTINEL_13D4C86A";
    let legacy = TempDir::new("legacy-success");
    let archive = legacy_backup_with_projection(&legacy, SENTINEL, DeleteFailure::Never);
    let live = TempDir::new("restore-live");
    let store = Store::open(live.path()).expect("open live store");
    let mut ledger = Ledger::new();

    store
        .restore(
            &mut ledger,
            &archive,
            live.path(),
            "restore-test",
            OffsetDateTime::from_unix_timestamp(1_780_000_001).unwrap(),
        )
        .expect("restore legacy archive");

    assert_fenced_tombstone(&store);
    let live_db = std::fs::read(live.path().join(DB_FILE)).expect("read restored live database");
    assert!(
        !contains_subslice(&live_db, SENTINEL.as_bytes()),
        "the staged candidate must be compacted before its bytes reach the live path"
    );
}

#[test]
fn sqlite_restore_sanitization_failure_happens_before_the_live_swap() {
    const ARCHIVE_SENTINEL: &str = "UNIQUE_INJECTED_ARCHIVE_SENTINEL_C5690F42";
    const LIVE_SENTINEL: &str = "UNIQUE_LIVE_PROJECTION_SENTINEL_9164F0AE";
    let legacy = TempDir::new("legacy-failure");
    let archive = legacy_backup_with_projection(
        &legacy,
        ARCHIVE_SENTINEL,
        DeleteFailure::FirstSearchStateDelete,
    );
    let live = TempDir::new("failure-live");
    let store = Store::open(live.path()).expect("open live store");
    seed_projection(&store, "act:live-projection", LIVE_SENTINEL);
    let mut ledger = Ledger::new();

    let error = store
        .restore(
            &mut ledger,
            &archive,
            live.path(),
            "restore-test",
            OffsetDateTime::from_unix_timestamp(1_780_000_002).unwrap(),
        )
        .expect_err("injected staged sanitization failure must abort restore");
    assert!(
        error
            .to_string()
            .contains("injected search projection delete failure"),
        "surface the pre-swap staging failure: {error}"
    );
    let live_documents = store
        .search_documents()
        .expect("read untouched live search");
    assert_eq!(live_documents.len(), 1);
    assert!(
        live_documents[0].body.contains(LIVE_SENTINEL),
        "the live DB must remain the pre-restore database"
    );
    assert_eq!(store.search_index_state().unwrap(), Some(completed_state()));
    assert!(ledger.is_empty(), "no restore event is appended on refusal");
    let restore_residue: Vec<_> = std::fs::read_dir(live.path())
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with(".restore-verify-")
        })
        .collect();
    assert!(
        restore_residue.is_empty(),
        "the armed staging cleanup must remove legacy-text candidates on failure"
    );
}

#[test]
fn sqlite_restore_never_runs_a_second_fallible_search_purge_after_swap() {
    const SENTINEL: &str = "UNIQUE_POST_SWAP_GUARD_SENTINEL_A52D0C71";
    let legacy = TempDir::new("legacy-second-delete");
    let archive =
        legacy_backup_with_projection(&legacy, SENTINEL, DeleteFailure::SecondSearchStateDelete);
    let live = TempDir::new("second-delete-live");
    let store = Store::open(live.path()).expect("open live store");
    let mut ledger = Ledger::new();

    store
        .restore(
            &mut ledger,
            &archive,
            live.path(),
            "restore-test",
            OffsetDateTime::from_unix_timestamp(1_780_000_003).unwrap(),
        )
        .expect("restore must finish after the single pre-swap search purge");

    assert_fenced_tombstone(&store);
    let raw = rusqlite::Connection::open(live.path().join(DB_FILE)).expect("open restored db");
    let delete_count: i64 = raw
        .query_row("SELECT delete_count FROM search_delete_faults", [], |row| {
            row.get(0)
        })
        .expect("read injected purge counter");
    assert_eq!(
        delete_count, 1,
        "derived sanitization runs exactly once in staging, never again after the swap"
    );
}

#[cfg(feature = "sqlcipher")]
#[test]
fn sqlcipher_backup_and_restore_reuse_the_current_key_and_keep_the_archive_encrypted() {
    const SENTINEL: &str = "UNIQUE_SQLCIPHER_SEARCH_SENTINEL_6F38B1D2";
    const OLD_KEY: &str = "sqlite-recovery-old-test-key";
    const CURRENT_KEY: &str = "sqlite-recovery-current-test-key";
    let source = TempDir::new("sqlcipher-source");
    let old_options = StoreOpenOptions::new().with_encryption_key(OLD_KEY);
    let current_options = StoreOpenOptions::new().with_encryption_key(CURRENT_KEY);
    let store =
        Store::open_with_options(source.path(), old_options.clone()).expect("open keyed source");
    assert!(
        !format!("{store:?}").contains(OLD_KEY),
        "retained SQLite options must keep key material redacted"
    );
    seed_projection(&store, "act:sqlcipher-projection", SENTINEL);
    store
        .rotate_encryption_key(CURRENT_KEY)
        .expect("rotate the live SQLCipher key");

    let backup = store
        .backup(source.path(), &[])
        .expect("backup keyed store");
    let preflight = store
        .restore_preflight(Path::new(&backup.path), source.path(), None)
        .expect("preflight keyed archive");
    assert!(preflight.ready);
    assert_eq!(
        preflight
            .isolated_restore
            .as_ref()
            .and_then(|evidence| evidence.sqlcipher_encryption_verified),
        Some(true),
        "preflight must reuse the retained key and positively prove encrypted material"
    );
    let archived_db = zip_member(Path::new(&backup.path), DB_FILE);
    assert!(
        !archived_db.starts_with(b"SQLite format 3"),
        "the sanitized database member must retain SQLCipher at-rest encryption"
    );

    let extracted = TempDir::new("sqlcipher-extracted");
    std::fs::write(extracted.path().join(DB_FILE), &archived_db).unwrap();
    let archived_store = Store::open_with_options(extracted.path(), current_options.clone())
        .expect("the current key opens the archived database");
    assert_fenced_tombstone(&archived_store);
    drop(archived_store);
    assert!(
        matches!(
            Store::open_with_options(extracted.path(), old_options),
            Err(StoreError::EncryptionKeyRejected { .. })
        ),
        "the pre-rotation key must not open the archived database"
    );
    assert!(
        Store::open(extracted.path()).is_err(),
        "an encrypted archive database must fail closed without a key"
    );

    // Restore through the same handle that performed the rekey. This specifically proves that the
    // retained options were advanced to the current key before staged verification/live reopen.
    let mut ledger = Ledger::new();
    store
        .restore(
            &mut ledger,
            Path::new(&backup.path),
            source.path(),
            "sqlcipher-restore-test",
            OffsetDateTime::from_unix_timestamp(1_780_000_004).unwrap(),
        )
        .expect("restore keyed archive through rekeyed handle");
    assert_fenced_tombstone(&store);
    assert!(
        !std::fs::read(source.path().join(DB_FILE))
            .unwrap()
            .starts_with(b"SQLite format 3"),
        "the restored live database must remain SQLCipher-encrypted"
    );
    drop(store);

    let reopened = Store::open_with_options(source.path(), current_options)
        .expect("current key reopens restored live database");
    assert_fenced_tombstone(&reopened);
}
