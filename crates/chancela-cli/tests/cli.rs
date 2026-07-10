//! Integration tests for the `chancela` CLI, driving the built binary over temp data dirs.
//!
//! Each test seeds a store with the store/ledger/core primitives, runs `chancela` as a child
//! process (with `--data-dir` and a null stdin, so destructive commands are refused unless `--yes`),
//! then re-opens the store to assert the effect. Example data uses the fictional
//! "Encosto Estratégico Lda" / "amelia.marques" — never real names.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use chancela_api::{DB_KEY_ENV, DB_KEY_FILE_ENV, User};
use chancela_authz::OWNER_ROLE_ID;
use chancela_core::{Book, BookKind, Entity, EntityKind, Nipc};
use chancela_store::{DB_FILE, Store};

/// A throwaway data directory unique to one test.
fn tmp_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("chancela-cli-test-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Run the `chancela` binary against `dir`. stdin is null (so destructive commands without `--yes`
/// are refused), and ambient data-dir / database-key env vars are cleared.
fn cli(dir: &Path, args: &[&str]) -> Output {
    cli_with_env(dir, args, &[])
}

/// Run the CLI with explicit extra env vars after clearing ambient durable-store env.
fn cli_with_env(dir: &Path, args: &[&str], envs: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_chancela"));
    cmd.arg("--data-dir")
        .arg(dir)
        .args(args)
        .stdin(Stdio::null())
        .env_remove("CHANCELA_DATA_DIR")
        .env_remove(DB_KEY_ENV)
        .env_remove(DB_KEY_FILE_ENV);
    for (key, value) in envs {
        cmd.env(key, value);
    }
    cmd.output().expect("failed to run chancela binary")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// Seed a store with an entity + book and a valid two-event chain (entity.created → book.opened),
/// returning the book id (as its uuid string). The chain verifies cleanly.
fn seed(dir: &Path) -> String {
    let store = Store::open(dir).unwrap();
    let mut ledger = store.load().unwrap().ledger;

    let entity = Entity::new(
        "Encosto Estratégico Lda",
        Nipc::parse("503004642").unwrap(),
        "Lisboa",
        EntityKind::SociedadePorQuotas,
    );
    let eid = entity.id;
    let book = Book::new(eid, BookKind::AssembleiaGeral);
    let bid = book.id;

    // Company-chain genesis must be entity.created; the book-chain genesis must be book.opened.
    let e1 = ledger
        .append(
            "cli",
            &eid.to_string(),
            "entity.created",
            Some("seed"),
            b"seed",
        )
        .clone();
    let scope = format!("entity:{eid}/book:{bid}");
    let e2 = ledger
        .append("cli", &scope, "book.opened", Some("seed"), b"seed")
        .clone();

    store
        .persist(|tx| {
            tx.upsert_entity(&entity)?;
            tx.upsert_book(&book)?;
            tx.append_event(&e1)?;
            tx.append_event(&e2)?;
            Ok(())
        })
        .unwrap();
    bid.to_string()
}

fn counts(dir: &Path) -> (usize, usize, usize, usize) {
    let store = Store::open(dir).unwrap();
    let loaded = store.load().unwrap();
    (
        loaded.entities.len(),
        loaded.books.len(),
        loaded.acts.len(),
        loaded.ledger.len(),
    )
}

#[test]
fn status_on_fresh_store() {
    let dir = tmp_dir();
    let out = cli(&dir, &["status"]);
    assert!(
        out.status.success(),
        "status should succeed: {}",
        stdout(&out)
    );
    let text = stdout(&out);
    assert!(text.contains("Instance id"), "{text}");
    assert!(text.contains("0 events"), "{text}");

    let out_json = cli(&dir, &["--json", "status"]);
    assert!(out_json.status.success());
    let v: serde_json::Value = serde_json::from_str(&stdout(&out_json)).unwrap();
    assert_eq!(v["ledger_length"], 0);
    assert_eq!(v["healthy"], true);

    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(not(feature = "sqlcipher"))]
#[test]
fn db_key_env_fails_closed_without_sqlcipher_and_does_not_create_plaintext_db() {
    let dir = tmp_dir();
    let secret = "correct horse battery staple";

    let out = cli_with_env(&dir, &["status"], &[(DB_KEY_ENV, secret)]);

    assert!(
        !out.status.success(),
        "keyed status must fail without sqlcipher"
    );
    let err = stderr(&out);
    assert!(err.contains("sqlcipher feature"), "{err}");
    assert!(
        !err.contains(secret),
        "database key must not be printed: {err}"
    );
    assert!(
        !dir.join(DB_FILE).exists(),
        "no plaintext store should be created for a keyed default build"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(not(feature = "sqlcipher"))]
#[test]
fn db_key_file_env_fails_closed_without_sqlcipher_and_does_not_leak_key() {
    let dir = tmp_dir();
    let key_file = dir.join("db.key");
    let secret = "file-backed database key";
    std::fs::write(&key_file, format!("{secret}\n")).unwrap();
    let key_file = key_file.to_string_lossy().into_owned();

    let out = cli_with_env(&dir, &["status"], &[(DB_KEY_FILE_ENV, key_file.as_str())]);

    assert!(
        !out.status.success(),
        "key-file status must fail without sqlcipher"
    );
    let err = stderr(&out);
    assert!(err.contains("sqlcipher feature"), "{err}");
    assert!(
        !err.contains(secret),
        "key file contents must not leak: {err}"
    );
    assert!(
        !dir.join(DB_FILE).exists(),
        "no plaintext store should be created for a keyed default build"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn ambiguous_db_key_sources_are_rejected_before_store_open() {
    let dir = tmp_dir();
    let key_file = dir.join("db.key");
    std::fs::write(&key_file, "file-secret").unwrap();
    let key_file = key_file.to_string_lossy().into_owned();

    let out = cli_with_env(
        &dir,
        &["status"],
        &[
            (DB_KEY_ENV, "direct-secret"),
            (DB_KEY_FILE_ENV, key_file.as_str()),
        ],
    );

    assert!(!out.status.success(), "ambiguous key sources must fail");
    let err = stderr(&out);
    assert!(err.contains(DB_KEY_ENV), "{err}");
    assert!(err.contains(DB_KEY_FILE_ENV), "{err}");
    assert!(!err.contains("direct-secret"), "{err}");
    assert!(!err.contains("file-secret"), "{err}");
    assert!(
        !dir.join(DB_FILE).exists(),
        "invalid key config should fail before opening the store"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(feature = "sqlcipher")]
#[test]
fn db_key_env_opens_existing_encrypted_store_when_sqlcipher_is_enabled() {
    let dir = tmp_dir();
    let secret = "correct horse battery staple";
    Store::open_with_options(
        &dir,
        chancela_store::StoreOpenOptions::new().with_encryption_key(secret),
    )
    .unwrap();

    let out = cli_with_env(&dir, &["status"], &[(DB_KEY_ENV, secret)]);

    assert!(
        out.status.success(),
        "keyed status should open encrypted store: stdout={} stderr={}",
        stdout(&out),
        stderr(&out)
    );
    assert!(stdout(&out).contains("Instance id"), "{}", stdout(&out));
    assert!(!stdout(&out).contains(secret), "{}", stdout(&out));
    assert!(!stderr(&out).contains(secret), "{}", stderr(&out));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn version_prints() {
    let dir = tmp_dir();
    let out = cli(&dir, &["version"]);
    assert!(out.status.success());
    assert!(stdout(&out).contains("chancela"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn wipe_refuses_without_yes_and_makes_no_mutation() {
    let dir = tmp_dir();
    seed(&dir);
    assert_eq!(counts(&dir).0, 1);

    let out = cli(&dir, &["data", "wipe", "--no-export"]);
    assert!(!out.status.success(), "wipe without --yes must fail");
    // No mutation: the entity is still there.
    assert_eq!(counts(&dir).0, 1, "refused wipe must not clear domain data");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn wipe_domain_clears_data_preserves_ledger() {
    let dir = tmp_dir();
    seed(&dir);
    let before = counts(&dir);
    assert_eq!((before.0, before.1), (1, 1));

    let out = cli(&dir, &["data", "wipe", "--yes", "--no-export"]);
    assert!(out.status.success(), "{}", stdout(&out));

    let after = counts(&dir);
    assert_eq!(after.0, 0, "entities cleared");
    assert_eq!(after.1, 0, "books cleared");
    // Ledger preserved and a data.wiped event appended.
    assert!(
        after.3 >= before.3,
        "ledger preserved + data.wiped appended"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn wipe_factory_blanks_everything() {
    let dir = tmp_dir();
    seed(&dir);

    let out = cli(&dir, &["data", "wipe", "--factory", "--yes", "--no-export"]);
    assert!(out.status.success(), "{}", stdout(&out));

    let after = counts(&dir);
    assert_eq!(after.0, 0, "entities cleared");
    assert_eq!(after.3, 0, "ledger destroyed by factory reset");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn backup_then_restore_round_trips() {
    let dir = tmp_dir();
    seed(&dir);
    let archive = dir.join("snapshot.zip");

    let out = cli(&dir, &["backup", "--out", archive.to_str().unwrap()]);
    assert!(out.status.success(), "{}", stdout(&out));
    assert!(archive.is_file(), "backup archive written to --out");

    // Wipe domain data, then restore from the backup.
    let out = cli(&dir, &["data", "wipe", "--yes", "--no-export"]);
    assert!(out.status.success());
    assert_eq!(counts(&dir).0, 0);

    let out = cli(&dir, &["restore", archive.to_str().unwrap(), "--yes"]);
    assert!(out.status.success(), "{}", stdout(&out));
    assert_eq!(counts(&dir).0, 1, "entity restored from backup");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn restore_refuses_without_yes() {
    let dir = tmp_dir();
    seed(&dir);
    let archive = dir.join("snapshot.zip");
    assert!(
        cli(&dir, &["backup", "--out", archive.to_str().unwrap()])
            .status
            .success()
    );

    let out = cli(&dir, &["restore", archive.to_str().unwrap()]);
    assert!(!out.status.success(), "restore without --yes must fail");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn book_export_then_import_round_trips() {
    let src = tmp_dir();
    let book_id = seed(&src);
    let bundle = src.join("book.zip");

    let out = cli(
        &src,
        &[
            "book",
            "export",
            &book_id,
            "--out",
            bundle.to_str().unwrap(),
        ],
    );
    assert!(out.status.success(), "{}", stdout(&out));
    assert!(bundle.is_file(), "bundle written");

    // Import into a fresh, independent instance.
    let dst = tmp_dir();
    let out = cli(&dst, &["book", "import", bundle.to_str().unwrap()]);
    assert!(out.status.success(), "{}", stdout(&out));
    assert!(
        stdout(&out).contains("verified"),
        "clean bundle imports as verified: {}",
        stdout(&out)
    );

    let _ = std::fs::remove_dir_all(&src);
    let _ = std::fs::remove_dir_all(&dst);
}

#[test]
fn ledger_verify_healthy() {
    let dir = tmp_dir();
    seed(&dir);
    let out = cli(&dir, &["ledger", "verify"]);
    assert!(out.status.success(), "{}", stdout(&out));
    assert!(stdout(&out).contains("intact"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn ledger_integrity_reports() {
    let dir = tmp_dir();
    seed(&dir);
    let out = cli(&dir, &["--json", "ledger", "integrity"]);
    assert!(out.status.success(), "{}", stdout(&out));
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(v["healthy"], true);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn user_create_bootstraps_owner_then_gestor() {
    let dir = tmp_dir();

    let out = cli(
        &dir,
        &[
            "user",
            "create",
            "amelia.marques",
            "--display-name",
            "Amélia Marques",
        ],
    );
    assert!(out.status.success(), "{}", stdout(&out));
    assert!(
        stdout(&out).contains("Owner"),
        "first user is Owner: {}",
        stdout(&out)
    );

    let out = cli(&dir, &["user", "create", "joao.silva"]);
    assert!(out.status.success(), "{}", stdout(&out));
    assert!(
        stdout(&out).contains("Gestor"),
        "second user is Gestor: {}",
        stdout(&out)
    );

    // The on-disk users.json is the exact api contract: first user holds Owner@Global.
    let users: Vec<User> =
        serde_json::from_slice(&std::fs::read(dir.join("users.json")).unwrap()).unwrap();
    assert_eq!(users.len(), 2);
    let amelia = users
        .iter()
        .find(|u| u.username == "amelia.marques")
        .unwrap();
    assert!(
        amelia
            .role_assignments
            .iter()
            .any(|a| a.role_id == OWNER_ROLE_ID)
    );
    assert!(
        amelia.password_hash.is_none(),
        "no secret material is ever written"
    );

    // `user ls` lists both.
    let out = cli(&dir, &["user", "ls"]);
    assert!(out.status.success());
    let text = stdout(&out);
    assert!(
        text.contains("amelia.marques") && text.contains("joao.silva"),
        "{text}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn user_create_rejects_duplicate() {
    let dir = tmp_dir();
    assert!(
        cli(&dir, &["user", "create", "amelia.marques"])
            .status
            .success()
    );
    let out = cli(&dir, &["user", "create", "amelia.marques"]);
    assert!(!out.status.success(), "duplicate username must be rejected");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn migrate_reports_schema() {
    let dir = tmp_dir();
    let out = cli(&dir, &["migrate"]);
    assert!(out.status.success(), "{}", stdout(&out));
    assert!(stdout(&out).contains("schema v"));
    let _ = std::fs::remove_dir_all(&dir);
}
