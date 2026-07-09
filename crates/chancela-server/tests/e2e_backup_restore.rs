//! Journey (t30 Wave A acceptance): `POST /v1/backup` produces a verifiable archive, and unpacking
//! it over a wiped data dir restores the whole system of record.
//!
//! Build a domain (user, a manual + a registry-imported entity, a book, a sealed ata), take a hot
//! backup, and prove the returned manifest is trustworthy: it shape-matches the frozen contract, its
//! `bytes` equals the real archive size on disk, and — unpacking the zip in-test — every member's
//! recomputed sha256 matches the manifest's per-file digest (and every manifest file is present).
//! Then simulate a disaster: stop the server, **wipe the data dir**, unpack the backup back over it,
//! restart, and confirm the entities/book/sealed act are all present and the durable chain verifies.

mod common;

use std::collections::HashMap;
use std::io::{Cursor, Read};
use std::path::Path;

use common::*;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const CODE: &str = "1234-5678-9012";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg_attr(
    not(feature = "e2e"),
    ignore = "composed-system e2e: spawns the real server binary (run with --features e2e)"
)]
async fn backup_manifest_verifies_and_restore_over_a_wiped_dir_round_trips() {
    let registry = spawn_registry_fixture(CERTIDAO_HTML).await;
    let mut h =
        ServerHarness::start_with(HarnessOptions::default().with_registry(registry.url.clone()))
            .await;

    // --- Seed a domain worth backing up ----------------------------------------------------
    let user_id = create_user(&h, "amelia.marques", "Amélia Marques").await;
    let token = open_session(&h, &user_id).await;

    let (status, manual) = h
        .post_json_auth(
            "/v1/entities",
            json!({
                "name": "Manual, Lda",
                "nipc": "500000000",
                "seat": "Porto",
                "kind": "SociedadePorQuotas",
            }),
            &token,
        )
        .await;
    assert_eq!(status, 201, "manual entity: {manual}");
    let manual_id = manual["id"].as_str().expect("manual id").to_owned();

    let (status, report) = h
        .post_json_auth(
            "/v1/entities/import-from-registry",
            json!({ "code": CODE }),
            &token,
        )
        .await;
    assert_eq!(status, 201, "import: {report}");
    let imported_id = report["entity"]["id"]
        .as_str()
        .expect("imported id")
        .to_owned();

    let book_id = open_book(&h, &manual_id, &token).await;
    let act_id = draft_act(&h, &book_id, "Ata da Assembleia Geral Anual", Some(&token)).await;
    fill_act_contents(&h, &act_id, &token).await;
    advance_to_signing(&h, &act_id, Some(&token)).await;
    let (status, _) = h
        // The fully-filled CSC ata (mesa set via the wire, t31) has no findings — no ack needed.
        .post_json_auth(&format!("/v1/acts/{act_id}/seal"), json!({}), &token)
        .await;
    assert_eq!(status, 200);

    let (_, verify_before) = h.get_json("/v1/ledger/verify").await;
    assert_eq!(verify_before["valid"], true);
    let length_before = verify_before["length"].as_u64().expect("length");

    // --- Take a hot backup and verify the manifest -----------------------------------------
    let (status, manifest) = h.post_json_auth("/v1/backup", json!({}), &token).await;
    assert_eq!(status, 200, "backup: {manifest}");
    assert_shape(
        "backup.manifest",
        &manifest,
        &contract("backup.manifest.json"),
    );

    // The archive really exists on disk and its size matches the manifest's `bytes`.
    let zip_path = manifest["path"].as_str().expect("manifest path").to_owned();
    let zip_bytes = std::fs::read(&zip_path).expect("backup archive readable on disk");
    assert_eq!(
        manifest["bytes"].as_u64().expect("bytes"),
        zip_bytes.len() as u64,
        "manifest bytes matches the on-disk archive size"
    );
    assert!(!zip_bytes.is_empty(), "the archive has content");

    // The backup snapshotted the durable chain at full length, and it verified at backup time.
    assert_eq!(
        manifest["ledger_length"].as_u64().expect("length"),
        length_before
    );
    assert_eq!(manifest["ledger_verified"], true);
    assert_eq!(
        manifest["store_schema_version"],
        chancela_store::schema::SCHEMA_VERSION
    );

    // Recompute every archive member's sha256 and cross-check the manifest's per-file digests.
    // (`manifest.json` itself is the only member NOT listed in `files` — it carries the digests.)
    let claimed: HashMap<String, String> = manifest["files"]
        .as_array()
        .expect("files array")
        .iter()
        .map(|f| {
            (
                f["name"].as_str().expect("file name").to_owned(),
                f["sha256"].as_str().expect("file sha256").to_owned(),
            )
        })
        .collect();
    assert!(
        claimed.contains_key("chancela.db"),
        "the DB snapshot is in the manifest: {:?}",
        claimed.keys().collect::<Vec<_>>()
    );

    let members = read_zip_members(&zip_bytes);
    for (name, bytes) in &members {
        if name == "manifest.json" {
            continue;
        }
        let recomputed = hex(&Sha256::digest(bytes));
        let claimed_digest = claimed
            .get(name)
            .unwrap_or_else(|| panic!("archive member {name} is absent from the manifest files"));
        assert_eq!(
            &recomputed, claimed_digest,
            "recomputed sha256 of {name} matches the manifest digest"
        );
    }
    for name in claimed.keys() {
        assert!(
            members.iter().any(|(n, _)| n == name),
            "manifest file {name} is present in the archive"
        );
    }

    // --- Simulate a disaster: stop, wipe the data dir, unpack the backup over it -------------
    h.stop();

    // Wipe everything the running server left behind (the DB + WAL sidecars, JSON sidecars, the
    // backups dir). The archive bytes are already in memory, so wiping the backup itself is fine.
    std::fs::remove_dir_all(&h.data_dir).expect("wipe the data dir");
    std::fs::create_dir_all(&h.data_dir).expect("recreate the empty data dir");
    assert!(
        !h.data_dir.join("chancela.db").exists(),
        "the durable DB is gone after the wipe"
    );

    // Unpack the archive back over the empty data dir (what `scripts/restore.*` do on real metal).
    for (name, bytes) in &members {
        let dest = h.data_dir.join(name);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).expect("member parent dir");
        }
        std::fs::write(&dest, bytes).expect("write restored member");
    }
    assert!(
        h.data_dir.join("chancela.db").exists(),
        "the DB snapshot is back after the restore"
    );

    // --- Bring the server back up over the restored dir ------------------------------------
    h.start_again().await;

    // The records are all present again.
    let (status, e1) = h.get_json(&format!("/v1/entities/{manual_id}")).await;
    assert_eq!(status, 200, "manual entity restored: {e1}");
    assert_eq!(e1["name"], "Manual, Lda");
    let (status, e2) = h.get_json(&format!("/v1/entities/{imported_id}")).await;
    assert_eq!(status, 200, "imported entity restored: {e2}");
    assert_eq!(e2["nipc"], "503004642");

    let (status, book) = h.get_json(&format!("/v1/books/{book_id}")).await;
    assert_eq!(status, 200, "book restored: {book}");
    let (status, act) = h.get_json(&format!("/v1/acts/{act_id}")).await;
    assert_eq!(status, 200, "sealed act restored: {act}");
    assert_eq!(act["state"], "Sealed");
    assert_eq!(act["ata_number"], 1);

    // The durable chain came back intact and verifies.
    let (status, verify) = h.get_json("/v1/ledger/verify").await;
    assert_eq!(status, 200);
    assert_eq!(verify["valid"], true, "the restored chain verifies");
    assert_eq!(
        verify["length"].as_u64().expect("length"),
        length_before,
        "the restored ledger is at its backed-up length"
    );

    let (status, health) = h.get_json("/health").await;
    assert_eq!(status, 200);
    assert_eq!(health["persistent"], true);
    assert_eq!(health["ledger_verified"], true);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg_attr(
    not(feature = "e2e"),
    ignore = "composed-system e2e: spawns the real server binary (run with --features e2e)"
)]
async fn invalid_restore_archive_is_rejected_without_partial_apply() {
    let h = ServerHarness::start().await;

    // Seed durable state across the read models and JSON sidecars that a whole-store restore swaps:
    // users, settings, ledger, API keys, DSR requests, and persisted legal hold on a book.
    let user_id = create_user(&h, "amelia.marques", "Amélia Marques").await;
    let token = open_session(&h, &user_id).await;

    let (status, mut settings) = h.get_json("/v1/settings").await;
    assert_eq!(status, 200, "settings before mutation: {settings}");
    settings["organization"]["name"] = json!("Chancela E2E");
    settings["appearance"]["theme"] = json!("dark");
    let (status, stored_settings) = h.put_json_auth("/v1/settings", settings, &token).await;
    assert_eq!(status, 200, "settings mutation: {stored_settings}");

    let entity_id = create_entity(
        &h,
        "Restore Guard, Lda",
        "500000000",
        "Porto",
        "SociedadePorQuotas",
        &token,
    )
    .await;
    let book_id = open_book(&h, &entity_id, &token).await;
    let (status, legal_hold) = h
        .put_json_auth(
            &format!("/v1/books/{book_id}/legal-hold"),
            json!({ "reason": "litigation hold" }),
            &token,
        )
        .await;
    assert_eq!(status, 200, "set legal hold: {legal_hold}");
    assert_eq!(legal_hold["legal_hold"], true);

    let (status, api_key) = h
        .post_json_auth(
            "/v1/api-keys",
            json!({
                "name": "Ledger export",
                "grant": {
                    "kind": "permissions",
                    "permissions": ["ledger.read"],
                    "scope": { "kind": "global" }
                },
                "rate_limit": { "rpm": 120, "burst": 10 }
            }),
            &token,
        )
        .await;
    assert_eq!(status, 201, "create API key: {api_key}");
    assert!(
        api_key["secret"]
            .as_str()
            .is_some_and(|s| s.starts_with("chk_"))
    );

    let (status, dsr) = h
        .post_json_auth(
            &format!("/v1/privacy/users/{user_id}/dsr-requests"),
            json!({ "request_type": "export", "reason": "subject access request" }),
            &token,
        )
        .await;
    assert_eq!(status, 201, "create DSR request: {dsr}");

    let before = Snapshot::capture(&h, &token, &user_id, &entity_id, &book_id).await;
    let sidecars_before = read_sidecars(
        &h.data_dir,
        &[
            "settings.json",
            "users.json",
            "apikeys.json",
            "privacy-dsr-requests.json",
        ],
    );

    let bad_archive = h.data_dir.join("backups").join("not-a-backup.zip");
    std::fs::create_dir_all(bad_archive.parent().expect("backup parent"))
        .expect("create backups dir");
    std::fs::write(&bad_archive, b"this is not a zip archive").expect("write invalid backup");

    let (status, body) = h
        .post_json_auth(
            "/v1/ledger/recovery/restore",
            json!({ "archive": "not-a-backup.zip" }),
            &token,
        )
        .await;
    assert_eq!(status, 422, "bad restore must be rejected: {body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("cópia de segurança inválida"),
        "restore error should identify an invalid backup: {body}"
    );

    let after = Snapshot::capture(&h, &token, &user_id, &entity_id, &book_id).await;
    assert_eq!(after, before, "bad restore must not alter live state");
    assert_eq!(
        read_sidecars(
            &h.data_dir,
            &[
                "settings.json",
                "users.json",
                "apikeys.json",
                "privacy-dsr-requests.json",
            ],
        ),
        sidecars_before,
        "bad restore must not rewrite sidecar files"
    );
}

/// Read every member of a zip archive (from its raw bytes) as `(name, bytes)`.
fn read_zip_members(zip_bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut archive =
        zip::ZipArchive::new(Cursor::new(zip_bytes)).expect("backup archive is a valid zip");
    let mut out = Vec::with_capacity(archive.len());
    for i in 0..archive.len() {
        let mut member = archive.by_index(i).expect("zip member");
        // Directory entries (if any) carry no bytes to restore or digest.
        if member.is_dir() {
            continue;
        }
        let name = member.name().to_owned();
        let mut bytes = Vec::with_capacity(member.size() as usize);
        member.read_to_end(&mut bytes).expect("read zip member");
        out.push((name, bytes));
    }
    out
}

/// Lowercase-hex encoding of a byte slice (mirrors the store's manifest digest formatting).
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[derive(Debug, PartialEq)]
struct Snapshot {
    user: Value,
    users: Value,
    settings: Value,
    entity: Value,
    book: Value,
    legal_hold: Value,
    api_keys: Value,
    dsr_requests: Value,
    ledger_verify: Value,
    ledger_events: Value,
}

impl Snapshot {
    async fn capture(
        h: &ServerHarness,
        token: &str,
        user_id: &str,
        entity_id: &str,
        book_id: &str,
    ) -> Self {
        let user = expect_json(
            h.get_json_auth(&format!("/v1/users/{user_id}"), token)
                .await,
        );
        let users = expect_json(h.get_json_auth("/v1/users", token).await);
        let settings = expect_json(h.get_json_auth("/v1/settings", token).await);
        let entity = expect_json(
            h.get_json_auth(&format!("/v1/entities/{entity_id}"), token)
                .await,
        );
        let book = expect_json(
            h.get_json_auth(&format!("/v1/books/{book_id}"), token)
                .await,
        );
        let legal_hold = expect_json(
            h.get_json_auth(&format!("/v1/books/{book_id}/legal-hold"), token)
                .await,
        );
        let api_keys = expect_json(h.get_json_auth("/v1/api-keys", token).await);
        let dsr_requests = expect_json(
            h.get_json_auth(&format!("/v1/privacy/users/{user_id}/dsr-requests"), token)
                .await,
        );
        let ledger_verify = expect_json(h.get_json_auth("/v1/ledger/verify", token).await);
        let ledger_events =
            expect_json(h.get_json_auth("/v1/ledger/events?limit=1000", token).await);

        Snapshot {
            user,
            users,
            settings,
            entity,
            book,
            legal_hold,
            api_keys,
            dsr_requests,
            ledger_verify,
            ledger_events,
        }
    }
}

fn expect_json((status, body): (u16, Value)) -> Value {
    assert_eq!(status, 200, "snapshot read failed: {body}");
    body
}

fn read_sidecars(data_dir: &Path, names: &[&str]) -> HashMap<String, Vec<u8>> {
    names
        .iter()
        .map(|name| {
            let path = data_dir.join(name);
            let bytes = std::fs::read(&path)
                .unwrap_or_else(|e| panic!("read sidecar {}: {e}", path.display()));
            ((*name).to_owned(), bytes)
        })
        .collect()
}
