//! Store edge cases over the real server binary.
//!
//! These journeys pin the startup behavior for durable state that cannot be trusted enough to load:
//! the server still answers `/health`, but it must not report a verified durable ledger. Today the
//! API falls back to an in-memory state when the SQLite file or persisted aggregate JSON is
//! unreadable; that fallback is visible as `persistent:false` and `ledger_verified:null`.

mod common;

use common::*;
use serde_json::Value;

fn assert_store_fallback_health(health: &Value) {
    assert_eq!(health["status"], "ok");
    assert_eq!(
        health["persistent"], false,
        "an unreadable store must not be advertised as durable: {health}"
    );
    assert_eq!(
        health["ledger_verified"],
        Value::Null,
        "no durable boot verification happened, so this must not be true: {health}"
    );
    assert_eq!(health["ledger_length"], 0);
    assert!(
        health.get("store_schema_version").is_none(),
        "schema version is only present for an opened durable store: {health}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg_attr(
    not(feature = "e2e"),
    ignore = "composed-system e2e: spawns the real server binary (run with --features e2e)"
)]
async fn unreadable_sqlite_store_boots_with_an_honest_non_persistent_health_signal() {
    let mut h = ServerHarness::start().await;
    let token = bootstrap_session(&h).await;
    let entity_id = create_entity(
        &h,
        "Encosto Estrategico, S.A.",
        "503004642",
        "Lisboa",
        "SociedadeAnonima",
        &token,
    )
    .await;

    let (_, before) = h.get_json_noauth("/health").await;
    assert_eq!(before["persistent"], true);
    assert_eq!(before["ledger_verified"], true);
    assert!(before["ledger_length"].as_u64().expect("length") >= 2);

    h.stop();
    let db_path = h.data_dir.join(chancela_store::DB_FILE);
    let _ = std::fs::remove_file(h.data_dir.join(format!("{}-wal", chancela_store::DB_FILE)));
    let _ = std::fs::remove_file(h.data_dir.join(format!("{}-shm", chancela_store::DB_FILE)));
    std::fs::remove_file(&db_path).expect("remove store db before replacing it");
    std::fs::create_dir(&db_path).expect("replace store db with an unreadable directory");

    h.start_again().await;

    let (status, health) = h.get_json_noauth("/health").await;
    assert_eq!(status, 200);
    assert_store_fallback_health(&health);

    let (status, missing) = h.get_json(&format!("/v1/entities/{entity_id}")).await;
    assert_eq!(
        status, 404,
        "the corrupt durable domain was not silently treated as loaded: {missing}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg_attr(
    not(feature = "e2e"),
    ignore = "composed-system e2e: spawns the real server binary (run with --features e2e)"
)]
async fn malformed_persisted_aggregate_boots_without_claiming_the_ledger_verified() {
    let mut h = ServerHarness::start().await;
    let token = bootstrap_session(&h).await;
    let entity_id = create_entity(
        &h,
        "Manual, Lda",
        "500000000",
        "Porto",
        "SociedadePorQuotas",
        &token,
    )
    .await;

    let (_, before) = h.get_json_noauth("/health").await;
    assert_eq!(before["persistent"], true);
    assert_eq!(before["ledger_verified"], true);

    h.stop();
    {
        let conn = rusqlite::Connection::open(h.data_dir.join(chancela_store::DB_FILE))
            .expect("open store db for aggregate corruption");
        let rows = conn
            .execute(
                "UPDATE entities SET json = ?1 WHERE id = ?2",
                rusqlite::params!["{\"id\":", entity_id],
            )
            .expect("write malformed entity JSON");
        assert_eq!(rows, 1, "exactly one aggregate row was corrupted");
    }

    h.start_again().await;

    let (status, health) = h.get_json_noauth("/health").await;
    assert_eq!(status, 200);
    assert_store_fallback_health(&health);

    let (status, body) = h.get_json(&format!("/v1/entities/{entity_id}")).await;
    assert_eq!(
        status, 404,
        "malformed aggregate state must not be silently loaded: {body}"
    );
}
