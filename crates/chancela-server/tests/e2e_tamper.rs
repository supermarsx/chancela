//! Journey (t30 acceptance #2): a tampered durable chain still boots — loudly, never silently.
//!
//! The durability guarantee is worthless if a corrupted store can lie about it. So: build a domain
//! (entity → book → sealed ata), stop the server, and flip a byte inside a stored event row
//! directly via rusqlite (the kind of on-disk corruption a durable store must survive). On restart
//! the server must (a) come up at all — never refuse to start — (b) report the broken chain
//! (`/health` `ledger_verified: false`, `GET /v1/ledger/verify` `valid: false`), and (c) still serve
//! the domain read model, so an operator can inspect and restore rather than face a dead server.

mod common;

use common::*;
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg_attr(
    not(feature = "e2e"),
    ignore = "composed-system e2e: spawns the real server binary (run with --features e2e)"
)]
async fn a_tampered_chain_boots_but_reports_itself_broken() {
    let mut h = ServerHarness::start().await;
    let token = bootstrap_session(&h).await;

    // A small but complete domain: entity → book → sealed ata #1.
    let entity_id = create_entity(
        &h,
        "Encosto Estratégico, S.A.",
        "503004642",
        "Lisboa",
        "SociedadeAnonima",
        &token,
    )
    .await;
    let book_id = open_book(&h, &entity_id, &token).await;
    let act_id = draft_act(&h, &book_id, "Ata da Assembleia Geral Anual", Some(&token)).await;
    fill_act_contents(&h, &act_id, &token).await;
    advance_to_signing(&h, &act_id, Some(&token)).await;
    let (status, _) = h
        // The fully-filled CSC ata (mesa set via the wire, t31) has no findings — no ack needed.
        .post_json_auth(&format!("/v1/acts/{act_id}/seal"), json!({}), &token)
        .await;
    assert_eq!(status, 200);

    // Baseline: the durable chain is valid and non-trivial before tampering.
    let (_, verify_before) = h.get_json("/v1/ledger/verify").await;
    assert_eq!(verify_before["valid"], true);
    let length_before = verify_before["length"].as_u64().expect("length");
    assert!(length_before >= 3, "a non-trivial chain: {length_before}");

    // --- Tamper: stop the server and flip a byte in the first stored event's payload digest ---
    h.stop();

    let db_path = h.data_dir.join(chancela_store::DB_FILE);
    {
        let conn = rusqlite::Connection::open(&db_path).expect("open the store db for tampering");
        let mut digest: Vec<u8> = conn
            .query_row(
                "SELECT payload_digest FROM events WHERE seq = 1",
                [],
                |row| row.get(0),
            )
            .expect("read the first event's payload digest");
        assert_eq!(digest.len(), 32, "payload digest is a 32-byte blob");
        // Flip one byte: the recomputed event hash will no longer match the stored hash, so a boot
        // `verify()` fails at seq 1 — genuine tamper, not a schema break.
        digest[0] ^= 0xff;
        let rows = conn
            .execute(
                "UPDATE events SET payload_digest = ?1 WHERE seq = 1",
                rusqlite::params![digest],
            )
            .expect("write the tampered event row");
        assert_eq!(rows, 1, "exactly one event row was tampered");
    }

    // --- Restart over the tampered dir: the server MUST still come up ------------------------
    // `start_again` polls `/health` until it answers 200, so reaching the next line already proves
    // the server booted rather than refusing to start on a broken chain (§D-boot).
    h.start_again().await;

    // /health reports the store is persistent but the boot chain did NOT verify.
    let (status, health) = h.get_json("/health").await;
    assert_eq!(status, 200);
    assert_eq!(health["persistent"], true, "the store is still durable");
    assert_eq!(
        health["ledger_verified"], false,
        "the tampered chain is reported broken, not silently accepted"
    );
    assert_eq!(
        health["store_schema_version"],
        chancela_store::schema::SCHEMA_VERSION
    );

    // The on-demand verify agrees: invalid, but the events are all still there.
    let (status, verify) = h.get_json("/v1/ledger/verify").await;
    assert_eq!(status, 200);
    assert_eq!(
        verify["valid"], false,
        "the durable chain no longer verifies"
    );
    assert_eq!(
        verify["length"].as_u64().expect("length"),
        length_before,
        "no events were lost — the chain is broken, not truncated"
    );

    // The domain read model is still fully served (the operator can inspect and restore).
    let (status, entity) = h.get_json(&format!("/v1/entities/{entity_id}")).await;
    assert_eq!(
        status, 200,
        "entity still readable on a broken chain: {entity}"
    );
    assert_eq!(entity["nipc"], "503004642");
    let (status, book) = h.get_json(&format!("/v1/books/{book_id}")).await;
    assert_eq!(status, 200, "book still readable: {book}");
    let (status, act) = h.get_json(&format!("/v1/acts/{act_id}")).await;
    assert_eq!(status, 200, "sealed act still readable");
    assert_eq!(act["state"], "Sealed");
    assert_eq!(act["ata_number"], 1);

    // And the full event feed is still queryable for the audit.
    let (status, events) = h.get_json("/v1/ledger/events").await;
    assert_eq!(status, 200);
    assert_eq!(
        events.as_array().expect("events").len() as u64,
        length_before
    );
}
