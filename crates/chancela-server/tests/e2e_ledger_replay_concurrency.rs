//! Ledger replay/tamper and write-concurrency edges over the real server binary.
//!
//! The first journey removes a persisted middle event while the server is stopped, forcing a replay
//! sequence break on boot. The second races several ready-to-seal acts and asserts the durable
//! ledger still has a contiguous global sequence and the book assigned each ata number once.

mod common;

use std::collections::BTreeSet;
use std::time::Duration;

use common::*;
use serde_json::{Value, json};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg_attr(
    not(feature = "e2e"),
    ignore = "composed-system e2e: spawns the real server binary (run with --features e2e)"
)]
async fn deleting_a_middle_event_restarts_degraded_with_a_sequence_break() {
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
    let _book_id = open_book(&h, &entity_id, &token).await;

    let (_, verify_before) = h.get_json("/v1/ledger/verify").await;
    assert_eq!(verify_before["valid"], true);
    let len_before = verify_before["length"].as_u64().expect("length");
    assert!(
        len_before >= 4,
        "expected a non-trivial chain: {len_before}"
    );

    h.stop();
    {
        let conn = rusqlite::Connection::open(h.data_dir.join(chancela_store::DB_FILE))
            .expect("open store db for event deletion");
        let rows = conn
            .execute("DELETE FROM events WHERE seq = 1", [])
            .expect("delete one middle ledger event");
        assert_eq!(rows, 1, "exactly one middle event was removed");
    }

    h.start_again().await;

    let (status, health) = h.get_json_noauth("/health").await;
    assert_eq!(status, 200);
    assert_eq!(health["persistent"], true);
    assert_eq!(health["ledger_verified"], false);
    assert_eq!(health["integrity"], "broken");
    assert_eq!(health["degraded"], true);
    assert_eq!(health["ledger_length"], len_before - 1);

    let (status, verify) = h.get_json("/v1/ledger/verify").await;
    assert_eq!(status, 200);
    assert_eq!(verify["valid"], false);
    assert_eq!(verify["length"], len_before - 1);
    assert!(
        verify["error"]
            .as_str()
            .expect("verify error")
            .contains("sequence broken"),
        "the replay failure should identify the sequence gap: {verify}"
    );

    let (status, body) = h
        .post_json_auth(
            "/v1/entities",
            json!({
                "name": "Nova, S.A.",
                "nipc": "500000000",
                "seat": "Porto",
                "kind": "SociedadeAnonima"
            }),
            &token,
        )
        .await;
    assert_eq!(
        status, 503,
        "ordinary writes are gated while degraded: {body}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg_attr(
    not(feature = "e2e"),
    ignore = "composed-system e2e: spawns the real server binary (run with --features e2e)"
)]
async fn concurrent_seals_keep_contiguous_ledger_sequences_and_unique_ata_numbers() {
    let h = ServerHarness::start().await;
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
    let book_id = open_book(&h, &entity_id, &token).await;

    let mut act_ids = Vec::new();
    for n in 1..=5 {
        let act_id = draft_act(&h, &book_id, &format!("Ata concorrente {n}"), Some(&token)).await;
        fill_act_contents(&h, &act_id, &token).await;
        advance_to_signing(&h, &act_id, Some(&token)).await;
        act_ids.push(act_id);
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(2))
        .build()
        .expect("reqwest client");
    let mut tasks = Vec::new();
    for act_id in act_ids.clone() {
        let client = client.clone();
        let token = token.clone();
        let url = format!("{}/v1/acts/{act_id}/seal", h.base_url);
        tasks.push(tokio::spawn(async move {
            let resp = client
                .post(url)
                .header(SESSION_HEADER, token)
                .json(&json!({}))
                .send()
                .await
                .expect("seal request sent");
            let status = resp.status().as_u16();
            let body = resp.json::<Value>().await.expect("seal response JSON");
            (status, body)
        }));
    }

    let mut ata_numbers = Vec::new();
    for task in tasks {
        let (status, body) = task.await.expect("seal task joined");
        assert_eq!(status, 200, "concurrent seal succeeded: {body}");
        assert_eq!(body["act"]["state"], "Sealed", "sealed response: {body}");
        ata_numbers.push(body["ata_number"].as_u64().expect("ata number"));
    }
    ata_numbers.sort_unstable();
    assert_eq!(ata_numbers, vec![1, 2, 3, 4, 5]);
    assert_eq!(
        ata_numbers.iter().copied().collect::<BTreeSet<_>>().len(),
        ata_numbers.len(),
        "ata numbers must be unique"
    );

    let (status, feed) = h.get_json(&format!("/v1/books/{book_id}/acts")).await;
    assert_eq!(status, 200, "book acts feed: {feed}");
    let mut feed_numbers: Vec<u64> = feed
        .as_array()
        .expect("acts feed array")
        .iter()
        .map(|act| {
            assert_eq!(act["state"], "Sealed", "all prepared acts sealed: {act}");
            act["ata_number"].as_u64().expect("feed ata number")
        })
        .collect();
    feed_numbers.sort_unstable();
    assert_eq!(feed_numbers, vec![1, 2, 3, 4, 5]);

    let (status, events) = h.get_json("/v1/ledger/events?limit=1000").await;
    assert_eq!(status, 200);
    let seqs: Vec<u64> = events
        .as_array()
        .expect("events array")
        .iter()
        .map(|event| event["seq"].as_u64().expect("event seq"))
        .collect();
    let expected: Vec<u64> = (0..seqs.len() as u64).collect();
    assert_eq!(seqs, expected, "global ledger seqs remain contiguous");

    let (status, verify) = h.get_json("/v1/ledger/verify").await;
    assert_eq!(status, 200);
    assert_eq!(
        verify["valid"], true,
        "ledger verifies after concurrent seals"
    );
    assert_eq!(
        verify["length"].as_u64().expect("verify length"),
        seqs.len() as u64
    );
}
