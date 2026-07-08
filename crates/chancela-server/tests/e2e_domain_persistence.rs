//! Journey (t30 Wave A acceptance): the whole domain survives a process restart, and the durable
//! hash chain keeps going afterwards.
//!
//! This is THE durability acceptance walk. Build a full domain over the real binary — a user +
//! session, a manually-created entity, a registry-imported entity (+ its stored extract), a book
//! (termo de abertura), a sealed ata (#1), and a superseding CAE refresh that writes the on-disk
//! cache — then **restart the process over the same data dir** and prove every record is present
//! and correct: entities, book, the sealed act (its ata number **and** payload digest intact), the
//! registry extract with its masked-code provenance, the CAE catalog reloaded from cache, and the
//! full-length audit ledger that still `verify()`s (with `/health` reporting `persistent: true`,
//! `ledger_verified: true`, and the same length). Finally, a POST-restart seal continues the chain
//! correctly — the book's ata counter picks up at **#2**, and the chain grows and still verifies.
//!
//! (A law-archive fetch is deliberately left out of this walk: the only archivable diplomas pin
//! their `pdf_url` at live Diário da República URLs, so a fetch needs the network and no cheap
//! offline fixture exists — persistence of the `laws/` sidecar is covered by the backup journey,
//! which bundles and restores that directory.)

mod common;

use common::*;
use serde_json::json;

const CODE: &str = "1234-5678-9012";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg_attr(
    not(feature = "e2e"),
    ignore = "composed-system e2e: spawns the real server binary (run with --features e2e)"
)]
async fn full_domain_survives_restart_and_the_chain_continues() {
    let registry = spawn_registry_fixture(CERTIDAO_HTML).await;
    let cae = spawn_cae_fixture(SUPERSEDING_CAE_DATASET).await;
    let mut h = ServerHarness::start_with(
        HarnessOptions::default()
            .with_registry(registry.url.clone())
            .with_cae(cae.url.clone())
            .with_seed_cae_cache(STALE_CAE_CACHE),
    )
    .await;

    // --- Build the full domain -------------------------------------------------------------

    // A user + session so the chain is attributed to a real person.
    let user_id = create_user(&h, "amelia.marques", "Amélia Marques").await;
    let token = open_session(&h, &user_id).await;

    // A manually-created entity.
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

    // A registry-imported entity (the child's real transport fetches the fixture certidão).
    let (status, report) = h
        .post_json_auth(
            "/v1/entities/import-from-registry",
            json!({ "code": CODE }),
            &token,
        )
        .await;
    assert_eq!(status, 201, "import-from-registry: {report}");
    let imported_id = report["entity"]["id"]
        .as_str()
        .expect("imported id")
        .to_owned();
    assert_eq!(report["entity"]["nipc"], "503004642");

    // A book (termo de abertura) on the manual entity, then a full ata lifecycle → sealed #1.
    let book_id = open_book(&h, &manual_id, &token).await;
    let act_id = draft_act(&h, &book_id, "Ata da Assembleia Geral Anual", Some(&token)).await;
    fill_act_contents(&h, &act_id, &token).await;
    advance_to_signing(&h, &act_id, Some(&token)).await;
    let (status, sealed) = h
        // The fully-filled CSC ata (mesa set via the wire, t31) has no findings — no ack needed.
        .post_json_auth(&format!("/v1/acts/{act_id}/seal"), json!({}), &token)
        .await;
    assert_eq!(status, 200, "seal: {sealed}");
    assert_eq!(sealed["ata_number"], 1);
    let sealed_digest = sealed["payload_digest"]
        .as_str()
        .expect("digest")
        .to_owned();
    assert_eq!(sealed_digest.len(), 64);

    // A CAE refresh supersedes the embedded catalog and writes the on-disk cache.
    let (status, refresh) = h.post_json_auth("/v1/cae/refresh", json!({}), &token).await;
    assert_eq!(status, 200, "cae refresh: {refresh}");
    assert_eq!(refresh["updated"], true);
    let (status, a) = h.get_json("/v1/cae/A").await;
    assert_eq!(status, 200);
    assert_eq!(a["designation"], "Secção de teste");

    // --- Snapshot the pre-restart truth ----------------------------------------------------

    let (_, verify_before) = h.get_json("/v1/ledger/verify").await;
    assert_eq!(verify_before["valid"], true);
    let length_before = verify_before["length"].as_u64().expect("length");
    assert!(
        length_before >= 6,
        "a non-trivial chain before restart: {length_before}"
    );

    let (_, dash_before) = h.get_json("/v1/dashboard").await;
    assert_eq!(dash_before["entities"], 2);
    assert_eq!(dash_before["books_total"], 1);
    assert_eq!(dash_before["books_open"], 1);
    assert_eq!(dash_before["acts_sealed"], 1);

    // --- RESTART over the same data dir (drop CHANCELA_CAE_URL → catalog loads from cache) ---

    h.clear_cae_url();
    h.restart().await;

    // The in-memory session did not survive the restart, so re-open one for the persisted user to
    // attribute the post-restart mutations below.
    let token = open_session(&h, &user_id).await;

    // Both entities survived, byte-for-byte.
    let (status, e1) = h.get_json(&format!("/v1/entities/{manual_id}")).await;
    assert_eq!(status, 200, "manual entity survived the restart: {e1}");
    assert_eq!(e1["name"], "Manual, Lda");
    assert_eq!(e1["nipc"], "500000000");
    let (status, e2) = h.get_json(&format!("/v1/entities/{imported_id}")).await;
    assert_eq!(status, 200, "imported entity survived the restart: {e2}");
    assert_eq!(e2["nipc"], "503004642");
    assert_eq!(e2["name"], "Encosto Estratégico, Lda");

    // The book is still Open, and the sealed ata kept BOTH its number and its payload digest.
    let (status, book) = h.get_json(&format!("/v1/books/{book_id}")).await;
    assert_eq!(status, 200, "book survived the restart: {book}");
    assert_eq!(book["state"], "Open");
    let (status, act) = h.get_json(&format!("/v1/acts/{act_id}")).await;
    assert_eq!(status, 200, "sealed act survived the restart: {act}");
    assert_eq!(act["state"], "Sealed");
    assert_eq!(act["ata_number"], 1);
    assert_eq!(
        act["payload_digest"], sealed_digest,
        "the sealed ata's payload digest is intact across the restart"
    );

    // The registry extract + its masked-code provenance survived (and the full code never surfaces).
    let (status, extract) = h
        .get_json_auth(&format!("/v1/entities/{imported_id}/registry"), &token)
        .await;
    assert_eq!(
        status, 200,
        "registry extract survived the restart: {extract}"
    );
    assert_eq!(extract["nipc"], "503004642");
    assert_eq!(
        extract["provenance"]["access_code_masked"],
        "****-****-9012"
    );
    assert!(
        !extract.to_string().contains(CODE),
        "the full access code is not resurrected on reload"
    );

    // The CAE catalog reloaded from the on-disk cache the refresh wrote.
    let (status, meta) = h.get_json("/v1/cae").await;
    assert_eq!(status, 200);
    assert_eq!(meta["origin"], "Cache", "CAE catalog reloaded from cache");
    let (status, a) = h.get_json("/v1/cae/A").await;
    assert_eq!(status, 200);
    assert_eq!(a["designation"], "Secção de teste");

    // The durable audit ledger reloaded intact: same length, still verifying.
    let (status, verify) = h.get_json("/v1/ledger/verify").await;
    assert_eq!(status, 200);
    assert_eq!(
        verify["valid"], true,
        "the durable chain verifies after restart"
    );
    assert_eq!(
        verify["length"].as_u64().expect("length"),
        length_before,
        "the ledger survived the restart at full length"
    );

    // /health reflects durable persistence + a verified boot chain (§3.3).
    let (status, health) = h.get_json("/health").await;
    assert_eq!(status, 200);
    assert_eq!(health["persistent"], true);
    assert_eq!(health["ledger_verified"], true);
    assert_eq!(
        health["store_schema_version"],
        chancela_store::schema::SCHEMA_VERSION
    );
    assert_eq!(
        health["ledger_length"].as_u64().expect("ledger_length"),
        length_before
    );

    // The dashboard counts are unchanged by the restart.
    let (_, dash_after) = h.get_json("/v1/dashboard").await;
    assert_eq!(dash_after["entities"], 2);
    assert_eq!(dash_after["books_total"], 1);
    assert_eq!(dash_after["acts_sealed"], 1);

    // --- A POST-restart mutation continues the chain correctly ------------------------------
    //
    // Sealing a second ata into the persisted book proves (a) the chain links onto the durable
    // head (verify stays valid as it grows) and (b) the book's ata counter survived — the next ata
    // is #2, not a reset #1.
    let act2 = draft_act(
        &h,
        &book_id,
        "Ata da Assembleia Geral Extraordinária",
        Some(&token),
    )
    .await;
    fill_act_contents(&h, &act2, &token).await;
    advance_to_signing(&h, &act2, Some(&token)).await;
    let (status, sealed2) = h
        // The fully-filled CSC ata (mesa set via the wire, t31) has no findings — no ack needed.
        .post_json_auth(&format!("/v1/acts/{act2}/seal"), json!({}), &token)
        .await;
    assert_eq!(status, 200, "post-restart seal: {sealed2}");
    assert_eq!(
        sealed2["ata_number"], 2,
        "the ata counter continued from the persisted book (not reset)"
    );

    let (status, verify) = h.get_json("/v1/ledger/verify").await;
    assert_eq!(status, 200);
    assert_eq!(
        verify["valid"], true,
        "the chain still verifies after the post-restart seal"
    );
    assert!(
        verify["length"].as_u64().expect("length") > length_before,
        "the post-restart mutation extended the durable chain"
    );
}
