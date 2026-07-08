//! Journey: the synchronous Cartão de Cidadão signing endpoint, exercised against the real server
//! **without** a physical card (t58-e2). The full mock-backed CC round-trip lives in the
//! `chancela-api` integration tests (which can inject a key-backed `CryptoToken`); the composed
//! system builds its own state from the environment and cannot fake a reader, so here we prove the
//! two host-boundary behaviours end to end:
//!
//! - a **plain server** (no `CHANCELA_LOCAL_SIGNING`) refuses the CC endpoint with `409` — the card
//!   is on the client's machine, unreachable by a remote server's PKCS#11 (co-location gate, CC-B);
//! - a **co-located server** (`CHANCELA_LOCAL_SIGNING=1`, as the desktop shell sets) passes the gate
//!   but, with no reader/middleware in CI, fails cleanly with an honest `422` naming the Cartão de
//!   Cidadão / Autenticação.gov — never a `500`, and no signed artifact is left behind.
//!
//! No hardware is touched (t58 gate). Fictional example data only: "Encosto Estratégico, S.A.".

mod common;

use common::*;

/// Seal an act as the bootstrap Owner and return `(harness_token, act_id)`.
async fn seal_act(h: &ServerHarness) -> (String, String) {
    let token = bootstrap_session(h).await;
    let entity_id = create_entity(
        h,
        "Encosto Estratégico, S.A.",
        "503004642",
        "Lisboa",
        "SociedadeAnonima",
        &token,
    )
    .await;
    let book_id = open_book(h, &entity_id, &token).await;
    let act_id = draft_act(h, &book_id, "Ata da AG anual", Some(&token)).await;
    fill_act_contents(h, &act_id, &token).await;
    advance_to_signing(h, &act_id, Some(&token)).await;
    let (status, sealed) = h
        .post_json_auth(
            &format!("/v1/acts/{act_id}/seal"),
            serde_json::json!({}),
            &token,
        )
        .await;
    assert_eq!(status, 200, "seal: {sealed}");
    (token, act_id)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg_attr(
    not(feature = "e2e"),
    ignore = "composed-system e2e: spawns the real server binary (run with --features e2e)"
)]
async fn cc_signing_409s_on_a_remote_server_but_passes_the_gate_when_co_located() {
    // --- Plain (remote) server: the CC endpoint is refused with 409 (co-location gate). -----------
    let h = ServerHarness::start().await;
    let (token, act_id) = seal_act(&h).await;

    let (status, err) = h
        .post_json_auth(
            &format!("/v1/acts/{act_id}/signature/cc/sign"),
            serde_json::json!({ "capacity": "Administrador" }),
            &token,
        )
        .await;
    assert_eq!(status, 409, "remote server refuses CC signing: {err}");
    assert!(
        err["error"]
            .as_str()
            .unwrap_or_default()
            .contains("aplicação de secretária"),
        "honest co-location message: {err}"
    );

    // The status view is unaffected and the signed PDF stays 404.
    let (status, view) = h
        .get_json_auth(&format!("/v1/acts/{act_id}/signature"), &token)
        .await;
    assert_eq!(status, 200);
    assert_eq!(view["status"], "unsigned");
    let (status, _) = h
        .get_json_auth(&format!("/v1/acts/{act_id}/document/signed"), &token)
        .await;
    assert_eq!(status, 404);

    // --- Co-located server: the gate passes, but with no reader in CI signing fails cleanly (422). -
    let h2 = ServerHarness::start_with(HarnessOptions::default().with_local_signing()).await;
    let (token2, act_id2) = seal_act(&h2).await;

    let (status, err) = h2
        .post_json_auth(
            &format!("/v1/acts/{act_id2}/signature/cc/sign"),
            serde_json::json!({}),
            &token2,
        )
        .await;
    assert_eq!(
        status, 422,
        "co-located but no reader/middleware → honest 422 (not 409, not 500): {err}"
    );
    let msg = err["error"].as_str().unwrap_or_default();
    assert!(
        msg.contains("Cartão de Cidadão"),
        "honest hardware error names the card: {msg}"
    );

    // No signed artifact was produced.
    let (status, _) = h2
        .get_json_auth(&format!("/v1/acts/{act_id2}/document/signed"), &token2)
        .await;
    assert_eq!(status, 404);
}
