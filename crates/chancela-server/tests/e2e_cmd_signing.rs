//! Journey: the qualified Chave Móvel Digital signing endpoints, exercised against the real server
//! **without** a live SCMD (t57-S3). The full mock-backed initiate→confirm round-trip lives in the
//! `chancela-api` integration tests (which can inject a mock transport); the composed-system server
//! builds its own state from the environment, so here we prove the endpoints are wired and behave
//! honestly end-to-end when CMD is not configured: a sealed act reports `unsigned`, the signed PDF is
//! `404` until signed, and `initiate` refuses with `422` (no ApplicationId configured — no OTP is
//! ever dispatched). No live SCMD/TSL traffic (t57 gate).
//!
//! Fictional example data only: "Encosto Estratégico, S.A." / "Amélia Marques".

mod common;

use common::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg_attr(
    not(feature = "e2e"),
    ignore = "composed-system e2e: spawns the real server binary (run with --features e2e)"
)]
async fn cmd_signing_endpoints_are_wired_and_refuse_cleanly_without_cmd_config() {
    let h = ServerHarness::start().await;
    let token = bootstrap_session(&h).await;

    // Seal an act → an unsigned PDF/A exists, but no qualified signature yet.
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
    let act_id = draft_act(&h, &book_id, "Ata da AG anual", Some(&token)).await;
    fill_act_contents(&h, &act_id, &token).await;
    advance_to_signing(&h, &act_id, Some(&token)).await;
    let (status, sealed) = h
        .post_json_auth(
            &format!("/v1/acts/{act_id}/seal"),
            manual_signature_seal_body("Arquivo E2E / CMD signing ata"),
            &token,
        )
        .await;
    assert_eq!(status, 200, "seal: {sealed}");

    // Signature status: unsigned; and (require_qualified defaults off) the act is finalizado.
    let (status, view) = h
        .get_json_auth(&format!("/v1/acts/{act_id}/signature"), &token)
        .await;
    assert_eq!(status, 200);
    assert_eq!(view["status"], "unsigned");
    assert_eq!(view["finalization"], "finalizado");

    // The signed PDF is 404 until a qualified signature exists.
    let (status, _) = h
        .get_json_auth(&format!("/v1/acts/{act_id}/document/signed"), &token)
        .await;
    assert_eq!(status, 404);

    // Initiate with CMD not configured (no ApplicationId, no env) → 422; no OTP dispatched, no secret
    // echoed in the error body.
    let (status, err) = h
        .post_json_auth(
            &format!("/v1/acts/{act_id}/signature/cmd/initiate"),
            serde_json::json!({ "phone": "+351 912345678", "pin": "271828" }),
            &token,
        )
        .await;
    assert_eq!(status, 422, "initiate without CMD config: {err}");
    assert!(
        !err.to_string().contains("271828"),
        "the PIN must never be echoed"
    );

    // Confirming an unknown session is a clean 404 (never a 500).
    let (status, _) = h
        .post_json_auth(
            &format!("/v1/acts/{act_id}/signature/cmd/confirm"),
            serde_json::json!({ "session_id": "does-not-exist", "otp": "000000" }),
            &token,
        )
        .await;
    assert_eq!(status, 404);
}
