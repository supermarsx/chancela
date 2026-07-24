//! Journey: the compliance gate refuses an under-filled transition to Signing, and the state
//! machine refuses an out-of-order seal.
//!
//! An ata without its mandatory CSC contents is refused when advancing to Signing with `422` + a
//! non-empty `issues` list (all blocking errors); an ata still in Draft cannot be sealed at all
//! (`409`).

mod common;

use common::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg_attr(
    not(feature = "e2e"),
    ignore = "composed-system e2e: spawns the real server binary (run with --features e2e)"
)]
async fn compliance_refuses_underfilled_signing_and_out_of_order_seal() {
    let h = ServerHarness::start().await;
    let token = bootstrap_session(&h).await;

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

    // An empty ata can progress through review, but cannot enter Signing without its mandatory
    // contents.
    let act_id = draft_act(&h, &book_id, "Ata vazia", Some(&token)).await;
    for to in ["Review", "Convened", "Deliberated", "TextApproved"] {
        let (status, advanced) = h
            .post_json_auth(
                &format!("/v1/acts/{act_id}/advance"),
                serde_json::json!({ "to": to }),
                &token,
            )
            .await;
        assert_eq!(status, 200, "advance to {to}: {advanced}");
    }
    let (status, body) = h
        .post_json_auth(
            &format!("/v1/acts/{act_id}/advance"),
            serde_json::json!({ "to": "Signing" }),
            &token,
        )
        .await;
    assert_eq!(status, 422, "underfilled signing transition: {body}");
    let issues = body["issues"].as_array().expect("issues array");
    assert!(!issues.is_empty(), "refusal explains what is missing");
    assert!(
        issues.iter().all(|issue| issue["severity"] == "Error"),
        "signing-blocking issues are Errors: {issues:?}"
    );

    // The compliance endpoint reports the same blocking state.
    let (status, comp) = h.get_json(&format!("/v1/acts/{act_id}/compliance")).await;
    assert_eq!(status, 200);
    assert!(comp["errors"].as_u64().expect("errors count") > 0);
    assert_eq!(comp["seal_allowed"], false);

    // A second ata, never advanced to Signing, cannot be sealed out of order (409).
    let draft_id = draft_act(&h, &book_id, "Ainda rascunho", Some(&token)).await;
    let (status, body) = h
        .post_json_auth(
            &format!("/v1/acts/{draft_id}/seal"),
            manual_signature_seal_body("Arquivo E2E / Ata draft"),
            &token,
        )
        .await;
    assert_eq!(status, 409, "out-of-order seal: {body}");
    assert!(body["error"].is_string());

    // Nothing was sealed, and the chain is still valid.
    let (status, verify) = h.get_json("/v1/ledger/verify").await;
    assert_eq!(status, 200);
    assert_eq!(verify["valid"], true);
}
