//! Journey: the compliance gate refuses an under-filled seal, and the state machine refuses an
//! out-of-order seal.
//!
//! An ata advanced to Signing without its mandatory CSC contents is refused at the seal with `422` +
//! a non-empty `issues` list (all blocking errors); an ata still in Draft cannot be sealed at all
//! (`409`).

mod common;

use common::*;
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg_attr(
    not(feature = "e2e"),
    ignore = "composed-system e2e: spawns the real server binary (run with --features e2e)"
)]
async fn compliance_refuses_underfilled_seal_and_out_of_order_seal() {
    let h = ServerHarness::start().await;

    let entity_id = create_entity(
        &h,
        "Encosto Estratégico, S.A.",
        "503004642",
        "Lisboa",
        "SociedadeAnonima",
    )
    .await;
    let book_id = open_book(&h, &entity_id).await;

    // An empty ata pushed to Signing WITHOUT filling the mandatory contents.
    let act_id = draft_act(&h, &book_id, "Ata vazia", None).await;
    advance_to_signing(&h, &act_id, None).await;

    // The compliance gate itself reports blocking errors and refuses the seal.
    let (status, comp) = h.get_json(&format!("/v1/acts/{act_id}/compliance")).await;
    assert_eq!(status, 200);
    assert!(comp["errors"].as_u64().expect("errors count") > 0);
    assert_eq!(comp["seal_allowed"], false);

    // Sealing it is a 422 carrying the non-empty, all-Error issue list.
    let (status, body) = h
        .post_json(&format!("/v1/acts/{act_id}/seal"), json!({}))
        .await;
    assert_eq!(status, 422, "underfilled seal: {body}");
    let issues = body["issues"].as_array().expect("issues array");
    assert!(!issues.is_empty(), "refusal explains what is missing");
    assert!(
        issues.iter().all(|i| i["severity"] == "Error"),
        "seal-blocking issues are Errors: {issues:?}"
    );

    // A second ata, never advanced to Signing, cannot be sealed out of order (409).
    let draft_id = draft_act(&h, &book_id, "Ainda rascunho", None).await;
    let (status, body) = h
        .post_json(&format!("/v1/acts/{draft_id}/seal"), json!({}))
        .await;
    assert_eq!(status, 409, "out-of-order seal: {body}");
    assert!(body["error"].is_string());

    // Nothing was sealed, and the chain is still valid.
    let (status, verify) = h.get_json("/v1/ledger/verify").await;
    assert_eq!(status, 200);
    assert_eq!(verify["valid"], true);
}
