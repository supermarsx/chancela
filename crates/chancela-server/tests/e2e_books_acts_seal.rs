//! Journey: the full book + ata seal lifecycle over the real binary.
//!
//! Open a book (termo de abertura) → draft an ata → fill contents → advance to Signing → confirm the
//! compliance gate is clean → seal (ata #1, Sealed, 64-hex payload digest) → see it in the book's
//! acts feed → close the book (termo de encerramento) → confirm drafting into a closed book is refused.

mod common;

use common::*;
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg_attr(
    not(feature = "e2e"),
    ignore = "composed-system e2e: spawns the real server binary (run with --features e2e)"
)]
async fn books_acts_full_seal_lifecycle() {
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

    // Draft an ata, fill its contents, and advance it to Signing.
    let act_id = draft_act(&h, &book_id, "Ata da Assembleia Geral Anual", None).await;
    fill_act_contents(&h, &act_id).await;
    advance_to_signing(&h, &act_id, None).await;

    // The fully-filled CSC ata (mesa/time/agenda all set via the wire, t31) has no findings, so
    // the compliance gate permits the seal.
    let (status, comp) = h.get_json(&format!("/v1/acts/{act_id}/compliance")).await;
    assert_eq!(status, 200);
    assert_eq!(comp["rule_pack"], "csc-art63/v2");
    assert_eq!(comp["errors"], 0);
    assert_eq!(comp["seal_allowed"], true);

    // Seal → ata #1, Sealed, a 64-hex payload digest. No warnings to acknowledge.
    let (status, sealed) = h
        .post_json(&format!("/v1/acts/{act_id}/seal"), json!({}))
        .await;
    assert_eq!(status, 200, "seal: {sealed}");
    assert_eq!(sealed["ata_number"], 1);
    assert_eq!(sealed["act"]["state"], "Sealed");
    assert_eq!(sealed["payload_digest"].as_str().expect("digest").len(), 64);

    // The act now reads Sealed with its ata number.
    let (status, got) = h.get_json(&format!("/v1/acts/{act_id}")).await;
    assert_eq!(status, 200);
    assert_eq!(got["state"], "Sealed");
    assert_eq!(got["ata_number"], 1);

    // The book's acts feed lists the sealed ata #1.
    let (status, feed) = h.get_json(&format!("/v1/books/{book_id}/acts")).await;
    assert_eq!(status, 200);
    let arr = feed.as_array().expect("acts feed");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["ata_number"], 1);
    assert_eq!(arr[0]["state"], "Sealed");

    // Close the book (termo de encerramento).
    let (status, closed) = h
        .post_json(
            &format!("/v1/books/{book_id}/close"),
            json!({
                "reason": "BookFull",
                "closing_date": "2026-12-31",
                "required_signatories": ["Administrador"],
            }),
        )
        .await;
    assert_eq!(status, 200, "close book: {closed}");
    assert_eq!(closed["state"], "Closed");
    assert_eq!(closed["closing_date"], "2026-12-31");

    // Drafting into a closed book is refused.
    let (status, body) = h
        .post_json(
            "/v1/acts",
            json!({ "book_id": book_id, "title": "Tardia", "channel": "Physical" }),
        )
        .await;
    assert_eq!(status, 409, "draft into closed book: {body}");
    assert!(body["error"].is_string());

    let (status, verify) = h.get_json("/v1/ledger/verify").await;
    assert_eq!(status, 200);
    assert_eq!(verify["valid"], true);
}
