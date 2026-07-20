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

    // Draft an ata, fill its contents, and advance it to Signing.
    let act_id = draft_act(&h, &book_id, "Ata da Assembleia Geral Anual", Some(&token)).await;
    fill_act_contents(&h, &act_id, &token).await;
    advance_to_signing(&h, &act_id, Some(&token)).await;

    // The fully-filled CSC ata (mesa/time/agenda all set via the wire, t31) has no findings, so
    // the compliance gate permits the seal.
    let (status, comp) = h.get_json(&format!("/v1/acts/{act_id}/compliance")).await;
    assert_eq!(status, 200);
    assert_eq!(comp["rule_pack"], "csc-art63/v2");
    assert_eq!(comp["errors"], 0);
    assert_eq!(comp["seal_allowed"], true);

    // Seal → ata #1, Sealed, a 64-hex payload digest. No warnings to acknowledge.
    let (status, sealed) = h
        .post_json_auth(
            &format!("/v1/acts/{act_id}/seal"),
            manual_signature_seal_body("Arquivo E2E / Ata AG anual"),
            &token,
        )
        .await;
    assert_eq!(status, 200, "seal: {sealed}");
    assert_eq!(sealed["ata_number"], 1);
    assert_eq!(sealed["act"]["state"], "Sealed");
    assert_eq!(sealed["payload_digest"].as_str().expect("digest").len(), 64);

    // t48/DOC-01: the seal produced a PDF/A-2u document — the response names its id, digest, and
    // the pinned template version.
    let doc = &sealed["document"];
    assert_eq!(doc["template_id"], "csc-ata-ag/v1", "sealed doc: {sealed}");
    assert_eq!(doc["pdf_digest"].as_str().expect("pdf digest").len(), 64);
    assert!(doc["id"].is_string());

    // The document is bound into the tamper-evident chain (a `document.generated` event).
    let (status, events) = h.get_json("/v1/ledger/events").await;
    assert_eq!(status, 200);
    assert!(
        events
            .as_array()
            .expect("events")
            .iter()
            .any(|e| e["kind"] == "document.generated"),
        "the seal appended a document.generated event: {events}"
    );

    // The DOC-03 bundle is preserved (PDF bytes + metadata + technical validation report).
    let (status, bundle) = h
        .get_json(&format!("/v1/acts/{act_id}/document/bundle"))
        .await;
    assert_eq!(status, 200, "bundle: {bundle}");
    assert_eq!(bundle["pdf"]["media_type"], "application/pdf");
    assert!(bundle["pdf"]["byte_length"].as_u64().expect("length") > 0);
    assert_document_bundle_validation_report(&bundle, &act_id);

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
        .post_json_auth(
            &format!("/v1/books/{book_id}/close"),
            json!({
                "reason": "BookFull",
                "closing_date": "2026-12-31",
                "required_signatories": ["Administrador"],
            }),
            &token,
        )
        .await;
    assert_eq!(status, 200, "close book: {closed}");
    assert_eq!(closed["state"], "Closed");
    assert_eq!(closed["closing_date"], "2026-12-31");

    // t53: closing the book generated the family's termo de encerramento in the SAME commit as
    // book.closed — a book-scoped `document.generated` event and a preserved, retrievable PDF/A.
    let (status, events) = h.get_json("/v1/ledger/events").await;
    assert_eq!(status, 200);
    let book_doc_events = events
        .as_array()
        .expect("events")
        .iter()
        .filter(|e| {
            e["kind"] == "document.generated"
                && e["scope"]
                    .as_str()
                    .is_some_and(|s| s.contains(&format!("book:{book_id}")) && !s.contains("/act:"))
        })
        .count();
    assert!(
        book_doc_events >= 2,
        "book-open abertura + book-close encerramento document events: {events}"
    );
    // The encerramento is the latest document for the book key (a real csc-termo-encerramento/v1).
    let (status, bundle) = h
        .get_json(&format!("/v1/acts/{book_id}/document/bundle"))
        .await;
    assert_eq!(status, 200, "encerramento bundle: {bundle}");
    assert_eq!(
        bundle["document"]["template_id"], "csc-termo-encerramento/v1",
        "book-close produced the termo de encerramento document: {bundle}"
    );

    // Drafting into a closed book is refused.
    let (status, body) = h
        .post_json_auth(
            "/v1/acts",
            json!({ "book_id": book_id, "title": "Tardia", "channel": "Physical" }),
            &token,
        )
        .await;
    assert_eq!(status, 409, "draft into closed book: {body}");
    assert!(body["error"].is_string());

    let (status, verify) = h.get_json("/v1/ledger/verify").await;
    assert_eq!(status, 200);
    assert_eq!(verify["valid"], true);
}
