//! Journey (t31 Wave B acceptance): per-family compliance is legally right, and it survives a
//! restart. These are the two headline proofs of `.orchestration/plans/t31.md` §5 — plus a cheap
//! statute-overlay leg — made permanent as composed-system journeys over the real server binary.
//!
//! 1. **A condominium ata is sealed by the DL 268/94 pack, NOT CSC-63.** A `Condominio` entity's ata
//!    (essential matters + a structured per-vote result) is checked by `condominio-dl268/v1`, which
//!    requires no mesa — so it seals with **no** presiding board, proving the gate is family-anchored
//!    (a CSC ata would block on the missing chair). After a restart the sealed ata keeps its number
//!    and payload digest, and compliance still dispatches to the condominium pack.
//! 2. **A CSC ata is blocked for a missing mesa, then passes once it is filled.** A
//!    `SociedadePorQuotas` ata complete in everything but the mesa is refused at the seal (422,
//!    `CSC-63/mesa-presidente` Error); a `PATCH` supplying the mesa clears the block and the seal
//!    succeeds; the sealed ata (mesa + number) survives a restart.
//! 3. **A statute overlay tightens the majority and drives the gate.** `PATCH`ing a 2/3 statutory
//!    majority onto the entity makes a 60%-in-favour vote fire `STATUTE/majority`; raising the vote
//!    to 70% clears it and the ata seals.

mod common;

use common::*;
use serde_json::json;

/// Headline proof #1 — a condominium is sealed by the CONDOMINIO pack, not CSC-63, and the
/// family-anchored gate + the sealed ata survive a restart.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg_attr(
    not(feature = "e2e"),
    ignore = "composed-system e2e: spawns the real server binary (run with --features e2e)"
)]
async fn condominium_is_sealed_by_the_condominio_pack_and_survives_restart() {
    let mut h = ServerHarness::start().await;

    let entity_id = create_entity(
        &h,
        "Condomínio do Edifício Liberdade",
        "503004642",
        "Lisboa",
        "Condominio",
    )
    .await;
    let book_id = open_book(&h, &entity_id).await;

    // A condominium ata: essential matters (free-text summary) PLUS a structured deliberation
    // carrying a per-vote result. It has NO mesa, NO agenda, NO meeting time — none of which the
    // DL 268/94 pack requires.
    let act_id = draft_act(&h, &book_id, "Ata da assembleia de condóminos", None).await;
    let (status, _) = h
        .patch_json(
            &format!("/v1/acts/{act_id}"),
            json!({
                "meeting_date": "2026-03-30",
                "place": "Hall do prédio",
                "attendance_reference": "Folha de presenças dos condóminos",
                "deliberations": "Aprovado o orçamento ordinário e o fundo comum de reserva.",
                "deliberation_items": [{
                    "agenda_number": null,
                    "text": "Aprovação do orçamento ordinário para 2026.",
                    "vote": { "type": "Recorded", "em_favor": 8, "contra": 2, "abstencoes": 0 },
                    "statements": []
                }],
            }),
        )
        .await;
    assert_eq!(status, 200, "patch condo ata contents");
    advance_to_signing(&h, &act_id, None).await;

    // The gate is the condominium pack — not CSC — and it clears the ata with no mesa.
    let (status, comp) = h.get_json(&format!("/v1/acts/{act_id}/compliance")).await;
    assert_eq!(status, 200);
    assert_eq!(
        comp["rule_pack"], "condominio-dl268/v1",
        "a condominium is gated by the DL 268/94 pack, not CSC-63: {comp}"
    );
    assert_ne!(comp["rule_pack"], "csc-art63/v2");
    assert_eq!(comp["family"], "Condominium");
    assert_eq!(comp["statute_overlay"], false);
    assert_eq!(comp["errors"], 0, "no CSC mesa/agenda Errors here: {comp}");
    assert_eq!(comp["seal_allowed"], true);

    // Seal with NO mesa and NO acknowledgement — the condo pack has nothing to flag.
    let (status, sealed) = h
        .post_json(&format!("/v1/acts/{act_id}/seal"), json!({}))
        .await;
    assert_eq!(status, 200, "condo seal without a mesa: {sealed}");
    assert_eq!(sealed["ata_number"], 1);
    let sealed_digest = sealed["payload_digest"]
        .as_str()
        .expect("digest")
        .to_owned();
    assert_eq!(sealed_digest.len(), 64);

    // --- RESTART over the same data dir --------------------------------------------------------
    h.restart().await;

    // The sealed ata kept its number, its payload digest, and its structured deliberation.
    let (status, act) = h.get_json(&format!("/v1/acts/{act_id}")).await;
    assert_eq!(status, 200, "sealed condo ata survived the restart: {act}");
    assert_eq!(act["state"], "Sealed");
    assert_eq!(act["ata_number"], 1);
    assert_eq!(
        act["payload_digest"], sealed_digest,
        "the condo ata's payload digest is intact across the restart"
    );
    assert!(act["mesa"]["presidente"].is_null(), "no mesa was ever set");
    let item = &act["deliberation_items"][0];
    assert_eq!(item["vote"]["type"], "Recorded");
    assert_eq!(
        item["vote"]["em_favor"], 8,
        "the structured per-vote result survived the restart: {act}"
    );

    // Compliance still dispatches to the family-anchored condominium pack after the restart.
    let (status, comp) = h.get_json(&format!("/v1/acts/{act_id}/compliance")).await;
    assert_eq!(status, 200);
    assert_eq!(
        comp["rule_pack"], "condominio-dl268/v1",
        "the family pack id is intact after the restart: {comp}"
    );

    let (status, verify) = h.get_json("/v1/ledger/verify").await;
    assert_eq!(status, 200);
    assert_eq!(verify["valid"], true);
}

/// Headline proof #2 — a CSC ata is refused for a missing mesa (422, `CSC-63/mesa-presidente`),
/// passes once the mesa is filled through the wire, and the sealed ata survives a restart.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg_attr(
    not(feature = "e2e"),
    ignore = "composed-system e2e: spawns the real server binary (run with --features e2e)"
)]
async fn csc_seal_blocked_without_mesa_then_passes_and_survives_restart() {
    let mut h = ServerHarness::start().await;

    let entity_id = create_entity(
        &h,
        "Encosto Estratégico, Lda",
        "503004642",
        "Lisboa",
        "SociedadePorQuotas",
    )
    .await;
    let book_id = open_book(&h, &entity_id).await;

    // A CSC ata complete in everything EXCEPT the mesa (time + agenda + place + attendance +
    // deliberations all present, so only the presiding board is missing).
    let act_id = draft_act(&h, &book_id, "Ata da Assembleia Geral Anual", None).await;
    let (status, _) = h
        .patch_json(
            &format!("/v1/acts/{act_id}"),
            json!({
                "meeting_date": "2026-03-30",
                "meeting_time": "10:00",
                "place": "Sede social",
                "agenda": [{ "number": 1, "text": "Aprovação das contas do exercício" }],
                "attendance_reference": "Lista de presenças anexa",
                "deliberations": "Aprovadas por unanimidade as contas do exercício de 2025.",
            }),
        )
        .await;
    assert_eq!(status, 200, "patch csc ata contents (no mesa)");
    advance_to_signing(&h, &act_id, None).await;

    // Compliance reports the blocking mesa Error and forbids the seal.
    let (status, comp) = h.get_json(&format!("/v1/acts/{act_id}/compliance")).await;
    assert_eq!(status, 200);
    assert_eq!(comp["rule_pack"], "csc-art63/v2");
    assert!(comp["errors"].as_u64().expect("errors") >= 1);
    assert_eq!(comp["seal_allowed"], false);
    assert!(
        comp["issues"]
            .as_array()
            .expect("issues")
            .iter()
            .any(|i| i["rule_id"] == "CSC-63/mesa-presidente" && i["severity"] == "Error"),
        "the blocking mesa Error is reported: {comp}"
    );

    // Sealing is refused with 422 and the refusal carries the mesa Error.
    let (status, body) = h
        .post_json(&format!("/v1/acts/{act_id}/seal"), json!({}))
        .await;
    assert_eq!(status, 422, "seal refused without a mesa: {body}");
    assert!(
        body["issues"]
            .as_array()
            .expect("issues")
            .iter()
            .any(|i| i["rule_id"] == "CSC-63/mesa-presidente"),
        "the seal refusal explains the missing mesa: {body}"
    );

    // Fill the mesa (presidente + secretários) through the wire.
    let (status, _) = h
        .patch_json(
            &format!("/v1/acts/{act_id}"),
            json!({
                "mesa": { "presidente": "Ana Presidente", "secretarios": ["Rui Secretário"] }
            }),
        )
        .await;
    assert_eq!(status, 200, "patch mesa onto the csc ata");

    // Compliance is clean(er): no more blocking Errors.
    let (status, comp) = h.get_json(&format!("/v1/acts/{act_id}/compliance")).await;
    assert_eq!(status, 200);
    assert_eq!(comp["errors"], 0, "the mesa Error is cleared: {comp}");
    assert_eq!(comp["seal_allowed"], true);
    // Acknowledge any residual advisory Warnings honestly (there should be none here — mesa, time,
    // agenda, secretaries all set and the NIPC is control-digit valid — but do not assume it).
    let ack = comp["warnings"].as_u64().expect("warnings") > 0;

    let (status, sealed) = h
        .post_json(
            &format!("/v1/acts/{act_id}/seal"),
            json!({ "acknowledge_warnings": ack }),
        )
        .await;
    assert_eq!(
        status, 200,
        "seal succeeds once the mesa is filled: {sealed}"
    );
    assert_eq!(sealed["ata_number"], 1);
    let sealed_digest = sealed["payload_digest"]
        .as_str()
        .expect("digest")
        .to_owned();
    assert_eq!(sealed_digest.len(), 64);

    // GET shows the sealed ata with its mesa and ata number.
    let (status, got) = h.get_json(&format!("/v1/acts/{act_id}")).await;
    assert_eq!(status, 200);
    assert_eq!(got["state"], "Sealed");
    assert_eq!(got["ata_number"], 1);
    assert_eq!(got["mesa"]["presidente"], "Ana Presidente");

    // --- RESTART over the same data dir --------------------------------------------------------
    h.restart().await;

    let (status, act) = h.get_json(&format!("/v1/acts/{act_id}")).await;
    assert_eq!(status, 200, "sealed csc ata survived the restart: {act}");
    assert_eq!(act["state"], "Sealed");
    assert_eq!(act["ata_number"], 1);
    assert_eq!(
        act["mesa"]["presidente"], "Ana Presidente",
        "the mesa survived the restart"
    );
    assert_eq!(
        act["payload_digest"], sealed_digest,
        "the csc ata's payload digest is intact across the restart"
    );

    let (status, verify) = h.get_json("/v1/ledger/verify").await;
    assert_eq!(status, 200);
    assert_eq!(verify["valid"], true);
}

/// The statute-overlay leg (ENT-03) — a 2/3 statutory majority makes a 60%-in-favour vote fire
/// `STATUTE/majority`; raising the vote to 70% clears it and the ata seals.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg_attr(
    not(feature = "e2e"),
    ignore = "composed-system e2e: spawns the real server binary (run with --features e2e)"
)]
async fn statute_two_thirds_majority_overlay_fires_then_clears() {
    let h = ServerHarness::start().await;

    let entity_id = create_entity(
        &h,
        "Encosto Estratégico, S.A.",
        "503004642",
        "Lisboa",
        "SociedadeAnonima",
    )
    .await;

    // PATCH a 2/3 statutory majority onto the entity; the overlay edit is audited on the chain.
    let (status, patched) = h
        .patch_json(
            &format!("/v1/entities/{entity_id}"),
            json!({ "statute": { "majority": { "numerator": 2, "denominator": 3 } } }),
        )
        .await;
    assert_eq!(status, 200, "patch statute majority: {patched}");
    assert_eq!(patched["statute"]["majority"]["numerator"], 2);
    assert_eq!(patched["statute"]["majority"]["denominator"], 3);
    assert!(
        ledger_kinds(&h)
            .await
            .iter()
            .any(|k| k == "entity.statute_updated"),
        "the statute overlay edit is on the audit chain"
    );

    let book_id = open_book(&h, &entity_id).await;
    let act_id = draft_act(&h, &book_id, "Ata — alteração ao contrato", None).await;

    // A structured vote of 60/40 (misses the 2/3 majority). The ata is otherwise complete so the
    // ONLY finding is the statute overlay's advisory.
    let patch_vote = |em_favor: u64, contra: u64| {
        json!({
            "meeting_date": "2026-03-30",
            "meeting_time": "10:00",
            "place": "Sede social",
            "mesa": { "presidente": "Ana Presidente", "secretarios": ["Rui Secretário"] },
            "agenda": [{ "number": 1, "text": "Alteração ao contrato de sociedade" }],
            "attendance_reference": "Lista de presenças",
            "deliberation_items": [{
                "agenda_number": 1,
                "text": "Deliberada a alteração ao contrato de sociedade.",
                "vote": { "type": "Recorded", "em_favor": em_favor, "contra": contra, "abstencoes": 0 },
                "statements": []
            }],
        })
    };
    let (status, _) = h
        .patch_json(&format!("/v1/acts/{act_id}"), patch_vote(60, 40))
        .await;
    assert_eq!(status, 200, "patch failing vote");
    advance_to_signing(&h, &act_id, None).await;

    // The overlay is active and its majority check fires on the 60% vote.
    let (status, comp) = h.get_json(&format!("/v1/acts/{act_id}/compliance")).await;
    assert_eq!(status, 200);
    assert_eq!(comp["statute_overlay"], true);
    assert!(
        comp["issues"]
            .as_array()
            .expect("issues")
            .iter()
            .any(|i| i["rule_id"] == "STATUTE/majority" && i["severity"] == "Warning"),
        "60/100 misses the 2/3 statutory majority: {comp}"
    );

    // Raise the vote to 70/30 — now it meets the 2/3 majority and the finding clears.
    let (status, _) = h
        .patch_json(&format!("/v1/acts/{act_id}"), patch_vote(70, 30))
        .await;
    assert_eq!(status, 200, "patch passing vote");
    let (status, comp) = h.get_json(&format!("/v1/acts/{act_id}/compliance")).await;
    assert_eq!(status, 200);
    assert!(
        !comp["issues"]
            .as_array()
            .expect("issues")
            .iter()
            .any(|i| i["rule_id"] == "STATUTE/majority"),
        "70/100 meets the 2/3 majority, so the overlay finding is gone: {comp}"
    );

    // The now-compliant ata seals (acknowledging any residual advisories honestly).
    let ack = comp["warnings"].as_u64().expect("warnings") > 0;
    let (status, sealed) = h
        .post_json(
            &format!("/v1/acts/{act_id}/seal"),
            json!({ "acknowledge_warnings": ack }),
        )
        .await;
    assert_eq!(status, 200, "the passing ata seals: {sealed}");
    assert_eq!(sealed["ata_number"], 1);

    let (status, verify) = h.get_json("/v1/ledger/verify").await;
    assert_eq!(status, 200);
    assert_eq!(verify["valid"], true);
}
