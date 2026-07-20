//! The frozen seal digest, pinned end to end through the public sealing API.
//!
//! A sealed act's `payload_digest` is the sha-256 of a JSON preimage, and that digest is already
//! recorded in its book's hash chain. The preimage is therefore not an implementation detail free
//! to be reshaped: adding, removing or reordering a field — or letting an optional field emit
//! bytes it used to skip — invalidates every frozen digest at once.
//!
//! The in-crate tests in `seal.rs` prove that property against the private `ActPayload`. These
//! prove it against what a caller can actually observe: seal a fully deterministic act through
//! `seal_act` and compare the digest the ledger froze to a **literal** recorded when the optional
//! append-only fields (`convening`, `attendees`, `page_count`, `superseded_signing_snapshots`,
//! `convening_waiver`) did not exist or did not apply.
//!
//! **A failure here is a chain-compatibility break, not a stale fixture.** Re-derive the constant
//! only after deciding the change is intended and that already-sealed acts' digests may cease to
//! be reproducible.

use chancela_core::{
    Act, ActId, ActState, AgendaItem, Book, BookId, BookKind, ConveningWaiver, Entity, EntityId,
    EntityKind, MeetingChannel, Nipc, NoConveningBasis, NumberingScheme, SupersededSigningSnapshot,
    TermoDeAbertura, act::ManualSignatureOriginalReference, open_and_seal_book, rule_pack_for,
    seal_act,
};
use chancela_ledger::Ledger;
use time::OffsetDateTime;
use time::macros::{date, time};
use uuid::Uuid;

/// The digest a clean act — one carrying none of the optional append-only fields — seals to.
///
/// See the module docs before changing this.
const CLEAN_ACT_SEAL_DIGEST: &str =
    "1e3e76e7aa223644de478433edad311821d38c27b47de524793f06a7994ee2ae";

fn fixed(byte: u8) -> Uuid {
    Uuid::from_bytes([byte; 16])
}

/// A wholly deterministic entity/book/act triple: fixed identifiers, fixed dates, no random
/// component anywhere, so the seal digest is a pure function of the domain types.
fn deterministic_entity() -> Entity {
    let mut entity = Entity::new(
        "Encosto Estratégico, S.A.",
        Nipc::parse("503004642").unwrap(),
        "Lisboa",
        EntityKind::SociedadeAnonima,
    );
    entity.id = EntityId(fixed(0x11));
    entity
}

fn deterministic_book(entity: &Entity) -> Book {
    let mut book = Book::new(entity.id, BookKind::AssembleiaGeral);
    book.id = BookId(fixed(0x22));
    book
}

fn abertura(entity: &Entity) -> TermoDeAbertura {
    TermoDeAbertura {
        entity_name: entity.name.clone(),
        entity_nipc: entity.nipc.to_string(),
        entity_seat: entity.seat.clone(),
        purpose: "livro de atas da assembleia geral".into(),
        numbering_scheme: NumberingScheme::Sequential,
        opening_date: date!(2026 - 01 - 15),
        required_signatories: vec!["Administrador".into()],
        required_signatory_records: Vec::new(),
        ..TermoDeAbertura::default()
    }
}

/// An ata that seals clean under the dispatched CSC pack and carries **none** of the optional
/// append-only fields. This is the shape every act sealed before those fields existed had, so its
/// digest must still be the digest they were frozen with.
fn clean_act() -> Act {
    let mut act = Act::draft(
        BookId(fixed(0x22)),
        "Ata da assembleia geral anual",
        MeetingChannel::Physical,
    );
    act.id = ActId(fixed(0x33));
    act.meeting_date = Some(date!(2026 - 03 - 30));
    act.meeting_time = Some(time!(10:00));
    act.place = Some("Sede social".into());
    act.attendance_reference = Some("Lista de presenças anexa".into());
    act.mesa.presidente = Some("Amélia Marques".into());
    act.mesa.secretarios = vec!["Rui Ferreira".into()];
    act.agenda = vec![AgendaItem {
        number: 1,
        text: "Relatório de gestão e contas do exercício".into(),
    }];
    act.deliberations = "Aprovadas as contas do exercício.".into();
    act
}

fn advance_to_signing(act: &mut Act) {
    for state in [
        ActState::Review,
        ActState::Convened,
        ActState::Deliberated,
        ActState::TextApproved,
        ActState::Signing,
    ] {
        act.advance_to(state).unwrap();
    }
}

fn manual_reference() -> ManualSignatureOriginalReference {
    ManualSignatureOriginalReference {
        storage_reference: "Arquivo A / Pasta 2026 / Ata 1".to_owned(),
        custodian: None,
        note: None,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Seal `act` into a fresh deterministic book and return its frozen payload digest, hex-encoded.
fn seal_and_return_digest(act: &mut Act) -> String {
    let entity = deterministic_entity();
    let mut book = deterministic_book(&entity);
    let mut ledger = Ledger::default();
    open_and_seal_book(
        &mut book,
        &entity,
        abertura(&entity),
        "sec@encosto",
        &mut ledger,
    )
    .unwrap();
    let pack = rule_pack_for(&entity);
    let outcome = seal_act(
        &mut book,
        act,
        &entity,
        &*pack,
        "sec@encosto",
        // Warnings are acknowledged so a fixture variant that raises one still reaches the seal;
        // acknowledgement is recorded on the outcome and is not part of the preimage.
        true,
        Some(manual_reference()),
        &mut ledger,
    )
    .expect("the fixture act must seal");
    assert_eq!(
        act.payload_digest,
        Some(outcome.payload_digest),
        "the digest frozen on the act is the one the ledger recorded"
    );
    hex(&outcome.payload_digest)
}

#[test]
fn a_clean_act_seals_to_its_frozen_golden_digest() {
    let mut act = clean_act();
    advance_to_signing(&mut act);
    assert_eq!(
        seal_and_return_digest(&mut act),
        CLEAN_ACT_SEAL_DIGEST,
        "the seal preimage moved — every already-frozen act digest is now irreproducible"
    );
    assert_eq!(act.state, ActState::Sealed);
}

#[test]
fn an_act_that_was_reopened_seals_carrying_that_history_and_a_clean_one_does_not() {
    // Two halves of one guarantee, both observed through the public seal. An act reopened for
    // correction must seal binding the snapshot its reopen retired — so the regression travels
    // with the instrument rather than being hidden by it. An act never reopened must emit no bytes
    // for that history, which is what keeps the golden digest above reachable at all.
    let mut reopened = clean_act();
    advance_to_signing(&mut reopened);

    let released = reopened
        .reopen_for_correction()
        .expect("a Signing act with no collected signature reopens");
    assert_eq!(released, None, "this fixture froze no page count");
    assert_eq!(reopened.state, ActState::TextApproved);
    reopened.record_superseded_signing_snapshot(SupersededSigningSnapshot {
        document_id: "doc-retirado-1".to_owned(),
        pdf_digest: "aa".repeat(32),
        actor: "amelia.marques".to_owned(),
        superseded_at: OffsetDateTime::UNIX_EPOCH,
        reason: "mesa em falta".to_owned(),
    });
    // The correction the reopen exists for, then back out for signature.
    reopened
        .set_deliberations("Aprovadas as contas do exercício, com a redação corrigida.")
        .unwrap();
    reopened.advance_to(ActState::Signing).unwrap();

    let reopened_digest = seal_and_return_digest(&mut reopened);
    assert_ne!(
        reopened_digest, CLEAN_ACT_SEAL_DIGEST,
        "a retired signing snapshot must bind into the seal"
    );

    // And the never-reopened act is untouched by the existence of the field.
    let mut untouched = clean_act();
    advance_to_signing(&mut untouched);
    assert_eq!(
        seal_and_return_digest(&mut untouched),
        CLEAN_ACT_SEAL_DIGEST
    );
}

#[test]
fn a_reopened_act_binds_the_specific_snapshot_it_retired() {
    // Not merely "something was retired": *which* snapshot, and why. Otherwise a retirement record
    // could be rewritten under a frozen digest, which is the one thing the seal exists to prevent.
    let seal_with = |snapshot: SupersededSigningSnapshot| {
        let mut act = clean_act();
        advance_to_signing(&mut act);
        act.reopen_for_correction().unwrap();
        act.record_superseded_signing_snapshot(snapshot);
        act.advance_to(ActState::Signing).unwrap();
        seal_and_return_digest(&mut act)
    };
    let base = SupersededSigningSnapshot {
        document_id: "doc-retirado-1".to_owned(),
        pdf_digest: "aa".repeat(32),
        actor: "amelia.marques".to_owned(),
        superseded_at: OffsetDateTime::UNIX_EPOCH,
        reason: "mesa em falta".to_owned(),
    };
    let baseline = seal_with(base.clone());

    for (label, mutated) in [
        (
            "the retired document's identity",
            SupersededSigningSnapshot {
                document_id: "doc-retirado-2".to_owned(),
                ..base.clone()
            },
        ),
        (
            "the retired document's digest",
            SupersededSigningSnapshot {
                pdf_digest: "bb".repeat(32),
                ..base.clone()
            },
        ),
        (
            "the stated reason",
            SupersededSigningSnapshot {
                reason: "outro motivo".to_owned(),
                ..base.clone()
            },
        ),
        (
            "who retired it",
            SupersededSigningSnapshot {
                actor: "rui.ferreira".to_owned(),
                ..base.clone()
            },
        ),
    ] {
        assert_ne!(
            seal_with(mutated),
            baseline,
            "{label} must bind into the seal"
        );
    }
}

#[test]
fn a_convocatoria_waiver_binds_into_the_seal_and_its_absence_costs_nothing() {
    // The ata recites the ground on which a meeting was lawfully held without a convocatória, and
    // under CSC art. 56.º/1 a) that ground is what stands between a valid deliberação and a null
    // one. A seal that did not cover it would leave the most load-bearing — and most attractive to
    // alter — datum about the convening outside its own tamper-evidence.
    let seal_with = |waiver: Option<ConveningWaiver>| {
        let mut act = clean_act();
        act.convening_waiver = waiver;
        advance_to_signing(&mut act);
        seal_and_return_digest(&mut act)
    };

    // No waiver ⇒ byte-identical to the pre-field digest.
    assert_eq!(
        seal_with(None),
        CLEAN_ACT_SEAL_DIGEST,
        "an act with no waiver must emit no bytes for it"
    );

    let recorded = ConveningWaiver {
        basis: NoConveningBasis::AssembleiaUniversal,
        grounds: None,
        all_agreed_to_meet: true,
        all_agreed_to_agenda: true,
        evidence_reference: Some("Anexo I — declaração conjunta".into()),
    };
    let baseline = seal_with(Some(recorded.clone()));
    assert_ne!(
        baseline, CLEAN_ACT_SEAL_DIGEST,
        "a recorded no-convocatória basis must bind"
    );

    // The content binds, not merely the presence: what the operator declared cannot be swapped
    // under a frozen digest.
    for (label, mutated) in [
        (
            "the declared basis",
            ConveningWaiver {
                basis: NoConveningBasis::Other,
                grounds: Some("Outro fundamento.".into()),
                ..recorded.clone()
            },
        ),
        (
            "the stated ground",
            ConveningWaiver {
                basis: NoConveningBasis::Other,
                grounds: Some("Um fundamento diferente.".into()),
                ..recorded.clone()
            },
        ),
        (
            "the evidence reference",
            ConveningWaiver {
                evidence_reference: Some("Anexo II".into()),
                ..recorded.clone()
            },
        ),
    ] {
        assert_ne!(
            seal_with(Some(mutated)),
            baseline,
            "{label} must bind into the seal"
        );
    }
}

#[test]
fn withdrawing_either_limb_of_the_universal_assembly_agreement_refuses_the_seal() {
    // Stronger than "the digest changes": an assembleia universal whose recorded agreement is
    // incomplete cannot be sealed at all. CSC art. 54.º/1 conditions the mechanism on all agreeing
    // to the assembly constituting itself, and art. 54.º/2 narrows it to the matters consented to,
    // so each limb is a constitutive condition rather than a product preference. There is
    // therefore no sealed instrument in which one of them is missing for a later edit to move.
    let entity = deterministic_entity();
    let pack = rule_pack_for(&entity);

    for (label, waiver) in [
        (
            "agreement to constitute the assembly",
            ConveningWaiver {
                basis: NoConveningBasis::AssembleiaUniversal,
                grounds: None,
                all_agreed_to_meet: false,
                all_agreed_to_agenda: true,
                evidence_reference: None,
            },
        ),
        (
            "agreement to the matters deliberated",
            ConveningWaiver {
                basis: NoConveningBasis::AssembleiaUniversal,
                grounds: None,
                all_agreed_to_meet: true,
                all_agreed_to_agenda: false,
                evidence_reference: None,
            },
        ),
    ] {
        let mut book = deterministic_book(&entity);
        let mut ledger = Ledger::default();
        open_and_seal_book(
            &mut book,
            &entity,
            abertura(&entity),
            "sec@encosto",
            &mut ledger,
        )
        .unwrap();
        let mut act = clean_act();
        act.convening_waiver = Some(waiver);
        advance_to_signing(&mut act);

        let err = seal_act(
            &mut book,
            &mut act,
            &entity,
            &*pack,
            "sec@encosto",
            true, // even acknowledging every warning does not get past a blocking error
            Some(manual_reference()),
            &mut ledger,
        )
        .expect_err("an incomplete universal-assembly agreement must not seal");
        assert!(
            matches!(&err, chancela_core::SealError::ComplianceBlocked(message)
                if message.contains("CSC-54/universal-assembly-agreement")),
            "{label}: unexpected refusal {err:?}"
        );
        // Refused means nothing was minted: no ata number burnt, no seal event, act still Signing.
        assert_eq!(book.last_ata_number, 0);
        assert_eq!(ledger.events().len(), 1, "only the book genesis event");
        assert_eq!(act.state, ActState::Signing);
        assert!(act.payload_digest.is_none());
    }
}

#[test]
fn a_frozen_page_count_binds_and_an_absent_one_costs_nothing() {
    let mut counted = clean_act();
    advance_to_signing(&mut counted);
    counted.freeze_page_count(4).unwrap();
    assert_ne!(
        seal_and_return_digest(&mut counted),
        CLEAN_ACT_SEAL_DIGEST,
        "a frozen page count must bind"
    );
}
