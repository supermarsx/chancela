//! Serde back-compatibility proofs (t31 §3).
//!
//! Wave A persists aggregates as document-in-relational JSON blobs, so an **old-shape** row
//! (written before Wave B added the mesa / agenda / statute / structured-deliberation fields)
//! MUST still deserialize, with every new field taking its default. These tests pin that with
//! hardcoded old-shape JSON string literals, mirroring the in-crate
//! `deserialized_entity_with_mismatched_family_is_inconsistent` test.

use chancela_core::{
    Act, ActState, Book, BookKind, Entity, EntityId, EntityKind, MeetingChannel, Nipc,
    TermoDeAbertura, open_and_seal_book, rule_pack_for, seal_act,
};
use chancela_ledger::Ledger;
use time::macros::{date, time};

/// A Wave-A act JSON: no `meeting_time`, `mesa`, `agenda`, `referenced_documents`,
/// `deliberation_items`, `members_present`/`members_represented`; attachments without
/// `beginning_of_proof`; signatories without `permilage`.
const OLD_SHAPE_ACT_JSON: &str = r#"{
    "id": "00000000-0000-0000-0000-000000000001",
    "book_id": "00000000-0000-0000-0000-000000000002",
    "title": "Ata antiga",
    "channel": "Physical",
    "meeting_date": null,
    "place": "Sede social",
    "attendance_reference": "Lista de presenças",
    "deliberations": "Aprovado o relatório de gestão.",
    "telematic_evidence": null,
    "attachments": [{ "label": "Anexo", "kind": "Exhibit", "digest": null }],
    "signatories": [{ "name": "Ana", "capacity": "Chair", "signed": false }],
    "state": "Draft",
    "ata_number": null,
    "payload_digest": null,
    "seal_event_seq": null,
    "retifies": null
}"#;

/// A v1 entity JSON: no `statute` key, bare-string `nipc`.
const OLD_SHAPE_ENTITY_JSON: &str = r#"{
    "id": "00000000-0000-0000-0000-000000000003",
    "name": "Sociedade X, S.A.",
    "nipc": "503004642",
    "seat": "Lisboa",
    "family": "CommercialCompany",
    "kind": "SociedadeAnonima"
}"#;

#[test]
fn old_shape_act_json_deserializes_with_defaults() {
    let act: Act = serde_json::from_str(OLD_SHAPE_ACT_JSON).expect("old-shape act deserializes");

    // Every new field takes its default.
    assert_eq!(act.meeting_time, None);
    assert_eq!(act.mesa.presidente, None);
    assert!(act.mesa.secretarios.is_empty());
    assert!(act.agenda.is_empty());
    assert!(act.referenced_documents.is_empty());
    assert!(act.deliberation_items.is_empty());
    assert_eq!(act.members_present, None);
    assert_eq!(act.members_represented, None);
    assert!(!act.attachments[0].beginning_of_proof);
    assert_eq!(act.signatories[0].permilage, None);

    // The free-text substance is intact and the act is still mutable / usable.
    assert_eq!(act.deliberations, "Aprovado o relatório de gestão.");
    assert_eq!(act.state, ActState::Draft);
    assert!(act.is_mutable());
}

#[test]
fn old_shape_entity_json_deserializes_with_statute_none() {
    let entity: Entity =
        serde_json::from_str(OLD_SHAPE_ENTITY_JSON).expect("old-shape entity deserializes");
    assert!(entity.statute.is_none());
    assert!(
        entity.nipc.is_validated(),
        "a bare-string NIPC is validated"
    );
    assert!(entity.is_consistent());
}

#[test]
fn default_new_shape_act_round_trips() {
    let book = Book::new(EntityId::new(), BookKind::AssembleiaGeral);
    let act = Act::draft(book.id, "Ata", MeetingChannel::Physical);
    let json = serde_json::to_string(&act).unwrap();
    let back: Act = serde_json::from_str(&json).unwrap();
    assert_eq!(act, back);
}

#[test]
fn default_new_shape_entity_round_trips() {
    let entity = Entity::new(
        "Sociedade Y, S.A.",
        Nipc::parse("503004642").unwrap(),
        "Porto",
        EntityKind::SociedadeAnonima,
    );
    let json = serde_json::to_string(&entity).unwrap();
    let back: Entity = serde_json::from_str(&json).unwrap();
    assert_eq!(entity, back);
    assert!(back.statute.is_none());
}

#[test]
fn structured_new_shape_act_round_trips() {
    use chancela_core::{
        AgendaItem, DeliberationItem, DocumentReference, MemberStatement, VoteResult,
    };
    let book = Book::new(EntityId::new(), BookKind::AssembleiaGeral);
    let mut act = Act::draft(book.id, "Ata estruturada", MeetingChannel::Telematic);
    act.meeting_date = Some(date!(2026 - 05 - 04));
    act.meeting_time = Some(time!(14:30));
    act.mesa.presidente = Some("Ana".into());
    act.mesa.secretarios = vec!["Rui".into()];
    act.agenda = vec![AgendaItem {
        number: 1,
        text: "Contas".into(),
    }];
    act.referenced_documents = vec![DocumentReference {
        label: "Relatório".into(),
        reference: Some("REG-1".into()),
    }];
    act.members_present = Some(12);
    act.members_represented = Some(3);
    act.deliberation_items = vec![DeliberationItem {
        agenda_number: Some(1),
        text: "Aprovado.".into(),
        vote: Some(VoteResult::Recorded {
            em_favor: 12,
            contra: 2,
            abstencoes: 1,
        }),
        statements: vec![MemberStatement {
            member: "Rui".into(),
            text: "Voto vencido.".into(),
        }],
    }];
    let json = serde_json::to_string(&act).unwrap();
    let back: Act = serde_json::from_str(&json).unwrap();
    assert_eq!(act, back);
}

#[test]
fn free_text_only_act_still_seals_under_csc_v2() {
    // R3 fallback: an act with free-text `deliberations` (no `deliberation_items`) plus the
    // scalar mandatory fields and a mesa chair seals clean under the dispatched CSC v2 pack.
    let entity = Entity::new(
        "Encosto Estratégico, S.A.",
        Nipc::parse("503004642").unwrap(),
        "Lisboa",
        EntityKind::SociedadeAnonima,
    );
    let mut ledger = Ledger::default();
    let mut book = Book::new(entity.id, BookKind::AssembleiaGeral);
    open_and_seal_book(
        &mut book,
        &entity,
        TermoDeAbertura {
            entity_name: entity.name.clone(),
            entity_nipc: entity.nipc.to_string(),
            entity_seat: entity.seat.clone(),
            purpose: "livro de atas".into(),
            numbering_scheme: chancela_core::NumberingScheme::Sequential,
            opening_date: date!(2026 - 01 - 15),
            required_signatories: vec!["Administrador".into()],
        },
        "sec@encosto",
        &mut ledger,
    )
    .unwrap();

    let mut act = Act::draft(book.id, "Ata da AG", MeetingChannel::Physical);
    act.meeting_date = Some(date!(2026 - 03 - 30));
    act.meeting_time = Some(time!(10:00));
    act.place = Some("Sede social".into());
    act.mesa.presidente = Some("Ana Presidente".into());
    act.mesa.secretarios = vec!["Rui Secretário".into()];
    act.agenda = vec![chancela_core::AgendaItem {
        number: 1,
        text: "Contas".into(),
    }];
    act.attendance_reference = Some("Lista de presenças".into());
    act.deliberations = "Aprovadas as contas do exercício.".into(); // free-text only
    assert!(act.deliberation_items.is_empty());
    for state in [
        ActState::Review,
        ActState::Convened,
        ActState::Deliberated,
        ActState::TextApproved,
        ActState::Signing,
    ] {
        act.advance_to(state).unwrap();
    }

    let pack = rule_pack_for(&entity);
    let outcome = seal_act(
        &mut book,
        &mut act,
        &entity,
        &*pack,
        "sec@encosto",
        false, // no warnings to acknowledge
        &mut ledger,
    )
    .expect("free-text-only act should seal clean under CSC v2");
    assert_eq!(outcome.ata_number, 1);
    assert_eq!(act.state, ActState::Sealed);
    assert!(outcome.acknowledged_warnings.is_empty());
}
