//! Serde back-compatibility proofs (t31 §3).
//!
//! Wave A persists aggregates as document-in-relational JSON blobs, so an **old-shape** row
//! (written before Wave B added the mesa / agenda / statute / structured-deliberation fields)
//! MUST still deserialize, with every new field taking its default. These tests pin that with
//! hardcoded old-shape JSON string literals, mirroring the in-crate
//! `deserialized_entity_with_mismatched_family_is_inconsistent` test.

use chancela_core::{
    Act, ActState, Book, BookKind, Entity, EntityId, EntityKind, MeetingChannel, Nipc,
    TermoDeAbertura, TermoDeEncerramento, act::ManualSignatureOriginalReference,
    open_and_seal_book, rule_pack_for, seal_act,
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

/// A pre-retention book JSON: no `legal_hold` key.
const OLD_SHAPE_BOOK_JSON: &str = r#"{
    "id": "00000000-0000-0000-0000-000000000004",
    "entity_id": "00000000-0000-0000-0000-000000000003",
    "kind": "AssembleiaGeral",
    "state": "Created",
    "termo_abertura": null,
    "termo_encerramento": null,
    "last_ata_number": 0,
    "predecessor": null
}"#;

/// A string-only termo de abertura JSON: no structured `required_signatory_records` key.
const OLD_SHAPE_TERMO_ABERTURA_JSON: &str = r#"{
    "entity_name": "Sociedade X, S.A.",
    "entity_nipc": "503004642",
    "entity_seat": "Lisboa",
    "purpose": "livro de atas",
    "numbering_scheme": "Sequential",
    "opening_date": [2026, 15],
    "required_signatories": ["Administrador"]
}"#;

/// A string-only termo de encerramento JSON: no structured records, no t8 tail.
const OLD_SHAPE_TERMO_ENCERRAMENTO_JSON: &str = r#"{
    "ata_count": 17,
    "reason": "BookFull",
    "closing_date": [2026, 365],
    "required_signatories": ["Gerente"]
}"#;

/// A pre-t8 **open** book JSON: no `book_number`, `page_capacity`, `pages_used` or
/// `pages_reserved` keys, and a termo carrying none of the instrument fields.
const PRE_T8_OPEN_BOOK_JSON: &str = r#"{
    "id": "00000000-0000-0000-0000-000000000005",
    "entity_id": "00000000-0000-0000-0000-000000000003",
    "kind": "GerenciaAdministracao",
    "state": "Open",
    "termo_abertura": {
        "entity_name": "Sociedade X, S.A.",
        "entity_nipc": "503004642",
        "entity_seat": "Lisboa",
        "purpose": "livro de atas",
        "numbering_scheme": "Sequential",
        "opening_date": [2020, 15],
        "required_signatories": ["Gerente"]
    },
    "termo_encerramento": null,
    "last_ata_number": 41,
    "predecessor": null
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
    assert!(act.seal_metadata.is_none());
    // t8/F15: an act that predates the capacity model has no frozen page count.
    assert_eq!(act.page_count, None);

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
fn old_shape_book_json_deserializes_with_no_legal_hold() {
    let book: Book =
        serde_json::from_str(OLD_SHAPE_BOOK_JSON).expect("old-shape book deserializes");
    assert!(book.legal_hold.is_none());
    // t8/F14: no capacity was ever declared, so the book is unlimited and its counters start
    // at zero rather than being invented from historical content.
    assert_eq!(book.book_number, None);
    assert_eq!(book.page_capacity, None);
    assert!(!book.has_page_capacity());
    assert_eq!(book.pages_used, 0);
    assert_eq!(book.pages_reserved, 0);
    assert_eq!(book.pages_remaining(), None);
}

#[test]
fn old_shape_termo_abertura_deserializes_with_no_structured_signatories() {
    let termo: TermoDeAbertura =
        serde_json::from_str(OLD_SHAPE_TERMO_ABERTURA_JSON).expect("old-shape termo deserializes");
    assert_eq!(termo.required_signatories, vec!["Administrador"]);
    assert!(termo.required_signatory_records.is_empty());
    // t8: the instrument tail is absent, so the termo is a purely *declared* one.
    assert_eq!(termo.termo_instrument_id, None);
    assert_eq!(termo.title, None);
    assert_eq!(termo.book_number, None);
    assert_eq!(termo.place, None);
    assert_eq!(termo.page_capacity, None);
    assert!(termo.body.is_empty());
    assert!(
        termo.collected_signatures.is_empty(),
        "a legacy termo has declared names, never collected signatures"
    );
}

#[test]
fn old_shape_termo_encerramento_deserializes_with_no_instrument_tail() {
    let termo: TermoDeEncerramento = serde_json::from_str(OLD_SHAPE_TERMO_ENCERRAMENTO_JSON)
        .expect("old-shape closing termo deserializes");
    assert_eq!(termo.ata_count, 17);
    assert!(termo.required_signatory_records.is_empty());
    assert_eq!(termo.termo_instrument_id, None);
    assert!(termo.body.is_empty());
    assert!(termo.collected_signatures.is_empty());
    assert_eq!(termo.pages_used_at_close, None);
}

#[test]
fn a_pre_t8_open_book_still_accepts_atas_without_limit() {
    // §7.3 rule 4, non-negotiable: a book opened before the capacity model must never suddenly
    // refuse an ata because a limit it never agreed to was invented for it.
    let mut book: Book =
        serde_json::from_str(PRE_T8_OPEN_BOOK_JSON).expect("pre-t8 open book deserializes");
    assert!(book.is_open());
    assert!(!book.has_page_capacity());
    assert!(!book.is_capacity_exhausted());

    for expected in 42..=60 {
        assert_eq!(book.assign_next_ata_number().unwrap(), expected);
        book.reserve_pages(25).unwrap();
        book.consume_reserved_pages(25).unwrap();
    }
    assert!(
        !book.is_capacity_exhausted(),
        "an unlimited book never exhausts"
    );
}

#[test]
fn a_pre_t8_book_round_trips_without_gaining_keys() {
    // Re-serializing a legacy book must not stamp t8 keys onto it: the stored JSON stays the
    // shape it was written in, so nothing downstream sees a spurious capacity.
    let book: Book = serde_json::from_str(PRE_T8_OPEN_BOOK_JSON).unwrap();
    let json = serde_json::to_string(&book).unwrap();
    for absent in [
        "page_capacity",
        "pages_used",
        "pages_reserved",
        "book_number",
        "termo_instrument_id",
        "collected_signatures",
    ] {
        assert!(!json.contains(absent), "{absent} must not appear: {json}");
    }
    let back: Book = serde_json::from_str(&json).unwrap();
    assert_eq!(book, back);
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
            required_signatory_records: Vec::new(),
            ..TermoDeAbertura::default()
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
        Some(ManualSignatureOriginalReference {
            storage_reference: "Arquivo A / Pasta 2026 / Ata antiga".to_owned(),
            custodian: None,
            note: None,
        }),
        &mut ledger,
    )
    .expect("free-text-only act should seal clean under CSC v2");
    assert_eq!(outcome.ata_number, 1);
    assert_eq!(act.state, ActState::Sealed);
    assert!(outcome.acknowledged_warnings.is_empty());
}
