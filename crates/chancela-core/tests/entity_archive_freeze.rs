//! Archiving an entity moves no digest, and an archived entity can still name its own parties.
//!
//! Two guarantees are pinned here, and they are separate things.
//!
//! # 1. The `Entity` payload shape is frozen for an active entity
//!
//! `Entity` is a ledger payload: it is serialized **whole** as the digest preimage of
//! `entity.created` (`chancela-api/src/entities.rs`, `create_entity`), of `entity.statute_updated`
//! (same module), and of the entity genesis appended on the certidão-permanente import path
//! (`chancela-api/src/registry.rs`, `import_from_registry`). All three call the same `Serialize`
//! impl, so freezing the shape **here**, in the core, proves the property for all three by
//! construction. An API-level assertion on the `entity.created` payload alone would pass while the
//! registry-import digest silently moved — which is why this test is not written there.
//!
//! # 2. Archiving cannot reach the evidentiary chain — and the chain is not where it looks
//!
//! The reason a sealed act can still name the parties of an archived entity is **not** that the act
//! carries their identity. It does not: `ActPayload` — the act's canonical digest preimage in
//! `chancela-core/src/seal.rs` — has zero entity-identity fields. Party identity is frozen one level
//! up, at book opening:
//!
//! ```text
//! act.book_id  ->  Book.termo_abertura  ->  TermoDeAbertura { entity_name, entity_nipc, entity_seat }
//! ```
//!
//! and `TermoDeAbertura` **is** the `book.opened` genesis digest preimage — `open_and_seal_book`
//! serializes it directly, whose own doc forbids reordering, renaming or removing a field there. So
//! the identity of an act's parties is a documented snapshot taken when the book was opened, and the
//! entity row is not consulted to produce it.
//!
//! **A test that looked for the party name inside the act's preimage would be asserting something
//! that was never there.** If one of these fails, the repair is not to relax the assertion: read the
//! chain above and find out which link moved.

use chancela_core::{
    Act, ActId, ActState, AgendaItem, Book, BookId, BookKind, Entity, EntityId, EntityKind,
    MeetingChannel, Nipc, NumberingScheme, TermoDeAbertura, act::ManualSignatureOriginalReference,
    open_and_seal_book, rule_pack_for, seal_act,
};
use chancela_ledger::Ledger;
use time::macros::{date, datetime, time};
use uuid::Uuid;

fn fixed(byte: u8) -> Uuid {
    Uuid::from_bytes([byte; 16])
}

/// A wholly deterministic entity: fixed identifier, no random component, so every preimage below is
/// a pure function of the domain types.
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

/// The termo that freezes party identity at opening. Built from the entity's *current* values, which
/// is exactly the point: after this moment the snapshot is the record, not the entity row.
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
    for state in [
        ActState::Review,
        ActState::Convened,
        ActState::Deliberated,
        ActState::TextApproved,
        ActState::Signing,
    ] {
        act.advance_to(state).unwrap();
    }
    act
}

fn manual_reference() -> ManualSignatureOriginalReference {
    ManualSignatureOriginalReference {
        storage_reference: "Arquivo A / Pasta 2026 / Ata 1".to_owned(),
        custodian: None,
        note: None,
    }
}

/// Open a deterministic book on `entity` and return the `book.opened` genesis event's payload digest
/// alongside the scope it was appended under.
fn open_book_genesis(entity: &Entity) -> (Book, Ledger, [u8; 32], String) {
    let mut book = deterministic_book(entity);
    let mut ledger = Ledger::default();
    open_and_seal_book(
        &mut book,
        entity,
        abertura(entity),
        "sec@encosto",
        &mut ledger,
    )
    .expect("the deterministic book opens");
    let genesis = &ledger.events()[0];
    assert_eq!(genesis.kind, "book.opened");
    let digest = genesis.payload_digest;
    let scope = genesis.scope.clone();
    (book, ledger, digest, scope)
}

// ---------------------------------------------------------------------------------------------
// 1. Payload shape freeze — protects all three whole-`Entity` ledger payload sites at once.
// ---------------------------------------------------------------------------------------------

#[test]
fn an_active_entity_emits_no_archived_at_bytes() {
    // The whole mitigation for the digest hazard. `skip_serializing_if = "Option::is_none"` means an
    // active entity serializes byte-identically to the pre-archiving shape, so neither an existing
    // digest nor any future digest of an active entity moves.
    let entity = deterministic_entity();
    let json = serde_json::to_string(&entity).expect("serializes");
    assert!(
        !json.contains("archived_at"),
        "an active entity must emit no bytes for archiving — every future entity-event digest \
         (entity.created, entity.statute_updated, and the certidão-import genesis) depends on it: \
         {json}"
    );
}

#[test]
fn the_active_entity_preimage_is_byte_identical_to_the_pre_archiving_shape() {
    // Stronger than "no `archived_at` key": the *whole* preimage, byte for byte, including field
    // order. Serde emits struct fields in declaration order, so a field inserted anywhere but the end
    // would reorder the JSON and move every future digest even while the key stayed absent.
    let entity = deterministic_entity();
    let bytes = serde_json::to_vec(&entity).expect("serializes");
    assert_eq!(
        String::from_utf8(bytes).unwrap(),
        concat!(
            r#"{"id":"11111111-1111-1111-1111-111111111111","#,
            r#""tenant_id":"74656e61-6e74-0000-0000-000000000001","#,
            r#""name":"Encosto Estratégico, S.A.","#,
            r#""nipc":"503004642","#,
            r#""seat":"Lisboa","#,
            r#""family":"CommercialCompany","#,
            r#""kind":"SociedadeAnonima","#,
            // `statute` carries `#[serde(default)]` **without** `skip_serializing_if`, so it emits
            // `null` rather than nothing. That is exactly the shape `archived_at` must not copy:
            // an always-emitting optional is what moves every future digest.
            r#""statute":null}"#,
        ),
        "the `Entity` ledger-payload preimage moved — every future entity-event digest at \
         entities.rs (entity.created, entity.statute_updated) and registry.rs (certidão import) \
         moves with it. Re-derive this literal only after deciding that is intended."
    );
}

#[test]
fn only_an_archived_entity_carries_the_key_and_it_is_appended_last() {
    // Archived entities do move a digest — but only ones minted after a separately ledgered archive
    // event, never a historical one. The key must land at the end so the preimage of every field
    // that existed before it is unchanged.
    let mut entity = deterministic_entity();
    let active = serde_json::to_string(&entity).expect("serializes");
    entity.archive(datetime!(2026-07-27 09:30:00 UTC)).unwrap();
    let archived = serde_json::to_string(&entity).expect("serializes");

    assert_eq!(
        archived,
        format!(
            "{},\"archived_at\":\"2026-07-27T09:30:00Z\"}}",
            active.trim_end_matches('}')
        ),
        "archiving must append to the preimage, never insert into it"
    );
}

// ---------------------------------------------------------------------------------------------
// 2. The evidentiary chain — where party identity actually lives, and that archiving cannot reach it.
// ---------------------------------------------------------------------------------------------

#[test]
fn archiving_an_entity_cannot_move_the_book_opened_genesis_preimage() {
    // The genesis preimage is the `TermoDeAbertura`, not the entity: `open_and_seal_book` serializes
    // the termo the book now holds, and consults the entity only for the scope's ids. So the same
    // book opened on an archived entity produces the identical `book.opened` payload digest under
    // the identical scope. This is the guarantee the plan forbids anyone from touching.
    let active = deterministic_entity();
    let mut archived = deterministic_entity();
    archived
        .archive(datetime!(2026-07-27 09:30:00 UTC))
        .unwrap();

    let (_, _, active_digest, active_scope) = open_book_genesis(&active);
    let (_, _, archived_digest, archived_scope) = open_book_genesis(&archived);

    assert_eq!(
        active_digest, archived_digest,
        "the book.opened genesis preimage moved when the entity was archived — the frozen party \
         identity of every already-opened book is now irreproducible"
    );
    assert_eq!(active_scope, archived_scope);
}

#[test]
fn an_archived_entitys_party_identity_still_reads_off_the_books_frozen_termo() {
    // The chain, walked: the book keeps its `TermoDeAbertura`, so name/NIPC/seat are readable
    // directly off the book forever — without consulting the entity row and without replaying the
    // ledger. Archiving the entity afterwards changes none of it.
    let mut entity = deterministic_entity();
    let (book, _ledger, _digest, _scope) = open_book_genesis(&entity);

    entity.archive(datetime!(2026-07-27 09:30:00 UTC)).unwrap();
    assert!(entity.is_archived());

    let frozen = book
        .termo_abertura
        .as_ref()
        .expect("an opened book retains its termo de abertura");
    assert_eq!(frozen.entity_name, "Encosto Estratégico, S.A.");
    assert_eq!(frozen.entity_nipc, "503004642");
    assert_eq!(frozen.entity_seat, "Lisboa");
}

#[test]
fn a_sealed_act_seals_identically_whether_or_not_its_entity_is_archived() {
    // `ActPayload` carries no entity-identity fields at all, and `SealMetadata` is built from two
    // `Copy` enums (`entity.family`, `entity.kind`) rather than from the `Entity` struct — so
    // neither the sealed act's digest nor its recorded profile can notice archiving.
    let seal_digest = |entity: &Entity| {
        let mut book = deterministic_book(entity);
        let mut ledger = Ledger::default();
        open_and_seal_book(
            &mut book,
            entity,
            abertura(entity),
            "sec@encosto",
            &mut ledger,
        )
        .unwrap();
        let pack = rule_pack_for(entity);
        let mut act = clean_act();
        let outcome = seal_act(
            &mut book,
            &mut act,
            entity,
            &*pack,
            "sec@encosto",
            true,
            Some(manual_reference()),
            &mut ledger,
        )
        .expect("the fixture act must seal");
        assert_eq!(act.state, ActState::Sealed);
        (outcome.payload_digest, outcome.seal_metadata)
    };

    let active = deterministic_entity();
    let mut archived = deterministic_entity();
    archived
        .archive(datetime!(2026-07-27 09:30:00 UTC))
        .unwrap();

    let (active_digest, active_metadata) = seal_digest(&active);
    let (archived_digest, archived_metadata) = seal_digest(&archived);

    assert_eq!(
        active_digest, archived_digest,
        "the act seal preimage must not notice the entity's archive state"
    );
    assert_eq!(
        active_metadata, archived_metadata,
        "the recorded rule-pack/profile evidence is built from `family` and `kind`, not from the \
         `Entity` struct, so archiving must not perturb it"
    );
}

#[test]
fn an_entity_archived_before_a_book_is_opened_still_freezes_its_identity() {
    // The termo snapshot is taken from whatever the entity is at opening. Even in the order the
    // domain forbids at the API layer (a book opened on an already-archived entity), nothing about
    // the frozen identity or the genesis preimage degrades — archiving is not a data change.
    let mut entity = deterministic_entity();
    entity.archive(datetime!(2026-07-27 09:30:00 UTC)).unwrap();

    let (book, _ledger, _digest, _scope) = open_book_genesis(&entity);
    let frozen = book.termo_abertura.as_ref().expect("termo retained");
    assert_eq!(frozen.entity_name, entity.name);
    assert_eq!(frozen.entity_nipc, entity.nipc.to_string());
    assert_eq!(frozen.entity_seat, entity.seat);
}
