//! Contracts that span two domain concepts and are therefore easy to leave untested inside either.
//!
//! Each of these pins a property that is stated somewhere in the code's own doc comments as a
//! guarantee to a caller, but whose two halves live in different modules — so no single unit test
//! naturally covers it.

use chancela_core::{
    Act, ActState, AgendaItem, Attendee, Book, BookKind, ComplianceIssue, ConveningWaiver,
    DEFAULT_PAGE_CAPACITY, Entity, EntityKind, MeetingChannel, Nipc, NoConveningBasis,
    NumberingScheme, PresenceMode, Severity, SignatoryCapacity, TermoDeAbertura, TermoFields,
    attendee_qualities, membership_qualities, rule_pack_for,
};
use time::macros::{date, time};

const EVERY_KIND: [EntityKind; 10] = [
    EntityKind::SociedadeEmNomeColetivo,
    EntityKind::SociedadePorQuotas,
    EntityKind::SociedadeUnipessoalPorQuotas,
    EntityKind::SociedadeAnonima,
    EntityKind::SociedadeEmComanditaSimples,
    EntityKind::SociedadeEmComanditaPorAcoes,
    EntityKind::Condominio,
    EntityKind::Associacao,
    EntityKind::Fundacao,
    EntityKind::Cooperativa,
];

fn entity(kind: EntityKind) -> Entity {
    Entity::new(
        "Encosto Estratégico, Lda",
        Nipc::parse("503004642").unwrap(),
        "Lisboa",
        kind,
    )
}

// --- attendee qualidade: derived from the membership term, not from a position in a list --------

/// The offered qualidades must be *derived* from `membership_qualities(kind)`, not recovered from
/// where a term happens to sit in the returned list.
///
/// This is the property the rules engine depends on: `no_convening_issues` decides whether an
/// absent attendee falsifies an assembleia universal by asking `membership_qualities` whether that
/// row is a member. If the two lists could disagree — if a picker offered *acionista* for an
/// entity whose membership term the rule pack believed to be *sócio* — an absent shareholder would
/// silently stop blocking, which is exactly the defect the article exists to catch. Asserting a
/// prefix rather than an index is what makes reordering the picker safe.
#[test]
fn the_offered_qualidades_begin_with_exactly_the_membership_terms_of_the_legal_type() {
    // The universe of every term that is a membership term *somewhere*. A kind's own list must
    // contain its own membership terms and none of the others'.
    let all_membership: Vec<SignatoryCapacity> = {
        let mut terms: Vec<SignatoryCapacity> = EVERY_KIND
            .iter()
            .flat_map(|kind| membership_qualities(*kind))
            .collect();
        terms.sort_by_key(|c| format!("{c:?}"));
        terms.dedup();
        terms
    };
    assert!(
        all_membership.len() >= 5,
        "the fixture must span several distinct membership terms, got {all_membership:?}"
    );

    for kind in EVERY_KIND {
        let offered = attendee_qualities(kind);
        let membership = membership_qualities(kind);

        assert!(
            offered.starts_with(&membership),
            "{kind:?}: the offered list must open with its membership terms, \
             got {offered:?} against {membership:?}"
        );

        // Position-independent restatement: no *other* family's membership term leaks in, and
        // none of this one's is missing. A test that only checked `offered[0]` would pass while
        // an SA quietly offered "Sócio" further down the list.
        let membership_in_offer: Vec<SignatoryCapacity> = offered
            .iter()
            .copied()
            .filter(|c| all_membership.contains(c))
            .collect();
        assert_eq!(
            membership_in_offer, membership,
            "{kind:?}: the only membership terms offered must be its own"
        );

        let mut seen = offered.clone();
        seen.sort_by_key(|c| format!("{c:?}"));
        seen.dedup();
        assert_eq!(
            seen.len(),
            offered.len(),
            "{kind:?}: no duplicate qualidade"
        );

        // The free-text escape hatch is always reachable, whatever the legal type.
        assert!(
            offered.contains(&SignatoryCapacity::Other),
            "{kind:?}: `Other` must always be offered"
        );
    }

    // The one kind with no members at all offers none, rather than falling back to a default.
    assert!(membership_qualities(EntityKind::Fundacao).is_empty());
    let fundacao = attendee_qualities(EntityKind::Fundacao);
    assert!(
        !fundacao.iter().any(|c| all_membership.contains(c)),
        "a fundação has no members, so no membership term may be offered: {fundacao:?}"
    );
}

// --- the universal assembly, across every family pack -------------------------------------------

fn attendee(name: &str, quality: SignatoryCapacity, presence: PresenceMode) -> Attendee {
    Attendee {
        name: name.to_owned(),
        quality,
        quality_note: None,
        presence,
        represented_by: None,
        weight: None,
    }
}

fn universal_waiver() -> ConveningWaiver {
    ConveningWaiver {
        basis: NoConveningBasis::AssembleiaUniversal,
        grounds: None,
        all_agreed_to_meet: true,
        all_agreed_to_agenda: true,
        evidence_reference: None,
    }
}

fn act_with_attendees(attendees: Vec<Attendee>) -> Act {
    let book = Book::new(chancela_core::EntityId::new(), BookKind::AssembleiaGeral);
    let mut act = Act::draft(book.id, "Ata da assembleia", MeetingChannel::Physical);
    act.meeting_date = Some(date!(2026 - 03 - 30));
    act.meeting_time = Some(time!(10:00));
    act.place = Some("Sede social".into());
    act.attendance_reference = Some("Lista de presenças".into());
    act.mesa.presidente = Some("Amélia Marques".into());
    act.mesa.secretarios = vec!["Rui Ferreira".into()];
    act.agenda = vec![AgendaItem {
        number: 1,
        text: "Contas do exercício".into(),
    }];
    act.deliberations = "Aprovadas as contas do exercício.".into();
    act.convening_waiver = Some(universal_waiver());
    act.attendees = attendees;
    act
}

fn issues(act: &Act, entity: &Entity) -> Vec<ComplianceIssue> {
    rule_pack_for(entity).check_act(act, entity)
}

fn has_rule(issues: &[ComplianceIssue], rule_id: &str) -> bool {
    issues.iter().any(|i| i.rule_id == rule_id)
}

const ATTENDANCE_RULE: &str = "CSC-54/universal-assembly-attendance";

/// An absent **member** falsifies the claim in every family that has members — not only under the
/// pack the rule was written against.
///
/// The dispatched pack differs per family (`rule_pack_for`), so a rule reached only from one pack's
/// own checks would silently stop applying elsewhere. `no_convening_issues` is called from the
/// shared civil baseline precisely so it cannot; this asserts that reaches every pack, using each
/// family's *own* membership term rather than a hardcoded `Member`.
#[test]
fn an_absent_member_falsifies_a_universal_assembly_under_every_family_pack() {
    let mut covered = 0;
    for kind in EVERY_KIND {
        let membership = membership_qualities(kind);
        let Some(term) = membership.first().copied() else {
            continue; // a fundação has no members; covered separately below
        };
        covered += 1;
        let entity = entity(kind);

        let absent = act_with_attendees(vec![
            attendee("Amélia Marques", term, PresenceMode::InPerson),
            attendee("Rui Ferreira", term, PresenceMode::Absent),
        ]);
        let found = issues(&absent, &entity);
        assert!(
            has_rule(&found, ATTENDANCE_RULE),
            "{kind:?}: an absent {term:?} must falsify the universal assembly, got {found:?}"
        );
        assert!(
            found.iter().any(|i| i.rule_id == ATTENDANCE_RULE
                && i.severity == Severity::Error
                && i.message.contains("Rui Ferreira")),
            "{kind:?}: the finding must block and name who was absent"
        );

        // The same roll with everyone present raises nothing about attendance.
        let present = act_with_attendees(vec![
            attendee("Amélia Marques", term, PresenceMode::InPerson),
            attendee("Rui Ferreira", term, PresenceMode::Represented),
        ]);
        assert!(
            !has_rule(&issues(&present, &entity), ATTENDANCE_RULE),
            "{kind:?}: represented counts as present under CSC art. 56.º/1 a)"
        );
    }
    assert!(
        covered >= 8,
        "expected most kinds to have members, got {covered}"
    );
}

/// The complement, and the reason the check is filtered on membership at all: the people who
/// attend an assembly **without being members** cannot falsify "todos estavam presentes". An
/// absent revisor oficial de contas or convidado says nothing about whether the sócios were all
/// there, and blocking on it would refuse good atas.
#[test]
fn an_absent_non_member_never_falsifies_a_universal_assembly_in_any_family() {
    for kind in EVERY_KIND {
        let entity = entity(kind);
        let membership = membership_qualities(kind);
        let non_membership: Vec<SignatoryCapacity> = attendee_qualities(kind)
            .into_iter()
            .filter(|c| !membership.contains(c) && *c != SignatoryCapacity::Other)
            .collect();
        assert!(
            non_membership.len() >= 4,
            "{kind:?}: expected several non-membership capacities, got {non_membership:?}"
        );

        for quality in non_membership {
            let mut roll = vec![attendee("Rui Ferreira", quality, PresenceMode::Absent)];
            // Keep a present member on the roll so the "nothing to check against" advisory is not
            // what is doing the work.
            if let Some(term) = membership.first().copied() {
                roll.push(attendee("Amélia Marques", term, PresenceMode::InPerson));
            }
            let found = issues(&act_with_attendees(roll), &entity);
            assert!(
                !has_rule(&found, ATTENDANCE_RULE),
                "{kind:?}: an absent {quality:?} must not falsify a universal assembly: {found:?}"
            );
        }
    }
}

/// A row under the free-text qualidade is neither counted as a member nor ignored: Chancela says
/// it cannot tell, which is a judgement it should surface rather than make.
#[test]
fn an_absent_free_text_attendee_is_flagged_as_unclassified_rather_than_decided() {
    let entity = entity(EntityKind::SociedadeAnonima);
    let mut unclassified = attendee(
        "Duarte Antunes",
        SignatoryCapacity::Other,
        PresenceMode::Absent,
    );
    unclassified.quality_note = Some("usufrutuário da quota".to_owned());
    let found = issues(
        &act_with_attendees(vec![
            attendee(
                "Amélia Marques",
                SignatoryCapacity::Shareholder,
                PresenceMode::InPerson,
            ),
            unclassified,
        ]),
        &entity,
    );
    assert!(
        !has_rule(&found, ATTENDANCE_RULE),
        "an unclassified row must not be silently treated as a member: {found:?}"
    );
    assert!(
        found.iter().any(
            |i| i.rule_id == "CONV/universal-assembly-unclassified-absentee"
                && i.severity == Severity::Warning
        ),
        "nor silently ignored — it must be raised as an advisory: {found:?}"
    );
}

// --- book capacity, and the page count a reopen hands back --------------------------------------

fn abertura_with_capacity(capacity: Option<u32>) -> TermoDeAbertura {
    TermoDeAbertura {
        entity_name: "Encosto Estratégico, Lda".into(),
        entity_nipc: "503004642".into(),
        entity_seat: "Lisboa".into(),
        purpose: "livro de atas da assembleia geral".into(),
        numbering_scheme: NumberingScheme::Sequential,
        opening_date: date!(2026 - 01 - 15),
        required_signatories: vec!["Gerente".into()],
        required_signatory_records: Vec::new(),
        page_capacity: capacity,
        ..TermoDeAbertura::default()
    }
}

/// The default a drafter is offered is 100 pages, and it reaches the *book* rather than stopping at
/// the termo. `Book::new` deliberately starts unlimited, so the only way a book acquires a capacity
/// is a termo that declares one — which makes "what does the default termo produce?" a question
/// about the two together.
#[test]
fn the_default_termo_capacity_opens_a_hundred_page_book() {
    assert_eq!(
        TermoFields::for_abertura().page_capacity,
        Some(DEFAULT_PAGE_CAPACITY),
        "the drafting default is the source of the 100"
    );

    let mut book = Book::new(chancela_core::EntityId::new(), BookKind::AssembleiaGeral);
    book.open(abertura_with_capacity(
        TermoFields::for_abertura().page_capacity,
    ))
    .unwrap();

    assert_eq!(book.page_capacity, Some(100));
    assert!(book.has_page_capacity());
    assert_eq!(book.pages_remaining(), Some(100));
    assert!(!book.is_capacity_exhausted());
}

/// A book whose termo declares no size is **unlimited, not zero-capacity**, and must never refuse
/// an ata. The two are distinct states that a `pages_remaining()` of `Some(0)` versus `None`
/// deliberately separates, and conflating them would make every legacy book instantly full.
#[test]
fn a_book_whose_termo_declares_no_capacity_never_refuses_an_ata() {
    let mut book = Book::new(chancela_core::EntityId::new(), BookKind::AssembleiaGeral);
    book.open(abertura_with_capacity(None)).unwrap();

    assert!(!book.has_page_capacity());
    assert_eq!(book.pages_remaining(), None, "unlimited is not zero");
    assert!(!book.is_capacity_exhausted());

    // Far past any plausible declared size, and still accepting.
    for expected in 1..=40u64 {
        assert_eq!(book.assign_next_ata_number().unwrap(), expected);
        book.reserve_pages(25).unwrap();
        book.consume_reserved_pages(25).unwrap();
    }
    assert_eq!(book.pages_used, 1000);
    assert!(
        !book.is_capacity_exhausted(),
        "an unlimited book never exhausts"
    );
    assert_eq!(book.pages_remaining(), None);
}

/// The page count `reopen_for_correction` returns is exactly what the caller owes the book.
///
/// `Act::reopen_for_correction` documents that a capacity-aware caller "must release it with the
/// returned count, or the reservation leaks against the book's capacity" — but the act does not
/// hold the book, so nothing in the type system enforces it and no unit test of either side sees
/// the whole loop. This walks it: reserve, freeze, reopen, release, correct, re-freeze at a new
/// length, re-reserve, consume.
#[test]
fn the_page_count_a_reopen_hands_back_settles_the_books_reservation_exactly() {
    let mut book = Book::new(chancela_core::EntityId::new(), BookKind::AssembleiaGeral);
    book.open(abertura_with_capacity(Some(10))).unwrap();

    let mut act = Act::draft(book.id, "Ata da AG", MeetingChannel::Physical);
    for state in [
        ActState::Review,
        ActState::Convened,
        ActState::Deliberated,
        ActState::TextApproved,
        ActState::Signing,
    ] {
        act.advance_to(state).unwrap();
    }
    // Entering Signing is where the rendered length becomes knowable and stable.
    act.freeze_page_count(4).unwrap();
    book.reserve_pages(4).unwrap();
    assert_eq!(book.pages_remaining(), Some(6));

    // The reopen retires the snapshot that count described, and hands the count back.
    let released = act
        .reopen_for_correction()
        .expect("an unsigned Signing act reopens");
    assert_eq!(
        released,
        Some(4),
        "the caller is handed exactly what it reserved"
    );
    assert_eq!(act.page_count, None, "and the act is ready to re-freeze");

    book.release_reserved_pages(released.unwrap()).unwrap();
    assert_eq!(book.pages_reserved, 0, "no reservation leaks");
    assert_eq!(book.pages_used, 0, "and nothing was consumed by a reopen");
    assert_eq!(
        book.pages_remaining(),
        Some(10),
        "the book is back where it started"
    );

    // The corrected content is longer, and re-freezes at its own length.
    act.set_deliberations("Aprovadas as contas do exercício, com a redação corrigida.")
        .unwrap();
    act.advance_to(ActState::Signing).unwrap();
    act.freeze_page_count(6).unwrap();
    book.reserve_pages(6).unwrap();
    book.consume_reserved_pages(6).unwrap();

    assert_eq!(book.pages_used, 6);
    assert_eq!(book.pages_reserved, 0);
    assert_eq!(
        book.pages_remaining(),
        Some(4),
        "the book paid for the corrected ata once, not twice"
    );
}

/// The negative form of the same contract: had the caller *not* released, the book would carry a
/// reservation for a snapshot that no longer exists. Pinned so the released count can never
/// silently become `None` for an act that had one.
#[test]
fn a_reopen_that_is_not_settled_leaves_the_reservation_outstanding() {
    let mut book = Book::new(chancela_core::EntityId::new(), BookKind::AssembleiaGeral);
    book.open(abertura_with_capacity(Some(10))).unwrap();

    let mut act = Act::draft(book.id, "Ata da AG", MeetingChannel::Physical);
    for state in [
        ActState::Review,
        ActState::Convened,
        ActState::Deliberated,
        ActState::TextApproved,
        ActState::Signing,
    ] {
        act.advance_to(state).unwrap();
    }
    act.freeze_page_count(7).unwrap();
    book.reserve_pages(7).unwrap();

    assert_eq!(act.reopen_for_correction(), Ok(Some(7)));
    // The book is untouched by the reopen — which is why the returned count is load-bearing.
    assert_eq!(book.pages_reserved, 7);
    assert_eq!(book.pages_remaining(), Some(3));
}
