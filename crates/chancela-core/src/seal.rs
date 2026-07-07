//! Sealing: the point where a book opening or an act becomes part of the immutable
//! hash-chained record.
//!
//! Grounding: spec 06 §3 (WFL-20/22), spec 05 (DAT-10/11). Sealing an act consults the
//! compliance rule pack (LEG-05), assigns the sequential ata number (WFL-12), freezes the
//! payload, and appends an append-only event to the book's [`Ledger`]. Opening a book
//! appends the genesis event whose existence *is* the digital anti-falsification function
//! of the termo de abertura (WFL-11).
//!
//! The ledger preimage/chain layout is owned by `chancela-ledger`; this module only feeds
//! it canonical payload bytes and reads back the assigned sequence and digest.

use serde::Serialize;

use chancela_ledger::Ledger;

use crate::act::{
    Act, ActState, AgendaItem, Attachment, DeliberationItem, DocumentReference, MeetingChannel,
    Mesa, SignatorySlot,
};
use crate::book::{Book, TermoDeAbertura};
use crate::entity::Entity;
use crate::error::{ActError, BookError, SealError};
use crate::rules::{ComplianceIssue, RulePack, Severity};

/// Result of successfully sealing an act.
#[derive(Debug, Clone)]
pub struct SealOutcome {
    /// Sequential ata number assigned within the book (WFL-12).
    pub ata_number: u64,
    /// Sequence number of the seal event in the ledger.
    pub event_seq: u64,
    /// The frozen payload digest (sha-256), as computed by the ledger.
    pub payload_digest: [u8; 32],
    /// Any `Warning`-severity issues that were acknowledged at sealing (LEG-05), retained
    /// so the acknowledgement is itself part of the record.
    pub acknowledged_warnings: Vec<ComplianceIssue>,
}

/// Canonical, digest-stable view of an act's sealed content.
///
/// Serde serializes struct fields in declaration order, so serializing this view yields a
/// stable byte string for the same content — adequate for the scaffold's digesting. The
/// act's identity (`act_id`, `book_id`) is included so the digest binds to *this* act.
#[derive(Serialize)]
struct ActPayload<'a> {
    act_id: String,
    book_id: String,
    title: &'a str,
    channel: MeetingChannel,
    meeting_date: Option<time::Date>,
    place: Option<&'a str>,
    attendance_reference: Option<&'a str>,
    deliberations: &'a str,
    telematic_evidence: Option<&'a str>,
    attachments: &'a [Attachment],
    signatories: &'a [SignatorySlot],
    retifies: Option<String>,
    // R8: the new mandatory-content fields are appended (append-only, after the pre-existing
    // fields) so a new seal binds them into its digest. Already-sealed acts are never
    // recomputed, so their frozen digests are unaffected by this growth.
    meeting_time: Option<time::Time>,
    mesa: &'a Mesa,
    agenda: &'a [AgendaItem],
    referenced_documents: &'a [DocumentReference],
    deliberation_items: &'a [DeliberationItem],
    members_present: Option<u32>,
    members_represented: Option<u32>,
}

impl<'a> ActPayload<'a> {
    fn of(act: &'a Act) -> Self {
        ActPayload {
            act_id: act.id.to_string(),
            book_id: act.book_id.to_string(),
            title: &act.title,
            channel: act.channel,
            meeting_date: act.meeting_date,
            place: act.place.as_deref(),
            attendance_reference: act.attendance_reference.as_deref(),
            deliberations: &act.deliberations,
            telematic_evidence: act.telematic_evidence.as_deref(),
            attachments: &act.attachments,
            signatories: &act.signatories,
            retifies: act.retifies.map(|id| id.to_string()),
            meeting_time: act.meeting_time,
            mesa: &act.mesa,
            agenda: &act.agenda,
            referenced_documents: &act.referenced_documents,
            deliberation_items: &act.deliberation_items,
            members_present: act.members_present,
            members_represented: act.members_represented,
        }
    }
}

fn render_issues(issues: &[ComplianceIssue]) -> String {
    issues
        .iter()
        .map(|i| format!("[{}] {}", i.rule_id, i.message))
        .collect::<Vec<_>>()
        .join("; ")
}

/// Open a book and append its genesis event to `ledger` (WFL-10/11).
///
/// The genesis event digests the sealed termo de abertura; from here the book's hash chain
/// grows one seal at a time. Returns the genesis event's sequence number.
///
/// `actor` is the identity performing the opening (management/administrator), recorded on
/// the ledger event (DAT-10).
pub fn open_and_seal_book(
    book: &mut Book,
    entity: &Entity,
    termo: TermoDeAbertura,
    actor: &str,
    ledger: &mut Ledger,
) -> Result<u64, SealError> {
    // State guard first: do not touch the ledger if the book cannot be opened.
    book.open(termo)?;
    // `open` moved the termo into the book; serialize it from there.
    let termo_ref = book
        .termo_abertura
        .as_ref()
        .expect("termo present immediately after open");
    let payload = serde_json::to_vec(termo_ref).map_err(|e| SealError::Serialize(e.to_string()))?;
    let scope = format!("entity:{}/book:{}", entity.id, book.id);
    let event = ledger.append(actor, &scope, "book.opened", None, &payload);
    Ok(event.seq)
}

/// Seal an act into its book (WFL-20).
///
/// Steps, in order: verify the act belongs to `book` and is in `Signing`; run
/// `rule_pack`; block on any `Error` issue and on unacknowledged `Warning`s (LEG-05);
/// serialize and digest the payload; assign the next ata number (WFL-12); append the
/// `act.sealed` event to `ledger`; freeze the act.
///
/// `acknowledge_warnings` records that the operator has seen and accepted the warnings; it
/// has no effect when there are none.
pub fn seal_act(
    book: &mut Book,
    act: &mut Act,
    entity: &Entity,
    rule_pack: &dyn RulePack,
    actor: &str,
    acknowledge_warnings: bool,
    ledger: &mut Ledger,
) -> Result<SealOutcome, SealError> {
    // The act must belong to this book.
    if act.book_id != book.id {
        return Err(SealError::Book(BookError::WrongBook {
            act_book: act.book_id.to_string(),
            book: book.id.to_string(),
        }));
    }

    // The act must be ready to seal (out for signature). Check before assigning a number
    // or touching the ledger, so a premature seal burns neither.
    if act.state != ActState::Signing {
        return Err(SealError::Act(ActError::InvalidTransition {
            from: act.state,
            to: ActState::Sealed,
        }));
    }

    // Compliance gate (LEG-05).
    let issues = rule_pack.check_act(act, entity);
    let (warnings, errors): (Vec<_>, Vec<_>) = issues
        .into_iter()
        .partition(|i| i.severity == Severity::Warning);
    if !errors.is_empty() {
        return Err(SealError::ComplianceBlocked(render_issues(&errors)));
    }
    if !warnings.is_empty() && !acknowledge_warnings {
        return Err(SealError::WarningsNotAcknowledged(render_issues(&warnings)));
    }

    // Freeze the payload before mutating anything (a serialize failure must not burn a
    // number or append an event).
    let payload = serde_json::to_vec(&ActPayload::of(act))
        .map_err(|e| SealError::Serialize(e.to_string()))?;

    // Assign the sequential ata number (WFL-12); refuses unless the book is open (WFL-14).
    let ata_number = book.assign_next_ata_number()?;

    // Append the seal event; the ledger computes and stores the payload digest.
    let scope = format!("entity:{}/book:{}", entity.id, book.id);
    let justification = format!("seal ata n.º {ata_number} ({})", rule_pack.id());
    let event = ledger.append(actor, &scope, "act.sealed", Some(&justification), &payload);
    let event_seq = event.seq;
    let payload_digest = event.payload_digest;

    // Freeze the act (Signing → Sealed).
    act.mark_sealed(ata_number, payload_digest, event_seq)?;

    Ok(SealOutcome {
        ata_number,
        event_seq,
        payload_digest,
        acknowledged_warnings: warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::{date, time};

    use crate::act::{Act, ActState, AgendaItem, MeetingChannel};
    use crate::book::{Book, BookKind, NumberingScheme};
    use crate::entity::{Entity, EntityId, EntityKind, Nipc};
    use crate::rules::CscArt63RulePack;

    fn entity() -> Entity {
        Entity::new(
            "Encosto Estratégico, S.A.",
            Nipc::parse("503004642").unwrap(),
            "Lisboa",
            EntityKind::SociedadeAnonima,
        )
    }

    fn abertura(e: &Entity) -> TermoDeAbertura {
        TermoDeAbertura {
            entity_name: e.name.clone(),
            entity_nipc: e.nipc.to_string(),
            entity_seat: e.seat.clone(),
            purpose: "livro de atas da assembleia geral".into(),
            numbering_scheme: NumberingScheme::Sequential,
            opening_date: date!(2026 - 01 - 15),
            required_signatories: vec!["Administrador".into()],
        }
    }

    fn ready_act(book: &Book) -> Act {
        let mut act = Act::draft(book.id, "Ata da AG anual", MeetingChannel::Physical);
        act.meeting_date = Some(date!(2026 - 03 - 30));
        act.meeting_time = Some(time!(10:00));
        act.place = Some("Sede social".into());
        // To seal without acknowledging advisories, CSC v2 wants the mesa chair (a blocking
        // Error), the secretaries, time, and agenda (§2.5): make the fixture fully clean under
        // the v2 pack.
        act.mesa.presidente = Some("Ana Presidente".into());
        act.mesa.secretarios = vec!["Rui Secretário".into()];
        act.agenda = vec![AgendaItem {
            number: 1,
            text: "Aprovação das contas".into(),
        }];
        act.attendance_reference = Some("Lista de presenças".into());
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

    #[test]
    fn opening_a_book_emits_genesis_event() {
        let e = entity();
        let mut ledger = Ledger::default();
        let mut book = Book::new(e.id, BookKind::AssembleiaGeral);
        let seq =
            open_and_seal_book(&mut book, &e, abertura(&e), "sec@encosto", &mut ledger).unwrap();
        assert_eq!(seq, 0);
        assert_eq!(ledger.events().len(), 1);
        assert_eq!(ledger.events()[0].kind, "book.opened");
        assert!(book.is_open());
    }

    #[test]
    fn seal_assigns_sequential_numbers_and_chains_events() {
        let e = entity();
        let mut ledger = Ledger::default();
        let mut book = Book::new(e.id, BookKind::AssembleiaGeral);
        open_and_seal_book(&mut book, &e, abertura(&e), "sec@encosto", &mut ledger).unwrap();

        let mut first = ready_act(&book);
        let out1 = seal_act(
            &mut book,
            &mut first,
            &e,
            &CscArt63RulePack,
            "sec@encosto",
            false,
            &mut ledger,
        )
        .unwrap();
        assert_eq!(out1.ata_number, 1);
        assert_eq!(first.state, ActState::Sealed);
        assert_eq!(first.payload_digest, Some(out1.payload_digest));

        let mut second = ready_act(&book);
        let out2 = seal_act(
            &mut book,
            &mut second,
            &e,
            &CscArt63RulePack,
            "sec@encosto",
            false,
            &mut ledger,
        )
        .unwrap();
        assert_eq!(out2.ata_number, 2);

        // genesis + two seals, and the chain verifies.
        assert_eq!(ledger.events().len(), 3);
        assert_eq!(ledger.verify().unwrap(), 3);
    }

    #[test]
    fn seal_rejected_on_compliance_error_without_burning_a_number() {
        let e = entity();
        let mut ledger = Ledger::default();
        let mut book = Book::new(e.id, BookKind::AssembleiaGeral);
        open_and_seal_book(&mut book, &e, abertura(&e), "sec@encosto", &mut ledger).unwrap();

        let mut act = ready_act(&book);
        act.deliberations = "   ".into(); // now violates CSC art. 63.º
        let err = seal_act(
            &mut book,
            &mut act,
            &e,
            &CscArt63RulePack,
            "sec@encosto",
            false,
            &mut ledger,
        )
        .unwrap_err();
        assert!(matches!(err, SealError::ComplianceBlocked(_)));
        // No ata number consumed, no seal event appended, act still in Signing.
        assert_eq!(book.last_ata_number, 0);
        assert_eq!(ledger.events().len(), 1);
        assert_eq!(act.state, ActState::Signing);
    }

    #[test]
    fn seal_requires_signing_state() {
        let e = entity();
        let mut ledger = Ledger::default();
        let mut book = Book::new(e.id, BookKind::AssembleiaGeral);
        open_and_seal_book(&mut book, &e, abertura(&e), "sec@encosto", &mut ledger).unwrap();

        let mut act = Act::draft(book.id, "Rascunho", MeetingChannel::Physical);
        let err = seal_act(
            &mut book,
            &mut act,
            &e,
            &CscArt63RulePack,
            "sec@encosto",
            false,
            &mut ledger,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            SealError::Act(ActError::InvalidTransition { .. })
        ));
    }

    #[test]
    fn seal_rejects_act_from_another_book() {
        let e = entity();
        let mut ledger = Ledger::default();
        let mut book = Book::new(e.id, BookKind::AssembleiaGeral);
        open_and_seal_book(&mut book, &e, abertura(&e), "sec@encosto", &mut ledger).unwrap();

        let other = Book::new(e.id, BookKind::GerenciaAdministracao);
        let mut act = ready_act(&other);
        let err = seal_act(
            &mut book,
            &mut act,
            &e,
            &CscArt63RulePack,
            "sec@encosto",
            false,
            &mut ledger,
        )
        .unwrap_err();
        assert!(matches!(err, SealError::Book(BookError::WrongBook { .. })));
    }

    #[test]
    fn unvalidated_nipc_warns_and_seals_only_when_acknowledged() {
        // End-to-end through the SHIPPED CscArt63RulePack: an entity whose NIPC was stored
        // via the validation override raises a Warning, so sealing needs acknowledgement.
        let e = Entity::new(
            "Foreign Holdings Ltd.",
            Nipc::unvalidated("GB-00000000"),
            "London",
            EntityKind::SociedadeAnonima,
        );
        let mut ledger = Ledger::default();
        let mut book = Book::new(e.id, BookKind::AssembleiaGeral);
        open_and_seal_book(&mut book, &e, abertura(&e), "sec@encosto", &mut ledger).unwrap();

        // Without acknowledgement the advisory blocks the seal (no number burned).
        let mut act = ready_act(&book);
        let err = seal_act(
            &mut book,
            &mut act,
            &e,
            &CscArt63RulePack,
            "sec@encosto",
            false,
            &mut ledger,
        )
        .unwrap_err();
        assert!(matches!(err, SealError::WarningsNotAcknowledged(_)));
        assert_eq!(book.last_ata_number, 0);
        assert_eq!(ledger.events().len(), 1);

        // With acknowledgement it seals and records the acknowledged warning.
        let outcome = seal_act(
            &mut book,
            &mut act,
            &e,
            &CscArt63RulePack,
            "sec@encosto",
            true,
            &mut ledger,
        )
        .unwrap();
        assert_eq!(outcome.ata_number, 1);
        assert_eq!(act.state, ActState::Sealed);
        assert_eq!(outcome.acknowledged_warnings.len(), 1);
        assert_eq!(
            outcome.acknowledged_warnings[0].rule_id,
            "CSC-63/nipc-unvalidated"
        );
    }

    /// A rule pack that emits exactly one `Warning` (plus an optional blocking `Error`), so the
    /// LEG-05 warning-acknowledgement branch of `seal_act` can be exercised — the shipped
    /// `CscArt63RulePack` only ever emits `Error`s.
    struct WarningPack {
        also_errors: bool,
    }

    impl crate::rules::RulePack for WarningPack {
        fn id(&self) -> &str {
            "test-warning/v1"
        }
        fn check_act(&self, _act: &Act, _entity: &Entity) -> Vec<crate::rules::ComplianceIssue> {
            let mut issues = vec![crate::rules::ComplianceIssue {
                rule_id: "TEST/advisory".into(),
                severity: crate::rules::Severity::Warning,
                message: "advisory finding".into(),
            }];
            if self.also_errors {
                issues.push(crate::rules::ComplianceIssue {
                    rule_id: "TEST/blocking".into(),
                    severity: crate::rules::Severity::Error,
                    message: "blocking finding".into(),
                });
            }
            issues
        }
    }

    #[test]
    fn unacknowledged_warning_blocks_the_seal_without_burning_a_number() {
        let e = entity();
        let mut ledger = Ledger::default();
        let mut book = Book::new(e.id, BookKind::AssembleiaGeral);
        open_and_seal_book(&mut book, &e, abertura(&e), "sec@encosto", &mut ledger).unwrap();

        let mut act = ready_act(&book);
        let err = seal_act(
            &mut book,
            &mut act,
            &e,
            &WarningPack { also_errors: false },
            "sec@encosto",
            false, // do NOT acknowledge
            &mut ledger,
        )
        .unwrap_err();
        assert!(matches!(err, SealError::WarningsNotAcknowledged(_)));
        // The advisory refusal must not consume a number, append an event, or freeze the act.
        assert_eq!(book.last_ata_number, 0);
        assert_eq!(ledger.events().len(), 1);
        assert_eq!(act.state, ActState::Signing);
    }

    #[test]
    fn acknowledged_warning_seals_and_records_the_warning() {
        let e = entity();
        let mut ledger = Ledger::default();
        let mut book = Book::new(e.id, BookKind::AssembleiaGeral);
        open_and_seal_book(&mut book, &e, abertura(&e), "sec@encosto", &mut ledger).unwrap();

        let mut act = ready_act(&book);
        let outcome = seal_act(
            &mut book,
            &mut act,
            &e,
            &WarningPack { also_errors: false },
            "sec@encosto",
            true, // acknowledge the advisory
            &mut ledger,
        )
        .unwrap();
        assert_eq!(outcome.ata_number, 1);
        assert_eq!(act.state, ActState::Sealed);
        // The acknowledgement is itself part of the record (LEG-05).
        assert_eq!(outcome.acknowledged_warnings.len(), 1);
        assert_eq!(outcome.acknowledged_warnings[0].rule_id, "TEST/advisory");
        assert_eq!(ledger.events().len(), 2); // genesis + seal
    }

    #[test]
    fn a_blocking_error_wins_even_when_warnings_are_acknowledged() {
        let e = entity();
        let mut ledger = Ledger::default();
        let mut book = Book::new(e.id, BookKind::AssembleiaGeral);
        open_and_seal_book(&mut book, &e, abertura(&e), "sec@encosto", &mut ledger).unwrap();

        let mut act = ready_act(&book);
        // Acknowledging warnings must not relax the hard `Error` gate: the error is reported.
        let err = seal_act(
            &mut book,
            &mut act,
            &e,
            &WarningPack { also_errors: true },
            "sec@encosto",
            true,
            &mut ledger,
        )
        .unwrap_err();
        assert!(matches!(err, SealError::ComplianceBlocked(_)));
        assert_eq!(book.last_ata_number, 0);
        assert_eq!(ledger.events().len(), 1);
    }

    #[test]
    fn payload_digest_preimage_binds_the_new_mandatory_fields() {
        // R8: the sealed payload must bind the new content, so two otherwise-identical acts
        // (same id) that differ only in a new field produce different digest preimages.
        let book = Book::new(EntityId::new(), BookKind::AssembleiaGeral);
        let base = ready_act(&book);
        let bytes = |a: &Act| serde_json::to_vec(&ActPayload::of(a)).unwrap();

        let mut time_changed = base.clone();
        time_changed.meeting_time = Some(time!(15:30)); // base is 10:00
        assert_ne!(bytes(&base), bytes(&time_changed), "meeting_time must bind");

        let mut mesa_changed = base.clone();
        mesa_changed.mesa.presidente = Some("Outro Presidente".into());
        assert_ne!(bytes(&base), bytes(&mesa_changed), "mesa must bind");

        let mut items_changed = base.clone();
        items_changed.deliberation_items = vec![crate::act::DeliberationItem {
            agenda_number: Some(1),
            text: "Nova deliberação".into(),
            vote: Some(crate::act::VoteResult::Unanimous),
            statements: Vec::new(),
        }];
        assert_ne!(
            bytes(&base),
            bytes(&items_changed),
            "deliberation_items must bind"
        );

        let mut counts_changed = base.clone();
        counts_changed.members_present = Some(7);
        assert_ne!(bytes(&base), bytes(&counts_changed), "counts must bind");
    }
}
