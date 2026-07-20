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
    Act, ActState, AgendaItem, Attachment, Attendee, Convening, DeliberationItem,
    DocumentReference, ManualSignatureOriginalReference, MeetingChannel, Mesa, SealMetadata,
    SignatorySlot, SupersededSigningSnapshot, WrittenResolutionEvidence,
};
use crate::book::{Book, TermoDeAbertura};
use crate::entity::Entity;
use crate::error::{ActError, BookError, SealError};
use crate::rules::{ComplianceIssue, RulePack, Severity};

/// Evidence accepted by the final seal gate.
///
/// A digital seal binds the immutable signing snapshot, the completed signed PDF, and the
/// deterministic technical validation report. A manual seal instead records where the signed
/// original is retained. Neither variant is itself a legal-validity or qualification claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SealEvidence {
    /// Complete digital signed-PDF evidence.
    Digital {
        /// SHA-256 of the canonical PDF snapshot presented to the signer.
        signing_snapshot_digest: String,
        /// SHA-256 of the completed signed PDF.
        signed_pdf_digest: String,
        /// SHA-256 of the technical validation report used by the gate.
        signature_validation_report_digest: String,
    },
    /// Explicit reference to a manually signed original retained outside this digital flow.
    Manual {
        /// Custody/location metadata for the original.
        original_reference: ManualSignatureOriginalReference,
    },
}

impl SealEvidence {
    fn validate(&self) -> Result<(), SealError> {
        match self {
            Self::Digital {
                signing_snapshot_digest,
                signed_pdf_digest,
                signature_validation_report_digest,
            } => {
                for (field, value) in [
                    ("signing_snapshot_digest", signing_snapshot_digest),
                    ("signed_pdf_digest", signed_pdf_digest),
                    (
                        "signature_validation_report_digest",
                        signature_validation_report_digest,
                    ),
                ] {
                    if value.len() != 64
                        || !value
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                    {
                        return Err(SealError::InvalidSignatureEvidence(format!(
                            "{field} must be a lowercase SHA-256 hex digest"
                        )));
                    }
                }
                Ok(())
            }
            Self::Manual { original_reference } => {
                if original_reference.storage_reference.trim().is_empty() {
                    return Err(SealError::InvalidSignatureEvidence(
                        "manual signature storage reference must not be empty".to_owned(),
                    ));
                }
                Ok(())
            }
        }
    }

    fn seal_metadata(&self, rule_pack_id: &str, entity: &Entity) -> SealMetadata {
        let metadata = SealMetadata::new(rule_pack_id, entity.family, entity.kind);
        match self {
            Self::Digital {
                signing_snapshot_digest,
                signed_pdf_digest,
                signature_validation_report_digest,
            } => metadata.with_digital_signature_evidence(
                signing_snapshot_digest.clone(),
                signed_pdf_digest.clone(),
                signature_validation_report_digest.clone(),
            ),
            Self::Manual { original_reference } => {
                metadata.with_manual_signature_original_reference(Some(original_reference.clone()))
            }
        }
    }
}

/// Result of successfully sealing an act.
#[derive(Debug, Clone)]
pub struct SealOutcome {
    /// Sequential ata number assigned within the book (WFL-12).
    pub ata_number: u64,
    /// Sequence number of the seal event in the ledger.
    pub event_seq: u64,
    /// The frozen payload digest (sha-256), as computed by the ledger.
    pub payload_digest: [u8; 32],
    /// Structured evidence of the rule pack/profile used for this seal (LEG-06/WFL-22).
    pub seal_metadata: SealMetadata,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    written_resolution_evidence: Option<&'a WrittenResolutionEvidence>,
    deliberation_items: &'a [DeliberationItem],
    members_present: Option<u32>,
    members_represented: Option<u32>,
    // G1/G2 (append-only). These are skipped from the preimage when empty — a convening of
    // `None` and no attendees emit no bytes — so the digest of a pre-existing act (one carrying
    // neither) is **byte-identical** to what it was before these fields existed. When either is
    // populated it serializes and binds into the new seal's digest (R8).
    #[serde(skip_serializing_if = "Option::is_none")]
    convening: Option<&'a Convening>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attendees: Option<&'a [Attendee]>,
    // F15 (append-only). The rendered page count frozen at the content freeze, so the seal
    // binds the act's page consumption as a fact rather than something re-derivable later. An
    // act without one emits no bytes, so already-sealed acts and any act sealed without a
    // count produce a byte-identical preimage.
    #[serde(skip_serializing_if = "Option::is_none")]
    page_count: Option<u32>,
    // Reopen history (append-only). An act that was reopened for correction seals carrying the
    // record of every canonical snapshot that reopen retired, so the seal binds the regression
    // rather than hiding it. An act that was never reopened emits no bytes, so its preimage — and
    // therefore any already-frozen digest — is byte-identical to before this field existed.
    #[serde(skip_serializing_if = "Option::is_none")]
    superseded_signing_snapshots: Option<&'a [SupersededSigningSnapshot]>,
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
            written_resolution_evidence: act.written_resolution_evidence.as_ref(),
            deliberation_items: &act.deliberation_items,
            members_present: act.members_present,
            members_represented: act.members_represented,
            convening: act.convening.as_ref(),
            attendees: (!act.attendees.is_empty()).then_some(act.attendees.as_slice()),
            page_count: act.page_count,
            superseded_signing_snapshots: (!act.superseded_signing_snapshots.is_empty())
                .then_some(act.superseded_signing_snapshots.as_slice()),
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
    // wp27-e3: a book opened in a **non-default** tenant joins its tenant chain (ChainId::Tenant) by
    // carrying the parent entity's `tenant:{t}` segment additively, ahead of the existing
    // `entity:`/`book:` segments (the per-tenant analogue of e1's `entity.created`). Single-tenant
    // deployments (the default tenant) keep the exact `entity:{}/book:{}` genesis scope, so their
    // ledger is byte-identical to before tenancy.
    let scope = if entity.tenant_id == crate::tenant::DEFAULT_TENANT_ID {
        format!("entity:{}/book:{}", entity.id, book.id)
    } else {
        format!(
            "tenant:{}/entity:{}/book:{}",
            entity.tenant_id, entity.id, book.id
        )
    };
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
#[allow(clippy::too_many_arguments)]
pub fn seal_act(
    book: &mut Book,
    act: &mut Act,
    entity: &Entity,
    rule_pack: &dyn RulePack,
    actor: &str,
    acknowledge_warnings: bool,
    manual_signature_original_reference: Option<ManualSignatureOriginalReference>,
    ledger: &mut Ledger,
) -> Result<SealOutcome, SealError> {
    let manual_signature_original_reference = manual_signature_original_reference
        .ok_or(SealError::MissingManualSignatureOriginalReference)?;

    seal_act_with_evidence(
        book,
        act,
        entity,
        rule_pack,
        actor,
        acknowledge_warnings,
        SealEvidence::Manual {
            original_reference: manual_signature_original_reference,
        },
        ledger,
    )
}

/// Seal an act using either validated digital evidence or an explicit manual-original reference.
///
/// This is the canonical `Signing -> Sealed` operation. The older [`seal_act`] entry point remains
/// as the manual-signature compatibility wrapper.
#[allow(clippy::too_many_arguments)]
pub fn seal_act_with_evidence(
    book: &mut Book,
    act: &mut Act,
    entity: &Entity,
    rule_pack: &dyn RulePack,
    actor: &str,
    acknowledge_warnings: bool,
    evidence: SealEvidence,
    ledger: &mut Ledger,
) -> Result<SealOutcome, SealError> {
    evidence.validate()?;

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

    let seal_metadata = evidence.seal_metadata(rule_pack.id(), entity);

    // Freeze the content and the evidence tuple before mutating anything (a serialize failure must
    // not burn a number or append an event). The evidence is embedded in the ledger preimage so a
    // later store edit cannot substitute a different signing snapshot or signed artifact.
    #[derive(Serialize)]
    struct SealedActPayload<'a> {
        act: ActPayload<'a>,
        seal_metadata: &'a SealMetadata,
    }
    let payload = serde_json::to_vec(&SealedActPayload {
        act: ActPayload::of(act),
        seal_metadata: &seal_metadata,
    })
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
    act.mark_sealed(ata_number, payload_digest, event_seq, seal_metadata.clone())?;

    Ok(SealOutcome {
        ata_number,
        event_seq,
        payload_digest,
        seal_metadata,
        acknowledged_warnings: warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::{date, time};

    use crate::act::{
        Act, ActState, AgendaItem, MeetingChannel, WrittenResolutionEvidence,
        WrittenResolutionEvidenceItem,
    };
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
            required_signatory_records: Vec::new(),
            ..TermoDeAbertura::default()
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

    fn manual_reference() -> ManualSignatureOriginalReference {
        ManualSignatureOriginalReference {
            storage_reference: "Arquivo A / Pasta 2026 / Ata teste".to_owned(),
            custodian: None,
            note: None,
        }
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
    fn opening_a_book_joins_its_tenant_chain() {
        // wp27-e3 (Part 2): the `book.opened` genesis carries the parent entity's `tenant:{t}`
        // segment so the book joins its tenant chain (ChainId::Tenant), mirroring the entity genesis.
        let tenant = crate::tenant::TenantId::new();
        let e = crate::entity::Entity::new(
            "Encosto Estratégico, S.A.",
            crate::entity::Nipc::unvalidated("A-0001"),
            "Lisboa",
            crate::entity::EntityKind::SociedadeAnonima,
        )
        .in_tenant(tenant);
        let mut ledger = Ledger::default();
        let mut book = Book::new(e.id, BookKind::AssembleiaGeral);
        open_and_seal_book(&mut book, &e, abertura(&e), "sec@encosto", &mut ledger).unwrap();
        let scope = &ledger.events()[0].scope;
        assert_eq!(
            scope,
            &format!("tenant:{tenant}/entity:{}/book:{}", e.id, book.id),
            "book.opened must carry the tenant/entity/book scope"
        );
        let memberships = Ledger::memberships(scope, "book.opened");
        assert!(
            memberships.contains(&chancela_ledger::ChainId::Tenant(tenant.to_string())),
            "book.opened must join its tenant chain, got {memberships:?}"
        );
    }

    #[test]
    fn seal_assigns_sequential_numbers_and_chains_events() {
        let e = entity();
        let mut ledger = Ledger::default();
        // Mirror the real flow: the entity is created first, so the company chain's genesis is
        // `entity.created` (per the multi-chain model) before the book's `book.opened`.
        ledger.append(
            "sec@encosto",
            &e.id.to_string(),
            "entity.created",
            None,
            b"entity",
        );
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
            Some(manual_reference()),
            &mut ledger,
        )
        .unwrap();
        assert_eq!(out1.ata_number, 1);
        assert_eq!(first.state, ActState::Sealed);
        assert_eq!(first.payload_digest, Some(out1.payload_digest));
        assert_eq!(out1.seal_metadata.rule_pack_id, "csc-art63/v2");
        assert_eq!(out1.seal_metadata.version, "v2");
        assert_eq!(
            out1.seal_metadata.family,
            crate::entity::EntityFamily::CommercialCompany
        );
        assert_eq!(
            out1.seal_metadata.profile,
            crate::entity::EntityKind::SociedadeAnonima
        );
        assert_eq!(first.seal_metadata, Some(out1.seal_metadata.clone()));

        let mut second = ready_act(&book);
        let out2 = seal_act(
            &mut book,
            &mut second,
            &e,
            &CscArt63RulePack,
            "sec@encosto",
            false,
            Some(manual_reference()),
            &mut ledger,
        )
        .unwrap();
        assert_eq!(out2.ata_number, 2);

        // entity.created (company genesis) + book.opened (book genesis) + two seals; chain verifies.
        assert_eq!(ledger.events().len(), 4);
        assert_eq!(ledger.verify().unwrap(), 4);
    }

    #[test]
    fn manual_signature_original_reference_is_frozen_in_seal_metadata() {
        let e = entity();
        let mut ledger = Ledger::default();
        let mut book = Book::new(e.id, BookKind::AssembleiaGeral);
        open_and_seal_book(&mut book, &e, abertura(&e), "sec@encosto", &mut ledger).unwrap();

        let reference = ManualSignatureOriginalReference {
            storage_reference: "Arquivo A / Pasta 2026 / Ata 1".to_owned(),
            custodian: Some("Secretariado".to_owned()),
            note: Some("Original assinado em papel; metadados locais apenas.".to_owned()),
        };
        let mut act = ready_act(&book);
        let outcome = seal_act(
            &mut book,
            &mut act,
            &e,
            &CscArt63RulePack,
            "sec@encosto",
            false,
            Some(reference.clone()),
            &mut ledger,
        )
        .unwrap();

        assert_eq!(
            outcome.seal_metadata.manual_signature_original_reference,
            Some(reference.clone())
        );
        assert_eq!(
            act.seal_metadata
                .as_ref()
                .and_then(|metadata| metadata.manual_signature_original_reference.as_ref()),
            Some(&reference)
        );
    }

    #[test]
    fn digital_signature_evidence_is_bound_and_frozen_before_seal() {
        let e = entity();
        let mut ledger = Ledger::default();
        ledger.append(
            "sec@encosto",
            &e.id.to_string(),
            "entity.created",
            None,
            b"entity",
        );
        let mut book = Book::new(e.id, BookKind::AssembleiaGeral);
        open_and_seal_book(&mut book, &e, abertura(&e), "sec@encosto", &mut ledger).unwrap();

        let snapshot = "11".repeat(32);
        let signed = "22".repeat(32);
        let validation = "33".repeat(32);
        let mut act = ready_act(&book);
        let outcome = seal_act_with_evidence(
            &mut book,
            &mut act,
            &e,
            &CscArt63RulePack,
            "sec@encosto",
            false,
            SealEvidence::Digital {
                signing_snapshot_digest: snapshot.clone(),
                signed_pdf_digest: signed.clone(),
                signature_validation_report_digest: validation.clone(),
            },
            &mut ledger,
        )
        .unwrap();

        assert_eq!(act.state, ActState::Sealed);
        assert!(
            outcome
                .seal_metadata
                .manual_signature_original_reference
                .is_none()
        );
        assert_eq!(
            outcome.seal_metadata.signing_snapshot_digest,
            Some(snapshot)
        );
        assert_eq!(outcome.seal_metadata.signed_pdf_digest, Some(signed));
        assert_eq!(
            outcome.seal_metadata.signature_validation_report_digest,
            Some(validation)
        );
        assert!(outcome.seal_metadata.has_complete_signature_evidence());
        assert_eq!(act.seal_metadata, Some(outcome.seal_metadata));
        assert_eq!(ledger.verify().unwrap(), 3);
    }

    #[test]
    fn malformed_digital_evidence_rolls_back_without_number_or_event() {
        let e = entity();
        let mut ledger = Ledger::default();
        let mut book = Book::new(e.id, BookKind::AssembleiaGeral);
        open_and_seal_book(&mut book, &e, abertura(&e), "sec@encosto", &mut ledger).unwrap();
        let mut act = ready_act(&book);

        let error = seal_act_with_evidence(
            &mut book,
            &mut act,
            &e,
            &CscArt63RulePack,
            "sec@encosto",
            false,
            SealEvidence::Digital {
                signing_snapshot_digest: "not-a-digest".to_owned(),
                signed_pdf_digest: "22".repeat(32),
                signature_validation_report_digest: "33".repeat(32),
            },
            &mut ledger,
        )
        .unwrap_err();

        assert!(matches!(error, SealError::InvalidSignatureEvidence(_)));
        assert_eq!(book.last_ata_number, 0);
        assert_eq!(act.state, ActState::Signing);
        assert!(act.seal_metadata.is_none());
        assert_eq!(ledger.len(), 1);
    }

    #[test]
    fn manual_signature_original_reference_is_required_before_mutation() {
        let e = entity();
        let mut ledger = Ledger::default();
        let mut book = Book::new(e.id, BookKind::AssembleiaGeral);
        open_and_seal_book(&mut book, &e, abertura(&e), "sec@encosto", &mut ledger).unwrap();

        let mut act = ready_act(&book);
        let err = seal_act(
            &mut book,
            &mut act,
            &e,
            &CscArt63RulePack,
            "sec@encosto",
            false,
            None,
            &mut ledger,
        )
        .unwrap_err();

        assert!(matches!(
            err,
            SealError::MissingManualSignatureOriginalReference
        ));
        assert_eq!(book.last_ata_number, 0);
        assert_eq!(ledger.events().len(), 1);
        assert_eq!(act.state, ActState::Signing);
        assert!(act.seal_metadata.is_none());
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
            Some(manual_reference()),
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
            Some(manual_reference()),
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
            Some(manual_reference()),
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
            Some(manual_reference()),
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
            Some(manual_reference()),
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
                legal_basis: Vec::new(),
            }];
            if self.also_errors {
                issues.push(crate::rules::ComplianceIssue {
                    rule_id: "TEST/blocking".into(),
                    severity: crate::rules::Severity::Error,
                    message: "blocking finding".into(),
                    legal_basis: Vec::new(),
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
            Some(manual_reference()),
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
            Some(manual_reference()),
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
            Some(manual_reference()),
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

    #[test]
    fn g1_g2_bind_into_the_seal_digest_when_present() {
        // R8: a populated convening record or attendance list must change the sealed preimage,
        // so it is bound into the new seal's digest.
        let book = Book::new(EntityId::new(), BookKind::AssembleiaGeral);
        let base = ready_act(&book);
        let bytes = |a: &Act| serde_json::to_vec(&ActPayload::of(a)).unwrap();

        let mut with_convening = base.clone();
        with_convening.convening = Some(crate::act::Convening {
            convener: Some("Amélia Marques".into()),
            antecedence_days: Some(15),
            ..Default::default()
        });
        assert_ne!(bytes(&base), bytes(&with_convening), "convening must bind");

        let mut with_attendees = base.clone();
        with_attendees.attendees = vec![crate::act::Attendee {
            name: "Amélia Marques".into(),
            quality: crate::act::SignatoryCapacity::Member,
            quality_note: None,
            presence: crate::act::PresenceMode::InPerson,
            represented_by: None,
            weight: Some(crate::act::AttendanceWeight::Permilage(250)),
        }];
        assert_ne!(bytes(&base), bytes(&with_attendees), "attendees must bind");
    }

    #[test]
    fn written_resolution_evidence_binds_into_the_seal_digest_when_present() {
        let book = Book::new(EntityId::new(), BookKind::AssembleiaGeral);
        let mut base = ready_act(&book);
        base.channel = MeetingChannel::WrittenResolution;
        let bytes = |a: &Act| serde_json::to_vec(&ActPayload::of(a)).unwrap();

        let mut with_evidence = base.clone();
        with_evidence.written_resolution_evidence = Some(WrittenResolutionEvidence {
            checklist: vec![WrittenResolutionEvidenceItem {
                label: "Signed written approvals".to_owned(),
                reference: Some("doc:written-approvals".to_owned()),
                digest: Some([11; 32]),
                note: Some("capture note".to_owned()),
            }],
            review_receipts: vec![],
            note: Some("operator note".to_owned()),
        });

        assert_ne!(
            bytes(&base),
            bytes(&with_evidence),
            "written-resolution evidence must bind"
        );
        let json = String::from_utf8(bytes(&with_evidence)).unwrap();
        assert!(json.contains("written_resolution_evidence"));
    }

    #[test]
    fn digest_of_pre_existing_act_is_unchanged_by_g1_g2_fields() {
        // The critical backward-compat guarantee: an act carrying neither a convening record
        // nor structured attendees (i.e. one that predates G1/G2) must produce a preimage —
        // and therefore a digest — **byte-identical** to what it produced before the fields
        // were appended. Already-sealed acts thus stay chain-valid.
        use sha2::{Digest, Sha256};

        let book = Book::new(EntityId::new(), BookKind::AssembleiaGeral);
        let act = ready_act(&book);
        assert!(act.convening.is_none() && act.attendees.is_empty());

        // Faithful reconstruction of the ActPayload shape *before* G1/G2 were appended: the
        // same fields, same declaration order, up to `members_represented`.
        #[derive(Serialize)]
        struct OldActPayload<'a> {
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
            meeting_time: Option<time::Time>,
            mesa: &'a Mesa,
            agenda: &'a [AgendaItem],
            referenced_documents: &'a [DocumentReference],
            deliberation_items: &'a [DeliberationItem],
            members_present: Option<u32>,
            members_represented: Option<u32>,
        }
        let old = OldActPayload {
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
        };

        let new_bytes = serde_json::to_vec(&ActPayload::of(&act)).unwrap();
        let old_bytes = serde_json::to_vec(&old).unwrap();

        // Preimage is byte-unchanged, and the empty G1/G2 fields emit nothing at all.
        assert_eq!(new_bytes, old_bytes);
        let json = String::from_utf8(new_bytes.clone()).unwrap();
        assert!(
            !json.contains("convening"),
            "empty convening must not serialize"
        );
        assert!(
            !json.contains("attendees"),
            "empty attendees must not serialize"
        );

        // Byte-identical preimage ⇒ identical sha-256 digest (chain-valid).
        assert_eq!(
            Sha256::digest(&new_bytes).as_slice(),
            Sha256::digest(&old_bytes).as_slice(),
        );
    }

    #[test]
    fn digest_of_pre_existing_act_is_unchanged_by_the_f15_page_count() {
        // The same guarantee for F15. An act carrying no frozen page count — every act that
        // predates the capacity model, and any act sealed without one — must produce a
        // preimage byte-identical to what it produced before `page_count` was appended.
        use sha2::{Digest, Sha256};

        let book = Book::new(EntityId::new(), BookKind::AssembleiaGeral);
        let act = ready_act(&book);
        assert!(act.page_count.is_none());

        // Faithful reconstruction of the ActPayload shape *before* F15 was appended: the same
        // fields, same declaration order, up to `attendees`.
        #[derive(Serialize)]
        struct OldActPayload<'a> {
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
            meeting_time: Option<time::Time>,
            mesa: &'a Mesa,
            agenda: &'a [AgendaItem],
            referenced_documents: &'a [DocumentReference],
            #[serde(skip_serializing_if = "Option::is_none")]
            written_resolution_evidence: Option<&'a WrittenResolutionEvidence>,
            deliberation_items: &'a [DeliberationItem],
            members_present: Option<u32>,
            members_represented: Option<u32>,
            #[serde(skip_serializing_if = "Option::is_none")]
            convening: Option<&'a Convening>,
            #[serde(skip_serializing_if = "Option::is_none")]
            attendees: Option<&'a [Attendee]>,
        }
        let old = OldActPayload {
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
            written_resolution_evidence: act.written_resolution_evidence.as_ref(),
            deliberation_items: &act.deliberation_items,
            members_present: act.members_present,
            members_represented: act.members_represented,
            convening: act.convening.as_ref(),
            attendees: (!act.attendees.is_empty()).then_some(act.attendees.as_slice()),
        };

        let new_bytes = serde_json::to_vec(&ActPayload::of(&act)).unwrap();
        let old_bytes = serde_json::to_vec(&old).unwrap();

        assert_eq!(new_bytes, old_bytes);
        let json = String::from_utf8(new_bytes.clone()).unwrap();
        assert!(
            !json.contains("page_count"),
            "an absent page count must not serialize"
        );
        assert_eq!(
            Sha256::digest(&new_bytes).as_slice(),
            Sha256::digest(&old_bytes).as_slice(),
        );
    }

    #[test]
    fn a_frozen_page_count_binds_into_the_seal_digest() {
        // The companion proof: F15 is not silently dropped. A frozen page count changes the
        // preimage, so the seal binds the act's page consumption as a recorded fact.
        let book = Book::new(EntityId::new(), BookKind::AssembleiaGeral);
        let mut act = ready_act(&book);
        let without = serde_json::to_vec(&ActPayload::of(&act)).unwrap();

        act.freeze_page_count(3).unwrap();
        let with = serde_json::to_vec(&ActPayload::of(&act)).unwrap();

        assert_ne!(without, with, "a frozen page count must bind");
        let json = String::from_utf8(with).unwrap();
        assert!(json.contains("\"page_count\":3"), "{json}");
    }

    #[test]
    fn reopen_history_binds_into_the_seal_digest_without_moving_untouched_acts() {
        // Two halves of one guarantee. An act that was never reopened must produce a preimage
        // byte-identical to what it produced before the field existed; an act that *was* reopened
        // must seal carrying that regression, not hiding it.
        let book = Book::new(EntityId::new(), BookKind::AssembleiaGeral);
        let act = ready_act(&book);
        assert!(act.superseded_signing_snapshots.is_empty());
        let without = serde_json::to_vec(&ActPayload::of(&act)).unwrap();
        assert!(
            !String::from_utf8(without.clone())
                .unwrap()
                .contains("superseded_signing_snapshots"),
            "an act that was never reopened must emit no bytes for the field"
        );

        let mut reopened = act.clone();
        reopened.reopen_for_correction().unwrap();
        reopened.record_superseded_signing_snapshot(crate::act::SupersededSigningSnapshot {
            document_id: "doc-1".to_owned(),
            pdf_digest: "aa".repeat(32),
            actor: "amelia.marques".to_owned(),
            superseded_at: time::OffsetDateTime::UNIX_EPOCH,
            reason: "mesa em falta".to_owned(),
        });
        reopened.advance_to(ActState::Signing).unwrap();

        let with = serde_json::to_vec(&ActPayload::of(&reopened)).unwrap();
        assert_ne!(without, with, "a retired signing snapshot must bind");
        assert!(String::from_utf8(with).unwrap().contains("doc-1"));
    }

    #[test]
    fn a_page_count_is_frozen_once_and_never_moved() {
        // R6: the count is captured at the content freeze and is a historical fact. If a
        // template revision changed the rendered length, re-freezing must be refused rather
        // than silently moving a sealed act's page consumption.
        let book = Book::new(EntityId::new(), BookKind::AssembleiaGeral);
        let mut act = ready_act(&book);
        act.freeze_page_count(4).unwrap();
        // Idempotent for the same value, so a retried freeze is harmless.
        act.freeze_page_count(4).unwrap();
        assert!(matches!(
            act.freeze_page_count(5),
            Err(ActError::PageCountAlreadyFrozen { frozen: 4 })
        ));
        assert_eq!(act.page_count, Some(4));
    }

    #[test]
    fn a_sealed_act_cannot_acquire_a_page_count_after_the_fact() {
        let entity = entity();
        let mut ledger = Ledger::default();
        let mut book = Book::new(entity.id, BookKind::AssembleiaGeral);
        open_and_seal_book(&mut book, &entity, abertura(&entity), "sec@x", &mut ledger).unwrap();
        let mut act = ready_act(&book);
        seal_act(
            &mut book,
            &mut act,
            &entity,
            &CscArt63RulePack,
            "sec@x",
            true,
            Some(manual_reference()),
            &mut ledger,
        )
        .unwrap();
        assert_eq!(act.state, ActState::Sealed);
        assert!(matches!(act.freeze_page_count(2), Err(ActError::Sealed)));
    }
}
