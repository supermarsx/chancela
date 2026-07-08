//! Acts (*atas*): the minutes themselves, with their lifecycle state machine.
//!
//! Grounding: spec 06 §1 (WFL-01/02) and §3 (WFL-20/21). An act is drafted, reviewed,
//! and progressively locked down through convening, deliberating, text approval, and
//! signing, then **sealed** — after which it is append-only (DAT-12) and corrections must
//! be a new act referencing it (WFL-21).

use serde::{Deserialize, Serialize};
use time::{Date, Time};
use uuid::Uuid;

use crate::book::BookId;
use crate::error::ActError;

/// Opaque identifier for an [`Act`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ActId(pub Uuid);

impl ActId {
    /// Mint a fresh random identifier.
    pub fn new() -> Self {
        ActId(Uuid::new_v4())
    }
}

impl Default for ActId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ActId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The meeting / deliberation channel (WFL-02; LEG-04 for telematic).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MeetingChannel {
    /// In-person meeting.
    Physical,
    /// Mixed in-person and remote.
    Hybrid,
    /// Fully remote; for SA this carries the CSC art. 377.º evidence set (ENT-C4).
    Telematic,
    /// Deliberação unânime por escrito / voto escrito (ENT-C5).
    WrittenResolution,
}

/// The act lifecycle (WFL-01). Transitions are one step forward at a time until sealing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActState {
    /// Being drafted; freely editable.
    Draft,
    /// Under review.
    Review,
    /// Meeting convened (convocatória issued).
    Convened,
    /// Deliberations held.
    Deliberated,
    /// Text of the ata approved.
    TextApproved,
    /// Out for signature collection (SIG-31).
    Signing,
    /// Sealed / finalized and locked — append-only (WFL-20 / DAT-12).
    Sealed,
    /// Archived into a preservation package.
    Archived,
}

/// The kind of a supporting document chained to the act (WFL-02 / WFL-33).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttachmentKind {
    /// Convocatória.
    Convocatoria,
    /// Agenda / ordem de trabalhos.
    Agenda,
    /// Procuração / proxy document.
    Proxy,
    /// Lista de presenças.
    AttendanceList,
    /// Relatório.
    Report,
    /// Documento anexo genérico (exhibit).
    Exhibit,
    /// Anything else.
    Other,
}

/// A document attached to the act. `digest` is a sha-256 of the file bytes when known;
/// the bytes themselves live in the document store, not in the domain model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attachment {
    /// Human label.
    pub label: String,
    /// Document category.
    pub kind: AttachmentKind,
    /// Optional content digest, folded into the act payload digest when present.
    pub digest: Option<[u8; 32]>,
    /// When `true`, this document is a *detached private document* whose evidentiary weight
    /// is reduced: under CSC art. 63.º a resolution found only in such a document is merely a
    /// **beginning of proof** (ENT-C6). The CSC pack surfaces this as an advisory. Defaults to
    /// `false` (additive; old-shape attachments deserialize without it).
    #[serde(default)]
    pub beginning_of_proof: bool,
}

/// The capacity in which a signatory signs — part of the evidence (ROL-04 / SIG-04).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatoryCapacity {
    /// Presidente da mesa / chair.
    Chair,
    /// Secretário.
    Secretary,
    /// Member / sócio / associado.
    Member,
    /// Gerente.
    Manager,
    /// Administrador (SA / condomínio).
    Administrator,
    /// Mandatário / procurador.
    Attorney,
    /// Condómino (condominium owner).
    CondoOwner,
}

/// A signature slot on the act: who is expected to sign, in what capacity, and whether
/// they have. The cryptographic artifact itself lives in `chancela-signing`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatorySlot {
    /// Signatory name.
    pub name: String,
    /// Capacity in which they sign.
    pub capacity: SignatoryCapacity,
    /// Whether a signature has been collected for this slot.
    pub signed: bool,
    /// For a condominium owner ([`SignatoryCapacity::CondoOwner`]), the owner's *permilagem*
    /// (millésimos, 0..=1000) — the fraction of the building this owner represents (ENT-D6).
    /// Metadata only in this scaffold: permilage-weighted vote tallies are deferred. Defaults
    /// to `None` (additive; old-shape signatories deserialize without it).
    #[serde(default)]
    pub permilage: Option<u16>,
}

/// The **mesa** (presiding board) of a meeting: the chair and any secretaries (CSC art. 63.º).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Mesa {
    /// Presidente da mesa / chair. An ata with no chair identified is defective (CSC art. 63.º).
    pub presidente: Option<String>,
    /// Secretários. Small organs legitimately have none.
    pub secretarios: Vec<String>,
}

/// One point on the **ordem de trabalhos** (agenda) of a meeting (CSC art. 63.º).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgendaItem {
    /// Sequential point number within the agenda.
    pub number: u32,
    /// Text of the agenda point.
    pub text: String,
}

/// A document submitted to or referenced by the meeting (CSC art. 63.º "references to
/// submitted documents"). A capture field — legitimately may be empty.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocumentReference {
    /// Human label for the document (e.g., "Relatório de gestão 2025").
    pub label: String,
    /// Optional external reference / locator (registry entry, archive id, digest note).
    pub reference: Option<String>,
}

/// A structured voting result for one resolution (CSC art. 63.º "voting results").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VoteResult {
    /// Carried unanimously.
    Unanimous,
    /// Recorded tally: votes in favour, against, and abstentions.
    Recorded {
        /// Votes in favour.
        em_favor: u32,
        /// Votes against.
        contra: u32,
        /// Abstentions.
        abstencoes: u32,
    },
}

/// A statement a member asked to have recorded (*declaração*), including a *declaração de
/// voto vencido*. A capture field — the absence of one cannot be proven, so it is never a gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberStatement {
    /// Member who made the statement.
    pub member: String,
    /// Text of the statement.
    pub text: String,
}

/// One structured deliberation, tied to an agenda item when known (R3). This is **additive**
/// to the free-text [`Act::deliberations`], never a replacement: the free-text path is the
/// import / historical / simple-ata fallback, and the structured path unlocks the deeper
/// per-vote and statute-majority checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliberationItem {
    /// The agenda point this deliberation resolves, when known.
    #[serde(default)]
    pub agenda_number: Option<u32>,
    /// Full text of the resolution taken.
    pub text: String,
    /// Structured voting result, when captured.
    #[serde(default)]
    pub vote: Option<VoteResult>,
    /// Statements (*declarações*) members asked to have recorded against this resolution.
    #[serde(default)]
    pub statements: Vec<MemberStatement>,
}

/// The channel through which a convocatória (meeting notice) was dispatched — part of the
/// TPL-20 dispatch-proof evidence. The statutory *minimum* antecedence for each channel is a
/// legal threshold owned by the templates registry, **not** modelled here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DispatchChannel {
    /// Carta registada.
    RegisteredLetter,
    /// Carta registada com aviso de receção.
    RegisteredLetterAR,
    /// Correio eletrónico.
    Email,
    /// Entrega em mão (contra recibo).
    HandDelivery,
    /// Publicação (e.g. site das publicações do MJ / imprensa).
    Publication,
    /// Portal / plataforma eletrónica da entidade.
    Portal,
}

/// One recipient of the convocatória, with the individual dispatch proof (TPL-20).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConveningRecipient {
    /// Recipient name.
    pub name: String,
    /// Channel this recipient was reached through, when it differs from the convening default.
    #[serde(default)]
    pub channel: Option<DispatchChannel>,
    /// Dispatch reference (registered-letter tracking number, email id, receipt number, …).
    #[serde(default)]
    pub reference: Option<String>,
    /// When the notice was dispatched to this recipient.
    #[serde(default)]
    pub dispatched_at: Option<Date>,
}

/// The **second convocation** of a meeting (condominium reduced-quorum 2.ª convocatória, CC
/// art. 1432.º/4): the fallback session that may deliberate on a reduced quorum when the first
/// call fails to gather one.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SecondCall {
    /// Date of the second convocation.
    #[serde(default)]
    pub date: Option<Date>,
    /// Time of the second convocation.
    #[serde(default)]
    pub time: Option<Time>,
    /// Whether the second call deliberates on the statutory reduced quorum.
    #[serde(default)]
    pub reduced_quorum: bool,
}

/// The **convening** (convocatória) record: metadata about how the meeting the [`Act`]
/// represents was called (spec gap G1). `antecedence_days` is the **actual** notice given —
/// the statutory **minimum** is a legal threshold in the templates registry, never hardcoded
/// here. Additive metadata; every field defaults so an act without a convening record (or with
/// a partial one) round-trips unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Convening {
    /// Who convened the meeting (the competent organ / person).
    #[serde(default)]
    pub convener: Option<String>,
    /// The capacity in which the convener acted.
    #[serde(default)]
    pub convener_capacity: Option<SignatoryCapacity>,
    /// When the notice was dispatched.
    #[serde(default)]
    pub dispatch_date: Option<Date>,
    /// The **actual** notice given, in days (not the statutory minimum — that is a threshold).
    #[serde(default)]
    pub antecedence_days: Option<u16>,
    /// The default dispatch channel for the convocatória.
    #[serde(default)]
    pub channel: Option<DispatchChannel>,
    /// Per-recipient dispatch proof (TPL-20).
    #[serde(default)]
    pub recipients: Vec<ConveningRecipient>,
    /// The reduced-quorum second convocation, when one was set (condominium).
    #[serde(default)]
    pub second_call: Option<SecondCall>,
}

/// How an attendee took part in the meeting (spec gap G2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PresenceMode {
    /// Present in person.
    InPerson,
    /// Represented by a proxy / mandatário.
    Represented,
    /// Absent (recorded for the lista and for absent-owner communications, TPL-41).
    Absent,
}

/// The voting weight an attendee carries. Companies weight by **capital**; condominiums weight
/// by **permilagem** (millésimos). Weighted tallies themselves stay deferred (ENT-D6) — this
/// carries the row datum, not the arithmetic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttendanceWeight {
    /// Represented capital, in minor units (e.g. cents).
    Capital(u64),
    /// Permilagem (‰), 0..=1000.
    Permilage(u32),
}

/// One row of the structured **lista de presenças** (spec gap G2). Coexists with the
/// [`Act::members_present`] / [`Act::members_represented`] counts, which remain the fallback;
/// when `attendees` is non-empty a per-row list can be rendered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attendee {
    /// Attendee name.
    pub name: String,
    /// The capacity in which they attend (reuses the signatory capacity vocabulary).
    pub quality: SignatoryCapacity,
    /// Whether they were present in person, represented, or absent.
    pub presence: PresenceMode,
    /// When [`PresenceMode::Represented`], the proxy who stood in for them.
    #[serde(default)]
    pub represented_by: Option<String>,
    /// The capital / permilagem this attendee carries, when weighted.
    #[serde(default)]
    pub weight: Option<AttendanceWeight>,
}

/// An **ata**. Mutable through the pre-seal states; frozen at sealing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Act {
    /// Stable identifier.
    pub id: ActId,
    /// The book this act belongs to (WFL-14).
    pub book_id: BookId,
    /// Title / subject.
    pub title: String,
    /// Meeting channel.
    pub channel: MeetingChannel,
    /// Meeting date (part of the CSC art. 63.º mandatory contents).
    pub meeting_date: Option<Date>,
    /// Meeting time (CSC art. 63.º mandatory contents). Additive; defaults to `None`.
    #[serde(default)]
    pub meeting_time: Option<Time>,
    /// Meeting place (part of the CSC art. 63.º mandatory contents).
    pub place: Option<String>,
    /// The mesa (presiding board): chair and secretaries (CSC art. 63.º). Additive; defaults
    /// to an empty mesa.
    #[serde(default)]
    pub mesa: Mesa,
    /// The ordem de trabalhos (agenda). Additive; defaults to empty.
    #[serde(default)]
    pub agenda: Vec<AgendaItem>,
    /// Reference to the attendance evidence (lista de presenças).
    pub attendance_reference: Option<String>,
    /// Number of members present in person (statute-quorum overlay input). Additive.
    #[serde(default)]
    pub members_present: Option<u32>,
    /// Number of members represented (by proxy). Additive.
    #[serde(default)]
    pub members_represented: Option<u32>,
    /// Documents submitted to or referenced by the meeting (CSC art. 63.º). Additive; empty.
    #[serde(default)]
    pub referenced_documents: Vec<DocumentReference>,
    /// The deliberations text — the substance of the ata.
    pub deliberations: String,
    /// Structured deliberations, additive to the free-text `deliberations` (R3). Empty on the
    /// free-text / historical / simple-ata path; populated on the structured path.
    #[serde(default)]
    pub deliberation_items: Vec<DeliberationItem>,
    /// For telematic SA meetings, the art. 377.º evidence note (ENT-C4 / LEG-04).
    pub telematic_evidence: Option<String>,
    /// Chained supporting documents (WFL-33).
    pub attachments: Vec<Attachment>,
    /// Signature slots (SIG-31 / ROL-04).
    pub signatories: Vec<SignatorySlot>,
    /// Current lifecycle state.
    pub state: ActState,
    /// Sequential ata number within the book, assigned at sealing (WFL-12).
    pub ata_number: Option<u64>,
    /// Frozen payload digest, set at sealing.
    pub payload_digest: Option<[u8; 32]>,
    /// Sequence number of the seal event in the book's ledger, set at sealing.
    pub seal_event_seq: Option<u64>,
    /// When this act corrects an earlier sealed one, the retificação chain link (WFL-21).
    pub retifies: Option<ActId>,
    /// The convening (convocatória) record for this meeting (spec gap G1). Additive and
    /// **append-only**: defaults to `None` so acts predating this field round-trip unchanged.
    #[serde(default)]
    pub convening: Option<Convening>,
    /// The structured lista de presenças (spec gap G2). Additive and **append-only**: defaults
    /// to empty so acts predating this field round-trip unchanged.
    #[serde(default)]
    pub attendees: Vec<Attendee>,
}

impl Act {
    /// Start a fresh draft act in `book`.
    pub fn draft(book_id: BookId, title: impl Into<String>, channel: MeetingChannel) -> Self {
        Act {
            id: ActId::new(),
            book_id,
            title: title.into(),
            channel,
            meeting_date: None,
            meeting_time: None,
            place: None,
            mesa: Mesa::default(),
            agenda: Vec::new(),
            attendance_reference: None,
            members_present: None,
            members_represented: None,
            referenced_documents: Vec::new(),
            deliberations: String::new(),
            deliberation_items: Vec::new(),
            telematic_evidence: None,
            attachments: Vec::new(),
            signatories: Vec::new(),
            state: ActState::Draft,
            ata_number: None,
            payload_digest: None,
            seal_event_seq: None,
            retifies: None,
            convening: None,
            attendees: Vec::new(),
        }
    }

    /// Whether the act's content may still be edited (i.e., it is not yet sealed).
    pub fn is_mutable(&self) -> bool {
        !matches!(self.state, ActState::Sealed | ActState::Archived)
    }

    fn ensure_mutable(&self) -> Result<(), ActError> {
        if self.is_mutable() {
            Ok(())
        } else {
            Err(ActError::Sealed)
        }
    }

    /// Set the deliberations text (rejected once sealed).
    pub fn set_deliberations(&mut self, text: impl Into<String>) -> Result<(), ActError> {
        self.ensure_mutable()?;
        self.deliberations = text.into();
        Ok(())
    }

    /// Attach a supporting document (rejected once sealed).
    pub fn add_attachment(&mut self, attachment: Attachment) -> Result<(), ActError> {
        self.ensure_mutable()?;
        self.attachments.push(attachment);
        Ok(())
    }

    /// Add a signatory slot (rejected once sealed).
    pub fn add_signatory(&mut self, slot: SignatorySlot) -> Result<(), ActError> {
        self.ensure_mutable()?;
        self.signatories.push(slot);
        Ok(())
    }

    /// Advance one step through the pre-seal lifecycle.
    ///
    /// Legal transitions: `Draft → Review → Convened → Deliberated → TextApproved →
    /// Signing`. Sealing (`Signing → Sealed`) is performed by [`crate::seal::seal_act`],
    /// and archiving (`Sealed → Archived`) by [`Act::archive`], because both do more than
    /// flip the state.
    pub fn advance_to(&mut self, to: ActState) -> Result<(), ActError> {
        let ok = matches!(
            (self.state, to),
            (ActState::Draft, ActState::Review)
                | (ActState::Review, ActState::Convened)
                | (ActState::Convened, ActState::Deliberated)
                | (ActState::Deliberated, ActState::TextApproved)
                | (ActState::TextApproved, ActState::Signing)
        );
        if ok {
            self.state = to;
            Ok(())
        } else {
            Err(ActError::InvalidTransition {
                from: self.state,
                to,
            })
        }
    }

    /// Archive a sealed act (`Sealed → Archived`).
    pub fn archive(&mut self) -> Result<(), ActError> {
        if self.state == ActState::Sealed {
            self.state = ActState::Archived;
            Ok(())
        } else {
            Err(ActError::InvalidTransition {
                from: self.state,
                to: ActState::Archived,
            })
        }
    }

    /// Mark the act sealed. Internal to the sealing flow: requires the `Signing` state and
    /// records the assigned ata number, frozen digest, and ledger event sequence. Callers
    /// should go through [`crate::seal::seal_act`] rather than calling this directly.
    pub(crate) fn mark_sealed(
        &mut self,
        ata_number: u64,
        payload_digest: [u8; 32],
        seal_event_seq: u64,
    ) -> Result<(), ActError> {
        if self.state != ActState::Signing {
            return Err(ActError::InvalidTransition {
                from: self.state,
                to: ActState::Sealed,
            });
        }
        self.ata_number = Some(ata_number);
        self.payload_digest = Some(payload_digest);
        self.seal_event_seq = Some(seal_event_seq);
        self.state = ActState::Sealed;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::book::BookId;

    fn draft() -> Act {
        Act::draft(BookId::new(), "Ata n.º 1", MeetingChannel::Physical)
    }

    #[test]
    fn advances_through_the_full_forward_path() {
        let mut act = draft();
        for state in [
            ActState::Review,
            ActState::Convened,
            ActState::Deliberated,
            ActState::TextApproved,
            ActState::Signing,
        ] {
            act.advance_to(state).unwrap();
            assert_eq!(act.state, state);
        }
    }

    #[test]
    fn rejects_skipping_a_state() {
        let mut act = draft();
        assert!(matches!(
            act.advance_to(ActState::Signing),
            Err(ActError::InvalidTransition {
                from: ActState::Draft,
                to: ActState::Signing
            })
        ));
    }

    #[test]
    fn advance_cannot_reach_sealed_or_archived() {
        let mut act = draft();
        act.advance_to(ActState::Review).unwrap();
        assert!(matches!(
            act.advance_to(ActState::Sealed),
            Err(ActError::InvalidTransition { .. })
        ));
    }

    #[test]
    fn mark_sealed_requires_signing_then_freezes() {
        let mut act = draft();
        // Not yet in Signing.
        assert!(act.mark_sealed(1, [0u8; 32], 0).is_err());

        for state in [
            ActState::Review,
            ActState::Convened,
            ActState::Deliberated,
            ActState::TextApproved,
            ActState::Signing,
        ] {
            act.advance_to(state).unwrap();
        }
        act.mark_sealed(7, [9u8; 32], 3).unwrap();
        assert_eq!(act.state, ActState::Sealed);
        assert_eq!(act.ata_number, Some(7));
        assert_eq!(act.seal_event_seq, Some(3));
        assert!(!act.is_mutable());
    }

    #[test]
    fn sealed_act_refuses_content_mutation() {
        let mut act = draft();
        for state in [
            ActState::Review,
            ActState::Convened,
            ActState::Deliberated,
            ActState::TextApproved,
            ActState::Signing,
        ] {
            act.advance_to(state).unwrap();
        }
        act.mark_sealed(1, [0u8; 32], 0).unwrap();
        assert!(matches!(
            act.set_deliberations("tampered"),
            Err(ActError::Sealed)
        ));
        assert!(matches!(
            act.add_attachment(Attachment {
                label: "x".into(),
                kind: AttachmentKind::Exhibit,
                digest: None,
                beginning_of_proof: false,
            }),
            Err(ActError::Sealed)
        ));
    }

    #[test]
    fn archive_only_from_sealed() {
        let mut act = draft();
        assert!(act.archive().is_err());
        for state in [
            ActState::Review,
            ActState::Convened,
            ActState::Deliberated,
            ActState::TextApproved,
            ActState::Signing,
        ] {
            act.advance_to(state).unwrap();
        }
        act.mark_sealed(1, [0u8; 32], 0).unwrap();
        act.archive().unwrap();
        assert_eq!(act.state, ActState::Archived);
    }

    #[test]
    fn old_shape_act_without_convening_or_attendees_deserializes_to_defaults() {
        // An act serialized before G1/G2 existed carries no `convening`/`attendees` keys.
        // Simulate that by stripping the keys, then prove they deserialize to empty defaults
        // and the value is otherwise unchanged (backward-compatible storage).
        let act = draft();
        let mut value = serde_json::to_value(&act).unwrap();
        let obj = value.as_object_mut().unwrap();
        obj.remove("convening");
        obj.remove("attendees");
        assert!(!obj.contains_key("convening"));
        assert!(!obj.contains_key("attendees"));

        let restored: Act = serde_json::from_value(value).unwrap();
        assert_eq!(restored.convening, None);
        assert!(restored.attendees.is_empty());
        // Everything round-trips: the defaulted act equals the original, and re-serializes
        // identically.
        assert_eq!(restored, act);
        assert_eq!(
            serde_json::to_string(&restored).unwrap(),
            serde_json::to_string(&act).unwrap()
        );
    }

    #[test]
    fn act_with_convening_and_attendees_round_trips() {
        use time::macros::{date, time};

        let mut act = draft();
        act.convening = Some(Convening {
            convener: Some("Amélia Marques".into()),
            convener_capacity: Some(SignatoryCapacity::Chair),
            dispatch_date: Some(date!(2026 - 03 - 10)),
            antecedence_days: Some(15),
            channel: Some(DispatchChannel::RegisteredLetterAR),
            recipients: vec![ConveningRecipient {
                name: "Encosto Estratégico Lda".into(),
                channel: Some(DispatchChannel::Email),
                reference: Some("RR123456789PT".into()),
                dispatched_at: Some(date!(2026 - 03 - 10)),
            }],
            second_call: Some(SecondCall {
                date: Some(date!(2026 - 03 - 30)),
                time: Some(time!(10:30)),
                reduced_quorum: true,
            }),
        });
        act.attendees = vec![
            Attendee {
                name: "Amélia Marques".into(),
                quality: SignatoryCapacity::Member,
                presence: PresenceMode::InPerson,
                represented_by: None,
                weight: Some(AttendanceWeight::Capital(500_000)),
            },
            Attendee {
                name: "Encosto Estratégico Lda".into(),
                quality: SignatoryCapacity::CondoOwner,
                presence: PresenceMode::Represented,
                represented_by: Some("Amélia Marques".into()),
                weight: Some(AttendanceWeight::Permilage(250)),
            },
        ];

        let json = serde_json::to_string(&act).unwrap();
        let restored: Act = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, act);
    }
}
