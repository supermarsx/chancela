//! Acts (*atas*): the minutes themselves, with their lifecycle state machine.
//!
//! Grounding: spec 06 §1 (WFL-01/02) and §3 (WFL-20/21). An act is drafted, reviewed,
//! and progressively locked down through convening, deliberating, text approval, and
//! signing, then **sealed** — after which it is append-only (DAT-12) and corrections must
//! be a new act referencing it (WFL-21).

use serde::{Deserialize, Serialize};
use time::{Date, OffsetDateTime, Time};
use uuid::Uuid;

use crate::book::BookId;
use crate::entity::{EntityFamily, EntityKind};
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

/// Human-review status for AI-assisted act text. `Accepted` means only that a person reviewed the
/// AI-assisted draft; it is not a legal-validity assertion.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum AiHumanVerificationStatus {
    /// Awaiting human review.
    #[serde(rename = "pending_human_verification")]
    #[default]
    Pending,
    /// A human reviewed the AI-assisted content.
    #[serde(rename = "accepted_by_human")]
    Accepted,
    /// A human rejected the AI-assisted content.
    #[serde(rename = "rejected_by_human")]
    Rejected,
}

/// Human-review evidence attached to AI provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiHumanVerification {
    /// Review status. Defaults to pending for additive compatibility.
    #[serde(default)]
    pub status: AiHumanVerificationStatus,
    /// Actor who accepted/rejected the review, when reviewed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    /// UTC review timestamp, when reviewed.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub reviewed_at: Option<OffsetDateTime>,
    /// Operator note. This is human-review context only, not a legal-validity claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl Default for AiHumanVerification {
    fn default() -> Self {
        AiHumanVerification {
            status: AiHumanVerificationStatus::Pending,
            actor: None,
            reviewed_at: None,
            note: None,
        }
    }
}

/// Statement-level provenance row for AI-assisted draft content. These rows are source breadcrumbs
/// only; flags default to safe false and do not assert legal validity or authoritative status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiStatementSource {
    /// JSON-ish path or stable label for the drafted statement/field.
    pub path: String,
    /// Source kind, for example `ai_suggestion` or `caller_supplied`.
    pub source_type: String,
    /// Human-readable source label, for example `arguments.title`.
    pub source_label: String,
    /// Whether this row has been human-verified. Kept false for draft provenance.
    #[serde(default)]
    pub human_verified: bool,
    /// Row-level human-review status. Defaults to pending.
    #[serde(default)]
    pub human_verification_status: AiHumanVerificationStatus,
    /// Whether an authoritative source is claimed. Kept false for draft provenance.
    #[serde(default)]
    pub authoritative_source_claimed: bool,
    /// Whether legal validity is claimed. Kept false for draft provenance.
    #[serde(default)]
    pub legal_validity_claimed: bool,
}

/// Non-authoritative provenance for AI-assisted draft creation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiProvenance {
    /// Declared source of the AI assistance (for example, "mcp" or "api").
    pub source: String,
    /// Tool/model/integration identifier, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    /// Where the human statement or instruction came from, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statement_source: Option<String>,
    /// Statement-level source breadcrumbs. Additive; legacy records default to no rows.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub statement_sources: Vec<AiStatementSource>,
    /// Human-review status for the AI-assisted draft. Defaults to pending.
    #[serde(default)]
    pub human_verification: AiHumanVerification,
}

impl AiProvenance {
    /// Whether the human review gate has been accepted. This is not a legal-validity claim.
    #[must_use]
    pub fn human_review_accepted(&self) -> bool {
        self.human_verification.status == AiHumanVerificationStatus::Accepted
    }

    /// Record a human accept/reject decision.
    pub fn set_human_verification(
        &mut self,
        status: AiHumanVerificationStatus,
        actor: impl Into<String>,
        reviewed_at: OffsetDateTime,
        note: Option<String>,
    ) {
        self.human_verification = AiHumanVerification {
            status,
            actor: Some(actor.into()),
            reviewed_at: Some(reviewed_at),
            note,
        };
    }
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

/// The capacity in which a person signs an act or attends the meeting it records — part of the
/// evidence (ROL-04 / SIG-04, and the `quality` of an [`Attendee`]).
///
/// The vocabulary is deliberately shared between the two uses, because most capacities are both
/// (a gerente attends *and* signs). The two roles differ only in which subset is *offered*:
/// [`attendee_qualities`](crate::attendee_qualities) narrows the list to the membership term the
/// entity's legal type actually uses, plus the non-membership capacities that attend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatoryCapacity {
    /// Presidente da mesa / chair.
    Chair,
    /// Secretário.
    Secretary,
    /// Sócio — a member of a sociedade por quotas / em nome coletivo / em comandita.
    Member,
    /// Acionista — a shareholder of a sociedade anónima or em comandita por ações.
    Shareholder,
    /// Associado — a member of an associação.
    Associate,
    /// Cooperador — a member of a cooperativa (Código Cooperativo).
    Cooperator,
    /// Gerente.
    Manager,
    /// Administrador (SA / condomínio).
    Administrator,
    /// Mandatário / procurador.
    Attorney,
    /// Condómino (condominium owner).
    CondoOwner,
    /// Revisor oficial de contas / ROC.
    StatutoryAuditor,
    /// Convidado — attends without any membership or organic capacity.
    Guest,
    /// A capacity outside this vocabulary. On an attendance row it is the escape hatch for a
    /// legitimate but unmodelled qualidade, and the free text goes in
    /// [`Attendee::quality_note`] — never into the structured value, so that reporting over
    /// `quality` stays a closed set.
    Other,
}

/// A signature slot on the act: who is expected to sign, in what capacity, and whether
/// they have. The cryptographic artifact itself lives in `chancela-signing`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatorySlot {
    /// Signatory name.
    pub name: String,
    /// Optional contact email for coordinating this signatory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Capacity in which they sign.
    pub capacity: SignatoryCapacity,
    /// Whether a signature has been collected for this slot.
    pub signed: bool,
    /// For a condominium owner ([`SignatoryCapacity::CondoOwner`]), the owner's *permilagem*
    /// (millésimos, 0..=1000) — the fraction of the building this owner represents (ENT-D6).
    /// Used as auditable weight metadata where captured. Defaults to `None` (additive;
    /// old-shape signatories deserialize without it).
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

/// Boundary marker for the written-resolution evidence status derivation. The status is a
/// workflow/evidence-presence signal only; it is not a legal-sufficiency conclusion.
pub const WRITTEN_RESOLUTION_EVIDENCE_STATUS_BOUNDARY: &str = "workflow_evidence_status_only";

/// Optional written-resolution checklist metadata captured on an act. The stored data is
/// evidence-oriented: operators can record references and digests, while status is derived from
/// this metadata plus signed signatory slots and digested attachments.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct WrittenResolutionEvidence {
    /// Operator checklist items for the written approvals/evidence retained for this act.
    #[serde(default)]
    pub checklist: Vec<WrittenResolutionEvidenceItem>,
    /// Append-only operator review receipts for the retained evidence. These are local audit
    /// metadata only; they do not prove consent, quorum, identity, legal sufficiency, acceptance,
    /// or authority certification.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub review_receipts: Vec<WrittenResolutionReviewReceipt>,
    /// Operator note about the evidence capture. This is context only, not a validity claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// One written-resolution evidence checklist item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrittenResolutionEvidenceItem {
    /// Human label for the evidence item.
    pub label: String,
    /// External reference / locator when the item is referenced but not itself digest-bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    /// Optional sha-256 digest of the retained evidence bytes. Presence means this checklist item
    /// is bound into the sealed act payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<[u8; 32]>,
    /// Operator note about this item. This is evidence context only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Local operator review status for written-resolution evidence receipts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WrittenResolutionReviewStatus {
    /// The operator reviewed the retained evidence metadata.
    Reviewed,
    /// The operator found a gap or follow-up need in the retained evidence metadata.
    NeedsFollowUp,
}

impl WrittenResolutionReviewStatus {
    /// Stable wire/status string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            WrittenResolutionReviewStatus::Reviewed => "reviewed",
            WrittenResolutionReviewStatus::NeedsFollowUp => "needs_follow_up",
        }
    }
}

/// One reviewed evidence locator referenced by an operator receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrittenResolutionReviewEvidenceLocator {
    /// Human label for the reviewed local evidence.
    pub label: String,
    /// Local reference/path/document id when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locator: Option<String>,
    /// Optional sha-256 digest for the reviewed evidence bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<[u8; 32]>,
}

/// One append-only local review receipt for written-resolution evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrittenResolutionReviewReceipt {
    /// Operator/reviewer who recorded the local evidence review.
    pub reviewer: String,
    /// UTC review timestamp supplied by the operator/API caller.
    #[serde(with = "time::serde::rfc3339")]
    pub reviewed_at: OffsetDateTime,
    /// Local review status. This is not legal acceptance or approval.
    pub status: WrittenResolutionReviewStatus,
    /// Guardrail acknowledgements recorded by the operator before saving this receipt.
    #[serde(default)]
    pub guardrail_acknowledgements: Vec<String>,
    /// Evidence locators/digests considered in this local review.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<WrittenResolutionReviewEvidenceLocator>,
    /// Operator review note. This is local evidence context only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Explicit false proof/legal boundary flags.
    #[serde(default)]
    pub consent_proof_claimed: bool,
    #[serde(default)]
    pub quorum_proof_claimed: bool,
    #[serde(default)]
    pub identity_proof_claimed: bool,
    #[serde(default)]
    pub legal_acceptance_claimed: bool,
    #[serde(default)]
    pub legal_sufficiency_claimed: bool,
    #[serde(default)]
    pub external_validation_claimed: bool,
    #[serde(default)]
    pub automatic_approval_claimed: bool,
    #[serde(default)]
    pub authority_certified_claimed: bool,
}

/// Derived technical status for written-resolution evidence capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WrittenResolutionEvidenceStatus {
    /// The act is not a written-resolution act.
    NotApplicable,
    /// Written-resolution channel selected, but no bound evidence and no reference-only evidence.
    Missing,
    /// Written-resolution evidence is referenced, but no digest/signed slot binds it.
    ReferencedOnly,
    /// At least one signed signatory slot, digested attachment, or digested checklist item exists.
    BoundPresent,
}

impl WrittenResolutionEvidenceStatus {
    /// Stable wire/status string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            WrittenResolutionEvidenceStatus::NotApplicable => "not_applicable",
            WrittenResolutionEvidenceStatus::Missing => "missing",
            WrittenResolutionEvidenceStatus::ReferencedOnly => "referenced_only",
            WrittenResolutionEvidenceStatus::BoundPresent => "bound_present",
        }
    }
}

/// Aggregate counts behind a written-resolution evidence status. These are technical
/// evidence-presence counts only; they do not establish unanimity, signature qualification,
/// timestamp sufficiency, legal sufficiency, or enforceability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WrittenResolutionEvidenceSummary {
    /// Derived technical status.
    pub status: WrittenResolutionEvidenceStatus,
    /// Signed signatory slots on the act.
    pub signed_signatory_slots: usize,
    /// Attachments carrying a digest.
    pub digested_attachments: usize,
    /// Checklist items recorded in the optional metadata block.
    pub checklist_items: usize,
    /// Checklist items carrying a digest.
    pub digested_checklist_items: usize,
    /// Checklist items with a reference but no digest.
    pub referenced_checklist_items: usize,
    /// Operator review receipts recorded in the optional metadata block.
    pub review_receipts: usize,
    /// Status from the latest operator review receipt, when present.
    pub latest_review_status: Option<WrittenResolutionReviewStatus>,
    /// Evidence locator rows recorded across review receipts.
    pub reviewed_evidence_locators: usize,
    /// Evidence locator rows carrying a digest across review receipts.
    pub reviewed_evidence_digests: usize,
}

impl WrittenResolutionEvidenceSummary {
    /// Count of evidence surfaces bound into the sealed payload or signed slot set.
    #[must_use]
    pub const fn bound_count(self) -> usize {
        self.signed_signatory_slots + self.digested_attachments + self.digested_checklist_items
    }

    /// Count of reference-only evidence surfaces.
    #[must_use]
    pub const fn referenced_only_count(self) -> usize {
        self.referenced_checklist_items
    }
}

/// Derive the written-resolution evidence status for an act. This is a workflow/evidence
/// availability signal only and intentionally makes no legal sufficiency claim.
#[must_use]
pub fn written_resolution_evidence_summary(act: &Act) -> WrittenResolutionEvidenceSummary {
    let mut summary = WrittenResolutionEvidenceSummary {
        status: WrittenResolutionEvidenceStatus::NotApplicable,
        signed_signatory_slots: 0,
        digested_attachments: 0,
        checklist_items: 0,
        digested_checklist_items: 0,
        referenced_checklist_items: 0,
        review_receipts: 0,
        latest_review_status: None,
        reviewed_evidence_locators: 0,
        reviewed_evidence_digests: 0,
    };

    if act.channel != MeetingChannel::WrittenResolution {
        return summary;
    }

    summary.signed_signatory_slots = act.signatories.iter().filter(|slot| slot.signed).count();
    summary.digested_attachments = act
        .attachments
        .iter()
        .filter(|attachment| attachment.digest.is_some())
        .count();

    if let Some(evidence) = &act.written_resolution_evidence {
        summary.checklist_items = evidence.checklist.len();
        summary.digested_checklist_items = evidence
            .checklist
            .iter()
            .filter(|item| item.digest.is_some())
            .count();
        summary.referenced_checklist_items = evidence
            .checklist
            .iter()
            .filter(|item| {
                item.digest.is_none()
                    && item
                        .reference
                        .as_deref()
                        .is_some_and(|reference| !reference.trim().is_empty())
            })
            .count();
        summary.review_receipts = evidence.review_receipts.len();
        summary.latest_review_status = evidence
            .review_receipts
            .last()
            .map(|receipt| receipt.status);
        summary.reviewed_evidence_locators = evidence
            .review_receipts
            .iter()
            .map(|receipt| receipt.evidence.len())
            .sum();
        summary.reviewed_evidence_digests = evidence
            .review_receipts
            .iter()
            .flat_map(|receipt| receipt.evidence.iter())
            .filter(|evidence| evidence.digest.is_some())
            .count();
    }

    summary.status = if summary.bound_count() > 0 {
        WrittenResolutionEvidenceStatus::BoundPresent
    } else if summary.referenced_only_count() > 0 {
        WrittenResolutionEvidenceStatus::ReferencedOnly
    } else {
        WrittenResolutionEvidenceStatus::Missing
    };

    summary
}

/// A structured voting result for one resolution (CSC art. 63.º "voting results").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
    /// Operator-supplied contact locator for the recipient (email, address, account id, or other
    /// local contact metadata). This is distinct from dispatch proof/tracking data.
    #[serde(default)]
    pub contact: Option<String>,
    /// Channel this recipient was reached through, when it differs from the convening default.
    #[serde(default)]
    pub channel: Option<DispatchChannel>,
    /// Dispatch proof/tracking reference (registered-letter tracking number, email id, receipt
    /// number, archive locator, or other proof metadata). Do not treat this as contact metadata.
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
    /// Short reference to the retained dispatch evidence (file id, archive path, tracking set, or
    /// other operator note). The actual evidence lives in the document/archive store.
    #[serde(default)]
    pub evidence_reference: Option<String>,
    /// Per-recipient dispatch proof (TPL-20).
    #[serde(default)]
    pub recipients: Vec<ConveningRecipient>,
    /// The reduced-quorum second convocation, when one was set (condominium).
    #[serde(default)]
    pub second_call: Option<SecondCall>,
}

/// The lawful ground on which a meeting was held **without a prior convocatória**.
///
/// Recorded rather than inferred: a bare "no convocatória" flag would let Chancela produce an ata
/// that is silently defective, because under CSC art. 56.º/1 a) deliberações "tomadas em
/// assembleia geral não convocada" are **null** *unless* every sócio was present or represented.
/// Naming the ground is what makes the omission legible on the face of the ata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NoConveningBasis {
    /// **Assembleia universal** — CSC art. 54.º/1: the sócios may "reunir-se em assembleia geral,
    /// sem observância de formalidades prévias, desde que todos estejam presentes e todos
    /// manifestem a vontade de que a assembleia se constitua e delibere sobre determinado
    /// assunto". Art. 54.º/2 adds that such an assembly "só pode deliberar sobre os assuntos
    /// consentidos por todos os sócios", which is why the two limbs of the agreement are captured
    /// separately on [`ConveningWaiver`].
    ///
    /// The article sits in the CSC's *parte geral* and so covers every company type. Chancela does
    /// **not** assert that it extends by analogy to the other entity families it serves — see the
    /// `CONV/basis-family-unverified` advisory in [`crate::rules`].
    AssembleiaUniversal,
    /// Some other ground, stated by the operator in [`ConveningWaiver::grounds`]. Chancela records
    /// it verbatim and asserts nothing about it.
    Other,
}

impl NoConveningBasis {
    /// Stable wire/display token.
    pub fn as_str(self) -> &'static str {
        match self {
            NoConveningBasis::AssembleiaUniversal => "assembleia_universal",
            NoConveningBasis::Other => "other",
        }
    }
}

/// The record that a meeting was held **without a convocatória**, and on what ground.
///
/// This is the deliberate alternative to simply leaving [`Act::convening`] empty. An absent
/// convening record is ambiguous — it may mean "not captured yet" as easily as "there was none" —
/// and an ata rendered from it recites nothing at all about how the meeting came to be held. A
/// waiver says *there was none, and here is why that was lawful*, which is the fact a reader of
/// the livro de atas needs.
///
/// Nothing here is a legal conclusion. The agreement flags record **what the operator captured**,
/// not a finding that the assembly was validly constituted; confirm any load-bearing case with
/// counsel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConveningWaiver {
    /// The lawful ground relied on.
    pub basis: NoConveningBasis,
    /// The operator's statement of the ground. Required by the API for
    /// [`NoConveningBasis::Other`], where the enum carries no meaning on its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grounds: Option<String>,
    /// Whether the record captures that **all** those entitled to take part agreed to the assembly
    /// constituting itself (CSC art. 54.º/1, first limb).
    #[serde(default)]
    pub all_agreed_to_meet: bool,
    /// Whether the record captures that **all** agreed to deliberate on the matters actually taken
    /// (CSC art. 54.º/1 *in fine* and art. 54.º/2 — the assembly "só pode deliberar sobre os
    /// assuntos consentidos por todos os sócios").
    #[serde(default)]
    pub all_agreed_to_agenda: bool,
    /// Short reference to any retained evidence of that agreement (signed declaration, the lista de
    /// presenças itself, an archive locator). The evidence lives in the document/archive store.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_reference: Option<String>,
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
/// by **permilagem** (millésimos). Rule packs use these row data for bounded weighted
/// quorum/tally checks when the captured attendance list is complete enough to support them.
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
    /// The capacity in which they attend — *na qualidade de* — from the shared, closed
    /// [`SignatoryCapacity`] vocabulary. Which values are offered depends on the entity's legal
    /// type: see [`attendee_qualities`](crate::attendee_qualities).
    pub quality: SignatoryCapacity,
    /// Free-text qualidade, meaningful **only** when `quality` is [`SignatoryCapacity::Other`].
    /// Kept separate from the structured value so that reporting over `quality` is never
    /// poisoned by prose. The API rejects a note on any other capacity.
    ///
    /// Skipped when absent so that the canonical act payload — and therefore the seal digest of
    /// every act sealed before this field existed — is byte-identical to what it was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quality_note: Option<String>,
    /// Whether they were present in person, represented, or absent.
    pub presence: PresenceMode,
    /// When [`PresenceMode::Represented`], the proxy who stood in for them.
    #[serde(default)]
    pub represented_by: Option<String>,
    /// The capital / permilagem this attendee carries, when weighted.
    #[serde(default)]
    pub weight: Option<AttendanceWeight>,
}

/// Operator-supplied reference to the manual-signature original captured at sealing (WFL-23).
///
/// This is immutable custody/location metadata only. It is not signature validation, archive
/// certification, or a legal-validity assertion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManualSignatureOriginalReference {
    /// Where the signed paper/PDF original is kept, or the local storage reference for it.
    pub storage_reference: String,
    /// Custodian responsible for the original, when recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custodian: Option<String>,
    /// Operator note about the reference/custody location, when recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Structured evidence of the rule pack/profile applied when an act was sealed (LEG-06/WFL-22).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealMetadata {
    /// Stable rule-pack id in force at sealing, including its version segment.
    pub rule_pack_id: String,
    /// Parsed version tag from [`SealMetadata::rule_pack_id`] (for example, `"v2"`).
    pub version: String,
    /// Entity family whose legal behavior selected the rule pack.
    pub family: EntityFamily,
    /// Entity profile/kind used to derive the family profile.
    pub profile: EntityKind,
    /// Operator-supplied manual-signature original reference, present only for manual sealing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manual_signature_original_reference: Option<ManualSignatureOriginalReference>,
    /// Lowercase SHA-256 of the immutable canonical PDF snapshot presented for signing.
    /// Absent for manual-signature seals and legacy rows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_snapshot_digest: Option<String>,
    /// Lowercase SHA-256 of the validated signed PDF frozen by this seal. Absent for
    /// manual-signature seals and legacy rows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_pdf_digest: Option<String>,
    /// Lowercase SHA-256 of the deterministic technical validation report used by the seal gate.
    /// The report is technical evidence only; this field does not assert legal validity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_validation_report_digest: Option<String>,
}

impl SealMetadata {
    /// Build seal metadata from the dispatched rule-pack id and entity profile evidence.
    pub fn new(rule_pack_id: impl Into<String>, family: EntityFamily, profile: EntityKind) -> Self {
        let rule_pack_id = rule_pack_id.into();
        let version = rule_pack_version(&rule_pack_id);
        SealMetadata {
            rule_pack_id,
            version,
            family,
            profile,
            manual_signature_original_reference: None,
            signing_snapshot_digest: None,
            signed_pdf_digest: None,
            signature_validation_report_digest: None,
        }
    }

    /// Attach an immutable manual-signature original reference captured by the seal request.
    pub fn with_manual_signature_original_reference(
        mut self,
        reference: Option<ManualSignatureOriginalReference>,
    ) -> Self {
        self.manual_signature_original_reference = reference;
        self
    }

    /// Attach the immutable digest tuple for a digitally signed seal.
    pub fn with_digital_signature_evidence(
        mut self,
        signing_snapshot_digest: impl Into<String>,
        signed_pdf_digest: impl Into<String>,
        signature_validation_report_digest: impl Into<String>,
    ) -> Self {
        self.signing_snapshot_digest = Some(signing_snapshot_digest.into());
        self.signed_pdf_digest = Some(signed_pdf_digest.into());
        self.signature_validation_report_digest = Some(signature_validation_report_digest.into());
        self
    }

    /// Whether this row carries a complete digital-evidence tuple.
    #[must_use]
    pub fn has_complete_digital_signature_evidence(&self) -> bool {
        self.signing_snapshot_digest.is_some()
            && self.signed_pdf_digest.is_some()
            && self.signature_validation_report_digest.is_some()
    }

    /// Whether this row carries one of the two seal evidence paths accepted by the lifecycle.
    #[must_use]
    pub fn has_complete_signature_evidence(&self) -> bool {
        self.manual_signature_original_reference.is_some()
            || self.has_complete_digital_signature_evidence()
    }
}

fn rule_pack_version(rule_pack_id: &str) -> String {
    rule_pack_id
        .rsplit_once('/')
        .and_then(|(_, version)| (!version.is_empty()).then_some(version))
        .unwrap_or("unversioned")
        .to_owned()
}

/// A canonical signing snapshot that a reopen (`Signing → TextApproved`) retired.
///
/// Entering `Signing` persists one immutable canonical PDF and the signing model is built on it.
/// Reopening the act for correction invalidates that PDF: it is no longer the document anyone may
/// sign or seal against. The bytes are **not** destroyed — the `document.generated` event that
/// created them is part of the chain — so the retirement is recorded here instead, and the
/// superseded row is skipped when the canonical signing document is resolved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupersededSigningSnapshot {
    /// Document id of the retired canonical snapshot.
    pub document_id: String,
    /// Lowercase SHA-256 the retired snapshot carried, so the retirement names exact bytes.
    pub pdf_digest: String,
    /// Actor who reopened the act.
    pub actor: String,
    /// When the reopen retired this snapshot (UTC).
    #[serde(with = "time::serde::rfc3339")]
    pub superseded_at: OffsetDateTime,
    /// Operator's reason for the reopen.
    pub reason: String,
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
    /// Optional written-resolution evidence checklist metadata. Evidence-oriented only: derived
    /// status is computed from this metadata, signed signatory slots, and digested attachments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub written_resolution_evidence: Option<WrittenResolutionEvidence>,
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
    /// Structured LEG-06/WFL-22 metadata for the rule pack/profile applied at sealing. Absent on
    /// unsealed acts and old sealed rows whose historical record only carried the ledger
    /// justification string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal_metadata: Option<SealMetadata>,
    /// When this act corrects an earlier sealed one, the retificação chain link (WFL-21).
    pub retifies: Option<ActId>,
    /// The convening (convocatória) record for this meeting (spec gap G1). Additive and
    /// **append-only**: defaults to `None` so acts predating this field round-trip unchanged.
    #[serde(default)]
    pub convening: Option<Convening>,
    /// Recorded when the meeting was held **without** a convocatória, naming the lawful ground
    /// (CSC art. 54.º assembleia universal, or another ground the operator states).
    ///
    /// Distinct from `convening: None`, which only means no convening record was captured. The two
    /// are mutually exclusive in substance, and the rule packs warn when both are populated.
    ///
    /// Skipped when absent so the canonical act payload — and therefore the frozen seal digest of
    /// every act sealed before this field existed — is byte-identical to what it was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub convening_waiver: Option<ConveningWaiver>,
    /// The structured lista de presenças (spec gap G2). Additive and **append-only**: defaults
    /// to empty so acts predating this field round-trip unchanged.
    #[serde(default)]
    pub attendees: Vec<Attendee>,
    /// Non-authoritative AI provenance. Absent for human-authored or historical acts; when present,
    /// `TextApproved -> Signing` requires accepted human review first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ai_provenance: Option<AiProvenance>,
    /// F15 — how many PDF/A pages this act occupies in its book.
    ///
    /// Captured **once**, at the `TextApproved -> Signing` content freeze, which is the moment
    /// the rendered page count becomes both knowable and permanently stable. It is bound into
    /// the seal payload as a recorded historical fact and **is never recomputed on read**: a
    /// template revision must not be able to move a sealed act's page consumption after the
    /// event. `None` on acts that predate the capacity model.
    ///
    /// Additive and append-only: `None` emits no bytes, so a pre-existing act's preimage — and
    /// therefore its frozen digest — is unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_count: Option<u32>,
    /// Canonical signing snapshots retired by a `Signing → TextApproved` reopen, oldest first.
    ///
    /// Append-only history of a state regression on an evidentiary object. Empty for every act
    /// that was never reopened, so it emits no bytes and no existing seal preimage moves.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub superseded_signing_snapshots: Vec<SupersededSigningSnapshot>,
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
            written_resolution_evidence: None,
            deliberations: String::new(),
            deliberation_items: Vec::new(),
            telematic_evidence: None,
            attachments: Vec::new(),
            signatories: Vec::new(),
            state: ActState::Draft,
            ata_number: None,
            payload_digest: None,
            seal_event_seq: None,
            seal_metadata: None,
            retifies: None,
            convening: None,
            convening_waiver: None,
            attendees: Vec::new(),
            ai_provenance: None,
            page_count: None,
            superseded_signing_snapshots: Vec::new(),
        }
    }

    /// Freeze the rendered page count at the content freeze (F15).
    ///
    /// Idempotent for the same value so a retried freeze is harmless, but a *different* value
    /// is refused: the count is a fact about the bytes the signatures bind, not a cache.
    pub fn freeze_page_count(&mut self, pages: u32) -> Result<(), ActError> {
        match self.page_count {
            Some(frozen) if frozen == pages => Ok(()),
            Some(frozen) => Err(ActError::PageCountAlreadyFrozen { frozen }),
            None => {
                if matches!(self.state, ActState::Sealed | ActState::Archived) {
                    return Err(ActError::Sealed);
                }
                self.page_count = Some(pages);
                Ok(())
            }
        }
    }

    /// Whether the act's content may still be edited.
    ///
    /// Entry into `Signing` freezes the exact content and signatory set that produced the
    /// canonical signing snapshot. No implicit edit or replacement is allowed after that point.
    pub fn is_mutable(&self) -> bool {
        !matches!(
            self.state,
            ActState::Signing | ActState::Sealed | ActState::Archived
        )
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
        if self.state == ActState::TextApproved
            && to == ActState::Signing
            && self.requires_ai_human_verification()
        {
            return Err(ActError::InvalidTransition {
                from: self.state,
                to,
            });
        }
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

    /// Reopen a `Signing` act for correction (`Signing → TextApproved`).
    ///
    /// The one reverse edge in the lifecycle, and deliberately the *only* one. It exists because
    /// entering `Signing` is otherwise terminal for an act that cannot be sealed: `is_mutable()`
    /// is false there and sealing requires `Signing`, so an act that reached `Signing` carrying a
    /// blocking compliance defect had no way out. [`Act::advance_to`] now refuses that entry, but
    /// acts already stranded still need a route back.
    ///
    /// Refused once **any signature has been collected** ([`SignatorySlot::signed`]): a collected
    /// signature is evidence of a person's assent to specific bytes, and silently invalidating it
    /// to allow an edit is not a correction the operator gets to make. A signed act is corrected
    /// the way every sealed act is — by a new act that retifies it (WFL-21).
    ///
    /// Returns the page count released by the reopen, if one had been frozen. The frozen count
    /// (F15) describes the snapshot this reopen retires, so it is cleared and must be re-frozen
    /// from the corrected content at the next `TextApproved → Signing`. **A capacity-aware caller
    /// holding a `reserve_pages` reservation for this act must release it with the returned
    /// count**, or the reservation leaks against the book's capacity.
    ///
    /// The canonical PDF snapshot is not touched here — it lives in the document store, not the
    /// domain model. The caller records its retirement with
    /// [`Act::record_superseded_signing_snapshot`], which is what stops it being resolved as the
    /// act's signing document.
    pub fn reopen_for_correction(&mut self) -> Result<Option<u32>, ActError> {
        if self.state != ActState::Signing {
            return Err(ActError::InvalidTransition {
                from: self.state,
                to: ActState::TextApproved,
            });
        }
        if self.signatories.iter().any(|slot| slot.signed) {
            return Err(ActError::SignaturesCollected);
        }
        self.state = ActState::TextApproved;
        Ok(self.page_count.take())
    }

    /// Record that a canonical signing snapshot was retired by a reopen.
    pub fn record_superseded_signing_snapshot(&mut self, snapshot: SupersededSigningSnapshot) {
        self.superseded_signing_snapshots.push(snapshot);
    }

    /// Whether `document_id` names a canonical snapshot a reopen has retired.
    #[must_use]
    pub fn is_signing_snapshot_superseded(&self, document_id: &str) -> bool {
        self.superseded_signing_snapshots
            .iter()
            .any(|snapshot| snapshot.document_id == document_id)
    }

    /// Whether an AI-assisted act still needs accepted human review before signing.
    #[must_use]
    pub fn requires_ai_human_verification(&self) -> bool {
        self.ai_provenance
            .as_ref()
            .is_some_and(|p| !p.human_review_accepted())
    }

    /// Record a human review decision for AI-assisted draft content.
    pub fn set_ai_human_verification(
        &mut self,
        status: AiHumanVerificationStatus,
        actor: impl Into<String>,
        reviewed_at: OffsetDateTime,
        note: Option<String>,
    ) -> Result<(), ActError> {
        self.ensure_mutable()?;
        if let Some(provenance) = &mut self.ai_provenance {
            provenance.set_human_verification(status, actor, reviewed_at, note);
        }
        Ok(())
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
        seal_metadata: SealMetadata,
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
        self.seal_metadata = Some(seal_metadata);
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

    fn seal_metadata() -> SealMetadata {
        SealMetadata::new(
            "test-pack/v1",
            EntityFamily::CommercialCompany,
            EntityKind::SociedadeAnonima,
        )
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
        assert!(act.mark_sealed(1, [0u8; 32], 0, seal_metadata()).is_err());

        for state in [
            ActState::Review,
            ActState::Convened,
            ActState::Deliberated,
            ActState::TextApproved,
            ActState::Signing,
        ] {
            act.advance_to(state).unwrap();
        }
        act.mark_sealed(7, [9u8; 32], 3, seal_metadata()).unwrap();
        assert_eq!(act.state, ActState::Sealed);
        assert_eq!(act.ata_number, Some(7));
        assert_eq!(act.seal_event_seq, Some(3));
        assert_eq!(
            act.seal_metadata.as_ref().map(|m| m.rule_pack_id.as_str()),
            Some("test-pack/v1")
        );
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
        act.mark_sealed(1, [0u8; 32], 0, seal_metadata()).unwrap();
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
    fn signing_act_freezes_content_and_signatory_set() {
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

        assert!(!act.is_mutable());
        assert_eq!(
            act.set_deliberations("replacement after snapshot"),
            Err(ActError::Sealed)
        );
        assert_eq!(
            act.add_signatory(SignatorySlot {
                name: "Late signer".to_owned(),
                email: None,
                capacity: SignatoryCapacity::Member,
                signed: false,
                permilage: None,
            }),
            Err(ActError::Sealed)
        );
        assert!(act.deliberations.is_empty());
        assert!(act.signatories.is_empty());
    }

    fn signing_act() -> Act {
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
        act
    }

    fn slot(name: &str, signed: bool) -> SignatorySlot {
        SignatorySlot {
            name: name.to_owned(),
            email: None,
            capacity: SignatoryCapacity::Chair,
            signed,
            permilage: None,
        }
    }

    #[test]
    fn reopen_returns_a_stuck_signing_act_to_textapproved_and_mutability() {
        let mut act = signing_act();
        assert!(!act.is_mutable());

        assert_eq!(act.reopen_for_correction(), Ok(None));
        assert_eq!(act.state, ActState::TextApproved);
        assert!(act.is_mutable());

        // The whole point: the act can now be corrected and sent back out for signature.
        act.mesa.presidente = Some("Ana Presidente".into());
        act.set_deliberations("Aprovadas as contas.").unwrap();
        act.advance_to(ActState::Signing).unwrap();
        assert_eq!(act.state, ActState::Signing);
    }

    #[test]
    fn reopen_releases_the_frozen_page_count_for_the_retired_snapshot() {
        let mut act = signing_act();
        act.page_count = Some(4);

        // The count described the snapshot the reopen retires, so it comes back to the caller
        // (who owes the book a `release_reserved_pages`) and is cleared for a fresh freeze.
        assert_eq!(act.reopen_for_correction(), Ok(Some(4)));
        assert_eq!(act.page_count, None);
        act.freeze_page_count(6)
            .expect("corrected content re-freezes at its own length");
    }

    #[test]
    fn reopen_is_refused_once_a_signature_has_been_collected() {
        let mut act = draft();
        act.add_signatory(slot("Ana Presidente", false)).unwrap();
        act.add_signatory(slot("Rui Secretário", false)).unwrap();
        for state in [
            ActState::Review,
            ActState::Convened,
            ActState::Deliberated,
            ActState::TextApproved,
            ActState::Signing,
        ] {
            act.advance_to(state).unwrap();
        }
        act.signatories[1].signed = true;

        assert_eq!(
            act.reopen_for_correction(),
            Err(ActError::SignaturesCollected)
        );
        // Refused means untouched: still frozen in Signing, signature intact.
        assert_eq!(act.state, ActState::Signing);
        assert!(act.signatories[1].signed);
    }

    #[test]
    fn reopen_is_the_only_reverse_edge_and_only_from_signing() {
        let mut act = draft();
        for state in [
            ActState::Review,
            ActState::Convened,
            ActState::Deliberated,
            ActState::TextApproved,
        ] {
            assert!(matches!(
                act.reopen_for_correction(),
                Err(ActError::InvalidTransition {
                    to: ActState::TextApproved,
                    ..
                })
            ));
            act.advance_to(state).unwrap();
        }
        act.advance_to(ActState::Signing).unwrap();
        act.reopen_for_correction().unwrap();

        // Sealed and archived acts stay append-only: no reopen rescues them (WFL-20/21).
        act.advance_to(ActState::Signing).unwrap();
        act.mark_sealed(1, [0u8; 32], 0, seal_metadata()).unwrap();
        assert!(matches!(
            act.reopen_for_correction(),
            Err(ActError::InvalidTransition {
                from: ActState::Sealed,
                to: ActState::TextApproved
            })
        ));
        act.archive().unwrap();
        assert!(matches!(
            act.reopen_for_correction(),
            Err(ActError::InvalidTransition {
                from: ActState::Archived,
                ..
            })
        ));
    }

    #[test]
    fn superseded_snapshots_are_recorded_and_round_trip_additively() {
        // An act that was never reopened emits no key at all, so stored rows do not churn.
        let act = draft();
        let value = serde_json::to_value(&act).unwrap();
        assert!(
            !value
                .as_object()
                .unwrap()
                .contains_key("superseded_signing_snapshots")
        );
        let restored: Act = serde_json::from_value(value).unwrap();
        assert!(restored.superseded_signing_snapshots.is_empty());

        let mut reopened = signing_act();
        reopened.reopen_for_correction().unwrap();
        reopened.record_superseded_signing_snapshot(SupersededSigningSnapshot {
            document_id: "doc-1".to_owned(),
            pdf_digest: "aa".repeat(32),
            actor: "amelia.marques".to_owned(),
            superseded_at: OffsetDateTime::UNIX_EPOCH,
            reason: "mesa em falta".to_owned(),
        });
        assert!(reopened.is_signing_snapshot_superseded("doc-1"));
        assert!(!reopened.is_signing_snapshot_superseded("doc-2"));

        let json = serde_json::to_string(&reopened).unwrap();
        let restored: Act = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, reopened);
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
        act.mark_sealed(1, [0u8; 32], 0, seal_metadata()).unwrap();
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
        obj.remove("ai_provenance");
        obj.remove("written_resolution_evidence");
        assert!(!obj.contains_key("convening"));
        assert!(!obj.contains_key("attendees"));
        assert!(!obj.contains_key("ai_provenance"));
        assert!(!obj.contains_key("written_resolution_evidence"));

        let restored: Act = serde_json::from_value(value).unwrap();
        assert_eq!(restored.convening, None);
        assert!(restored.attendees.is_empty());
        assert_eq!(restored.ai_provenance, None);
        assert_eq!(restored.written_resolution_evidence, None);
        // Everything round-trips: the defaulted act equals the original, and re-serializes
        // identically.
        assert_eq!(restored, act);
        assert_eq!(
            serde_json::to_string(&restored).unwrap(),
            serde_json::to_string(&act).unwrap()
        );
    }

    #[test]
    fn an_act_without_a_convening_waiver_emits_no_bytes_for_it() {
        // The seal digest is taken over the canonical act payload, so a new field that serialized
        // even as `null` would move the preimage of every act sealed before it existed. It must be
        // absent from the wire entirely until an operator records one.
        let act = draft();
        let json = serde_json::to_string(&act).unwrap();
        assert!(
            !json.contains("convening_waiver"),
            "an absent waiver must not appear in the canonical payload: {json}"
        );

        let restored: Act = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.convening_waiver, None);
        assert_eq!(restored, act);
    }

    #[test]
    fn act_with_a_no_convocatoria_basis_round_trips() {
        let mut act = draft();
        act.convening_waiver = Some(ConveningWaiver {
            basis: NoConveningBasis::AssembleiaUniversal,
            grounds: None,
            all_agreed_to_meet: true,
            all_agreed_to_agenda: true,
            evidence_reference: Some("Anexo I — declaração conjunta".into()),
        });

        let json = serde_json::to_string(&act).unwrap();
        let restored: Act = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, act);
        let waiver = restored.convening_waiver.expect("waiver");
        assert_eq!(waiver.basis, NoConveningBasis::AssembleiaUniversal);
        assert_eq!(waiver.basis.as_str(), "assembleia_universal");
        assert!(waiver.all_agreed_to_meet && waiver.all_agreed_to_agenda);
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
            evidence_reference: Some("doc:convocatoria-rr123456789pt".into()),
            recipients: vec![ConveningRecipient {
                name: "Encosto Estratégico Lda".into(),
                contact: Some("socios@example.test".into()),
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
                quality_note: None,
                presence: PresenceMode::InPerson,
                represented_by: None,
                weight: Some(AttendanceWeight::Capital(500_000)),
            },
            Attendee {
                name: "Encosto Estratégico Lda".into(),
                quality: SignatoryCapacity::CondoOwner,
                quality_note: None,
                presence: PresenceMode::Represented,
                represented_by: Some("Amélia Marques".into()),
                weight: Some(AttendanceWeight::Permilage(250)),
            },
        ];

        let json = serde_json::to_string(&act).unwrap();
        let restored: Act = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, act);
    }

    #[test]
    fn written_resolution_evidence_round_trips_and_status_is_derived() {
        let mut act = Act::draft(
            BookId::new(),
            "Written resolution",
            MeetingChannel::WrittenResolution,
        );
        assert_eq!(
            written_resolution_evidence_summary(&act).status,
            WrittenResolutionEvidenceStatus::Missing
        );

        act.written_resolution_evidence = Some(WrittenResolutionEvidence {
            checklist: vec![
                WrittenResolutionEvidenceItem {
                    label: "Circular approval email".to_owned(),
                    reference: Some("mailbox:thread-123".to_owned()),
                    digest: None,
                    note: Some("reference only".to_owned()),
                },
                WrittenResolutionEvidenceItem {
                    label: "Signed written approval pack".to_owned(),
                    reference: Some("doc:approval-pack".to_owned()),
                    digest: Some([3; 32]),
                    note: Some("digest retained".to_owned()),
                },
            ],
            review_receipts: vec![WrittenResolutionReviewReceipt {
                reviewer: "operator@example.test".to_owned(),
                reviewed_at: OffsetDateTime::UNIX_EPOCH,
                status: WrittenResolutionReviewStatus::Reviewed,
                guardrail_acknowledgements: vec![
                    "local_metadata_only".to_owned(),
                    "no_legal_or_proof_claim".to_owned(),
                ],
                evidence: vec![WrittenResolutionReviewEvidenceLocator {
                    label: "Approval pack review".to_owned(),
                    locator: Some("doc:approval-pack".to_owned()),
                    digest: Some([4; 32]),
                }],
                note: Some("reviewed local evidence metadata".to_owned()),
                consent_proof_claimed: false,
                quorum_proof_claimed: false,
                identity_proof_claimed: false,
                legal_acceptance_claimed: false,
                legal_sufficiency_claimed: false,
                external_validation_claimed: false,
                automatic_approval_claimed: false,
                authority_certified_claimed: false,
            }],
            note: Some("operator capture note".to_owned()),
        });

        let json = serde_json::to_string(&act).unwrap();
        let restored: Act = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, act);

        let summary = written_resolution_evidence_summary(&restored);
        assert_eq!(
            summary.status,
            WrittenResolutionEvidenceStatus::BoundPresent
        );
        assert_eq!(summary.checklist_items, 2);
        assert_eq!(summary.digested_checklist_items, 1);
        assert_eq!(summary.referenced_checklist_items, 1);
        assert_eq!(summary.bound_count(), 1);
        assert_eq!(summary.review_receipts, 1);
        assert_eq!(
            summary.latest_review_status,
            Some(WrittenResolutionReviewStatus::Reviewed)
        );
        assert_eq!(summary.reviewed_evidence_locators, 1);
        assert_eq!(summary.reviewed_evidence_digests, 1);

        let mut referenced = Act::draft(
            BookId::new(),
            "Referenced only",
            MeetingChannel::WrittenResolution,
        );
        referenced.written_resolution_evidence = Some(WrittenResolutionEvidence {
            checklist: vec![WrittenResolutionEvidenceItem {
                label: "Approval folder".to_owned(),
                reference: Some("folder:approvals".to_owned()),
                digest: None,
                note: None,
            }],
            review_receipts: vec![],
            note: None,
        });
        assert_eq!(
            written_resolution_evidence_summary(&referenced).status,
            WrittenResolutionEvidenceStatus::ReferencedOnly
        );

        referenced.channel = MeetingChannel::Physical;
        assert_eq!(
            written_resolution_evidence_summary(&referenced).status,
            WrittenResolutionEvidenceStatus::NotApplicable
        );
    }

    #[test]
    fn ai_provenance_is_additive_and_blocks_signing_until_human_review_accepted() {
        let act = draft();
        let value = serde_json::to_value(&act).unwrap();
        assert!(
            !value.as_object().unwrap().contains_key("ai_provenance"),
            "absent AI provenance is skipped to avoid contract churn"
        );
        let restored: Act = serde_json::from_value(value).unwrap();
        assert_eq!(restored.ai_provenance, None);

        let mut ai_act = draft();
        ai_act.ai_provenance = Some(AiProvenance {
            source: "mcp".to_owned(),
            tool: Some("draft_act".to_owned()),
            statement_source: Some("operator instruction".to_owned()),
            statement_sources: vec![],
            human_verification: Default::default(),
        });
        for state in [
            ActState::Review,
            ActState::Convened,
            ActState::Deliberated,
            ActState::TextApproved,
        ] {
            ai_act.advance_to(state).unwrap();
        }
        assert!(ai_act.requires_ai_human_verification());
        assert!(matches!(
            ai_act.advance_to(ActState::Signing),
            Err(ActError::InvalidTransition {
                from: ActState::TextApproved,
                to: ActState::Signing
            })
        ));

        ai_act
            .set_ai_human_verification(
                AiHumanVerificationStatus::Accepted,
                "ana",
                time::OffsetDateTime::UNIX_EPOCH,
                Some("human reviewed only".to_owned()),
            )
            .unwrap();
        assert!(!ai_act.requires_ai_human_verification());
        ai_act.advance_to(ActState::Signing).unwrap();
    }

    #[test]
    fn ai_provenance_statement_sources_are_backward_compatible_and_roundtrip() {
        let mut old_json = serde_json::to_value(draft()).unwrap();
        old_json["ai_provenance"] = serde_json::json!({
            "source": "mcp",
            "tool": "draft_minutes",
            "statement_source": "mcp tool arguments"
        });
        let old: Act = serde_json::from_value(old_json).unwrap();
        let old_provenance = old.ai_provenance.expect("old provenance restored");
        assert_eq!(
            old_provenance.statement_source.as_deref(),
            Some("mcp tool arguments")
        );
        assert!(old_provenance.statement_sources.is_empty());

        let mut ai_act = draft();
        ai_act.ai_provenance = Some(AiProvenance {
            source: "mcp".to_owned(),
            tool: Some("draft_minutes".to_owned()),
            statement_source: Some("mcp tool arguments".to_owned()),
            statement_sources: vec![
                AiStatementSource {
                    path: "/draft".to_owned(),
                    source_type: "ai_suggestion".to_owned(),
                    source_label: "draft_minutes".to_owned(),
                    human_verified: false,
                    human_verification_status: AiHumanVerificationStatus::Pending,
                    authoritative_source_claimed: false,
                    legal_validity_claimed: false,
                },
                AiStatementSource {
                    path: "/draft/title".to_owned(),
                    source_type: "caller_supplied".to_owned(),
                    source_label: "arguments.title".to_owned(),
                    human_verified: false,
                    human_verification_status: AiHumanVerificationStatus::Pending,
                    authoritative_source_claimed: false,
                    legal_validity_claimed: false,
                },
            ],
            human_verification: Default::default(),
        });

        let value = serde_json::to_value(&ai_act).unwrap();
        assert_eq!(
            value["ai_provenance"]["statement_sources"][1]["source_label"],
            "arguments.title"
        );
        let restored: Act = serde_json::from_value(value).unwrap();
        assert_eq!(
            restored
                .ai_provenance
                .expect("new provenance restored")
                .statement_sources
                .len(),
            2
        );
    }
}
