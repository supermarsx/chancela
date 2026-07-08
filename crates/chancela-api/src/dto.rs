//! JSON data-transfer objects: the wire shapes the API owns.
//!
//! The API never serializes `chancela-core`'s domain types directly onto the wire. Two things
//! force that: `time::Date` has no stable JSON contract we want to expose, and digests are
//! `[u8; 32]` which serde would render as integer arrays. So this module defines the response
//! *views* (`BookView`, `ActView`, `LedgerEventView`, …) and request *bodies* pinned in the
//! cross-executor contract (plan §2), converting dates to ISO `YYYY-MM-DD` strings and digests
//! to lowercase hex ([`crate::hex`]). Enum fields reuse the core enums directly: their serde
//! representation is the bare variant name, which is exactly what the contract pins (§2.1).

use serde::{Deserialize, Deserializer, Serialize};
use time::format_description::well_known::Rfc3339;
use time::macros::format_description;
use time::{Date, OffsetDateTime};
use uuid::Uuid;

use chancela_cae::CaeCatalog;
use chancela_core::book::ClosingReason;
use chancela_core::{
    Act, ActState, AgendaItem, Attachment, AttachmentKind, Book, BookKind, BookState,
    ComplianceIssue, DeliberationItem, DocumentReference, Entity, EntityFamily, EntityKind,
    MeetingChannel, MemberStatement, Mesa, NumberingScheme, Severity, SignatoryCapacity,
    SignatorySlot, SignaturePolicyHint, StatuteOverrides, VoteResult, profile_for,
};
use chancela_ledger::Event;
use chancela_registry::{
    Address, AmendmentPayload, Apresentacao, CessationPayload, ConstitutionPayload,
    DesignationPayload, InscriptionDetail, InscriptionPayload, Money, Organ, OrganMember, Person,
    Quota, RegistryAnnotation, RegistryEvent, RegistryExtract, RegistryOfficer,
    RegistryOfficialSignature, RegistryProvenance,
};

use crate::cae::{CaeRefView, enrich_cae_ref};
use crate::error::ApiError;
use crate::hex::{hex, parse_hex32};
use crate::registry::legal_form_name;

// --- Date <-> ISO string helpers ---------------------------------------------------------

/// Format a `time::Date` as the contract's ISO `YYYY-MM-DD` string.
pub fn format_date(d: Date) -> String {
    let fmt = format_description!("[year]-[month]-[day]");
    d.format(&fmt).unwrap_or_default()
}

/// Parse an ISO `YYYY-MM-DD` string into a `time::Date`, mapping any error to `422`.
pub fn parse_date(s: &str) -> Result<Date, ApiError> {
    let fmt = format_description!("[year]-[month]-[day]");
    Date::parse(s, &fmt)
        .map_err(|_| ApiError::Unprocessable(format!("invalid date {s:?}; expected YYYY-MM-DD")))
}

/// Format a `time::Time` as the contract's `HH:MM` string (the meeting-time wire form).
pub fn format_time(t: time::Time) -> String {
    let fmt = format_description!("[hour]:[minute]");
    t.format(&fmt).unwrap_or_default()
}

/// Parse an `HH:MM` string into a `time::Time`, mapping any error to `422`.
pub fn parse_time(s: &str) -> Result<time::Time, ApiError> {
    let fmt = format_description!("[hour]:[minute]");
    time::Time::parse(s, &fmt)
        .map_err(|_| ApiError::Unprocessable(format!("invalid time {s:?}; expected HH:MM")))
}

/// Serde adapter that distinguishes an absent field from an explicit `null` (PATCH semantics).
///
/// A plain `Option<T>` collapses "key omitted" and "key: null" both to `None`. For PATCH we
/// need three states — leave unchanged (absent), clear (null), set (value) — so nullable
/// fields use `Option<Option<T>>` with this deserializer: `#[serde(default)]` supplies the
/// outer `None` when the key is absent, and this fn wraps whatever is present (including
/// `null`, which becomes `Some(None)`).
pub(crate) fn double_option<'de, T, D>(de: D) -> Result<Option<Option<T>>, D::Error>
where
    T: Deserialize<'de>,
    D: Deserializer<'de>,
{
    Ok(Some(Option::deserialize(de)?))
}

fn default_actor() -> String {
    "api".to_owned()
}

fn default_numbering() -> NumberingScheme {
    NumberingScheme::Sequential
}

// --- Compliance issue view ---------------------------------------------------------------

/// Wire form of a `ComplianceIssue`. `Severity` is not `Serialize` in core, and the contract
/// pins its encoding to the bare variant name, so we map it explicitly.
#[derive(Debug, Serialize, Clone)]
pub struct IssueView {
    pub rule_id: String,
    pub severity: String,
    pub message: String,
}

/// The contract's `Severity` encoding (§2.1): the bare variant name.
fn severity_str(s: Severity) -> &'static str {
    match s {
        Severity::Warning => "Warning",
        Severity::Error => "Error",
    }
}

impl From<&ComplianceIssue> for IssueView {
    fn from(i: &ComplianceIssue) -> Self {
        IssueView {
            rule_id: i.rule_id.clone(),
            severity: severity_str(i.severity).to_owned(),
            message: i.message.clone(),
        }
    }
}

// --- Entity view -------------------------------------------------------------------------

/// Response view of an [`Entity`] (contract §2.3).
///
/// The API owns this wire shape rather than serializing the core `Entity` directly, so the NIPC
/// is **stable** regardless of validation state. Core's `Nipc` serializes asymmetrically — a
/// validated NIPC as a bare string, but an *unvalidated* one (the `allow_invalid_nipc` override)
/// as an object `{"value":…,"validated":false}`. This view flattens both cases: `nipc` is always
/// the raw identifier (from [`chancela_core::Nipc::as_str`]) and `nipc_validated` carries the flag
/// (from [`chancela_core::Nipc::is_validated`]), so the web client sees one predictable shape.
///
/// Every other field mirrors the core type one-for-one (`id` as its UUID string; `family`/`kind`
/// as their bare variant names), keeping the response byte-identical to the old raw-`Entity` form
/// for validated entities, aside from the additive `nipc_validated` key.
#[derive(Serialize)]
pub struct EntityView {
    pub id: String,
    pub name: String,
    pub nipc: String,
    pub nipc_validated: bool,
    pub seat: String,
    pub family: EntityFamily,
    pub kind: EntityKind,
    /// The entity's derived profile (ENT-02): rule pack id, allowed channels, signature-policy
    /// hint, template-family seed, calendar presets. Additive (t31 §2.4).
    pub profile: EntityProfileView,
    /// The per-entity statute overlay (ENT-03), or `null`. Additive.
    pub statute: Option<StatuteOverrides>,
}

impl From<&Entity> for EntityView {
    fn from(e: &Entity) -> Self {
        EntityView {
            id: e.id.to_string(),
            name: e.name.clone(),
            nipc: e.nipc.as_str().to_owned(),
            nipc_validated: e.nipc.is_validated(),
            seat: e.seat.clone(),
            family: e.family,
            kind: e.kind,
            profile: EntityProfileView::from(e.kind),
            statute: e.statute.clone(),
        }
    }
}

/// Wire view of an entity's derived [`profile`](chancela_core::profile_for) (ENT-02). Owns its
/// strings (the core profile carries `&'static str` seed ids), so it is a stable, serializable
/// wire shape rather than the core type.
#[derive(Serialize)]
pub struct EntityProfileView {
    pub family: EntityFamily,
    pub rule_pack_id: String,
    pub allowed_channels: Vec<MeetingChannel>,
    pub signature_policy: SignaturePolicyHint,
    pub template_family: String,
    pub calendar_presets: Vec<CalendarPresetView>,
}

impl EntityProfileView {
    /// Build the wire profile for a legal type.
    pub fn from(kind: EntityKind) -> Self {
        let p = profile_for(kind);
        EntityProfileView {
            family: p.family,
            rule_pack_id: p.rule_pack_id.to_owned(),
            allowed_channels: p.allowed_channels,
            signature_policy: p.signature_policy,
            template_family: p.template_family.to_owned(),
            calendar_presets: p
                .calendar_presets
                .iter()
                .map(CalendarPresetView::from)
                .collect(),
        }
    }
}

/// Wire view of one [`CalendarPreset`](chancela_core::CalendarPreset) seed (ENT-02(e)).
#[derive(Serialize)]
pub struct CalendarPresetView {
    pub id: String,
    pub label: String,
    pub months_after_fiscal_year_end: Option<u8>,
}

impl From<&chancela_core::CalendarPreset> for CalendarPresetView {
    fn from(c: &chancela_core::CalendarPreset) -> Self {
        CalendarPresetView {
            id: c.id.to_owned(),
            label: c.label.to_owned(),
            months_after_fiscal_year_end: c.months_after_fiscal_year_end,
        }
    }
}

// --- Book views + bodies -----------------------------------------------------------------

/// Response view of a `Book` (contract §2.4). Termo fields are flattened out of the two
/// optional instruments so the client sees a single record.
#[derive(Serialize)]
pub struct BookView {
    pub id: String,
    pub entity_id: String,
    pub kind: BookKind,
    pub state: BookState,
    pub purpose: Option<String>,
    pub numbering_scheme: Option<NumberingScheme>,
    pub opening_date: Option<String>,
    pub closing_date: Option<String>,
    pub closing_reason: Option<ClosingReason>,
    pub last_ata_number: u64,
    pub predecessor: Option<String>,
    pub required_signatories_abertura: Option<Vec<String>>,
    pub required_signatories_encerramento: Option<Vec<String>>,
}

impl From<&Book> for BookView {
    fn from(b: &Book) -> Self {
        let ab = b.termo_abertura.as_ref();
        let en = b.termo_encerramento.as_ref();
        BookView {
            id: b.id.to_string(),
            entity_id: b.entity_id.to_string(),
            kind: b.kind,
            state: b.state,
            purpose: ab.map(|t| t.purpose.clone()),
            numbering_scheme: ab.map(|t| t.numbering_scheme),
            opening_date: ab.map(|t| format_date(t.opening_date)),
            closing_date: en.map(|t| format_date(t.closing_date)),
            closing_reason: en.map(|t| t.reason.clone()),
            last_ata_number: b.last_ata_number,
            predecessor: b.predecessor.map(|p| p.to_string()),
            required_signatories_abertura: ab.map(|t| t.required_signatories.clone()),
            required_signatories_encerramento: en.map(|t| t.required_signatories.clone()),
        }
    }
}

/// Body of `POST /v1/books` (create + open in one step, WFL-10/11).
#[derive(Deserialize)]
pub struct CreateBook {
    pub entity_id: Uuid,
    pub kind: BookKind,
    pub purpose: String,
    #[serde(default = "default_numbering")]
    pub numbering_scheme: NumberingScheme,
    pub opening_date: String,
    pub required_signatories: Vec<String>,
    pub predecessor: Option<Uuid>,
    #[serde(default = "default_actor")]
    pub actor: String,
}

/// Body of `POST /v1/books/{id}/close` (WFL-13).
#[derive(Deserialize)]
pub struct CloseBook {
    pub reason: ClosingReason,
    pub closing_date: String,
    pub required_signatories: Vec<String>,
    #[serde(default = "default_actor")]
    pub actor: String,
}

/// Optional filter for `GET /v1/books`.
#[derive(Deserialize)]
pub struct BooksQuery {
    pub entity_id: Option<Uuid>,
}

// --- Act views + bodies ------------------------------------------------------------------

/// Wire view of an attachment: the digest becomes hex (or `null`).
#[derive(Serialize)]
pub struct AttachmentView {
    pub label: String,
    pub kind: AttachmentKind,
    pub digest: Option<String>,
    /// Detached-document beginning-of-proof flag (ENT-C6 / R7). Additive.
    pub beginning_of_proof: bool,
}

impl From<&Attachment> for AttachmentView {
    fn from(a: &Attachment) -> Self {
        AttachmentView {
            label: a.label.clone(),
            kind: a.kind,
            digest: a.digest.as_ref().map(hex),
            beginning_of_proof: a.beginning_of_proof,
        }
    }
}

/// Wire view of a signatory slot.
#[derive(Serialize)]
pub struct SignatoryView {
    pub name: String,
    pub capacity: SignatoryCapacity,
    pub signed: bool,
    /// A condómino's *permilagem* (millésimos, 0..=1000), when recorded (ENT-D6 / R6). Additive.
    pub permilage: Option<u16>,
}

impl From<&SignatorySlot> for SignatoryView {
    fn from(s: &SignatorySlot) -> Self {
        SignatoryView {
            name: s.name.clone(),
            capacity: s.capacity,
            signed: s.signed,
            permilage: s.permilage,
        }
    }
}

// --- Structured act content views + inputs (t31 §2.4) ------------------------------------

/// Wire view + input of the **mesa** (presiding board): the chair and any secretaries.
#[derive(Serialize, Deserialize, Default)]
pub struct MesaView {
    pub presidente: Option<String>,
    #[serde(default)]
    pub secretarios: Vec<String>,
}

impl From<&Mesa> for MesaView {
    fn from(m: &Mesa) -> Self {
        MesaView {
            presidente: m.presidente.clone(),
            secretarios: m.secretarios.clone(),
        }
    }
}

impl From<MesaView> for Mesa {
    fn from(m: MesaView) -> Self {
        Mesa {
            presidente: m.presidente,
            secretarios: m.secretarios,
        }
    }
}

/// Wire view + input of one agenda point (ordem de trabalhos).
#[derive(Serialize, Deserialize)]
pub struct AgendaItemView {
    pub number: u32,
    pub text: String,
}

impl From<&AgendaItem> for AgendaItemView {
    fn from(a: &AgendaItem) -> Self {
        AgendaItemView {
            number: a.number,
            text: a.text.clone(),
        }
    }
}

impl From<AgendaItemView> for AgendaItem {
    fn from(a: AgendaItemView) -> Self {
        AgendaItem {
            number: a.number,
            text: a.text,
        }
    }
}

/// Wire view + input of a document submitted to / referenced by the meeting (art. 63.º).
#[derive(Serialize, Deserialize)]
pub struct DocumentReferenceView {
    pub label: String,
    pub reference: Option<String>,
}

impl From<&DocumentReference> for DocumentReferenceView {
    fn from(d: &DocumentReference) -> Self {
        DocumentReferenceView {
            label: d.label.clone(),
            reference: d.reference.clone(),
        }
    }
}

impl From<DocumentReferenceView> for DocumentReference {
    fn from(d: DocumentReferenceView) -> Self {
        DocumentReference {
            label: d.label,
            reference: d.reference,
        }
    }
}

/// Wire view + input of a structured voting result. Internally-tagged (`{ "type": … }`),
/// matching the DTO enum convention (`InscriptionPayloadView`):
/// `{"type":"Unanimous"}` | `{"type":"Recorded","em_favor":..,"contra":..,"abstencoes":..}`.
#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum VoteResultView {
    Unanimous,
    Recorded {
        em_favor: u32,
        contra: u32,
        abstencoes: u32,
    },
}

impl From<&VoteResult> for VoteResultView {
    fn from(v: &VoteResult) -> Self {
        match v {
            VoteResult::Unanimous => VoteResultView::Unanimous,
            VoteResult::Recorded {
                em_favor,
                contra,
                abstencoes,
            } => VoteResultView::Recorded {
                em_favor: *em_favor,
                contra: *contra,
                abstencoes: *abstencoes,
            },
        }
    }
}

impl From<VoteResultView> for VoteResult {
    fn from(v: VoteResultView) -> Self {
        match v {
            VoteResultView::Unanimous => VoteResult::Unanimous,
            VoteResultView::Recorded {
                em_favor,
                contra,
                abstencoes,
            } => VoteResult::Recorded {
                em_favor,
                contra,
                abstencoes,
            },
        }
    }
}

/// Wire view + input of a member statement (declaração / declaração de voto vencido).
#[derive(Serialize, Deserialize)]
pub struct MemberStatementView {
    pub member: String,
    pub text: String,
}

impl From<&MemberStatement> for MemberStatementView {
    fn from(s: &MemberStatement) -> Self {
        MemberStatementView {
            member: s.member.clone(),
            text: s.text.clone(),
        }
    }
}

impl From<MemberStatementView> for MemberStatement {
    fn from(s: MemberStatementView) -> Self {
        MemberStatement {
            member: s.member,
            text: s.text,
        }
    }
}

/// Wire view + input of one structured deliberation, tied to an agenda item when known (R3).
#[derive(Serialize, Deserialize)]
pub struct DeliberationItemView {
    #[serde(default)]
    pub agenda_number: Option<u32>,
    pub text: String,
    #[serde(default)]
    pub vote: Option<VoteResultView>,
    #[serde(default)]
    pub statements: Vec<MemberStatementView>,
}

impl From<&DeliberationItem> for DeliberationItemView {
    fn from(d: &DeliberationItem) -> Self {
        DeliberationItemView {
            agenda_number: d.agenda_number,
            text: d.text.clone(),
            vote: d.vote.as_ref().map(VoteResultView::from),
            statements: d.statements.iter().map(MemberStatementView::from).collect(),
        }
    }
}

impl From<DeliberationItemView> for DeliberationItem {
    fn from(d: DeliberationItemView) -> Self {
        DeliberationItem {
            agenda_number: d.agenda_number,
            text: d.text,
            vote: d.vote.map(Into::into),
            statements: d.statements.into_iter().map(Into::into).collect(),
        }
    }
}

/// Response view of an `Act` (contract §2.5). The structured art. 63.º content fields
/// (`meeting_time`, `mesa`, `agenda`, `referenced_documents`, `deliberation_items`,
/// `members_present`/`members_represented`) are additive (t31 §2.4); old clients tolerate them.
#[derive(Serialize)]
pub struct ActView {
    pub id: String,
    pub book_id: String,
    pub title: String,
    pub channel: MeetingChannel,
    pub meeting_date: Option<String>,
    /// Meeting time as `HH:MM`, or `null` (CSC art. 63.º mandatory content). Additive.
    pub meeting_time: Option<String>,
    pub place: Option<String>,
    /// The mesa (presiding board): chair + secretaries. Additive.
    pub mesa: MesaView,
    /// The ordem de trabalhos (agenda). Additive.
    pub agenda: Vec<AgendaItemView>,
    pub attendance_reference: Option<String>,
    /// Members present in person (statute-quorum input). Additive.
    pub members_present: Option<u32>,
    /// Members represented by proxy. Additive.
    pub members_represented: Option<u32>,
    /// Documents submitted to / referenced by the meeting (art. 63.º). Additive.
    pub referenced_documents: Vec<DocumentReferenceView>,
    pub deliberations: String,
    /// Structured deliberations (per-item text + vote + statements), additive to `deliberations`.
    pub deliberation_items: Vec<DeliberationItemView>,
    pub telematic_evidence: Option<String>,
    pub attachments: Vec<AttachmentView>,
    pub signatories: Vec<SignatoryView>,
    pub state: ActState,
    pub ata_number: Option<u64>,
    pub payload_digest: Option<String>,
    pub seal_event_seq: Option<u64>,
    pub retifies: Option<String>,
}

impl From<&Act> for ActView {
    fn from(a: &Act) -> Self {
        ActView {
            id: a.id.to_string(),
            book_id: a.book_id.to_string(),
            title: a.title.clone(),
            channel: a.channel,
            meeting_date: a.meeting_date.map(format_date),
            meeting_time: a.meeting_time.map(format_time),
            place: a.place.clone(),
            mesa: MesaView::from(&a.mesa),
            agenda: a.agenda.iter().map(AgendaItemView::from).collect(),
            attendance_reference: a.attendance_reference.clone(),
            members_present: a.members_present,
            members_represented: a.members_represented,
            referenced_documents: a
                .referenced_documents
                .iter()
                .map(DocumentReferenceView::from)
                .collect(),
            deliberations: a.deliberations.clone(),
            deliberation_items: a
                .deliberation_items
                .iter()
                .map(DeliberationItemView::from)
                .collect(),
            telematic_evidence: a.telematic_evidence.clone(),
            attachments: a.attachments.iter().map(AttachmentView::from).collect(),
            signatories: a.signatories.iter().map(SignatoryView::from).collect(),
            state: a.state,
            ata_number: a.ata_number,
            payload_digest: a.payload_digest.as_ref().map(hex),
            seal_event_seq: a.seal_event_seq,
            retifies: a.retifies.map(|r| r.to_string()),
        }
    }
}

/// Body of `POST /v1/acts` (draft a new ata, WFL-14).
#[derive(Deserialize)]
pub struct DraftAct {
    pub book_id: Uuid,
    pub title: String,
    pub channel: MeetingChannel,
    pub retifies: Option<Uuid>,
    #[serde(default = "default_actor")]
    pub actor: String,
}

/// Attachment as accepted on a PATCH (input side: digest is an optional hex string).
#[derive(Deserialize)]
pub struct AttachmentInput {
    pub label: String,
    pub kind: AttachmentKind,
    pub digest: Option<String>,
    /// Detached-document beginning-of-proof flag (ENT-C6 / R7). Defaults to `false` when absent.
    #[serde(default)]
    pub beginning_of_proof: bool,
}

impl AttachmentInput {
    /// Convert to the core type, parsing the hex digest (a malformed digest is a `422`).
    pub fn into_core(self) -> Result<Attachment, ApiError> {
        let digest = match self.digest {
            Some(s) => Some(parse_hex32(&s).ok_or_else(|| {
                ApiError::Unprocessable(format!("invalid attachment digest {s:?}"))
            })?),
            None => None,
        };
        Ok(Attachment {
            label: self.label,
            kind: self.kind,
            digest,
            beginning_of_proof: self.beginning_of_proof,
        })
    }
}

/// Signatory slot as accepted on a PATCH.
#[derive(Deserialize)]
pub struct SignatoryInput {
    pub name: String,
    pub capacity: SignatoryCapacity,
    #[serde(default)]
    pub signed: bool,
    /// A condómino's *permilagem* (millésimos, 0..=1000), when recorded (ENT-D6 / R6). Absent ⇒
    /// `None`.
    #[serde(default)]
    pub permilage: Option<u16>,
}

impl From<SignatoryInput> for SignatorySlot {
    fn from(s: SignatoryInput) -> Self {
        SignatorySlot {
            name: s.name,
            capacity: s.capacity,
            signed: s.signed,
            permilage: s.permilage,
        }
    }
}

/// Body of `PATCH /v1/acts/{id}` (working-content edit; every field optional). Nullable
/// domain fields use [`double_option`] so a present `null` clears them and an absent key
/// leaves them untouched. `attachments`/`signatories`/`agenda`/`referenced_documents`/
/// `deliberation_items`/`mesa` are full replacements when present. The structured art. 63.º
/// fields are additive (t31 §2.4): a pre-t31 PATCH omits them and leaves them untouched.
#[derive(Deserialize)]
pub struct PatchAct {
    pub title: Option<String>,
    pub channel: Option<MeetingChannel>,
    #[serde(default, deserialize_with = "double_option")]
    pub meeting_date: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option")]
    pub meeting_time: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option")]
    pub place: Option<Option<String>>,
    /// Replace the mesa when present.
    pub mesa: Option<MesaView>,
    /// Replace the agenda (ordem de trabalhos) when present.
    pub agenda: Option<Vec<AgendaItemView>>,
    #[serde(default, deserialize_with = "double_option")]
    pub attendance_reference: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option")]
    pub members_present: Option<Option<u32>>,
    #[serde(default, deserialize_with = "double_option")]
    pub members_represented: Option<Option<u32>>,
    /// Replace the referenced-documents list when present.
    pub referenced_documents: Option<Vec<DocumentReferenceView>>,
    pub deliberations: Option<String>,
    /// Replace the structured deliberations list when present.
    pub deliberation_items: Option<Vec<DeliberationItemView>>,
    #[serde(default, deserialize_with = "double_option")]
    pub telematic_evidence: Option<Option<String>>,
    pub attachments: Option<Vec<AttachmentInput>>,
    pub signatories: Option<Vec<SignatoryInput>>,
}

/// Body of `POST /v1/acts/{id}/advance`.
#[derive(Deserialize)]
pub struct AdvanceAct {
    pub to: ActState,
    #[serde(default = "default_actor")]
    pub actor: String,
}

/// Body of `POST /v1/acts/{id}/seal` (all fields optional; empty body allowed).
#[derive(Deserialize)]
pub struct SealAct {
    #[serde(default = "default_actor")]
    pub actor: String,
    #[serde(default)]
    pub acknowledge_warnings: bool,
}

impl Default for SealAct {
    fn default() -> Self {
        SealAct {
            actor: default_actor(),
            acknowledge_warnings: false,
        }
    }
}

/// Body of `POST /v1/acts/{id}/archive` (optional; empty body allowed).
#[derive(Deserialize)]
pub struct ArchiveAct {
    #[serde(default = "default_actor")]
    pub actor: String,
}

impl Default for ArchiveAct {
    fn default() -> Self {
        ArchiveAct {
            actor: default_actor(),
        }
    }
}

/// Response of `POST /v1/acts/{id}/seal` on success.
#[derive(Serialize)]
pub struct SealResponse {
    pub act: ActView,
    pub ata_number: u64,
    pub event_seq: u64,
    pub payload_digest: String,
    pub acknowledged_warnings: Vec<IssueView>,
    /// The document generated for this seal (t48 / DOC-01): its id, PDF/A-2u digest, and the
    /// pinned template version. Additive. `null` when the act's family has no bound template yet
    /// (documented fallback) — existing fields are unchanged.
    pub document: Option<SealDocument>,
}

/// The additive `document` block of a [`SealResponse`] (t48 §3.3).
#[derive(Serialize)]
pub struct SealDocument {
    pub id: String,
    pub pdf_digest: String,
    pub template_id: String,
}

/// Response of `GET /v1/acts/{id}/compliance`. `rule_pack` is the **dispatched** family pack id
/// (per-family, R4). `family` and `statute_overlay` are additive (t31 §2.4): the entity family
/// the pack was selected for, and whether a statute overlay contributed findings.
#[derive(Serialize)]
pub struct ComplianceResponse {
    pub rule_pack: String,
    pub family: EntityFamily,
    pub statute_overlay: bool,
    pub issues: Vec<IssueView>,
    pub errors: u32,
    pub warnings: u32,
    pub seal_allowed: bool,
}

// --- Ledger view + query -----------------------------------------------------------------

/// Compact attestation summary joined onto a ledger event view (plan t29 §4.6): who attested the
/// event, with which key, and how. The full record (signature, timestamp) is fetched separately
/// via `GET /v1/ledger/attestations/{seq}`.
#[derive(Serialize, Clone)]
pub struct AttestationSummary {
    pub username: String,
    pub fingerprint: String,
    pub algorithm: String,
}

impl From<&crate::attestation::Attestation> for AttestationSummary {
    fn from(a: &crate::attestation::Attestation) -> Self {
        AttestationSummary {
            username: a.username.clone(),
            fingerprint: a.fingerprint.clone(),
            algorithm: a.algorithm.clone(),
        }
    }
}

/// Wire view of a ledger `Event` (contract §2.6): hex digests, RFC 3339 timestamp. Additively
/// carries an `attestation` summary (plan t29 §4.6), `null` when the event was not attested.
#[derive(Serialize)]
pub struct LedgerEventView {
    pub id: String,
    pub seq: u64,
    pub actor: String,
    pub justification: Option<String>,
    pub timestamp: String,
    pub scope: String,
    pub kind: String,
    pub payload_digest: String,
    pub prev_hash: String,
    pub hash: String,
    /// The attestation for this event, or `null`. Joined by the handler from the in-memory
    /// sidecar; `From<&Event>` alone leaves it `None`.
    pub attestation: Option<AttestationSummary>,
}

impl From<&Event> for LedgerEventView {
    fn from(e: &Event) -> Self {
        LedgerEventView {
            id: e.id.to_string(),
            seq: e.seq,
            actor: e.actor.clone(),
            justification: e.justification.clone(),
            timestamp: e.timestamp.format(&Rfc3339).unwrap_or_default(),
            scope: e.scope.clone(),
            kind: e.kind.clone(),
            payload_digest: hex(&e.payload_digest),
            prev_hash: hex(&e.prev_hash),
            hash: hex(&e.hash),
            attestation: None,
        }
    }
}

/// Query for `GET /v1/ledger/events`: substring `scope` filter and last-N `limit`.
#[derive(Deserialize)]
pub struct LedgerQuery {
    pub scope: Option<String>,
    pub limit: Option<usize>,
}

// --- Dashboard ---------------------------------------------------------------------------

/// Response of `GET /v1/dashboard` (WFL-40 subset, contract §2.7).
#[derive(Serialize)]
pub struct DashboardResponse {
    pub entities: usize,
    pub books_open: usize,
    pub books_total: usize,
    pub acts_total: usize,
    pub acts_draft: usize,
    pub acts_awaiting_signature: usize,
    pub acts_sealed: usize,
    pub unresolved_compliance: usize,
    pub ledger_length: u64,
    pub ledger_valid: bool,
    pub recent_events: Vec<LedgerEventView>,
}

// --- Registry views + report (§2.7) ------------------------------------------------------

/// Wire view of an extract's provenance (LEG-22). Carries only the **masked** access code —
/// the full código de acesso never reaches a DTO. The certidão-meta / validity fields are
/// additive (t21); `expired` is **computed** here against today (UTC) from `valid_until` — it is
/// not stored in the model, which stays clock-independent.
#[derive(Serialize)]
pub struct RegistryProvenanceView {
    pub access_code_masked: String,
    pub retrieved_at: String,
    pub source_url: String,
    pub raw_digest: String,
    pub conservatoria: Option<String>,
    pub oficial: Option<String>,
    pub subscribed_on: Option<String>,
    pub valid_until: Option<String>,
    /// `true` when `valid_until` is a valid ISO date strictly before today (UTC); `null` when
    /// `valid_until` is absent or unparseable (honest: we do not claim expiry we cannot compute).
    pub expired: Option<bool>,
}

impl From<&RegistryProvenance> for RegistryProvenanceView {
    fn from(p: &RegistryProvenance) -> Self {
        let today = OffsetDateTime::now_utc().date();
        RegistryProvenanceView {
            access_code_masked: p.access_code_masked.clone(),
            retrieved_at: p.retrieved_at.clone(),
            source_url: p.source_url.clone(),
            raw_digest: p.raw_digest.clone(),
            conservatoria: p.conservatoria.clone(),
            oficial: p.oficial.clone(),
            subscribed_on: p.subscribed_on.clone(),
            valid_until: p.valid_until.clone(),
            expired: compute_expired(p.valid_until.as_deref(), today),
        }
    }
}

/// Whether a certidão is expired: `valid_until` (ISO `YYYY-MM-DD`) strictly before `today`.
/// `None` when `valid_until` is absent or does not parse — expiry we cannot compute is not claimed.
pub(crate) fn compute_expired(valid_until: Option<&str>, today: Date) -> Option<bool> {
    let parsed = parse_date(valid_until?).ok()?;
    Some(parsed < today)
}

// --- Structured inscription layer views (t21 §3.1) --------------------------------------------

/// Wire view of a certidão [`Address`] — free lines plus the admin/postal breakdown.
#[derive(Serialize)]
pub struct AddressView {
    pub lines: Vec<String>,
    pub distrito: Option<String>,
    pub concelho: Option<String>,
    pub freguesia: Option<String>,
    pub postal_code: Option<String>,
    pub locality: Option<String>,
}

impl From<&Address> for AddressView {
    fn from(a: &Address) -> Self {
        AddressView {
            lines: a.lines.clone(),
            distrito: a.distrito.clone(),
            concelho: a.concelho.clone(),
            freguesia: a.freguesia.clone(),
            postal_code: a.postal_code.clone(),
            locality: a.locality.clone(),
        }
    }
}

/// Wire view of a [`Money`] figure — amount as printed (TEXT, no numeric coercion) + currency.
#[derive(Serialize)]
pub struct MoneyView {
    pub amount_text: String,
    pub currency: Option<String>,
}

impl From<&Money> for MoneyView {
    fn from(m: &Money) -> Self {
        MoneyView {
            amount_text: m.amount_text.clone(),
            currency: m.currency.clone(),
        }
    }
}

/// Wire view of a named party ([`Person`]) — a sócio's titular or a person's identity block.
#[derive(Serialize)]
pub struct PersonView {
    pub name: String,
    pub nif: Option<String>,
    pub estado_civil: Option<String>,
    pub nacionalidade: Option<String>,
    pub residencia: Option<AddressView>,
}

impl From<&Person> for PersonView {
    fn from(p: &Person) -> Self {
        PersonView {
            name: p.name.clone(),
            nif: p.nif.clone(),
            estado_civil: p.estado_civil.clone(),
            nacionalidade: p.nacionalidade.clone(),
            residencia: p.residencia.as_ref().map(AddressView::from),
        }
    }
}

/// Wire view of a [`Quota`] (share) and its holder.
#[derive(Serialize)]
pub struct QuotaView {
    pub amount: MoneyView,
    pub titular: PersonView,
}

impl From<&Quota> for QuotaView {
    fn from(q: &Quota) -> Self {
        QuotaView {
            amount: MoneyView::from(&q.amount),
            titular: PersonView::from(&q.titular),
        }
    }
}

/// Wire view of a social organ ([`Organ`]) and its members.
#[derive(Serialize)]
pub struct OrganView {
    pub name: String,
    pub members: Vec<OrganMemberView>,
}

impl From<&Organ> for OrganView {
    fn from(o: &Organ) -> Self {
        OrganView {
            name: o.name.clone(),
            members: o.members.iter().map(OrganMemberView::from).collect(),
        }
    }
}

/// Wire view of one [`OrganMember`].
#[derive(Serialize)]
pub struct OrganMemberView {
    pub name: String,
    pub nif: Option<String>,
    pub cargo: Option<String>,
    pub nacionalidade: Option<String>,
    pub residencia: Option<AddressView>,
}

impl From<&OrganMember> for OrganMemberView {
    fn from(m: &OrganMember) -> Self {
        OrganMemberView {
            name: m.name.clone(),
            nif: m.nif.clone(),
            cargo: m.cargo.clone(),
            nacionalidade: m.nacionalidade.clone(),
            residencia: m.residencia.as_ref().map(AddressView::from),
        }
    }
}

/// Wire view of the parsed [`Apresentacao`] header.
#[derive(Serialize)]
pub struct ApresentacaoView {
    pub number: Option<String>,
    pub date: Option<String>,
    pub time: Option<String>,
    pub act_kinds: Vec<String>,
}

impl From<&Apresentacao> for ApresentacaoView {
    fn from(a: &Apresentacao) -> Self {
        ApresentacaoView {
            number: a.number.clone(),
            date: a.date.clone(),
            time: a.time.clone(),
            act_kinds: a.act_kinds.clone(),
        }
    }
}

/// Wire view of a conservatória/oficial signature pair found inside an entry body.
#[derive(Serialize)]
pub struct RegistryOfficialSignatureView {
    pub conservatoria: Option<String>,
    pub oficial: Option<String>,
}

impl From<&RegistryOfficialSignature> for RegistryOfficialSignatureView {
    fn from(s: &RegistryOfficialSignature) -> Self {
        RegistryOfficialSignatureView {
            conservatoria: s.conservatoria.clone(),
            oficial: s.oficial.clone(),
        }
    }
}

/// Wire view of a `CONSTITUIÇÃO DE SOCIEDADE` payload.
#[derive(Serialize)]
pub struct ConstitutionPayloadView {
    pub firma: Option<String>,
    pub nipc: Option<String>,
    pub natureza_juridica: Option<String>,
    pub sede: Option<AddressView>,
    pub objecto: Option<String>,
    pub capital: Option<MoneyView>,
    pub capital_realization_note: Option<String>,
    pub fiscal_year_end: Option<String>,
    pub socios: Vec<QuotaView>,
    pub forma_de_obrigar: Option<String>,
    pub orgaos: Vec<OrganView>,
    pub deliberation_date: Option<String>,
}

impl From<&ConstitutionPayload> for ConstitutionPayloadView {
    fn from(c: &ConstitutionPayload) -> Self {
        ConstitutionPayloadView {
            firma: c.firma.clone(),
            nipc: c.nipc.clone(),
            natureza_juridica: c.natureza_juridica.clone(),
            sede: c.sede.as_ref().map(AddressView::from),
            objecto: c.objecto.clone(),
            capital: c.capital.as_ref().map(MoneyView::from),
            capital_realization_note: c.capital_realization_note.clone(),
            fiscal_year_end: c.fiscal_year_end.clone(),
            socios: c.socios.iter().map(QuotaView::from).collect(),
            forma_de_obrigar: c.forma_de_obrigar.clone(),
            orgaos: c.orgaos.iter().map(OrganView::from).collect(),
            deliberation_date: c.deliberation_date.clone(),
        }
    }
}

/// Wire view of a `DESIGNAÇÃO DE MEMBRO(S)` payload.
#[derive(Serialize)]
pub struct DesignationPayloadView {
    pub orgaos: Vec<OrganView>,
    pub deliberation_date: Option<String>,
}

impl From<&DesignationPayload> for DesignationPayloadView {
    fn from(d: &DesignationPayload) -> Self {
        DesignationPayloadView {
            orgaos: d.orgaos.iter().map(OrganView::from).collect(),
            deliberation_date: d.deliberation_date.clone(),
        }
    }
}

/// Wire view of a `CESSAÇÃO DE FUNÇÕES` / renúncia payload.
#[derive(Serialize)]
pub struct CessationPayloadView {
    pub members: Vec<OrganMemberView>,
    pub cause: Option<String>,
    pub date: Option<String>,
}

impl From<&CessationPayload> for CessationPayloadView {
    fn from(c: &CessationPayload) -> Self {
        CessationPayloadView {
            members: c.members.iter().map(OrganMemberView::from).collect(),
            cause: c.cause.clone(),
            date: c.date.clone(),
        }
    }
}

/// Wire view of an `ALTERAÇÕES AO CONTRATO` payload.
#[derive(Serialize)]
pub struct AmendmentPayloadView {
    pub new_firma: Option<String>,
    pub new_sede: Option<AddressView>,
    pub new_objecto: Option<String>,
    pub new_capital: Option<MoneyView>,
    pub deliberation_date: Option<String>,
}

impl From<&AmendmentPayload> for AmendmentPayloadView {
    fn from(a: &AmendmentPayload) -> Self {
        AmendmentPayloadView {
            new_firma: a.new_firma.clone(),
            new_sede: a.new_sede.as_ref().map(AddressView::from),
            new_objecto: a.new_objecto.clone(),
            new_capital: a.new_capital.as_ref().map(MoneyView::from),
            deliberation_date: a.deliberation_date.clone(),
        }
    }
}

/// Wire view of the per-act structured payload. Internally-tagged (`{ "type": … }`) mirroring the
/// model's [`InscriptionPayload`]. A future (non-exhaustive) model variant maps to `None` — the
/// raw `RegistryEvent.text` still carries everything, so the wire never loses the entry.
#[derive(Serialize)]
#[serde(tag = "type")]
pub enum InscriptionPayloadView {
    Constitution(ConstitutionPayloadView),
    Designation(DesignationPayloadView),
    Cessation(CessationPayloadView),
    ContractAmendment(AmendmentPayloadView),
}

impl InscriptionPayloadView {
    /// Mirror a known model payload; a not-yet-viewed (non-exhaustive) variant yields `None`.
    fn from_model(p: &InscriptionPayload) -> Option<Self> {
        Some(match p {
            InscriptionPayload::Constitution(c) => Self::Constitution(c.into()),
            InscriptionPayload::Designation(d) => Self::Designation(d.into()),
            InscriptionPayload::Cessation(c) => Self::Cessation(c.into()),
            InscriptionPayload::ContractAmendment(a) => Self::ContractAmendment(a.into()),
            _ => return None,
        })
    }
}

/// Wire view of the structured layer on top of a [`RegistryEvent`].
#[derive(Serialize)]
pub struct InscriptionDetailView {
    pub apresentacao: Option<ApresentacaoView>,
    pub payload: Option<InscriptionPayloadView>,
    pub signatures: Vec<RegistryOfficialSignatureView>,
}

impl From<&InscriptionDetail> for InscriptionDetailView {
    fn from(d: &InscriptionDetail) -> Self {
        InscriptionDetailView {
            apresentacao: d.apresentacao.as_ref().map(ApresentacaoView::from),
            payload: d
                .payload
                .as_ref()
                .and_then(InscriptionPayloadView::from_model),
            signatures: d
                .signatures
                .iter()
                .map(RegistryOfficialSignatureView::from)
                .collect(),
        }
    }
}

/// Wire view of a publication annotation (`An. N`).
#[derive(Serialize)]
pub struct RegistryAnnotationView {
    pub number: Option<String>,
    pub date: Option<String>,
    pub publication_url: Option<String>,
    pub text: String,
}

impl From<&RegistryAnnotation> for RegistryAnnotationView {
    fn from(a: &RegistryAnnotation) -> Self {
        RegistryAnnotationView {
            number: a.number.clone(),
            date: a.date.clone(),
            publication_url: a.publication_url.clone(),
            text: a.text.clone(),
        }
    }
}

/// Wire view of a best-effort social-organ officer.
#[derive(Serialize)]
pub struct RegistryOfficerView {
    pub name: String,
    pub role: Option<String>,
    pub appointment_date: Option<String>,
    pub cessation_date: Option<String>,
    pub source_event: Option<String>,
}

impl From<&RegistryOfficer> for RegistryOfficerView {
    fn from(o: &RegistryOfficer) -> Self {
        RegistryOfficerView {
            name: o.name.clone(),
            role: o.role.clone(),
            appointment_date: o.appointment_date.clone(),
            cessation_date: o.cessation_date.clone(),
            source_event: o.source_event.clone(),
        }
    }
}

/// Wire view of one numbered inscrição/averbamento (the ordered DOC-30 event feed).
#[derive(Serialize)]
pub struct RegistryEventView {
    pub number: Option<String>,
    pub kind_hint: Option<String>,
    pub apresentacao: Option<String>,
    pub date: Option<String>,
    pub text: String,
    /// The structured layer read off `text` (additive, t21); `null` when the body was not
    /// deep-parsed. The raw `text` above always carries everything.
    pub detail: Option<InscriptionDetailView>,
}

impl From<&RegistryEvent> for RegistryEventView {
    fn from(e: &RegistryEvent) -> Self {
        RegistryEventView {
            number: e.number.clone(),
            kind_hint: e.kind_hint.clone(),
            apresentacao: e.apresentacao.clone(),
            date: e.date.clone(),
            text: e.text.clone(),
            detail: e.detail.as_ref().map(InscriptionDetailView::from),
        }
    }
}

/// Response view of a [`RegistryExtract`] (contract §2.7). Mirrors the extract model, but
/// renders `legal_form` as its bare variant string (or `null` when the natureza jurídica was
/// absent or unmapped — the raw text stays available in `forma_juridica`), and enriches each
/// role-tagged CAE reference with its designation/level/revision from the [`CaeCatalog`].
#[derive(Serialize)]
pub struct RegistryExtractView {
    pub matricula: Option<String>,
    pub nipc: Option<String>,
    pub firma: Option<String>,
    pub forma_juridica: Option<String>,
    pub legal_form: Option<String>,
    pub sede: Option<String>,
    /// Role-tagged CAE codes (Principal/Secundário), each enriched from the catalog — a breaking
    /// change from the previous `Vec<String>` (t14; consumed by the t13 CAE UI).
    pub cae: Vec<CaeRefView>,
    pub objeto: Option<String>,
    pub capital: Option<String>,
    pub data_constituicao: Option<String>,
    pub orgaos: Vec<RegistryOfficerView>,
    pub inscricoes: Vec<RegistryEventView>,
    /// The `An. N` publication annotations, ordered as printed (additive, t21).
    pub anotacoes: Vec<RegistryAnnotationView>,
    pub provenance: RegistryProvenanceView,
}

impl RegistryExtractView {
    /// Build the view, resolving each CAE code against `cae` (Rev.4 first, then Rev.3). Replaces
    /// the old `From<&RegistryExtract>` impl now that enrichment needs the catalog.
    pub fn build(e: &RegistryExtract, cae: &CaeCatalog) -> Self {
        RegistryExtractView {
            matricula: e.matricula.clone(),
            nipc: e.nipc.clone(),
            firma: e.firma.clone(),
            forma_juridica: e.forma_juridica.clone(),
            legal_form: e.legal_form.as_ref().and_then(legal_form_name),
            sede: e.sede.clone(),
            cae: e.cae.iter().map(|r| enrich_cae_ref(r, cae)).collect(),
            objeto: e.objeto.clone(),
            capital: e.capital.clone(),
            data_constituicao: e.data_constituicao.clone(),
            orgaos: e.orgaos.iter().map(RegistryOfficerView::from).collect(),
            inscricoes: e.inscricoes.iter().map(RegistryEventView::from).collect(),
            anotacoes: e
                .anotacoes
                .iter()
                .map(RegistryAnnotationView::from)
                .collect(),
            provenance: RegistryProvenanceView::from(&e.provenance),
        }
    }
}

/// One cross-check divergence between an entity field and the imported extract (contract
/// §2.7). `current` is the entity's value before import, `incoming` the extract's; either may
/// be `null`.
#[derive(Serialize)]
pub struct RegistryConflict {
    pub field: String,
    pub current: Option<String>,
    pub incoming: Option<String>,
}

/// Response of the registry import endpoints (contract §2.7): the (possibly updated or newly
/// created) entity, the imported extract, the list of fields filled/overwritten from the
/// extract (`applied`), and the divergences that were **kept** unless overwritten (`conflicts`).
#[derive(Serialize)]
pub struct RegistryImportReport {
    pub entity: EntityView,
    pub extract: RegistryExtractView,
    pub applied: Vec<String>,
    pub conflicts: Vec<RegistryConflict>,
    /// Non-fatal advisories surfaced alongside a successful import (additive, t21) — currently an
    /// expired-certidão notice ("certidão expirada em <valid_until>"). Import still returns
    /// 200/201: an expired certidão is surfaced, not rejected.
    pub warnings: Vec<String>,
}
