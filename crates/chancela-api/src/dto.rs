//! JSON data-transfer objects: the wire shapes the API owns.
//!
//! The API never serializes `chancela-core`'s domain types directly onto the wire. Two things
//! force that: `time::Date` has no stable JSON contract we want to expose, and digests are
//! `[u8; 32]` which serde would render as integer arrays. So this module defines the response
//! *views* (`BookView`, `ActView`, `LedgerEventView`, …) and request *bodies* pinned in the
//! cross-executor contract (plan §2), converting dates to ISO `YYYY-MM-DD` strings and digests
//! to lowercase hex ([`crate::hex`]). Enum fields reuse the core enums directly: their serde
//! representation is the bare variant name, which is exactly what the contract pins (§2.1).

use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize};
use time::format_description::well_known::Rfc3339;
use time::macros::format_description;
use time::{Date, OffsetDateTime};
use uuid::Uuid;

use chancela_authz::{Permission, ScopedPermissionSet};
use chancela_cae::CaeCatalog;
use chancela_core::act::{
    AiHumanVerification, AiHumanVerificationStatus, AiProvenance, AiStatementSource,
    ManualSignatureOriginalReference, WrittenResolutionReviewEvidenceLocator,
    WrittenResolutionReviewReceipt, WrittenResolutionReviewStatus,
};
#[cfg(test)]
use chancela_core::book::{BookId, TermoDeAbertura};
use chancela_core::book::{ClosingReason, TermoSignatory};
#[cfg(test)]
use chancela_core::entity::EntityId;
use chancela_core::{
    Act, ActState, AgendaItem, Attachment, AttachmentKind, AttendanceWeight, Attendee, Book,
    BookKind, BookState, ComplianceIssue, Convening, ConveningRecipient, ConveningWaiver,
    DeliberationItem, DispatchChannel, DocumentReference, Entity, EntityFamily, EntityKind,
    LegalBasis, LegalBasisVerification, MeetingChannel, MemberStatement, Mesa, NoConveningBasis,
    NumberingScheme, PresenceMode, SealMetadata, SecondCall, Severity, SignatoryCapacity,
    SignatorySlot, SignaturePolicyHint, StatuteOverrides, SupersededSigningSnapshot, VoteResult,
    WRITTEN_RESOLUTION_EVIDENCE_STATUS_BOUNDARY, WrittenResolutionEvidence,
    WrittenResolutionEvidenceItem, WrittenResolutionEvidenceSummary, profile_for,
    written_resolution_evidence_summary,
};
use chancela_ledger::Event;
use chancela_registry::{
    Address, AmendmentPayload, Apresentacao, CessationPayload, ConstitutionPayload,
    DesignationPayload, InscriptionDetail, InscriptionPayload, Money, Organ, OrganMember, Person,
    Quota, RegistryAnnotation, RegistryEvent, RegistryExtract, RegistryOfficer,
    RegistryOfficialSignature, RegistryProvenance,
};
use chancela_store::{StoredFollowUp, StoredFollowUpStatus};

use crate::AppState;
use crate::actor::CurrentActor;
use crate::cae::{CaeRefView, enrich_cae_ref};
use crate::error::ApiError;
use crate::hex::{hex, parse_hex32};
use crate::registry::legal_form_name;

/// Explicit marker used when a wire field is non-nullable but must be hidden from
/// Guest/read-only-minimal callers. Nullable fields use `null` instead.
pub(crate) const REDACTED: &str = "<redacted>";

fn redacted() -> String {
    REDACTED.to_owned()
}

/// Read-response privacy policy selected after RBAC has already allowed a read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReadRedaction {
    None,
    Guest,
}

impl ReadRedaction {
    #[must_use]
    pub(crate) fn for_effective_permissions(effective: &ScopedPermissionSet) -> Self {
        let mut grants = effective.all_grants().peekable();
        if grants.peek().is_some()
            && grants.all(|(permission, _)| {
                matches!(
                    permission,
                    Permission::EntityRead
                        | Permission::BookRead
                        | Permission::ActRead
                        | Permission::CaeRead
                        | Permission::LawRead
                )
            })
        {
            ReadRedaction::Guest
        } else {
            ReadRedaction::None
        }
    }

    #[must_use]
    pub(crate) const fn is_guest(self) -> bool {
        matches!(self, ReadRedaction::Guest)
    }
}

/// Resolve the caller's effective authority into the read-response privacy policy.
///
/// Authorization is still performed by the handler's `require`/`permits` checks first; this helper
/// only decides the response shape after a read has been allowed.
pub(crate) async fn read_redaction_for_actor(
    state: &AppState,
    actor: &CurrentActor,
) -> Result<ReadRedaction, ApiError> {
    if let Some(principal) = actor.api_key_principal() {
        return Ok(ReadRedaction::for_effective_permissions(
            &principal.effective_permissions,
        ));
    }

    let now = OffsetDateTime::now_utc();
    let (_, effective) = crate::roles::effective_permissions_for_actor(state, actor, now).await?;
    Ok(ReadRedaction::for_effective_permissions(&effective))
}

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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub legal_basis: Vec<LegalBasisView>,
}

/// Wire form of a compliance legal-basis reference. Pending references are structural only:
/// `source_url` is `null` and `source_complete` is `false` unless the underlying corpus article is
/// authenticity-gated.
#[derive(Debug, Serialize, Clone)]
pub struct LegalBasisView {
    pub source_id: String,
    pub source_label: String,
    pub article: Option<String>,
    pub article_label: Option<String>,
    pub citation: String,
    pub verification: String,
    pub source_url: Option<String>,
    pub source_complete: bool,
}

/// The contract's `Severity` encoding (§2.1): the bare variant name.
fn severity_str(s: Severity) -> &'static str {
    match s {
        Severity::Warning => "Warning",
        Severity::Error => "Error",
    }
}

fn legal_basis_verification_str(v: LegalBasisVerification) -> &'static str {
    match v {
        LegalBasisVerification::Verified => "Verified",
        LegalBasisVerification::Pending => "Pending",
    }
}

impl From<&LegalBasis> for LegalBasisView {
    fn from(b: &LegalBasis) -> Self {
        LegalBasisView {
            source_id: b.source_id.clone(),
            source_label: b.source_label.clone(),
            article: b.article.clone(),
            article_label: b.article_label.clone(),
            citation: b.citation.clone(),
            verification: legal_basis_verification_str(b.verification).to_owned(),
            source_url: b.source_url.clone(),
            source_complete: b.source_complete,
        }
    }
}

impl From<&ComplianceIssue> for IssueView {
    fn from(i: &ComplianceIssue) -> Self {
        IssueView {
            rule_id: i.rule_id.clone(),
            severity: severity_str(i.severity).to_owned(),
            message: i.message.clone(),
            legal_basis: i.legal_basis.iter().map(LegalBasisView::from).collect(),
        }
    }
}

// --- Entity view -------------------------------------------------------------------------

impl RegistryChangeSummaryView {
    fn from_event(e: &RegistryEvent) -> Option<Self> {
        let label = e
            .kind_hint
            .clone()
            .or_else(|| {
                e.text
                    .lines()
                    .map(str::trim)
                    .find(|line| !line.is_empty())
                    .map(str::to_owned)
            })
            .or_else(|| {
                e.number
                    .as_ref()
                    .map(|number| format!("Inscrição {number}"))
            })?;
        Some(RegistryChangeSummaryView {
            label,
            date: e.date.clone(),
            reference: e.apresentacao.clone().or_else(|| e.number.clone()),
        })
    }
}

impl EntityRegistrySummaryView {
    pub(crate) fn build(e: &RegistryExtract, cae: &CaeCatalog, today: Date) -> Self {
        EntityRegistrySummaryView {
            imported: true,
            matricula: e.matricula.clone(),
            data_constituicao: e.effective_data_constituicao(),
            capital: e.effective_capital(),
            cae: e.cae.iter().map(|r| enrich_cae_ref(r, cae)).collect(),
            retrieved_at: e.provenance.retrieved_at.clone(),
            valid_until: e.provenance.valid_until.clone(),
            expired: compute_expired(e.provenance.valid_until.as_deref(), today),
            last_registry_change: e
                .inscricoes
                .iter()
                .rev()
                .find_map(RegistryChangeSummaryView::from_event),
        }
    }
}

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
    pub tenant_id: String,
    pub group_id: Option<String>,
    pub name: String,
    pub nipc: String,
    pub nipc_validated: bool,
    pub seat: String,
    pub family: EntityFamily,
    pub kind: EntityKind,
    pub fiscal_year_end: Option<String>,
    /// The entity's derived profile (ENT-02): rule pack id, allowed channels, signature-policy
    /// hint, template-family seed, calendar presets. Additive (t31 §2.4).
    pub profile: EntityProfileView,
    /// The per-entity statute overlay (ENT-03), or `null`. Additive.
    pub statute: Option<StatuteOverrides>,
}

/// List-only activity rollup for one entity. This is computed by the API from the full book state
/// and full in-memory ledger, so clients do not need to infer it from the capped ledger feed.
#[derive(Serialize)]
pub struct EntityActivitySummaryView {
    pub last_book: Option<BookView>,
    pub book_state_counts: BookStateCountsView,
    pub last_change: Option<LedgerEventView>,
}

/// Compact list-only registry rollup for one entity. The full extract remains available via
/// `GET /v1/entities/{id}/registry`; this shape keeps the entities table useful without pushing
/// a heavy per-row registry payload through the list endpoint.
#[derive(Serialize)]
pub struct EntityRegistrySummaryView {
    pub imported: bool,
    pub matricula: Option<String>,
    pub data_constituicao: Option<String>,
    pub capital: Option<String>,
    pub cae: Vec<CaeRefView>,
    pub retrieved_at: String,
    pub valid_until: Option<String>,
    pub expired: Option<bool>,
    pub last_registry_change: Option<RegistryChangeSummaryView>,
}

/// The most recent registry-side change/event already available in the stored extract.
#[derive(Serialize)]
pub struct RegistryChangeSummaryView {
    pub label: String,
    pub date: Option<String>,
    pub reference: Option<String>,
}

/// Stable count shape for an entity's readable books by lifecycle state.
#[derive(Default, Serialize)]
pub struct BookStateCountsView {
    pub created: usize,
    pub open: usize,
    pub closed: usize,
}

impl BookStateCountsView {
    pub(crate) fn add(&mut self, state: BookState) {
        match state {
            BookState::Created => self.created += 1,
            BookState::Open => self.open += 1,
            BookState::Closed => self.closed += 1,
        }
    }
}

/// `GET /v1/entities` row: the normal entity view plus server-owned activity enrichment. Detail and
/// create responses keep returning [`EntityView`] without this list-only summary.
#[derive(Serialize)]
pub struct EntityListItemView {
    #[serde(flatten)]
    pub entity: EntityView,
    pub activity_summary: EntityActivitySummaryView,
    pub registry_summary: Option<EntityRegistrySummaryView>,
}

impl From<&Entity> for EntityView {
    fn from(e: &Entity) -> Self {
        EntityView {
            id: e.id.to_string(),
            tenant_id: e.tenant_id.to_string(),
            group_id: e.group_id.map(|id| id.to_string()),
            name: e.name.clone(),
            nipc: e.nipc.as_str().to_owned(),
            nipc_validated: e.nipc.is_validated(),
            seat: e.seat.clone(),
            family: e.family,
            kind: e.kind,
            fiscal_year_end: e.fiscal_year_end.clone(),
            profile: EntityProfileView::from(e.kind),
            statute: e.statute.clone(),
        }
    }
}

impl EntityView {
    /// Build an entity read view under the selected privacy policy.
    #[must_use]
    pub(crate) fn build(e: &Entity, redaction: ReadRedaction) -> Self {
        let mut view = EntityView::from(e);
        if redaction.is_guest() {
            view.nipc = redacted();
            view.nipc_validated = false;
            view.seat = redacted();
        }
        view
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
    /// The qualidades an attendance row may be recorded under for this legal type (t28). The
    /// editor's «na qualidade de» picker reads this rather than re-deriving the mapping, so a
    /// sociedade anónima offers *acionista* and a condomínio *condómino*.
    pub attendee_qualities: Vec<SignatoryCapacity>,
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
            attendee_qualities: p.attendee_qualities.clone(),
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
    pub required_signatory_records_abertura: Option<Vec<TermoSignatoryView>>,
    pub required_signatory_records_encerramento: Option<Vec<TermoSignatoryView>>,
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
            required_signatory_records_abertura: ab.map(|t| {
                termo_signatory_records(&t.required_signatory_records, &t.required_signatories)
            }),
            required_signatory_records_encerramento: en.map(|t| {
                termo_signatory_records(&t.required_signatory_records, &t.required_signatories)
            }),
        }
    }
}

impl BookView {
    /// Build a book read view under the selected privacy policy.
    #[must_use]
    pub(crate) fn build(b: &Book, redaction: ReadRedaction) -> Self {
        let mut view = BookView::from(b);
        if redaction.is_guest() {
            view.redact_sensitive();
        }
        view
    }

    fn redact_sensitive(&mut self) {
        self.purpose = None;
        self.predecessor = None;
        self.required_signatories_abertura = self
            .required_signatories_abertura
            .as_ref()
            .map(|items| vec![redacted(); items.len()]);
        self.required_signatories_encerramento = self
            .required_signatories_encerramento
            .as_ref()
            .map(|items| vec![redacted(); items.len()]);
        self.required_signatory_records_abertura = self
            .required_signatory_records_abertura
            .as_ref()
            .map(|items| vec![TermoSignatoryView::redacted(); items.len()]);
        self.required_signatory_records_encerramento = self
            .required_signatory_records_encerramento
            .as_ref()
            .map(|items| vec![TermoSignatoryView::redacted(); items.len()]);
    }
}

/// Wire view of a structured opening/closing termo signatory.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TermoSignatoryView {
    pub name: String,
    #[serde(default, alias = "role")]
    pub capacity: Option<SignatoryCapacity>,
    #[serde(default)]
    pub email: Option<String>,
}

impl From<&TermoSignatory> for TermoSignatoryView {
    fn from(s: &TermoSignatory) -> Self {
        TermoSignatoryView {
            name: s.name.clone(),
            capacity: s.capacity,
            email: s.email.clone(),
        }
    }
}

impl TermoSignatoryView {
    fn redacted() -> Self {
        TermoSignatoryView {
            name: redacted(),
            capacity: None,
            email: None,
        }
    }
}

fn termo_signatory_records(
    structured: &[TermoSignatory],
    legacy: &[String],
) -> Vec<TermoSignatoryView> {
    if structured.is_empty() {
        legacy
            .iter()
            .map(|value| TermoSignatoryView::from(&TermoSignatory::from_legacy(value.clone())))
            .collect()
    } else {
        structured.iter().map(TermoSignatoryView::from).collect()
    }
}

/// Request item accepted in the legacy `required_signatories` array.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum TermoSignatoryInput {
    Legacy(String),
    Structured(TermoSignatoryView),
}

pub(crate) fn normalize_termo_signatories(
    items: Vec<TermoSignatoryInput>,
    field: &'static str,
) -> Result<Vec<TermoSignatory>, ApiError> {
    let mut out = Vec::with_capacity(items.len());
    for (idx, item) in items.into_iter().enumerate() {
        let mut record = match item {
            TermoSignatoryInput::Legacy(value) => TermoSignatory::from_legacy(value.trim()),
            TermoSignatoryInput::Structured(value) => TermoSignatory {
                name: value.name.trim().to_owned(),
                capacity: value.capacity,
                email: crate::email::normalize_optional_email(
                    value.email,
                    "required_signatories.email",
                )?,
            },
        };
        if record.name.trim().is_empty() {
            return Err(ApiError::Unprocessable(format!(
                "{field}[{idx}].name must not be empty"
            )));
        }
        record.name = record.name.trim().to_owned();
        out.push(record);
    }
    Ok(out)
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
    pub required_signatories: Vec<TermoSignatoryInput>,
    pub predecessor: Option<Uuid>,
    #[serde(default = "default_actor")]
    pub actor: String,
}

/// Body of `POST /v1/books/{id}/close` (WFL-13).
#[derive(Deserialize)]
pub struct CloseBook {
    pub reason: ClosingReason,
    pub closing_date: String,
    pub required_signatories: Vec<TermoSignatoryInput>,
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

impl AttachmentView {
    fn redact_sensitive(&mut self) {
        self.label = redacted();
        self.digest = None;
    }
}

/// Wire view of a signatory slot.
#[derive(Serialize)]
pub struct SignatoryView {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    pub capacity: SignatoryCapacity,
    pub signed: bool,
    /// A condómino's *permilagem* (millésimos, 0..=1000), when recorded (ENT-D6 / R6). Additive.
    pub permilage: Option<u16>,
}

impl From<&SignatorySlot> for SignatoryView {
    fn from(s: &SignatorySlot) -> Self {
        SignatoryView {
            name: s.name.clone(),
            email: s.email.clone(),
            capacity: s.capacity,
            signed: s.signed,
            permilage: s.permilage,
        }
    }
}

impl SignatoryView {
    fn redact_sensitive(&mut self) {
        self.name = redacted();
        self.email = None;
    }
}

/// Wire view of WFL-23 manual-signature original-reference metadata.
#[derive(Serialize, Clone)]
pub struct ManualSignatureOriginalReferenceView {
    pub storage_reference: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custodian: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl From<&ManualSignatureOriginalReference> for ManualSignatureOriginalReferenceView {
    fn from(reference: &ManualSignatureOriginalReference) -> Self {
        ManualSignatureOriginalReferenceView {
            storage_reference: reference.storage_reference.clone(),
            custodian: reference.custodian.clone(),
            note: reference.note.clone(),
        }
    }
}

/// Wire view of the LEG-06/WFL-22 rule-pack/profile evidence recorded at sealing.
#[derive(Serialize, Clone)]
pub struct SealMetadataView {
    pub rule_pack_id: String,
    pub version: String,
    pub family: EntityFamily,
    pub profile: EntityKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manual_signature_original_reference: Option<ManualSignatureOriginalReferenceView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_snapshot_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_pdf_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_validation_report_digest: Option<String>,
}

impl From<&SealMetadata> for SealMetadataView {
    fn from(metadata: &SealMetadata) -> Self {
        SealMetadataView {
            rule_pack_id: metadata.rule_pack_id.clone(),
            version: metadata.version.clone(),
            family: metadata.family,
            profile: metadata.profile,
            manual_signature_original_reference: metadata
                .manual_signature_original_reference
                .as_ref()
                .map(ManualSignatureOriginalReferenceView::from),
            signing_snapshot_digest: metadata.signing_snapshot_digest.clone(),
            signed_pdf_digest: metadata.signed_pdf_digest.clone(),
            signature_validation_report_digest: metadata.signature_validation_report_digest.clone(),
        }
    }
}

impl SealMetadataView {
    fn redact_sensitive(&mut self) {
        self.manual_signature_original_reference = None;
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

impl MesaView {
    fn redact_sensitive(&mut self) {
        self.presidente = self.presidente.as_ref().map(|_| redacted());
        self.secretarios = vec![redacted(); self.secretarios.len()];
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

impl AgendaItemView {
    fn redact_sensitive(&mut self) {
        self.text = redacted();
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

impl DocumentReferenceView {
    fn redact_sensitive(&mut self) {
        self.label = redacted();
        self.reference = None;
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

/// Derived written-resolution evidence status exposed by API views. The boundary field makes the
/// scope explicit: this is a workflow/evidence-presence signal only.
#[derive(Debug, Serialize, Clone)]
pub struct WrittenResolutionEvidenceStatusView {
    pub status: String,
    pub boundary: String,
    pub signed_signatory_slots: usize,
    pub digested_attachments: usize,
    pub checklist_items: usize,
    pub digested_checklist_items: usize,
    pub referenced_checklist_items: usize,
    pub bound_count: usize,
    pub referenced_only_count: usize,
    pub review_receipts: usize,
    pub latest_review_status: Option<String>,
    pub reviewed_evidence_locators: usize,
    pub reviewed_evidence_digests: usize,
}

impl WrittenResolutionEvidenceStatusView {
    pub(crate) fn from_summary(summary: WrittenResolutionEvidenceSummary) -> Self {
        WrittenResolutionEvidenceStatusView {
            status: summary.status.as_str().to_owned(),
            boundary: WRITTEN_RESOLUTION_EVIDENCE_STATUS_BOUNDARY.to_owned(),
            signed_signatory_slots: summary.signed_signatory_slots,
            digested_attachments: summary.digested_attachments,
            checklist_items: summary.checklist_items,
            digested_checklist_items: summary.digested_checklist_items,
            referenced_checklist_items: summary.referenced_checklist_items,
            bound_count: summary.bound_count(),
            referenced_only_count: summary.referenced_only_count(),
            review_receipts: summary.review_receipts,
            latest_review_status: summary
                .latest_review_status
                .map(|status| status.as_str().to_owned()),
            reviewed_evidence_locators: summary.reviewed_evidence_locators,
            reviewed_evidence_digests: summary.reviewed_evidence_digests,
        }
    }
}

/// Wire view of one written-resolution evidence checklist item. Digests are hex on the wire.
#[derive(Serialize)]
pub struct WrittenResolutionEvidenceItemView {
    pub label: String,
    pub reference: Option<String>,
    pub digest: Option<String>,
    pub note: Option<String>,
}

impl From<&WrittenResolutionEvidenceItem> for WrittenResolutionEvidenceItemView {
    fn from(item: &WrittenResolutionEvidenceItem) -> Self {
        WrittenResolutionEvidenceItemView {
            label: item.label.clone(),
            reference: item.reference.clone(),
            digest: item.digest.as_ref().map(hex),
            note: item.note.clone(),
        }
    }
}

impl WrittenResolutionEvidenceItemView {
    fn redact_sensitive(&mut self) {
        self.label = redacted();
        self.reference = None;
        self.digest = None;
        self.note = None;
    }
}

/// Wire view of one evidence locator reviewed in a written-resolution receipt.
#[derive(Serialize)]
pub struct WrittenResolutionReviewEvidenceLocatorView {
    pub label: String,
    pub locator: Option<String>,
    pub digest: Option<String>,
}

impl From<&WrittenResolutionReviewEvidenceLocator> for WrittenResolutionReviewEvidenceLocatorView {
    fn from(locator: &WrittenResolutionReviewEvidenceLocator) -> Self {
        WrittenResolutionReviewEvidenceLocatorView {
            label: locator.label.clone(),
            locator: locator.locator.clone(),
            digest: locator.digest.as_ref().map(hex),
        }
    }
}

impl WrittenResolutionReviewEvidenceLocatorView {
    fn redact_sensitive(&mut self) {
        self.label = redacted();
        self.locator = None;
        self.digest = None;
    }
}

/// Wire view of one local written-resolution evidence review receipt.
#[derive(Serialize)]
pub struct WrittenResolutionReviewReceiptView {
    pub reviewer: String,
    pub reviewed_at: String,
    pub status: String,
    pub guardrail_acknowledgements: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<WrittenResolutionReviewEvidenceLocatorView>,
    pub note: Option<String>,
    pub consent_proof_claimed: bool,
    pub quorum_proof_claimed: bool,
    pub identity_proof_claimed: bool,
    pub legal_acceptance_claimed: bool,
    pub legal_sufficiency_claimed: bool,
    pub external_validation_claimed: bool,
    pub automatic_approval_claimed: bool,
    pub authority_certified_claimed: bool,
}

impl From<&WrittenResolutionReviewReceipt> for WrittenResolutionReviewReceiptView {
    fn from(receipt: &WrittenResolutionReviewReceipt) -> Self {
        WrittenResolutionReviewReceiptView {
            reviewer: receipt.reviewer.clone(),
            reviewed_at: receipt.reviewed_at.format(&Rfc3339).unwrap_or_default(),
            status: receipt.status.as_str().to_owned(),
            guardrail_acknowledgements: receipt.guardrail_acknowledgements.clone(),
            evidence: receipt
                .evidence
                .iter()
                .map(WrittenResolutionReviewEvidenceLocatorView::from)
                .collect(),
            note: receipt.note.clone(),
            consent_proof_claimed: receipt.consent_proof_claimed,
            quorum_proof_claimed: receipt.quorum_proof_claimed,
            identity_proof_claimed: receipt.identity_proof_claimed,
            legal_acceptance_claimed: receipt.legal_acceptance_claimed,
            legal_sufficiency_claimed: receipt.legal_sufficiency_claimed,
            external_validation_claimed: receipt.external_validation_claimed,
            automatic_approval_claimed: receipt.automatic_approval_claimed,
            authority_certified_claimed: receipt.authority_certified_claimed,
        }
    }
}

impl WrittenResolutionReviewReceiptView {
    fn redact_sensitive(&mut self) {
        self.reviewer = redacted();
        self.guardrail_acknowledgements.clear();
        self.note = None;
        for locator in &mut self.evidence {
            locator.redact_sensitive();
        }
    }
}

/// Wire view of the optional written-resolution evidence metadata block.
#[derive(Serialize)]
pub struct WrittenResolutionEvidenceView {
    pub status: WrittenResolutionEvidenceStatusView,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub checklist: Vec<WrittenResolutionEvidenceItemView>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub review_receipts: Vec<WrittenResolutionReviewReceiptView>,
    pub note: Option<String>,
}

impl WrittenResolutionEvidenceView {
    fn from_core(
        evidence: &WrittenResolutionEvidence,
        summary: WrittenResolutionEvidenceSummary,
    ) -> Self {
        WrittenResolutionEvidenceView {
            status: WrittenResolutionEvidenceStatusView::from_summary(summary),
            checklist: evidence
                .checklist
                .iter()
                .map(WrittenResolutionEvidenceItemView::from)
                .collect(),
            review_receipts: evidence
                .review_receipts
                .iter()
                .map(WrittenResolutionReviewReceiptView::from)
                .collect(),
            note: evidence.note.clone(),
        }
    }

    fn redact_sensitive(&mut self) {
        self.note = None;
        for item in &mut self.checklist {
            item.redact_sensitive();
        }
        for receipt in &mut self.review_receipts {
            receipt.redact_sensitive();
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

impl MemberStatementView {
    fn redact_sensitive(&mut self) {
        self.member = redacted();
        self.text = redacted();
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

impl DeliberationItemView {
    fn redact_sensitive(&mut self) {
        self.text = redacted();
        for statement in &mut self.statements {
            statement.redact_sensitive();
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

// --- Convening (G1) + attendance (G2) views + inputs (t61-E1) ----------------------------

/// Wire view of one dispatch recipient of a convening notice. Date leaves become the contract's
/// ISO wire strings.
#[derive(Serialize)]
pub struct ConveningRecipientView {
    pub name: String,
    pub contact: Option<String>,
    pub channel: Option<DispatchChannel>,
    pub reference: Option<String>,
    pub dispatched_at: Option<String>,
}

impl From<&ConveningRecipient> for ConveningRecipientView {
    fn from(r: &ConveningRecipient) -> Self {
        ConveningRecipientView {
            name: r.name.clone(),
            contact: r.contact.clone(),
            channel: r.channel,
            reference: r.reference.clone(),
            dispatched_at: r.dispatched_at.map(format_date),
        }
    }
}

impl ConveningRecipientView {
    fn redact_sensitive(&mut self) {
        self.name = redacted();
        self.contact = None;
        self.reference = None;
    }
}

/// Wire view of a second-call record (split `date` + `time` as `YYYY-MM-DD` / `HH:MM`).
#[derive(Serialize)]
pub struct SecondCallView {
    pub date: Option<String>,
    pub time: Option<String>,
    pub reduced_quorum: bool,
}

impl From<&SecondCall> for SecondCallView {
    fn from(s: &SecondCall) -> Self {
        SecondCallView {
            date: s.date.map(format_date),
            time: s.time.map(format_time),
            reduced_quorum: s.reduced_quorum,
        }
    }
}

/// Wire view of an act's convening/dispatch record (G1). Date leaves are ISO strings; enum leaves
/// keep their bare serde variant names.
#[derive(Serialize)]
pub struct ConveningView {
    pub convener: Option<String>,
    pub convener_capacity: Option<SignatoryCapacity>,
    pub dispatch_date: Option<String>,
    pub antecedence_days: Option<u16>,
    pub channel: Option<DispatchChannel>,
    pub evidence_reference: Option<String>,
    pub recipients: Vec<ConveningRecipientView>,
    pub second_call: Option<SecondCallView>,
}

impl From<&Convening> for ConveningView {
    fn from(c: &Convening) -> Self {
        ConveningView {
            convener: c.convener.clone(),
            convener_capacity: c.convener_capacity,
            dispatch_date: c.dispatch_date.map(format_date),
            antecedence_days: c.antecedence_days,
            channel: c.channel,
            evidence_reference: c.evidence_reference.clone(),
            recipients: c
                .recipients
                .iter()
                .map(ConveningRecipientView::from)
                .collect(),
            second_call: c.second_call.as_ref().map(SecondCallView::from),
        }
    }
}

impl ConveningView {
    fn redact_sensitive(&mut self) {
        self.convener = self.convener.as_ref().map(|_| redacted());
        self.evidence_reference = None;
        for recipient in &mut self.recipients {
            recipient.redact_sensitive();
        }
    }
}

/// Wire view of a no-convocatória basis. Carries no date fields, so it mirrors the core type; the
/// `basis` enum keeps its bare serde variant name.
#[derive(Serialize)]
pub struct ConveningWaiverView {
    pub basis: NoConveningBasis,
    pub grounds: Option<String>,
    pub all_agreed_to_meet: bool,
    pub all_agreed_to_agenda: bool,
    pub evidence_reference: Option<String>,
}

impl From<&ConveningWaiver> for ConveningWaiverView {
    fn from(w: &ConveningWaiver) -> Self {
        ConveningWaiverView {
            basis: w.basis,
            grounds: w.grounds.clone(),
            all_agreed_to_meet: w.all_agreed_to_meet,
            all_agreed_to_agenda: w.all_agreed_to_agenda,
            evidence_reference: w.evidence_reference.clone(),
        }
    }
}

impl ConveningWaiverView {
    fn redact_sensitive(&mut self) {
        // `grounds` is operator prose that can name the people who agreed; the evidence reference
        // is an archive locator. Both follow `ConveningView`'s redaction, while the structured
        // basis and the agreement flags stay visible — they carry no personal data and they are
        // the part a redacted view still needs to explain why there was no convocatória.
        self.grounds = self.grounds.as_ref().map(|_| redacted());
        self.evidence_reference = None;
    }
}

/// Wire view of one attendance row (G2). Carries no date fields, so it mirrors the core type.
#[derive(Serialize)]
pub struct AttendeeView {
    pub name: String,
    pub quality: SignatoryCapacity,
    /// Free-text qualidade; only ever `Some` alongside `quality: Other`.
    pub quality_note: Option<String>,
    pub presence: PresenceMode,
    pub represented_by: Option<String>,
    pub weight: Option<AttendanceWeight>,
}

impl From<&Attendee> for AttendeeView {
    fn from(a: &Attendee) -> Self {
        AttendeeView {
            name: a.name.clone(),
            quality: a.quality,
            quality_note: a.quality_note.clone(),
            presence: a.presence,
            represented_by: a.represented_by.clone(),
            weight: a.weight,
        }
    }
}

impl AttendeeView {
    fn redact_sensitive(&mut self) {
        self.name = redacted();
        self.represented_by = self.represented_by.as_ref().map(|_| redacted());
    }
}

/// Convening/dispatch record as accepted on a PATCH (input side: dates are ISO strings, parsed to
/// `time` in [`ConveningInput::into_core`], a malformed value being a `422`).
#[derive(Deserialize)]
pub struct ConveningInput {
    #[serde(default)]
    pub convener: Option<String>,
    #[serde(default)]
    pub convener_capacity: Option<SignatoryCapacity>,
    #[serde(default)]
    pub dispatch_date: Option<String>,
    #[serde(default)]
    pub antecedence_days: Option<u16>,
    #[serde(default)]
    pub channel: Option<DispatchChannel>,
    #[serde(default)]
    pub evidence_reference: Option<String>,
    #[serde(default)]
    pub recipients: Vec<ConveningRecipientInput>,
    #[serde(default)]
    pub second_call: Option<SecondCallInput>,
}

impl ConveningInput {
    /// Convert to the core [`Convening`], parsing every date/time leaf (`422` on a malformed value).
    pub fn into_core(self) -> Result<Convening, ApiError> {
        let dispatch_date = match self.dispatch_date {
            Some(s) => Some(parse_date(&s)?),
            None => None,
        };
        let mut recipients = Vec::with_capacity(self.recipients.len());
        for r in self.recipients {
            recipients.push(r.into_core()?);
        }
        let second_call = match self.second_call {
            Some(sc) => Some(sc.into_core()?),
            None => None,
        };
        Ok(Convening {
            convener: self.convener,
            convener_capacity: self.convener_capacity,
            dispatch_date,
            antecedence_days: self.antecedence_days,
            channel: self.channel,
            evidence_reference: self.evidence_reference,
            recipients,
            second_call,
        })
    }
}

/// A no-convocatória basis as accepted on a PATCH.
///
/// [`Self::into_core`] enforces the one thing that cannot be left to the rules engine: an `Other`
/// basis with no stated ground is content-free, and accepting it would let a caller persist a
/// "there was no convocatória" record that says nothing about why. `AssembleiaUniversal` may carry
/// grounds too (extra context is welcome); the agreement flags default to `false`, so a caller that
/// omits them is recorded as *not having captured* the agreement, never as having it.
#[derive(Deserialize)]
pub struct ConveningWaiverInput {
    pub basis: NoConveningBasis,
    #[serde(default)]
    pub grounds: Option<String>,
    #[serde(default)]
    pub all_agreed_to_meet: bool,
    #[serde(default)]
    pub all_agreed_to_agenda: bool,
    #[serde(default)]
    pub evidence_reference: Option<String>,
}

impl ConveningWaiverInput {
    /// Convert to the core [`ConveningWaiver`] (`422` when an `Other` basis states no ground).
    pub fn into_core(self) -> Result<ConveningWaiver, ApiError> {
        let grounds = self.grounds.filter(|g| !g.trim().is_empty());
        if self.basis == NoConveningBasis::Other && grounds.is_none() {
            return Err(ApiError::Unprocessable(
                "convening_waiver.grounds is required when basis is Other".to_owned(),
            ));
        }
        Ok(ConveningWaiver {
            basis: self.basis,
            grounds,
            all_agreed_to_meet: self.all_agreed_to_meet,
            all_agreed_to_agenda: self.all_agreed_to_agenda,
            evidence_reference: self
                .evidence_reference
                .filter(|r| !r.trim().is_empty()),
        })
    }
}

/// One dispatch recipient as accepted on a PATCH.
#[derive(Deserialize)]
pub struct ConveningRecipientInput {
    pub name: String,
    #[serde(default)]
    pub contact: Option<String>,
    #[serde(default)]
    pub channel: Option<DispatchChannel>,
    #[serde(default)]
    pub reference: Option<String>,
    #[serde(default)]
    pub dispatched_at: Option<String>,
}

impl ConveningRecipientInput {
    fn into_core(self) -> Result<ConveningRecipient, ApiError> {
        let dispatched_at = match self.dispatched_at {
            Some(s) => Some(parse_date(&s)?),
            None => None,
        };
        Ok(ConveningRecipient {
            name: self.name,
            contact: self.contact,
            channel: self.channel,
            reference: self.reference,
            dispatched_at,
        })
    }
}

/// Second-call record as accepted on a PATCH (split `date` + `time`).
#[derive(Deserialize)]
pub struct SecondCallInput {
    #[serde(default)]
    pub date: Option<String>,
    #[serde(default)]
    pub time: Option<String>,
    #[serde(default)]
    pub reduced_quorum: bool,
}

impl SecondCallInput {
    fn into_core(self) -> Result<SecondCall, ApiError> {
        let date = match self.date {
            Some(s) => Some(parse_date(&s)?),
            None => None,
        };
        let time = match self.time {
            Some(s) => Some(parse_time(&s)?),
            None => None,
        };
        Ok(SecondCall {
            date,
            time,
            reduced_quorum: self.reduced_quorum,
        })
    }
}

/// One attendance row as accepted on a PATCH. `into_core` validates permilage `≤ 1000` and that
/// `represented_by` is present **iff** the presence is `Represented` (else `422`).
#[derive(Deserialize)]
pub struct AttendeeInput {
    pub name: String,
    pub quality: SignatoryCapacity,
    #[serde(default)]
    pub quality_note: Option<String>,
    pub presence: PresenceMode,
    #[serde(default)]
    pub represented_by: Option<String>,
    #[serde(default)]
    pub weight: Option<AttendanceWeight>,
}

impl AttendeeInput {
    /// Convert to the core [`Attendee`], validating the weight and the represented/proxy invariant.
    pub fn into_core(self) -> Result<Attendee, ApiError> {
        if let Some(AttendanceWeight::Permilage(p @ 1001..)) = self.weight {
            return Err(ApiError::Unprocessable(format!(
                "attendee {:?}: permilage {p} exceeds 1000",
                self.name
            )));
        }
        // The free-text qualidade is an escape hatch, not a second name for a capacity that is
        // already in the vocabulary: it is accepted only alongside `Other`, so that a report
        // grouping by `quality` can never be split by prose. Blank/whitespace is dropped rather
        // than stored, and `Other` with nothing to say is allowed (the ata simply omits the
        // clause) rather than being a 422 the operator cannot act on mid-draft.
        let note = self
            .quality_note
            .as_deref()
            .map(str::trim)
            .filter(|n| !n.is_empty())
            .map(str::to_owned);
        if note.is_some() && self.quality != SignatoryCapacity::Other {
            return Err(ApiError::Unprocessable(format!(
                "attendee {:?}: quality_note is only accepted when quality is Other",
                self.name
            )));
        }

        let is_represented = matches!(self.presence, PresenceMode::Represented);
        if is_represented != self.represented_by.is_some() {
            return Err(ApiError::Unprocessable(format!(
                "attendee {:?}: represented_by must be present iff presence is Represented",
                self.name
            )));
        }
        Ok(Attendee {
            name: self.name,
            quality: self.quality,
            quality_note: note,
            presence: self.presence,
            represented_by: self.represented_by,
            weight: self.weight,
        })
    }
}

/// Body of `POST /v1/acts/{id}/convening/dispatch`. All fields optional except `dispatched_at`;
/// `recipients` (names) omitted ⇒ every recipient is stamped.
#[derive(Deserialize)]
pub struct DispatchConvening {
    #[serde(default = "default_actor")]
    pub actor: String,
    pub dispatched_at: String,
    #[serde(default)]
    pub channel: Option<DispatchChannel>,
    #[serde(default)]
    pub reference: Option<String>,
    #[serde(default)]
    pub recipients: Option<Vec<String>>,
}

/// Response view of a first-class act follow-up/task. These rows are deliberately outside `ActView`
/// so sealed act JSON remains immutable.
#[derive(Serialize)]
pub struct FollowUpView {
    pub id: String,
    pub act_id: String,
    pub agenda_number: Option<u32>,
    pub deliberation_index: Option<u32>,
    pub title: String,
    pub detail: Option<String>,
    pub due_date: Option<String>,
    pub assignee: Option<String>,
    pub assignee_display: Option<String>,
    pub status: StoredFollowUpStatus,
    pub created_at: String,
    pub created_by: String,
    pub completed_at: Option<String>,
    pub completed_by: Option<String>,
}

impl From<&StoredFollowUp> for FollowUpView {
    fn from(f: &StoredFollowUp) -> Self {
        FollowUpView {
            id: f.id.clone(),
            act_id: f.act_id.to_string(),
            agenda_number: f.agenda_number,
            deliberation_index: f.deliberation_index,
            title: f.title.clone(),
            detail: f.detail.clone(),
            due_date: f.due_date.map(format_date),
            assignee: f.assignee.clone(),
            assignee_display: f.assignee_display.clone(),
            status: f.status,
            created_at: f.created_at.format(&Rfc3339).unwrap_or_default(),
            created_by: f.created_by.clone(),
            completed_at: f
                .completed_at
                .map(|t| t.format(&Rfc3339).unwrap_or_default()),
            completed_by: f.completed_by.clone(),
        }
    }
}

/// Body of `POST /v1/acts/{id}/follow-ups`.
#[derive(Deserialize)]
pub struct CreateFollowUp {
    #[serde(default = "default_actor")]
    pub actor: String,
    #[serde(default)]
    pub agenda_number: Option<u32>,
    #[serde(default)]
    pub deliberation_index: Option<u32>,
    pub title: String,
    #[serde(default)]
    pub detail: Option<String>,
    #[serde(default)]
    pub due_date: Option<String>,
    #[serde(default)]
    pub assignee: Option<String>,
    #[serde(default)]
    pub assignee_display: Option<String>,
}

/// Body of `PATCH /v1/follow-ups/{id}`. Nullable fields use [`double_option`] semantics.
#[derive(Deserialize)]
pub struct PatchFollowUp {
    #[serde(default = "default_actor")]
    pub actor: String,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default, deserialize_with = "double_option")]
    pub detail: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option")]
    pub due_date: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option")]
    pub assignee: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option")]
    pub assignee_display: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option")]
    pub agenda_number: Option<Option<u32>>,
    #[serde(default, deserialize_with = "double_option")]
    pub deliberation_index: Option<Option<u32>>,
}

/// Body of `POST /v1/follow-ups/{id}/complete`.
#[derive(Deserialize)]
pub struct CompleteFollowUp {
    #[serde(default = "default_actor")]
    pub actor: String,
}

impl Default for CompleteFollowUp {
    fn default() -> Self {
        Self {
            actor: default_actor(),
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
    /// Optional written-resolution evidence checklist metadata. The nested status is derived and
    /// bounded to workflow evidence presence only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub written_resolution_evidence: Option<WrittenResolutionEvidenceView>,
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
    /// Structured rule-pack/profile evidence recorded when the act was sealed (LEG-06/WFL-22).
    /// Absent on unsealed acts and old sealed rows that predate this metadata slice.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seal_metadata: Option<SealMetadataView>,
    pub retifies: Option<String>,
    /// The convening/dispatch record (G1), when set. **Skip-serialized when absent** (t61-E1
    /// drift-safe): an act without a convening emits **no** `convening` key, so response fixtures for
    /// convening-less acts stay byte-identical and the web contract test is not forced to change.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub convening: Option<ConveningView>,
    /// The recorded basis for holding the meeting **without** a convocatória, when there was one.
    /// Skip-serialized when absent, so responses for the overwhelmingly common convened act are
    /// byte-identical to what they were before this field existed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub convening_waiver: Option<ConveningWaiverView>,
    /// The structured attendance rows (G2). **Skip-serialized when empty** (t61-E1 drift-safe): an
    /// act with no attendees emits **no** `attendees` key.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub attendees: Vec<AttendeeView>,
    /// Non-authoritative AI provenance. Omitted when absent so existing act responses do not churn.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ai_provenance: Option<AiProvenanceView>,
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
            written_resolution_evidence: a.written_resolution_evidence.as_ref().map(|evidence| {
                WrittenResolutionEvidenceView::from_core(
                    evidence,
                    written_resolution_evidence_summary(a),
                )
            }),
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
            seal_metadata: a.seal_metadata.as_ref().map(SealMetadataView::from),
            retifies: a.retifies.map(|r| r.to_string()),
            convening: a.convening.as_ref().map(ConveningView::from),
            convening_waiver: a.convening_waiver.as_ref().map(ConveningWaiverView::from),
            attendees: a.attendees.iter().map(AttendeeView::from).collect(),
            ai_provenance: a.ai_provenance.as_ref().map(AiProvenanceView::from),
        }
    }
}

impl ActView {
    /// Build an act read view under the selected privacy policy.
    #[must_use]
    pub(crate) fn build(a: &Act, redaction: ReadRedaction) -> Self {
        let mut view = ActView::from(a);
        if redaction.is_guest() {
            view.redact_sensitive();
        }
        view
    }

    fn redact_sensitive(&mut self) {
        self.title = redacted();
        self.place = self.place.as_ref().map(|_| redacted());
        self.mesa.redact_sensitive();
        for item in &mut self.agenda {
            item.redact_sensitive();
        }
        self.attendance_reference = self.attendance_reference.as_ref().map(|_| redacted());
        for document in &mut self.referenced_documents {
            document.redact_sensitive();
        }
        if let Some(evidence) = &mut self.written_resolution_evidence {
            evidence.redact_sensitive();
        }
        self.deliberations = redacted();
        for item in &mut self.deliberation_items {
            item.redact_sensitive();
        }
        self.telematic_evidence = self.telematic_evidence.as_ref().map(|_| redacted());
        for attachment in &mut self.attachments {
            attachment.redact_sensitive();
        }
        for signatory in &mut self.signatories {
            signatory.redact_sensitive();
        }
        if let Some(metadata) = &mut self.seal_metadata {
            metadata.redact_sensitive();
        }
        if let Some(convening) = &mut self.convening {
            convening.redact_sensitive();
        }
        if let Some(waiver) = &mut self.convening_waiver {
            waiver.redact_sensitive();
        }
        for attendee in &mut self.attendees {
            attendee.redact_sensitive();
        }
        if let Some(provenance) = &mut self.ai_provenance {
            provenance.redact_sensitive();
        }
    }
}

/// Wire view of non-authoritative AI provenance. Human verification means human review only.
#[derive(Serialize)]
pub struct AiProvenanceView {
    pub source: String,
    pub tool: Option<String>,
    pub statement_source: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub statement_sources: Vec<AiStatementSourceView>,
    pub human_verification: AiHumanVerificationView,
}

impl From<&AiProvenance> for AiProvenanceView {
    fn from(p: &AiProvenance) -> Self {
        AiProvenanceView {
            source: p.source.clone(),
            tool: p.tool.clone(),
            statement_source: p.statement_source.clone(),
            statement_sources: p
                .statement_sources
                .iter()
                .map(AiStatementSourceView::from)
                .collect(),
            human_verification: AiHumanVerificationView::from(&p.human_verification),
        }
    }
}

impl AiProvenanceView {
    fn redact_sensitive(&mut self) {
        self.statement_source = self.statement_source.as_ref().map(|_| redacted());
        for source in &mut self.statement_sources {
            source.redact_sensitive();
        }
        self.human_verification.redact_sensitive();
    }
}

/// Wire view of a statement-level AI source breadcrumb. Flags are conservative: these rows do not
/// certify human verification, authoritative source status, or legal validity.
#[derive(Serialize)]
pub struct AiStatementSourceView {
    pub path: String,
    pub source_type: String,
    pub source_label: String,
    pub human_verified: bool,
    pub human_verification_status: AiHumanVerificationStatus,
    pub authoritative_source_claimed: bool,
    pub legal_validity_claimed: bool,
}

impl From<&AiStatementSource> for AiStatementSourceView {
    fn from(source: &AiStatementSource) -> Self {
        AiStatementSourceView {
            path: source.path.clone(),
            source_type: source.source_type.clone(),
            source_label: source.source_label.clone(),
            human_verified: false,
            human_verification_status: AiHumanVerificationStatus::Pending,
            authoritative_source_claimed: false,
            legal_validity_claimed: false,
        }
    }
}

impl AiStatementSourceView {
    fn redact_sensitive(&mut self) {
        self.source_label = redacted();
    }
}

/// Wire view of AI human-review evidence. `Accepted` is not a legal-validity claim.
#[derive(Serialize)]
pub struct AiHumanVerificationView {
    pub status: AiHumanVerificationStatus,
    pub actor: Option<String>,
    pub reviewed_at: Option<String>,
    pub note: Option<String>,
}

impl From<&AiHumanVerification> for AiHumanVerificationView {
    fn from(v: &AiHumanVerification) -> Self {
        AiHumanVerificationView {
            status: v.status,
            actor: v.actor.clone(),
            reviewed_at: v
                .reviewed_at
                .map(|t| t.format(&Rfc3339).unwrap_or_default()),
            note: v.note.clone(),
        }
    }
}

impl AiHumanVerificationView {
    fn redact_sensitive(&mut self) {
        self.actor = self.actor.as_ref().map(|_| redacted());
        self.note = self.note.as_ref().map(|_| redacted());
    }
}

/// Body of `POST /v1/acts` (draft a new ata, WFL-14).
#[derive(Deserialize)]
pub struct DraftAct {
    pub book_id: Uuid,
    pub title: String,
    pub channel: MeetingChannel,
    #[serde(default)]
    pub ai_provenance: Option<AiProvenanceInput>,
    #[serde(default)]
    pub convening: Option<ConveningInput>,
    /// Recorded when the meeting was held with **no** convocatória, naming the lawful basis.
    #[serde(default)]
    pub convening_waiver: Option<ConveningWaiverInput>,
    pub retifies: Option<Uuid>,
    #[serde(default = "default_actor")]
    pub actor: String,
}

/// Non-authoritative AI provenance accepted when drafting. Human verification is intentionally not
/// accepted here; it is recorded only by the dedicated review route.
#[derive(Deserialize)]
pub struct AiProvenanceInput {
    pub source: String,
    #[serde(default)]
    pub tool: Option<String>,
    #[serde(default)]
    pub statement_source: Option<String>,
    #[serde(default)]
    pub statement_sources: Vec<AiStatementSourceInput>,
}

impl AiProvenanceInput {
    pub fn into_core(self) -> Result<AiProvenance, ApiError> {
        if self.source.trim().is_empty() {
            return Err(ApiError::Unprocessable(
                "ai_provenance.source must not be empty".to_owned(),
            ));
        }
        let statement_sources = self
            .statement_sources
            .into_iter()
            .map(AiStatementSourceInput::into_core)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(AiProvenance {
            source: self.source,
            tool: self.tool,
            statement_source: self.statement_source,
            statement_sources,
            human_verification: Default::default(),
        })
    }
}

/// Statement-level AI provenance accepted on draft creation. Unsafe truthy flags are ignored.
#[derive(Deserialize)]
pub struct AiStatementSourceInput {
    pub path: String,
    pub source_type: String,
    pub source_label: String,
    #[serde(default)]
    pub human_verified: bool,
    #[serde(default)]
    pub human_verification_status: AiHumanVerificationStatus,
    #[serde(default)]
    pub authoritative_source_claimed: bool,
    #[serde(default)]
    pub legal_validity_claimed: bool,
}

impl AiStatementSourceInput {
    fn into_core(self) -> Result<AiStatementSource, ApiError> {
        let ignored_client_claims = (
            self.human_verified,
            self.human_verification_status,
            self.authoritative_source_claimed,
            self.legal_validity_claimed,
        );
        let _ = ignored_client_claims;
        if self.path.trim().is_empty() {
            return Err(ApiError::Unprocessable(
                "ai_provenance.statement_sources[].path must not be empty".to_owned(),
            ));
        }
        if self.source_type.trim().is_empty() {
            return Err(ApiError::Unprocessable(
                "ai_provenance.statement_sources[].source_type must not be empty".to_owned(),
            ));
        }
        if self.source_label.trim().is_empty() {
            return Err(ApiError::Unprocessable(
                "ai_provenance.statement_sources[].source_label must not be empty".to_owned(),
            ));
        }
        Ok(AiStatementSource {
            path: self.path,
            source_type: self.source_type,
            source_label: self.source_label,
            human_verified: false,
            human_verification_status: AiHumanVerificationStatus::Pending,
            authoritative_source_claimed: false,
            legal_validity_claimed: false,
        })
    }
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
    #[serde(default)]
    pub email: Option<String>,
    pub capacity: SignatoryCapacity,
    #[serde(default)]
    pub signed: bool,
    /// A condómino's *permilagem* (millésimos, 0..=1000), when recorded (ENT-D6 / R6). Absent ⇒
    /// `None`.
    #[serde(default)]
    pub permilage: Option<u16>,
}

impl SignatoryInput {
    pub fn into_core(self) -> Result<SignatorySlot, ApiError> {
        Ok(SignatorySlot {
            name: self.name,
            email: crate::email::normalize_optional_email(self.email, "signatory.email")?,
            capacity: self.capacity,
            signed: self.signed,
            permilage: self.permilage,
        })
    }
}

/// Written-resolution evidence metadata as accepted on PATCH. The stored model remains
/// evidence-oriented; status is derived server-side.
#[derive(Deserialize)]
pub struct WrittenResolutionEvidenceInput {
    #[serde(default)]
    pub checklist: Vec<WrittenResolutionEvidenceItemInput>,
    #[serde(default)]
    pub review_receipts: Vec<WrittenResolutionReviewReceiptInput>,
    #[serde(default)]
    pub note: Option<String>,
}

impl WrittenResolutionEvidenceInput {
    pub fn into_core(self) -> Result<WrittenResolutionEvidence, ApiError> {
        let mut checklist = Vec::with_capacity(self.checklist.len());
        for item in self.checklist {
            checklist.push(item.into_core()?);
        }
        let mut review_receipts = Vec::with_capacity(self.review_receipts.len());
        for receipt in self.review_receipts {
            review_receipts.push(receipt.into_core()?);
        }
        Ok(WrittenResolutionEvidence {
            checklist,
            review_receipts,
            note: self.note,
        })
    }
}

/// One written-resolution evidence checklist item as accepted on PATCH.
#[derive(Deserialize)]
pub struct WrittenResolutionEvidenceItemInput {
    pub label: String,
    #[serde(default)]
    pub reference: Option<String>,
    #[serde(default)]
    pub digest: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}

impl WrittenResolutionEvidenceItemInput {
    fn into_core(self) -> Result<WrittenResolutionEvidenceItem, ApiError> {
        let digest = match self.digest {
            Some(s) => Some(parse_hex32(&s).ok_or_else(|| {
                ApiError::Unprocessable(format!(
                    "invalid written_resolution_evidence checklist digest {s:?}"
                ))
            })?),
            None => None,
        };
        Ok(WrittenResolutionEvidenceItem {
            label: self.label,
            reference: self.reference,
            digest,
            note: self.note,
        })
    }
}

/// One local written-resolution evidence review receipt accepted on PATCH.
#[derive(Deserialize)]
pub struct WrittenResolutionReviewReceiptInput {
    pub reviewer: String,
    pub reviewed_at: String,
    pub status: WrittenResolutionReviewStatus,
    #[serde(default)]
    pub guardrail_acknowledgements: Vec<String>,
    #[serde(default)]
    pub evidence: Vec<WrittenResolutionReviewEvidenceLocatorInput>,
    #[serde(default)]
    pub note: Option<String>,
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

impl WrittenResolutionReviewReceiptInput {
    fn into_core(self) -> Result<WrittenResolutionReviewReceipt, ApiError> {
        reject_true_written_resolution_claim_flags(
            self.consent_proof_claimed,
            self.quorum_proof_claimed,
            self.identity_proof_claimed,
            self.legal_acceptance_claimed,
            self.legal_sufficiency_claimed,
            self.external_validation_claimed,
            self.automatic_approval_claimed,
            self.authority_certified_claimed,
        )?;

        let reviewer = non_empty_written_resolution_field(self.reviewer, "reviewer")?;
        let reviewed_at =
            OffsetDateTime::parse(self.reviewed_at.trim(), &Rfc3339).map_err(|_| {
                ApiError::Unprocessable(format!(
                    "invalid written_resolution_evidence review_receipts reviewed_at {:?}",
                    self.reviewed_at
                ))
            })?;
        let guardrail_acknowledgements = non_empty_written_resolution_list(
            self.guardrail_acknowledgements,
            "guardrail_acknowledgements",
        )?;
        if self.evidence.is_empty() {
            return Err(ApiError::Unprocessable(
                "written_resolution_evidence review_receipts evidence must not be empty".to_owned(),
            ));
        }
        let mut evidence = Vec::with_capacity(self.evidence.len());
        for locator in self.evidence {
            evidence.push(locator.into_core()?);
        }

        Ok(WrittenResolutionReviewReceipt {
            reviewer,
            reviewed_at,
            status: self.status,
            guardrail_acknowledgements,
            evidence,
            note: self.note,
            consent_proof_claimed: false,
            quorum_proof_claimed: false,
            identity_proof_claimed: false,
            legal_acceptance_claimed: false,
            legal_sufficiency_claimed: false,
            external_validation_claimed: false,
            automatic_approval_claimed: false,
            authority_certified_claimed: false,
        })
    }
}

/// One reviewed evidence locator accepted on PATCH.
#[derive(Deserialize)]
pub struct WrittenResolutionReviewEvidenceLocatorInput {
    pub label: String,
    #[serde(default)]
    pub locator: Option<String>,
    #[serde(default)]
    pub digest: Option<String>,
}

impl WrittenResolutionReviewEvidenceLocatorInput {
    fn into_core(self) -> Result<WrittenResolutionReviewEvidenceLocator, ApiError> {
        let label = non_empty_written_resolution_field(self.label, "evidence.label")?;
        let locator = self.locator.and_then(|locator| {
            let trimmed = locator.trim().to_owned();
            (!trimmed.is_empty()).then_some(trimmed)
        });
        let digest = match self.digest {
            Some(s) => Some(parse_hex32(&s).ok_or_else(|| {
                ApiError::Unprocessable(format!(
                    "invalid written_resolution_evidence review_receipts evidence digest {s:?}"
                ))
            })?),
            None => None,
        };
        if locator.is_none() && digest.is_none() {
            return Err(ApiError::Unprocessable(
                "written_resolution_evidence review_receipts evidence requires locator or digest"
                    .to_owned(),
            ));
        }
        Ok(WrittenResolutionReviewEvidenceLocator {
            label,
            locator,
            digest,
        })
    }
}

fn non_empty_written_resolution_field(value: String, field: &str) -> Result<String, ApiError> {
    let trimmed = value.trim().to_owned();
    if trimmed.is_empty() {
        return Err(ApiError::Unprocessable(format!(
            "written_resolution_evidence review_receipts {field} must not be empty"
        )));
    }
    Ok(trimmed)
}

fn non_empty_written_resolution_list(
    values: Vec<String>,
    field: &str,
) -> Result<Vec<String>, ApiError> {
    if values.is_empty() {
        return Err(ApiError::Unprocessable(format!(
            "written_resolution_evidence review_receipts {field} must not be empty"
        )));
    }
    let mut out = Vec::with_capacity(values.len());
    for value in values {
        out.push(non_empty_written_resolution_field(value, field)?);
    }
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
fn reject_true_written_resolution_claim_flags(
    consent_proof_claimed: bool,
    quorum_proof_claimed: bool,
    identity_proof_claimed: bool,
    legal_acceptance_claimed: bool,
    legal_sufficiency_claimed: bool,
    external_validation_claimed: bool,
    automatic_approval_claimed: bool,
    authority_certified_claimed: bool,
) -> Result<(), ApiError> {
    let flags = [
        ("consent_proof_claimed", consent_proof_claimed),
        ("quorum_proof_claimed", quorum_proof_claimed),
        ("identity_proof_claimed", identity_proof_claimed),
        ("legal_acceptance_claimed", legal_acceptance_claimed),
        ("legal_sufficiency_claimed", legal_sufficiency_claimed),
        ("external_validation_claimed", external_validation_claimed),
        ("automatic_approval_claimed", automatic_approval_claimed),
        ("authority_certified_claimed", authority_certified_claimed),
    ];
    if let Some((field, _)) = flags.iter().find(|(_, value)| *value) {
        return Err(ApiError::Unprocessable(format!(
            "written_resolution_evidence review_receipts {field} must be false"
        )));
    }
    Ok(())
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
    /// Written-resolution evidence checklist metadata. [`double_option`] semantics: absent ⇒
    /// leave untouched, explicit `null` ⇒ clear, a value ⇒ replace.
    #[serde(default, deserialize_with = "double_option")]
    pub written_resolution_evidence: Option<Option<WrittenResolutionEvidenceInput>>,
    pub deliberations: Option<String>,
    /// Replace the structured deliberations list when present.
    pub deliberation_items: Option<Vec<DeliberationItemView>>,
    #[serde(default, deserialize_with = "double_option")]
    pub telematic_evidence: Option<Option<String>>,
    pub attachments: Option<Vec<AttachmentInput>>,
    pub signatories: Option<Vec<SignatoryInput>>,
    /// The convening/dispatch record (G1). [`double_option`] semantics: absent ⇒ leave untouched,
    /// explicit `null` ⇒ clear to `None`, a value ⇒ replace. Dates parse via [`parse_date`]/
    /// [`parse_time`] (malformed ⇒ `422`).
    #[serde(default, deserialize_with = "double_option")]
    pub convening: Option<Option<ConveningInput>>,
    /// The no-convocatória basis. Same [`double_option`] semantics as `convening`: absent ⇒ leave
    /// untouched, explicit `null` ⇒ clear (the act *was* convened after all), a value ⇒ replace.
    /// An `Other` basis with no stated ground is a `422` ([`ConveningWaiverInput::into_core`]).
    #[serde(default, deserialize_with = "double_option")]
    pub convening_waiver: Option<Option<ConveningWaiverInput>>,
    /// The structured attendance rows (G2). Present ⇒ replace wholesale (`[]` clears); absent ⇒
    /// leave untouched. Each row is validated in [`AttendeeInput::into_core`] (permilage/proxy).
    pub attendees: Option<Vec<AttendeeInput>>,
}

/// Body of `POST /v1/acts/{id}/advance`.
#[derive(Deserialize)]
pub struct AdvanceAct {
    pub to: ActState,
    #[serde(default = "default_actor")]
    pub actor: String,
    /// Optional versioned Ata template selected when entering `Signing`. The canonical signing
    /// snapshot is created exactly once during that transition; later seal requests cannot replace
    /// it with another template.
    #[serde(default)]
    pub template_id: Option<String>,
}

/// Body of `POST /v1/acts/{id}/reopen`.
#[derive(Deserialize)]
pub struct ReopenAct {
    #[serde(default = "default_actor")]
    pub actor: String,
    /// Why the act is being pulled back out of signature collection. Required and non-empty: a
    /// state regression on an evidentiary object has to be reconstructable from the ledger alone.
    pub reason: String,
}

/// The canonical signing snapshot a reopen retired.
#[derive(Debug, Serialize, Clone)]
pub struct SupersededSigningSnapshotView {
    pub document_id: String,
    pub pdf_digest: String,
    pub actor: String,
    pub superseded_at: String,
    pub reason: String,
}

impl SupersededSigningSnapshotView {
    #[must_use]
    pub fn from_core(snapshot: &SupersededSigningSnapshot) -> Self {
        SupersededSigningSnapshotView {
            document_id: snapshot.document_id.clone(),
            pdf_digest: snapshot.pdf_digest.clone(),
            actor: snapshot.actor.clone(),
            superseded_at: snapshot
                .superseded_at
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            reason: snapshot.reason.clone(),
        }
    }
}

/// Response of `POST /v1/acts/{id}/reopen`.
#[derive(Serialize)]
pub struct ReopenActResponse {
    pub act: ActView,
    /// State the act was reopened from (always `Signing`).
    pub from: ActState,
    /// State it was reopened into (always `TextApproved`).
    pub to: ActState,
    /// Sequence number of the `act.reopened` ledger event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_seq: Option<u64>,
    /// The retired canonical snapshot, when the act had one. It is no longer resolvable as the
    /// act's signing document; its bytes stay in the store as evidence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub superseded_signing_snapshot: Option<SupersededSigningSnapshotView>,
    /// The frozen page count (F15) the reopen released, when one had been captured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub released_page_count: Option<u32>,
}

/// Body of `POST /v1/acts/{id}/human-verification`.
#[derive(Deserialize)]
pub struct VerifyAiHumanReview {
    pub decision: HumanVerificationDecision,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default = "default_actor")]
    pub actor: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HumanVerificationDecision {
    Accept,
    Reject,
}

const MANUAL_SIGNATURE_ORIGINAL_REFERENCE_MAX_CHARS: usize = 512;
const MANUAL_SIGNATURE_ORIGINAL_CUSTODIAN_MAX_CHARS: usize = 256;
const MANUAL_SIGNATURE_ORIGINAL_NOTE_MAX_CHARS: usize = 2000;

/// Operator-supplied WFL-23 reference to the signed manual original kept outside Chancela.
#[derive(Deserialize)]
pub struct ManualSignatureOriginalReferenceInput {
    pub storage_reference: String,
    #[serde(default)]
    pub custodian: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}

impl ManualSignatureOriginalReferenceInput {
    pub(crate) fn into_core(self) -> Result<ManualSignatureOriginalReference, ApiError> {
        Ok(ManualSignatureOriginalReference {
            storage_reference: required_manual_signature_reference_text(
                self.storage_reference,
                "storage_reference",
                MANUAL_SIGNATURE_ORIGINAL_REFERENCE_MAX_CHARS,
            )?,
            custodian: optional_manual_signature_reference_text(
                self.custodian,
                "custodian",
                MANUAL_SIGNATURE_ORIGINAL_CUSTODIAN_MAX_CHARS,
            )?,
            note: optional_manual_signature_reference_text(
                self.note,
                "note",
                MANUAL_SIGNATURE_ORIGINAL_NOTE_MAX_CHARS,
            )?,
        })
    }
}

fn required_manual_signature_reference_text(
    value: String,
    field: &str,
    max_chars: usize,
) -> Result<String, ApiError> {
    let trimmed = value.trim().to_owned();
    if trimmed.is_empty() {
        return Err(ApiError::Unprocessable(format!(
            "manual_signature_original_reference.{field} must not be empty"
        )));
    }
    validate_manual_signature_reference_text(&trimmed, field, max_chars)?;
    Ok(trimmed)
}

fn optional_manual_signature_reference_text(
    value: Option<String>,
    field: &str,
    max_chars: usize,
) -> Result<Option<String>, ApiError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let trimmed = value.trim().to_owned();
    if trimmed.is_empty() {
        return Ok(None);
    }
    validate_manual_signature_reference_text(&trimmed, field, max_chars)?;
    Ok(Some(trimmed))
}

fn validate_manual_signature_reference_text(
    value: &str,
    field: &str,
    max_chars: usize,
) -> Result<(), ApiError> {
    if value.chars().count() > max_chars {
        return Err(ApiError::Unprocessable(format!(
            "manual_signature_original_reference.{field} must be at most {max_chars} characters"
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(ApiError::Unprocessable(format!(
            "manual_signature_original_reference.{field} must not contain control characters"
        )));
    }
    Ok(())
}

/// Body of `POST /v1/acts/{id}/seal`.
#[derive(Deserialize)]
pub struct SealAct {
    #[serde(default = "default_actor")]
    pub actor: String,
    #[serde(default)]
    pub acknowledge_warnings: bool,
    /// WFL-23 manual-signature custody/location metadata supplied by the operator at sealing.
    /// This is immutable reference metadata only; it carries no validation/certification claim.
    #[serde(default)]
    pub manual_signature_original_reference: Option<ManualSignatureOriginalReferenceInput>,
    /// Optional ata-subtype assertion retained for wire compatibility. The canonical Ata is now
    /// selected and generated when the act enters `Signing`; when this field is present at seal it
    /// must match that frozen snapshot and never causes regeneration or replacement.
    #[serde(default)]
    pub template_id: Option<String>,
}

impl Default for SealAct {
    fn default() -> Self {
        SealAct {
            actor: default_actor(),
            acknowledge_warnings: false,
            manual_signature_original_reference: None,
            template_id: None,
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
    /// Derived technical status for written-resolution evidence capture. This is a workflow
    /// evidence-presence status only, not a legal-sufficiency claim.
    pub written_resolution_evidence_status: WrittenResolutionEvidenceStatusView,
    /// Convening-antecedence advisories — **WARN-only, never blocking** (does not feed
    /// `seal_allowed`). Statute advisories compare `entity.statute.convocation_notice_days` with
    /// the act's actual `convening.antecedence_days` and also warn when the actual notice is
    /// missing; family legal-threshold advisories stay dormant while their threshold is
    /// `[a definir]`. **Additive + skip-serialized when empty** (drift-safe): existing compliance
    /// responses are unchanged.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub convening_advisories: Vec<ConveningAdvisory>,
}

/// One convening-antecedence advisory (t61-E1). Non-blocking guidance surfaced on the compliance
/// report; `severity` is the bare string (mirroring [`IssueView`]).
#[derive(Debug, Serialize, Clone)]
pub struct ConveningAdvisory {
    pub code: String,
    pub severity: String,
    pub message: String,
    pub threshold_id: String,
    pub actual_days: Option<u16>,
    pub minimum_days: Option<u16>,
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
    /// Canonical chain ids this event belongs to, including the implicit `global` chain.
    pub chains: Vec<String>,
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
            chains: ledger_event_chains(e),
            attestation: None,
        }
    }
}

pub(crate) fn ledger_event_chains(e: &Event) -> Vec<String> {
    std::iter::once("global".to_owned())
        .chain(e.links.iter().map(|link| link.chain.canonical()))
        .collect()
}

/// Query for `GET /v1/ledger/events`: optional chain, substring `scope` filter, and last-N `limit`.
#[derive(Deserialize)]
pub struct LedgerQuery {
    pub q: Option<String>,
    pub chain: Option<String>,
    pub scope: Option<String>,
    #[serde(
        default,
        deserialize_with = "crate::ledger_filter::deserialize_kind_query"
    )]
    pub kind: Vec<String>,
    pub actor: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
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
    /// Failed durable connector sync jobs visible to this globally authorized dashboard reader.
    pub failed_sync_jobs: usize,
    /// Queued/running/retryable durable backup jobs visible to this globally authorized reader.
    pub pending_backup_jobs: usize,
    pub ledger_length: u64,
    pub ledger_valid: bool,
    pub current_work: DashboardCurrentWork,
    pub alerts: Vec<DashboardAlert>,
    pub reminders: Vec<DashboardReminder>,
    pub recent_events: Vec<LedgerEventView>,
}

/// Current mutable work surfaced by the dashboard. This is additive to the legacy summary counts:
/// `act_counts_by_state` names the exact [`ActState`] variants, and `open_books` carries only safe
/// already-stored identifiers/metadata.
#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct DashboardCurrentWork {
    pub open_books: Vec<DashboardOpenBook>,
    pub act_counts_by_state: DashboardActStateCounts,
}

/// Count of acts in each exact lifecycle state. Field names are pinned to the core enum variant
/// names so consumers do not need to reverse-map the legacy aggregate counters.
#[derive(Debug, Serialize, Clone, Default, PartialEq, Eq)]
pub struct DashboardActStateCounts {
    #[serde(rename = "Draft")]
    pub draft: usize,
    #[serde(rename = "Review")]
    pub review: usize,
    #[serde(rename = "Convened")]
    pub convened: usize,
    #[serde(rename = "Deliberated")]
    pub deliberated: usize,
    #[serde(rename = "TextApproved")]
    pub text_approved: usize,
    #[serde(rename = "Signing")]
    pub signing: usize,
    #[serde(rename = "Sealed")]
    pub sealed: usize,
    #[serde(rename = "Archived")]
    pub archived: usize,
}

/// One open book row for the current-work dashboard panel.
#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct DashboardOpenBook {
    pub book_id: String,
    pub entity_id: String,
    pub entity_name: Option<String>,
    pub kind: BookKind,
    pub purpose: Option<String>,
    pub opening_date: Option<String>,
    pub last_ata_number: u64,
    pub total_acts: usize,
    pub open_acts: usize,
    pub next_ata_number: u64,
    pub links: DashboardTargetLinks,
}

/// One actionable dashboard alert. Alerts are routing/review signals only: `label` is intentionally
/// limited to advisory/review-required and messages avoid unsupported legal conclusions.
#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct DashboardAlert {
    pub code: String,
    pub label: String,
    pub severity: String,
    pub category: String,
    pub message: String,
    pub params: BTreeMap<String, String>,
    pub target: DashboardAlertTarget,
    pub source: Option<String>,
    pub law_refs: Vec<DashboardLawReference>,
    pub action: Option<DashboardAction>,
    pub recommended_next_steps: Vec<String>,
    pub i18n: Option<DashboardI18n>,
}

/// Safe target ids for a dashboard alert.
#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct DashboardAlertTarget {
    pub entity_id: Option<String>,
    pub book_id: Option<String>,
    pub act_id: Option<String>,
    pub links: DashboardTargetLinks,
}

/// API links a client can follow for the target, when such a target exists.
#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct DashboardTargetLinks {
    pub entity: Option<String>,
    pub book: Option<String>,
    pub act: Option<String>,
    pub ledger: Option<String>,
}

/// One law-corpus article reference attached to a dashboard actionable.
///
/// `verification` carries the corpus authenticity tier on the wire as `"Verified"` /
/// `"automated_review"` / `"Pending"` (the [`chancela_law::Verification`] serde value). An
/// `"automated_review"` reference is authentic vendored text reviewed by an automated process but
/// **not** human-legally-approved; `review_method` (e.g. `"automated-capture"`) and `review_note`
/// (the standing pt-PT caveat) are populated for that tier so the client can badge it honestly and
/// show the caveat tooltip. Both are `null` for `Verified`/`Pending`/`Missing` references.
#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct DashboardLawReference {
    pub diploma_id: String,
    pub article: String,
    pub label: String,
    pub heading: String,
    pub verification: String,
    pub source_url: Option<String>,
    pub source_complete: bool,
    pub review_method: Option<String>,
    pub review_note: Option<String>,
}

/// Client-facing action metadata for dashboard actionables.
#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct DashboardAction {
    pub kind: String,
    pub label_key: String,
    pub api_href: Option<String>,
    pub route: Option<String>,
}

/// Translation keys for user-facing dashboard actionable text.
#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct DashboardI18n {
    pub title_key: String,
    pub body_key: String,
    pub action_key: Option<String>,
}

/// One bounded dashboard reminder/action item. These are advisory planning signals, not compliance
/// gates; `source_rule` is the calendar/rule seed and `source_profile` is the entity profile facet
/// that produced it.
#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct DashboardReminder {
    pub due_date: String,
    pub severity: String,
    pub status: String,
    pub reason: String,
    pub entity_id: String,
    pub entity_name: String,
    pub source_rule: String,
    pub source_profile: String,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub params: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_calendar_plan: Option<DashboardProfileCalendarPlan>,
    pub law_refs: Vec<DashboardLawReference>,
    pub action: Option<DashboardAction>,
    pub recommended_next_steps: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub i18n: Option<DashboardI18n>,
}

/// Typed local advisory profile-calendar metadata attached to profile-calendar reminders.
///
/// This is a local plan surface only. It does not assert legal-calendar authority, legal
/// compliance, source completeness, external delivery/sync, provider effects, or certification.
#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct DashboardProfileCalendarPlan {
    pub preset_id: String,
    pub preset_label: String,
    pub rule_kind: String,
    pub support_status: String,
    pub review_status: String,
    pub source_status: String,
    pub due_rule: DashboardProfileCalendarDueRule,
    pub evaluation: DashboardProfileCalendarEvaluation,
    pub no_claims: DashboardProfileCalendarNoClaimFlags,
}

/// The local due-rule shape for a profile-calendar reminder.
#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct DashboardProfileCalendarDueRule {
    pub kind: String,
    pub months_after_fiscal_year_end: Option<u8>,
    pub default_fiscal_year_end: Option<String>,
    pub annual_fixed_month: Option<u8>,
    pub annual_fixed_day: Option<u8>,
    pub unsupported_reason: Option<String>,
}

/// The local evaluation result rendered on the reminder.
#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct DashboardProfileCalendarEvaluation {
    pub local_due_date_rule_configured: bool,
    pub local_due_date_calculated: bool,
    pub legal_deadline_calculated: bool,
    pub fiscal_year_end: Option<String>,
    pub due_year: Option<i32>,
    pub due_basis: Option<String>,
    pub unsupported_reason: Option<String>,
}

/// Explicit no-claim flags for profile-calendar output.
#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct DashboardProfileCalendarNoClaimFlags {
    pub local_advisory_only: bool,
    pub legal_deadline_authority_claimed: bool,
    pub legal_calendar_authority_claimed: bool,
    pub legal_compliance_claimed: bool,
    pub compliance_status_claimed: bool,
    pub workflow_completion_claimed: bool,
    pub external_delivery_claimed: bool,
    pub external_calendar_sync_claimed: bool,
    pub webhook_delivery_claimed: bool,
    pub legal_review_claimed: bool,
    pub dre_verification_claimed: bool,
    pub provider_effect_claimed: bool,
    pub certification_claimed: bool,
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

impl RegistryProvenanceView {
    fn redact_sensitive(&mut self) {
        self.access_code_masked = redacted();
        self.source_url = redacted();
        self.raw_digest = redacted();
        self.oficial = None;
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

impl PersonView {
    fn redact_sensitive(&mut self) {
        self.name = redacted();
        self.nif = None;
        self.estado_civil = None;
        self.nacionalidade = None;
        self.residencia = None;
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

impl QuotaView {
    fn redact_sensitive(&mut self) {
        self.titular.redact_sensitive();
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

impl OrganView {
    fn redact_sensitive(&mut self) {
        for member in &mut self.members {
            member.redact_sensitive();
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

impl OrganMemberView {
    fn redact_sensitive(&mut self) {
        self.name = redacted();
        self.nif = None;
        self.nacionalidade = None;
        self.residencia = None;
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

impl RegistryOfficialSignatureView {
    fn redact_sensitive(&mut self) {
        self.oficial = None;
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

impl ConstitutionPayloadView {
    fn redact_sensitive(&mut self) {
        self.nipc = None;
        self.sede = None;
        for socio in &mut self.socios {
            socio.redact_sensitive();
        }
        for organ in &mut self.orgaos {
            organ.redact_sensitive();
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

impl DesignationPayloadView {
    fn redact_sensitive(&mut self) {
        for organ in &mut self.orgaos {
            organ.redact_sensitive();
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

impl CessationPayloadView {
    fn redact_sensitive(&mut self) {
        for member in &mut self.members {
            member.redact_sensitive();
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

impl AmendmentPayloadView {
    fn redact_sensitive(&mut self) {
        self.new_sede = None;
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

    fn redact_sensitive(&mut self) {
        match self {
            InscriptionPayloadView::Constitution(payload) => payload.redact_sensitive(),
            InscriptionPayloadView::Designation(payload) => payload.redact_sensitive(),
            InscriptionPayloadView::Cessation(payload) => payload.redact_sensitive(),
            InscriptionPayloadView::ContractAmendment(payload) => payload.redact_sensitive(),
        }
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

impl InscriptionDetailView {
    fn redact_sensitive(&mut self) {
        if let Some(payload) = &mut self.payload {
            payload.redact_sensitive();
        }
        for signature in &mut self.signatures {
            signature.redact_sensitive();
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

impl RegistryAnnotationView {
    fn redact_sensitive(&mut self) {
        self.text = redacted();
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

impl RegistryOfficerView {
    fn redact_sensitive(&mut self) {
        self.name = redacted();
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

impl RegistryEventView {
    fn redact_sensitive(&mut self) {
        self.text = redacted();
        if let Some(detail) = &mut self.detail {
            detail.redact_sensitive();
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
            data_constituicao: e.effective_data_constituicao(),
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

    /// Build an extract read view under the selected privacy policy.
    pub(crate) fn build_with_redaction(
        e: &RegistryExtract,
        cae: &CaeCatalog,
        redaction: ReadRedaction,
    ) -> Self {
        let mut view = Self::build(e, cae);
        if redaction.is_guest() {
            view.redact_sensitive();
        }
        view
    }

    fn redact_sensitive(&mut self) {
        self.nipc = None;
        self.sede = None;
        for officer in &mut self.orgaos {
            officer.redact_sensitive();
        }
        for event in &mut self.inscricoes {
            event.redact_sensitive();
        }
        for annotation in &mut self.anotacoes {
            annotation.redact_sensitive();
        }
        self.provenance.redact_sensitive();
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

#[cfg(test)]
mod tests {
    use super::*;

    fn waiver_input(json: serde_json::Value) -> Result<ConveningWaiver, ApiError> {
        serde_json::from_value::<ConveningWaiverInput>(json)
            .expect("waiver input deserializes")
            .into_core()
    }

    #[test]
    fn an_other_basis_must_state_its_ground() {
        // "There was no convocatória, for reasons unstated" is not a record of anything.
        let err = waiver_input(serde_json::json!({ "basis": "Other" }))
            .expect_err("a groundless Other basis must be refused");
        assert!(matches!(err, ApiError::Unprocessable(_)), "{err:?}");

        let err = waiver_input(serde_json::json!({ "basis": "Other", "grounds": "   " }))
            .expect_err("whitespace is not a ground");
        assert!(matches!(err, ApiError::Unprocessable(_)), "{err:?}");

        let ok = waiver_input(serde_json::json!({
            "basis": "Other",
            "grounds": "Reunião do órgão realizada por acordo de todos os titulares."
        }))
        .expect("a stated ground is accepted");
        assert_eq!(ok.basis, NoConveningBasis::Other);
    }

    #[test]
    fn omitted_agreement_flags_default_to_not_captured() {
        // Never the other way round: a caller that says nothing about the art. 54.º agreement must
        // be recorded as not having captured it, so the rule pack still asks for it.
        let waiver = waiver_input(serde_json::json!({ "basis": "AssembleiaUniversal" }))
            .expect("universal basis needs no free-text ground");
        assert!(!waiver.all_agreed_to_meet);
        assert!(!waiver.all_agreed_to_agenda);
        assert_eq!(waiver.grounds, None);
    }

    #[test]
    fn a_waiver_view_redacts_prose_but_keeps_the_basis_legible() {
        let mut view = ConveningWaiverView::from(&ConveningWaiver {
            basis: NoConveningBasis::AssembleiaUniversal,
            grounds: Some("Todos os sócios presentes na sede.".to_owned()),
            all_agreed_to_meet: true,
            all_agreed_to_agenda: true,
            evidence_reference: Some("archive:declaracao-conjunta".to_owned()),
        });
        view.redact_sensitive();

        let value = serde_json::to_value(&view).expect("view serializes");
        assert_eq!(value["basis"], "AssembleiaUniversal");
        assert_eq!(value["all_agreed_to_meet"], true);
        assert_ne!(value["grounds"], "Todos os sócios presentes na sede.");
        assert_eq!(value["evidence_reference"], serde_json::Value::Null);
    }

    #[test]
    fn an_act_without_a_waiver_emits_no_waiver_key() {
        let act = Act::draft(
            chancela_core::BookId::new(),
            "Ata n.º 1",
            MeetingChannel::Physical,
        );
        let value = serde_json::to_value(ActView::from(&act)).expect("act view serializes");
        assert!(
            !value.as_object().expect("object").contains_key("convening_waiver"),
            "convened acts must not gain a key: {value}"
        );
    }

    #[test]
    fn issue_view_serializes_pending_legal_basis_without_source_claims() {
        let issue = ComplianceIssue {
            rule_id: "CSC-63/mesa-presidente".to_owned(),
            severity: Severity::Error,
            message: "missing chair".to_owned(),
            legal_basis: vec![LegalBasis {
                source_id: "csc".to_owned(),
                source_label: "Código das Sociedades Comerciais".to_owned(),
                article: Some("63".to_owned()),
                article_label: Some("Artigo 63.º".to_owned()),
                citation: "Código das Sociedades Comerciais, Artigo 63.º".to_owned(),
                verification: LegalBasisVerification::Pending,
                source_url: None,
                source_complete: false,
            }],
        };

        let value = serde_json::to_value(IssueView::from(&issue)).expect("issue serializes");
        assert_eq!(value["rule_id"], "CSC-63/mesa-presidente");
        assert_eq!(value["severity"], "Error");
        assert_eq!(value["legal_basis"][0]["source_id"], "csc");
        assert_eq!(value["legal_basis"][0]["article"], "63");
        assert_eq!(value["legal_basis"][0]["verification"], "Pending");
        assert_eq!(
            value["legal_basis"][0]["source_url"],
            serde_json::Value::Null
        );
        assert_eq!(value["legal_basis"][0]["source_complete"], false);
    }

    #[test]
    fn guest_book_view_redacts_opening_signatories_and_purpose() {
        let mut book = Book::new(EntityId(Uuid::from_u128(1)), BookKind::AssembleiaGeral);
        book.open(TermoDeAbertura {
            entity_name: "Encosto Estratégico Lda".to_owned(),
            entity_nipc: "503004642".to_owned(),
            entity_seat: "Rua da Liberdade".to_owned(),
            purpose: "Ata com assunto reservado".to_owned(),
            numbering_scheme: NumberingScheme::Sequential,
            opening_date: parse_date("2026-07-10").expect("valid date"),
            required_signatories: vec!["Amélia Marques".to_owned(), "Rui Nunes".to_owned()],
            required_signatory_records: vec![
                TermoSignatory {
                    name: "Amélia Marques".to_owned(),
                    capacity: Some(SignatoryCapacity::Administrator),
                    email: Some("amelia@example.pt".to_owned()),
                },
                TermoSignatory {
                    name: "Rui Nunes".to_owned(),
                    capacity: None,
                    email: None,
                },
            ],
            ..Default::default()
        })
        .expect("book opens");

        let view = BookView::build(&book, ReadRedaction::Guest);
        assert_eq!(view.purpose, None);
        assert_eq!(
            view.required_signatories_abertura,
            Some(vec![REDACTED.to_owned(), REDACTED.to_owned()])
        );
        assert_eq!(
            view.required_signatory_records_abertura,
            Some(vec![
                TermoSignatoryView::redacted(),
                TermoSignatoryView::redacted()
            ])
        );
        let raw = serde_json::to_string(&view).expect("book view JSON");
        assert!(!raw.contains("Ata com assunto reservado"));
        assert!(!raw.contains("Amélia Marques"));
        assert!(!raw.contains("Rui Nunes"));
        assert!(!raw.contains("amelia@example.pt"));
    }

    #[test]
    fn book_view_falls_back_to_structured_records_for_legacy_signatory_strings() {
        let mut book = Book::new(EntityId(Uuid::from_u128(1)), BookKind::AssembleiaGeral);
        book.open(TermoDeAbertura {
            entity_name: "Encosto Estratégico Lda".to_owned(),
            entity_nipc: "503004642".to_owned(),
            entity_seat: "Rua da Liberdade".to_owned(),
            purpose: "Livro".to_owned(),
            numbering_scheme: NumberingScheme::Sequential,
            opening_date: parse_date("2026-07-10").expect("valid date"),
            required_signatories: vec!["Administrador".to_owned()],
            required_signatory_records: Vec::new(),
            ..Default::default()
        })
        .expect("book opens");

        let view = BookView::from(&book);
        assert_eq!(
            view.required_signatory_records_abertura,
            Some(vec![TermoSignatoryView {
                name: "Administrador".to_owned(),
                capacity: None,
                email: None,
            }])
        );
    }

    #[test]
    fn create_book_required_signatories_accept_legacy_strings_and_structured_records() {
        let req: CreateBook = serde_json::from_value(serde_json::json!({
            "entity_id": "00000000-0000-0000-0000-000000000001",
            "kind": "AssembleiaGeral",
            "purpose": "livro",
            "opening_date": "2026-07-10",
            "required_signatories": [
                "Administrador",
                {
                    "name": " Amélia Marques ",
                    "capacity": "Chair",
                    "email": " AMELIA@EXAMPLE.PT "
                }
            ]
        }))
        .expect("compatible required_signatories request deserializes");

        let records = normalize_termo_signatories(req.required_signatories, "required_signatories")
            .expect("signatories normalize");
        assert_eq!(records[0], TermoSignatory::from_legacy("Administrador"));
        assert_eq!(
            records[1],
            TermoSignatory {
                name: "Amélia Marques".to_owned(),
                capacity: Some(SignatoryCapacity::Chair),
                email: Some("amelia@example.pt".to_owned()),
            }
        );
        let legacy: Vec<_> = records.iter().map(TermoSignatory::legacy_label).collect();
        assert_eq!(legacy, vec!["Administrador", "Amélia Marques (Chair)"]);
    }

    #[test]
    fn structured_termo_signatory_rejects_blank_name_and_invalid_email() {
        let blank = normalize_termo_signatories(
            vec![TermoSignatoryInput::Structured(TermoSignatoryView {
                name: " ".to_owned(),
                capacity: Some(SignatoryCapacity::Chair),
                email: None,
            })],
            "required_signatories",
        );
        assert!(matches!(blank, Err(ApiError::Unprocessable(msg)) if msg.contains("name")));

        let invalid_email = normalize_termo_signatories(
            vec![TermoSignatoryInput::Structured(TermoSignatoryView {
                name: "Amélia Marques".to_owned(),
                capacity: None,
                email: Some("not-an-email".to_owned()),
            })],
            "required_signatories",
        );
        assert!(
            matches!(invalid_email, Err(ApiError::Unprocessable(msg)) if msg.contains("email"))
        );
    }

    #[test]
    fn guest_act_view_redacts_participants_and_free_text_metadata() {
        let mut act = Act::draft(
            BookId(Uuid::from_u128(2)),
            "Deliberação reservada",
            MeetingChannel::Physical,
        );
        act.place = Some("Sala do Conselho".to_owned());
        act.mesa.presidente = Some("Amélia Marques".to_owned());
        act.mesa.secretarios = vec!["Rui Nunes".to_owned()];
        act.agenda.push(AgendaItem {
            number: 1,
            text: "Avaliar processo disciplinar".to_owned(),
        });
        act.attendance_reference = Some("Lista nominal assinada".to_owned());
        act.referenced_documents.push(DocumentReference {
            label: "Relatório médico".to_owned(),
            reference: Some("doc-123".to_owned()),
        });
        act.channel = MeetingChannel::WrittenResolution;
        act.written_resolution_evidence = Some(WrittenResolutionEvidence {
            checklist: vec![
                WrittenResolutionEvidenceItem {
                    label: "Approval pack for Ana".to_owned(),
                    reference: Some("vault:approval-pack-ana".to_owned()),
                    digest: Some([9; 32]),
                    note: Some("private digest note".to_owned()),
                },
                WrittenResolutionEvidenceItem {
                    label: "Reference-only approval folder".to_owned(),
                    reference: Some("folder:referenced-approvals".to_owned()),
                    digest: None,
                    note: Some("private reference note".to_owned()),
                },
            ],
            review_receipts: vec![WrittenResolutionReviewReceipt {
                reviewer: "private reviewer".to_owned(),
                reviewed_at: OffsetDateTime::UNIX_EPOCH,
                status: WrittenResolutionReviewStatus::Reviewed,
                guardrail_acknowledgements: vec!["no legal claim".to_owned()],
                evidence: vec![WrittenResolutionReviewEvidenceLocator {
                    label: "private review locator".to_owned(),
                    locator: Some("vault:private-review".to_owned()),
                    digest: Some([8; 32]),
                }],
                note: Some("private review note".to_owned()),
                consent_proof_claimed: false,
                quorum_proof_claimed: false,
                identity_proof_claimed: false,
                legal_acceptance_claimed: false,
                legal_sufficiency_claimed: false,
                external_validation_claimed: false,
                automatic_approval_claimed: false,
                authority_certified_claimed: false,
            }],
            note: Some("private written-resolution evidence note".to_owned()),
        });
        act.deliberations = "Texto de deliberação com dados pessoais".to_owned();
        act.deliberation_items.push(DeliberationItem {
            agenda_number: Some(1),
            text: "Voto vencido com fundamento pessoal".to_owned(),
            vote: None,
            statements: vec![MemberStatement {
                member: "Joana Silva".to_owned(),
                text: "Declaração pessoal".to_owned(),
            }],
        });
        act.telematic_evidence = Some("IP e sessão".to_owned());
        act.attachments.push(Attachment {
            label: "Anexo confidencial".to_owned(),
            kind: AttachmentKind::Other,
            digest: Some([7; 32]),
            beginning_of_proof: false,
        });
        act.signatories.push(SignatorySlot {
            name: "Carlos Costa".to_owned(),
            email: Some("carlos@example.test".to_owned()),
            capacity: SignatoryCapacity::Chair,
            signed: false,
            permilage: None,
        });
        act.convening = Some(Convening {
            convener: Some("Administração".to_owned()),
            convener_capacity: Some(SignatoryCapacity::Manager),
            dispatch_date: None,
            antecedence_days: Some(15),
            channel: None,
            evidence_reference: Some("email-msg-123".to_owned()),
            recipients: vec![ConveningRecipient {
                name: "Sócia Identificada".to_owned(),
                contact: Some("socia@example.test".to_owned()),
                channel: None,
                reference: Some("email-msg-recipient-1".to_owned()),
                dispatched_at: None,
            }],
            second_call: None,
        });
        act.attendees.push(Attendee {
            name: "Presente Identificado".to_owned(),
            quality: SignatoryCapacity::Member,
            quality_note: None,
            presence: PresenceMode::InPerson,
            represented_by: None,
            weight: None,
        });

        let view = ActView::build(&act, ReadRedaction::Guest);
        let value = serde_json::to_value(&view).expect("act view JSON");
        let raw = serde_json::to_string(&value).expect("act view JSON string");
        for leaked in [
            "Deliberação reservada",
            "Sala do Conselho",
            "Amélia Marques",
            "Rui Nunes",
            "Avaliar processo disciplinar",
            "Lista nominal assinada",
            "Relatório médico",
            "Approval pack for Ana",
            "vault:approval-pack-ana",
            "0909090909090909090909090909090909090909090909090909090909090909",
            "private digest note",
            "Reference-only approval folder",
            "folder:referenced-approvals",
            "private reference note",
            "private written-resolution evidence note",
            "private reviewer",
            "no legal claim",
            "private review locator",
            "vault:private-review",
            "private review note",
            "Texto de deliberação",
            "Joana Silva",
            "IP e sessão",
            "Anexo confidencial",
            "carlos@example.test",
            "Administração",
            "email-msg-123",
            "Sócia Identificada",
            "socia@example.test",
            "email-msg-recipient-1",
            "Presente Identificado",
        ] {
            assert!(
                !raw.contains(leaked),
                "guest act view leaked {leaked}: {raw}"
            );
        }
        assert!(raw.contains(REDACTED));

        let evidence = &value["written_resolution_evidence"];
        assert_eq!(evidence["status"]["status"], "bound_present");
        assert_eq!(
            evidence["status"]["boundary"],
            WRITTEN_RESOLUTION_EVIDENCE_STATUS_BOUNDARY
        );
        assert_eq!(evidence["status"]["checklist_items"], 2);
        assert_eq!(evidence["status"]["digested_attachments"], 1);
        assert_eq!(evidence["status"]["digested_checklist_items"], 1);
        assert_eq!(evidence["status"]["referenced_checklist_items"], 1);
        assert_eq!(evidence["status"]["bound_count"], 2);
        assert_eq!(evidence["status"]["review_receipts"], 1);
        assert_eq!(evidence["status"]["latest_review_status"], "reviewed");
        assert_eq!(evidence["status"]["reviewed_evidence_locators"], 1);
        assert_eq!(evidence["status"]["reviewed_evidence_digests"], 1);
        assert_eq!(
            evidence["checklist"][0]["reference"],
            serde_json::Value::Null
        );
        assert_eq!(evidence["checklist"][0]["digest"], serde_json::Value::Null);
        assert_eq!(evidence["checklist"][0]["note"], serde_json::Value::Null);
        let receipt = &evidence["review_receipts"][0];
        assert_eq!(receipt["reviewer"], REDACTED);
        assert_eq!(
            receipt["guardrail_acknowledgements"]
                .as_array()
                .expect("acknowledgements array")
                .len(),
            0
        );
        assert_eq!(receipt["note"], serde_json::Value::Null);
        assert_eq!(receipt["evidence"][0]["label"], REDACTED);
        assert_eq!(receipt["evidence"][0]["locator"], serde_json::Value::Null);
        assert_eq!(receipt["evidence"][0]["digest"], serde_json::Value::Null);
        assert_eq!(receipt["legal_sufficiency_claimed"], false);
        assert_eq!(receipt["authority_certified_claimed"], false);
        assert_eq!(evidence["note"], serde_json::Value::Null);
    }

    /// The qualidade round-trips through the wire DTOs, and the free-text escape hatch stays
    /// welded to `Other` so a report grouping by `quality` cannot be split by prose (t28).
    #[test]
    fn attendee_quality_round_trips_and_free_text_stays_paired_with_other() {
        let parse = |v: serde_json::Value| serde_json::from_value::<AttendeeInput>(v).unwrap();

        // A sociedade anonima's acionista survives the wire in both directions.
        let core = parse(serde_json::json!({
            "name": "Amelia Marques",
            "quality": "Shareholder",
            "presence": "InPerson"
        }))
        .into_core()
        .expect("a shareholder attendance row is accepted");
        assert_eq!(core.quality, SignatoryCapacity::Shareholder);
        assert_eq!(core.quality_note, None);
        let view = serde_json::to_value(AttendeeView::from(&core)).unwrap();
        assert_eq!(view["quality"], "Shareholder");
        assert_eq!(view["quality_note"], serde_json::Value::Null);

        // `Other` + a note: the note is carried, trimmed, and surfaced on the view.
        let core = parse(serde_json::json!({
            "name": "Amelia Marques",
            "quality": "Other",
            "quality_note": "  usufrutuario da quota  ",
            "presence": "InPerson"
        }))
        .into_core()
        .expect("a free-text qualidade is accepted alongside Other");
        assert_eq!(core.quality, SignatoryCapacity::Other);
        assert_eq!(core.quality_note.as_deref(), Some("usufrutuario da quota"));
        let view = serde_json::to_value(AttendeeView::from(&core)).unwrap();
        assert_eq!(view["quality_note"], "usufrutuario da quota");

        // Blank free text is dropped rather than stored, and `Other` alone is legal mid-draft.
        let core = parse(serde_json::json!({
            "name": "Amelia Marques",
            "quality": "Other",
            "quality_note": "   ",
            "presence": "InPerson"
        }))
        .into_core()
        .expect("an unfilled note is not an error");
        assert_eq!(core.quality_note, None);

        // A note on a structured capacity is a 422: it would poison reporting over `quality`.
        let err = parse(serde_json::json!({
            "name": "Amelia Marques",
            "quality": "Member",
            "quality_note": "socio maioritario",
            "presence": "InPerson"
        }))
        .into_core()
        .expect_err("a note on a structured capacity is rejected");
        assert!(matches!(err, ApiError::Unprocessable(_)), "{err:?}");
    }

    /// The offered qualidades reach the wire profile, and they differ by legal type (t28).
    #[test]
    fn entity_profile_view_carries_the_attendee_qualities_of_its_kind() {
        let sa = EntityProfileView::from(EntityKind::SociedadeAnonima);
        let lda = EntityProfileView::from(EntityKind::SociedadePorQuotas);
        let condo = EntityProfileView::from(EntityKind::Condominio);

        assert!(
            sa.attendee_qualities
                .contains(&SignatoryCapacity::Shareholder)
        );
        assert!(!sa.attendee_qualities.contains(&SignatoryCapacity::Member));
        assert!(lda.attendee_qualities.contains(&SignatoryCapacity::Member));
        assert!(
            !lda.attendee_qualities
                .contains(&SignatoryCapacity::Shareholder)
        );
        assert!(
            condo
                .attendee_qualities
                .contains(&SignatoryCapacity::CondoOwner)
        );

        let json = serde_json::to_value(&sa).unwrap();
        assert_eq!(json["attendee_qualities"][0], "Shareholder");
    }
}
