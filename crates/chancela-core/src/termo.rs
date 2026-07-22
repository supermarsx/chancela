//! The **termos** (abertura and encerramento) as first-class signable instruments.
//!
//! Grounding: **Código Comercial art. 31.º n.º 2** (wording given by art. 8.º of
//! DL 76-A/2006) is the only operative provision, and it prescribes *who lavra os termos*,
//! not what they say:
//!
//! > "Os livros de actas podem ser constituídos por folhas soltas numeradas sequencialmente
//! > e rubricadas pela administração ou pelos membros do órgão social a que respeitam ou,
//! > quando existam, pelo secretário da sociedade ou pelo presidente da mesa da assembleia
//! > geral da sociedade, **que lavram, igualmente, os termos de abertura e de encerramento**,
//! > devendo as folhas soltas ser encadernadas depois de utilizadas."
//!
//! Because the provision names the two termos *together* and puts them on the *same*
//! signers, one model — [`TermoInstrument`] — serves both, discriminated by [`TermoKind`].
//!
//! # What is legally required, and what is not
//!
//! Exactly **two** things modelled here are legally required, and nothing else in this
//! module may be described as such:
//!
//! 1. The **signer-capacity allow-list** ([`is_permitted_termo_capacity`]) — art. 31.º n.º 2
//!    gives a closed list of who may draw up the termos.
//! 2. **At least one signatory** ([`TermoError::NoSignatories`]) — a termo that nobody draws
//!    up has no author.
//!
//! Everything else (page capacity, book number, place, the ata/page counts, the management
//! floor, the completion policy, clause text) is **product or evidentiary-assurance policy**.
//! Portuguese law prescribes no content for either termo, and mandatory legalização at the
//! conservatória was abolished by DL 76-A/2006. This is documentation of intent, not legal
//! advice.
//!
//! # Relationship to the sealed payload types
//!
//! [`TermoInstrument`] is the *editable draft* record. It is **projected** at seal time into
//! [`crate::book::TermoDeAbertura`] / [`crate::book::TermoDeEncerramento`], which remain the
//! payload types digested into the `book.opened` / `book.closed` ledger events. Draft-only
//! state (clause origins, per-slot bookkeeping) deliberately does not cross that boundary.

use serde::{Deserialize, Serialize};
use time::{Date, OffsetDateTime};
use uuid::Uuid;

use crate::act::SignatoryCapacity;
use crate::book::{
    BookId, ClosingReason, TermoClauseRecord, TermoCollectedSignature, TermoDeAbertura,
    TermoDeEncerramento, TermoSignatory,
};
use crate::error::TermoError;

/// Default size of a new book, in pages, declared by its termo de abertura.
///
/// A product default, not a legal requirement: no source requires a stated capacity at
/// opening. It is *consistent with* art. 31.º n.º 2's numbered-folhas regime, no more.
pub const DEFAULT_PAGE_CAPACITY: u32 = 100;

/// Smallest page capacity a termo de abertura may declare.
pub const MIN_PAGE_CAPACITY: u32 = 1;

/// Largest page capacity a termo de abertura may declare.
pub const MAX_PAGE_CAPACITY: u32 = 10_000;

/// Maximum number of clauses in a termo body (F8).
pub const MAX_TERMO_CLAUSES: usize = 100;

/// Maximum size of a single clause's text, in bytes (F8; mirrors the template-authoring cap).
pub const MAX_CLAUSE_TEXT_BYTES: usize = 8 * 1024;

/// Maximum length of a termo title, a clause heading, or a place, in characters.
pub const MAX_TERMO_TEXT_CHARS: usize = 200;

/// Maximum length of the abertura's free-text purpose, in characters (F11).
pub const MAX_TERMO_PURPOSE_CHARS: usize = 500;

/// Opaque identifier for a [`TermoInstrument`].
///
/// Deliberately distinct from [`BookId`] and [`crate::act::ActId`]: the abertura and the
/// encerramento of the same book must not collide on a single document/signature key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TermoInstrumentId(pub Uuid);

impl TermoInstrumentId {
    /// Mint a fresh random identifier.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for TermoInstrumentId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for TermoInstrumentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Which of the two termos this instrument is.
///
/// Art. 31.º n.º 2 names them together and puts them on the same signers, which is why one
/// type covers both rather than two parallel models.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TermoKind {
    /// The termo de abertura, which opens the book.
    Abertura,
    /// The termo de encerramento, which closes it.
    Encerramento,
}

impl std::fmt::Display for TermoKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Abertura => f.write_str("abertura"),
            Self::Encerramento => f.write_str("encerramento"),
        }
    }
}

/// The termo lifecycle: three states, deliberately not a copy of [`crate::act::ActState`].
///
/// A termo has no convening, no deliberation and no text-approval gate, so inventing those
/// stages would be cargo-culting the ata's machine onto a different instrument.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TermoState {
    /// Being drafted; title, body, fields and signatory slots are freely editable.
    Draft,
    /// Content and signatory set are frozen; signatures are being collected against the
    /// rendered snapshot.
    Signing,
    /// The termo has taken effect (the book was opened or closed by it) and is immutable.
    Sealed,
}

/// Where a clause's text came from — draft-only provenance, never part of a digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClauseOrigin {
    /// Seeded verbatim from the template's `default_body`.
    TemplateDefault,
    /// Seeded from the template and then edited by an operator.
    UserEdited,
    /// Added by an operator; no template ancestor.
    UserAdded,
}

/// One clause of the termo's fillable text (F8).
///
/// **Security invariant:** `text` is operator input. It is rendered as a template *value*
/// (`{{ text }}`) and must never be compiled as template *source*. A clause containing
/// `{{ ... }}` or `{% ... %}` must render literally.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TermoClause {
    /// Stable id, so edits and reorders are diffable and the UI has a key.
    pub id: Uuid,
    /// Optional heading rendered above the clause.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub heading: Option<String>,
    /// Plain text. Rendered as a value, never compiled.
    pub text: String,
    /// Draft-only provenance.
    pub origin: ClauseOrigin,
}

impl TermoClause {
    /// A clause seeded from the template's default body.
    pub fn from_template(heading: Option<String>, text: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            heading,
            text: text.into(),
            origin: ClauseOrigin::TemplateDefault,
        }
    }

    /// A clause written by an operator.
    pub fn user_added(heading: Option<String>, text: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            heading,
            text: text.into(),
            origin: ClauseOrigin::UserAdded,
        }
    }

    /// Replace the text, recording that an operator edited it.
    pub fn edit_text(&mut self, text: impl Into<String>) {
        self.text = text.into();
        if self.origin == ClauseOrigin::TemplateDefault {
            self.origin = ClauseOrigin::UserEdited;
        }
    }

    fn validate(&self) -> Result<(), TermoError> {
        if self.text.trim().is_empty() {
            return Err(TermoError::EmptyClauseText { clause_id: self.id });
        }
        if self.text.len() > MAX_CLAUSE_TEXT_BYTES {
            return Err(TermoError::ClauseTextTooLong {
                clause_id: self.id,
                bytes: self.text.len(),
                max_bytes: MAX_CLAUSE_TEXT_BYTES,
            });
        }
        if let Some(heading) = &self.heading
            && heading.chars().count() > MAX_TERMO_TEXT_CHARS
        {
            return Err(TermoError::TextTooLong {
                field: "clause.heading",
                max_chars: MAX_TERMO_TEXT_CHARS,
            });
        }
        Ok(())
    }

    /// Project to the payload shape: the text as signed, without draft provenance.
    #[must_use]
    pub fn to_record(&self) -> TermoClauseRecord {
        TermoClauseRecord {
            heading: self.heading.clone(),
            text: self.text.clone(),
        }
    }
}

/// Whether a capacity is one art. 31.º n.º 2 admits for drawing up a termo (F5).
///
/// **This allow-list is one of the only two legally-required things in the whole feature.**
/// The provision names: a administração (gerência — [`SignatoryCapacity::Manager`]; conselho
/// de administração — [`SignatoryCapacity::Administrator`]), os membros do órgão social a que
/// respeitam ([`SignatoryCapacity::Member`]), o secretário da sociedade, quando exista
/// ([`SignatoryCapacity::Secretary`]), and o presidente da mesa da assembleia geral
/// ([`SignatoryCapacity::Chair`]).
///
/// [`SignatoryCapacity::Attorney`] and [`SignatoryCapacity::CondoOwner`] are **not** in the
/// list and are refused. Whether the listed capacities are alternative rather than cumulative
/// is only *medium* confidence, and no ROC, notary or conservador is required — none of that
/// is asserted here.
#[must_use]
pub const fn is_permitted_termo_capacity(capacity: SignatoryCapacity) -> bool {
    matches!(
        capacity,
        SignatoryCapacity::Manager
            | SignatoryCapacity::Administrator
            | SignatoryCapacity::Member
            | SignatoryCapacity::Secretary
            | SignatoryCapacity::Chair
    )
}

/// Whether a capacity counts as *management* for the §5.2.1 floor.
#[must_use]
pub const fn is_management_capacity(capacity: SignatoryCapacity) -> bool {
    matches!(
        capacity,
        SignatoryCapacity::Manager | SignatoryCapacity::Administrator
    )
}

/// A signature slot on a termo (F5/F7).
///
/// Unlike [`crate::book::TermoSignatory`], whose `capacity` is optional and whose names are
/// merely *declared*, a slot has a required capacity and records whether a signature was
/// actually **collected**.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TermoSignatorySlot {
    /// Stable slot id. Unique within the instrument; also the `slot_id` written to the
    /// store's `instrument_signatures` history.
    pub id: Uuid,
    /// Signatory name.
    pub name: String,
    /// Optional contact address for coordinating this signatory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// The legal quality in which this person signs. Required, and constrained to the
    /// art. 31.º n.º 2 allow-list. This is *evidence*, not a software permission — see the
    /// capacity-vs-role distinction in the module docs of `chancela-authz`.
    pub capacity: SignatoryCapacity,
    /// Free-text quality note, **required** when `capacity` is [`SignatoryCapacity::Other`] and
    /// forbidden otherwise.
    ///
    /// **`ASSURANCE`.** `Other` is outside the art. 31.º n.º 2 allow-list: it is an escape hatch
    /// for a legitimate but unmodelled qualidade, and this note says what that qualidade is. It
    /// never satisfies the legal capacity requirement (which only the modelled capacities meet)
    /// and never counts toward the management floor. Mirrors
    /// [`crate::act::Attendee::quality_note`] — the free text stays out of the structured
    /// `capacity`, so reporting over capacities remains a closed set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capacity_note: Option<String>,
    /// Required slots must sign for the instrument to complete. Optional co-signers (a
    /// secretário, say) are legitimate.
    pub required: bool,
    /// Print order, and the order in which sequential PAdES signatures are collected: signer
    /// *n+1* signs the output of signer *n*.
    pub order: u16,
    /// Whether a signature has been collected for this slot. System-managed.
    #[serde(default)]
    pub signed: bool,
    /// When the signature was collected. System-managed.
    #[serde(
        default,
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none"
    )]
    pub signed_at: Option<OffsetDateTime>,
    /// Identifier of the collected signature artifact. System-managed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_id: Option<Uuid>,
}

impl TermoSignatorySlot {
    /// A required, unsigned slot.
    pub fn required(name: impl Into<String>, capacity: SignatoryCapacity, order: u16) -> Self {
        Self {
            id: Uuid::new_v4(),
            name: name.into(),
            email: None,
            capacity,
            capacity_note: None,
            required: true,
            order,
            signed: false,
            signed_at: None,
            signature_id: None,
        }
    }

    /// An optional, unsigned slot.
    pub fn optional(name: impl Into<String>, capacity: SignatoryCapacity, order: u16) -> Self {
        Self {
            required: false,
            ..Self::required(name, capacity, order)
        }
    }

    /// Attach a contact address.
    #[must_use]
    pub fn with_email(mut self, email: impl Into<String>) -> Self {
        self.email = Some(email.into());
        self
    }

    /// Attach the free-text quality note that [`SignatoryCapacity::Other`] requires. An
    /// `ASSURANCE` value; see [`TermoSignatorySlot::capacity_note`].
    #[must_use]
    pub fn with_capacity_note(mut self, note: impl Into<String>) -> Self {
        self.capacity_note = Some(note.into());
        self
    }

    fn validate(&self) -> Result<(), TermoError> {
        if self.name.trim().is_empty() {
            return Err(TermoError::EmptySignatoryName { slot_id: self.id });
        }
        if self.name.chars().count() > MAX_TERMO_TEXT_CHARS {
            return Err(TermoError::TextTooLong {
                field: "signatory.name",
                max_chars: MAX_TERMO_TEXT_CHARS,
            });
        }
        // Capacity gate. [`is_permitted_termo_capacity`] — the art. 31.º n.º 2 allow-list — is
        // one of the only two legally-required checks and stays a pure closed set that `Other`
        // is never in. `Other` is admitted *alongside* it as an ASSURANCE escape hatch, and only
        // with a non-empty note saying what the quality is. It never satisfies the legal capacity
        // requirement and never counts as management (see [`is_management_capacity`]).
        let note_present = self
            .capacity_note
            .as_deref()
            .is_some_and(|note| !note.trim().is_empty());
        match self.capacity {
            SignatoryCapacity::Other => {
                if !note_present {
                    return Err(TermoError::MissingSignatoryCapacityNote { slot_id: self.id });
                }
            }
            capacity if is_permitted_termo_capacity(capacity) => {
                if note_present {
                    return Err(TermoError::UnexpectedSignatoryCapacityNote { slot_id: self.id });
                }
            }
            capacity => {
                return Err(TermoError::ForbiddenCapacity {
                    slot_id: self.id,
                    capacity,
                });
            }
        }
        Ok(())
    }

    /// Project to the payload shape, preserving the declared-signatory record.
    #[must_use]
    pub fn to_declared_record(&self) -> TermoSignatory {
        TermoSignatory {
            name: self.name.clone(),
            capacity: Some(self.capacity),
            capacity_note: self.capacity_note.clone(),
            email: self.email.clone(),
        }
    }

    /// Project the *collected* signature, when one was actually collected.
    #[must_use]
    pub fn to_collected_record(&self) -> Option<TermoCollectedSignature> {
        let signed_at = self.signed_at?;
        self.signed.then(|| TermoCollectedSignature {
            slot_id: self.id,
            name: self.name.clone(),
            capacity: self.capacity,
            capacity_note: self.capacity_note.clone(),
            signed_at,
            signature_id: self.signature_id,
        })
    }
}

/// How many of the slots must sign before the termo is complete (F9).
///
/// **Basis: `OPEN`.** Whether plural, jointly-binding gerência must *all* sign is legally
/// unresolved (low confidence; flagged for counsel), and whether art. 31.º n.º 2's list is
/// alternative rather than cumulative is only medium confidence. All three readings are
/// therefore expressible, the conservative one is the default, and **no copy anywhere may
/// state that the law requires all gerentes to sign, or that one suffices.**
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum TermoCompletionPolicy {
    /// Every `required` slot must sign. The default, because when the law is unresolved the
    /// product must not silently adopt the permissive reading.
    #[default]
    AllRequired,
    /// At least `n` of the required slots must sign.
    AtLeast(u16),
    /// Any single qualifying signer — the reading art. 31.º n.º 2 arguably supports on its
    /// face. Subject to the management floor, so it can never settle for a secretário alone.
    SingleQualifying,
}

impl TermoCompletionPolicy {
    /// The number of required-slot signatures this policy will settle for, given how many
    /// required slots exist.
    #[must_use]
    pub fn threshold(self, required_slot_count: u16) -> u16 {
        match self {
            Self::AllRequired => required_slot_count,
            Self::AtLeast(n) => n.min(required_slot_count),
            Self::SingleQualifying => 1.min(required_slot_count),
        }
    }
}

/// Progress towards completion, without any legal or certificate-level assertion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TermoCompletionSummary {
    /// Policy in force.
    pub policy: TermoCompletionPolicy,
    /// How many slots are marked required.
    pub required_slot_count: u16,
    /// How many required slots have a collected signature.
    pub signed_required_slot_count: u16,
    /// How many signatures the policy is waiting for.
    pub threshold: u16,
    /// Required slots that still block completion.
    pub blocking_required_slot_ids: Vec<Uuid>,
    /// Whether the policy is satisfied right now.
    pub complete: bool,
}

/// The fillable, non-body fields of a termo (F1-F3, F11, F12, F20).
///
/// Every field here is `ASSURANCE` or `PRODUCT`. None of it is legally required.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TermoFields {
    /// F1 — "livro n.º N": the identity users expect on a termo. No source requires it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub book_number: Option<u32>,
    /// F2 — place of drawing up. Its absence is **not** a compliance gap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub place: Option<String>,
    /// F3 — the book's declared size in pages. Abertura only; a one-way door once sealed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_capacity: Option<u32>,
    /// F11 — free-text purpose ("livro de atas da assembleia geral"). Abertura only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    /// F12 — the opening date (abertura) or closing date (encerramento).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instrument_date: Option<Date>,
    /// F20 — why the book is being closed. Encerramento only; user-chosen, never derived
    /// from capacity exhaustion (which merely preselects [`ClosingReason::BookFull`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closing_reason: Option<ClosingReason>,
    /// D5 — a free-text reference to a **paper/legacy predecessor book** that is not in the
    /// system.
    ///
    /// **`ASSURANCE`.** The real successor link is [`crate::book::Book::predecessor`], a book id
    /// that makes the verifiable chain; this note is only a human reference for a predecessor
    /// with no digital record, and never stands in for that link. Abertura-oriented but not
    /// gated by kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predecessor_note: Option<String>,
}

impl TermoFields {
    /// Fields seeded for a fresh termo de abertura, with the default page capacity.
    #[must_use]
    pub fn for_abertura() -> Self {
        Self {
            page_capacity: Some(DEFAULT_PAGE_CAPACITY),
            ..Self::default()
        }
    }

    /// Fields seeded for a fresh termo de encerramento.
    #[must_use]
    pub fn for_encerramento() -> Self {
        Self::default()
    }

    fn validate(&self, kind: TermoKind) -> Result<(), TermoError> {
        if let Some(number) = self.book_number
            && number < 1
        {
            return Err(TermoError::InvalidBookNumber(number));
        }
        check_len("place", self.place.as_deref(), MAX_TERMO_TEXT_CHARS)?;
        check_len("purpose", self.purpose.as_deref(), MAX_TERMO_PURPOSE_CHARS)?;
        check_len(
            "predecessor_note",
            self.predecessor_note.as_deref(),
            MAX_TERMO_TEXT_CHARS,
        )?;

        match kind {
            TermoKind::Abertura => {
                let capacity = self
                    .page_capacity
                    .ok_or(TermoError::MissingField("page_capacity"))?;
                if !(MIN_PAGE_CAPACITY..=MAX_PAGE_CAPACITY).contains(&capacity) {
                    return Err(TermoError::PageCapacityOutOfRange {
                        requested: capacity,
                        min: MIN_PAGE_CAPACITY,
                        max: MAX_PAGE_CAPACITY,
                    });
                }
                if self.closing_reason.is_some() {
                    return Err(TermoError::FieldNotApplicable {
                        field: "closing_reason",
                        kind,
                    });
                }
            }
            TermoKind::Encerramento => {
                if self.page_capacity.is_some() {
                    return Err(TermoError::FieldNotApplicable {
                        field: "page_capacity",
                        kind,
                    });
                }
                match self
                    .closing_reason
                    .as_ref()
                    .ok_or(TermoError::MissingField("closing_reason"))?
                {
                    // The user ruling that added this variant made the note REQUIRED:
                    // forcing a false structured reason onto an instrument whose purpose is
                    // stating facts is the failure mode being avoided, and the note is what
                    // keeps the choice auditable.
                    ClosingReason::Other { note } if note.trim().is_empty() => {
                        return Err(TermoError::MissingField("closing_reason.note"));
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }
}

fn check_len(field: &'static str, value: Option<&str>, max_chars: usize) -> Result<(), TermoError> {
    match value {
        Some(text) if text.trim().is_empty() => Err(TermoError::EmptyField(field)),
        Some(text) if text.chars().count() > max_chars => {
            Err(TermoError::TextTooLong { field, max_chars })
        }
        _ => Ok(()),
    }
}

/// A termo de abertura or de encerramento as a drafted, fillable, signable instrument.
///
/// This is an ata-class instrument in its own right: it has its own identity, its own
/// lifecycle, its own editable body and its own signatories — but it is deliberately **not**
/// a [`crate::act::Act`]. An act lives *inside* an open book and consumes an ata number; the
/// termos *bound* the book and are unnumbered (art. 31.º n.º 2 numbers the folhas, and
/// CCom art. 37.º governs the atas — neither numbers a termo).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TermoInstrument {
    /// Stable identifier, distinct from the book's and from any act's.
    pub id: TermoInstrumentId,
    /// The book this instrument opens or closes.
    pub book_id: BookId,
    /// Which termo this is.
    pub kind: TermoKind,
    /// Current lifecycle state.
    pub state: TermoState,
    /// Title (F4). Replaces what used to be a hardcoded literal in the render path.
    pub title: String,
    /// The fillable text (F8), seeded from the template and thereafter operator-editable.
    #[serde(default)]
    pub body: Vec<TermoClause>,
    /// The non-body fillable fields.
    #[serde(default)]
    pub fields: TermoFields,
    /// Signature slots. At least one required slot is needed to leave `Draft`.
    #[serde(default)]
    pub signatories: Vec<TermoSignatorySlot>,
    /// Completion rule in force.
    #[serde(default)]
    pub completion_policy: TermoCompletionPolicy,
    /// Template pinned at the content freeze, so the rendered PDF/A is reproducible (F10).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template_id: Option<String>,
    /// When the draft was created.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// When the content was frozen and signature collection began.
    #[serde(
        default,
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none"
    )]
    pub signing_started_at: Option<OffsetDateTime>,
    /// When the instrument took effect.
    #[serde(
        default,
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none"
    )]
    pub sealed_at: Option<OffsetDateTime>,
}

impl TermoInstrument {
    /// Start a fresh draft instrument.
    ///
    /// The body is empty: seeding it from the template's `default_body` belongs to the API
    /// layer, which knows which template family applies.
    pub fn draft(
        book_id: BookId,
        kind: TermoKind,
        title: impl Into<String>,
        created_at: OffsetDateTime,
    ) -> Self {
        Self {
            id: TermoInstrumentId::new(),
            book_id,
            kind,
            state: TermoState::Draft,
            title: title.into(),
            body: Vec::new(),
            fields: match kind {
                TermoKind::Abertura => TermoFields::for_abertura(),
                TermoKind::Encerramento => TermoFields::for_encerramento(),
            },
            signatories: Vec::new(),
            completion_policy: TermoCompletionPolicy::default(),
            template_id: None,
            created_at,
            signing_started_at: None,
            sealed_at: None,
        }
    }

    /// Whether the content and signatory set may still be edited.
    ///
    /// Entry into `Signing` freezes exactly the content and slots that produced the signing
    /// snapshot, because those are the bytes the signatures bind — the same discipline as
    /// [`crate::act::Act::is_mutable`].
    #[must_use]
    pub fn is_mutable(&self) -> bool {
        self.state == TermoState::Draft
    }

    fn ensure_mutable(&self) -> Result<(), TermoError> {
        if self.is_mutable() {
            Ok(())
        } else {
            Err(TermoError::NotMutable(self.state))
        }
    }

    /// Replace the title (rejected once frozen).
    pub fn set_title(&mut self, title: impl Into<String>) -> Result<(), TermoError> {
        self.ensure_mutable()?;
        self.title = title.into();
        Ok(())
    }

    /// Replace the body (rejected once frozen).
    pub fn set_body(&mut self, body: Vec<TermoClause>) -> Result<(), TermoError> {
        self.ensure_mutable()?;
        self.body = body;
        Ok(())
    }

    /// Add a signature slot (rejected once frozen).
    pub fn add_signatory(&mut self, slot: TermoSignatorySlot) -> Result<(), TermoError> {
        self.ensure_mutable()?;
        if self
            .signatories
            .iter()
            .any(|existing| existing.id == slot.id)
        {
            return Err(TermoError::DuplicateSlotId(slot.id));
        }
        self.signatories.push(slot);
        Ok(())
    }

    /// Set the completion policy, validating it against the current slots (rejected once
    /// frozen). The management floor is re-checked here as well as at the freeze.
    pub fn set_completion_policy(
        &mut self,
        policy: TermoCompletionPolicy,
    ) -> Result<(), TermoError> {
        self.ensure_mutable()?;
        let previous = self.completion_policy;
        self.completion_policy = policy;
        if let Err(error) = self.validate_policy() {
            self.completion_policy = previous;
            return Err(error);
        }
        Ok(())
    }

    /// Slots marked required.
    fn required_slots(&self) -> impl Iterator<Item = &TermoSignatorySlot> {
        self.signatories.iter().filter(|slot| slot.required)
    }

    /// How many slots are marked required.
    #[must_use]
    pub fn required_slot_count(&self) -> u16 {
        u16::try_from(self.required_slots().count()).unwrap_or(u16::MAX)
    }

    /// Whether the configured policy can only complete with at least one management
    /// signature — the §5.2.1 **gerência floor**.
    ///
    /// The user's rule for the encerramento is "signed by the manager or managers **at
    /// least**", and "at least" is a floor, not an exact rule. So: at least one required slot
    /// must carry a management capacity, **and** the policy must be incapable of completing
    /// without it. `SingleQualifying` is refused when it could settle for a secretário alone;
    /// `AtLeast(n)` is refused when `n` is low enough that the non-management required slots
    /// could satisfy it by themselves.
    ///
    /// This is deliberately **stricter than the statute** (which reads as a set of
    /// alternatives) and **looser than "all gerentes"** (which is legally unresolved). It is
    /// a **product policy applied on top of the law** and must be presented as such.
    ///
    /// The floor applies to both termos, because art. 31.º n.º 2 names them as a pair on the
    /// same signers.
    #[must_use]
    pub fn satisfies_management_floor(&self) -> bool {
        let required = self.required_slot_count();
        let management = u16::try_from(
            self.required_slots()
                .filter(|slot| is_management_capacity(slot.capacity))
                .count(),
        )
        .unwrap_or(u16::MAX);
        if management == 0 {
            return false;
        }
        // The policy must demand more signatures than the non-management required slots can
        // supply on their own.
        self.completion_policy.threshold(required) > required - management
    }

    fn validate_policy(&self) -> Result<(), TermoError> {
        let required = self.required_slot_count();
        if let TermoCompletionPolicy::AtLeast(n) = self.completion_policy
            && (n == 0 || n > required)
        {
            return Err(TermoError::InvalidCompletionPolicy {
                policy: self.completion_policy,
                required_slot_count: required,
            });
        }
        if required > 0 && !self.satisfies_management_floor() {
            return Err(TermoError::ManagementFloorNotSatisfiable {
                policy: self.completion_policy,
            });
        }
        Ok(())
    }

    /// Validate everything that must hold before the content can be frozen.
    ///
    /// Two of these checks are the feature's only legally-grounded ones:
    /// [`TermoError::NoSignatories`] (F6) and [`TermoError::ForbiddenCapacity`] (F5).
    /// Every other check is product or assurance policy.
    pub fn validate(&self) -> Result<(), TermoError> {
        if self.title.trim().is_empty() {
            return Err(TermoError::EmptyField("title"));
        }
        if self.title.chars().count() > MAX_TERMO_TEXT_CHARS {
            return Err(TermoError::TextTooLong {
                field: "title",
                max_chars: MAX_TERMO_TEXT_CHARS,
            });
        }

        if self.body.is_empty() {
            return Err(TermoError::EmptyBody);
        }
        if self.body.len() > MAX_TERMO_CLAUSES {
            return Err(TermoError::TooManyClauses {
                count: self.body.len(),
                max: MAX_TERMO_CLAUSES,
            });
        }
        let mut seen_clauses = std::collections::HashSet::with_capacity(self.body.len());
        for clause in &self.body {
            if !seen_clauses.insert(clause.id) {
                return Err(TermoError::DuplicateClauseId(clause.id));
            }
            clause.validate()?;
        }

        self.fields.validate(self.kind)?;

        // F6 (LAW): a termo that nobody draws up has no author.
        if self.signatories.is_empty() {
            return Err(TermoError::NoSignatories);
        }
        let mut seen_slots = std::collections::HashSet::with_capacity(self.signatories.len());
        let mut seen_orders = std::collections::HashSet::with_capacity(self.signatories.len());
        for slot in &self.signatories {
            if !seen_slots.insert(slot.id) {
                return Err(TermoError::DuplicateSlotId(slot.id));
            }
            // Ambiguous ordering would make sequential PAdES non-deterministic.
            if !seen_orders.insert(slot.order) {
                return Err(TermoError::DuplicateSlotOrder(slot.order));
            }
            slot.validate()?;
        }
        if self.required_slot_count() == 0 {
            return Err(TermoError::NoRequiredSlots);
        }

        self.validate_policy()
    }

    /// Freeze the content and begin collecting signatures (`Draft -> Signing`).
    ///
    /// `template_id` is pinned here so the rendered PDF/A is reproducible; the capacity model
    /// depends on that determinism.
    pub fn advance_to_signing(
        &mut self,
        template_id: impl Into<String>,
        now: OffsetDateTime,
    ) -> Result<(), TermoError> {
        if self.state != TermoState::Draft {
            return Err(TermoError::InvalidTransition {
                from: self.state,
                to: TermoState::Signing,
            });
        }
        self.validate()?;
        self.template_id = Some(template_id.into());
        self.signing_started_at = Some(now);
        self.state = TermoState::Signing;
        Ok(())
    }

    /// Return to `Draft`, discarding the frozen snapshot.
    ///
    /// Permitted **only** while zero signatures have been collected: a withdrawal after a
    /// signature would leave that signature binding bytes the instrument no longer has.
    pub fn withdraw_to_draft(&mut self) -> Result<(), TermoError> {
        if self.state != TermoState::Signing {
            return Err(TermoError::InvalidTransition {
                from: self.state,
                to: TermoState::Draft,
            });
        }
        if self.signatories.iter().any(|slot| slot.signed) {
            return Err(TermoError::SignaturesAlreadyCollected);
        }
        self.template_id = None;
        self.signing_started_at = None;
        self.state = TermoState::Draft;
        Ok(())
    }

    /// Record that a signature was collected for `slot_id`.
    ///
    /// Enforces the sequential order: a slot cannot sign while an earlier **required** slot
    /// is unsigned, because signer *n+1* signs signer *n*'s output.
    pub fn mark_slot_signed(
        &mut self,
        slot_id: Uuid,
        signature_id: Option<Uuid>,
        now: OffsetDateTime,
    ) -> Result<(), TermoError> {
        if self.state != TermoState::Signing {
            return Err(TermoError::NotSigning(self.state));
        }
        let index = self
            .signatories
            .iter()
            .position(|slot| slot.id == slot_id)
            .ok_or(TermoError::SlotNotFound(slot_id))?;
        if self.signatories[index].signed {
            return Err(TermoError::SlotAlreadySigned(slot_id));
        }
        let order = self.signatories[index].order;
        if let Some(waiting_on) = self
            .signatories
            .iter()
            .filter(|slot| slot.required && !slot.signed && slot.order < order)
            .min_by_key(|slot| slot.order)
        {
            return Err(TermoError::SequentialOrderBlocked {
                blocked: slot_id,
                waiting_on: waiting_on.id,
            });
        }
        let slot = &mut self.signatories[index];
        slot.signed = true;
        slot.signed_at = Some(now);
        slot.signature_id = signature_id;
        Ok(())
    }

    /// Required slots that still block completion under the current policy.
    #[must_use]
    pub fn blocking_required_slot_ids(&self) -> Vec<Uuid> {
        self.required_slots()
            .filter(|slot| !slot.signed)
            .map(|slot| slot.id)
            .collect()
    }

    /// Progress towards completion.
    #[must_use]
    pub fn completion_summary(&self) -> TermoCompletionSummary {
        let required_slot_count = self.required_slot_count();
        let signed_required_slot_count =
            u16::try_from(self.required_slots().filter(|slot| slot.signed).count())
                .unwrap_or(u16::MAX);
        TermoCompletionSummary {
            policy: self.completion_policy,
            required_slot_count,
            signed_required_slot_count,
            threshold: self.completion_policy.threshold(required_slot_count),
            blocking_required_slot_ids: self.blocking_required_slot_ids(),
            complete: self.ensure_completable().is_ok(),
        }
    }

    /// Whether the completion policy is satisfied.
    ///
    /// Mirrors [`crate::external_signing::ExternalSignatureEnvelope`]'s completion vocabulary
    /// and error shapes deliberately, so the two slot models report failures the same way.
    ///
    /// This is only half the gate the open/close endpoints apply: the other half — that every
    /// collected signature binds the frozen signing snapshot — is a byte check that belongs to
    /// the signing pipeline, not to the domain model.
    pub fn ensure_completable(&self) -> Result<(), TermoError> {
        let required_slot_count = self.required_slot_count();
        if required_slot_count == 0 {
            return Err(TermoError::NoRequiredSlots);
        }
        let signed = u16::try_from(self.required_slots().filter(|slot| slot.signed).count())
            .unwrap_or(u16::MAX);
        if signed < self.completion_policy.threshold(required_slot_count) {
            return Err(TermoError::RequiredSlotsNotSigned {
                slot_ids: self.blocking_required_slot_ids(),
            });
        }
        Ok(())
    }

    /// Mark the instrument as having taken effect (`Signing -> Sealed`).
    ///
    /// Refuses unless the completion policy is satisfied. The caller performs the
    /// corresponding [`crate::book::Book::open`] / [`crate::book::Book::close`] and the
    /// ledger append in the same durable commit.
    pub fn seal(&mut self, now: OffsetDateTime) -> Result<(), TermoError> {
        if self.state != TermoState::Signing {
            return Err(TermoError::InvalidTransition {
                from: self.state,
                to: TermoState::Sealed,
            });
        }
        self.ensure_completable()?;
        self.sealed_at = Some(now);
        self.state = TermoState::Sealed;
        Ok(())
    }

    /// The clause records as they will appear in the sealed payload.
    #[must_use]
    pub fn body_records(&self) -> Vec<TermoClauseRecord> {
        self.body.iter().map(TermoClause::to_record).collect()
    }

    /// The declared signatory records, in slot order.
    #[must_use]
    pub fn declared_signatory_records(&self) -> Vec<TermoSignatory> {
        let mut slots: Vec<_> = self.signatories.iter().collect();
        slots.sort_by_key(|slot| slot.order);
        slots
            .into_iter()
            .map(TermoSignatorySlot::to_declared_record)
            .collect()
    }

    /// The **collected** signatures, in slot order. Empty for a legacy or one-shot termo,
    /// which is exactly the distinction the UI must preserve: declared names are not
    /// signatures.
    #[must_use]
    pub fn collected_signature_records(&self) -> Vec<TermoCollectedSignature> {
        let mut slots: Vec<_> = self.signatories.iter().collect();
        slots.sort_by_key(|slot| slot.order);
        slots
            .into_iter()
            .filter_map(TermoSignatorySlot::to_collected_record)
            .collect()
    }

    /// Project this instrument into the sealed [`TermoDeAbertura`] payload.
    ///
    /// The entity snapshot and numbering scheme are supplied by the caller, which holds the
    /// entity aggregate. The payload binds the filled body and the collected signatures, so
    /// the genesis event digests the final, filled, signed termo rather than declared names.
    pub fn project_abertura(
        &self,
        entity_name: impl Into<String>,
        entity_nipc: impl Into<String>,
        entity_seat: impl Into<String>,
        numbering_scheme: crate::book::NumberingScheme,
    ) -> Result<TermoDeAbertura, TermoError> {
        if self.kind != TermoKind::Abertura {
            return Err(TermoError::WrongKind {
                expected: TermoKind::Abertura,
                actual: self.kind,
            });
        }
        let opening_date = self
            .fields
            .instrument_date
            .ok_or(TermoError::MissingField("instrument_date"))?;
        let declared = self.declared_signatory_records();
        Ok(TermoDeAbertura {
            entity_name: entity_name.into(),
            entity_nipc: entity_nipc.into(),
            entity_seat: entity_seat.into(),
            purpose: self.fields.purpose.clone().unwrap_or_default(),
            numbering_scheme,
            opening_date,
            required_signatories: declared.iter().map(TermoSignatory::legacy_label).collect(),
            required_signatory_records: declared,
            termo_instrument_id: Some(self.id.0),
            title: Some(self.title.clone()),
            book_number: self.fields.book_number,
            place: self.fields.place.clone(),
            page_capacity: self.fields.page_capacity,
            body: self.body_records(),
            collected_signatures: self.collected_signature_records(),
        })
    }

    /// Project this instrument into the sealed [`TermoDeEncerramento`] payload.
    ///
    /// `ata_count` and `pages_used_at_close` are **derived from the book**, never from
    /// operator input: the closing termo states facts about the book, and the book knows the
    /// answers. [`crate::book::Book::close`] overwrites `ata_count` again defensively.
    pub fn project_encerramento(
        &self,
        ata_count: u64,
        pages_used_at_close: Option<u32>,
    ) -> Result<TermoDeEncerramento, TermoError> {
        if self.kind != TermoKind::Encerramento {
            return Err(TermoError::WrongKind {
                expected: TermoKind::Encerramento,
                actual: self.kind,
            });
        }
        let closing_date = self
            .fields
            .instrument_date
            .ok_or(TermoError::MissingField("instrument_date"))?;
        let reason = self
            .fields
            .closing_reason
            .clone()
            .ok_or(TermoError::MissingField("closing_reason"))?;
        let declared = self.declared_signatory_records();
        Ok(TermoDeEncerramento {
            ata_count,
            reason,
            closing_date,
            required_signatories: declared.iter().map(TermoSignatory::legacy_label).collect(),
            required_signatory_records: declared,
            termo_instrument_id: Some(self.id.0),
            title: Some(self.title.clone()),
            book_number: self.fields.book_number,
            place: self.fields.place.clone(),
            body: self.body_records(),
            collected_signatures: self.collected_signature_records(),
            pages_used_at_close,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::{date, datetime};

    fn now() -> OffsetDateTime {
        datetime!(2026-07-19 10:00 UTC)
    }

    fn draft_abertura() -> TermoInstrument {
        let mut termo = TermoInstrument::draft(
            BookId::new(),
            TermoKind::Abertura,
            "Termo de abertura",
            now(),
        );
        termo.fields.instrument_date = Some(date!(2026 - 01 - 15));
        termo.fields.purpose = Some("livro de atas da gerência".into());
        termo.body = vec![TermoClause::from_template(
            None,
            "Este livro destina-se ao lançamento das atas da gerência.",
        )];
        termo
            .add_signatory(TermoSignatorySlot::required(
                "Amélia Marques",
                SignatoryCapacity::Manager,
                0,
            ))
            .unwrap();
        termo
    }

    #[test]
    fn a_valid_abertura_freezes_and_pins_its_template() {
        let mut termo = draft_abertura();
        assert!(termo.is_mutable());
        termo
            .advance_to_signing("csc-termo-abertura", now())
            .unwrap();
        assert_eq!(termo.state, TermoState::Signing);
        assert_eq!(termo.template_id.as_deref(), Some("csc-termo-abertura"));
        assert!(!termo.is_mutable());
        assert!(matches!(
            termo.set_title("outro"),
            Err(TermoError::NotMutable(TermoState::Signing))
        ));
    }

    #[test]
    fn default_page_capacity_is_one_hundred() {
        assert_eq!(DEFAULT_PAGE_CAPACITY, 100);
        assert_eq!(
            TermoFields::for_abertura().page_capacity,
            Some(DEFAULT_PAGE_CAPACITY)
        );
        assert_eq!(TermoFields::for_encerramento().page_capacity, None);
    }

    // ---- F6: at least one signatory (LAW) ----

    #[test]
    fn a_termo_with_no_signatory_cannot_be_frozen() {
        let mut termo = draft_abertura();
        termo.signatories.clear();
        assert!(matches!(
            termo.advance_to_signing("csc-termo-abertura", now()),
            Err(TermoError::NoSignatories)
        ));
        assert_eq!(termo.state, TermoState::Draft);
    }

    #[test]
    fn a_termo_with_only_optional_slots_cannot_be_frozen() {
        let mut termo = draft_abertura();
        termo.signatories = vec![TermoSignatorySlot::optional(
            "Secretária",
            SignatoryCapacity::Secretary,
            0,
        )];
        assert!(matches!(
            termo.advance_to_signing("csc-termo-abertura", now()),
            Err(TermoError::NoRequiredSlots)
        ));
    }

    // ---- F5: the capacity allow-list (LAW) ----

    #[test]
    fn the_capacity_allow_list_mirrors_art_31_n2() {
        for allowed in [
            SignatoryCapacity::Manager,
            SignatoryCapacity::Administrator,
            SignatoryCapacity::Member,
            SignatoryCapacity::Secretary,
            SignatoryCapacity::Chair,
        ] {
            assert!(is_permitted_termo_capacity(allowed), "{allowed:?}");
        }
        for refused in [SignatoryCapacity::Attorney, SignatoryCapacity::CondoOwner] {
            assert!(!is_permitted_termo_capacity(refused), "{refused:?}");
        }
    }

    #[test]
    fn a_forbidden_capacity_is_rejected_at_the_freeze() {
        let mut termo = draft_abertura();
        termo.signatories = vec![TermoSignatorySlot::required(
            "Procurador",
            SignatoryCapacity::Attorney,
            0,
        )];
        assert!(matches!(
            termo.advance_to_signing("csc-termo-abertura", now()),
            Err(TermoError::ForbiddenCapacity {
                capacity: SignatoryCapacity::Attorney,
                ..
            })
        ));
    }

    // ---- qualidade "Other" (D1): an ASSURANCE escape hatch, never the legal allow-list ----

    #[test]
    fn other_is_never_in_the_legal_capacity_allow_list() {
        // The allow-list stays a pure closed set: `Other` is outside art. 31.º n.º 2, note or no
        // note. Admissibility of an `Other` signatory is a separate, broader slot-level check.
        assert!(!is_permitted_termo_capacity(SignatoryCapacity::Other));
        assert!(!is_management_capacity(SignatoryCapacity::Other));
    }

    #[test]
    fn an_other_signatory_needs_a_note_but_then_is_admitted() {
        let mut termo = draft_abertura();
        // Gerente (clears the floor) plus an out-of-list co-signer with no note yet.
        termo.signatories = vec![
            TermoSignatorySlot::required("Gerente", SignatoryCapacity::Manager, 0),
            TermoSignatorySlot::required("Liquidatária", SignatoryCapacity::Other, 1),
        ];
        assert!(matches!(
            termo.advance_to_signing("csc-termo-abertura", now()),
            Err(TermoError::MissingSignatoryCapacityNote { .. })
        ));
        // With the required note it is admitted (the gerente still clears the floor).
        termo.signatories[1] =
            TermoSignatorySlot::required("Liquidatária", SignatoryCapacity::Other, 1)
                .with_capacity_note("liquidatária judicial");
        termo
            .advance_to_signing("csc-termo-abertura", now())
            .unwrap();
    }

    #[test]
    fn a_blank_other_note_is_rejected() {
        let mut termo = draft_abertura();
        termo.signatories = vec![
            TermoSignatorySlot::required("Gerente", SignatoryCapacity::Manager, 0),
            TermoSignatorySlot::required("Outra", SignatoryCapacity::Other, 1)
                .with_capacity_note("   "),
        ];
        assert!(matches!(
            termo.advance_to_signing("csc-termo-abertura", now()),
            Err(TermoError::MissingSignatoryCapacityNote { .. })
        ));
    }

    #[test]
    fn a_note_on_a_modelled_capacity_is_rejected() {
        // The structured capacity stays a closed set: a stray note is an error, not silently
        // dropped.
        let mut termo = draft_abertura();
        termo.signatories = vec![
            TermoSignatorySlot::required("Gerente", SignatoryCapacity::Manager, 0)
                .with_capacity_note("não aplicável"),
        ];
        assert!(matches!(
            termo.advance_to_signing("csc-termo-abertura", now()),
            Err(TermoError::UnexpectedSignatoryCapacityNote { .. })
        ));
    }

    #[test]
    fn an_other_only_slate_counts_as_a_signatory_but_never_clears_the_management_floor() {
        let mut termo = draft_abertura();
        termo.signatories = vec![
            TermoSignatorySlot::required("Liquidatária", SignatoryCapacity::Other, 0)
                .with_capacity_note("liquidatária judicial"),
        ];
        // It is a signatory (not NoSignatories / NoRequiredSlots) and passes the slot check…
        assert_eq!(termo.required_slot_count(), 1);
        assert!(!termo.satisfies_management_floor());
        // …but a book cannot be opened on an out-of-list signatory alone.
        assert!(matches!(
            termo.advance_to_signing("csc-termo-abertura", now()),
            Err(TermoError::ManagementFloorNotSatisfiable { .. })
        ));
    }

    #[test]
    fn the_other_note_is_projected_into_the_payload_as_assurance() {
        let mut termo = draft_abertura();
        termo.signatories = vec![
            TermoSignatorySlot::required("Gerente", SignatoryCapacity::Manager, 0),
            TermoSignatorySlot::required("Liquidatária", SignatoryCapacity::Other, 1)
                .with_capacity_note("liquidatária judicial"),
        ];
        termo
            .advance_to_signing("csc-termo-abertura", now())
            .unwrap();
        let g = termo.signatories[0].id;
        let o = termo.signatories[1].id;
        termo.mark_slot_signed(g, None, now()).unwrap();
        termo.mark_slot_signed(o, None, now()).unwrap();
        termo.seal(now()).unwrap();

        let payload = termo
            .project_abertura(
                "Encosto Estratégico Lda",
                "503004642",
                "Lisboa",
                crate::book::NumberingScheme::Sequential,
            )
            .unwrap();
        let declared = payload
            .required_signatory_records
            .iter()
            .find(|r| r.capacity == Some(SignatoryCapacity::Other))
            .expect("the Other declared record survives");
        assert_eq!(
            declared.capacity_note.as_deref(),
            Some("liquidatária judicial")
        );
        let collected = payload
            .collected_signatures
            .iter()
            .find(|s| s.capacity == SignatoryCapacity::Other)
            .expect("the Other collected signature survives");
        assert_eq!(
            collected.capacity_note.as_deref(),
            Some("liquidatária judicial")
        );
    }

    #[test]
    fn predecessor_note_is_length_bounded() {
        let mut termo = draft_abertura();
        termo.fields.predecessor_note = Some("x".repeat(MAX_TERMO_TEXT_CHARS + 1));
        assert!(matches!(
            termo.validate(),
            Err(TermoError::TextTooLong {
                field: "predecessor_note",
                ..
            })
        ));
        termo.fields.predecessor_note = Some("Livro em papel n.º 3, arquivo físico".into());
        termo.validate().unwrap();
    }

    // ---- the gerência floor (PRODUCT, over a LAW allow-list) ----

    #[test]
    fn a_policy_that_could_complete_on_a_secretary_alone_is_rejected() {
        let mut termo = draft_abertura();
        termo.signatories = vec![
            TermoSignatorySlot::required("Gerente", SignatoryCapacity::Manager, 0),
            TermoSignatorySlot::required("Secretária", SignatoryCapacity::Secretary, 1),
        ];
        // One of two, where the secretária alone could satisfy it.
        assert!(matches!(
            termo.set_completion_policy(TermoCompletionPolicy::AtLeast(1)),
            Err(TermoError::ManagementFloorNotSatisfiable { .. })
        ));
        // The rejected policy is not left in place.
        assert_eq!(
            termo.completion_policy,
            TermoCompletionPolicy::AllRequired,
            "a rejected policy change must not stick"
        );
        assert!(matches!(
            termo.set_completion_policy(TermoCompletionPolicy::SingleQualifying),
            Err(TermoError::ManagementFloorNotSatisfiable { .. })
        ));
        // Two of two forces the gerente to sign, so it clears the floor.
        termo
            .set_completion_policy(TermoCompletionPolicy::AtLeast(2))
            .unwrap();
    }

    #[test]
    fn single_qualifying_is_accepted_when_every_required_slot_is_management() {
        let mut termo = draft_abertura();
        termo.signatories = vec![
            TermoSignatorySlot::required("Gerente A", SignatoryCapacity::Manager, 0),
            TermoSignatorySlot::required("Gerente B", SignatoryCapacity::Manager, 1),
        ];
        termo
            .set_completion_policy(TermoCompletionPolicy::SingleQualifying)
            .unwrap();
        assert!(termo.satisfies_management_floor());
    }

    #[test]
    fn a_slate_with_no_management_slot_is_rejected() {
        let mut termo = draft_abertura();
        termo.signatories = vec![TermoSignatorySlot::required(
            "Presidente da mesa",
            SignatoryCapacity::Chair,
            0,
        )];
        assert!(!termo.satisfies_management_floor());
        assert!(matches!(
            termo.advance_to_signing("csc-termo-abertura", now()),
            Err(TermoError::ManagementFloorNotSatisfiable { .. })
        ));
    }

    #[test]
    fn at_least_n_must_be_within_the_required_slot_count() {
        let mut termo = draft_abertura();
        assert!(matches!(
            termo.set_completion_policy(TermoCompletionPolicy::AtLeast(0)),
            Err(TermoError::InvalidCompletionPolicy { .. })
        ));
        assert!(matches!(
            termo.set_completion_policy(TermoCompletionPolicy::AtLeast(9)),
            Err(TermoError::InvalidCompletionPolicy { .. })
        ));
    }

    // ---- completion ----

    #[test]
    fn all_required_needs_every_required_slot_two_of_two() {
        let mut termo = draft_abertura();
        termo.signatories = vec![
            TermoSignatorySlot::required("Gerente A", SignatoryCapacity::Manager, 0),
            TermoSignatorySlot::required("Gerente B", SignatoryCapacity::Manager, 1),
        ];
        termo
            .advance_to_signing("csc-termo-abertura", now())
            .unwrap();

        let first = termo.signatories[0].id;
        let second = termo.signatories[1].id;

        assert!(matches!(
            termo.ensure_completable(),
            Err(TermoError::RequiredSlotsNotSigned { .. })
        ));
        termo.mark_slot_signed(first, None, now()).unwrap();
        assert!(matches!(
            termo.ensure_completable(),
            Err(TermoError::RequiredSlotsNotSigned { ref slot_ids }) if slot_ids == &vec![second]
        ));
        termo.mark_slot_signed(second, None, now()).unwrap();
        termo.ensure_completable().unwrap();

        termo.seal(now()).unwrap();
        assert_eq!(termo.state, TermoState::Sealed);
        assert_eq!(termo.sealed_at, Some(now()));
    }

    #[test]
    fn one_of_two_completes_after_a_single_management_signature() {
        let mut termo = draft_abertura();
        termo.signatories = vec![
            TermoSignatorySlot::required("Gerente A", SignatoryCapacity::Manager, 0),
            TermoSignatorySlot::required("Gerente B", SignatoryCapacity::Manager, 1),
        ];
        termo
            .set_completion_policy(TermoCompletionPolicy::AtLeast(1))
            .unwrap();
        termo
            .advance_to_signing("csc-termo-abertura", now())
            .unwrap();
        let first = termo.signatories[0].id;
        termo.mark_slot_signed(first, None, now()).unwrap();
        termo.ensure_completable().unwrap();
        assert!(termo.completion_summary().complete);
        assert_eq!(termo.completion_summary().signed_required_slot_count, 1);
    }

    #[test]
    fn an_incomplete_termo_cannot_be_sealed() {
        let mut termo = draft_abertura();
        termo
            .advance_to_signing("csc-termo-abertura", now())
            .unwrap();
        assert!(matches!(
            termo.seal(now()),
            Err(TermoError::RequiredSlotsNotSigned { .. })
        ));
        assert_eq!(termo.state, TermoState::Signing);
    }

    // ---- signing mechanics ----

    #[test]
    fn signatures_follow_slot_order_because_each_signs_the_previous_output() {
        let mut termo = draft_abertura();
        termo.signatories = vec![
            TermoSignatorySlot::required("Gerente A", SignatoryCapacity::Manager, 0),
            TermoSignatorySlot::required("Gerente B", SignatoryCapacity::Manager, 1),
        ];
        termo
            .advance_to_signing("csc-termo-abertura", now())
            .unwrap();
        let first = termo.signatories[0].id;
        let second = termo.signatories[1].id;

        assert!(matches!(
            termo.mark_slot_signed(second, None, now()),
            Err(TermoError::SequentialOrderBlocked { .. })
        ));
        termo.mark_slot_signed(first, None, now()).unwrap();
        termo.mark_slot_signed(second, None, now()).unwrap();
        assert!(matches!(
            termo.mark_slot_signed(second, None, now()),
            Err(TermoError::SlotAlreadySigned(_))
        ));
    }

    #[test]
    fn a_draft_termo_cannot_collect_signatures() {
        let mut termo = draft_abertura();
        let slot = termo.signatories[0].id;
        assert!(matches!(
            termo.mark_slot_signed(slot, None, now()),
            Err(TermoError::NotSigning(TermoState::Draft))
        ));
    }

    #[test]
    fn withdraw_is_allowed_only_before_the_first_signature() {
        let mut termo = draft_abertura();
        termo
            .advance_to_signing("csc-termo-abertura", now())
            .unwrap();
        termo.withdraw_to_draft().unwrap();
        assert_eq!(termo.state, TermoState::Draft);
        assert!(termo.template_id.is_none());
        assert!(termo.signing_started_at.is_none());

        termo
            .advance_to_signing("csc-termo-abertura", now())
            .unwrap();
        let slot = termo.signatories[0].id;
        termo.mark_slot_signed(slot, None, now()).unwrap();
        assert!(matches!(
            termo.withdraw_to_draft(),
            Err(TermoError::SignaturesAlreadyCollected)
        ));
    }

    #[test]
    fn duplicate_slot_orders_are_rejected() {
        let mut termo = draft_abertura();
        termo.signatories = vec![
            TermoSignatorySlot::required("Gerente A", SignatoryCapacity::Manager, 0),
            TermoSignatorySlot::required("Gerente B", SignatoryCapacity::Manager, 0),
        ];
        assert!(matches!(
            termo.advance_to_signing("csc-termo-abertura", now()),
            Err(TermoError::DuplicateSlotOrder(0))
        ));
    }

    // ---- fields ----

    #[test]
    fn an_abertura_must_declare_a_capacity_within_range() {
        let mut termo = draft_abertura();
        termo.fields.page_capacity = None;
        assert!(matches!(
            termo.validate(),
            Err(TermoError::MissingField("page_capacity"))
        ));
        termo.fields.page_capacity = Some(0);
        assert!(matches!(
            termo.validate(),
            Err(TermoError::PageCapacityOutOfRange { .. })
        ));
        termo.fields.page_capacity = Some(MAX_PAGE_CAPACITY + 1);
        assert!(matches!(
            termo.validate(),
            Err(TermoError::PageCapacityOutOfRange { .. })
        ));
        termo.fields.page_capacity = Some(MAX_PAGE_CAPACITY);
        termo.validate().unwrap();
    }

    #[test]
    fn an_encerramento_needs_a_reason_and_a_note_when_it_is_other() {
        let mut termo =
            TermoInstrument::draft(BookId::new(), TermoKind::Encerramento, "Termo", now());
        termo.fields.instrument_date = Some(date!(2026 - 12 - 31));
        termo.body = vec![TermoClause::from_template(None, "Encerra-se o livro.")];
        termo
            .add_signatory(TermoSignatorySlot::required(
                "Gerente",
                SignatoryCapacity::Manager,
                0,
            ))
            .unwrap();

        assert!(matches!(
            termo.validate(),
            Err(TermoError::MissingField("closing_reason"))
        ));
        termo.fields.closing_reason = Some(ClosingReason::Other { note: "   ".into() });
        assert!(matches!(
            termo.validate(),
            Err(TermoError::MissingField("closing_reason.note"))
        ));
        termo.fields.closing_reason = Some(ClosingReason::Other {
            note: "novo exercício económico".into(),
        });
        termo.validate().unwrap();
    }

    #[test]
    fn capacity_is_not_applicable_to_an_encerramento() {
        let mut termo =
            TermoInstrument::draft(BookId::new(), TermoKind::Encerramento, "Termo", now());
        termo.fields.page_capacity = Some(100);
        termo.fields.closing_reason = Some(ClosingReason::BookFull);
        termo.fields.instrument_date = Some(date!(2026 - 12 - 31));
        termo.body = vec![TermoClause::from_template(None, "Encerra-se o livro.")];
        termo
            .add_signatory(TermoSignatorySlot::required(
                "Gerente",
                SignatoryCapacity::Manager,
                0,
            ))
            .unwrap();
        assert!(matches!(
            termo.validate(),
            Err(TermoError::FieldNotApplicable {
                field: "page_capacity",
                ..
            })
        ));
    }

    // ---- body ----

    #[test]
    fn the_body_must_be_non_empty_and_bounded() {
        let mut termo = draft_abertura();
        termo.body.clear();
        assert!(matches!(termo.validate(), Err(TermoError::EmptyBody)));

        termo.body = (0..=MAX_TERMO_CLAUSES)
            .map(|i| TermoClause::user_added(None, format!("cláusula {i}")))
            .collect();
        assert!(matches!(
            termo.validate(),
            Err(TermoError::TooManyClauses { .. })
        ));

        termo.body = vec![TermoClause::user_added(
            None,
            "x".repeat(MAX_CLAUSE_TEXT_BYTES + 1),
        )];
        assert!(matches!(
            termo.validate(),
            Err(TermoError::ClauseTextTooLong { .. })
        ));
    }

    #[test]
    fn editing_a_seeded_clause_records_that_a_human_changed_it() {
        let mut clause = TermoClause::from_template(None, "texto original");
        assert_eq!(clause.origin, ClauseOrigin::TemplateDefault);
        clause.edit_text("texto revisto");
        assert_eq!(clause.origin, ClauseOrigin::UserEdited);
        clause.edit_text("outra revisão");
        assert_eq!(clause.origin, ClauseOrigin::UserEdited);
    }

    // ---- projection ----

    #[test]
    fn projection_binds_the_filled_body_and_the_collected_signatures() {
        let mut termo = draft_abertura();
        termo.fields.book_number = Some(2);
        termo.fields.place = Some("Lisboa".into());
        termo
            .advance_to_signing("csc-termo-abertura", now())
            .unwrap();
        let slot = termo.signatories[0].id;
        let signature = Uuid::new_v4();
        termo
            .mark_slot_signed(slot, Some(signature), now())
            .unwrap();
        termo.seal(now()).unwrap();

        let payload = termo
            .project_abertura(
                "Encosto Estratégico Lda",
                "503004642",
                "Lisboa",
                crate::book::NumberingScheme::Sequential,
            )
            .unwrap();

        assert_eq!(payload.termo_instrument_id, Some(termo.id.0));
        assert_eq!(payload.title.as_deref(), Some("Termo de abertura"));
        assert_eq!(payload.book_number, Some(2));
        assert_eq!(payload.page_capacity, Some(DEFAULT_PAGE_CAPACITY));
        assert_eq!(payload.body.len(), 1);
        assert_eq!(payload.collected_signatures.len(), 1);
        assert_eq!(
            payload.collected_signatures[0].signature_id,
            Some(signature)
        );
        // Draft-only provenance never crosses into the payload.
        let json = serde_json::to_string(&payload).unwrap();
        assert!(!json.contains("TemplateDefault"), "{json}");
        assert!(!json.contains("origin"), "{json}");
    }

    #[test]
    fn a_termo_with_declared_but_uncollected_signatures_projects_no_collected_records() {
        let termo = draft_abertura();
        assert!(termo.collected_signature_records().is_empty());
        assert_eq!(termo.declared_signatory_records().len(), 1);
    }

    #[test]
    fn projecting_the_wrong_kind_is_refused() {
        let termo = draft_abertura();
        assert!(matches!(
            termo.project_encerramento(3, Some(12)),
            Err(TermoError::WrongKind {
                expected: TermoKind::Encerramento,
                actual: TermoKind::Abertura,
            })
        ));
    }

    #[test]
    fn instrument_round_trips_through_serde() {
        let termo = draft_abertura();
        let json = serde_json::to_string(&termo).unwrap();
        let back: TermoInstrument = serde_json::from_str(&json).unwrap();
        assert_eq!(termo, back);
    }
}
