//! # chancela-core
//!
//! Domain core for **Chancela**, a Portuguese digital minute-book (*livro de atas*)
//! platform. This crate models the legal objects that everything else is built around:
//!
//! - [`Entity`] — the legal person that owns books (commercial company, condominium,
//!   association, foundation, cooperative), identified by a validated [`Nipc`].
//! - [`Book`] — a *livro de atas* for one organ, with the `Created -> Open -> Closed`
//!   lifecycle framed by a [`TermoDeAbertura`] and a [`TermoDeEncerramento`]
//!   (WFL-10..14). The sealed termo de abertura is the genesis event of the book's
//!   hash chain (WFL-11 / DAT-11).
//! - [`Act`] — an *ata*, with the
//!   `Draft -> Review -> Convened -> Deliberated -> TextApproved -> Signing -> Sealed
//!   -> Archived` state machine (WFL-01). Sealing assigns a sequential *ata* number
//!   within the book (WFL-12), freezes the payload, and makes it append-only
//!   (WFL-20 / DAT-12).
//! - [`RulePack`] — pluggable compliance authority (rule packs are authority, templates
//!   are conveniences, WFL-31); [`CscArt63RulePack`] is a minimal CSC art. 63.º pack.
//!
//! Sealing (see [`seal`]) records the event into a [`chancela_ledger::Ledger`] hash
//! chain (DAT-10/11).
//!
//! Legal references in doc comments cite the Código das Sociedades Comerciais (CSC),
//! DL 76-A/2006, DL 268/94, and related instruments; they document intent and are not
//! legal advice.

pub mod act;
pub mod book;
pub mod document_model;
pub mod entity;
pub mod error;
pub mod external_signing;
pub mod profile;
pub mod rules;
pub mod seal;

pub use act::{
    Act, ActId, ActState, AgendaItem, Attachment, AttachmentKind, AttendanceWeight, Attendee,
    Convening, ConveningRecipient, DeliberationItem, DispatchChannel, DocumentReference,
    MeetingChannel, MemberStatement, Mesa, PresenceMode, SealMetadata, SecondCall,
    SignatoryCapacity, SignatorySlot, VoteResult, WRITTEN_RESOLUTION_EVIDENCE_STATUS_BOUNDARY,
    WrittenResolutionEvidence, WrittenResolutionEvidenceItem, WrittenResolutionEvidenceStatus,
    WrittenResolutionEvidenceSummary, written_resolution_evidence_summary,
};
pub use book::{
    Book, BookId, BookKind, BookState, LegalHold, NumberingScheme, TermoDeAbertura,
    TermoDeEncerramento, TermoSignatory,
};
pub use document_model::{
    Block, DocumentModel, KvRow, LifecycleStage, Run, SignatureSlot, VoteRow,
};
pub use entity::{
    Entity, EntityFamily, EntityId, EntityKind, Majority, Nipc, Quorum, StatuteOverrides,
};
pub use error::{ActError, BookError, CoreError, NipcError, SealError};
pub use external_signing::{
    ExternalSignatureCompletionSummary, ExternalSignatureEnvelope, ExternalSignatureEnvelopeId,
    ExternalSignatureEvidence, ExternalSignerSlot, ExternalSignerSlotId, ExternalSignerSlotStatus,
    ExternalSigningError, ExternalSigningOrderPolicy,
};
pub use profile::{
    CalendarPreset, EntityProfile, ProfilePack, SignaturePolicyHint, profile_for, rule_pack_for,
};
pub use rules::{
    AssociacaoRulePack, ComplianceIssue, CondominioRulePack, CooperativaRulePack, CscArt63RulePack,
    FundacaoRulePack, LegalBasis, LegalBasisVerification, RulePack, Severity, statute_findings,
};
pub use seal::{SealOutcome, open_and_seal_book, seal_act};
