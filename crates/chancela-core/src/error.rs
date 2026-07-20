//! Error types for the domain core.
//!
//! Each subsystem carries its own typed error; [`CoreError`] aggregates them for callers
//! (such as `chancela-api`) that would rather match a single enum.

use thiserror::Error;
use uuid::Uuid;

use crate::act::{ActState, SignatoryCapacity};
use crate::book::BookState;
use crate::termo::{TermoCompletionPolicy, TermoKind, TermoState};

/// A NIPC (número de identificação de pessoa coletiva) failed validation.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum NipcError {
    /// Not exactly nine ASCII digits.
    #[error("NIPC must be 9 digits, got {0:?}")]
    Format(String),
    /// The mod-11 control digit does not match (CSC/registry anti-typo check).
    #[error("NIPC control digit is invalid for {0:?}")]
    CheckDigit(String),
}

/// A book lifecycle operation was not permitted in the book's current state.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum BookError {
    /// Tried to open a book that was not in the `Created` state (WFL-10).
    #[error("cannot open a book in state {0:?}; opening requires state Created")]
    NotOpenable(BookState),
    /// Tried to close a book that was not `Open` (WFL-13).
    #[error("cannot close a book in state {0:?}; closing requires state Open")]
    NotClosable(BookState),
    /// Tried to assign an ata number (or otherwise use the book) while it was not `Open`
    /// (WFL-14: an ata must not be created outside an open book).
    #[error("book is not open (state {0:?}); acts may only be created in an open book")]
    NotOpen(BookState),
    /// The kind declared by the closing termo did not match the book's kind, or the act
    /// being sealed belongs to a different book.
    #[error("act belongs to book {act_book}, not to this book {book}")]
    WrongBook {
        /// The book id recorded on the act.
        act_book: String,
        /// The id of the book the operation was invoked on.
        book: String,
    },
    /// The book has no room for the pages an act needs (F14).
    ///
    /// Raised at the act's content freeze, never mid-signature. The remedy is to close this
    /// book and continue in a successor. A book with no declared capacity never raises this.
    #[error(
        "book has no remaining capacity: {required} page(s) requested, \
         {used} used and {reserved} reserved of {capacity}"
    )]
    CapacityExceeded {
        /// Pages the book was opened with.
        capacity: u32,
        /// Pages consumed by sealed atas.
        used: u32,
        /// Pages held by atas frozen in signing.
        reserved: u32,
        /// Pages the refused operation asked for.
        required: u32,
    },
    /// A reservation release or conversion referred to more pages than are reserved.
    #[error("cannot settle {requested} reserved page(s); only {reserved} are reserved")]
    NoSuchReservation {
        /// Pages currently reserved.
        reserved: u32,
        /// Pages the operation asked to settle.
        requested: u32,
    },
    /// A declared page capacity fell outside the accepted bounds.
    #[error("page capacity {requested} is outside the accepted range {min}..={max}")]
    PageCapacityOutOfRange {
        /// The rejected value.
        requested: u32,
        /// Smallest accepted capacity.
        min: u32,
        /// Largest accepted capacity.
        max: u32,
    },
    /// The page arithmetic would overflow.
    #[error("page count arithmetic overflowed")]
    PageCountOverflow,
}

/// A termo instrument transition, mutation or validation was rejected.
///
/// Only two of these encode a legal requirement — [`TermoError::NoSignatories`] (CCom
/// art. 31.º n.º 2 requires the termo be *lavrado* by a qualified person, so a termo with no
/// signatory has no author) and [`TermoError::ForbiddenCapacity`] (the provision's closed list
/// of who may draw it up). Every other variant is product or evidentiary-assurance policy and
/// must not be surfaced as a legal mandate.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TermoError {
    /// A mutation was attempted after the content was frozen for signing.
    #[error("termo is not editable in state {0:?}; content freezes on entering Signing")]
    NotMutable(TermoState),
    /// The requested lifecycle transition is not legal from the current state.
    #[error("invalid termo transition from {from:?} to {to:?}")]
    InvalidTransition {
        /// State the instrument was in.
        from: TermoState,
        /// State the transition attempted to reach.
        to: TermoState,
    },
    /// A signature operation was attempted while the instrument was not collecting.
    #[error("termo is not collecting signatures (state {0:?})")]
    NotSigning(TermoState),
    /// **LAW** — CCom art. 31.º n.º 2: the termo must be drawn up by a qualified person, so an
    /// instrument with no signatory at all has no author.
    #[error("a termo must name at least one signatory (Código Comercial art. 31.º n.º 2)")]
    NoSignatories,
    /// Signatories exist but none is marked required, so nothing would ever have to be signed.
    #[error("a termo must have at least one required signatory")]
    NoRequiredSlots,
    /// **LAW** — the capacity is outside CCom art. 31.º n.º 2's closed list of who may draw up
    /// the termos.
    #[error(
        "capacity {capacity:?} may not draw up a termo; Código Comercial art. 31.º n.º 2 names \
         the administração, the members of the organ concerned, the secretário da sociedade \
         and the presidente da mesa da assembleia geral"
    )]
    ForbiddenCapacity {
        /// The slot that carried the refused capacity.
        slot_id: Uuid,
        /// The refused capacity.
        capacity: SignatoryCapacity,
    },
    /// The same slot id appears twice.
    #[error("duplicate termo signatory slot id {0}")]
    DuplicateSlotId(Uuid),
    /// Two slots claim the same position, which would make the signing order ambiguous.
    #[error("duplicate termo signatory slot order {0}")]
    DuplicateSlotOrder(u16),
    /// No slot with the requested id exists.
    #[error("termo signatory slot {0} was not found")]
    SlotNotFound(Uuid),
    /// The slot already carries a collected signature.
    #[error("termo signatory slot {0} has already signed")]
    SlotAlreadySigned(Uuid),
    /// A slot cannot sign while an earlier required slot is unsigned: in sequential PAdES,
    /// each signer signs the previous signer's output.
    #[error("termo signatory slot {blocked} waits for earlier required slot {waiting_on}")]
    SequentialOrderBlocked {
        /// The slot being held back.
        blocked: Uuid,
        /// The earlier required slot that must sign first.
        waiting_on: Uuid,
    },
    /// The completion policy is not yet satisfied.
    #[error("required termo signatory slots are not signed: {slot_ids:?}")]
    RequiredSlotsNotSigned {
        /// Required slot ids that still block completion.
        slot_ids: Vec<Uuid>,
    },
    /// The completion policy cannot be satisfied by the configured slots.
    #[error("completion policy {policy:?} is invalid for {required_slot_count} required slot(s)")]
    InvalidCompletionPolicy {
        /// The rejected policy.
        policy: TermoCompletionPolicy,
        /// How many slots are marked required.
        required_slot_count: u16,
    },
    /// The policy could complete without any management signature.
    ///
    /// **Product policy applied on top of the law, not a legal requirement.** The statute
    /// reads as a set of alternatives in which a secretário or presidente da mesa alone could
    /// suffice; requiring management at minimum is the product's own stricter rule.
    #[error(
        "completion policy {policy:?} could complete without a signature from the \
         administração; at least one required signatory must sign in a management capacity"
    )]
    ManagementFloorNotSatisfiable {
        /// The rejected policy.
        policy: TermoCompletionPolicy,
    },
    /// The termo has no clauses.
    #[error("a termo must have at least one clause")]
    EmptyBody,
    /// The body exceeds the clause cap.
    #[error("a termo may have at most {max} clauses, got {count}")]
    TooManyClauses {
        /// Clauses supplied.
        count: usize,
        /// Cap.
        max: usize,
    },
    /// The same clause id appears twice.
    #[error("duplicate termo clause id {0}")]
    DuplicateClauseId(Uuid),
    /// A clause carries no text.
    #[error("termo clause {clause_id} has no text")]
    EmptyClauseText {
        /// The offending clause.
        clause_id: Uuid,
    },
    /// A clause's text exceeds the size cap.
    #[error("termo clause {clause_id} is {bytes} bytes; the maximum is {max_bytes}")]
    ClauseTextTooLong {
        /// The offending clause.
        clause_id: Uuid,
        /// Size supplied.
        bytes: usize,
        /// Cap.
        max_bytes: usize,
    },
    /// A signatory slot carries no name.
    #[error("termo signatory slot {slot_id} has no name")]
    EmptySignatoryName {
        /// The offending slot.
        slot_id: Uuid,
    },
    /// A required field was absent.
    #[error("termo field {0} is required")]
    MissingField(&'static str),
    /// A field was present but blank.
    #[error("termo field {0} must not be blank")]
    EmptyField(&'static str),
    /// A field exceeded its length bound.
    #[error("termo field {field} exceeds {max_chars} characters")]
    TextTooLong {
        /// The offending field.
        field: &'static str,
        /// Cap.
        max_chars: usize,
    },
    /// A field was set that does not belong on this kind of termo.
    #[error("termo field {field} does not apply to a termo de {kind}")]
    FieldNotApplicable {
        /// The offending field.
        field: &'static str,
        /// The kind it was set on.
        kind: TermoKind,
    },
    /// The declared page capacity fell outside the accepted bounds.
    #[error("page capacity {requested} is outside the accepted range {min}..={max}")]
    PageCapacityOutOfRange {
        /// The rejected value.
        requested: u32,
        /// Smallest accepted capacity.
        min: u32,
        /// Largest accepted capacity.
        max: u32,
    },
    /// A book number below 1 was supplied.
    #[error("book number must be at least 1, got {0}")]
    InvalidBookNumber(u32),
    /// A withdrawal was attempted after signatures had been collected, which would leave those
    /// signatures binding bytes the instrument no longer has.
    #[error("cannot withdraw a termo once signatures have been collected")]
    SignaturesAlreadyCollected,
    /// The instrument was projected into the wrong payload type.
    #[error("expected a termo de {expected}, got a termo de {actual}")]
    WrongKind {
        /// Kind the projection required.
        expected: TermoKind,
        /// Kind the instrument actually is.
        actual: TermoKind,
    },
}

/// An act (ata) state-machine transition or mutation was rejected.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ActError {
    /// The requested transition is not legal from the current state.
    #[error("invalid act transition from {from:?} to {to:?}")]
    InvalidTransition {
        /// State the act was in.
        from: ActState,
        /// State the transition attempted to reach.
        to: ActState,
    },
    /// A content mutation was attempted on a sealed (append-only) act (WFL-20 / DAT-12).
    #[error("act is sealed and append-only; corrections must be a new act (WFL-21)")]
    Sealed,
    /// The act's rendered page count was already frozen (F15).
    ///
    /// The count is a recorded historical fact captured at the content freeze; recomputing it
    /// on read would let a template revision silently move a sealed act's page consumption.
    #[error("act page count is already frozen at {frozen}; it is never recomputed")]
    PageCountAlreadyFrozen {
        /// The count captured at the content freeze.
        frozen: u32,
    },
    /// A reopen was attempted on an act that already carries a collected signature.
    ///
    /// Reopening would invalidate the bytes that signature was given for. A signed act is
    /// corrected by a new act that retifies it (WFL-21), never by editing it back into shape.
    #[error(
        "act already carries a collected signature; reopening would invalidate it. \
         Correct a signed act with a new act that retifies it (WFL-21)"
    )]
    SignaturesCollected,
}

/// Sealing an act or opening a book failed.
#[derive(Debug, Error)]
pub enum SealError {
    /// The book was not in a state that permits sealing into it.
    #[error(transparent)]
    Book(#[from] BookError),
    /// The act was not in the `Signing` state expected before sealing.
    #[error(transparent)]
    Act(#[from] ActError),
    /// The compliance rule pack reported one or more `Error`-severity issues, which block
    /// sealing (LEG-05). The offending issues are rendered into the message.
    #[error("sealing blocked by compliance errors: {0}")]
    ComplianceBlocked(String),
    /// The act carried unacknowledged `Warning`-severity issues and sealing was not
    /// invoked with acknowledgement (LEG-05 warning model).
    #[error("sealing blocked by unacknowledged compliance warnings: {0}")]
    WarningsNotAcknowledged(String),
    /// Manual-signature sealing must preserve where the signed original is held (WFL-23).
    #[error("manual_signature_original_reference is required for manual-signature sealing")]
    MissingManualSignatureOriginalReference,
    /// The digital/manual evidence supplied to the seal gate was absent or malformed.
    #[error("invalid signature evidence for sealing: {0}")]
    InvalidSignatureEvidence(String),
    /// The payload could not be serialized for digesting.
    #[error("failed to serialize act payload for digest: {0}")]
    Serialize(String),
}

/// Aggregate error for callers that prefer a single type across the whole core.
#[derive(Debug, Error)]
pub enum CoreError {
    /// See [`NipcError`].
    #[error(transparent)]
    Nipc(#[from] NipcError),
    /// See [`BookError`].
    #[error(transparent)]
    Book(#[from] BookError),
    /// See [`ActError`].
    #[error(transparent)]
    Act(#[from] ActError),
    /// See [`TermoError`].
    #[error(transparent)]
    Termo(#[from] TermoError),
    /// See [`SealError`].
    #[error(transparent)]
    Seal(#[from] SealError),
}
