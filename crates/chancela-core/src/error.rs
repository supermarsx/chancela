//! Error types for the domain core.
//!
//! Each subsystem carries its own typed error; [`CoreError`] aggregates them for callers
//! (such as `chancela-api`) that would rather match a single enum.

use thiserror::Error;

use crate::act::ActState;
use crate::book::BookState;

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
    /// See [`SealError`].
    #[error(transparent)]
    Seal(#[from] SealError),
}
