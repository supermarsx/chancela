//! Books (*livros de atas*) and their opening/closing instruments.
//!
//! Grounding: spec 06 §2 (WFL-10..15) and spec 05 (DAT-04). A book belongs to one organ
//! of an entity, is opened with a **termo de abertura** and closed with a **termo de
//! encerramento** (DL 76-A/2006 removed mandatory external legalization — the entity's own
//! management signs the termos). Acts live inside an open book and are numbered
//! sequentially within it.

use serde::{Deserialize, Serialize};
use time::{Date, OffsetDateTime};
use uuid::Uuid;

use crate::act::SignatoryCapacity;
use crate::entity::EntityId;
use crate::error::BookError;
use crate::termo::{MAX_PAGE_CAPACITY, MIN_PAGE_CAPACITY};

/// Opaque identifier for a [`Book`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BookId(pub Uuid);

impl BookId {
    /// Mint a fresh random identifier.
    pub fn new() -> Self {
        BookId(Uuid::new_v4())
    }
}

impl Default for BookId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for BookId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The organ a book belongs to (WFL-14: one book per organ, per the entity profile).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BookKind {
    /// Livro de atas da assembleia geral.
    AssembleiaGeral,
    /// Livro de atas da gerência / administração.
    GerenciaAdministracao,
    /// Livro de atas do conselho fiscal.
    ConselhoFiscal,
    /// Livro de atas do condomínio (DL 268/94).
    Condominio,
}

/// A book's lifecycle state (WFL-10 / DAT-04).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BookState {
    /// Record exists but has not yet been opened by a termo de abertura.
    Created,
    /// Opened; acts may be created and sealed into it.
    Open,
    /// Closed by a termo de encerramento; read-only.
    Closed,
}

/// How atas are numbered within the book (WFL-11 records the scheme).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NumberingScheme {
    /// Digital sequential numbering (ata n.º N), the default for native digital books.
    Sequential,
    /// Loose-leaf mode: sequential ata numbering plus page numbering and chaining per
    /// CSC art. 63.º (ENT-C6 / WFL-12). The page mechanics live in later work; the book
    /// records that this stricter mode is in force.
    LooseLeaf,
}

/// A structured signatory expected on a book opening/closing termo.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TermoSignatory {
    /// Signatory name.
    pub name: String,
    /// Capacity in which the person signs, when it maps to the modeled capacity enum.
    #[serde(default)]
    pub capacity: Option<SignatoryCapacity>,
    /// Optional contact email for coordinating this signatory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
}

impl TermoSignatory {
    /// Build a structured record from the legacy string-only field.
    #[must_use]
    pub fn from_legacy(value: impl Into<String>) -> Self {
        TermoSignatory {
            name: value.into(),
            capacity: None,
            email: None,
        }
    }

    /// Render a backward-compatible string for existing readers.
    #[must_use]
    pub fn legacy_label(&self) -> String {
        match self.capacity {
            Some(capacity) => format!("{} ({capacity:?})", self.name),
            None => self.name.clone(),
        }
    }
}

/// One clause of a termo's fillable text, as it appears in the **sealed payload**.
///
/// Deliberately leaner than [`crate::termo::TermoClause`]: draft-only provenance (the clause
/// id and its `origin`) must not enter the digest preimage, so this type structurally cannot
/// carry it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TermoClauseRecord {
    /// Optional heading rendered above the clause.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub heading: Option<String>,
    /// The clause text, rendered as a value and never compiled as a template.
    pub text: String,
}

/// A signature that was actually **collected** on a termo, as recorded in the sealed payload.
///
/// The distinction from [`TermoSignatory`] is the whole point: a `TermoSignatory` is a
/// *declared* name, which is all a pre-t8 or one-shot termo ever had. A
/// `TermoCollectedSignature` records that a signature was genuinely gathered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TermoCollectedSignature {
    /// The signatory slot this signature satisfied.
    pub slot_id: Uuid,
    /// Signatory name at the time of signing.
    pub name: String,
    /// Capacity in which they signed (constrained to the CCom art. 31.º n.º 2 allow-list).
    pub capacity: SignatoryCapacity,
    /// When the signature was collected.
    #[serde(with = "time::serde::rfc3339")]
    pub signed_at: OffsetDateTime,
    /// Identifier of the signature artifact, when one is recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_id: Option<Uuid>,
}

/// The **termo de abertura**: the formal instrument that opens a book (WFL-11).
///
/// For digital books its sealed form is the genesis event of the book's hash chain
/// (WFL-11 / DAT-11), which is why [`crate::seal::open_and_seal_book`] appends a ledger
/// event when a book is opened.
///
/// # Append-only shape
///
/// This struct **is** the genesis digest preimage: [`crate::seal::open_and_seal_book`]
/// serializes it directly. Every field added since the original shape is therefore appended
/// **last**, is `Option`/`Vec`, and carries `skip_serializing_if`, so a termo carrying none of
/// them serializes byte-identically to what it did before the fields existed. Never reorder,
/// rename or remove a field here: existing `book.opened` events depend on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TermoDeAbertura {
    /// Entity legal name at opening (WFL-11: entity identification).
    pub entity_name: String,
    /// Entity NIPC, as a plain string snapshot of [`crate::Nipc`].
    pub entity_nipc: String,
    /// Entity seat.
    pub entity_seat: String,
    /// Free-text purpose (e.g., "livro de atas da assembleia geral").
    pub purpose: String,
    /// Numbering scheme in force for this book.
    pub numbering_scheme: NumberingScheme,
    /// Opening date.
    pub opening_date: Date,
    /// Names/capacities of the signatories required by the entity profile
    /// (management / administrator) — the signatures that give the termo its force.
    pub required_signatories: Vec<String>,
    /// Structured signatory records, additive over the legacy string list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_signatory_records: Vec<TermoSignatory>,
    // ---- t8: the termo as a signable instrument. Appended last, all skippable. ----
    /// The [`crate::termo::TermoInstrument`] this payload was projected from, when the termo
    /// was drafted and signed as an instrument rather than built in one shot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub termo_instrument_id: Option<Uuid>,
    /// F4 — the instrument's title, which used to be a hardcoded literal in the render path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// F1 — "livro n.º N". `ASSURANCE`: no source requires it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub book_number: Option<u32>,
    /// F2 — place of drawing up. `ASSURANCE`: its absence is not a compliance gap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub place: Option<String>,
    /// F3 — the book's declared size in pages, mirrored onto the book at opening.
    /// `ASSURANCE`/`PRODUCT`: consistent with CCom art. 31.º n.º 2's numbered folhas, but no
    /// source requires a stated capacity at opening.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_capacity: Option<u32>,
    /// F8 — the fillable text as signed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub body: Vec<TermoClauseRecord>,
    /// F7 — the signatures actually collected, as distinct from the declared names above.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub collected_signatures: Vec<TermoCollectedSignature>,
}

impl Default for TermoDeAbertura {
    /// An empty termo, provided so call sites can append `..Default::default()` rather than
    /// enumerate the append-only tail. Not a meaningful instrument on its own.
    fn default() -> Self {
        TermoDeAbertura {
            entity_name: String::new(),
            entity_nipc: String::new(),
            entity_seat: String::new(),
            purpose: String::new(),
            numbering_scheme: NumberingScheme::Sequential,
            opening_date: Date::MIN,
            required_signatories: Vec::new(),
            required_signatory_records: Vec::new(),
            termo_instrument_id: None,
            title: None,
            book_number: None,
            place: None,
            page_capacity: None,
            body: Vec::new(),
            collected_signatures: Vec::new(),
        }
    }
}

/// Why a book was closed (WFL-13).
///
/// `ASSURANCE`: no statute requires a stated reason. Two of the structured variants are
/// inherently *early* closures, so the domain has always presupposed that a book may close
/// before it is full; capacity exhaustion is a trigger, never a precondition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClosingReason {
    /// The book has no remaining capacity.
    BookFull,
    /// The entity was dissolved.
    EntityDissolved,
    /// Migration to a successor book (the successor's abertura references this one).
    MigrationToSuccessor,
    /// None of the structured reasons fits — a change of organ composition, a new financial
    /// year, a merger.
    ///
    /// The `note` is **required and must be non-empty**: forcing a false structured reason
    /// onto an instrument whose whole purpose is stating facts is the failure mode this
    /// variant exists to avoid, and the note is what keeps the choice auditable.
    /// [`crate::termo::TermoFields`] enforces that.
    Other {
        /// Free-text reason. Must not be blank.
        note: String,
    },
}

/// The **termo de encerramento**: the formal instrument that closes a book (WFL-13).
///
/// Where the abertura *declares intent*, the encerramento *states facts* about what the book
/// ended up containing. Its numbers are therefore derived from the book and never
/// hand-entered — see [`Book::close`], which overwrites `ata_count` unconditionally.
///
/// The same append-only discipline as [`TermoDeAbertura`] applies: this struct is the
/// `book.closed` payload preimage, so new fields are appended last and skipped when absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TermoDeEncerramento {
    /// Number of atas contained at closing.
    pub ata_count: u64,
    /// Reason for closing.
    pub reason: ClosingReason,
    /// Closing date.
    pub closing_date: Date,
    /// Names/capacities of the required signatories.
    pub required_signatories: Vec<String>,
    /// Structured signatory records, additive over the legacy string list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_signatory_records: Vec<TermoSignatory>,
    // ---- t8: the termo as a signable instrument. Appended last, all skippable. ----
    /// The [`crate::termo::TermoInstrument`] this payload was projected from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub termo_instrument_id: Option<Uuid>,
    /// F4 — the instrument's title.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// F1 — "livro n.º N".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub book_number: Option<u32>,
    /// F2 — place of drawing up.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub place: Option<String>,
    /// F8 — the fillable text as signed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub body: Vec<TermoClauseRecord>,
    /// F7 — the signatures actually collected.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub collected_signatures: Vec<TermoCollectedSignature>,
    /// F16 — pages consumed by sealed atas at closing, derived from [`Book::pages_used`].
    ///
    /// `None` for legacy books, which never declared a capacity and whose historical page
    /// counts are deliberately not backfilled. `ASSURANCE`: no source requires a page count on
    /// the closing termo.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pages_used_at_close: Option<u32>,
}

impl Default for TermoDeEncerramento {
    /// An empty termo, provided so call sites can append `..Default::default()` rather than
    /// enumerate the append-only tail. Not a meaningful instrument on its own.
    fn default() -> Self {
        TermoDeEncerramento {
            ata_count: 0,
            reason: ClosingReason::BookFull,
            closing_date: Date::MIN,
            required_signatories: Vec::new(),
            required_signatory_records: Vec::new(),
            termo_instrument_id: None,
            title: None,
            book_number: None,
            place: None,
            body: Vec::new(),
            collected_signatures: Vec::new(),
            pages_used_at_close: None,
        }
    }
}

/// Active legal-hold metadata attached to a book.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegalHold {
    /// Free-text reason for the hold.
    pub reason: String,
    /// Actor that set the hold.
    pub actor: String,
    /// When the hold was set.
    #[serde(with = "time::serde::rfc3339")]
    pub set_at: OffsetDateTime,
}

/// A *livro de atas* for one organ of an entity.
///
/// Constructed in the `Created` state; opened via [`Book::open`] and closed via
/// [`Book::close`]. Ata numbers are handed out by [`Book::assign_next_ata_number`], which
/// refuses unless the book is open (WFL-14) and never reuses a number (WFL-12).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Book {
    /// Stable identifier.
    pub id: BookId,
    /// Owning entity.
    pub entity_id: EntityId,
    /// Organ this book serves.
    pub kind: BookKind,
    /// Current lifecycle state.
    pub state: BookState,
    /// Present once opened.
    pub termo_abertura: Option<TermoDeAbertura>,
    /// Present once closed.
    pub termo_encerramento: Option<TermoDeEncerramento>,
    /// Highest ata number assigned so far (0 = none yet). The next ata is `+ 1`.
    pub last_ata_number: u64,
    /// Predecessor book, when this book continues a full/closed one (WFL-13).
    pub predecessor: Option<BookId>,
    /// Active legal hold, if retention-driven disposal is blocked for this book.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legal_hold: Option<LegalHold>,
    // ---- t8 capacity model. Appended last, all skipped at their defaults. ----
    /// F1 — "livro n.º N", the identity users expect on a termo.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub book_number: Option<u32>,
    /// F14 — the book's size in pages, mirrored from the termo de abertura at opening.
    ///
    /// **`None` means "no capacity was ever declared" and capacity checks are skipped
    /// entirely.** Every book that existed before this field did carries `None`, and a
    /// pre-existing book must never suddenly refuse an ata because a limit it never agreed to
    /// was invented for it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_capacity: Option<u32>,
    /// F14 — pages consumed by sealed atas.
    ///
    /// Maintained going forward for every book, but **authoritative only where
    /// `page_capacity` is `Some`**: historical page counts are deliberately not backfilled,
    /// because recomputing them would mean re-rendering every historical ata under template
    /// versions that may since have moved.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub pages_used: u32,
    /// F14 — pages reserved by atas whose content is frozen in `Signing` but not yet sealed.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub pages_reserved: u32,
}

fn is_zero_u32(value: &u32) -> bool {
    *value == 0
}

impl Book {
    /// Create a book in the `Created` state. It cannot hold acts until [`Book::open`].
    pub fn new(entity_id: EntityId, kind: BookKind) -> Self {
        Book {
            id: BookId::new(),
            entity_id,
            kind,
            state: BookState::Created,
            termo_abertura: None,
            termo_encerramento: None,
            last_ata_number: 0,
            predecessor: None,
            legal_hold: None,
            book_number: None,
            // Deliberately `None`, not `Some(DEFAULT_PAGE_CAPACITY)`: a book gets a capacity
            // only from a termo de abertura that actually declares one (see `Book::open`), so
            // every construction path that predates the capacity model stays unlimited.
            page_capacity: None,
            pages_used: 0,
            pages_reserved: 0,
        }
    }

    /// Create a successor book that references `predecessor` (WFL-13).
    pub fn new_successor(entity_id: EntityId, kind: BookKind, predecessor: BookId) -> Self {
        let mut book = Book::new(entity_id, kind);
        book.predecessor = Some(predecessor);
        book
    }

    /// Open the book with its termo de abertura (WFL-10/11).
    ///
    /// Requires the `Created` state. This method mutates state only; appending the genesis
    /// ledger event is done by [`crate::seal::open_and_seal_book`], which calls this.
    /// The termo's declared `page_capacity` (F3) is mirrored onto the book here, and only
    /// here. A termo that declares none leaves the book unlimited — which is what keeps the
    /// legacy and one-shot paths behaving exactly as before.
    pub fn open(&mut self, termo: TermoDeAbertura) -> Result<(), BookError> {
        if self.state != BookState::Created {
            return Err(BookError::NotOpenable(self.state));
        }
        if let Some(capacity) = termo.page_capacity {
            if !(MIN_PAGE_CAPACITY..=MAX_PAGE_CAPACITY).contains(&capacity) {
                return Err(BookError::PageCapacityOutOfRange {
                    requested: capacity,
                    min: MIN_PAGE_CAPACITY,
                    max: MAX_PAGE_CAPACITY,
                });
            }
            self.page_capacity = Some(capacity);
        }
        if let Some(number) = termo.book_number {
            self.book_number = Some(number);
        }
        self.termo_abertura = Some(termo);
        self.state = BookState::Open;
        Ok(())
    }

    /// Close the book with its termo de encerramento (WFL-13). Requires the `Open` state.
    ///
    /// The termo's `ata_count` is overwritten with the book's authoritative count so the
    /// closing instrument cannot understate how many atas the book holds. `pages_used_at_close`
    /// (F16) is overwritten on exactly the same principle — the closing termo states facts
    /// about the book, and the book knows the answers.
    ///
    /// A book that never declared a capacity gets `None` rather than a partial count, because
    /// its historical pages were never counted.
    pub fn close(&mut self, mut termo: TermoDeEncerramento) -> Result<(), BookError> {
        if self.state != BookState::Open {
            return Err(BookError::NotClosable(self.state));
        }
        termo.ata_count = self.last_ata_number;
        termo.pages_used_at_close = self.has_page_capacity().then_some(self.pages_used);
        self.termo_encerramento = Some(termo);
        self.state = BookState::Closed;
        Ok(())
    }

    /// Assign the next sequential ata number (WFL-12). Refuses unless the book is `Open`
    /// (WFL-14). Numbers are strictly increasing and never reused.
    pub fn assign_next_ata_number(&mut self) -> Result<u64, BookError> {
        if self.state != BookState::Open {
            return Err(BookError::NotOpen(self.state));
        }
        self.last_ata_number += 1;
        Ok(self.last_ata_number)
    }

    /// True when acts may currently be created/sealed into this book.
    pub fn is_open(&self) -> bool {
        self.state == BookState::Open
    }

    /// Whether this book enforces a page capacity at all.
    ///
    /// `false` for every book opened before the capacity model existed, and for any book
    /// whose termo de abertura declared no size.
    #[must_use]
    pub fn has_page_capacity(&self) -> bool {
        self.page_capacity.is_some()
    }

    /// Pages still available: used + reserved subtracted from the declared capacity.
    ///
    /// `None` for an unlimited book — not zero. Callers must not treat the two alike.
    #[must_use]
    pub fn pages_remaining(&self) -> Option<u32> {
        let capacity = self.page_capacity?;
        Some(capacity.saturating_sub(self.pages_used.saturating_add(self.pages_reserved)))
    }

    /// Whether the book has no room left for another page.
    ///
    /// Always `false` for an unlimited book. When this becomes `true` the book **stays
    /// `Open`** and merely refuses new content: it must never auto-close, because closing
    /// requires a *signed* termo de encerramento and signatures cannot be automated.
    #[must_use]
    pub fn is_capacity_exhausted(&self) -> bool {
        self.pages_remaining() == Some(0)
    }

    /// Reserve `pages` for an act whose content has just been frozen (F14/F15).
    ///
    /// Called at the act's `TextApproved -> Signing` transition, which is the moment the
    /// rendered page count becomes knowable *and* permanently stable. Refusing here — before
    /// anyone signs — is the only humane place to refuse: an act that entered `Signing` has
    /// already reserved its pages and can therefore always be sealed, so an in-flight ata can
    /// never be stranded by the book filling up underneath it.
    ///
    /// On an unlimited book the reservation is tracked but never refused.
    pub fn reserve_pages(&mut self, pages: u32) -> Result<(), BookError> {
        let committed = self
            .pages_used
            .checked_add(self.pages_reserved)
            .ok_or(BookError::PageCountOverflow)?;
        let requested_total = committed
            .checked_add(pages)
            .ok_or(BookError::PageCountOverflow)?;
        if let Some(capacity) = self.page_capacity
            && requested_total > capacity
        {
            return Err(BookError::CapacityExceeded {
                capacity,
                used: self.pages_used,
                reserved: self.pages_reserved,
                required: pages,
            });
        }
        self.pages_reserved += pages;
        Ok(())
    }

    /// Convert a reservation into consumed pages when the act is sealed.
    pub fn consume_reserved_pages(&mut self, pages: u32) -> Result<(), BookError> {
        let reserved =
            self.pages_reserved
                .checked_sub(pages)
                .ok_or(BookError::NoSuchReservation {
                    reserved: self.pages_reserved,
                    requested: pages,
                })?;
        let used = self
            .pages_used
            .checked_add(pages)
            .ok_or(BookError::PageCountOverflow)?;
        // Defensive re-verification: reaching this branch would mean a reservation was granted
        // that the capacity could not honour.
        if let Some(capacity) = self.page_capacity
            && used > capacity
        {
            return Err(BookError::CapacityExceeded {
                capacity,
                used: self.pages_used,
                reserved: self.pages_reserved,
                required: pages,
            });
        }
        self.pages_reserved = reserved;
        self.pages_used = used;
        Ok(())
    }

    /// Release a reservation when a frozen act is withdrawn or deleted before sealing.
    pub fn release_reserved_pages(&mut self, pages: u32) -> Result<(), BookError> {
        self.pages_reserved =
            self.pages_reserved
                .checked_sub(pages)
                .ok_or(BookError::NoSuchReservation {
                    reserved: self.pages_reserved,
                    requested: pages,
                })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::{date, datetime};

    fn sample_abertura() -> TermoDeAbertura {
        TermoDeAbertura {
            entity_name: "Encosto Estratégico, S.A.".into(),
            entity_nipc: "503004642".into(),
            entity_seat: "Lisboa".into(),
            purpose: "livro de atas da assembleia geral".into(),
            numbering_scheme: NumberingScheme::Sequential,
            opening_date: date!(2026 - 01 - 15),
            required_signatories: vec!["Presidente do Conselho de Administração".into()],
            required_signatory_records: vec![TermoSignatory {
                name: "Amélia Marques".into(),
                capacity: Some(SignatoryCapacity::Chair),
                email: Some("amelia@example.pt".into()),
            }],
            ..TermoDeAbertura::default()
        }
    }

    fn sample_encerramento() -> TermoDeEncerramento {
        TermoDeEncerramento {
            ata_count: 0,
            reason: ClosingReason::BookFull,
            closing_date: date!(2026 - 12 - 31),
            required_signatories: vec!["Administrador".into()],
            required_signatory_records: vec![TermoSignatory {
                name: "Rui Nunes".into(),
                capacity: Some(SignatoryCapacity::Administrator),
                email: None,
            }],
            ..TermoDeEncerramento::default()
        }
    }

    #[test]
    fn happy_path_open_number_close() {
        let mut book = Book::new(EntityId::new(), BookKind::AssembleiaGeral);
        assert_eq!(book.state, BookState::Created);

        book.open(sample_abertura()).unwrap();
        assert_eq!(book.state, BookState::Open);
        assert!(book.termo_abertura.is_some());

        assert_eq!(book.assign_next_ata_number().unwrap(), 1);
        assert_eq!(book.assign_next_ata_number().unwrap(), 2);

        book.close(sample_encerramento()).unwrap();
        assert_eq!(book.state, BookState::Closed);
        // Closing overwrites the termo's ata_count with the book's authoritative count.
        assert_eq!(book.termo_encerramento.unwrap().ata_count, 2);
    }

    #[test]
    fn cannot_assign_number_before_open() {
        let mut book = Book::new(EntityId::new(), BookKind::GerenciaAdministracao);
        assert!(matches!(
            book.assign_next_ata_number(),
            Err(BookError::NotOpen(BookState::Created))
        ));
    }

    #[test]
    fn cannot_open_twice() {
        let mut book = Book::new(EntityId::new(), BookKind::AssembleiaGeral);
        book.open(sample_abertura()).unwrap();
        assert!(matches!(
            book.open(sample_abertura()),
            Err(BookError::NotOpenable(BookState::Open))
        ));
    }

    #[test]
    fn cannot_close_twice_or_before_open() {
        let mut book = Book::new(EntityId::new(), BookKind::ConselhoFiscal);
        assert!(matches!(
            book.close(sample_encerramento()),
            Err(BookError::NotClosable(BookState::Created))
        ));
        book.open(sample_abertura()).unwrap();
        book.close(sample_encerramento()).unwrap();
        assert!(matches!(
            book.close(sample_encerramento()),
            Err(BookError::NotClosable(BookState::Closed))
        ));
    }

    #[test]
    fn cannot_number_after_close() {
        let mut book = Book::new(EntityId::new(), BookKind::AssembleiaGeral);
        book.open(sample_abertura()).unwrap();
        book.close(sample_encerramento()).unwrap();
        assert!(matches!(
            book.assign_next_ata_number(),
            Err(BookError::NotOpen(BookState::Closed))
        ));
    }

    #[test]
    fn successor_references_predecessor() {
        let entity = EntityId::new();
        let first = Book::new(entity, BookKind::AssembleiaGeral);
        let second = Book::new_successor(entity, BookKind::AssembleiaGeral, first.id);
        assert_eq!(second.predecessor, Some(first.id));
    }

    // ---------------------------------------------------------------------------------
    // Byte-identity of the ledger preimages.
    //
    // `TermoDeAbertura` IS the `book.opened` genesis preimage and `TermoDeEncerramento` IS the
    // `book.closed` preimage — `seal::open_and_seal_book` serializes them directly, unlike acts
    // which digest a dedicated `ActPayload` projection. A record carrying none of the t8 fields
    // must therefore serialize byte-for-byte as it did before those fields existed, or every
    // pre-existing book's genesis digest moves. These are the load-bearing tests in this module.
    // ---------------------------------------------------------------------------------

    /// Faithful reconstruction of `TermoDeAbertura` *before* the t8 tail was appended.
    #[derive(Serialize)]
    struct OldTermoDeAbertura {
        entity_name: String,
        entity_nipc: String,
        entity_seat: String,
        purpose: String,
        numbering_scheme: NumberingScheme,
        opening_date: Date,
        required_signatories: Vec<String>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        required_signatory_records: Vec<TermoSignatory>,
    }

    /// Faithful reconstruction of `TermoDeEncerramento` *before* the t8 tail was appended.
    #[derive(Serialize)]
    struct OldTermoDeEncerramento {
        ata_count: u64,
        reason: ClosingReason,
        closing_date: Date,
        required_signatories: Vec<String>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        required_signatory_records: Vec<TermoSignatory>,
    }

    /// Faithful reconstruction of `Book` *before* the capacity fields were appended.
    #[derive(Serialize)]
    struct OldBook {
        id: BookId,
        entity_id: EntityId,
        kind: BookKind,
        state: BookState,
        termo_abertura: Option<TermoDeAbertura>,
        termo_encerramento: Option<TermoDeEncerramento>,
        last_ata_number: u64,
        predecessor: Option<BookId>,
        #[serde(skip_serializing_if = "Option::is_none")]
        legal_hold: Option<LegalHold>,
    }

    #[test]
    fn genesis_preimage_of_a_pre_existing_abertura_is_byte_identical() {
        use sha2::{Digest, Sha256};

        let termo = sample_abertura();
        assert!(
            termo.termo_instrument_id.is_none()
                && termo.title.is_none()
                && termo.book_number.is_none()
                && termo.place.is_none()
                && termo.page_capacity.is_none()
                && termo.body.is_empty()
                && termo.collected_signatures.is_empty()
        );

        let old = OldTermoDeAbertura {
            entity_name: termo.entity_name.clone(),
            entity_nipc: termo.entity_nipc.clone(),
            entity_seat: termo.entity_seat.clone(),
            purpose: termo.purpose.clone(),
            numbering_scheme: termo.numbering_scheme,
            opening_date: termo.opening_date,
            required_signatories: termo.required_signatories.clone(),
            required_signatory_records: termo.required_signatory_records.clone(),
        };

        let new_bytes = serde_json::to_vec(&termo).unwrap();
        let old_bytes = serde_json::to_vec(&old).unwrap();
        assert_eq!(new_bytes, old_bytes);

        let json = String::from_utf8(new_bytes.clone()).unwrap();
        for absent in [
            "termo_instrument_id",
            "title",
            "book_number",
            "place",
            "page_capacity",
            "body",
            "collected_signatures",
        ] {
            assert!(
                !json.contains(absent),
                "{absent} must not serialize: {json}"
            );
        }
        assert_eq!(
            Sha256::digest(&new_bytes).as_slice(),
            Sha256::digest(&old_bytes).as_slice(),
            "the genesis digest of a pre-existing book must not move"
        );
    }

    #[test]
    fn closing_preimage_of_a_pre_existing_encerramento_is_byte_identical() {
        use sha2::{Digest, Sha256};

        let termo = sample_encerramento();
        let old = OldTermoDeEncerramento {
            ata_count: termo.ata_count,
            reason: termo.reason.clone(),
            closing_date: termo.closing_date,
            required_signatories: termo.required_signatories.clone(),
            required_signatory_records: termo.required_signatory_records.clone(),
        };

        let new_bytes = serde_json::to_vec(&termo).unwrap();
        let old_bytes = serde_json::to_vec(&old).unwrap();
        assert_eq!(new_bytes, old_bytes);

        let json = String::from_utf8(new_bytes.clone()).unwrap();
        for absent in ["termo_instrument_id", "body", "pages_used_at_close"] {
            assert!(
                !json.contains(absent),
                "{absent} must not serialize: {json}"
            );
        }
        assert_eq!(
            Sha256::digest(&new_bytes).as_slice(),
            Sha256::digest(&old_bytes).as_slice(),
        );
    }

    #[test]
    fn a_pre_capacity_book_serializes_byte_identically() {
        let mut book = Book::new(EntityId::new(), BookKind::AssembleiaGeral);
        book.open(sample_abertura()).unwrap();
        book.assign_next_ata_number().unwrap();
        assert!(book.page_capacity.is_none() && book.pages_used == 0 && book.pages_reserved == 0);

        let old = OldBook {
            id: book.id,
            entity_id: book.entity_id,
            kind: book.kind,
            state: book.state,
            termo_abertura: book.termo_abertura.clone(),
            termo_encerramento: book.termo_encerramento.clone(),
            last_ata_number: book.last_ata_number,
            predecessor: book.predecessor,
            legal_hold: book.legal_hold.clone(),
        };

        let new_bytes = serde_json::to_vec(&book).unwrap();
        assert_eq!(new_bytes, serde_json::to_vec(&old).unwrap());
        let json = String::from_utf8(new_bytes).unwrap();
        for absent in [
            "page_capacity",
            "pages_used",
            "pages_reserved",
            "book_number",
        ] {
            assert!(
                !json.contains(absent),
                "{absent} must not serialize: {json}"
            );
        }
    }

    // ---- the companion proof: the new fields are NOT silently dropped ----

    #[test]
    fn a_filled_signed_abertura_binds_every_new_field() {
        let mut termo = sample_abertura();
        let base = serde_json::to_vec(&termo).unwrap();

        termo.termo_instrument_id = Some(Uuid::nil());
        termo.title = Some("Termo de abertura".into());
        termo.book_number = Some(2);
        termo.place = Some("Lisboa".into());
        termo.page_capacity = Some(100);
        termo.body = vec![TermoClauseRecord {
            heading: Some("Objeto".into()),
            text: "Este livro destina-se ao lançamento das atas.".into(),
        }];
        termo.collected_signatures = vec![TermoCollectedSignature {
            slot_id: Uuid::nil(),
            name: "Amélia Marques".into(),
            capacity: SignatoryCapacity::Manager,
            signed_at: datetime!(2026-07-19 10:00 UTC),
            signature_id: None,
        }];

        let filled = serde_json::to_vec(&termo).unwrap();
        assert_ne!(base, filled, "the filled termo must change the preimage");
        let json = String::from_utf8(filled).unwrap();
        for present in [
            "termo_instrument_id",
            "\"title\"",
            "\"book_number\":2",
            "\"place\":\"Lisboa\"",
            "\"page_capacity\":100",
            "\"body\"",
            "collected_signatures",
        ] {
            assert!(json.contains(present), "{present} must bind: {json}");
        }

        // And the whole thing round-trips.
        let back: TermoDeAbertura = serde_json::from_str(&json).unwrap();
        assert_eq!(termo, back);
    }

    #[test]
    fn a_filled_encerramento_binds_every_new_field() {
        let mut termo = sample_encerramento();
        let base = serde_json::to_vec(&termo).unwrap();
        termo.termo_instrument_id = Some(Uuid::nil());
        termo.title = Some("Termo de encerramento".into());
        termo.book_number = Some(2);
        termo.place = Some("Lisboa".into());
        termo.body = vec![TermoClauseRecord {
            heading: None,
            text: "Encerra-se o presente livro.".into(),
        }];
        termo.pages_used_at_close = Some(87);
        let filled = serde_json::to_vec(&termo).unwrap();
        assert_ne!(base, filled);
        let json = String::from_utf8(filled).unwrap();
        assert!(json.contains("\"pages_used_at_close\":87"), "{json}");
        let back: TermoDeEncerramento = serde_json::from_str(&json).unwrap();
        assert_eq!(termo, back);
    }

    #[test]
    fn the_other_closing_reason_round_trips_with_its_note() {
        let reason = ClosingReason::Other {
            note: "novo exercício económico".into(),
        };
        let json = serde_json::to_string(&reason).unwrap();
        assert_eq!(json, r#"{"Other":{"note":"novo exercício económico"}}"#);
        let back: ClosingReason = serde_json::from_str(&json).unwrap();
        assert_eq!(reason, back);
        // The pre-existing variants are untouched, so old payloads keep their exact bytes.
        assert_eq!(
            serde_json::to_string(&ClosingReason::BookFull).unwrap(),
            "\"BookFull\""
        );
    }

    // ---- capacity arithmetic (F14) ----

    fn book_with_capacity(capacity: Option<u32>) -> Book {
        let mut termo = sample_abertura();
        termo.page_capacity = capacity;
        let mut book = Book::new(EntityId::new(), BookKind::GerenciaAdministracao);
        book.open(termo).unwrap();
        book
    }

    #[test]
    fn a_legacy_book_with_no_declared_capacity_is_unlimited() {
        // Non-negotiable: a pre-t8 book must never suddenly refuse an ata because a limit it
        // never agreed to was invented for it.
        let mut book = book_with_capacity(None);
        assert!(!book.has_page_capacity());
        assert_eq!(book.pages_remaining(), None);
        assert!(!book.is_capacity_exhausted());

        for _ in 0..500 {
            book.reserve_pages(10).unwrap();
            book.consume_reserved_pages(10).unwrap();
        }
        assert_eq!(book.pages_used, 5_000);
        assert!(
            !book.is_capacity_exhausted(),
            "still unlimited after 5000 pages"
        );
        // Even a single enormous ata is accepted.
        book.reserve_pages(u32::MAX - book.pages_used).unwrap();
    }

    #[test]
    fn capacity_is_mirrored_from_the_termo_at_opening() {
        let book = book_with_capacity(Some(100));
        assert_eq!(book.page_capacity, Some(100));
        assert_eq!(book.pages_remaining(), Some(100));
    }

    #[test]
    fn an_out_of_range_capacity_is_refused_at_opening() {
        let mut termo = sample_abertura();
        termo.page_capacity = Some(0);
        let mut book = Book::new(EntityId::new(), BookKind::AssembleiaGeral);
        assert!(matches!(
            book.open(termo),
            Err(BookError::PageCapacityOutOfRange { requested: 0, .. })
        ));
        // The book was not opened by a refused termo.
        assert_eq!(book.state, BookState::Created);
    }

    #[test]
    fn reserve_consume_and_release_move_pages_between_the_two_counters() {
        let mut book = book_with_capacity(Some(10));

        book.reserve_pages(4).unwrap();
        assert_eq!((book.pages_used, book.pages_reserved), (0, 4));
        assert_eq!(book.pages_remaining(), Some(6));

        book.consume_reserved_pages(4).unwrap();
        assert_eq!((book.pages_used, book.pages_reserved), (4, 0));
        assert_eq!(book.pages_remaining(), Some(6));

        book.reserve_pages(3).unwrap();
        book.release_reserved_pages(3).unwrap();
        assert_eq!((book.pages_used, book.pages_reserved), (4, 0));
        assert_eq!(book.pages_remaining(), Some(6));
    }

    #[test]
    fn a_reservation_that_would_overflow_the_book_is_refused() {
        let mut book = book_with_capacity(Some(10));
        book.reserve_pages(6).unwrap();
        book.consume_reserved_pages(6).unwrap();
        book.reserve_pages(3).unwrap();

        // 6 used + 3 reserved + 2 more = 11 > 10.
        assert!(matches!(
            book.reserve_pages(2),
            Err(BookError::CapacityExceeded {
                capacity: 10,
                used: 6,
                reserved: 3,
                required: 2,
            })
        ));
        // The refusal changed nothing.
        assert_eq!((book.pages_used, book.pages_reserved), (6, 3));
        // Exactly filling the book is fine.
        book.reserve_pages(1).unwrap();
        assert!(book.is_capacity_exhausted());
    }

    #[test]
    fn an_ata_that_reserved_its_pages_can_always_be_sealed() {
        // The reason capacity is checked at the content freeze: once an ata has reserved, the
        // book cannot fill up underneath it, so it is never stranded mid-signature.
        let mut book = book_with_capacity(Some(5));
        book.reserve_pages(5).unwrap();
        assert!(book.is_capacity_exhausted());
        assert!(matches!(
            book.reserve_pages(1),
            Err(BookError::CapacityExceeded { .. })
        ));
        book.consume_reserved_pages(5).unwrap();
        assert_eq!(book.pages_used, 5);
    }

    #[test]
    fn settling_more_pages_than_are_reserved_is_refused() {
        let mut book = book_with_capacity(Some(10));
        book.reserve_pages(2).unwrap();
        assert!(matches!(
            book.consume_reserved_pages(3),
            Err(BookError::NoSuchReservation {
                reserved: 2,
                requested: 3
            })
        ));
        assert!(matches!(
            book.release_reserved_pages(3),
            Err(BookError::NoSuchReservation { .. })
        ));
        assert_eq!((book.pages_used, book.pages_reserved), (0, 2));
    }

    #[test]
    fn page_arithmetic_does_not_overflow() {
        let mut book = book_with_capacity(None);
        book.reserve_pages(u32::MAX).unwrap();
        assert!(matches!(
            book.reserve_pages(1),
            Err(BookError::PageCountOverflow)
        ));
    }

    #[test]
    fn closing_overwrites_the_page_count_and_leaves_legacy_books_without_one() {
        let mut book = book_with_capacity(Some(50));
        book.reserve_pages(12).unwrap();
        book.consume_reserved_pages(12).unwrap();
        let mut termo = sample_encerramento();
        // A caller cannot understate consumption any more than it can understate the ata count.
        termo.pages_used_at_close = Some(1);
        book.close(termo).unwrap();
        assert_eq!(
            book.termo_encerramento
                .as_ref()
                .unwrap()
                .pages_used_at_close,
            Some(12)
        );

        let mut legacy = book_with_capacity(None);
        let mut termo = sample_encerramento();
        termo.pages_used_at_close = Some(999);
        legacy.close(termo).unwrap();
        assert_eq!(
            legacy
                .termo_encerramento
                .as_ref()
                .unwrap()
                .pages_used_at_close,
            None,
            "a book that never counted pages must not claim a count"
        );
    }

    #[test]
    fn termo_signatory_keeps_legacy_label() {
        let record = TermoSignatory {
            name: "Amélia Marques".into(),
            capacity: Some(SignatoryCapacity::Administrator),
            email: Some("amelia@example.pt".into()),
        };

        assert_eq!(record.legacy_label(), "Amélia Marques (Administrator)");
        assert_eq!(
            TermoSignatory::from_legacy("Administrador"),
            TermoSignatory {
                name: "Administrador".into(),
                capacity: None,
                email: None,
            }
        );
    }
}
