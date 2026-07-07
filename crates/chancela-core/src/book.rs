//! Books (*livros de atas*) and their opening/closing instruments.
//!
//! Grounding: spec 06 §2 (WFL-10..15) and spec 05 (DAT-04). A book belongs to one organ
//! of an entity, is opened with a **termo de abertura** and closed with a **termo de
//! encerramento** (DL 76-A/2006 removed mandatory external legalization — the entity's own
//! management signs the termos). Acts live inside an open book and are numbered
//! sequentially within it.

use serde::{Deserialize, Serialize};
use time::Date;
use uuid::Uuid;

use crate::entity::EntityId;
use crate::error::BookError;

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

/// The **termo de abertura**: the formal instrument that opens a book (WFL-11).
///
/// For digital books its sealed form is the genesis event of the book's hash chain
/// (WFL-11 / DAT-11), which is why [`crate::seal::open_and_seal_book`] appends a ledger
/// event when a book is opened.
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
}

/// Why a book was closed (WFL-13).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClosingReason {
    /// The book has no remaining capacity.
    BookFull,
    /// The entity was dissolved.
    EntityDissolved,
    /// Migration to a successor book (the successor's abertura references this one).
    MigrationToSuccessor,
}

/// The **termo de encerramento**: the formal instrument that closes a book (WFL-13).
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
    pub fn open(&mut self, termo: TermoDeAbertura) -> Result<(), BookError> {
        if self.state != BookState::Created {
            return Err(BookError::NotOpenable(self.state));
        }
        self.termo_abertura = Some(termo);
        self.state = BookState::Open;
        Ok(())
    }

    /// Close the book with its termo de encerramento (WFL-13). Requires the `Open` state.
    ///
    /// The termo's `ata_count` is overwritten with the book's authoritative count so the
    /// closing instrument cannot understate how many atas the book holds.
    pub fn close(&mut self, mut termo: TermoDeEncerramento) -> Result<(), BookError> {
        if self.state != BookState::Open {
            return Err(BookError::NotClosable(self.state));
        }
        termo.ata_count = self.last_ata_number;
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::date;

    fn sample_abertura() -> TermoDeAbertura {
        TermoDeAbertura {
            entity_name: "Encosto Estratégico, S.A.".into(),
            entity_nipc: "503004642".into(),
            entity_seat: "Lisboa".into(),
            purpose: "livro de atas da assembleia geral".into(),
            numbering_scheme: NumberingScheme::Sequential,
            opening_date: date!(2026 - 01 - 15),
            required_signatories: vec!["Presidente do Conselho de Administração".into()],
        }
    }

    fn sample_encerramento() -> TermoDeEncerramento {
        TermoDeEncerramento {
            ata_count: 0,
            reason: ClosingReason::BookFull,
            closing_date: date!(2026 - 12 - 31),
            required_signatories: vec!["Administrador".into()],
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
}
