//! Authorization scopes and **narrowing-only** coverage (t64 plan §2.4).
//!
//! A grant (from a role assignment or a delegation) is held at a [`Scope`]; a check targets a
//! [`Scope`]. [`scope_covers`] answers "does a grant at `grant` authorise an action targeting
//! `target`?" and is deliberately **narrowing-only** — authority only ever flows to the same or a
//! contained scope, never outward:
//!
//! - `Global` covers everything.
//! - `Entity(E)` covers `Entity(E)` and any `Book(B)` owned by `E`; it does **not** cover `Global`,
//!   another entity, or a book outside `E`.
//! - `Book(B)` covers `Book(B)` only; not its entity, not `Global`, not another book.
//!
//! Consequence (the security-load-bearing one): **a scoped grant can never satisfy a `Global`
//! check.** A `Global` action is authorisable only by a `Global` grant — scope-escape is structurally
//! impossible in the widening direction.
//!
//! This crate never reads a store, so it cannot itself know which entity owns a given book. The
//! `Entity(E)` → `Book(B)` case consults a caller-supplied [`BookScope`] relation, letting the API
//! layer feed in the authoritative book→entity mapping while this crate stays pure/data-driven.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Opaque identifier of a legal entity. Serialises transparently as the inner UUID, so it is
/// wire-compatible with `chancela-core::EntityId` without this leaf crate depending on the domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EntityId(pub Uuid);

impl std::fmt::Display for EntityId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// Opaque identifier of a book (*livro de atas*). Serialises transparently as the inner UUID —
/// wire-compatible with `chancela-core::BookId`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BookId(pub Uuid);

impl std::fmt::Display for BookId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// Where an authority applies, or what an action targets.
///
/// Serialises externally-tagged and stably: `"Global"`, `{"Entity": "<uuid>"}`, `{"Book": "<uuid>"}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Scope {
    /// Instance-wide authority. The only scope that satisfies a `Global` check.
    Global,
    /// Authority over one entity and (via [`BookScope`]) the books it owns.
    Entity(EntityId),
    /// Authority over exactly one book.
    Book(BookId),
}

impl Scope {
    /// `true` for [`Scope::Global`] only. Convenience for the "a Global action needs a Global grant"
    /// discipline.
    #[must_use]
    pub const fn is_global(self) -> bool {
        matches!(self, Scope::Global)
    }
}

/// The authoritative book→entity ownership relation, supplied by the caller (the API layer resolves
/// it from the durable store). Kept as a trait so this crate never touches a store and so tests can
/// feed a fixture. Returning `None` for an unknown book is **fail-closed**: an unresolved book is
/// treated as owned by no entity, so no `Entity` grant covers it.
pub trait BookScope {
    /// The entity that owns `book`, or `None` if unknown.
    fn entity_of(&self, book: BookId) -> Option<EntityId>;
}

/// A `BookScope` that knows about no books — every book resolves to `None`. Correct for any check
/// that never targets an `Entity`-covers-`Book` case (e.g. purely `Global` administrative checks),
/// and the safe default.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoBooks;

impl BookScope for NoBooks {
    fn entity_of(&self, _book: BookId) -> Option<EntityId> {
        None
    }
}

/// Any closure `Fn(BookId) -> Option<EntityId>` is a [`BookScope`].
impl<F> BookScope for F
where
    F: Fn(BookId) -> Option<EntityId>,
{
    fn entity_of(&self, book: BookId) -> Option<EntityId> {
        self(book)
    }
}

/// Does an authority held at `grant` cover an action targeting `target`? **Narrowing-only** (see the
/// module docs). The `books` relation is consulted only for the `Entity(E)` → `Book(B)` case.
#[must_use]
pub fn scope_covers(grant: Scope, target: Scope, books: &impl BookScope) -> bool {
    match (grant, target) {
        // Global authority covers any target.
        (Scope::Global, _) => true,
        // An entity authority covers itself and the books it owns — never Global, never another
        // entity, never a book outside it.
        (Scope::Entity(g), Scope::Entity(t)) => g == t,
        (Scope::Entity(g), Scope::Book(b)) => books.entity_of(b) == Some(g),
        // A book authority covers only that exact book — never its entity, never Global.
        (Scope::Book(g), Scope::Book(t)) => g == t,
        // Everything else (scoped → Global, book → entity, cross-entity) does NOT cover.
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn e(n: u128) -> EntityId {
        EntityId(Uuid::from_u128(n))
    }
    fn b(n: u128) -> BookId {
        BookId(Uuid::from_u128(n))
    }

    /// Book 10 and 11 belong to entity 1; book 20 belongs to entity 2.
    fn rel() -> impl BookScope {
        let mut m = HashMap::new();
        m.insert(b(10), e(1));
        m.insert(b(11), e(1));
        m.insert(b(20), e(2));
        move |book: BookId| m.get(&book).copied()
    }

    #[test]
    fn global_covers_everything() {
        let r = rel();
        assert!(scope_covers(Scope::Global, Scope::Global, &r));
        assert!(scope_covers(Scope::Global, Scope::Entity(e(1)), &r));
        assert!(scope_covers(Scope::Global, Scope::Book(b(10)), &r));
    }

    #[test]
    fn scoped_never_satisfies_global() {
        let r = rel();
        assert!(!scope_covers(Scope::Entity(e(1)), Scope::Global, &r));
        assert!(!scope_covers(Scope::Book(b(10)), Scope::Global, &r));
    }

    #[test]
    fn entity_covers_itself_and_its_books_only() {
        let r = rel();
        assert!(scope_covers(Scope::Entity(e(1)), Scope::Entity(e(1)), &r));
        assert!(scope_covers(Scope::Entity(e(1)), Scope::Book(b(10)), &r));
        assert!(scope_covers(Scope::Entity(e(1)), Scope::Book(b(11)), &r));
        // Not another entity, not a book of another entity.
        assert!(!scope_covers(Scope::Entity(e(1)), Scope::Entity(e(2)), &r));
        assert!(!scope_covers(Scope::Entity(e(1)), Scope::Book(b(20)), &r));
    }

    #[test]
    fn book_covers_only_itself() {
        let r = rel();
        assert!(scope_covers(Scope::Book(b(10)), Scope::Book(b(10)), &r));
        assert!(!scope_covers(Scope::Book(b(10)), Scope::Book(b(11)), &r));
        // A book grant never widens to its owning entity.
        assert!(!scope_covers(Scope::Book(b(10)), Scope::Entity(e(1)), &r));
    }

    #[test]
    fn unknown_book_is_fail_closed() {
        // NoBooks resolves every book to None ⇒ no entity grant covers any book.
        assert!(!scope_covers(
            Scope::Entity(e(1)),
            Scope::Book(b(999)),
            &NoBooks
        ));
    }
}
