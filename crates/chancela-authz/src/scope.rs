//! Authorization scopes and **narrowing-only** coverage (t64 plan §2.4).
//!
//! A grant (from a role assignment or a delegation) is held at a [`Scope`]; a check targets a
//! [`Scope`]. [`scope_covers`] answers "does a grant at `grant` authorise an action targeting
//! `target`?" and is deliberately **narrowing-only** — authority only ever flows to the same or a
//! contained scope, never outward:
//!
//! - `Global` covers everything.
//! - `Tenant(T)` covers `Tenant(T)`, any `Entity(E)` in tenant `T`, and any `Book(B)` owned by such
//!   an entity; it does **not** cover `Global`, another tenant, an entity of another tenant, or a
//!   book of another tenant. This is the isolation boundary (wp26 tenancy, spec 05 DAT-01).
//! - `Entity(E)` covers `Entity(E)` and any `Book(B)` owned by `E`; it does **not** cover `Global`,
//!   a `Tenant`, another entity, or a book outside `E`.
//! - `Book(B)` covers `Book(B)` only; not its entity, not `Tenant`, not `Global`, not another book.
//!
//! Consequence (the security-load-bearing one): **a scoped grant can never satisfy a wider check.**
//! A `Global` action is authorisable only by a `Global` grant; a `Tenant` check is never satisfied by
//! an `Entity`/`Book` grant — scope-escape is structurally impossible in the widening direction.
//!
//! This crate never reads a store, so it cannot itself know which entity owns a given book, nor which
//! tenant owns a given entity. Both containment hops consult the caller-supplied [`BookScope`]
//! relation (`entity_of` for book→entity, `tenant_of` for entity→tenant), letting the API layer feed
//! in the authoritative mappings while this crate stays pure/data-driven.

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

/// Opaque identifier of a tenant (organizational isolation boundary). Serialises transparently as
/// the inner UUID — wire-compatible with `chancela-core::TenantId` without this leaf crate depending
/// on the domain (wp26 tenancy).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TenantId(pub Uuid);

impl std::fmt::Display for TenantId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// Where an authority applies, or what an action targets.
///
/// Serialises externally-tagged and stably: `"Global"`, `{"Tenant": "<uuid>"}`,
/// `{"Entity": "<uuid>"}`, `{"Book": "<uuid>"}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Scope {
    /// Instance-wide authority. The only scope that satisfies a `Global` check.
    Global,
    /// Authority over one tenant: its entities and (via [`BookScope`]) their books. The isolation
    /// boundary above `Entity` (wp26 tenancy). Never satisfies a `Global` check.
    Tenant(TenantId),
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

/// The authoritative scope-containment relation, supplied by the caller (the API layer resolves it
/// from live state). Kept as a trait so this crate never touches a store and so tests can feed a
/// fixture. It answers the two ownership hops [`scope_covers`] needs:
///
/// - `entity_of(book)` — the entity that owns a book (book→entity). `None` for an unknown book is
///   **fail-closed**: an unresolved book is owned by no entity, so no `Entity` (or `Tenant`) grant
///   covers it.
/// - `tenant_of(entity)` — the tenant that owns an entity (entity→tenant, wp26). Defaults to `None`,
///   which is **fail-closed**: an entity with no resolved tenant is covered by no `Tenant` grant. A
///   caller that does not model tenancy (or a purely `Global`/`Entity`/`Book` check) can ignore it
///   entirely and the narrowing behaviour is byte-identical to the pre-tenancy three-level tree.
pub trait BookScope {
    /// The entity that owns `book`, or `None` if unknown.
    fn entity_of(&self, book: BookId) -> Option<EntityId>;

    /// The tenant that owns `entity`, or `None` if unknown (fail-closed). Defaulted so every existing
    /// [`BookScope`] impl (closures, [`NoBooks`]) keeps compiling and resolves no tenant.
    fn tenant_of(&self, _entity: EntityId) -> Option<TenantId> {
        None
    }
}

/// A `BookScope` that knows about no books and no tenants — everything resolves to `None`. Correct
/// for any check that never targets an `Entity`-covers-`Book` or `Tenant`-covers-`Entity` case (e.g.
/// purely `Global` administrative checks), and the safe default.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoBooks;

impl BookScope for NoBooks {
    fn entity_of(&self, _book: BookId) -> Option<EntityId> {
        None
    }
}

/// Any closure `Fn(BookId) -> Option<EntityId>` is a [`BookScope`] (resolving no tenant — the default
/// `tenant_of`). Callers that need tenant resolution supply a concrete type overriding `tenant_of`.
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
        // A tenant authority (wp26) covers itself, its entities, and their books — never Global,
        // never another tenant, never an entity/book of another tenant. Both narrowing hops are
        // fail-closed: an unresolved tenant/entity (`None`) is covered by no tenant grant.
        (Scope::Tenant(g), Scope::Tenant(t)) => g == t,
        (Scope::Tenant(g), Scope::Entity(t)) => books.tenant_of(t) == Some(g),
        (Scope::Tenant(g), Scope::Book(b)) => {
            books.entity_of(b).and_then(|e| books.tenant_of(e)) == Some(g)
        }
        // An entity authority covers itself and the books it owns — never Global, never a Tenant,
        // never another entity, never a book outside it.
        (Scope::Entity(g), Scope::Entity(t)) => g == t,
        (Scope::Entity(g), Scope::Book(b)) => books.entity_of(b) == Some(g),
        // A book authority covers only that exact book — never its entity, never Tenant, never Global.
        (Scope::Book(g), Scope::Book(t)) => g == t,
        // Everything else (scoped → Global, entity/book → Tenant, book → entity, cross-entity,
        // cross-tenant) does NOT cover.
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
    fn t(n: u128) -> TenantId {
        TenantId(Uuid::from_u128(0x7E00_0000 + n))
    }

    /// Book 10 and 11 belong to entity 1; book 20 belongs to entity 2.
    fn rel() -> impl BookScope {
        let mut m = HashMap::new();
        m.insert(b(10), e(1));
        m.insert(b(11), e(1));
        m.insert(b(20), e(2));
        move |book: BookId| m.get(&book).copied()
    }

    /// A concrete [`BookScope`] carrying BOTH the book→entity and entity→tenant relations, mirroring
    /// how the API's `Authorizer` supplies them. Entity 1 ∈ tenant A; entity 2 ∈ tenant B.
    struct Rel {
        books: HashMap<BookId, EntityId>,
        tenants: HashMap<EntityId, TenantId>,
    }
    impl BookScope for Rel {
        fn entity_of(&self, book: BookId) -> Option<EntityId> {
            self.books.get(&book).copied()
        }
        fn tenant_of(&self, entity: EntityId) -> Option<TenantId> {
            self.tenants.get(&entity).copied()
        }
    }
    /// Books 10/11 → entity 1 → tenant A; book 20 → entity 2 → tenant B.
    fn tenant_rel() -> Rel {
        Rel {
            books: HashMap::from([(b(10), e(1)), (b(11), e(1)), (b(20), e(2))]),
            tenants: HashMap::from([(e(1), t(0xA)), (e(2), t(0xB))]),
        }
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

    // --- wp26 tenancy: the fourth (top) narrowing level -----------------------------------------

    #[test]
    fn global_covers_a_tenant() {
        assert!(scope_covers(Scope::Global, Scope::Tenant(t(0xA)), &NoBooks));
    }

    #[test]
    fn tenant_covers_itself_its_entities_and_their_books() {
        let r = tenant_rel();
        // Itself.
        assert!(scope_covers(
            Scope::Tenant(t(0xA)),
            Scope::Tenant(t(0xA)),
            &r
        ));
        // Its entity and that entity's books.
        assert!(scope_covers(Scope::Tenant(t(0xA)), Scope::Entity(e(1)), &r));
        assert!(scope_covers(Scope::Tenant(t(0xA)), Scope::Book(b(10)), &r));
        assert!(scope_covers(Scope::Tenant(t(0xA)), Scope::Book(b(11)), &r));
    }

    #[test]
    fn tenant_never_covers_another_tenants_entities_or_books() {
        let r = tenant_rel();
        // Entity 2 and book 20 belong to tenant B, never covered by a tenant-A grant.
        assert!(!scope_covers(
            Scope::Tenant(t(0xA)),
            Scope::Tenant(t(0xB)),
            &r
        ));
        assert!(!scope_covers(
            Scope::Tenant(t(0xA)),
            Scope::Entity(e(2)),
            &r
        ));
        assert!(!scope_covers(Scope::Tenant(t(0xA)), Scope::Book(b(20)), &r));
    }

    #[test]
    fn tenant_grant_never_satisfies_a_wider_check() {
        let r = tenant_rel();
        // A tenant grant can never satisfy a Global check (scope-escape barred, as for Entity/Book).
        assert!(!scope_covers(Scope::Tenant(t(0xA)), Scope::Global, &r));
    }

    #[test]
    fn entity_and_book_grants_never_widen_to_a_tenant() {
        let r = tenant_rel();
        // Narrowing-only: an Entity/Book grant never covers its owning Tenant.
        assert!(!scope_covers(
            Scope::Entity(e(1)),
            Scope::Tenant(t(0xA)),
            &r
        ));
        assert!(!scope_covers(Scope::Book(b(10)), Scope::Tenant(t(0xA)), &r));
    }

    #[test]
    fn unknown_entity_tenant_is_fail_closed() {
        // An entity with no resolved tenant (default `tenant_of` → None) is covered by no tenant
        // grant, even for an entity/book that otherwise exists in the book relation.
        assert!(!scope_covers(
            Scope::Tenant(t(0xA)),
            Scope::Entity(e(999)),
            &tenant_rel()
        ));
        // NoBooks resolves no tenant either ⇒ fail-closed.
        assert!(!scope_covers(
            Scope::Tenant(t(0xA)),
            Scope::Entity(e(1)),
            &NoBooks
        ));
    }
}
