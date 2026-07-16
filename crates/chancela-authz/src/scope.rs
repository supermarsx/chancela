//! Authorization scopes and **narrowing-only** coverage (t64 plan §2.4).
//!
//! A grant (from a role assignment or a delegation) is held at a [`Scope`]; a check targets a
//! [`Scope`]. [`scope_covers`] answers "does a grant at `grant` authorise an action targeting
//! `target`?" and is deliberately **narrowing-only** — authority only ever flows to the same or a
//! contained scope, never outward:
//!
//! - `Global` covers everything.
//! - `Tenant(T)` covers resources whose authoritative parent chain reaches that tenant.
//! - `Entity(E)` (the spec's company scope) covers its books and other resources whose parent chain
//!   reaches that entity.
//! - `Book(B)` covers the book and its acts/other contained resources.
//! - `Act`, `Folder`, `TemplateLibrary`, `Archive`, `Integration`, and `Repository` are first-class
//!   leaf scopes (ROL-03 plus ARC-30). They cover themselves; wider grants cover them only when the
//!   caller supplies a live, authoritative parent relation.
//!
//! Consequence (the security-load-bearing one): **a scoped grant can never satisfy a wider check.**
//! A `Global` action is authorisable only by a `Global` grant; a `Tenant` check is never satisfied by
//! an `Entity`/`Book` grant — scope-escape is structurally impossible in the widening direction.
//!
//! This crate never reads a store. Containment consults the caller-supplied [`BookScope`] relation,
//! whose original book→entity and entity→tenant methods remain source compatible and whose additive
//! methods resolve the ROL-03 leaf resources. Unknown parents are always fail-closed.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Opaque identifier of a legal entity. Serialises transparently as the inner UUID, so it is
/// wire-compatible with `chancela-core::EntityId` without this leaf crate depending on the domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EntityId(pub Uuid);

/// The product spec calls an entity-scoped authority a company scope. This alias preserves the
/// long-standing `Entity` wire variant while making that equivalence explicit.
pub type CompanyId = EntityId;

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

macro_rules! leaf_id {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
        )]
        pub struct $name(pub Uuid);

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.fmt(f)
            }
        }
    };
}

leaf_id!(ActId, "Opaque identifier of an act/minute record.");
leaf_id!(FolderId, "Opaque identifier of a records folder.");
leaf_id!(
    TemplateLibraryId,
    "Opaque identifier of a shared template library."
);
leaf_id!(ArchiveId, "Opaque identifier of an archive resource.");
leaf_id!(
    IntegrationId,
    "Opaque identifier of an integration/connector resource."
);
leaf_id!(
    RepositoryId,
    "Opaque identifier of a storage repository (ARC-30)."
);

/// Where an authority applies, or what an action targets.
///
/// Serialises externally-tagged and stably: `"Global"`, `{"Tenant": "<uuid>"}`,
/// `{"Entity": "<uuid>"}`, `{"Book": "<uuid>"}`, and the additive ROL-03 leaf variants.
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
    /// Authority over exactly one act. A live parent relation may narrow Book/Entity/Tenant grants
    /// to this act.
    Act(ActId),
    /// Authority over exactly one records folder.
    Folder(FolderId),
    /// Authority over exactly one shared template library.
    TemplateLibrary(TemplateLibraryId),
    /// Authority over exactly one archive/export repository.
    Archive(ArchiveId),
    /// Authority over exactly one integration or connector configuration.
    Integration(IntegrationId),
    /// Authority over exactly one storage repository (used by opt-in ZK policy and sync/backup).
    Repository(RepositoryId),
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

    /// The book that owns an act, or `None` when unresolved.
    fn book_of_act(&self, _act: ActId) -> Option<BookId> {
        None
    }

    /// The authoritative parent of a folder. A folder may sit at tenant, entity, book, or another
    /// folder scope; callers must reject/collapse cycles in their source graph.
    fn parent_of_folder(&self, _folder: FolderId) -> Option<Scope> {
        None
    }

    /// The authoritative parent of a template library (normally Tenant or Entity).
    fn parent_of_template_library(&self, _library: TemplateLibraryId) -> Option<Scope> {
        None
    }

    /// The authoritative parent of an archive resource (normally Repository, Book, Entity, or
    /// Tenant).
    fn parent_of_archive(&self, _archive: ArchiveId) -> Option<Scope> {
        None
    }

    /// The authoritative parent of an integration/connector (normally Tenant).
    fn parent_of_integration(&self, _integration: IntegrationId) -> Option<Scope> {
        None
    }

    /// The tenant/entity parent of a storage repository.
    fn parent_of_repository(&self, _repository: RepositoryId) -> Option<Scope> {
        None
    }

    /// Resolve one narrowing hop. The default composes the source-compatible book/entity methods
    /// with the additive ROL-03 relations. `Global` and `Tenant` have no parent.
    fn parent_scope(&self, scope: Scope) -> Option<Scope> {
        match scope {
            Scope::Global | Scope::Tenant(_) => None,
            Scope::Entity(entity) => self.tenant_of(entity).map(Scope::Tenant),
            Scope::Book(book) => self.entity_of(book).map(Scope::Entity),
            Scope::Act(act) => self.book_of_act(act).map(Scope::Book),
            Scope::Folder(folder) => self.parent_of_folder(folder),
            Scope::TemplateLibrary(library) => self.parent_of_template_library(library),
            Scope::Archive(archive) => self.parent_of_archive(archive),
            Scope::Integration(integration) => self.parent_of_integration(integration),
            Scope::Repository(repository) => self.parent_of_repository(repository),
        }
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
/// module docs). The relation is walked from target toward its authoritative parents, never from a
/// narrow grant outward. Eight hops cover the supported hierarchy while bounding malformed cycles.
#[must_use]
pub fn scope_covers(grant: Scope, target: Scope, books: &impl BookScope) -> bool {
    if grant == Scope::Global {
        return true;
    }
    let mut current = Some(target);
    for _ in 0..8 {
        let Some(scope) = current else {
            return false;
        };
        if scope == grant {
            return true;
        }
        current = books.parent_scope(scope);
    }
    false
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
    fn a(n: u128) -> ActId {
        ActId(Uuid::from_u128(0xAC70_0000 + n))
    }
    fn f(n: u128) -> FolderId {
        FolderId(Uuid::from_u128(0xF010_0000 + n))
    }
    fn tl(n: u128) -> TemplateLibraryId {
        TemplateLibraryId(Uuid::from_u128(0x7E40_0000 + n))
    }
    fn ar(n: u128) -> ArchiveId {
        ArchiveId(Uuid::from_u128(0xA2C0_0000 + n))
    }
    fn integration(n: u128) -> IntegrationId {
        IntegrationId(Uuid::from_u128(0x1A7E_0000 + n))
    }
    fn repository(n: u128) -> RepositoryId {
        RepositoryId(Uuid::from_u128(0x2E90_0000 + n))
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
        acts: HashMap<ActId, BookId>,
    }
    impl BookScope for Rel {
        fn entity_of(&self, book: BookId) -> Option<EntityId> {
            self.books.get(&book).copied()
        }
        fn tenant_of(&self, entity: EntityId) -> Option<TenantId> {
            self.tenants.get(&entity).copied()
        }
        fn book_of_act(&self, act: ActId) -> Option<BookId> {
            self.acts.get(&act).copied()
        }
        fn parent_of_folder(&self, folder: FolderId) -> Option<Scope> {
            (folder == f(1)).then_some(Scope::Book(b(10)))
        }
        fn parent_of_template_library(&self, library: TemplateLibraryId) -> Option<Scope> {
            (library == tl(1)).then_some(Scope::Tenant(t(0xA)))
        }
        fn parent_of_archive(&self, archive: ArchiveId) -> Option<Scope> {
            (archive == ar(1)).then_some(Scope::Repository(repository(1)))
        }
        fn parent_of_integration(&self, target: IntegrationId) -> Option<Scope> {
            (target == integration(1)).then_some(Scope::Tenant(t(0xA)))
        }
        fn parent_of_repository(&self, target: RepositoryId) -> Option<Scope> {
            (target == repository(1)).then_some(Scope::Tenant(t(0xA)))
        }
    }
    /// Books 10/11 → entity 1 → tenant A; book 20 → entity 2 → tenant B.
    fn tenant_rel() -> Rel {
        Rel {
            books: HashMap::from([(b(10), e(1)), (b(11), e(1)), (b(20), e(2))]),
            tenants: HashMap::from([(e(1), t(0xA)), (e(2), t(0xB))]),
            acts: HashMap::from([(a(100), b(10)), (a(200), b(20))]),
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

    #[test]
    fn act_scope_is_first_class_and_wider_authority_narrows_to_it() {
        let r = tenant_rel();
        assert!(scope_covers(Scope::Act(a(100)), Scope::Act(a(100)), &r));
        assert!(scope_covers(Scope::Book(b(10)), Scope::Act(a(100)), &r));
        assert!(scope_covers(Scope::Entity(e(1)), Scope::Act(a(100)), &r));
        assert!(scope_covers(Scope::Tenant(t(0xA)), Scope::Act(a(100)), &r));
        assert!(!scope_covers(Scope::Act(a(100)), Scope::Book(b(10)), &r));
        assert!(!scope_covers(Scope::Tenant(t(0xA)), Scope::Act(a(200)), &r));
        assert!(!scope_covers(Scope::Book(b(10)), Scope::Act(a(999)), &r));
    }

    #[test]
    fn remaining_rol03_and_repository_leaves_follow_authoritative_parents() {
        let r = tenant_rel();
        assert!(scope_covers(Scope::Book(b(10)), Scope::Folder(f(1)), &r));
        assert!(scope_covers(
            Scope::Tenant(t(0xA)),
            Scope::TemplateLibrary(tl(1)),
            &r
        ));
        assert!(scope_covers(
            Scope::Tenant(t(0xA)),
            Scope::Integration(integration(1)),
            &r
        ));
        assert!(scope_covers(
            Scope::Repository(repository(1)),
            Scope::Archive(ar(1)),
            &r
        ));
        assert!(scope_covers(
            Scope::Tenant(t(0xA)),
            Scope::Archive(ar(1)),
            &r
        ));
        assert!(!scope_covers(
            Scope::Tenant(t(0xB)),
            Scope::Archive(ar(1)),
            &r
        ));
        assert!(scope_covers(
            Scope::Folder(f(99)),
            Scope::Folder(f(99)),
            &NoBooks
        ));
    }

    #[test]
    fn malformed_parent_cycles_are_bounded_and_fail_closed() {
        struct Cycle;
        impl BookScope for Cycle {
            fn entity_of(&self, _book: BookId) -> Option<EntityId> {
                None
            }
            fn parent_of_folder(&self, folder: FolderId) -> Option<Scope> {
                Some(Scope::Folder(folder))
            }
        }
        assert!(!scope_covers(
            Scope::Tenant(t(0xA)),
            Scope::Folder(f(1)),
            &Cycle
        ));
    }
}
