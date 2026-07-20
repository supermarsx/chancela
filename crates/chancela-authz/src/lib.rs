//! `chancela-authz` — the scoped RBAC security core (t64-E1).
//!
//! This crate is the **authorization model** every sensitive feature gates through: a fine-grained
//! [`Permission`] catalog, [`Scope`]d authority with **narrowing-only** coverage ([`scope_covers`]),
//! [`Role`]s-as-data with seeded defaults, scoped revocable [`Delegation`], the derivation of a
//! principal's [`effective_permissions`], and the **escalation invariants** that make privilege
//! escalation structurally impossible:
//!
//! - **Subset invariant** — [`can_define_role`] / [`can_assign_role`]: you may only author or assign a
//!   role whose entire permission-set is within your *own* effective authority (at the relevant
//!   scope). Holding `role.manage`/`role.assign` does **not** exempt this check.
//! - **Scope-narrowing** — [`scope_covers`] is narrowing-only, so a scoped grant can never satisfy a
//!   `Global` check and authority never widens.
//! - **Delegation invariant** — [`can_delegate`]: you may only delegate a **non-meta** permission you
//!   hold **via a role** at that scope. Because a *received* (delegated) permission is never a role
//!   grant, **re-delegation is structurally impossible**.
//! - **Protected-Owner** — the Owner role is undeletable and its permission-set locked
//!   ([`Role::can_be_deleted`] / [`Role::can_edit_permission_set`]); [`last_owner_guard`] keeps ≥1
//!   Owner assignment.
//!
//! **Purity / fail-closed.** No clock, no network, no store: the caller supplies `now` and the
//! authoritative scope-parent relation ([`BookScope`], retained under its source-compatible name).
//! Unknown resources, missing roles and empty authority all resolve to *deny*. The invariants are
//! enforced by construction (a delegated grant is kept in a separate bucket that the delegation
//! check never reads), not merely spot-checked.

mod assignment;
mod delegation;
mod permission;
mod role;
mod scope;

use std::collections::HashSet;

use time::OffsetDateTime;

pub use assignment::RoleAssignment;
pub use delegation::{Delegation, UserId};
pub use permission::Permission;
pub use role::{
    API_CLIENT_ROLE_ID, AUDITOR_ROLE_ID, COMPANY_OWNER_ROLE_ID, CORPORATE_SECRETARY_ROLE_ID,
    GESTOR_ROLE_ID, GUEST_ROLE_ID, LEGAL_COUNSEL_ROLE_ID, LEITOR_ROLE_ID, OWNER_ROLE_ID,
    PLATFORM_ADMIN_ROLE_ID, RECORDS_MANAGER_ROLE_ID, REVIEWER_ROLE_ID, Role, RoleCatalog, RoleId,
    SIGNATARIO_ROLE_ID, SIGNATORY_ROLE_ID, TENANT_ADMIN_ROLE_ID, default_roles,
};
pub use scope::{
    ActId, ArchiveId, BookId, BookScope, CompanyId, EntityId, FolderId, IntegrationId, NoBooks,
    RepositoryId, Scope, TemplateLibraryId, TenantId, scope_covers,
};

/// A principal's resolved authority: the set of `(permission, scope)` grants, partitioned by whether
/// each grant arrived **via a role** or **via a delegation**.
///
/// The partition is load-bearing. [`has_permission`] answers over the *union* (all authority), but
/// [`can_delegate`] answers over the **role grants only** — so a permission a principal merely
/// *received* by delegation can never be re-delegated. Constructed by [`effective_permissions`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScopedPermissionSet {
    role_grants: HashSet<(Permission, Scope)>,
    delegated_grants: HashSet<(Permission, Scope)>,
}

impl ScopedPermissionSet {
    /// An empty authority (holds nothing anywhere). Fail-closed default.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Iterate over grants held **via a role**.
    pub fn role_grants(&self) -> impl Iterator<Item = (Permission, Scope)> + '_ {
        self.role_grants.iter().copied()
    }

    /// Iterate over grants held **via a delegation**.
    pub fn delegated_grants(&self) -> impl Iterator<Item = (Permission, Scope)> + '_ {
        self.delegated_grants.iter().copied()
    }

    /// Iterate over every grant (role ∪ delegation).
    pub fn all_grants(&self) -> impl Iterator<Item = (Permission, Scope)> + '_ {
        self.role_grants
            .iter()
            .chain(self.delegated_grants.iter())
            .copied()
    }

    /// Holds nothing at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.role_grants.is_empty() && self.delegated_grants.is_empty()
    }

    /// Does the principal hold `perm` at a grant whose scope covers `target` — considering **role
    /// grants only**? This is the basis for the delegation invariant (a received permission is not a
    /// role grant, so it cannot ground a further delegation).
    #[must_use]
    pub fn has_via_role(&self, perm: Permission, target: Scope, books: &impl BookScope) -> bool {
        self.role_grants
            .iter()
            .any(|&(p, s)| p == perm && scope_covers(s, target, books))
    }
}

/// Derive a principal's effective authority from their role assignments, the role catalog, and the
/// delegations addressed to them, evaluated at `now`.
///
/// - Each [`RoleAssignment`] contributes its role's whole permission-set at the assignment's scope
///   (a missing role in the catalog contributes nothing — fail-closed).
/// - Each **active** (started, non-revoked, non-expired) [`Delegation`] whose `to == principal`
///   contributes **every** permission in its set ([`Delegation::permissions`]) at its scope, into
///   the *delegated* bucket. A revoked or expired delegation contributes none of them — the set
///   shares one lifetime, so it starts and ends together.
///
/// `delegations` may be the full delegation table; only those addressed to `principal` are consulted.
#[must_use]
pub fn effective_permissions(
    principal: UserId,
    assignments: &[RoleAssignment],
    roles: &RoleCatalog,
    delegations: &[Delegation],
    now: OffsetDateTime,
) -> ScopedPermissionSet {
    let mut set = ScopedPermissionSet::new();

    for a in assignments {
        if let Some(role) = roles.get(a.role_id) {
            for &perm in &role.permission_set {
                set.role_grants.insert((perm, a.scope));
            }
        }
    }

    for d in delegations {
        if d.to == principal && d.is_active(now) {
            for perm in d.permissions() {
                set.delegated_grants.insert((perm, d.scope));
            }
        }
    }

    set
}

/// Does `effective` grant `perm` covering `target`? Considers **all** authority (role ∪ delegation)
/// and uses the narrowing-only [`scope_covers`]. This is the primary check the API's
/// `require_permission(perm, scope)` gate composes with.
#[must_use]
pub fn has_permission(
    effective: &ScopedPermissionSet,
    perm: Permission,
    target: Scope,
    books: &impl BookScope,
) -> bool {
    effective
        .all_grants()
        .any(|(p, s)| p == perm && scope_covers(s, target, books))
}

/// **Subset invariant (role authoring).** May a principal with `actor` authority *create or edit* a
/// role whose contents are `permission_set`?
///
/// True iff **every** permission in `permission_set` is within the actor's own authority at `Global`
/// scope — because a role in the catalog is assignable at any scope, its contents must be within the
/// actor's *global* ceiling. Holding `role.manage` does not exempt this (this function never consults
/// it). Editing the protected Owner role is barred separately via [`Role::can_edit_permission_set`].
#[must_use]
pub fn can_define_role<'a>(
    actor: &ScopedPermissionSet,
    permission_set: impl IntoIterator<Item = &'a Permission>,
    books: &impl BookScope,
) -> bool {
    permission_set
        .into_iter()
        .all(|&p| has_permission(actor, p, Scope::Global, books))
}

/// **Subset invariant (role assignment).** May a principal with `actor` authority *assign* `role` at
/// `scope` to someone?
///
/// True iff **every** permission in the role's set is within the actor's own authority covering
/// `scope`. So assigning a role at `Global` requires the actor to hold each permission globally;
/// assigning at `Entity(E)` requires holding each permission covering `Entity(E)`. You cannot grant
/// authority you do not hold — not even by assigning a pre-existing "fat" role. Holding `role.assign`
/// does not exempt this.
#[must_use]
pub fn can_assign_role(
    actor: &ScopedPermissionSet,
    role: &Role,
    scope: Scope,
    books: &impl BookScope,
) -> bool {
    role.permission_set
        .iter()
        .all(|&p| has_permission(actor, p, scope, books))
}

/// **Delegation invariant.** May a principal with `actor` authority *delegate* `perm` at `scope`?
///
/// True iff `perm` is **not** a meta-permission AND the actor holds `perm` covering `scope` **via a
/// role** ([`ScopedPermissionSet::has_via_role`]). The via-role requirement simultaneously enforces
/// "delegate only what you hold" and **forbids re-delegation** — a permission the actor merely
/// received by delegation lives in the delegated bucket, which this check never reads.
#[must_use]
pub fn can_delegate(
    actor: &ScopedPermissionSet,
    perm: Permission,
    scope: Scope,
    books: &impl BookScope,
) -> bool {
    !perm.is_meta() && actor.has_via_role(perm, scope, books)
}

/// Why a permission may not be delegated. Returned by [`can_delegate_all`] so the caller can name
/// the offender instead of refusing the whole batch anonymously.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelegationRefusal {
    /// The permission is a meta-permission, which is never delegable.
    Meta(Permission),
    /// The actor does not hold the permission **via a role** covering the scope — delegating it
    /// would either escalate privilege or re-delegate a received grant.
    NotHeldViaRole(Permission),
}

impl DelegationRefusal {
    /// The permission that caused the refusal.
    #[must_use]
    pub fn permission(&self) -> Permission {
        match *self {
            DelegationRefusal::Meta(p) | DelegationRefusal::NotHeldViaRole(p) => p,
        }
    }
}

/// **Delegation invariant, applied element-wise.** May a principal with `actor` authority delegate
/// *every* permission in `permissions` at `scope`?
///
/// Each element is put through [`can_delegate`] independently — there is no aggregate shortcut, so a
/// batch can never smuggle a verb past the ceiling on the strength of its siblings. Returns the
/// **first** offender (in iteration order) rather than a bare bool, so the caller can refuse the
/// whole delegation and say which permission was the problem. An empty set is vacuously delegable;
/// callers must reject it separately (a delegation of nothing is meaningless, not dangerous).
///
/// # Errors
/// The first permission that is meta or not held via a role at `scope`.
pub fn can_delegate_all(
    actor: &ScopedPermissionSet,
    permissions: impl IntoIterator<Item = Permission>,
    scope: Scope,
    books: &impl BookScope,
) -> Result<(), DelegationRefusal> {
    for perm in permissions {
        if perm.is_meta() {
            return Err(DelegationRefusal::Meta(perm));
        }
        if !actor.has_via_role(perm, scope, books) {
            return Err(DelegationRefusal::NotHeldViaRole(perm));
        }
    }
    Ok(())
}

/// **Last-Owner guard.** Given the number of principals that currently hold an administrative Owner
/// assignment (Owner role at `Global` — see [`RoleAssignment::is_owner_admin`]), is it safe to remove
/// *one* of them (revoke the assignment, deactivate the user, etc.)?
///
/// Safe iff **more than one** holder currently exists, so at least one Owner always remains and the
/// instance can never reach a no-super-user / locked-out state. Pure; the API supplies the count.
#[must_use]
pub fn last_owner_guard(current_owner_admin_holders: usize) -> bool {
    current_owner_admin_holders > 1
}

/// Count the principals holding an administrative Owner assignment, over `(principal, assignment)`
/// pairs. Deduplicates by principal (a user with two Owner@Global assignments counts once), so the
/// count is a true holder count for [`last_owner_guard`].
#[must_use]
pub fn count_owner_admin_holders<'a>(
    assignments: impl IntoIterator<Item = (UserId, &'a RoleAssignment)>,
) -> usize {
    assignments
        .into_iter()
        .filter(|(_, a)| a.is_owner_admin())
        .map(|(u, _)| u)
        .collect::<HashSet<_>>()
        .len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use time::Duration;
    use uuid::Uuid;

    fn uid(n: u128) -> UserId {
        UserId(Uuid::from_u128(n))
    }
    fn ent(n: u128) -> EntityId {
        EntityId(Uuid::from_u128(0xE00 + n))
    }
    fn bk(n: u128) -> BookId {
        BookId(Uuid::from_u128(0xB00 + n))
    }

    /// Book 1 & 2 belong to entity 1; book 3 to entity 2.
    fn books() -> impl BookScope {
        let mut m = HashMap::new();
        m.insert(bk(1), ent(1));
        m.insert(bk(2), ent(1));
        m.insert(bk(3), ent(2));
        move |b: BookId| m.get(&b).copied()
    }

    fn epoch() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH
    }

    /// Owner @ Global for `principal`.
    fn owner_eff() -> ScopedPermissionSet {
        let cat = RoleCatalog::seeded_defaults();
        effective_permissions(
            uid(1),
            &[RoleAssignment::new(OWNER_ROLE_ID, Scope::Global)],
            &cat,
            &[],
            epoch(),
        )
    }

    // ---- effective_permissions -------------------------------------------------------------

    #[test]
    fn effective_unions_global_and_scoped_roles_and_active_delegations() {
        let cat = RoleCatalog::seeded_defaults();
        let principal = uid(1);
        let assignments = [
            RoleAssignment::new(LEITOR_ROLE_ID, Scope::Global),
            RoleAssignment::new(GESTOR_ROLE_ID, Scope::Entity(ent(1))),
        ];
        let delegations = [
            Delegation::new(uid(9), principal, Permission::DataBackup, Scope::Global),
            // Addressed to someone else — must NOT contribute.
            Delegation::new(uid(9), uid(2), Permission::DataWipe, Scope::Global),
            // Revoked — must NOT contribute.
            Delegation {
                revoked: true,
                ..Delegation::new(uid(9), principal, Permission::LawManage, Scope::Global)
            },
        ];
        let eff = effective_permissions(principal, &assignments, &cat, &delegations, epoch());

        // Global read from Leitor.
        assert!(has_permission(
            &eff,
            Permission::EntityRead,
            Scope::Global,
            &books()
        ));
        // Gestor's book.open only within entity 1 (and its books), never globally.
        assert!(has_permission(
            &eff,
            Permission::BookOpen,
            Scope::Entity(ent(1)),
            &books()
        ));
        assert!(has_permission(
            &eff,
            Permission::BookOpen,
            Scope::Book(bk(1)),
            &books()
        ));
        assert!(!has_permission(
            &eff,
            Permission::BookOpen,
            Scope::Global,
            &books()
        ));
        assert!(!has_permission(
            &eff,
            Permission::BookOpen,
            Scope::Entity(ent(2)),
            &books()
        ));
        // Delegated data.backup present; other-principal & revoked delegations absent.
        assert!(has_permission(
            &eff,
            Permission::DataBackup,
            Scope::Global,
            &books()
        ));
        assert!(!has_permission(
            &eff,
            Permission::DataWipe,
            Scope::Global,
            &books()
        ));
        assert!(!has_permission(
            &eff,
            Permission::LawManage,
            Scope::Global,
            &books()
        ));
    }

    #[test]
    fn expired_delegation_contributes_nothing() {
        let principal = uid(1);
        let cat = RoleCatalog::new();
        let d = Delegation::new(uid(9), principal, Permission::ActRead, Scope::Global)
            .expiring_at(epoch() + Duration::hours(1));
        let before = effective_permissions(principal, &[], &cat, std::slice::from_ref(&d), epoch());
        assert!(has_permission(
            &before,
            Permission::ActRead,
            Scope::Global,
            &NoBooks
        ));
        let after = effective_permissions(principal, &[], &cat, &[d], epoch() + Duration::hours(2));
        assert!(!has_permission(
            &after,
            Permission::ActRead,
            Scope::Global,
            &NoBooks
        ));
    }

    #[test]
    fn future_delegation_contributes_nothing_until_start() {
        let principal = uid(1);
        let cat = RoleCatalog::new();
        let starts_at = epoch() + Duration::hours(1);
        let d = Delegation::new(uid(9), principal, Permission::ActRead, Scope::Global)
            .starting_at(starts_at);

        let before = effective_permissions(
            principal,
            &[],
            &cat,
            std::slice::from_ref(&d),
            starts_at - Duration::seconds(1),
        );
        assert!(!has_permission(
            &before,
            Permission::ActRead,
            Scope::Global,
            &NoBooks
        ));

        let at_start = effective_permissions(principal, &[], &cat, &[d], starts_at);
        assert!(has_permission(
            &at_start,
            Permission::ActRead,
            Scope::Global,
            &NoBooks
        ));
    }

    #[test]
    fn missing_role_in_catalog_is_fail_closed() {
        let principal = uid(1);
        let empty = RoleCatalog::new();
        let eff = effective_permissions(
            principal,
            &[RoleAssignment::new(OWNER_ROLE_ID, Scope::Global)],
            &empty,
            &[],
            epoch(),
        );
        assert!(eff.is_empty());
        assert!(!has_permission(
            &eff,
            Permission::EntityRead,
            Scope::Global,
            &NoBooks
        ));
    }

    // ---- subset invariant: role definition -------------------------------------------------

    #[test]
    fn owner_can_define_any_role() {
        let owner = owner_eff();
        let all: Vec<_> = Permission::ALL.to_vec();
        assert!(can_define_role(&owner, all.iter(), &books()));
    }

    #[test]
    fn cannot_define_role_with_a_permission_you_lack() {
        // Actor holds only Leitor @ Global.
        let cat = RoleCatalog::seeded_defaults();
        let actor = effective_permissions(
            uid(1),
            &[RoleAssignment::new(LEITOR_ROLE_ID, Scope::Global)],
            &cat,
            &[],
            epoch(),
        );
        // Crafting a role that includes data.wipe (not held) must be refused.
        let crafted = [Permission::EntityRead, Permission::DataWipe];
        assert!(!can_define_role(&actor, crafted.iter(), &books()));
        // A role fully within the actor's authority is allowed.
        let ok = [Permission::EntityRead, Permission::BookRead];
        assert!(can_define_role(&actor, ok.iter(), &books()));
    }

    #[test]
    fn scoped_authority_cannot_define_a_global_assignable_role() {
        // Actor holds Gestor only within entity 1 — NOT globally. Role contents are checked at
        // Global (a catalog role is assignable anywhere), so the actor cannot author a role with
        // book.open even though they hold book.open within entity 1.
        let cat = RoleCatalog::seeded_defaults();
        let actor = effective_permissions(
            uid(1),
            &[RoleAssignment::new(GESTOR_ROLE_ID, Scope::Entity(ent(1)))],
            &cat,
            &[],
            epoch(),
        );
        assert!(!can_define_role(
            &actor,
            [Permission::BookOpen].iter(),
            &books()
        ));
    }

    #[test]
    fn holding_role_manage_does_not_exempt_subset_check() {
        // A bespoke role that grants role.manage but NOT data.wipe.
        let mut cat = RoleCatalog::seeded_defaults();
        let manager = Role {
            id: RoleId(Uuid::from_u128(0xAAAA)),
            name: "Gestor de Acessos".to_owned(),
            permission_set: [Permission::RoleManage, Permission::EntityRead]
                .into_iter()
                .collect(),
            protected: false,
        };
        cat.insert(manager.clone());
        let actor = effective_permissions(
            uid(1),
            &[RoleAssignment::new(manager.id, Scope::Global)],
            &cat,
            &[],
            epoch(),
        );
        // Has role.manage, yet still cannot mint a role containing data.wipe.
        assert!(has_permission(
            &actor,
            Permission::RoleManage,
            Scope::Global,
            &NoBooks
        ));
        assert!(!can_define_role(
            &actor,
            [Permission::DataWipe].iter(),
            &NoBooks
        ));
    }

    // ---- subset invariant: role assignment -------------------------------------------------

    #[test]
    fn cannot_assign_a_preexisting_fat_role_you_dont_cover() {
        // Actor holds only Leitor @ Global; tries to assign the Gestor (fat) role.
        let cat = RoleCatalog::seeded_defaults();
        let actor = effective_permissions(
            uid(1),
            &[RoleAssignment::new(LEITOR_ROLE_ID, Scope::Global)],
            &cat,
            &[],
            epoch(),
        );
        let gestor = cat.get(GESTOR_ROLE_ID).unwrap();
        assert!(!can_assign_role(&actor, gestor, Scope::Global, &books()));
        // But may assign Leitor (⊆ own authority).
        let leitor = cat.get(LEITOR_ROLE_ID).unwrap();
        assert!(can_assign_role(&actor, leitor, Scope::Global, &books()));
    }

    #[test]
    fn scoped_actor_can_assign_within_but_not_beyond_their_scope() {
        // Actor is Gestor of entity 1 only. They may assign Gestor scoped to entity 1 (or its books),
        // but NOT scoped to entity 2 or Global.
        let cat = RoleCatalog::seeded_defaults();
        let actor = effective_permissions(
            uid(1),
            &[RoleAssignment::new(GESTOR_ROLE_ID, Scope::Entity(ent(1)))],
            &cat,
            &[],
            epoch(),
        );
        let gestor = cat.get(GESTOR_ROLE_ID).unwrap();
        assert!(can_assign_role(
            &actor,
            gestor,
            Scope::Entity(ent(1)),
            &books()
        ));
        assert!(can_assign_role(
            &actor,
            gestor,
            Scope::Book(bk(1)),
            &books()
        ));
        assert!(!can_assign_role(
            &actor,
            gestor,
            Scope::Entity(ent(2)),
            &books()
        ));
        assert!(!can_assign_role(&actor, gestor, Scope::Global, &books()));
    }

    #[test]
    fn only_owner_can_assign_owner() {
        let cat = RoleCatalog::seeded_defaults();
        let owner = cat.owner().unwrap();
        // Owner actor: fine.
        assert!(can_assign_role(
            &owner_eff(),
            owner,
            Scope::Global,
            &books()
        ));
        // A Gestor cannot assign Owner (Owner contains meta + data.wipe the Gestor lacks).
        let gestor_actor = effective_permissions(
            uid(2),
            &[RoleAssignment::new(GESTOR_ROLE_ID, Scope::Global)],
            &cat,
            &[],
            epoch(),
        );
        assert!(!can_assign_role(
            &gestor_actor,
            owner,
            Scope::Global,
            &books()
        ));
    }

    // ---- delegation invariant --------------------------------------------------------------

    #[test]
    fn can_delegate_a_non_meta_perm_held_via_role() {
        let owner = owner_eff();
        assert!(can_delegate(
            &owner,
            Permission::ActRead,
            Scope::Global,
            &books()
        ));
        // Narrowing: Owner (global) may delegate at a narrower scope too.
        assert!(can_delegate(
            &owner,
            Permission::ActRead,
            Scope::Entity(ent(1)),
            &books()
        ));
    }

    #[test]
    fn cannot_delegate_a_meta_permission() {
        let owner = owner_eff();
        for meta in Permission::META {
            assert!(has_permission(&owner, meta, Scope::Global, &books()));
            assert!(!can_delegate(&owner, meta, Scope::Global, &books()));
        }
    }

    #[test]
    fn cannot_delegate_a_permission_you_lack() {
        let cat = RoleCatalog::seeded_defaults();
        let leitor = effective_permissions(
            uid(1),
            &[RoleAssignment::new(LEITOR_ROLE_ID, Scope::Global)],
            &cat,
            &[],
            epoch(),
        );
        assert!(!can_delegate(
            &leitor,
            Permission::DataWipe,
            Scope::Global,
            &books()
        ));
    }

    #[test]
    fn a_multi_permission_delegation_contributes_every_verb() {
        let cat = RoleCatalog::seeded_defaults();
        let grant = Delegation::with_permissions(
            uid(9),
            uid(1),
            [Permission::DataBackup, Permission::ActAdvance],
            Scope::Global,
        )
        .unwrap();
        let eff = effective_permissions(uid(1), &[], &cat, std::slice::from_ref(&grant), epoch());
        assert!(has_permission(
            &eff,
            Permission::DataBackup,
            Scope::Global,
            &books()
        ));
        assert!(has_permission(
            &eff,
            Permission::ActAdvance,
            Scope::Global,
            &books()
        ));
        // Every verb lands in the *delegated* bucket, so none of them can be re-delegated.
        assert_eq!(eff.role_grants().count(), 0);
        assert!(!can_delegate(
            &eff,
            Permission::ActAdvance,
            Scope::Global,
            &books()
        ));

        // Revoking the delegation withdraws the whole set at once — the set shares one lifetime.
        let mut revoked = grant;
        revoked.revoked = true;
        let eff = effective_permissions(uid(1), &[], &cat, &[revoked], epoch());
        assert!(eff.is_empty());
    }

    #[test]
    fn can_delegate_all_checks_element_wise_and_names_the_offender() {
        let owner = owner_eff();
        // A wholly-delegable batch passes.
        assert_eq!(
            can_delegate_all(
                &owner,
                [Permission::ActRead, Permission::ActAdvance],
                Scope::Global,
                &books()
            ),
            Ok(())
        );
        // One meta verb hidden behind delegable siblings still refuses the batch, by name.
        let meta = Permission::META[0];
        assert_eq!(
            can_delegate_all(
                &owner,
                [Permission::ActRead, meta, Permission::ActAdvance],
                Scope::Global,
                &books()
            ),
            Err(DelegationRefusal::Meta(meta))
        );

        // Above-ceiling: a Gestor of entity 1 cannot smuggle an entity-2 grant in behind a held one.
        let cat = RoleCatalog::seeded_defaults();
        let gestor = effective_permissions(
            uid(1),
            &[RoleAssignment::new(GESTOR_ROLE_ID, Scope::Entity(ent(1)))],
            &cat,
            &[],
            epoch(),
        );
        assert_eq!(
            can_delegate_all(
                &gestor,
                [Permission::BookOpen, Permission::DataWipe],
                Scope::Entity(ent(1)),
                &books()
            ),
            Err(DelegationRefusal::NotHeldViaRole(Permission::DataWipe))
        );
    }

    #[test]
    fn a_received_multi_delegation_cannot_be_re_delegated_element_wise() {
        let cat = RoleCatalog::seeded_defaults();
        // The attacker holds Leitor via a role and DataWipe only by delegation.
        let attacker = effective_permissions(
            uid(1),
            &[RoleAssignment::new(LEITOR_ROLE_ID, Scope::Global)],
            &cat,
            &[Delegation::new(
                uid(9),
                uid(1),
                Permission::DataWipe,
                Scope::Global,
            )],
            epoch(),
        );
        assert!(has_permission(
            &attacker,
            Permission::DataWipe,
            Scope::Global,
            &books()
        ));
        // Pairing it with a role-held verb does not launder it into a delegable batch.
        assert_eq!(
            can_delegate_all(
                &attacker,
                [Permission::ActRead, Permission::DataWipe],
                Scope::Global,
                &books()
            ),
            Err(DelegationRefusal::NotHeldViaRole(Permission::DataWipe))
        );
    }

    #[test]
    fn cannot_delegate_beyond_your_scope() {
        // Gestor of entity 1 may delegate book.open within entity 1 / its books, not entity 2 / Global.
        let cat = RoleCatalog::seeded_defaults();
        let actor = effective_permissions(
            uid(1),
            &[RoleAssignment::new(GESTOR_ROLE_ID, Scope::Entity(ent(1)))],
            &cat,
            &[],
            epoch(),
        );
        assert!(can_delegate(
            &actor,
            Permission::BookOpen,
            Scope::Entity(ent(1)),
            &books()
        ));
        assert!(can_delegate(
            &actor,
            Permission::BookOpen,
            Scope::Book(bk(1)),
            &books()
        ));
        assert!(!can_delegate(
            &actor,
            Permission::BookOpen,
            Scope::Book(bk(3)),
            &books()
        ));
        assert!(!can_delegate(
            &actor,
            Permission::BookOpen,
            Scope::Global,
            &books()
        ));
    }

    #[test]
    fn re_delegation_is_impossible() {
        // Principal 2 holds act.advance ONLY via a delegation from principal 1 — no role grants it.
        let principal = uid(2);
        let cat = RoleCatalog::new();
        let received = Delegation::new(uid(1), principal, Permission::ActAdvance, Scope::Global);
        let eff = effective_permissions(principal, &[], &cat, &[received], epoch());
        // They *hold* the permission...
        assert!(has_permission(
            &eff,
            Permission::ActAdvance,
            Scope::Global,
            &books()
        ));
        // ...but cannot re-delegate it (it is not a role grant).
        assert!(!can_delegate(
            &eff,
            Permission::ActAdvance,
            Scope::Global,
            &books()
        ));
    }

    // ---- protected-Owner + last-owner guard ------------------------------------------------

    #[test]
    fn protected_owner_is_locked_and_undeletable() {
        let owner = Role::owner();
        assert!(!owner.can_be_deleted());
        assert!(!owner.can_edit_permission_set());
    }

    #[test]
    fn last_owner_guard_blocks_removing_the_final_owner() {
        assert!(!last_owner_guard(1)); // one holder ⇒ not safe to remove
        assert!(!last_owner_guard(0)); // already none ⇒ never safe
        assert!(last_owner_guard(2)); // more than one ⇒ safe
    }

    #[test]
    fn count_owner_admin_holders_dedups_and_ignores_scoped_owner() {
        let a_owner = RoleAssignment::new(OWNER_ROLE_ID, Scope::Global);
        let a_scoped_owner = RoleAssignment::new(OWNER_ROLE_ID, Scope::Entity(ent(1)));
        let a_gestor = RoleAssignment::new(GESTOR_ROLE_ID, Scope::Global);
        let pairs = [
            (uid(1), &a_owner),
            (uid(1), &a_owner),        // same user twice → counts once
            (uid(2), &a_scoped_owner), // Owner but scoped → not an admin holder
            (uid(3), &a_gestor),       // not Owner
        ];
        assert_eq!(count_owner_admin_holders(pairs), 1);
    }

    // ---- ESCALATION BATTERY (every attempt must be DENIED) ---------------------------------

    /// A Gestor (broad but not Owner) tries every known way to escalate. All must fail.
    #[test]
    fn escalation_battery_all_denied() {
        let cat = RoleCatalog::seeded_defaults();
        let attacker = effective_permissions(
            uid(7),
            &[RoleAssignment::new(GESTOR_ROLE_ID, Scope::Global)],
            &cat,
            &[],
            epoch(),
        );
        let r = books();

        // 1. Craft a role that includes user.manage / role.manage / data.wipe they lack.
        assert!(!can_define_role(
            &attacker,
            [Permission::UserManage].iter(),
            &r
        ));
        assert!(!can_define_role(
            &attacker,
            [Permission::RoleManage].iter(),
            &r
        ));
        assert!(!can_define_role(
            &attacker,
            [Permission::DataWipe].iter(),
            &r
        ));
        assert!(!can_define_role(
            &attacker,
            [Permission::LedgerRecover].iter(),
            &r
        ));

        // 2. Assign the pre-existing Owner role (privilege grab via a fat role).
        assert!(!can_assign_role(
            &attacker,
            cat.owner().unwrap(),
            Scope::Global,
            &r
        ));

        // 3. Delegate a meta-permission (mint authority through a delegate).
        for meta in Permission::META {
            assert!(!can_delegate(&attacker, meta, Scope::Global, &r));
        }

        // 4. Delegate a permission they don't hold.
        assert!(!can_delegate(
            &attacker,
            Permission::DataWipe,
            Scope::Global,
            &r
        ));

        // 5. Use a scoped grant to satisfy a Global check (scope-escape upward).
        let scoped = effective_permissions(
            uid(8),
            &[RoleAssignment::new(GESTOR_ROLE_ID, Scope::Entity(ent(1)))],
            &cat,
            &[],
            epoch(),
        );
        assert!(!has_permission(
            &scoped,
            Permission::BookOpen,
            Scope::Global,
            &r
        ));
        // ...and cross-entity.
        assert!(!has_permission(
            &scoped,
            Permission::BookOpen,
            Scope::Entity(ent(2)),
            &r
        ));
        assert!(!has_permission(
            &scoped,
            Permission::BookOpen,
            Scope::Book(bk(3)),
            &r
        ));

        // 6. Re-delegate a received permission.
        let received = effective_permissions(
            uid(9),
            &[],
            &cat,
            &[Delegation::new(
                uid(1),
                uid(9),
                Permission::ActAdvance,
                Scope::Global,
            )],
            epoch(),
        );
        assert!(!can_delegate(
            &received,
            Permission::ActAdvance,
            Scope::Global,
            &r
        ));

        // 7. A holder of only role.assign still cannot assign a role above their ceiling.
        let mut cat2 = cat.clone();
        let assigner = Role {
            id: RoleId(Uuid::from_u128(0xBEEF)),
            name: "Atribuidor".to_owned(),
            permission_set: [Permission::RoleAssign].into_iter().collect(),
            protected: false,
        };
        cat2.insert(assigner.clone());
        let assigner_actor = effective_permissions(
            uid(10),
            &[RoleAssignment::new(assigner.id, Scope::Global)],
            &cat2,
            &[],
            epoch(),
        );
        assert!(has_permission(
            &assigner_actor,
            Permission::RoleAssign,
            Scope::Global,
            &r
        ));
        assert!(!can_assign_role(
            &assigner_actor,
            cat2.owner().unwrap(),
            Scope::Global,
            &r
        ));
        assert!(!can_assign_role(
            &assigner_actor,
            cat2.get(GESTOR_ROLE_ID).unwrap(),
            Scope::Global,
            &r
        ));
    }
}
