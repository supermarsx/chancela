//! Scoped, revocable, time-bounded delegation (t64 plan §2.5; **role-shaped** since t44).
//!
//! A [`Delegation`] hands **one or more funções** ([`RoleId`]s) from `from` to `to`, narrowed to a
//! scope, optionally starting in the future, and optionally expiring. Delegating is an act of
//! *substitution* — "act in my place as Secretário" — so the unit handed over is a role, not a
//! hand-assembled bag of verbs. It is pure data; start/expiry are evaluated against a caller-supplied
//! `now` (this crate holds no clock). The escalation invariants that make delegation safe —
//!
//! - delegate only a função whose **every** permission you hold **via a role** at that scope (kills
//!   privilege escalation AND re-delegation, since a *received* permission is never a role grant),
//! - a função containing a meta-permission is non-delegable,
//! - narrowing-only scope,
//!
//! — live in [`crate::can_delegate_role`]. A not-yet-started, expired, **suspended** or revoked
//! delegation contributes nothing to [`crate::effective_permissions`].
//!
//! ## Live, not snapshotted
//!
//! The record stores role **ids**, so an active delegation conveys whatever those roles grant *now*
//! ([`Delegation::granted_permissions`]). Editing a função moves the delegate's authority with it.
//! See [`crate::effective_permissions`] for why that is the intended — and the sharper — reading.
//!
//! ## Legacy permission-shaped records
//!
//! Records written before t44 carry `permission`/`extra_permissions` instead of `roles`. They keep
//! resolving verbatim: [`Delegation::granted_permissions`] unions the legacy verbs with the live
//! contents of the delegated funções. Nothing new is written in that shape.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::permission::Permission;
use crate::role::{RoleCatalog, RoleId};
use crate::scope::Scope;

/// Opaque identifier of a principal (a user). Transparent UUID on the wire — wire-compatible with the
/// API's `UserId` without depending on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct UserId(pub Uuid);

impl std::fmt::Display for UserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// A delegated **set of funções** sharing one grantor, grantee, scope and lifetime.
///
/// The model is intentionally minimal (the API layer, t64-E2, adds durable audit fields such as
/// `id`/`granted_at`/`revoked_by`); the security-relevant shape is frozen here.
///
/// **Wire shape (additive).** `roles` is the delegated set and is omitted when empty. The legacy
/// permission-shaped fields (`permission`/`extra_permissions`) are retained and optional, so a
/// pre-t44 record loads and resolves exactly as it did. New grants are role-shaped and carry no
/// `permission` key at all. Always read a delegation's authority through
/// [`Delegation::granted_permissions`], never the fields directly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Delegation {
    /// Grantor (the principal delegating). Must hold every permission in every delegated função at
    /// `scope` **via a role**.
    pub from: UserId,
    /// Grantee (the principal receiving the delegated funções).
    pub to: UserId,
    /// **Legacy.** The primary delegated permission of a pre-t44 permission-shaped record. `None`
    /// on every record written since — new delegations carry funções, not verbs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permission: Option<Permission>,
    /// **Legacy.** Any further delegated permissions beyond [`Self::permission`], in grant order.
    /// Empty on every role-shaped record.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra_permissions: Vec<Permission>,
    /// The delegated **funções**, in grant order. Each is subject to the delegation invariants
    /// *per permission it contains* — [`crate::can_delegate_role`] expands the role and checks every
    /// verb. Resolved **live** against the catalog at every authorization decision, so editing a
    /// função moves the delegate's authority with it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<RoleId>,
    /// The scope **every** delegated função is narrowed to. One scope per delegation: the set
    /// travels together.
    pub scope: Scope,
    /// When this delegation starts contributing authority. Legacy persisted delegations that lack
    /// this field default to the Unix epoch, preserving their previous immediate effect.
    #[serde(default = "default_starts_at")]
    pub starts_at: OffsetDateTime,
    /// Optional expiry; `None` means "until revoked". Evaluated against a caller-supplied `now`.
    #[serde(default)]
    pub expires_at: Option<OffsetDateTime>,
    /// Optional evidence/rationale for the delegation grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legal_basis: Option<String>,
    /// Whether the delegation has been revoked. A revoked delegation contributes nothing.
    #[serde(default)]
    pub revoked: bool,
    /// Whether the delegation is **suspended** — a reversible pause. A suspended delegation is
    /// still a live record (it can be resumed, and its lifetime keeps running) but it conveys
    /// **nothing**: [`Delegation::is_active`] is false, so the suspension is enforced where
    /// delegations resolve into effective authority, not by filtering a list in the UI.
    #[serde(default, skip_serializing_if = "is_false")]
    pub suspended: bool,
}

fn default_starts_at() -> OffsetDateTime {
    OffsetDateTime::UNIX_EPOCH
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_false(b: &bool) -> bool {
    !*b
}

impl Delegation {
    /// Build a **legacy** single-permission delegation (no expiry, not revoked). Retained for the
    /// pre-t44 records and the tests that model them; new grants use [`Delegation::with_roles`].
    #[must_use]
    pub fn new(from: UserId, to: UserId, permission: Permission, scope: Scope) -> Self {
        Delegation {
            from,
            to,
            permission: Some(permission),
            extra_permissions: Vec::new(),
            roles: Vec::new(),
            scope,
            starts_at: default_starts_at(),
            expires_at: None,
            legal_basis: None,
            revoked: false,
            suspended: false,
        }
    }

    /// Build a delegation over a **set of funções** (no expiry, not revoked). Duplicates are
    /// collapsed so the stored set is exactly the distinct role ids, in first-seen order. `None` for
    /// an empty set — a delegation that hands over no função is not representable.
    #[must_use]
    pub fn with_roles(
        from: UserId,
        to: UserId,
        roles: impl IntoIterator<Item = RoleId>,
        scope: Scope,
    ) -> Option<Self> {
        let mut distinct: Vec<RoleId> = Vec::new();
        for r in roles {
            if !distinct.contains(&r) {
                distinct.push(r);
            }
        }
        if distinct.is_empty() {
            return None;
        }
        Some(Delegation {
            from,
            to,
            permission: None,
            extra_permissions: Vec::new(),
            roles: distinct,
            scope,
            starts_at: default_starts_at(),
            expires_at: None,
            legal_basis: None,
            revoked: false,
            suspended: false,
        })
    }

    /// Build a delegation over a **set** of permissions (no expiry, not revoked). The first verb
    /// becomes [`Self::permission`] and the rest `extra_permissions`; duplicates are collapsed so
    /// the stored set is exactly the distinct verbs, in first-seen order. `None` for an empty set —
    /// a delegation that grants nothing is not representable.
    #[must_use]
    pub fn with_permissions(
        from: UserId,
        to: UserId,
        permissions: impl IntoIterator<Item = Permission>,
        scope: Scope,
    ) -> Option<Self> {
        let mut distinct: Vec<Permission> = Vec::new();
        for p in permissions {
            if !distinct.contains(&p) {
                distinct.push(p);
            }
        }
        let mut it = distinct.into_iter();
        let primary = it.next()?;
        let mut d = Delegation::new(from, to, primary, scope);
        d.extra_permissions = it.collect();
        Some(d)
    }

    /// The **legacy** permissions this delegation carries directly, in grant order. Empty for every
    /// role-shaped record. This is not a delegation's full authority — use
    /// [`Delegation::granted_permissions`], which also expands the delegated funções.
    #[must_use]
    pub fn permissions(&self) -> Vec<Permission> {
        let mut out = Vec::with_capacity(1 + self.extra_permissions.len());
        out.extend(self.permission);
        for &p in &self.extra_permissions {
            if !out.contains(&p) {
                out.push(p);
            }
        }
        out
    }

    /// The delegated funções, in grant order.
    #[must_use]
    pub fn roles(&self) -> &[RoleId] {
        &self.roles
    }

    /// Every permission this delegation currently conveys: the legacy verbs (if any) unioned with
    /// the **live** contents of every delegated função, de-duplicated, legacy-first then role order.
    ///
    /// Resolved against `catalog` at call time — *not* snapshotted at grant time. A função missing
    /// from the catalog contributes nothing (fail-closed), exactly as a missing role does for a role
    /// assignment. This is the **only** correct way to enumerate a delegation's authority.
    #[must_use]
    pub fn granted_permissions(&self, catalog: &RoleCatalog) -> Vec<Permission> {
        let mut out = self.permissions();
        for &role_id in &self.roles {
            let Some(role) = catalog.get(role_id) else {
                continue;
            };
            for &p in &role.permission_set {
                if !out.contains(&p) {
                    out.push(p);
                }
            }
        }
        out
    }

    /// With a start timestamp.
    #[must_use]
    pub fn starting_at(mut self, at: OffsetDateTime) -> Self {
        self.starts_at = at;
        self
    }

    /// With an expiry.
    #[must_use]
    pub fn expiring_at(mut self, at: OffsetDateTime) -> Self {
        self.expires_at = Some(at);
        self
    }

    /// With an optional legal basis.
    #[must_use]
    pub fn with_legal_basis(mut self, legal_basis: Option<String>) -> Self {
        self.legal_basis = legal_basis;
        self
    }

    /// Has this delegation started at `now`? Start is inclusive — at exactly `starts_at`, the grant
    /// may contribute if it is not also expired or revoked.
    #[must_use]
    pub fn has_started(&self, now: OffsetDateTime) -> bool {
        now >= self.starts_at
    }

    /// Has this delegation expired at `now`? A delegation with no expiry never expires. Expiry is
    /// inclusive of the boundary — at exactly `expires_at` the grant is spent.
    #[must_use]
    pub fn is_expired(&self, now: OffsetDateTime) -> bool {
        matches!(self.expires_at, Some(exp) if now >= exp)
    }

    /// Is this delegation currently contributing authority? True iff it has started and is **not
    /// revoked, not suspended and not expired**.
    ///
    /// Suspension is checked *here*, at the single point every resolution path funnels through
    /// ([`crate::effective_permissions`]), so a paused delegation conveys nothing regardless of what
    /// any list or UI chooses to show.
    #[must_use]
    pub fn is_active(&self, now: OffsetDateTime) -> bool {
        self.has_started(now) && !self.revoked && !self.suspended && !self.is_expired(now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::role::Role;
    use time::Duration;

    fn uid(n: u128) -> UserId {
        UserId(Uuid::from_u128(n))
    }

    #[test]
    fn no_expiry_is_active_until_revoked() {
        let now = OffsetDateTime::UNIX_EPOCH;
        let d = Delegation::new(uid(1), uid(2), Permission::ActRead, Scope::Global);
        assert!(d.is_active(now));
        let mut revoked = d.clone();
        revoked.revoked = true;
        assert!(!revoked.is_active(now));
    }

    #[test]
    fn expiry_boundary_is_inclusive() {
        let now = OffsetDateTime::UNIX_EPOCH;
        let d = Delegation::new(uid(1), uid(2), Permission::ActRead, Scope::Global)
            .expiring_at(now + Duration::hours(1));
        assert!(d.is_active(now));
        assert!(!d.is_active(now + Duration::hours(1)));
        assert!(!d.is_active(now + Duration::hours(2)));
    }

    #[test]
    fn start_boundary_is_inclusive() {
        let now = OffsetDateTime::UNIX_EPOCH;
        let starts_at = now + Duration::hours(1);
        let d = Delegation::new(uid(1), uid(2), Permission::ActRead, Scope::Global)
            .starting_at(starts_at);
        assert!(!d.is_active(now));
        assert!(d.is_active(starts_at));
    }

    #[test]
    fn a_multi_permission_delegation_lists_every_verb_in_order_without_duplicates() {
        let d = Delegation::with_permissions(
            uid(1),
            uid(2),
            [
                Permission::ActRead,
                Permission::ActAdvance,
                Permission::ActRead,
            ],
            Scope::Global,
        )
        .expect("non-empty set");
        assert_eq!(d.permission, Some(Permission::ActRead));
        assert_eq!(d.extra_permissions, vec![Permission::ActAdvance]);
        assert_eq!(
            d.permissions(),
            vec![Permission::ActRead, Permission::ActAdvance]
        );
    }

    #[test]
    fn an_empty_permission_set_is_not_representable() {
        assert!(Delegation::with_permissions(uid(1), uid(2), [], Scope::Global).is_none());
    }

    #[test]
    fn extra_permissions_round_trip_and_are_omitted_when_empty() {
        let multi = Delegation::with_permissions(
            uid(1),
            uid(2),
            [Permission::ActRead, Permission::ActAdvance],
            Scope::Global,
        )
        .unwrap();
        let value = serde_json::to_value(&multi).unwrap();
        assert_eq!(value["permission"], "act.read");
        assert_eq!(value["extra_permissions"][0], "act.advance");
        let back: Delegation = serde_json::from_value(value).unwrap();
        assert_eq!(back, multi);

        // A single-permission delegation keeps the original one-permission wire shape exactly.
        let single = Delegation::new(uid(1), uid(2), Permission::ActRead, Scope::Global);
        let value = serde_json::to_value(&single).unwrap();
        assert!(value.get("extra_permissions").is_none());
    }

    // ---- role-shaped delegations (t44) -----------------------------------------------------

    fn rid(n: u128) -> RoleId {
        RoleId(Uuid::from_u128(0xF00 + n))
    }

    #[test]
    fn a_delegation_of_funcoes_lists_them_in_order_without_duplicates() {
        let d = Delegation::with_roles(uid(1), uid(2), [rid(1), rid(2), rid(1)], Scope::Global)
            .expect("non-empty set");
        assert_eq!(d.roles(), [rid(1), rid(2)]);
        // Nothing permission-shaped is written on a new grant.
        assert_eq!(d.permission, None);
        assert!(d.permissions().is_empty());
    }

    #[test]
    fn a_delegation_of_no_funcao_is_not_representable() {
        assert!(Delegation::with_roles(uid(1), uid(2), [], Scope::Global).is_none());
    }

    #[test]
    fn a_funcao_delegation_conveys_the_roles_current_permissions_not_a_snapshot() {
        let secretario = Role {
            id: rid(1),
            name: "Secretário".to_owned(),
            permission_set: [Permission::ActRead, Permission::ActDraft]
                .into_iter()
                .collect(),
            protected: false,
        };
        let mut catalog = RoleCatalog::new();
        catalog.insert(secretario.clone());

        let d = Delegation::with_roles(uid(1), uid(2), [rid(1)], Scope::Global).unwrap();
        assert_eq!(
            d.granted_permissions(&catalog),
            vec![Permission::ActRead, Permission::ActDraft]
        );

        // Edit the função — the SAME delegation record now conveys the new set. This is the live
        // reading: the delegate stands in the role, whatever the role is today.
        catalog.insert(Role {
            permission_set: [Permission::ActRead].into_iter().collect(),
            ..secretario
        });
        assert_eq!(d.granted_permissions(&catalog), vec![Permission::ActRead]);

        // A função that has left the catalog conveys nothing (fail-closed).
        assert_eq!(
            d.granted_permissions(&RoleCatalog::new()),
            Vec::<Permission>::new()
        );
    }

    #[test]
    fn a_suspended_delegation_is_inactive_and_resumes_cleanly() {
        let now = OffsetDateTime::UNIX_EPOCH;
        let mut d = Delegation::with_roles(uid(1), uid(2), [rid(1)], Scope::Global).unwrap();
        assert!(d.is_active(now));
        d.suspended = true;
        assert!(!d.is_active(now));
        // Suspension is orthogonal to revocation: the record is intact and reversible.
        assert!(!d.revoked);
        d.suspended = false;
        assert!(d.is_active(now));
    }

    #[test]
    fn roles_and_suspended_round_trip_and_are_omitted_when_unset() {
        let d = Delegation::with_roles(uid(1), uid(2), [rid(1)], Scope::Global).unwrap();
        let value = serde_json::to_value(&d).unwrap();
        // A role-shaped record carries no legacy permission keys at all…
        assert!(value.get("permission").is_none());
        assert!(value.get("extra_permissions").is_none());
        // …and an unsuspended one carries no `suspended` key.
        assert!(value.get("suspended").is_none());
        assert_eq!(value["roles"][0], serde_json::json!(rid(1).0));
        assert_eq!(serde_json::from_value::<Delegation>(value).unwrap(), d);

        let suspended = Delegation {
            suspended: true,
            ..d
        };
        let value = serde_json::to_value(&suspended).unwrap();
        assert_eq!(value["suspended"], true);
        assert_eq!(
            serde_json::from_value::<Delegation>(value).unwrap(),
            suspended
        );
    }

    /// The migration promise, checked at the byte level rather than by naming absent keys: adding
    /// `roles` and `suspended` must have changed **nothing** on the wire for an unsuspended record.
    /// The reference shape is a struct carrying exactly the pre-t44 fields, so this compares two
    /// serialisations rather than a hand-copied literal (which would drift with the timestamp format).
    #[test]
    fn an_unsuspended_record_serialises_byte_identically_to_the_pre_t44_shape() {
        /// The `Delegation` wire shape as it stood before t44 — field order, names and attributes.
        #[derive(Serialize)]
        struct PreT44 {
            from: UserId,
            to: UserId,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            permission: Option<Permission>,
            #[serde(default, skip_serializing_if = "Vec::is_empty")]
            extra_permissions: Vec<Permission>,
            scope: Scope,
            starts_at: OffsetDateTime,
            #[serde(default)]
            expires_at: Option<OffsetDateTime>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            legal_basis: Option<String>,
            #[serde(default)]
            revoked: bool,
        }

        let now = OffsetDateTime::UNIX_EPOCH;
        let current = Delegation::with_permissions(
            uid(1),
            uid(2),
            [Permission::ActRead, Permission::ActAdvance],
            Scope::Global,
        )
        .unwrap()
        .starting_at(now)
        .expiring_at(now + Duration::hours(1))
        .with_legal_basis(Some("acta n.º 12".to_owned()));
        let reference = PreT44 {
            from: current.from,
            to: current.to,
            permission: current.permission,
            extra_permissions: current.extra_permissions.clone(),
            scope: current.scope,
            starts_at: current.starts_at,
            expires_at: current.expires_at,
            legal_basis: current.legal_basis.clone(),
            revoked: current.revoked,
        };

        assert_eq!(
            serde_json::to_string(&current).unwrap(),
            serde_json::to_string(&reference).unwrap(),
            "an unsuspended, role-less delegation must serialise exactly as it did before t44"
        );

        // …and the two new fields do appear the moment they carry something, so the byte-identity
        // above is the `skip_serializing_if` working, not the fields having been dropped.
        let suspended = Delegation {
            suspended: true,
            ..current
        };
        assert_ne!(
            serde_json::to_string(&suspended).unwrap(),
            serde_json::to_string(&reference).unwrap()
        );
    }

    #[test]
    fn one_deleted_funcao_does_not_take_the_surviving_ones_with_it() {
        let kept = Role {
            id: rid(1),
            name: "Secretário".to_owned(),
            permission_set: [Permission::ActRead].into_iter().collect(),
            protected: false,
        };
        let mut catalog = RoleCatalog::new();
        catalog.insert(kept);
        // The delegation names two funções; only the first is still in the catalog.
        let d = Delegation::with_roles(uid(1), uid(2), [rid(1), rid(2)], Scope::Global).unwrap();

        // Fail-closed is per função, not per delegation: the missing one contributes nothing and
        // the surviving one is unaffected. (A missing função must not silently widen or void the rest.)
        assert_eq!(d.granted_permissions(&catalog), vec![Permission::ActRead]);
        assert_eq!(d.roles(), [rid(1), rid(2)]);
    }

    #[test]
    fn a_legacy_permission_shaped_record_still_resolves_with_no_catalog_help() {
        // Exactly the pre-t44 wire shape: no `roles` key, no `suspended` key.
        let raw = serde_json::json!({
            "from": "00000000-0000-0000-0000-000000000001",
            "to": "00000000-0000-0000-0000-000000000002",
            "permission": "act.read",
            "extra_permissions": ["act.advance"],
            "scope": "Global"
        });
        let d: Delegation = serde_json::from_value(raw).expect("legacy delegation");
        assert!(d.roles().is_empty());
        assert!(!d.suspended);
        assert!(d.is_active(OffsetDateTime::UNIX_EPOCH));
        // It resolves to its own verbs even against an empty catalog — it needs no funções.
        assert_eq!(
            d.granted_permissions(&RoleCatalog::new()),
            vec![Permission::ActRead, Permission::ActAdvance]
        );
    }

    #[test]
    fn legacy_json_defaults_start_and_legal_basis() {
        let raw = serde_json::json!({
            "from": "00000000-0000-0000-0000-000000000001",
            "to": "00000000-0000-0000-0000-000000000002",
            "permission": "act.read",
            "scope": "Global"
        });
        let d: Delegation = serde_json::from_value(raw).expect("legacy delegation");
        // A legacy record has no `extra_permissions` and resolves to exactly its one verb.
        assert!(d.extra_permissions.is_empty());
        assert_eq!(d.permissions(), vec![Permission::ActRead]);
        assert_eq!(d.starts_at, OffsetDateTime::UNIX_EPOCH);
        assert_eq!(d.legal_basis, None);
        assert!(!d.revoked);
        assert_eq!(d.expires_at, None);
        assert!(d.is_active(OffsetDateTime::UNIX_EPOCH));
    }
}
