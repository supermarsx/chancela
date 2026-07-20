//! Scoped, revocable, time-bounded delegation (t64 plan §2.5).
//!
//! A [`Delegation`] grants **one or more** permissions from `from` to `to`, optionally narrowed to a
//! scope,
//! optionally starting in the future, and optionally expiring. It is pure data; start/expiry are
//! evaluated against a caller-supplied `now` (this crate holds no clock). The escalation invariants
//! that make delegation safe —
//!
//! - delegate only a permission you hold **via a role** at that scope (kills privilege escalation
//!   AND re-delegation, since a *received* permission is never a role grant),
//! - meta-permissions are non-delegable,
//! - narrowing-only scope,
//!
//! — live in [`crate::can_delegate`]. A not-yet-started, expired, or revoked delegation contributes
//! nothing to [`crate::effective_permissions`].

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::permission::Permission;
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

/// A delegated **set** of permissions sharing one grantor, grantee, scope and lifetime.
///
/// The model is intentionally minimal (the API layer, t64-E2, adds durable audit fields such as
/// `id`/`granted_at`/`revoked_by`); the security-relevant shape is frozen here.
///
/// **Wire shape (additive).** The original one-permission shape is preserved exactly: `permission`
/// remains the primary verb and any further verbs are appended in `extra_permissions`, which is
/// omitted when empty. A legacy record therefore loads unchanged, and a record written by this
/// version still resolves its primary verb under an older binary (fewer grants — fail-closed —
/// never more). Always read the set through [`Delegation::permissions`], never the fields directly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Delegation {
    /// Grantor (the principal delegating). Must hold `permission` at `scope` **via a role**.
    pub from: UserId,
    /// Grantee (the principal receiving the delegated permission).
    pub to: UserId,
    /// The primary delegated permission. Must not be a meta-permission ([`Permission::is_meta`]).
    /// Prefer [`Delegation::permissions`] over reading this field — it is only the *first* verb of
    /// the delegated set.
    pub permission: Permission,
    /// Any further delegated permissions beyond [`Self::permission`], in grant order. Each is
    /// subject to the *same* invariants as the primary (non-meta, held via a role at `scope`) —
    /// [`crate::can_delegate_all`] checks them element-wise. Empty for a single-permission
    /// delegation and for every legacy record.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra_permissions: Vec<Permission>,
    /// The scope **every** delegated permission is narrowed to. One scope per delegation: the set
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
}

fn default_starts_at() -> OffsetDateTime {
    OffsetDateTime::UNIX_EPOCH
}

impl Delegation {
    /// Build a single-permission delegation (no expiry, not revoked).
    #[must_use]
    pub fn new(from: UserId, to: UserId, permission: Permission, scope: Scope) -> Self {
        Delegation {
            from,
            to,
            permission,
            extra_permissions: Vec::new(),
            scope,
            starts_at: default_starts_at(),
            expires_at: None,
            legal_basis: None,
            revoked: false,
        }
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

    /// Every permission this delegation grants, in grant order: the primary followed by the extras.
    /// This is the **only** correct way to enumerate a delegation's authority.
    #[must_use]
    pub fn permissions(&self) -> Vec<Permission> {
        let mut out = Vec::with_capacity(1 + self.extra_permissions.len());
        out.push(self.permission);
        for &p in &self.extra_permissions {
            if !out.contains(&p) {
                out.push(p);
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
    /// revoked and not expired**.
    #[must_use]
    pub fn is_active(&self, now: OffsetDateTime) -> bool {
        self.has_started(now) && !self.revoked && !self.is_expired(now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        assert_eq!(d.permission, Permission::ActRead);
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
