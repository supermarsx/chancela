//! Scoped, revocable, time-bounded delegation (t64 plan §2.5).
//!
//! A [`Delegation`] grants **one** permission from `from` to `to`, optionally narrowed to a scope and
//! optionally expiring. It is pure data; expiry is evaluated against a caller-supplied `now` (this
//! crate holds no clock). The escalation invariants that make delegation safe —
//!
//! - delegate only a permission you hold **via a role** at that scope (kills privilege escalation
//!   AND re-delegation, since a *received* permission is never a role grant),
//! - meta-permissions are non-delegable,
//! - narrowing-only scope,
//!
//! — live in [`crate::can_delegate`]. An expired or revoked delegation contributes nothing to
//! [`crate::effective_permissions`].

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

/// A single delegated permission.
///
/// The model is intentionally minimal (the API layer, t64-E2, adds durable audit fields such as
/// `id`/`granted_at`/`revoked_by`); the security-relevant shape is frozen here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Delegation {
    /// Grantor (the principal delegating). Must hold `permission` at `scope` **via a role**.
    pub from: UserId,
    /// Grantee (the principal receiving the delegated permission).
    pub to: UserId,
    /// The single delegated permission. Must not be a meta-permission ([`Permission::is_meta`]).
    pub permission: Permission,
    /// The scope the delegated permission is narrowed to.
    pub scope: Scope,
    /// Optional expiry; `None` means "until revoked". Evaluated against a caller-supplied `now`.
    #[serde(default)]
    pub expires_at: Option<OffsetDateTime>,
    /// Whether the delegation has been revoked. A revoked delegation contributes nothing.
    #[serde(default)]
    pub revoked: bool,
}

impl Delegation {
    /// Build a delegation (no expiry, not revoked).
    #[must_use]
    pub fn new(from: UserId, to: UserId, permission: Permission, scope: Scope) -> Self {
        Delegation {
            from,
            to,
            permission,
            scope,
            expires_at: None,
            revoked: false,
        }
    }

    /// With an expiry.
    #[must_use]
    pub fn expiring_at(mut self, at: OffsetDateTime) -> Self {
        self.expires_at = Some(at);
        self
    }

    /// Has this delegation expired at `now`? A delegation with no expiry never expires. Expiry is
    /// inclusive of the boundary — at exactly `expires_at` the grant is spent.
    #[must_use]
    pub fn is_expired(&self, now: OffsetDateTime) -> bool {
        matches!(self.expires_at, Some(exp) if now >= exp)
    }

    /// Is this delegation currently contributing authority? True iff **not revoked and not expired**.
    #[must_use]
    pub fn is_active(&self, now: OffsetDateTime) -> bool {
        !self.revoked && !self.is_expired(now)
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
}
