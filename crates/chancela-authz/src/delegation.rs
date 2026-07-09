//! Scoped, revocable, time-bounded delegation (t64 plan §2.5).
//!
//! A [`Delegation`] grants **one** permission from `from` to `to`, optionally narrowed to a scope,
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
    /// Build a delegation (no expiry, not revoked).
    #[must_use]
    pub fn new(from: UserId, to: UserId, permission: Permission, scope: Scope) -> Self {
        Delegation {
            from,
            to,
            permission,
            scope,
            starts_at: default_starts_at(),
            expires_at: None,
            legal_basis: None,
            revoked: false,
        }
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
    fn legacy_json_defaults_start_and_legal_basis() {
        let raw = serde_json::json!({
            "from": "00000000-0000-0000-0000-000000000001",
            "to": "00000000-0000-0000-0000-000000000002",
            "permission": "act.read",
            "scope": "Global"
        });
        let d: Delegation = serde_json::from_value(raw).expect("legacy delegation");
        assert_eq!(d.starts_at, OffsetDateTime::UNIX_EPOCH);
        assert_eq!(d.legal_basis, None);
        assert!(!d.revoked);
        assert_eq!(d.expires_at, None);
        assert!(d.is_active(OffsetDateTime::UNIX_EPOCH));
    }
}
