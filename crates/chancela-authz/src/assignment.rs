//! Scoped role assignments (t64 plan §2.4).
//!
//! A [`RoleAssignment`] binds a role to a scope for one principal. It lives on the user record
//! (`User.role_assignments: Vec<RoleAssignment>`, added additively in t64-E2); this crate treats a
//! principal's assignments as an input to [`crate::effective_permissions`].

use serde::{Deserialize, Serialize};

use crate::role::{OWNER_ROLE_ID, RoleId};
use crate::scope::Scope;

/// A role held at a scope. A role held at `Global` grants its permissions everywhere; held at
/// `Entity(E)`/`Book(B)` it grants them only within that scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RoleAssignment {
    pub role_id: RoleId,
    pub scope: Scope,
}

impl RoleAssignment {
    /// Build an assignment.
    #[must_use]
    pub fn new(role_id: RoleId, scope: Scope) -> Self {
        RoleAssignment { role_id, scope }
    }

    /// Is this the administrative Owner assignment — the protected Owner role held at `Global`? These
    /// are the holders the last-Owner guard counts (an Owner scoped to a single entity is not a full
    /// super-user, so it does not keep the instance administrable).
    #[must_use]
    pub fn is_owner_admin(&self) -> bool {
        self.role_id == OWNER_ROLE_ID && self.scope.is_global()
    }
}
