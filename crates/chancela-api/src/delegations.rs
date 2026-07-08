//! The delegation store (`delegations.json`) — active **and** revoked scoped delegations (t64-E2).
//!
//! Mirrors the `users.json` / `roles.json` discipline: an atomic write-through, a malformed-tolerant
//! load, and `#[serde(default)]` throughout. A [`StoredDelegation`] wraps the frozen
//! [`chancela_authz::Delegation`] security model (`from`/`to`/`permission`/`scope`/`expires_at`/
//! `revoked`) and adds the durable **audit** fields the crate deliberately left to the API layer —
//! a stable [`DelegationId`], the `granted_at` timestamp, and the `revoked_at`/`revoked_by`
//! attribution recorded when a delegation is revoked (E4 wires the revoke endpoint).
//!
//! Revoked delegations are retained (never deleted) so the ledger + this store together form a
//! complete, reversible audit trail; the inner `revoked` flag makes them contribute **nothing** to
//! [`chancela_authz::effective_permissions`].

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use chancela_authz::{Delegation, UserId as AuthzUserId};

use crate::AppState;
use crate::error::ApiError;

pub const DELEGATIONS_FILE: &str = "delegations.json";

/// Opaque identifier of a stored delegation. Transparent UUID on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DelegationId(pub Uuid);

impl std::fmt::Display for DelegationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// A durable delegation record: the frozen [`chancela_authz::Delegation`] model (flattened, so the
/// on-disk shape is `{ id, granted_at, from, to, permission, scope, expires_at?, revoked,
/// revoked_at?, revoked_by? }`) plus the API-layer audit fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredDelegation {
    /// Stable id (audit + revoke lookup).
    pub id: DelegationId,
    /// When the delegation was granted (RFC 3339).
    pub granted_at: String,
    /// When it was revoked (RFC 3339), if it has been. Set alongside `inner.revoked`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
    /// Who revoked it, if revoked (grantor or a `delegation.revoke` holder).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_by: Option<AuthzUserId>,
    /// The frozen security model (grantor/grantee/permission/scope/expiry/revoked).
    #[serde(flatten)]
    pub inner: Delegation,
}

impl StoredDelegation {
    /// Build an active delegation record around a freshly-granted [`Delegation`].
    #[must_use]
    pub fn new(id: DelegationId, granted_at: String, inner: Delegation) -> Self {
        StoredDelegation {
            id,
            granted_at,
            revoked_at: None,
            revoked_by: None,
            inner,
        }
    }

    /// The frozen `chancela-authz` model this record wraps — what
    /// [`chancela_authz::effective_permissions`] consumes.
    #[must_use]
    pub fn authz(&self) -> &Delegation {
        &self.inner
    }
}

/// Load the delegation table from a `delegations.json` array, or `None` when the file is absent or
/// malformed (mirrors [`crate::users::load_users`] — a bad file never blocks startup). Duplicate ids
/// collapse to the last occurrence.
pub(crate) fn load_delegations(path: &Path) -> Option<HashMap<DelegationId, StoredDelegation>> {
    let bytes = std::fs::read(path).ok()?;
    match serde_json::from_slice::<Vec<StoredDelegation>>(&bytes) {
        Ok(list) => Some(list.into_iter().map(|d| (d.id, d)).collect()),
        Err(e) => {
            eprintln!(
                "warning: {} is not a valid delegations document ({e}); ignoring it",
                path.display()
            );
            None
        }
    }
}

/// Atomically write the delegation table to `delegations.json` (tmp file + rename), sorted by
/// `granted_at` then id for a deterministic document. Mirrors [`crate::users::write_users_atomic`].
// Wired by t64-E4 (delegation endpoints); E2 lands the store + round-trip. Exercised in tests.
#[allow(dead_code)]
pub(crate) fn write_delegations_atomic(
    path: &Path,
    delegations: &HashMap<DelegationId, StoredDelegation>,
) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let mut list: Vec<&StoredDelegation> = delegations.values().collect();
    list.sort_by(|a, b| a.granted_at.cmp(&b.granted_at).then(a.id.0.cmp(&b.id.0)));
    let json = serde_json::to_vec_pretty(&list).map_err(std::io::Error::other)?;
    let tmp = tmp_path(path);
    std::fs::write(&tmp, &json)?;
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// Persist the live delegation table through to `delegations.json` when the state is file-backed.
/// A no-op for pure in-memory state (`delegations_path` is `None`). Call after any mutation (E4).
// Wired by t64-E4 (delegation endpoints); E2 only lands the store + seam.
#[allow(dead_code)]
pub(crate) async fn persist_delegations(state: &AppState) -> Result<(), ApiError> {
    if let Some(path) = &state.delegations_path {
        let delegations = state.delegations.read().await;
        write_delegations_atomic(path, &delegations)
            .map_err(|e| ApiError::Internal(format!("failed to persist delegations: {e}")))?;
    }
    Ok(())
}

#[allow(dead_code)] // reachable only via write_delegations_atomic (wired by t64-E4)
fn tmp_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_else(|| DELEGATIONS_FILE.into());
    name.push(format!(".{}.tmp", Uuid::new_v4()));
    path.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chancela_authz::{Permission, Scope};
    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;

    fn uid(n: u128) -> AuthzUserId {
        AuthzUserId(Uuid::from_u128(n))
    }

    #[test]
    fn stored_delegation_round_trips_through_json() {
        let granted_at = OffsetDateTime::UNIX_EPOCH.format(&Rfc3339).unwrap();
        let inner = Delegation::new(uid(1), uid(2), Permission::ActAdvance, Scope::Global);
        let d = StoredDelegation::new(DelegationId(Uuid::from_u128(9)), granted_at, inner);

        let bytes = serde_json::to_vec(&[&d]).expect("serialize");
        // The flattened model + audit fields are all top-level keys.
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let obj = &value[0];
        assert!(obj.get("id").is_some());
        assert!(obj.get("granted_at").is_some());
        assert!(obj.get("permission").is_some());
        assert!(obj.get("scope").is_some());
        assert!(obj.get("revoked").is_some());
        // revoked_at / revoked_by are omitted while active.
        assert!(obj.get("revoked_at").is_none());
        assert!(obj.get("revoked_by").is_none());

        let back: Vec<StoredDelegation> = serde_json::from_slice(&bytes).expect("deserialize");
        assert_eq!(back, vec![d]);
    }

    #[test]
    fn revoked_record_carries_attribution_and_is_inactive() {
        let now = OffsetDateTime::UNIX_EPOCH;
        let granted_at = now.format(&Rfc3339).unwrap();
        let mut inner = Delegation::new(uid(1), uid(2), Permission::DataBackup, Scope::Global);
        inner.revoked = true;
        let d = StoredDelegation {
            revoked_at: Some(granted_at.clone()),
            revoked_by: Some(uid(1)),
            ..StoredDelegation::new(DelegationId(Uuid::from_u128(7)), granted_at, inner)
        };
        // A revoked delegation contributes nothing.
        assert!(!d.authz().is_active(now));

        let bytes = serde_json::to_vec(&[&d]).unwrap();
        let back: Vec<StoredDelegation> = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back[0].revoked_by, Some(uid(1)));
        assert!(back[0].revoked_at.is_some());
    }

    #[test]
    fn delegations_json_disk_round_trip() {
        let dir = std::env::temp_dir().join(format!("chancela-deleg-rt-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(DELEGATIONS_FILE);

        let granted_at = OffsetDateTime::UNIX_EPOCH.format(&Rfc3339).unwrap();
        let active = StoredDelegation::new(
            DelegationId(Uuid::from_u128(1)),
            granted_at.clone(),
            Delegation::new(uid(1), uid(2), Permission::ActAdvance, Scope::Global),
        );
        let mut revoked_inner =
            Delegation::new(uid(1), uid(3), Permission::DataBackup, Scope::Global);
        revoked_inner.revoked = true;
        let revoked = StoredDelegation {
            revoked_at: Some(granted_at.clone()),
            revoked_by: Some(uid(1)),
            ..StoredDelegation::new(DelegationId(Uuid::from_u128(2)), granted_at, revoked_inner)
        };

        let mut table: HashMap<DelegationId, StoredDelegation> = HashMap::new();
        table.insert(active.id, active.clone());
        table.insert(revoked.id, revoked.clone());

        write_delegations_atomic(&path, &table).expect("write");
        let loaded = load_delegations(&path).expect("load");
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[&active.id], active);
        assert_eq!(loaded[&revoked.id], revoked);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_ignores_a_malformed_file() {
        let dir = std::env::temp_dir().join(format!("chancela-deleg-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(DELEGATIONS_FILE);
        std::fs::write(&path, b"{ this is not json").unwrap();
        assert!(load_delegations(&path).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
