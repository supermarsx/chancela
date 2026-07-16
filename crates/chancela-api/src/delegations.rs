//! The delegation store (`delegations.json`) — active **and** revoked scoped delegations (t64-E2).
//!
//! Mirrors the `users.json` / `roles.json` discipline: an atomic write-through, a malformed-tolerant
//! load, and `#[serde(default)]` throughout. A [`StoredDelegation`] wraps the frozen
//! [`chancela_authz::Delegation`] security model (`from`/`to`/`permission`/`scope`/`starts_at`/
//! `expires_at`/`legal_basis`/`revoked`) and adds the durable **audit** fields the crate
//! deliberately left to the API layer —
//! a stable [`DelegationId`], the `granted_at` timestamp, and the `revoked_at`/`revoked_by`
//! attribution recorded when a delegation is revoked (E4 wires the revoke endpoint).
//!
//! Revoked delegations are retained (never deleted) so the ledger + this store together form a
//! complete, reversible audit trail; the inner `revoked` flag makes them contribute **nothing** to
//! [`chancela_authz::effective_permissions`].

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use axum::Json;
use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use chancela_authz::{Delegation, Permission, Scope, UserId as AuthzUserId};

use crate::AppState;
use crate::actor::{CurrentActor, CurrentAttestor};
use crate::authz::{authorizer, forbidden};
use crate::error::ApiError;
use crate::roles::ScopeInput;
use crate::session::ScopeView;
use crate::users::UserId;

pub const DELEGATIONS_FILE: &str = "delegations.json";
pub const MAX_DELEGATION_LEGAL_BASIS_CHARS: usize = 1024;

/// Opaque identifier of a stored delegation. Transparent UUID on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DelegationId(pub Uuid);

impl std::fmt::Display for DelegationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// A durable delegation record: the frozen [`chancela_authz::Delegation`] model (flattened, so the
/// on-disk shape is `{ id, granted_at, from, to, permission, scope, starts_at, expires_at?,
/// legal_basis?, revoked, revoked_at?, revoked_by? }`) plus the API-layer audit fields.
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
pub(crate) fn write_delegations_atomic(
    path: &Path,
    delegations: &HashMap<DelegationId, StoredDelegation>,
) -> std::io::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
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
pub(crate) async fn persist_delegations(state: &AppState) -> Result<(), ApiError> {
    // wp16 P3b: route to the active source (Postgres `delegations` table, else `delegations.json`).
    // File behaviour on SQLite/single-node is unchanged.
    crate::sidecar_store::persist_delegations(state).await
}

fn tmp_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_else(|| DELEGATIONS_FILE.into());
    name.push(format!(".{}.tmp", Uuid::new_v4()));
    path.with_file_name(name)
}

// =================================================================================================
// Scoped-delegation endpoints (t64-E4): grant / list / revoke. A grant enforces the delegation
// invariant server-side (non-meta AND held VIA A ROLE at the scope → no privilege escalation, no
// re-delegation); revocation is immediate (revoked delegations resolve to no authority). FROZEN DTOs.
// =================================================================================================

/// Body of `POST /v1/delegations` — delegate one permission to a grantee, optionally scoped and
/// optionally expiring. `permission` deserialises from its dotted id; a meta verb / unknown verb /
/// out-of-authority verb is refused by [`grant_delegation`] (`403`) or at deserialisation (`422`).
/// New grants must carry a non-empty operator-supplied local evidence/rationale string in
/// `legal_basis`; legacy stored records that predate this field still load with `None`.
#[derive(Deserialize)]
pub struct GrantDelegation {
    pub to: Uuid,
    pub permission: Permission,
    pub scope: ScopeInput,
    /// RFC 3339 start timestamp; absent ⇒ starts at grant time.
    #[serde(default)]
    pub starts_at: Option<String>,
    /// RFC 3339 expiry; absent ⇒ until revoked.
    #[serde(default)]
    pub expires_at: Option<String>,
    /// Required evidence/rationale for new grants. Kept optional at the DTO boundary so missing
    /// requests receive a controlled 422 instead of a serde extraction error.
    #[serde(default)]
    pub legal_basis: Option<String>,
}

/// A delegation rendered for the web (FROZEN for E7/t62). No secret material — only attribution,
/// the delegated verb, its scope, and lifecycle timestamps.
#[derive(Serialize)]
pub struct DelegationView {
    pub id: String,
    pub from: String,
    pub to: String,
    pub permission: String,
    pub scope: ScopeView,
    pub granted_at: String,
    pub starts_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub legal_basis: Option<String>,
    pub revoked: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_by: Option<String>,
}

impl From<&StoredDelegation> for DelegationView {
    fn from(d: &StoredDelegation) -> Self {
        DelegationView {
            id: d.id.0.to_string(),
            from: d.inner.from.0.to_string(),
            to: d.inner.to.0.to_string(),
            permission: d.inner.permission.as_str().to_owned(),
            scope: ScopeView::from(d.inner.scope),
            granted_at: d.granted_at.clone(),
            starts_at: d.inner.starts_at.format(&Rfc3339).unwrap_or_default(),
            expires_at: d.inner.expires_at.and_then(|t| t.format(&Rfc3339).ok()),
            legal_basis: d.inner.legal_basis.clone(),
            revoked: d.inner.revoked,
            revoked_at: d.revoked_at.clone(),
            revoked_by: d.revoked_by.map(|u| u.0.to_string()),
        }
    }
}

/// Append a chained `delegation.*` audit event (honest actor, no secret material).
///
/// The event is scoped `delegation:{uuid}`, a keyword-shaped application scope, so it lands on the
/// shared `application` audit chain. It must **not** be a *bare* UUID: the ledger classifies a bare
/// UUID as a `company:{uuid}` book-action chain whose genesis kind must be `entity.created`
/// (WFL-11), so a `delegation.*` event opening such a chain would fail `Ledger::verify()` after the
/// mutation. The `application` chain fixes no genesis kind, keeping verify() healthy (wp19-fix).
async fn record_delegation_event(
    state: &AppState,
    view: &DelegationView,
    kind: &str,
    justification: &str,
    actor: &CurrentActor,
    attestor: &CurrentAttestor,
) -> Result<(), ApiError> {
    let bytes = serde_json::to_vec(view)?;
    let actor_name = actor.resolve("api");
    let scope = format!("delegation:{}", view.id);
    let mut ledger = state.ledger.write().await;
    ledger.append(&actor_name, &scope, kind, Some(justification), &bytes);
    state.persist_write_through(&mut ledger, 1, |_tx| Ok(()))?;
    state.attest_latest(attestor, &ledger).await;
    Ok(())
}

/// `GET /v1/delegations` — the delegations the caller may see: a `delegation.revoke`\@Global holder
/// sees **all**, everyone else sees only delegations they granted or received. Any valid session.
pub async fn list_delegations(
    State(state): State<AppState>,
    actor: CurrentActor,
) -> Result<Json<Vec<DelegationView>>, ApiError> {
    let authz = authorizer(&state, &actor).await?;
    let principal = AuthzUserId(authz.principal()?.0);
    let can_see_all = authz.permits(Permission::DelegationRevoke, Scope::Global);

    let table = state.delegations.read().await;
    let mut list: Vec<DelegationView> = table
        .values()
        .filter(|d| can_see_all || d.inner.from == principal || d.inner.to == principal)
        .map(DelegationView::from)
        .collect();
    list.sort_by(|a, b| a.granted_at.cmp(&b.granted_at).then(a.id.cmp(&b.id)));
    Ok(Json(list))
}

/// `POST /v1/delegations` — grant a scoped, revocable, optionally-expiring delegation. Gated
/// `delegation.grant` at the delegation's scope, **and** the DELEGATION INVARIANT: the permission
/// must be non-meta AND held by the actor **via a role** covering that scope. The via-role rule makes
/// re-delegation structurally impossible (a received permission is never a role grant).
pub async fn grant_delegation(
    State(state): State<AppState>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<GrantDelegation>,
) -> Result<(StatusCode, Json<DelegationView>), ApiError> {
    let scope: Scope = req.scope.into();
    let authz = authorizer(&state, &actor).await?;
    // Meta gate at the delegation's scope.
    authz.require(Permission::DelegationGrant, scope)?;
    // DELEGATION INVARIANT: non-meta + hold-via-role at scope (blocks escalation AND re-delegation).
    if !authz.can_delegate(req.permission, scope) {
        return Err(forbidden());
    }

    let grantor = authz.principal()?;
    let grantee = UserId(req.to);
    if !state.users.read().await.contains_key(&grantee) {
        return Err(ApiError::NotFound);
    }

    let legal_basis = normalize_grant_legal_basis(req.legal_basis)?;
    let granted_at_time = OffsetDateTime::now_utc();
    let starts_at =
        parse_optional_rfc3339(req.starts_at.as_deref(), "starts_at")?.unwrap_or(granted_at_time);
    let expires_at = parse_optional_rfc3339(req.expires_at.as_deref(), "expires_at")?;

    let mut inner = Delegation::new(
        AuthzUserId(grantor.0),
        AuthzUserId(grantee.0),
        req.permission,
        scope,
    )
    .starting_at(starts_at)
    .with_legal_basis(Some(legal_basis));
    if let Some(exp) = expires_at {
        inner = inner.expiring_at(exp);
    }
    let granted_at = granted_at_time.format(&Rfc3339).unwrap_or_default();
    let stored = StoredDelegation::new(DelegationId(Uuid::new_v4()), granted_at, inner);

    state
        .delegations
        .write()
        .await
        .insert(stored.id, stored.clone());
    persist_delegations(&state).await?;

    let view = DelegationView::from(&stored);
    record_delegation_event(
        &state,
        &view,
        "delegation.granted",
        "permission delegated",
        &actor,
        &attestor,
    )
    .await?;
    // wp16 P3b: the grantee's effective authority changed — signal other nodes (no-op on single-node).
    state.publish_role_changed(grantee.0);
    Ok((StatusCode::CREATED, Json(view)))
}

/// `DELETE /v1/delegations/{id}` — revoke a delegation. The **grantor** may always revoke their own;
/// otherwise `delegation.revoke` at the delegation's scope is required. Revocation is **immediate**
/// (a revoked delegation contributes no authority). Idempotent for an already-revoked delegation.
pub async fn revoke_delegation(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
) -> Result<Json<DelegationView>, ApiError> {
    let del_id = DelegationId(id);
    let authz = authorizer(&state, &actor).await?;
    let principal = AuthzUserId(authz.principal()?.0);

    let existing = state.delegations.read().await.get(&del_id).cloned();
    let existing = existing.ok_or(ApiError::NotFound)?;
    // Grantor may always revoke their own; otherwise require delegation.revoke at the delegation's scope.
    if existing.inner.from != principal {
        authz.require(Permission::DelegationRevoke, existing.inner.scope)?;
    }
    // Idempotent: already revoked → return the current view unchanged.
    if existing.inner.revoked {
        return Ok(Json(DelegationView::from(&existing)));
    }

    let revoked_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default();
    let updated = {
        let mut table = state.delegations.write().await;
        let d = table.get_mut(&del_id).ok_or(ApiError::NotFound)?;
        d.inner.revoked = true;
        d.revoked_at = Some(revoked_at);
        d.revoked_by = Some(principal);
        d.clone()
    };
    persist_delegations(&state).await?;

    let view = DelegationView::from(&updated);
    record_delegation_event(
        &state,
        &view,
        "delegation.revoked",
        "delegation revoked",
        &actor,
        &attestor,
    )
    .await?;
    // wp16 P3b: the grantee's effective authority changed — signal other nodes (no-op on single-node).
    state.publish_role_changed(updated.inner.to.0);
    Ok(Json(view))
}

fn parse_optional_rfc3339(
    value: Option<&str>,
    field: &'static str,
) -> Result<Option<OffsetDateTime>, ApiError> {
    value
        .map(|s| {
            OffsetDateTime::parse(s, &Rfc3339).map_err(|_| {
                ApiError::Unprocessable(format!("{field} must be an RFC 3339 timestamp"))
            })
        })
        .transpose()
}

fn normalize_grant_legal_basis(value: Option<String>) -> Result<String, ApiError> {
    let Some(raw) = value else {
        return Err(ApiError::Unprocessable(
            "legal_basis is required for new delegations".to_owned(),
        ));
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ApiError::Unprocessable(
            "legal_basis must not be empty".to_owned(),
        ));
    }
    let len = trimmed.chars().count();
    if len > MAX_DELEGATION_LEGAL_BASIS_CHARS {
        return Err(ApiError::Unprocessable(format!(
            "legal_basis must be at most {MAX_DELEGATION_LEGAL_BASIS_CHARS} characters"
        )));
    }
    Ok(trimmed.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uid(n: u128) -> AuthzUserId {
        AuthzUserId(Uuid::from_u128(n))
    }

    #[test]
    fn stored_delegation_round_trips_through_json() {
        let granted_at = OffsetDateTime::UNIX_EPOCH.format(&Rfc3339).unwrap();
        let starts_at = OffsetDateTime::UNIX_EPOCH + time::Duration::hours(2);
        let inner = Delegation::new(uid(1), uid(2), Permission::ActAdvance, Scope::Global)
            .starting_at(starts_at)
            .with_legal_basis(Some("board resolution 2026-07-09".to_owned()));
        let d = StoredDelegation::new(DelegationId(Uuid::from_u128(9)), granted_at, inner);

        let bytes = serde_json::to_vec(&[&d]).expect("serialize");
        // The flattened model + audit fields are all top-level keys.
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let obj = &value[0];
        assert!(obj.get("id").is_some());
        assert!(obj.get("granted_at").is_some());
        assert!(obj.get("permission").is_some());
        assert!(obj.get("scope").is_some());
        assert!(obj.get("starts_at").is_some());
        assert_eq!(
            obj.get("legal_basis").and_then(serde_json::Value::as_str),
            Some("board resolution 2026-07-09")
        );
        assert!(obj.get("revoked").is_some());
        // revoked_at / revoked_by are omitted while active.
        assert!(obj.get("revoked_at").is_none());
        assert!(obj.get("revoked_by").is_none());

        let back: Vec<StoredDelegation> = serde_json::from_slice(&bytes).expect("deserialize");
        assert_eq!(back, vec![d]);
    }

    #[test]
    fn legacy_stored_delegation_defaults_evidence_fields() {
        let raw = serde_json::json!([{
            "id": "00000000-0000-0000-0000-000000000009",
            "granted_at": "2026-01-01T00:00:00Z",
            "from": "00000000-0000-0000-0000-000000000001",
            "to": "00000000-0000-0000-0000-000000000002",
            "permission": "act.advance",
            "scope": "Global",
            "revoked": false
        }]);

        let back: Vec<StoredDelegation> = serde_json::from_value(raw).expect("legacy delegation");
        assert_eq!(back[0].inner.starts_at, OffsetDateTime::UNIX_EPOCH);
        assert_eq!(back[0].inner.legal_basis, None);

        let view = DelegationView::from(&back[0]);
        assert_eq!(view.starts_at, "1970-01-01T00:00:00Z");
        assert_eq!(view.legal_basis, None);
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

    #[test]
    fn new_grant_legal_basis_is_required_trimmed_and_bounded() {
        let err = normalize_grant_legal_basis(None).expect_err("missing basis");
        assert!(matches!(err, ApiError::Unprocessable(message) if message.contains("required")));

        let err = normalize_grant_legal_basis(Some(" \t\n ".to_owned())).expect_err("blank basis");
        assert!(
            matches!(err, ApiError::Unprocessable(message) if message.contains("must not be empty"))
        );

        let too_long = "x".repeat(MAX_DELEGATION_LEGAL_BASIS_CHARS + 1);
        let err = normalize_grant_legal_basis(Some(too_long)).expect_err("overlong basis");
        assert!(matches!(err, ApiError::Unprocessable(message) if message.contains("at most")));

        let ok = normalize_grant_legal_basis(Some("  board minute R-17  ".to_owned()))
            .expect("trimmed legal basis");
        assert_eq!(ok, "board minute R-17");
    }
}
