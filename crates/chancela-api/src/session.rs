//! Session endpoints (contract §2.8, extended by plan t29 §4.2/§4.4/§4.5): mint, inspect, and
//! drop an opaque actor token, now honouring optional per-user passwords.
//!
//! A session maps an opaque token to a [`SessionEntry`] — the user, plus (when the user signed in
//! with a password and holds an attestation key) the **decrypted signing key** held in memory for
//! the life of the session. The UI mints one with `POST /v1/session {user_id, password?}`, sends
//! the returned token as the `X-Chancela-Session` header on every subsequent request, and the
//! [`CurrentActor`](crate::actor::CurrentActor) /
//! [`CurrentAttestor`](crate::actor::CurrentAttestor) extractors resolve it.
//!
//! **Security (t41):** sessions carry a 24h [`expires_at`](SessionEntry::expires_at) and the
//! [`CurrentActor`](crate::actor::CurrentActor) extractor rejects expired/missing tokens with
//! `401`. Sign-in failures (unknown user, inactive user, wrong password) all return a uniform
//! `401 "credenciais inválidas"` — no user enumeration via distinct status codes. The backoff
//! speed-bump holds its write lock across the argon2 verify so concurrent requests cannot all
//! read "no backoff" and then each spend ~100 ms in argon2.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use p256::ecdsa::SigningKey;
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::AppState;
use crate::actor::{SESSION_HEADER, SESSION_TTL_SECS, resolve_session_actor};
use crate::apikeys::read_bearer_api_key;
use crate::attestation::verify_secret;
use crate::error::ApiError;
use crate::users::{User, UserId, UserView};

/// A live session: the user it authenticates, plus the optional in-memory attestation signing key
/// unlocked at sign-in (plan t29 §4.4) and the expiry timestamp (t41 M3).
pub struct SessionEntry {
    pub user_id: UserId,
    pub unlocked_key: Option<SigningKey>,
    pub expires_at: OffsetDateTime,
}

/// Per-user sign-in backoff state (plan t29 §4.5).
pub struct Backoff {
    pub fails: u32,
    pub next_allowed_at: OffsetDateTime,
}

/// The backoff delay (seconds) after `fails` consecutive failures: `[1,2,4,8,16,32,64]`, capped
/// at 30 s (t41 M1 — leading zeros dropped so even the first failure buys a second). Shared with the
/// cross-user secret/reset backoff (t52) so both speed-bumps escalate identically.
pub(crate) fn backoff_secs(fails: u32) -> i64 {
    const TABLE: [i64; 7] = [1, 2, 4, 8, 16, 32, 64];
    let idx = (fails as usize).saturating_sub(1).min(TABLE.len() - 1);
    TABLE[idx].min(30)
}

#[derive(Deserialize)]
pub struct CreateSession {
    pub user_id: Uuid,
    #[serde(default)]
    pub password: Option<String>,
}

#[derive(Serialize)]
pub struct SessionCreated {
    pub token: String,
    pub user: UserView,
}

#[derive(Serialize)]
pub struct SessionView {
    pub user: Option<UserView>,
    /// The signed-in user's effective `(permission, scope)` grants, embedded for the web's first
    /// paint so it can gate its UI without a second round-trip (t64-E3 / E5). Empty when signed out.
    /// The authoritative, fuller shape is `GET /v1/session/permissions`.
    pub permissions: Vec<PermissionGrantView>,
}

/// A [`chancela_authz::Scope`] rendered for the web (t64-E3, FROZEN for E5). A tagged union so the
/// client can switch on `kind` and read the id: `{"kind":"global"}` / `{"kind":"entity","id":..}` /
/// `{"kind":"book","id":..}`.
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum ScopeView {
    Global,
    Entity { id: String },
    Book { id: String },
}

impl From<chancela_authz::Scope> for ScopeView {
    fn from(s: chancela_authz::Scope) -> Self {
        match s {
            chancela_authz::Scope::Global => ScopeView::Global,
            chancela_authz::Scope::Entity(e) => ScopeView::Entity {
                id: e.0.to_string(),
            },
            chancela_authz::Scope::Book(b) => ScopeView::Book {
                id: b.0.to_string(),
            },
        }
    }
}

/// One effective grant: a permission verb, the scope it is held at, and whether it arrived via a
/// role assignment or a delegation (t64-E3, FROZEN for E5).
#[derive(Serialize)]
pub struct PermissionGrantView {
    /// The dotted permission id, e.g. `"entity.read"`.
    pub permission: String,
    pub scope: ScopeView,
    /// `"role"` or `"delegation"`.
    pub source: &'static str,
}

/// One role assignment the user holds: the role id and the scope it is held at (t64-E3, FROZEN).
#[derive(Serialize)]
pub struct RoleAssignmentView {
    pub role_id: String,
    pub scope: ScopeView,
}

/// Response of `GET /v1/session/permissions` (t64-E3, FROZEN for E5's web permissions context): the
/// current principal's identity, the role assignments they hold (with scopes), and the flattened
/// effective `(permission, scope)` grants (role ∪ delegation, each tagged by `source`).
#[derive(Serialize)]
pub struct PermissionsView {
    pub user_id: String,
    pub username: String,
    pub role_assignments: Vec<RoleAssignmentView>,
    pub permissions: Vec<PermissionGrantView>,
}

/// Flatten a [`ScopedPermissionSet`](chancela_authz::ScopedPermissionSet) into the wire grants,
/// tagging each with whether it is a role grant or a delegated grant.
pub(crate) fn grant_views(eff: &chancela_authz::ScopedPermissionSet) -> Vec<PermissionGrantView> {
    let mut out: Vec<PermissionGrantView> = eff
        .role_grants()
        .map(|(p, s)| PermissionGrantView {
            permission: p.as_str().to_owned(),
            scope: ScopeView::from(s),
            source: "role",
        })
        .chain(eff.delegated_grants().map(|(p, s)| PermissionGrantView {
            permission: p.as_str().to_owned(),
            scope: ScopeView::from(s),
            source: "delegation",
        }))
        .collect();
    // Deterministic order for stable responses / snapshot tests.
    out.sort_by(|a, b| a.permission.cmp(&b.permission).then(a.source.cmp(b.source)));
    out
}

/// One entry in the signed-out sign-in roster: the minimum a sign-in picker needs, and nothing
/// sensitive. **No** attestation fingerprint, **no** `created_at`, **no** secret material.
#[derive(Serialize)]
pub struct RosterUser {
    pub id: String,
    pub username: String,
    pub display_name: String,
    /// Whether the user holds a sign-in secret, so the UI knows to prompt for a password.
    pub has_secret: bool,
}

impl From<&User> for RosterUser {
    fn from(u: &User) -> Self {
        RosterUser {
            id: u.id.to_string(),
            username: u.username.clone(),
            display_name: u.display_name.clone(),
            has_secret: u.password_hash.is_some(),
        }
    }
}

/// Response of `GET /v1/session/roster`.
#[derive(Serialize)]
pub struct SessionRoster {
    /// `true` when no user exists at all — the first-run bootstrap create is available and the UI
    /// should show the onboarding wizard instead of a sign-in picker.
    pub onboarding_required: bool,
    /// The **active** users a signed-out operator may sign in as (an inactive user can never mint a
    /// session), each reduced to the minimal, non-sensitive picker fields.
    pub users: Vec<RosterUser>,
}

/// `GET /v1/session/roster` — the **unauthenticated** minimal sign-in roster (t45).
///
/// The signed-out sign-in UI needs, without a session, to (a) decide onboarding-vs-sign-in and
/// (b) list the users it may sign in as. `GET /v1/users` stays auth-gated (it returns the full
/// [`UserView`], including attestation fingerprints, for signed-in management); this endpoint
/// deliberately exposes only `{ id, username, display_name, has_secret }` for active users so no
/// sensitive material leaks to an anonymous caller.
pub async fn session_roster(State(state): State<AppState>) -> Json<SessionRoster> {
    let users = state.users.read().await;
    let onboarding_required = users.is_empty();
    let mut active: Vec<&User> = users.values().filter(|u| u.active).collect();
    active.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.0.cmp(&b.id.0)));
    Json(SessionRoster {
        onboarding_required,
        users: active.into_iter().map(RosterUser::from).collect(),
    })
}

/// `POST /v1/session` — mint a token for a user. **t41 H1:** unknown user, inactive user, and
/// wrong password all return a uniform `401 "credenciais inválidas"`. While in backoff → `429`.
pub async fn create_session(
    State(state): State<AppState>,
    Json(req): Json<CreateSession>,
) -> Result<Json<SessionCreated>, ApiError> {
    let uid = UserId(req.user_id);
    let user = {
        let users = state.users.read().await;
        match users.get(&uid).cloned() {
            Some(u) if u.active => u,
            _ => return Err(ApiError::Unauthorized("credenciais inválidas".to_owned())),
        }
    };

    let unlocked_key = match &user.password_hash {
        None => None,
        Some(phc) => {
            let now = OffsetDateTime::now_utc();
            let mut backoff = state.signin_backoff.write().await;
            let entry = backoff.entry(uid).or_insert(Backoff {
                fails: 0,
                next_allowed_at: now,
            });
            if now < entry.next_allowed_at {
                let ms = (entry.next_allowed_at - now).whole_milliseconds();
                let remaining = ((ms + 999) / 1000).max(1);
                return Err(ApiError::TooManyRequests(format!(
                    "demasiadas tentativas — tente novamente em {remaining} s"
                )));
            }
            let ok = req
                .password
                .as_deref()
                .map(|p| verify_secret(p, phc))
                .unwrap_or(false);
            if !ok {
                entry.fails += 1;
                entry.next_allowed_at = now + Duration::seconds(backoff_secs(entry.fails));
                return Err(ApiError::Unauthorized("credenciais inválidas".to_owned()));
            }
            drop(backoff);
            state.signin_backoff.write().await.remove(&uid);
            let password = req.password.as_deref().unwrap_or_default();
            match &user.attestation_key {
                Some(blob) => Some(blob.unlock(password)?),
                None => None,
            }
        }
    };

    let token = Uuid::new_v4().to_string();
    let now = OffsetDateTime::now_utc();
    state.sessions.write().await.insert(
        token.clone(),
        SessionEntry {
            user_id: uid,
            unlocked_key,
            expires_at: now + Duration::seconds(SESSION_TTL_SECS),
        },
    );

    Ok(Json(SessionCreated {
        token,
        user: UserView::from(&user),
    }))
}

/// `GET /v1/session` — the user behind the `X-Chancela-Session` header, or `{ "user": null }`.
/// Does NOT use the fallible `CurrentActor` extractor (returns null, not 401, when no session).
pub async fn get_session(
    State(state): State<AppState>,
    parts: axum::http::HeaderMap,
) -> Result<Json<SessionView>, ApiError> {
    if read_bearer_api_key(&parts)?.is_some() {
        return Err(ApiError::Forbidden(
            "chave API não abre uma sessão interativa".to_owned(),
        ));
    }

    let resolved: Option<(UserView, UserId)> = match parts
        .get(SESSION_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|t| !t.is_empty())
    {
        Some(token) => match resolve_session_actor(&state, token).await {
            Ok(Some(username)) => {
                let users = state.users.read().await;
                users
                    .values()
                    .find(|u| u.username == username)
                    .map(|u| (UserView::from(u), u.id))
            }
            _ => None,
        },
        None => None,
    };

    let (user, permissions) = match resolved {
        Some((view, uid)) => {
            let eff =
                crate::roles::effective_permissions_for(&state, uid, OffsetDateTime::now_utc())
                    .await;
            (Some(view), grant_views(&eff))
        }
        None => (None, Vec::new()),
    };
    Ok(Json(SessionView { user, permissions }))
}

/// `GET /v1/session/permissions` — the current principal's role assignments (with scopes) and
/// flattened effective `(permission, scope)` grants (t64-E3, FROZEN for the web permissions context
/// in E5). Requires a valid session (`401` without one, via [`CurrentActor`]); `403` if the session
/// no longer names an active user. Never a specific permission — introspecting one's own authority
/// is always allowed.
pub async fn session_permissions(
    State(state): State<AppState>,
    actor: crate::actor::CurrentActor,
) -> Result<Json<PermissionsView>, ApiError> {
    let now = OffsetDateTime::now_utc();
    let (uid, eff) = crate::roles::effective_permissions_for_actor(&state, &actor, now).await?;

    let (username, role_assignments) = {
        let users = state.users.read().await;
        match users.get(&uid) {
            Some(u) => (
                u.username.clone(),
                u.role_assignments
                    .iter()
                    .map(|a| RoleAssignmentView {
                        role_id: a.role_id.0.to_string(),
                        scope: ScopeView::from(a.scope),
                    })
                    .collect(),
            ),
            // The resolve step already proved the user active; a race that removed them → empty.
            None => (String::new(), Vec::new()),
        }
    };

    Ok(Json(PermissionsView {
        user_id: uid.0.to_string(),
        username,
        role_assignments,
        permissions: grant_views(&eff),
    }))
}

/// `GET /v1/session/password-policy` — the active password strength ruleset (t68).
///
/// **Unauthenticated by design** (classified `Exempt`, like `/v1/session/roster`): the first-run
/// onboarding surface must render the requirement checklist while the operator is still setting up,
/// and the rules are public knowledge the web mirrors exactly. Returns the same parameters the server
/// enforces on every password-setting path (see [`crate::password_policy`]), so a client checklist can
/// never drift from server enforcement. Carries `allow_weak_passwords` (currently a constant default
/// = `false`); the settings-document toggle that will drive it is deferred to the coordinated web
/// slice to avoid drifting the settings contract.
pub async fn password_policy() -> Json<crate::password_policy::PasswordPolicyView> {
    Json(crate::password_policy::policy_view())
}

/// `DELETE /v1/session` — drop the presented token (idempotent; always `204`).
pub async fn delete_session(
    State(state): State<AppState>,
    parts: axum::http::HeaderMap,
) -> Result<StatusCode, ApiError> {
    if read_bearer_api_key(&parts)?.is_some() {
        return Err(ApiError::Forbidden(
            "chave API não abre uma sessão interativa".to_owned(),
        ));
    }

    if let Some(token) = parts
        .get(SESSION_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|t| !t.is_empty())
    {
        state.sessions.write().await.remove(token);
    }
    Ok(StatusCode::NO_CONTENT)
}
