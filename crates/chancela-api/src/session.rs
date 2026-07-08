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
) -> Json<SessionView> {
    let user = match parts
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
                    .map(UserView::from)
            }
            _ => None,
        },
        None => None,
    };
    Json(SessionView { user })
}

/// `DELETE /v1/session` — drop the presented token (idempotent; always `204`).
pub async fn delete_session(
    State(state): State<AppState>,
    parts: axum::http::HeaderMap,
) -> StatusCode {
    if let Some(token) = parts
        .get(SESSION_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|t| !t.is_empty())
    {
        state.sessions.write().await.remove(token);
    }
    StatusCode::NO_CONTENT
}
