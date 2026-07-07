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
//! **Honest boundary (plan §0/§6):** a password gates sign-in and unlocks the attestation key — a
//! local tamper speed-bump for a shared machine, **not** at-rest encryption and **not**
//! authentication against a hostile OS user. Passwordless users sign in exactly as before. Tokens
//! and unlocked keys never persist; they reset on restart.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use p256::ecdsa::SigningKey;
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::AppState;
use crate::actor::CurrentActor;
use crate::attestation::verify_secret;
use crate::error::ApiError;
use crate::users::{UserId, UserView};

/// A live session: the user it authenticates, plus the optional in-memory attestation signing key
/// unlocked at sign-in (plan t29 §4.4). The key never persists and never leaves the process.
pub struct SessionEntry {
    /// The authenticated user.
    pub user_id: UserId,
    /// The decrypted attestation signing key, if the user signed in with a password and holds a
    /// key. `None` for passwordless users or users without an attestation key.
    pub unlocked_key: Option<SigningKey>,
}

/// Per-user sign-in backoff state (plan t29 §4.5): a naive in-memory speed-bump. Resets on
/// restart; no persistence, no cross-user global limit.
pub struct Backoff {
    /// Consecutive failed attempts.
    pub fails: u32,
    /// The earliest instant the next attempt is allowed.
    pub next_allowed_at: OffsetDateTime,
}

/// The backoff delay (seconds) after `fails` consecutive failures: `[0,0,1,2,4,8,16]`, capped at
/// 30 s (plan t29 §4.5).
fn backoff_secs(fails: u32) -> i64 {
    const TABLE: [i64; 7] = [0, 0, 1, 2, 4, 8, 16];
    let idx = (fails as usize).min(TABLE.len() - 1);
    TABLE[idx].min(30)
}

/// Body of `POST /v1/session`. `password` is present only for users who set one; it is verified
/// and never echoed back (plan §4.2).
#[derive(Deserialize)]
pub struct CreateSession {
    pub user_id: Uuid,
    #[serde(default)]
    pub password: Option<String>,
}

/// Response of `POST /v1/session`: the freshly minted token plus the user it identifies.
#[derive(Serialize)]
pub struct SessionCreated {
    pub token: String,
    pub user: UserView,
}

/// Response of `GET /v1/session`: the current user, or `null` when no/invalid token is presented.
#[derive(Serialize)]
pub struct SessionView {
    pub user: Option<UserView>,
}

/// `POST /v1/session` — mint a token for a user (plan t29 §4.2).
///
/// Unknown user → `404`; inactive user → `409`. A user with a sign-in secret must supply the
/// correct `password`: missing/wrong → `401`, and while in backoff → `429`. On success any
/// attestation key is decrypted and held in the session. A passwordless user signs in exactly as
/// before (any supplied `password` is ignored), so existing password-free flows are unchanged.
pub async fn create_session(
    State(state): State<AppState>,
    Json(req): Json<CreateSession>,
) -> Result<Json<SessionCreated>, ApiError> {
    let uid = UserId(req.user_id);
    let user = {
        let users = state.users.read().await;
        let user = users.get(&uid).ok_or(ApiError::NotFound)?;
        if !user.active {
            return Err(ApiError::Conflict(format!(
                "user {} is inactive; cannot open a session",
                user.username
            )));
        }
        user.clone()
    };

    let unlocked_key = match &user.password_hash {
        // Passwordless: unchanged behaviour, no key to unlock.
        None => None,
        Some(phc) => {
            let now = OffsetDateTime::now_utc();
            // Refuse while in backoff (429) before spending an argon2 verify. The gate is a direct
            // instant comparison (`now < next_allowed_at`); the message rounds the remainder up so a
            // sub-second window still reads as "1 s".
            {
                let backoff = state.signin_backoff.read().await;
                if let Some(b) = backoff.get(&uid) {
                    if now < b.next_allowed_at {
                        let ms = (b.next_allowed_at - now).whole_milliseconds();
                        let remaining = ((ms + 999) / 1000).max(1);
                        return Err(ApiError::TooManyRequests(format!(
                            "demasiadas tentativas — tente novamente em {remaining} s"
                        )));
                    }
                }
            }
            let ok = req
                .password
                .as_deref()
                .map(|p| verify_secret(p, phc))
                .unwrap_or(false);
            if !ok {
                // Record the failure and extend the backoff window.
                let mut backoff = state.signin_backoff.write().await;
                let entry = backoff.entry(uid).or_insert(Backoff {
                    fails: 0,
                    next_allowed_at: now,
                });
                entry.fails += 1;
                entry.next_allowed_at = now + Duration::seconds(backoff_secs(entry.fails));
                return Err(ApiError::Unauthorized("palavra-passe incorreta".to_owned()));
            }
            // Success clears any backoff, and unlocks the attestation key (if any).
            state.signin_backoff.write().await.remove(&uid);
            let password = req.password.as_deref().unwrap_or_default();
            match &user.attestation_key {
                Some(blob) => Some(blob.unlock(password)?),
                None => None,
            }
        }
    };

    let token = Uuid::new_v4().to_string();
    state.sessions.write().await.insert(
        token.clone(),
        SessionEntry {
            user_id: uid,
            unlocked_key,
        },
    );

    Ok(Json(SessionCreated {
        token,
        user: UserView::from(&user),
    }))
}

/// `GET /v1/session` — the user behind the `X-Chancela-Session` header, or `{ "user": null }`.
pub async fn get_session(State(state): State<AppState>, actor: CurrentActor) -> Json<SessionView> {
    // The extractor already resolved the token to an active user's username; map it back to the
    // full profile for the view.
    let user = match actor.session_username() {
        Some(username) => {
            let users = state.users.read().await;
            users
                .values()
                .find(|u| u.username == username)
                .map(UserView::from)
        }
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
        .get(crate::actor::SESSION_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|t| !t.is_empty())
    {
        state.sessions.write().await.remove(token);
    }
    StatusCode::NO_CONTENT
}
