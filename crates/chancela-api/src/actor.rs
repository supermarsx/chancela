//! The `CurrentActor` extractor — resolves the ledger actor from a session or API key.
//!
//! Every mutating handler records an `actor` on its ledger event (DAT-10). Historically that came
//! from a request-body/query `actor` field defaulting to `"api"`. [`CurrentActor`] adds the
//! session layer on top: it reads the `X-Chancela-Session` header, and if it names a valid,
//! active user's session (not expired), that user's `username` becomes the actor.
//!
//! ## Authentication (t41 security hardening)
//!
//! [`CurrentActor`] is a **fallible** extractor: an absent, unknown, expired, inactive-user session
//! token, or invalid bearer API key yields `401 Unauthorized`. Every handler that takes
//! `CurrentActor` as a parameter therefore requires a valid credential. Session authentication is
//! unchanged; API keys resolve to the same RBAC permission-set shape but never expose a session
//! username, so self-service and step-up routes do not treat them as interactive users.
//!
//! ## Session expiry (t41 M3)
//!
//! Each session carries an `expires_at` timestamp (24h from creation). The extractor rejects
//! expired tokens (401) and slides the expiry forward on each successful request, so an active
//! user is never logged out mid-work while an idle session expires.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use chancela_apikey::RequestPrincipal;
use time::OffsetDateTime;

use crate::AppState;
use crate::apikeys::{read_bearer_api_key, resolve_bearer_principal};
use crate::error::ApiError;

/// The HTTP header carrying an opaque session token.
pub const SESSION_HEADER: &str = "x-chancela-session";

/// Session lifetime: 24 hours from creation (t41 M3).
pub const SESSION_TTL_SECS: i64 = 24 * 60 * 60;

/// The resolved session actor for a request. Construct it as a handler argument (it
/// implements [`FromRequestParts`]); call [`resolve`](CurrentActor::resolve) with the actor the
/// handler would otherwise use. The extractor is fallible: a missing/invalid/expired session
/// returns `401`.
#[derive(Debug, Clone, Default)]
pub struct CurrentActor {
    credential: Option<ActorCredential>,
}

#[derive(Debug, Clone)]
enum ActorCredential {
    Session { username: String },
    ApiKey { principal: RequestPrincipal },
}

impl CurrentActor {
    /// The resolved ledger actor: the session `username` when a valid session was presented,
    /// otherwise `request_actor` (which already carries its own default, e.g. `"api"`).
    pub fn resolve(&self, request_actor: &str) -> String {
        match &self.credential {
            Some(ActorCredential::Session { username }) => username.clone(),
            Some(ActorCredential::ApiKey { principal }) => principal.actor_label.clone(),
            None => request_actor.to_owned(),
        }
    }

    /// The session `username`, if a valid session was presented.
    pub fn session_username(&self) -> Option<&str> {
        match &self.credential {
            Some(ActorCredential::Session { username }) => Some(username),
            _ => None,
        }
    }

    /// The resolved API-key principal, if this request authenticated with `Authorization: Bearer`.
    pub(crate) fn api_key_principal(&self) -> Option<&RequestPrincipal> {
        match &self.credential {
            Some(ActorCredential::ApiKey { principal }) => Some(principal),
            _ => None,
        }
    }

    /// Whether the request authenticated with an API key instead of an interactive session.
    pub(crate) fn is_api_key(&self) -> bool {
        self.api_key_principal().is_some()
    }

    /// Build a [`CurrentActor`] from an already-resolved session username. Used where the session is
    /// resolved manually rather than via the extractor — the bootstrap-capable `create_user`, which
    /// must stay callable signed-out at zero users yet still gate `user.manage` once a session is
    /// present (t64-E3).
    pub(crate) fn from_session_username(username: Option<String>) -> Self {
        CurrentActor {
            credential: username.map(|username| ActorCredential::Session { username }),
        }
    }
}

impl FromRequestParts<AppState> for CurrentActor {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let session_token = read_session_token(parts);
        let bearer = read_bearer_api_key(&parts.headers)?;
        if session_token.is_some() && bearer.is_some() {
            return Err(ApiError::Unauthorized(
                "use sessão ou chave API, não ambas".to_owned(),
            ));
        }

        if let Some(token) = session_token {
            return match resolve_session_actor(state, token).await? {
                Some(username) => Ok(CurrentActor {
                    credential: Some(ActorCredential::Session { username }),
                }),
                None => Err(ApiError::Unauthorized("sessão inválida".to_owned())),
            };
        }

        if let Some(key) = bearer {
            return Ok(CurrentActor {
                credential: Some(ActorCredential::ApiKey {
                    principal: resolve_bearer_principal(state, key).await?,
                }),
            });
        }

        Err(ApiError::Unauthorized("sessão requerida".to_owned()))
    }
}

/// Resolve a session token to an active user's username, checking expiry and sliding the
/// expiry forward. Returns `Ok(Some(username))` for a valid session, `Ok(None)` when the token
/// is unknown/expired/inactive. Acquires a brief write lock on `sessions` to slide the expiry,
/// then a read lock on `users` to resolve the username.
pub async fn resolve_session_actor(
    state: &AppState,
    token: &str,
) -> Result<Option<String>, ApiError> {
    let user_id = {
        let now = OffsetDateTime::now_utc();
        let mut sessions = state.sessions.write().await;
        let entry = match sessions.get(token) {
            Some(e) => e,
            None => return Ok(None),
        };
        if now >= entry.expires_at {
            drop(sessions);
            state.sessions.write().await.remove(token);
            return Ok(None);
        }
        let entry = sessions.get_mut(token).expect("entry was just present");
        entry.expires_at = now + time::Duration::seconds(SESSION_TTL_SECS);
        entry.user_id
    };
    let username = {
        let users = state.users.read().await;
        users
            .get(&user_id)
            .filter(|u| u.active)
            .map(|u| u.username.clone())
    };
    Ok(username)
}

/// Read the raw session token from request headers (without validation).
pub fn read_session_token(parts: &Parts) -> Option<&str> {
    parts
        .headers
        .get(SESSION_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|t| !t.is_empty())
}

/// The unlocked attestation signer for a request, if the presenting session holds one.
///
/// A session gains an unlocked [`SigningKey`](p256::ecdsa::SigningKey) only when the user signed
/// in with the correct password **and** has an attestation key (plan t29 §4.4). This infallible
/// extractor exposes that key (with the actor's username) to a mutating handler so it can sign the
/// event it just appended. Absent/unknown/expired token, a passwordless or key-less session, or
/// an inactive user all yield "no signer" — never an error.
#[derive(Clone, Default)]
pub struct CurrentAttestor {
    signer: Option<(String, p256::ecdsa::SigningKey)>,
}

impl CurrentAttestor {
    /// The `(username, signing key)` to attest with, if this request carries an unlocked key.
    pub fn signer(&self) -> Option<(&str, &p256::ecdsa::SigningKey)> {
        self.signer.as_ref().map(|(u, k)| (u.as_str(), k))
    }
}

impl FromRequestParts<AppState> for CurrentAttestor {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = match read_session_token(parts) {
            Some(t) => t,
            None => return Ok(CurrentAttestor::default()),
        };

        let entry = {
            let sessions = state.sessions.read().await;
            sessions
                .get(token)
                .map(|e| (e.user_id, e.unlocked_key.clone()))
        };
        let signer = match entry {
            Some((uid, Some(key))) => {
                let now = OffsetDateTime::now_utc();
                let expired = state
                    .sessions
                    .read()
                    .await
                    .get(token)
                    .is_none_or(|e| now >= e.expires_at);
                if expired {
                    None
                } else {
                    state
                        .users
                        .read()
                        .await
                        .get(&uid)
                        .filter(|u| u.active)
                        .map(|u| (u.username.clone(), key))
                }
            }
            _ => None,
        };

        Ok(CurrentAttestor { signer })
    }
}
