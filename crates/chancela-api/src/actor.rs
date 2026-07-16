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
//!
//! ## Absolute lifetime cap (wp25-sec)
//!
//! The 24h expiry above is a *sliding* idle window — an active session renews it forever. On top of
//! it, a configurable **absolute** cap ([`AppState::session_max_lifetime`], default 7 days from
//! `CHANCELA_SESSION_MAX_LIFETIME`) bounds the total wall-clock age of a session so it cannot be
//! renewed indefinitely. The session's issued-at is recorded on first sight (recovered from the
//! pre-slide expiry on the minting node) in [`AppState::session_issued_at`]; once
//! `now >= issued_at + cap` the session is rejected (401) and evicted. A non-positive cap disables
//! the check. The exact issue time is retained in the durable digest registry (single-node) or the
//! shared Redis record (HA), so restarts and node changes cannot reset the cap.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use chancela_apikey::RequestPrincipal;
use time::OffsetDateTime;

use crate::AppState;
use crate::apikeys::{read_bearer_api_key, resolve_bearer_principal};
use crate::cluster_shared_state::SessionLookup;
use crate::error::ApiError;
use crate::users::UserId;

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
/// is unknown/expired/inactive.
///
/// Redis is authoritative whenever configured: every request checks it even when this node has an
/// unlocked-key cache entry, so a revoke or outage cannot be bypassed by a stale node-local hit.
/// Without Redis, the live map is checked first and a miss falls through to the digest-only durable
/// registry. All successful paths retain the exact original issue time while sliding idle expiry.
pub async fn resolve_session_actor(
    state: &AppState,
    token: &str,
) -> Result<Option<String>, ApiError> {
    let std_ttl = std::time::Duration::from_secs(SESSION_TTL_SECS.max(0) as u64);
    let now = OffsetDateTime::now_utc();
    let new_expires_at = now + time::Duration::seconds(SESSION_TTL_SECS);

    let user_id = match state.cluster_shared.sessions.resolve(token, std_ttl) {
        SessionLookup::Found {
            user_id,
            issued_at_unix,
        } => {
            let Ok(issued_at) = OffsetDateTime::from_unix_timestamp(issued_at_unix) else {
                evict_local_session(state, token).await;
                return Ok(None);
            };
            if session_absolute_cap_exceeded(state, token, now, issued_at).await {
                evict_session(state, token).await;
                return Ok(None);
            }
            let uid = UserId(user_id);
            let mut sessions = state.sessions.write().await;
            match sessions.get_mut(token) {
                Some(entry) if entry.user_id == uid => entry.expires_at = new_expires_at,
                _ => {
                    // A follower/restarted node reconstructs identity only. The unlocked signing key
                    // is intentionally unavailable until the user signs in on this process again.
                    sessions.insert(
                        token.to_owned(),
                        crate::session::SessionEntry {
                            user_id: uid,
                            unlocked_key: None,
                            expires_at: new_expires_at,
                        },
                    );
                }
            }
            uid
        }
        SessionLookup::NotFound | SessionLookup::Unavailable => {
            evict_local_session(state, token).await;
            return Ok(None);
        }
        SessionLookup::NotShared => {
            let local = {
                let mut sessions = state.sessions.write().await;
                match sessions.get(token) {
                    Some(entry) if now < entry.expires_at => Some((
                        entry.user_id,
                        entry.expires_at - time::Duration::seconds(SESSION_TTL_SECS),
                    )),
                    _ => {
                        sessions.remove(token);
                        None
                    }
                }
            };

            match local {
                Some((uid, derived_issued_at)) => {
                    let durable = state
                        .durable_sessions
                        .slide_if_present(token, now, new_expires_at)
                        .await?;
                    if durable
                        .as_ref()
                        .is_some_and(|record| record.user_id != uid.0)
                    {
                        evict_session(state, token).await;
                        return Ok(None);
                    }
                    let issued_at = durable
                        .and_then(|record| {
                            OffsetDateTime::from_unix_timestamp(record.issued_at_unix).ok()
                        })
                        .unwrap_or(derived_issued_at);
                    if session_absolute_cap_exceeded(state, token, now, issued_at).await {
                        evict_session(state, token).await;
                        return Ok(None);
                    }
                    if let Some(entry) = state.sessions.write().await.get_mut(token) {
                        entry.expires_at = new_expires_at;
                    }
                    uid
                }
                None => {
                    state.session_issued_at.write().await.remove(token);
                    let Some(record) = state
                        .durable_sessions
                        .resolve_and_slide(token, now, new_expires_at)
                        .await?
                    else {
                        return Ok(None);
                    };
                    let Ok(issued_at) = OffsetDateTime::from_unix_timestamp(record.issued_at_unix)
                    else {
                        let _ = state.durable_sessions.revoke(token).await;
                        return Ok(None);
                    };
                    if session_absolute_cap_exceeded(state, token, now, issued_at).await {
                        evict_session(state, token).await;
                        return Ok(None);
                    }
                    let uid = UserId(record.user_id);
                    state.sessions.write().await.insert(
                        token.to_owned(),
                        crate::session::SessionEntry {
                            user_id: uid,
                            unlocked_key: None,
                            expires_at: new_expires_at,
                        },
                    );
                    uid
                }
            }
        }
    };
    let username = {
        let users = state.users.read().await;
        users
            .get(&user_id)
            .filter(|u| u.active)
            .map(|u| u.username.clone())
    };
    if username.is_none() {
        evict_session(state, token).await;
    }
    Ok(username)
}

/// Whether a session has exceeded its absolute lifetime cap (wp25-sec).
///
/// Records the session's issued-at on first sight (`first_seen_issued_at` — the creation time
/// recovered from the pre-slide expiry on the minting node, or "now" for a session first observed
/// via the cluster-shared store) and returns `true` once `now >= issued_at + cap`. A prior pinned
/// issued-at always wins over the derived value, so the cap is anchored to the true creation time
/// even as the 24h idle expiry keeps sliding. A non-positive cap disables the check.
async fn session_absolute_cap_exceeded(
    state: &AppState,
    token: &str,
    now: OffsetDateTime,
    first_seen_issued_at: OffsetDateTime,
) -> bool {
    let cap_secs = state.session_max_lifetime.0;
    if cap_secs <= 0 {
        return false;
    }
    let issued_at = {
        let mut issued = state.session_issued_at.write().await;
        *issued
            .entry(token.to_owned())
            .or_insert(first_seen_issued_at)
    };
    now >= issued_at + time::Duration::seconds(cap_secs)
}

/// Evict a node-local cache entry without mutating the authoritative durable/shared record.
async fn evict_local_session(state: &AppState, token: &str) {
    state.sessions.write().await.remove(token);
    state.session_issued_at.write().await.remove(token);
}

/// Evict a session from every configured authority. Failures remain fail-closed because the current
/// request is denied and the exact issued-at cap is still enforced by every future resolver.
async fn evict_session(state: &AppState, token: &str) {
    evict_local_session(state, token).await;
    let _ = state.durable_sessions.revoke(token).await;
    let _ = state.cluster_shared.sessions.revoke(token);
    state.cluster_shared.invalidation.publish(
        &crate::cluster_shared_state::InvalidationEvent::SessionRevoked {
            token_sha256: crate::session::session_token_digest(token),
        },
    );
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
/// event it just appended. Absent/unknown/expired/over-age token, a legacy no-hash or key-less
/// session, or an inactive user all yield "no signer" — never an error.
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

        // Reuse the authoritative resolver first. In HA this checks Redis even when the node has a
        // cached unlocked key, preventing a stale cache from bypassing revocation or an outage.
        let Some(username) = resolve_session_actor(state, token).await.ok().flatten() else {
            return Ok(CurrentAttestor::default());
        };
        let signer = {
            let sessions = state.sessions.read().await;
            sessions
                .get(token)
                .and_then(|entry| entry.unlocked_key.clone())
                .map(|key| (username, key))
        };

        Ok(CurrentAttestor { signer })
    }
}
