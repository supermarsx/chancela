//! The `CurrentActor` extractor — resolves the ledger actor from a session (contract §2.8).
//!
//! Every mutating handler records an `actor` on its ledger event (DAT-10). Historically that came
//! from a request-body/query `actor` field defaulting to `"api"`. [`CurrentActor`] adds the
//! session layer on top **without breaking that**: it reads the `X-Chancela-Session` header, and
//! if it names a valid, active user's session, that user's `username` becomes the actor. Otherwise
//! resolution falls through to exactly the previous behaviour.
//!
//! ## Precedence (frozen)
//!
//! 1. `X-Chancela-Session` token → session → **active** user's `username`.
//! 2. the caller's explicit request `actor` (books/acts body, settings `?actor=`) — unchanged.
//! 3. `"api"` (the system/unattributed actor) — the built-in fallback in that request `actor`.
//!
//! The extractor only ever supplies step 1; the caller passes the value it would have used
//! otherwise into [`CurrentActor::resolve`], so a request with no session behaves byte-for-byte as
//! it did before sessions existed. The extractor is infallible: an absent, unknown, or
//! inactive-user token simply yields "no session actor", never an error.

use std::convert::Infallible;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;

use crate::AppState;

/// The HTTP header carrying an opaque session token.
pub const SESSION_HEADER: &str = "x-chancela-session";

/// The resolved session actor for a request, if any. Construct it as a handler argument (it
/// implements [`FromRequestParts`]); call [`resolve`](CurrentActor::resolve) with the actor the
/// handler would otherwise use.
#[derive(Debug, Clone, Default)]
pub struct CurrentActor {
    /// The `username` of the active user behind a valid session token, or `None`.
    session_username: Option<String>,
}

impl CurrentActor {
    /// The resolved ledger actor: the session `username` when a valid session was presented,
    /// otherwise `request_actor` (which already carries its own default, e.g. `"api"`).
    pub fn resolve(&self, request_actor: &str) -> String {
        match &self.session_username {
            Some(username) => username.clone(),
            None => request_actor.to_owned(),
        }
    }

    /// The session `username`, if a valid session was presented. Exposed for `GET /v1/session`.
    pub fn session_username(&self) -> Option<&str> {
        self.session_username.as_deref()
    }
}

impl FromRequestParts<AppState> for CurrentActor {
    type Rejection = Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = parts
            .headers
            .get(SESSION_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|t| !t.is_empty());

        let session_username = match token {
            // Independent, short-lived locks (sessions then users), both released before the
            // handler acquires its own — no interaction with the entities→…→ledger order.
            Some(token) => {
                let user_id = state.sessions.read().await.get(token).map(|e| e.user_id);
                match user_id {
                    Some(uid) => state
                        .users
                        .read()
                        .await
                        .get(&uid)
                        .filter(|u| u.active)
                        .map(|u| u.username.clone()),
                    None => None,
                }
            }
            None => None,
        };

        Ok(CurrentActor { session_username })
    }
}

/// The unlocked attestation signer for a request, if the presenting session holds one.
///
/// A session gains an unlocked [`SigningKey`](p256::ecdsa::SigningKey) only when the user signed
/// in with the correct password **and** has an attestation key (plan t29 §4.4). This infallible
/// extractor exposes that key (with the actor's username) to a mutating handler so it can sign the
/// event it just appended. Absent/unknown token, a passwordless or key-less session, or an
/// inactive user all yield "no signer" — never an error.
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
    type Rejection = Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = parts
            .headers
            .get(SESSION_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|t| !t.is_empty());

        let signer = match token {
            Some(token) => {
                // Clone the (user_id, unlocked key) out under a short read lock, then resolve the
                // username from the users map — same independent-lock discipline as `CurrentActor`.
                let entry = state
                    .sessions
                    .read()
                    .await
                    .get(token)
                    .map(|e| (e.user_id, e.unlocked_key.clone()));
                match entry {
                    Some((uid, Some(key))) => state
                        .users
                        .read()
                        .await
                        .get(&uid)
                        .filter(|u| u.active)
                        .map(|u| (u.username.clone(), key)),
                    _ => None,
                }
            }
            None => None,
        };

        Ok(CurrentAttestor { signer })
    }
}
