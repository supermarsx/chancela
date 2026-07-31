//! The **self-service account** surface (`/v1/me/*`) — what an account holder may do to their own
//! account with no administrative permission at all.
//!
//! ## Why this is a separate module from [`crate::users`]
//!
//! [`crate::users`] is the ADMINISTRATION surface: `GET`/`PATCH /v1/users/{id}` are gated
//! `user.read` / `user.manage` at Global, which is correct — reading the roster and editing another
//! person's profile are administrative acts. But an ordinary user holds neither verb, and the two
//! things they must always be able to do to their own record — correct their own display name /
//! e-mail / language, and lock their own account when they think it is compromised — were reachable
//! only through those gates. The result was a user with no route to their own settings at all.
//!
//! The fix is **not** to add a self arm to `patch_user`: that endpoint also writes `active` and
//! `two_factor_required`, and a self arm on it would hand every user the ability to lift their own
//! suspension and to clear a second-factor requirement an administrator set. So the self-service
//! operations get their own narrow endpoints here, each restricted to the fields it names, and
//! `patch_user` is left exactly as it was. `/v1/me/preferences` ([`crate::user_preferences`])
//! already established the address idiom.
//!
//! ## What is NOT here, and why
//!
//! - **Lifting a suspension.** `POST /v1/me/suspend` is one-way. Un-suspending is
//!   `PATCH /v1/users/{id}` `{active:true}` — `user.manage`\@Global. A suspension a user could lift
//!   themselves is not a suspension: the attacker the user is locking out would hold exactly the
//!   session needed to undo it.
//! - **`two_factor_required`.** An administrator may require a second factor on an account; the
//!   holder may not clear that requirement. (The holder still enrols the factor itself — the secret
//!   has to reach their own authenticator — see [`crate::totp`].)
//! - **Roles.** Authority is granted, never self-claimed.
//! - **Self data export.** `GET /v1/privacy/users/{id}/export` is `privacy.manage`\@Global with no
//!   self arm, so an ordinary user cannot export their own record. That is a genuine gap in the
//!   subject-access story and is deliberately left as one rather than papered over by widening the
//!   verb here: the export carries role assignments and ledger references, and deciding that every
//!   user may read those about themselves is a privacy-model ruling, not a screen-wiring detail.
//!
//! ## Step-up on the suspension, and only on it
//!
//! A profile rename rides the session alone: the worst a stolen session achieves is a wrong display
//! name, which the ledger records and an administrator undoes. Suspension is the opposite — it is
//! *irreversible without an administrator*, which is precisely what an attacker holding a stolen
//! session would do to lock the real owner out while they work. So it takes
//! [`require_step_up`](crate::data::require_step_up): the strongest proof the acting user can
//! provide, never the session token on its own for a user who holds any credential.

use axum::Json;
use axum::extract::State;
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::actor::{CurrentActor, CurrentAttestor};
use crate::data::{ReAuth, require_step_up};
use crate::error::ApiError;
use crate::users::{
    DeactivationBlock, User, UserLanguage, UserView, deactivation_block, record_user_update,
};

/// The ledger kind appended when a holder suspends their own account.
///
/// Deliberately **not** `user.updated`. A self-suspension is a security event an auditor looks for
/// by name — "when did this account lock itself, and was it before or after the sign-ins we are
/// investigating" — and burying it among renames and language changes would make that unanswerable.
/// The administrative re-activation that lifts it stays `user.updated`, because it *is* an ordinary
/// administrative edit performed by someone with the authority to make it.
const SELF_SUSPENDED_KIND: &str = "user.self_suspended";

/// The refusal for a caller with no interactive session (an API key). Self-service means "the person
/// signed in"; a machine credential has no self to act on.
const NO_INTERACTIVE_SESSION: &str = "chave API não abre uma sessão interativa";

/// Body of `PATCH /v1/me/profile` — the three profile fields a holder owns outright.
///
/// Note what is absent: `active`, `two_factor_required` and any role field. Their absence is the
/// gate. This struct is the whole allowlist, so a future field added to [`crate::users::PatchUser`]
/// does not silently become self-writable.
#[derive(Deserialize, Default)]
pub struct PatchMyProfile {
    /// A blank or whitespace-only name is ignored rather than accepted, matching `patch_user`.
    #[serde(default)]
    pub display_name: Option<String>,
    /// Present-and-null clears the address; absent leaves it unchanged (`double_option`).
    #[serde(default, deserialize_with = "crate::dto::double_option")]
    pub email: Option<Option<String>>,
    /// `"auto"` is a real value that restores "keep detecting", not a way to clear the field.
    #[serde(default)]
    pub language: Option<UserLanguage>,
}

/// Body of `POST /v1/me/suspend`. The step-up proof is the only field: there is nothing to choose.
#[derive(Deserialize, Default)]
pub struct SuspendMe {
    #[serde(default)]
    pub reauth: ReAuth,
}

/// The outcome of a self-suspension: the now-inactive profile, and how many sessions it ended.
#[derive(Serialize)]
pub struct SuspendedView {
    pub user: UserView,
    /// Every live session of this account, including the one that made the request. Reported so the
    /// client can say what happened rather than merely appearing to sign the operator out.
    pub sessions_revoked: usize,
}

/// Resolve the acting session's own user record, or refuse.
///
/// Uniform refusals: an API key is told it has no interactive session (a true statement about the
/// credential, not about any account), and a session naming a user that no longer resolves is a
/// `401` — the `CurrentActor` extractor only admits existing active users, so reaching that arm
/// means the session died mid-request.
async fn resolve_me(state: &AppState, actor: &CurrentActor) -> Result<User, ApiError> {
    let Some(username) = actor.session_username() else {
        return Err(ApiError::Forbidden(NO_INTERACTIVE_SESSION.to_owned())
            .with_code("api_key_no_interactive_session"));
    };
    let users = state.users.read().await;
    users
        .values()
        .find(|u| u.username == username)
        .cloned()
        .ok_or_else(|| {
            ApiError::Unauthorized("sessão inválida".to_owned()).with_code("session_invalid")
        })
}

/// `PATCH /v1/me/profile` — the acting user edits their own display name, contact e-mail and
/// interface language. Any valid interactive session; no permission verb.
///
/// Appends `user.updated`, exactly as the administrative edit does — a rename is a rename however it
/// was reached, and the ledger names the honest actor either way, so an auditor sees one kind of
/// event for one kind of change rather than having to know which screen was used.
pub async fn patch_me_profile(
    State(state): State<AppState>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<PatchMyProfile>,
) -> Result<Json<UserView>, ApiError> {
    let me = resolve_me(&state, &actor).await?;

    let user = {
        let mut users = state.users.write().await;
        let user = users.get_mut(&me.id).ok_or(ApiError::NotFound)?;
        if let Some(display_name) = req.display_name {
            let trimmed = display_name.trim();
            if !trimmed.is_empty() {
                user.display_name = trimmed.to_owned();
            }
        }
        if let Some(email) = req.email {
            user.email = crate::email::normalize_optional_email(email, "email")?;
        }
        if let Some(language) = req.language {
            user.language = language;
        }
        user.clone()
    };

    record_user_update(
        &state,
        &user,
        "profile updated by its holder",
        &actor,
        &attestor,
    )
    .await?;
    Ok(Json(UserView::from(&user)))
}

/// `POST /v1/me/suspend` — the account holder locks their own account. **Step-up re-auth required.**
///
/// The legitimate use is "I think my account is compromised, lock it now", which fixes every part of
/// the design:
///
/// - **One-way.** Only `user.manage`\@Global can set `active` back to `true`
///   ([`crate::users::patch_user`]). A holder who could lift it would hand the same power to whoever
///   is holding their session.
/// - **Step-up.** A session token alone must not suspend an account — that is exactly what the
///   attacker would do, to lock the real owner out while they work. The proof is the strongest one
///   the acting user *can* give (password, recovery phrase, or a passkey assertion answering a
///   step-up-scoped challenge); a user holding no credential at all is exempt, because their
///   authenticated self session already is the strongest proof available to them.
/// - **Every session dies, including this one.** A suspension that left the attacker's session live
///   would achieve nothing, and this handler cannot tell which live session is theirs — the request
///   it is serving may itself be riding the stolen token. So it ends all of them
///   ([`crate::session::revoke_all_sessions_for`]) and drops any in-flight sign-in challenge. The
///   caller is signed out as a consequence, not as a courtesy.
/// - **Refused when it would strand the instance.** [`deactivation_block`] — shared verbatim with
///   the administrative deactivation path, so the two cannot drift — refuses the sole active user
///   and the sole active Owner. A sole Owner suspending themselves would leave nobody able to lift
///   it, which is unrecoverable; the refusal names that reason rather than letting it be discovered
///   afterwards. Checked under the write lock, so two concurrent suspensions cannot both pass.
///
/// Ordering matters: step-up runs BEFORE any state is read or written, so a caller who cannot prove
/// themselves learns nothing about the account's Owner-ness or the instance's user count.
pub async fn suspend_me(
    State(state): State<AppState>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<SuspendMe>,
) -> Result<Json<SuspendedView>, ApiError> {
    // Self re-auth, first. An API key never reaches the state below: `require_step_up` refuses a
    // caller with no session username, and `resolve_me` refuses it again.
    require_step_up(&state, &actor, &req.reauth).await?;
    let me = resolve_me(&state, &actor).await?;

    let user = {
        let mut users = state.users.write().await;
        let target = users.get(&me.id).ok_or(ApiError::NotFound)?;
        if !target.active {
            return Err(ApiError::Conflict("a conta já está suspensa".to_owned())
                .with_code("account_already_suspended"));
        }
        match deactivation_block(&users, target) {
            Some(DeactivationBlock::LastActiveUser) => {
                return Err(ApiError::Conflict(
                    "não pode suspender a sua conta: é o único utilizador ativo desta instância, e \
                     uma instância sem utilizadores ativos não permite iniciar sessão nem reativar \
                     a conta"
                        .to_owned(),
                )
                .with_code("self_suspend_last_active_user"));
            }
            Some(DeactivationBlock::LastActiveOwner) => {
                return Err(ApiError::Conflict(
                    "não pode suspender a sua conta: é o único Proprietário ativo, e só um \
                     Proprietário pode levantar uma suspensão — ninguém ficaria com autoridade \
                     para reativar a conta. Atribua a função de Proprietário a outra conta ativa \
                     antes de suspender esta"
                        .to_owned(),
                )
                .with_code("self_suspend_last_active_owner"));
            }
            None => {}
        }
        let user = users.get_mut(&me.id).ok_or(ApiError::NotFound)?;
        user.active = false;
        user.clone()
    };

    // The ledger event is appended BEFORE the sessions are torn down: the attestation is signed with
    // the key this session unlocked, and revoking the session first would drop it.
    record_user_event_self_suspended(&state, &user, &actor, &attestor).await?;

    let sessions_revoked = crate::session::revoke_all_sessions_for(&state, me.id).await?;

    Ok(Json(SuspendedView {
        user: UserView::from(&user),
        sessions_revoked,
    }))
}

/// Append the `user.self_suspended` event, payload [`UserView`] like every other user event (never
/// the full [`User`], so no argon2 hash or wrapped key reaches the ledger).
async fn record_user_event_self_suspended(
    state: &AppState,
    user: &User,
    actor: &CurrentActor,
    attestor: &CurrentAttestor,
) -> Result<(), ApiError> {
    crate::users::record_user_event(
        state,
        user,
        SELF_SUSPENDED_KIND,
        "account suspended by its holder",
        actor,
        attestor,
    )
    .await
}
