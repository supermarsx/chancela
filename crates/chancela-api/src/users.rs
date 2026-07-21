//! Named user profiles + actor attribution (contract §2.8).
//!
//! Chancela is a local-first, single-operator / small-office app on loopback. User profiles serve
//! two purposes: **attribution** (DAT-10 — identify *who* performed each mutation so the audit
//! ledger names a real person instead of the fixed `"api"` fallback) and, since t41,
//! **access control** — every domain mutation requires a valid session, and users hold an argon2id
//! sign-in verifier (t29). This is a password-required surface: an operator signs in before doing
//! any work.
//!
//! **Security (t41):** all user-mutation endpoints require a valid session via the fallible
//! [`CurrentActor`] extractor. `create_user` is the one exception: it allows a **bootstrap** call
//! (no users exist yet → first-run setup) without a session, then requires auth for every
//! subsequent create.
//!
//! **Argon2 outside the lock (t41 H2):** secret/attestation-key handlers clone the user under a
//! brief read lock, release it, run the argon2 verify and key rewrap/generation outside any lock,
//! then re-acquire a write lock only to commit the validated change.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use axum::Json;
use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use chancela_authz::{
    Permission, RoleAssignment, Scope, UserId as AuthzUserId, count_owner_admin_holders,
    last_owner_guard,
};

use crate::AppState;
use crate::actor::{CurrentActor, CurrentAttestor, resolve_session_actor};
use crate::attestation::{self, AttestationKeyBlob, MAX_SECRET_LEN, MIN_SECRET_LEN, verify_secret};
use crate::authz::require_permission;
use crate::error::ApiError;
use crate::session::{Backoff, backoff_secs};
use crate::settings::Locale;

pub const USERS_FILE: &str = "users.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UserId(pub Uuid);

impl std::fmt::Display for UserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// Key for the cross-user secret/reset backoff (t52): `(requester, target-from-request)`. The
/// requester is `Option` (a valid session always resolves to `Some`, but the resolver is fallible);
/// the target is the id **from the request path**, so a non-existent target keys — and throttles —
/// exactly like a real one (anti-enumeration). See `authorize_secret_op_throttled`.
pub type SecretBackoffKey = (Option<UserId>, UserId);

/// How the user's **current** sign-in secret was established (t51 F4). Additive provenance for the
/// audit trail and the "was this password set via a recovery phrase" semantics. `#[serde(default)]`
/// on the field keeps every pre-t51 `users.json` loadable — an absent value reads as `Password`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretSource {
    /// Set by the user (or by a cross-user reset that proved the previous password).
    #[default]
    Password,
    /// Set by a cross-user reset authorized by a valid recovery phrase (t51 Phase B).
    Recovery,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    pub id: UserId,
    pub username: String,
    pub display_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    pub created_at: String,
    pub active: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_key: Option<crate::attestation::AttestationKeyBlob>,
    /// The **public halves** of this user's superseded attestation keys, newest last (t92).
    ///
    /// Rotating or removing a key used to strand every attestation it had signed: verification
    /// resolves the signing key by fingerprint, and the fingerprint of a replaced key was stored
    /// nowhere. Retiring the public half here keeps the past verifiable while the secret scalar
    /// still goes away with the blob, so a retired key can never sign again.
    ///
    /// **Additive.** `#[serde(default)]` reads an absent field as an empty vec, so every existing
    /// `users.json` loads untouched and `skip_serializing_if` keeps it out of the file until a
    /// user actually retires a key. Retention starts here: nothing is backfilled, and an
    /// attestation whose key was rotated *before* this shipped stays honestly unverifiable.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub retired_attestation_keys: Vec<crate::attestation::RetiredAttestationKey>,
    /// How the current secret was established (t51). Additive; defaults to `Password`.
    #[serde(default)]
    pub secret_source: SecretSource,
    /// Verifier for the user's recovery phrase (t51 Phase B), or `None` when no recovery credential
    /// is established. Stores ONLY the verifier — never the plaintext phrase and never anything
    /// reversible. New verifiers carry a per-verifier pepper and reference the app verifier seed
    /// sidecar; legacy argon2id PHC strings still load and verify. Independent of the password:
    /// possession of the phrase is its own proof. Consumed (set back to `None`) after a successful
    /// recovery-authorized reset (single-use).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_hash: Option<String>,
    /// The user's scoped RBAC role assignments (t64). **Additive** — `#[serde(default)]` keeps every
    /// pre-t64 `users.json` loadable (an absent value reads as an empty vec), which the one-time
    /// [`crate::roles::migrate_roles`] pass then brings forward (sole/first user ⇒ Owner\@Global,
    /// the rest ⇒ Gestor\@Global). A freshly bootstrapped user is assigned here at creation.
    #[serde(default)]
    pub role_assignments: Vec<chancela_authz::RoleAssignment>,
    /// The user's preferred UI language (t71). **Additive** — `#[serde(default)]` reads an absent
    /// value as [`UserLanguage::Auto`] and `skip_serializing_if` omits it again, so every
    /// pre-t71 `users.json` round-trips byte-identically.
    #[serde(default, skip_serializing_if = "UserLanguage::is_auto")]
    pub language: UserLanguage,
    /// The user's TOTP second-factor enrolment (t95 P1-C), or `None` when they have never enrolled.
    ///
    /// The **secret itself is not here** — it is AEAD-encrypted in the credential store
    /// ([`crate::secretstore_persist::CredentialMode::TwoFactorTotp`], keyed by the user id). This
    /// holds only the non-secret enrolment envelope: whether it is confirmed, when, the replay
    /// guard's `last_accepted_step`, and the backup-code verifiers. **Additive** —
    /// `#[serde(default)]` reads an absent field as `None` and `skip_serializing_if` omits it, so
    /// every pre-t95 `users.json` round-trips byte-identically.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp: Option<TotpEnrolment>,
    /// Whether this account must present a second factor (t95 §2.3, item 2). **Enforced as
    /// enrol-on-next-sign-in, never a hard lockout** — an affected user signs in far enough to
    /// enrol and no further. Additive; defaults `false`, and `skip_serializing_if` keeps it out of
    /// the file until set.
    #[serde(default, skip_serializing_if = "crate::dto::is_false")]
    pub two_factor_required: bool,
    /// Whether the next successful sign-in must force a password change before anything else (t95
    /// §2.3, item 3). Set when an account is created with a welcome email — the admin chose the
    /// initial password and can attest as the user until it changes — and cleared on the first
    /// successful change. Additive; defaults `false`.
    #[serde(default, skip_serializing_if = "crate::dto::is_false")]
    pub force_password_change: bool,
}

/// A user's TOTP enrolment envelope (t95 P1-C) — everything about their second factor **except the
/// secret**, which lives AEAD-encrypted in the credential store.
///
/// An enrolment exists in one of two states: **pending** (`confirmed == false`) the moment a secret
/// is generated, and **confirmed** once the user proves the authenticator by entering a live code.
/// A pending enrolment grants nothing — `has_totp` and every sign-in check read `confirmed` — so a
/// user who scanned nothing is never locked out; they simply have no active factor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TotpEnrolment {
    /// Whether the user has proved the authenticator works. Only a confirmed enrolment is a factor.
    pub confirmed: bool,
    /// RFC 3339 stamp of when confirmation happened, for the security screen. `None` while pending.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirmed_at: Option<String>,
    /// The last TOTP step this user successfully verified. The replay guard refuses any step at or
    /// below it, so a code cannot be reused inside its own window. `None` until the first accept.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_accepted_step: Option<i64>,
    /// Single-use backup-code verifiers (argon2id PHC strings — the plaintext is shown once and
    /// never stored). A code is consumed by clearing its slot, so the vector's live count is the
    /// "codes remaining" the UI shows.
    #[serde(default)]
    pub backup_code_hashes: Vec<String>,
}

impl TotpEnrolment {
    /// A pending enrolment: a secret has been generated and stored, but not yet confirmed.
    #[must_use]
    pub fn pending() -> Self {
        TotpEnrolment {
            confirmed: false,
            confirmed_at: None,
            last_accepted_step: None,
            backup_code_hashes: Vec::new(),
        }
    }

    /// Whether this is an active second factor (confirmed). A pending enrolment is not.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.confirmed
    }

    /// How many backup codes remain unspent.
    #[must_use]
    pub fn backup_codes_remaining(&self) -> usize {
        self.backup_code_hashes.len()
    }
}

impl User {
    /// Clear the current attestation key, keeping its **public half** in
    /// [`retired_attestation_keys`](Self::retired_attestation_keys) so the attestations it signed
    /// keep verifying (t92).
    ///
    /// Every path that stops using a key goes through here — a rotation, an explicit removal, and
    /// the recovery-phrase reset that cannot re-wrap the blob — because the damage was never
    /// specific to rotation: it was that the fingerprint disappeared. Idempotent when the user has
    /// no key, and a repeated retirement of an already-recorded fingerprint is not appended twice
    /// (a removal followed by a fresh generation and another removal must not accumulate copies).
    ///
    /// ## What retiring does NOT do: it does not stop a live session signing (t92, found by t88)
    ///
    /// Retiring removes the key **at rest**. It does not reach the sessions already holding it:
    /// `create_session` unlocks the scalar from the password once at sign-in and keeps it in
    /// memory for the life of that token (`session.rs:790`, `mint_session`), and nothing in this
    /// module touches the session layer. So a session opened *before* a rotation or removal keeps
    /// attesting with the superseded key until it ends.
    ///
    /// That gap predates retention — but retention changes its *symptom*, which is why it is
    /// documented here rather than left implicit. Before, a signature made by a live session after
    /// a removal failed to verify ("signing key not found"); now the fingerprint is retained, so it
    /// verifies as `valid`. Both are arguably right — the signature really was produced by that key
    /// — but the second no longer looks like an anomaly to anyone reading the verdict, so the
    /// window is invisible unless stated. Pinned by
    /// `a_live_session_keeps_signing_with_a_retired_key` in
    /// `crates/chancela-api/tests/attestation_key_at_create.rs`.
    ///
    /// Closing it means resolving the key per request instead of caching it at sign-in — the
    /// pattern `roles::effective_permissions_for` already follows for authority (t87/t88 verified:
    /// role, active-flag and delegation changes all take effect on the next request). The counter
    /// argument is cost: unlocking is an argon2 KEK derivation, which is exactly why it is cached.
    /// That trade-off is a product decision and is **not** taken here.
    pub(crate) fn retire_attestation_key(&mut self, retired_at: String) {
        let Some(blob) = self.attestation_key.take() else {
            return;
        };
        if self
            .retired_attestation_keys
            .iter()
            .any(|k| k.fingerprint == blob.fingerprint)
        {
            return;
        }
        self.retired_attestation_keys.push(blob.retire(retired_at));
    }
}

/// Current UTC instant as RFC 3339, for the `retired_at` stamp on a superseded key.
fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default()
}

/// A user's preferred UI language (t71): follow the environment, or a fixed locale.
///
/// ## Why `Auto` is stored as `Auto`
///
/// It is a *standing instruction to keep detecting*, not a locale. Resolving it once and writing
/// the detected tag back would silently convert "follow my environment" into "pin me to whatever I
/// happened to load the app with once" — the preference would still read as satisfied while having
/// quietly stopped doing the thing that was asked for. So detection happens at render time in the
/// client, every time, and nothing writes the result back here.
///
/// ## Server-side rendering
///
/// There is no browser to detect from when the server renders a document or an e-mail, so
/// [`UserLanguage::fixed`] returns `None` for `Auto` and the caller falls back to the **platform
/// default** (`settings.documents.locale`). Deliberately not the acting operator's language: an
/// administrator working in `en-GB` must not send a Portuguese colleague an English welcome. A
/// locale is NEVER guessed from a name or an e-mail domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum UserLanguage {
    /// Keep following the environment (the default, and what every pre-t71 user reads as).
    #[default]
    Auto,
    /// A locale the user chose explicitly.
    Fixed(Locale),
}

impl UserLanguage {
    /// The wire tag: `"auto"`, or the locale's BCP-47 tag.
    pub fn as_str(self) -> &'static str {
        match self {
            UserLanguage::Auto => AUTO_LANGUAGE,
            UserLanguage::Fixed(locale) => locale.as_str(),
        }
    }

    /// The explicitly chosen locale, or `None` for `Auto` — i.e. "the caller should fall back to
    /// the platform default". Server-side renderers use this; nothing else may interpret `Auto`.
    pub fn fixed(self) -> Option<Locale> {
        match self {
            UserLanguage::Auto => None,
            UserLanguage::Fixed(locale) => Some(locale),
        }
    }

    /// Whether this is the default — drives `skip_serializing_if` so stored payloads stay identical.
    pub fn is_auto(&self) -> bool {
        matches!(self, UserLanguage::Auto)
    }
}

/// The wire value meaning "keep detecting".
pub const AUTO_LANGUAGE: &str = "auto";

/// Parse a BCP-47 tag **through serde**, so the accepted set is by construction exactly the one
/// [`Locale`]'s `#[serde(rename)]`s define. A second hand-written list here would be free to drift
/// away from the enum the rest of the app uses.
fn locale_from_tag(tag: &str) -> Option<Locale> {
    serde_json::from_value::<Locale>(serde_json::Value::String(tag.to_owned())).ok()
}

impl From<UserLanguage> for String {
    fn from(value: UserLanguage) -> Self {
        value.as_str().to_owned()
    }
}

impl TryFrom<String> for UserLanguage {
    type Error = String;

    fn try_from(raw: String) -> Result<Self, Self::Error> {
        let tag = raw.trim();
        if tag.eq_ignore_ascii_case(AUTO_LANGUAGE) {
            return Ok(UserLanguage::Auto);
        }
        locale_from_tag(tag)
            .map(UserLanguage::Fixed)
            .ok_or_else(|| {
                format!(
                    "unknown language {raw:?}: expected \"{AUTO_LANGUAGE}\" or a supported locale"
                )
            })
    }
}

#[derive(Debug, Serialize)]
pub struct UserView {
    pub id: String,
    pub username: String,
    pub display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    pub created_at: String,
    pub active: bool,
    pub has_secret: bool,
    pub has_attestation_key: bool,
    /// Whether a recovery credential is established (t51). A **boolean only** — the phrase and its
    /// verifier never leave the server (mirrors the "no secret material in views" discipline).
    pub has_recovery_phrase: bool,
    /// Whether the user has a **confirmed** TOTP second factor (t95 P1-C). A boolean only — the
    /// secret, the provisioning URI and the backup codes never leave the server, mirroring the
    /// other `has_*` booleans. A pending (unconfirmed) enrolment reads `false`: it is not yet a
    /// factor. This is the cross-user state the security screen shows for another account.
    pub has_totp: bool,
    /// Whether this account is required to hold a second factor (t95 §2.3). Surfaced so an admin can
    /// see and toggle the per-account requirement; enforcement is enrol-on-next-sign-in, never a
    /// lockout.
    pub two_factor_required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_key_fingerprint: Option<String>,
    /// The user's language preference (t71). Always emitted so the client can render the control
    /// without a second read; `"auto"` for a user who has never chosen one.
    pub language: UserLanguage,
    /// The user's scoped role assignments (t103) — the **raw** `(role_id, scope)` pairs, exactly
    /// as [`crate::roles::assignment_views`] renders them everywhere else.
    ///
    /// ## Why raw, and not enriched
    ///
    /// No role *name* and no flattened permission set. Both would need an `async` read of the roles
    /// registry, and this `From` is sync and called from dozens of handlers. The enriched shape
    /// already exists for the one consumer that needs it —
    /// [`crate::privacy::RoleAssignmentExport`], on the DSR export path — and must not be rebuilt
    /// here. The client renders an id with `roleNameLabel(id, name)`.
    ///
    /// ## Why it is here at all
    ///
    /// `GET /v1/users` previously could not answer "which accounts hold this role", so the roster
    /// had no função filter (t89 refused to fake one with a per-row fetch). The underlying `User`
    /// has carried these assignments since t64; only the view omitted them.
    ///
    /// ## The consequence that had to be weighed: this struct is a ledger payload
    ///
    /// `UserView` is the `user.created` / `user.updated` payload (t88), and `Ledger::append`
    /// hashes the payload into `Event::payload_digest`. So a new field changes the digest of
    /// **future** user events. Past events are untouched and the hash chain stays intact — a
    /// digest covers the payload as serialized at append time, and nothing recomputes an old one.
    /// This is a deliberate, authorized change, not a side effect: it is recorded here because the
    /// next person to diff a `user.created` digest across this commit needs to know why it moved.
    ///
    /// Filter on the **role id**, never the display name: names are translatable and retired ids
    /// still resolve (t87).
    pub role_assignments: Vec<crate::session::RoleAssignmentView>,
}

impl From<&User> for UserView {
    fn from(u: &User) -> Self {
        UserView {
            id: u.id.to_string(),
            username: u.username.clone(),
            display_name: u.display_name.clone(),
            email: u.email.clone(),
            created_at: u.created_at.clone(),
            active: u.active,
            has_secret: u.password_hash.is_some(),
            has_attestation_key: u.attestation_key.is_some(),
            has_recovery_phrase: u.recovery_hash.is_some(),
            has_totp: u.totp.as_ref().is_some_and(TotpEnrolment::is_active),
            two_factor_required: u.two_factor_required,
            attestation_key_fingerprint: u.attestation_key.as_ref().map(|k| k.fingerprint.clone()),
            language: u.language,
            role_assignments: crate::roles::assignment_views(&u.role_assignments),
        }
    }
}

#[derive(Deserialize)]
pub struct CreateUser {
    pub username: String,
    pub display_name: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    pub password: String,
    /// t71: the `(role, scope)` to grant the new user, assigned **in this same request** so the
    /// operator never lands on a created-but-roleless account. Authorized with exactly the checks
    /// [`crate::roles::assign_role`] applies (`role.assign` at the scope **plus** the subset
    /// invariant), all of them *before* anything is written. Omitted ⇒ the historical default
    /// (`Gestor@Global`, see [`crate::roles::bootstrap_assignment`]). Rejected on a bootstrap
    /// create — the first user is always Owner\@Global.
    #[serde(default)]
    pub role: Option<crate::roles::RoleAssignmentInput>,
    /// t71: send the new account a welcome e-mail. The mail carries **no** password, token or
    /// link — no credential-delivery mechanism with expiry exists in this codebase — so it only
    /// announces that the account exists. A send failure never fails the create.
    #[serde(default)]
    pub send_welcome_email: bool,
    /// t71: the new account's language preference. Absent ⇒ [`UserLanguage::Auto`], so every
    /// existing caller and the bootstrap path are unchanged. A concrete locale here is also the
    /// language the welcome e-mail renders in.
    #[serde(default)]
    pub language: UserLanguage,
}

#[derive(Deserialize)]
pub struct PatchUser {
    pub display_name: Option<String>,
    #[serde(default, deserialize_with = "crate::dto::double_option")]
    pub email: Option<Option<String>>,
    pub active: Option<bool>,
    /// t71: change the language preference. Absent leaves it unchanged; `"auto"` is a real value
    /// that sets it back to "keep detecting", not a way to clear the field.
    #[serde(default)]
    pub language: Option<UserLanguage>,
    /// t95 §2.3: set/clear the per-account second-factor requirement (an admin act). Absent leaves
    /// it unchanged. Turning it **on** requires `auth.two_factor.totp_enabled` at the instance —
    /// requiring a factor the instance does not support would be a lockout with no way to satisfy
    /// it. Enforced as enrol-on-next-sign-in (the sign-in path, P2), never a hard lock here.
    #[serde(default)]
    pub two_factor_required: Option<bool>,
}

#[derive(Deserialize)]
pub struct SetSecret {
    pub password: String,
    /// Path (b): the target's current password — required to authorize a **cross-user** change,
    /// and (unchanged) to change one's **own** existing secret.
    #[serde(default)]
    pub current_password: Option<String>,
    /// Path (a): a valid recovery phrase for the target (t51 Phase B) — an alternative cross-user
    /// proof. Ignored for self-service.
    #[serde(default)]
    pub recovery_phrase: Option<String>,
}

#[derive(Deserialize)]
pub struct CurrentSecret {
    #[serde(default)]
    pub current_password: Option<String>,
    /// A valid recovery phrase for the target (t51 Phase B) — a cross-user proof for the adjacent
    /// remove-secret / attestation-key operations.
    #[serde(default)]
    pub recovery_phrase: Option<String>,
}

/// Body of `POST /v1/users/{id}/recovery` — issue or rotate a recovery phrase (t51 Phase B). Self
/// issuance proves the current password (when one exists); cross-user issuance is authorized by the
/// same rule as the secret ops (target's current password, or an existing recovery phrase).
#[derive(Deserialize)]
pub struct IssueRecovery {
    #[serde(default)]
    pub current_password: Option<String>,
    #[serde(default)]
    pub recovery_phrase: Option<String>,
}

/// Response of `POST /v1/users/{id}/recovery`: the freshly-minted phrase, returned **exactly once**
/// (the server keeps only its argon2id verifier), plus the updated user view.
#[derive(Serialize)]
pub struct RecoveryIssued {
    /// The plaintext recovery phrase — shown to the operator now and never retrievable again.
    pub recovery_phrase: String,
    #[serde(flatten)]
    pub user: UserView,
}

fn validate_username(raw: &str) -> Result<String, ApiError> {
    let name = raw.trim();
    if name.is_empty() {
        return Err(ApiError::Unprocessable(
            "username must not be empty".to_owned(),
        ));
    }
    if name.len() > 64 {
        return Err(ApiError::Unprocessable(
            "username must be at most 64 characters".to_owned(),
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
    {
        return Err(ApiError::Unprocessable(
            "username must be a lowercase slug of a-z, 0-9, '.', '_' or '-'".to_owned(),
        ));
    }
    Ok(name.to_owned())
}

pub(crate) fn load_users(path: &Path) -> Option<HashMap<UserId, User>> {
    let bytes = std::fs::read(path).ok()?;
    match serde_json::from_slice::<Vec<User>>(&bytes) {
        Ok(list) => Some(list.into_iter().map(|u| (u.id, u)).collect()),
        Err(e) => {
            eprintln!(
                "warning: {} is not a valid users document ({e}); ignoring it",
                path.display()
            );
            None
        }
    }
}

pub(crate) fn write_users_atomic(
    path: &Path,
    users: &HashMap<UserId, User>,
) -> std::io::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let mut list: Vec<&User> = users.values().collect();
    list.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.0.cmp(&b.id.0)));
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

fn tmp_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_else(|| USERS_FILE.into());
    name.push(format!(".{}.tmp", Uuid::new_v4()));
    path.with_file_name(name)
}

async fn persist(state: &AppState) -> Result<(), ApiError> {
    // wp16 P3b: route to the active source (Postgres `users` table, else `users.json`). File behaviour
    // on SQLite/single-node is unchanged.
    crate::sidecar_store::persist_users(state).await
}

/// `POST /v1/users` — create a profile. **Bootstrap (t41):** on a genuinely uninitialised instance
/// (no users AND no durable user directory — see [`is_uninitialised_instance`]) this is callable
/// WITHOUT a session and the created user is the instance's Owner\@Global. Once the instance is
/// initialised, a valid session plus `user.manage`\@Global is required.
pub async fn create_user(
    State(state): State<AppState>,
    parts: axum::http::HeaderMap,
    attestor: CurrentAttestor,
    Json(req): Json<CreateUser>,
) -> Result<(StatusCode, Json<UserView>), ApiError> {
    let (session_username, is_bootstrap) = {
        let user_count = state.users.read().await.len();
        if user_count == 0 && is_uninitialised_instance(&state) {
            (None, true)
        } else {
            let token = parts
                .get(crate::actor::SESSION_HEADER)
                .and_then(|v| v.to_str().ok())
                .map(str::trim)
                .filter(|t| !t.is_empty());
            let username = match token {
                Some(t) => resolve_session_actor(&state, t).await?,
                None => return Err(ApiError::Unauthorized("sessão requerida".to_owned())),
            };
            (username, false)
        }
    };
    // RBAC (t64-E3): first-run bootstrap (zero users) stays unauthenticated; every subsequent create
    // requires `user.manage` at Global. Resolve the manually-extracted session into an actor so the
    // gate composes with the same principal seam as every other endpoint. This intentionally runs
    // before password policy/hash work for non-bootstrap requests.
    if !is_bootstrap {
        let actor = CurrentActor::from_session_username(session_username.clone());
        require_permission(&state, &actor, Permission::UserManage, Scope::Global).await?;
    }

    // t71: resolve and AUTHORIZE the requested role before any validation that costs work and,
    // crucially, before the write lock — so a refusal leaves no user behind. This is the same pair
    // of checks `roles::assign_role` applies, in the same order, deliberately reusing
    // `Authorizer::can_assign_role` rather than restating the subset rule: the meta gate at the
    // assignment's scope, then the subset invariant (the role's permissions ⊆ the creator's
    // authority covering that scope). So creation can never grant authority the creator lacks.
    // The 403 is the uniform, non-enumerating `forbidden()` its sibling endpoint returns; the UI
    // names the offending role, having only offered roles it knows are grantable.
    let requested_assignment = match &req.role {
        None => None,
        Some(input) => {
            if is_bootstrap {
                return Err(ApiError::Unprocessable(
                    "the first user is always Owner at global scope; omit `role`".to_owned(),
                ));
            }
            let scope: Scope = input.scope.into();
            let role_id = chancela_authz::RoleId(input.role_id);
            let actor = CurrentActor::from_session_username(session_username.clone());
            let authz = crate::authz::authorizer(&state, &actor).await?;
            authz.require(Permission::RoleAssign, scope)?;
            let role = state
                .roles
                .read()
                .await
                .get(role_id)
                .cloned()
                .ok_or(ApiError::NotFound)?;
            if !authz.can_assign_role(&role, scope) {
                return Err(crate::authz::forbidden());
            }
            Some(RoleAssignment::new(role_id, scope))
        }
    };

    let username = validate_username(&req.username)?;
    let display_name = req
        .display_name
        .map(|d| d.trim().to_owned())
        .filter(|d| !d.is_empty())
        .unwrap_or_else(|| username.clone());
    let email = crate::email::normalize_optional_email(req.email, "email")?;
    validate_secret(&req.password)?;
    crate::password_policy::enforce(
        &req.password,
        &username,
        crate::password_policy::ALLOW_WEAK_PASSWORDS,
    )?;
    let seed = state.verifier_seed.read().await.clone();
    let password_hash = attestation::hash_secret_with_seed(&req.password, &seed)?;

    // t88: the audit (attestation) key is generated HERE, at creation, wrapped under the password
    // being set in this same request. Account creation is the only moment the key's wrapping secret
    // is legitimately in hand without asking the user for it again — `generate_attestation_key`
    // needs the target's *current* password, so an account created without a key can only get one
    // later by the user doing it themselves. Generating now is what makes the key the default
    // rather than an opt-in nobody exercises.
    //
    // Both argon2 costs (the verifier hash above and this KEK derivation) run OUTSIDE the write
    // lock, per t41 H2 — and, per t71, before it, so a failure here writes nothing at all. A crypto
    // fault therefore fails the create loudly with no account left behind, rather than yielding an
    // account that silently lacks a key. `AttestationKeyBlob::generate` fails only on an RNG or
    // serialization fault (never on a bad password), so this is a genuine 500, not a user error.
    let attestation_key = AttestationKeyBlob::generate(&req.password)?;

    let has_authenticated_actor = session_username.is_some();
    let request_actor = session_username.unwrap_or_else(|| "api".to_owned());

    let user = {
        let mut users = state.users.write().await;
        if users
            .values()
            .any(|u| u.username.eq_ignore_ascii_case(&username))
        {
            return Err(ApiError::Conflict(format!(
                "a user named {username:?} already exists"
            )));
        }
        // Bootstrap rule (t64 §5): the first user on a fresh install (no users existed yet) is
        // Owner@Global; every subsequent user is Gestor@Global. Re-check under the write lock so
        // a stale unauthenticated bootstrap request cannot create the second user after another
        // first-run request wins the race.
        let bootstrap = bootstrap_state_for_insert(&users, is_bootstrap, has_authenticated_actor)?;
        let user = User {
            id: UserId(Uuid::new_v4()),
            username,
            display_name,
            email,
            created_at: OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .unwrap_or_default(),
            active: true,
            password_hash: Some(password_hash),
            attestation_key: Some(attestation_key),
            retired_attestation_keys: Vec::new(),
            totp: None,
            two_factor_required: false,
            // t95 §2.3 item 3: an account created **with a welcome email** was given a password the
            // administrator chose, and the admin can attest as that user until it changes (t88, and
            // the create screen says so). Force a change at first sign-in so control passes to the
            // user. Bootstrap (the first Owner sets their own password) and no-email creates are
            // unaffected. Cleared on the first successful `set_secret` (enforced at sign-in, P2).
            force_password_change: req.send_welcome_email && !is_bootstrap,
            secret_source: SecretSource::default(),
            recovery_hash: None,
            // t71: the authorized explicit grant when one was requested, else the historical
            // default. `requested_assignment` is `None` on every bootstrap create, so the
            // first-user ⇒ Owner@Global invariant is reached by exactly the path it always was.
            role_assignments: vec![
                requested_assignment
                    .unwrap_or_else(|| crate::roles::bootstrap_assignment(bootstrap)),
            ],
            language: req.language,
        };
        users.insert(user.id, user.clone());
        user
    };

    persist(&state).await?;

    // t88: the payload is the [`UserView`], never the full [`User`] — the discipline every other
    // user handler already follows (see `record_user_event`, and the note on `patch_user`). This
    // create was the one handler still feeding the whole struct in.
    //
    // To be precise about what this does and does not fix: `Ledger::append` only *hashes* the
    // payload into `Event::payload_digest` and drops the bytes, and this call passes a static
    // justification, so the argon2 verifier and the wrapped key blob were never actually stored.
    // The change is about what the event *records* rather than a disclosure fix — the view states
    // that creation produced a key (`has_attestation_key`) and names it by public fingerprint,
    // which is the auditable fact, while keeping the KEK salt, nonce and ciphertext out of the
    // hash preimage entirely. It also stops the digest from covering key material that the very
    // next password change re-wraps, which would have made it describe a state no longer on disk.
    let payload = serde_json::to_vec(&UserView::from(&user))?;
    {
        let mut ledger = state.ledger.write().await;
        ledger.append(
            &request_actor,
            "user",
            "user.created",
            Some("user created"),
            &payload,
        );
        state
            .persist_write_through(&mut ledger, 1, |_tx| Ok(()))
            .await?;
        state.attest_latest(&attestor, &ledger).await;
    }

    // t71 + t70: the welcome mail is a COURTESY attached to the create, not part of it. It runs
    // only after the account is durably written and ledgered, carries no password/token/link (see
    // `smtp_settings::send_and_record_welcome_email`), and a relay refusal is logged and swallowed
    // — failing the request here would report "not created" for an account that certainly exists,
    // which is the one outcome an operator must never be told. Skipped without an address.
    //
    // t108: swallowing the error is still right; swallowing the *fact* was not. The sender now
    // appends `user.welcome_email_sent` / `user.welcome_email_failed` before returning, so the
    // outcome survives this handler whatever is done with the `Result`. The log line is kept and
    // is now the only place the relay's own refusal text appears — deliberately, since it can
    // quote the recipient's address back and the ledger is not erasable.
    if req.send_welcome_email && !is_bootstrap {
        match user.email.as_deref() {
            Some(address) => {
                // t71: render in the RECIPIENT's language. `Auto` yields `None`, which the sender
                // resolves to the platform default (`settings.documents.locale`) — deliberately
                // not the creating operator's language, and never guessed from the name or the
                // e-mail domain.
                let message = crate::smtp_settings::WelcomeMessage {
                    user_id: user.id.0,
                    recipient_email: address,
                    recipient_name: Some(&user.display_name),
                    created_by: Some(&request_actor),
                    locale_override: user.language.fixed().map(Locale::as_str),
                };
                if let Err(error) = crate::smtp_settings::send_and_record_welcome_email(
                    &state,
                    &request_actor,
                    &attestor,
                    message,
                )
                .await
                {
                    tracing::warn!(
                        user = %user.username,
                        ?error,
                        "user created, but the welcome message could not be sent"
                    );
                }
            }
            // No address is not a send outcome, so it is not filed as one: nothing was attempted,
            // no relay was involved, and an event claiming a failed send would misdescribe it.
            None => tracing::warn!(
                user = %user.username,
                "a welcome message was requested but the account has no e-mail address"
            ),
        }
    }

    Ok((StatusCode::CREATED, Json(UserView::from(&user))))
}

/// Whether this instance is genuinely **uninitialised** — the only state in which the
/// unauthenticated first-run bootstrap (`POST /v1/users` with no session ⇒ Owner\@Global) may fire.
///
/// An empty in-memory user map is NOT sufficient evidence on its own. On the file-backed
/// (SQLite / single-node) path `load_users` is deliberately malformed-tolerant — an unreadable or
/// corrupt `users.json` loads as `None` and boots as **zero users**, which would otherwise let an
/// unauthenticated caller mint themselves an Owner\@Global on an instance that already has an
/// operator directory (and then overwrite that directory on the next `persist_users`). So the
/// durable evidence is consulted too: an existing users document means "already initialised",
/// whatever the in-memory map says.
///
/// - **file-backed with a data dir:** uninitialised ⇔ `users.json` does not exist. A fresh install
///   has no file; the first successful create writes one; a factory reset removes the sidecars
///   (so a reset instance legitimately becomes bootstrappable again — it is not bricked).
/// - **DB-backed sidecars (Postgres):** boot hydration already fails startup closed on a store
///   error, so an empty user table is authoritative.
/// - **pure in-memory state (tests, ephemeral):** nothing durable to consult; the map is
///   authoritative.
pub(crate) fn is_uninitialised_instance(state: &AppState) -> bool {
    if state.sidecars_db_backed {
        return true;
    }
    match state.data_dir() {
        Some(dir) => !dir.join(USERS_FILE).exists(),
        None => true,
    }
}

fn bootstrap_state_for_insert(
    users: &HashMap<UserId, User>,
    initial_bootstrap: bool,
    has_authenticated_actor: bool,
) -> Result<bool, ApiError> {
    if users.is_empty() {
        return Ok(true);
    }
    if initial_bootstrap && !has_authenticated_actor {
        return Err(ApiError::Unauthorized("sessão requerida".to_owned()));
    }
    Ok(false)
}

fn validate_secret(secret: &str) -> Result<(), ApiError> {
    let len = secret.chars().count();
    if len < MIN_SECRET_LEN {
        return Err(ApiError::Unprocessable(format!(
            "sign-in secret must be at least {MIN_SECRET_LEN} characters"
        )));
    }
    if len > MAX_SECRET_LEN {
        return Err(ApiError::Unprocessable(format!(
            "sign-in secret must be at most {MAX_SECRET_LEN} characters"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stored_user(username: &str) -> User {
        User {
            id: UserId(Uuid::new_v4()),
            username: username.to_owned(),
            display_name: username.to_owned(),
            email: None,
            created_at: OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .unwrap_or_default(),
            active: true,
            password_hash: None,
            attestation_key: None,
            retired_attestation_keys: Vec::new(),
            totp: None,
            two_factor_required: false,
            force_password_change: false,
            secret_source: SecretSource::default(),
            recovery_hash: None,
            role_assignments: vec![crate::roles::bootstrap_assignment(true)],
            language: Default::default(),
        }
    }

    #[test]
    fn create_user_stale_unauthenticated_bootstrap_is_rejected_at_insert_recheck() {
        let empty = HashMap::new();
        assert!(bootstrap_state_for_insert(&empty, true, false).unwrap());

        let mut users = HashMap::new();
        let owner = stored_user("owner");
        users.insert(owner.id, owner);

        let err = bootstrap_state_for_insert(&users, true, false).unwrap_err();
        assert!(matches!(
            err,
            ApiError::Unauthorized(message) if message == "sessão requerida"
        ));
        assert!(!bootstrap_state_for_insert(&users, false, true).unwrap());
    }
}

fn verify_current(user: &User, provided: Option<&str>) -> Result<(), ApiError> {
    match &user.password_hash {
        Some(phc) => {
            if provided.map(|p| verify_secret(p, phc)).unwrap_or(false) {
                Ok(())
            } else {
                Err(ApiError::Unauthorized(
                    "palavra-passe atual incorreta".to_owned(),
                ))
            }
        }
        None => Ok(()),
    }
}

/// The single, honest PT refusal returned for **every** no-valid-proof cross-user case (wrong
/// password, no proof, or a non-existent target). Uniform so it never enumerates users (t51 §5).
const CROSS_USER_FORBIDDEN: &str = "não autorizado a alterar as credenciais de outro utilizador sem a palavra-passe atual ou uma frase de recuperação válida";

/// Refusal for cross-user attestation-key generation authorized only by a recovery phrase: the key
/// is wrapped under the password KEK, so without the password no usable key can be produced (t51).
const RECOVERY_CANNOT_GENERATE_KEY: &str =
    "não é possível gerar uma chave de atestação sem a palavra-passe atual do utilizador";

/// A fixed, valid argon2id PHC used to spend the **same** verification cost when the target has no
/// password / no recovery verifier / does not exist. Verifying any input against it always yields
/// `false`, but the argon2 work is spent so timing never reveals the target's state (t51 §5,
/// constant-work). Computed once with the production [`hash_secret`] params so its cost matches a
/// real verify exactly.
fn dummy_phc() -> &'static str {
    static DUMMY: OnceLock<String> = OnceLock::new();
    DUMMY.get_or_init(|| {
        attestation::hash_secret("chancela::t51::constant-work::dummy-verifier")
            .expect("argon2id hash of a constant never fails")
    })
}

/// Run a constant-work argon2id verify of `provided` against the target's `stored` verifier, or
/// against the [`dummy_phc`] when the target lacks one (or does not exist). Always runs exactly one
/// argon2 verify regardless of branch, so timing/branching does not leak whether the target has the
/// credential. `provided == None` still verifies (an empty candidate) so the cost is spent.
fn constant_work_verify(stored: Option<&str>, provided: Option<&str>) -> bool {
    let phc = stored.unwrap_or_else(|| dummy_phc());
    let candidate = provided.unwrap_or("");
    verify_secret(candidate, phc)
}

/// Which proof authorized a cross-user credential operation (for audit + provenance).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProofKind {
    /// The target's current password was supplied and verified (path b).
    Password,
    /// A valid recovery phrase for the target was supplied and verified (path a, Phase B).
    Recovery,
}

impl ProofKind {
    /// Honest, secret-free audit phrase.
    fn describe(self) -> &'static str {
        match self {
            ProofKind::Password => "via palavra-passe atual conhecida",
            ProofKind::Recovery => "via frase de recuperação",
        }
    }
}

/// The authorization outcome for a secret/attestation-key operation (t51 §1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SecretAuthz {
    /// Requester == target: self-service. Existing `verify_current` rules apply unchanged.
    SelfService,
    /// Requester != target, authorized by the named proof.
    CrossUser(ProofKind),
}

/// Resolve the requesting user's [`UserId`] (from the session username) and clone the target
/// snapshot, under a single `users` read lock. The requester is `None` if the session username no
/// longer maps to a user (should not happen for a valid session, but treated as non-self).
async fn resolve_requester_and_target(
    state: &AppState,
    actor: &CurrentActor,
    target: UserId,
) -> (Option<UserId>, Option<User>) {
    let users = state.users.read().await;
    let requester_id = actor
        .session_username()
        .and_then(|name| users.values().find(|u| u.username == name).map(|u| u.id));
    let snapshot = users.get(&target).cloned();
    (requester_id, snapshot)
}

/// The **constant-work** cross-user proof check (t51 §5). Runs one password-verify and, on failure,
/// one recovery-verify — always against the target's real verifier when present, else the
/// [`dummy_phc`], so the branch on target state is not observable. Returns the proof kind on success
/// or a **uniform** [`ApiError::Forbidden`] for every failure (wrong password, no proof, or a
/// non-existent target), so no case is distinguishable by status, body, or timing.
fn verify_cross_user_proof(
    target: Option<&User>,
    current_password: Option<&str>,
    recovery_phrase: Option<&str>,
) -> Result<ProofKind, ApiError> {
    let password_hash = target.and_then(|u| u.password_hash.as_deref());
    if constant_work_verify(password_hash, current_password) {
        return Ok(ProofKind::Password);
    }
    let recovery_hash = target.and_then(|u| u.recovery_hash.as_deref());
    if constant_work_verify(recovery_hash, recovery_phrase) {
        return Ok(ProofKind::Recovery);
    }
    Err(ApiError::Forbidden(CROSS_USER_FORBIDDEN.to_owned()))
}

/// Honest, secret-free description of which proof(s) the request *presented* (never the values, and
/// never whether they were correct) — for the failed-attempt audit event (t52 D2). Derived only from
/// the request body, so it can never leak the target's state.
fn attempted_proof(current_password: Option<&str>, recovery_phrase: Option<&str>) -> &'static str {
    match (current_password.is_some(), recovery_phrase.is_some()) {
        (false, false) => "sem prova",
        (true, false) => "palavra-passe",
        (false, true) => "frase de recuperação",
        (true, true) => "palavra-passe + frase de recuperação",
    }
}

/// The fixed-shape payload of a `user.secret.reset.denied` audit event (t52 D2). Contains ONLY
/// request-derived attribution — the target id *from the request path* (attacker-supplied; its
/// presence here does NOT imply the user exists), the operation, and which proof kind(s) were
/// presented. It is deliberately **not** a [`UserView`]: emitting a UserView would fire a richer
/// payload for a real target than for a ghost, turning the ledger into an enumeration oracle. No
/// secret/phrase/password material ever appears.
#[derive(Serialize)]
struct SecretResetDenied<'a> {
    target_id: String,
    operation: &'a str,
    attempted_proof: &'a str,
}

/// Append a `user.secret.reset.denied` audit event for a FAILED cross-user authorization (the 403
/// path, t52 D2). The `actor` is the honest requester (session user). Fires with a fixed-shape,
/// target-existence-independent payload, and goes through the same write-through/attest discipline as
/// every other user event. Does **not** persist `users.json` — a denial mutates no user state.
async fn record_secret_denied(
    state: &AppState,
    target_id: UserId,
    operation: &str,
    attempted_proof: &str,
    actor: &CurrentActor,
    attestor: &CurrentAttestor,
) -> Result<(), ApiError> {
    let payload = serde_json::to_vec(&SecretResetDenied {
        target_id: target_id.to_string(),
        operation,
        attempted_proof,
    })?;
    let actor_name = actor.resolve("api");
    let mut ledger = state.ledger.write().await;
    ledger.append(
        &actor_name,
        "user",
        "user.secret.reset.denied",
        Some("cross-user credential reset refused (no valid proof)"),
        &payload,
    );
    state
        .persist_write_through(&mut ledger, 1, |_tx| Ok(()))
        .await?;
    state.attest_latest(attestor, &ledger).await;
    Ok(())
}

/// The core t51 authorization decision, now with the t52 target-keyed backoff + failed-attempt audit
/// layered on top of the t51 constant-work / uniform-403 guarantees.
///
/// - **Self-service** (`requester == target`, and the target exists): returns
///   [`SecretAuthz::SelfService`] immediately — no argon2, no backoff, no audit. The caller (who
///   already *is* the target) preserves the exact prior behaviour and can never be locked out of
///   their own account by a third party hammering their id (see below).
/// - **Cross-user** (or an unknown target): throttled on **`(requester, target-from-request)`**.
///   - *Keying rationale (anti-enumeration + no victim lockout):* the target id is the one from the
///     request, so a failed attempt against a **non-existent** target accrues and throttles exactly
///     like one against a real target — an attacker cannot tell "throttled ⇒ real user" from "not
///     throttled ⇒ no such user". Including the **requester** in the key means the throttle bites the
///     abusive source; a victim's own self-service uses a different key (`(victim, victim)`, which is
///     never throttled at all), so an attacker cannot lock a victim out of their own account.
///   - While throttled → a uniform `429` **before** any argon2, identical for real vs ghost targets
///     (the delay is a pure function of the attacker's own prior failures against that key).
///   - Otherwise runs [`verify_cross_user_proof`] (constant-work, t51 §5) **while holding the backoff
///     lock** (mirrors `signin_backoff`, so concurrent attempts cannot all bypass the speed-bump).
///     Success clears the counter; a `403` bumps it (escalating `[1,2,4,…]` s window) and is audited
///     via [`record_secret_denied`] (detectability). The audit fires only on the un-throttled `403`,
///     not on the `429` — so the ledger can never be flooded faster than the backoff permits.
#[allow(clippy::too_many_arguments)]
async fn authorize_secret_op_throttled(
    state: &AppState,
    actor: &CurrentActor,
    attestor: &CurrentAttestor,
    operation: &str,
    requester_id: Option<UserId>,
    target_id: UserId,
    target: Option<&User>,
    current_password: Option<&str>,
    recovery_phrase: Option<&str>,
) -> Result<SecretAuthz, ApiError> {
    if actor.is_api_key() {
        return Err(ApiError::Forbidden(
            "chave API não abre uma sessão interativa".to_owned(),
        ));
    }

    // Self-service is only possible when the requester *is* the (existing) target. Never throttled,
    // never audited, never runs argon2 (the caller already holds the account).
    if requester_id == Some(target_id) && target.is_some() {
        return Ok(SecretAuthz::SelfService);
    }

    let key = (requester_id, target_id);
    let now = OffsetDateTime::now_utc();
    // Hold the backoff lock across the constant-work verify (mirrors `signin_backoff`): concurrent
    // attempts cannot each read "no backoff" and then each spend argon2 cost, nor bypass the window.
    let mut backoff = state.secret_backoff.write().await;
    {
        let entry = backoff.entry(key).or_insert_with(|| Backoff {
            fails: 0,
            next_allowed_at: now,
        });
        if now < entry.next_allowed_at {
            // Uniform 429 — identical for a real vs a non-existent target (the window is a function
            // of the attacker's own prior failures against this key, not of the target's state). No
            // argon2 is spent and no audit event is written (keeps the 429 timing minimal and the
            // ledger un-floodable). Layered ON TOP of the t51 uniform-403 guarantee, never below it.
            let ms = (entry.next_allowed_at - now).whole_milliseconds();
            let remaining = ((ms + 999) / 1000).max(1);
            return Err(ApiError::TooManyRequests(format!(
                "demasiadas tentativas — tente novamente em {remaining} s"
            )));
        }
    }

    match verify_cross_user_proof(target, current_password, recovery_phrase) {
        Ok(kind) => {
            backoff.remove(&key); // a valid proof clears the counter (mirrors signin on success)
            Ok(SecretAuthz::CrossUser(kind))
        }
        Err(forbidden) => {
            {
                let entry = backoff.entry(key).or_insert_with(|| Backoff {
                    fails: 0,
                    next_allowed_at: now,
                });
                entry.fails += 1;
                entry.next_allowed_at = now + Duration::seconds(backoff_secs(entry.fails));
            }
            drop(backoff); // release before the ledger write (independent lock, kept un-nested)
            record_secret_denied(
                state,
                target_id,
                operation,
                attempted_proof(current_password, recovery_phrase),
                actor,
                attestor,
            )
            .await?;
            Err(forbidden)
        }
    }
}

/// Append a user-scoped audit event whose payload is a [`UserView`] (never the full [`User`], so no
/// argon2 hash, wrapped key, or recovery verifier is ever fed into the ledger). The `actor` is the
/// honest requester (session user), so a cross-user reset names *who* performed it.
async fn record_user_event(
    state: &AppState,
    user: &User,
    kind: &str,
    justification: &str,
    actor: &CurrentActor,
    attestor: &CurrentAttestor,
) -> Result<(), ApiError> {
    persist(state).await?;
    let payload = serde_json::to_vec(&UserView::from(user))?;
    let actor = actor.resolve("api");
    let mut ledger = state.ledger.write().await;
    ledger.append(&actor, "user", kind, Some(justification), &payload);
    state
        .persist_write_through(&mut ledger, 1, |_tx| Ok(()))
        .await?;
    state.attest_latest(attestor, &ledger).await;
    Ok(())
}

/// A `user.updated` audit event (the common case for self-service + non-reset mutations).
async fn record_user_update(
    state: &AppState,
    user: &User,
    justification: &str,
    actor: &CurrentActor,
    attestor: &CurrentAttestor,
) -> Result<(), ApiError> {
    record_user_event(state, user, "user.updated", justification, actor, attestor).await
}

/// `POST /v1/users/{id}/secret` — set or change the sign-in secret. **t41 H2:** argon2 verify
/// and key rewrap run OUTSIDE the write lock.
///
/// **t51 authorization.** Self-service (requester == target) is unchanged: setting a first secret is
/// free, changing an existing one proves the current password. A **cross-user** reset is permitted
/// only with a valid proof — the target's current password (path b), or a valid recovery phrase
/// (path a, Phase B) — otherwise a uniform `403` (§ [`authorize_secret_op`]). A recovery-authorized
/// reset cannot recover the password-locked attestation key, so it drops the key and records the new
/// secret's provenance as [`SecretSource::Recovery`]; the used phrase is consumed (single-use).
pub async fn set_secret(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<SetSecret>,
) -> Result<Json<UserView>, ApiError> {
    validate_secret(&req.password)?;
    let uid = UserId(id);

    let (requester_id, snapshot) = resolve_requester_and_target(&state, &actor, uid).await;
    let decision = authorize_secret_op_throttled(
        &state,
        &actor,
        &attestor,
        "set_secret",
        requester_id,
        uid,
        snapshot.as_ref(),
        req.current_password.as_deref(),
        req.recovery_phrase.as_deref(),
    )
    .await?;
    // RBAC (t64-E3): a CROSS-USER credential reset additionally requires `user.manage` (self-service
    // is unaffected — a user always manages their own credential; the t51 proof still applies on top).
    if let SecretAuthz::CrossUser(_) = decision {
        require_permission(&state, &actor, Permission::UserManage, Scope::Global).await?;
    }
    // Authorized. For self the requester *is* the target and exists; for cross-user the authorize
    // step already returned a uniform 403 for a missing target, so a snapshot is present here.
    let snapshot = snapshot.ok_or(ApiError::Forbidden(CROSS_USER_FORBIDDEN.to_owned()))?;
    let changing = snapshot.password_hash.is_some();

    // Strength policy (t68). Enforced AFTER authorization so a cross-user caller without a valid proof
    // gets the uniform 403 first (anti-enumeration, t51) — the policy never becomes an oracle — and so
    // the username rule can validate against the *target's* real username. `validate_secret` above
    // already rejected an empty/over-long candidate (422); this adds the composition/denylist/run
    // rules (relaxable via `ALLOW_WEAK_PASSWORDS`, presence excepted). Login (`create_session`) and the
    // recovery/data-reset re-auth paths deliberately do NOT run this — they verify an existing secret,
    // and strength-checking them would lock out an account whose password predates the policy.
    crate::password_policy::enforce(
        &req.password,
        &snapshot.username,
        crate::password_policy::ALLOW_WEAK_PASSWORDS,
    )?;

    // Self-service keeps the exact prior contract: prove the current password when changing.
    if matches!(decision, SecretAuthz::SelfService) && changing {
        verify_current(&snapshot, req.current_password.as_deref())?;
    }

    let seed = state.verifier_seed.read().await.clone();
    let new_hash = attestation::hash_secret_with_seed(&req.password, &seed)?;

    // Attestation-key + provenance handling by authorization path (argon2/rewrap OUTSIDE the lock).
    // `proof` is `Some` only on a cross-user reset (drives the distinct audit event + recovery
    // single-use consumption).
    let (rewrapped, drop_key, source, proof): (
        Option<AttestationKeyBlob>,
        bool,
        SecretSource,
        Option<ProofKind>,
    ) = match decision {
        // Self-service or cross-user-with-password both hold the current password, so the
        // attestation key is re-wrapped forward under the new password (identity preserved).
        SecretAuthz::SelfService | SecretAuthz::CrossUser(ProofKind::Password) => {
            let rewrapped = if changing {
                let old = req.current_password.as_deref().unwrap_or_default();
                match &snapshot.attestation_key {
                    Some(blob) => Some(blob.rewrap(old, &req.password)?),
                    None => None,
                }
            } else {
                None
            };
            let proof = match decision {
                SecretAuthz::CrossUser(k) => Some(k),
                SecretAuthz::SelfService => None,
            };
            (rewrapped, false, SecretSource::Password, proof)
        }
        // Recovery reset: no old password is available, so the password-locked attestation key
        // cannot be re-wrapped — it is dropped, and provenance records the recovery origin.
        SecretAuthz::CrossUser(ProofKind::Recovery) => (
            None,
            true,
            SecretSource::Recovery,
            Some(ProofKind::Recovery),
        ),
    };

    let user = {
        let mut users = state.users.write().await;
        let user = users.get_mut(&uid).ok_or(ApiError::NotFound)?;
        if let Some(r) = rewrapped {
            user.attestation_key = Some(r);
        }
        if drop_key {
            // t92: the blob cannot be re-wrapped without the old password, but its public half is
            // retained so the attestations it signed before the reset still verify.
            user.retire_attestation_key(now_rfc3339());
        }
        user.password_hash = Some(new_hash);
        user.secret_source = source;
        if matches!(proof, Some(ProofKind::Recovery)) {
            user.recovery_hash = None; // single-use: the phrase is consumed on a successful reset.
        }
        // t95 §2.3 item 3: any successful secret change clears the forced-change flag. The admin's
        // initial password is gone, so the account no longer needs to be walled off at sign-in. This
        // fires for the self-service change the forced-change flow drives the user into, and for a
        // legitimate cross-user reset alike — either way the initial password no longer stands.
        user.force_password_change = false;
        user.clone()
    };

    match proof {
        Some(kind) => {
            let justification = format!("sign-in secret reset {}", kind.describe());
            record_user_event(
                &state,
                &user,
                "user.secret.reset",
                &justification,
                &actor,
                &attestor,
            )
            .await?;
        }
        None => record_user_update(&state, &user, "sign-in secret set", &actor, &attestor).await?,
    }
    Ok(Json(UserView::from(&user)))
}

/// `DELETE /v1/users/{id}/secret` — password removal is retired. The endpoint remains only to
/// return a clear error after the same authorization checks; callers must replace via `POST`.
///
/// **t51 authorization.** Self-service still proves the current password when one exists; cross-user
/// removal follows the same proof/RBAC rule as [`set_secret`]. Authorized requests return `409`
/// without clearing `password_hash` or the attestation key, so this path cannot create live
/// no-password users.
pub async fn remove_secret(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<CurrentSecret>,
) -> Result<Json<UserView>, ApiError> {
    let uid = UserId(id);

    let (requester_id, snapshot) = resolve_requester_and_target(&state, &actor, uid).await;
    let decision = authorize_secret_op_throttled(
        &state,
        &actor,
        &attestor,
        "remove_secret",
        requester_id,
        uid,
        snapshot.as_ref(),
        req.current_password.as_deref(),
        req.recovery_phrase.as_deref(),
    )
    .await?;
    // RBAC (t64-E3): a CROSS-USER credential reset additionally requires `user.manage`.
    if let SecretAuthz::CrossUser(_) = decision {
        require_permission(&state, &actor, Permission::UserManage, Scope::Global).await?;
    }

    match decision {
        SecretAuthz::SelfService => {
            let s = snapshot.as_ref().ok_or(ApiError::NotFound)?;
            if s.password_hash.is_some() {
                verify_current(s, req.current_password.as_deref())?;
            }
        }
        SecretAuthz::CrossUser(_) => {}
    }
    Err(ApiError::Conflict(
        "não é permitido remover a palavra-passe; defina uma nova palavra-passe em alternativa"
            .to_owned(),
    ))
}

/// `POST /v1/users/{id}/attestation-key` — generate or rotate the attestation key. **t41 H2.**
///
/// **t51 authorization.** Self-service is unchanged (requires a secret, proves the current
/// password). A cross-user generation is authorized by the same rule — but ONLY via the target's
/// **current password** (path b): the new key is wrapped under the password KEK, so a
/// recovery-phrase proof cannot produce a key the user could ever unlock, and is refused with `403`.
pub async fn generate_attestation_key(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<CurrentSecret>,
) -> Result<Json<UserView>, ApiError> {
    let uid = UserId(id);

    let (requester_id, snapshot) = resolve_requester_and_target(&state, &actor, uid).await;
    let decision = authorize_secret_op_throttled(
        &state,
        &actor,
        &attestor,
        "generate_attestation_key",
        requester_id,
        uid,
        snapshot.as_ref(),
        req.current_password.as_deref(),
        req.recovery_phrase.as_deref(),
    )
    .await?;
    // RBAC (t64-E3): a CROSS-USER attestation-key generation additionally requires `user.manage`.
    if let SecretAuthz::CrossUser(_) = decision {
        require_permission(&state, &actor, Permission::UserManage, Scope::Global).await?;
    }

    // The new key is wrapped under a password. Determine the wrapping secret per authorization path.
    let (wrapping_secret, cross_user) = match decision {
        SecretAuthz::SelfService => {
            let s = snapshot.as_ref().ok_or(ApiError::NotFound)?;
            if s.password_hash.is_none() {
                return Err(ApiError::Conflict(
                    "set a sign-in secret before generating an attestation key".to_owned(),
                ));
            }
            verify_current(s, req.current_password.as_deref())?;
            (req.current_password.clone().unwrap_or_default(), false)
        }
        SecretAuthz::CrossUser(ProofKind::Password) => {
            // The verified current password is the wrapping secret (the target can unlock it later).
            (req.current_password.clone().unwrap_or_default(), true)
        }
        SecretAuthz::CrossUser(ProofKind::Recovery) => {
            return Err(ApiError::Forbidden(RECOVERY_CANNOT_GENERATE_KEY.to_owned()));
        }
    };

    let new_key = AttestationKeyBlob::generate(&wrapping_secret)?;

    let user = {
        let mut users = state.users.write().await;
        let user = users.get_mut(&uid).ok_or(ApiError::NotFound)?;
        // t92: retire the outgoing key's public half BEFORE installing the new one, so a rotation
        // mints a key for future events without stranding the ones the old key already signed.
        user.retire_attestation_key(now_rfc3339());
        user.attestation_key = Some(new_key);
        user.clone()
    };
    let justification = if cross_user {
        "attestation key generated (cross-user, via known password)"
    } else {
        "attestation key generated"
    };
    record_user_update(&state, &user, justification, &actor, &attestor).await?;
    Ok(Json(UserView::from(&user)))
}

/// `DELETE /v1/users/{id}/attestation-key` — remove the attestation key. **t41 H2.**
///
/// **t51 authorization.** Self-service is unchanged (no-op when keyless, else prove the current
/// password). Removal needs no wrapping secret, so a cross-user removal is authorized by **either**
/// proof (current password or a valid recovery phrase); otherwise a uniform `403`. The self no-op
/// short-circuit is applied only for self, so a cross-user caller cannot probe key presence.
pub async fn remove_attestation_key(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<CurrentSecret>,
) -> Result<Json<UserView>, ApiError> {
    let uid = UserId(id);

    let (requester_id, snapshot) = resolve_requester_and_target(&state, &actor, uid).await;
    let decision = authorize_secret_op_throttled(
        &state,
        &actor,
        &attestor,
        "remove_attestation_key",
        requester_id,
        uid,
        snapshot.as_ref(),
        req.current_password.as_deref(),
        req.recovery_phrase.as_deref(),
    )
    .await?;
    // RBAC (t64-E3): a CROSS-USER attestation-key removal additionally requires `user.manage`.
    if let SecretAuthz::CrossUser(_) = decision {
        require_permission(&state, &actor, Permission::UserManage, Scope::Global).await?;
    }

    match decision {
        SecretAuthz::SelfService => {
            let s = snapshot.as_ref().ok_or(ApiError::NotFound)?;
            if s.attestation_key.is_none() {
                return Ok(Json(UserView::from(s))); // self no-op: nothing to remove.
            }
            verify_current(s, req.current_password.as_deref())?;
        }
        SecretAuthz::CrossUser(_) => {}
    }
    let consume_recovery = matches!(decision, SecretAuthz::CrossUser(ProofKind::Recovery));

    let user = {
        let mut users = state.users.write().await;
        let user = users.get_mut(&uid).ok_or(ApiError::NotFound)?;
        user.retire_attestation_key(now_rfc3339()); // t92: the past stays verifiable.
        if consume_recovery {
            user.recovery_hash = None; // single-use.
        }
        user.clone()
    };
    let justification = match decision {
        SecretAuthz::CrossUser(kind) => {
            format!("attestation key removed (cross-user, {})", kind.describe())
        }
        SecretAuthz::SelfService => "attestation key removed".to_owned(),
    };
    record_user_update(&state, &user, &justification, &actor, &attestor).await?;
    Ok(Json(UserView::from(&user)))
}

/// `POST /v1/users/{id}/recovery` — issue or rotate the user's recovery phrase (t51 Phase B).
///
/// The recovery phrase is an **independent** reset credential (not derived from, nor wrapping, the
/// password). It is generated server-side, returned **exactly once** in the response, and stored
/// only as an argon2id verifier. Issuing rotates any existing phrase (the old verifier is
/// overwritten). **Authorization:** self-service proves the current password when one exists (a
/// recovery credential is a reset backdoor — establishing it requires proving identity beyond the
/// session); a cross-user issuance uses the same rule as the secret ops (target's current password,
/// or a still-valid existing recovery phrase).
pub async fn issue_recovery(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<IssueRecovery>,
) -> Result<Json<RecoveryIssued>, ApiError> {
    let uid = UserId(id);

    let (requester_id, snapshot) = resolve_requester_and_target(&state, &actor, uid).await;
    let decision = authorize_secret_op_throttled(
        &state,
        &actor,
        &attestor,
        "issue_recovery",
        requester_id,
        uid,
        snapshot.as_ref(),
        req.current_password.as_deref(),
        req.recovery_phrase.as_deref(),
    )
    .await?;
    // RBAC (t64-E3): a CROSS-USER recovery issuance additionally requires `user.manage`.
    if let SecretAuthz::CrossUser(_) = decision {
        require_permission(&state, &actor, Permission::UserManage, Scope::Global).await?;
    }

    if let SecretAuthz::SelfService = decision {
        // Self-service: prove the current password when the account has one (legacy no-hash has none).
        let s = snapshot.as_ref().ok_or(ApiError::NotFound)?;
        verify_current(s, req.current_password.as_deref())?;
    }

    // Generate the phrase and its verifier OUTSIDE the write lock (argon2 discipline, t41 H2).
    let phrase = attestation::generate_recovery_phrase();
    let seed = state.verifier_seed.read().await.clone();
    let verifier = attestation::hash_secret_with_seed(&phrase, &seed)?;

    let user = {
        let mut users = state.users.write().await;
        let user = users.get_mut(&uid).ok_or(ApiError::NotFound)?;
        user.recovery_hash = Some(verifier);
        user.clone()
    };

    let justification = match decision {
        SecretAuthz::CrossUser(kind) => {
            format!("recovery phrase issued (cross-user, {})", kind.describe())
        }
        SecretAuthz::SelfService => "recovery phrase issued".to_owned(),
    };
    record_user_event(
        &state,
        &user,
        "user.recovery.issued",
        &justification,
        &actor,
        &attestor,
    )
    .await?;

    Ok(Json(RecoveryIssued {
        recovery_phrase: phrase,
        user: UserView::from(&user),
    }))
}

/// `GET /v1/users` — every profile. Requires a valid session (t41 C1).
pub async fn list_users(
    State(state): State<AppState>,
    actor: CurrentActor,
) -> Result<Json<Vec<UserView>>, ApiError> {
    // RBAC (t64-E3): the full user roster is `user.read` at Global (the unauth sign-in picker uses
    // the minimal `GET /v1/session/roster` instead).
    require_permission(&state, &actor, Permission::UserRead, Scope::Global).await?;
    let users = state.users.read().await;
    let mut list: Vec<&User> = users.values().collect();
    list.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.0.cmp(&b.id.0)));
    Ok(Json(list.into_iter().map(UserView::from).collect()))
}

/// `GET /v1/users/{id}` — one profile, or `404`. RBAC (t64-E3): `user.read` at Global.
pub async fn get_user(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    actor: CurrentActor,
) -> Result<Json<UserView>, ApiError> {
    require_permission(&state, &actor, Permission::UserRead, Scope::Global).await?;
    let users = state.users.read().await;
    users
        .get(&UserId(id))
        .map(|u| Json(UserView::from(u)))
        .ok_or(ApiError::NotFound)
}

/// `PATCH /v1/users/{id}` — rename and/or (de)activate a profile. Appends `user.updated`.
///
/// **Last-active-user guard:** deactivating (`active:false`) the only remaining active user is
/// refused with `409`. With no active user left, no session can ever be minted again
/// (`create_session` rejects inactive users) and the bootstrap-create only fires at *zero* users,
/// so the instance would be permanently bricked for mutations.
///
/// The `user.updated` payload is a [`UserView`] (via [`record_user_update`]), never the full
/// [`User`] — no argon2 hash or wrapped attestation key is fed into the audit event, matching
/// every other user handler.
pub async fn patch_user(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<PatchUser>,
) -> Result<Json<UserView>, ApiError> {
    // RBAC (t64-E3): editing a profile (rename / (de)activate) is `user.manage` at Global.
    require_permission(&state, &actor, Permission::UserManage, Scope::Global).await?;
    // t95 §2.3: requiring a second factor an instance cannot issue is a lockout with no cure. Refuse
    // the toggle-on unless TOTP is enabled instance-wide, before any state is touched.
    if req.two_factor_required == Some(true)
        && !state.settings.read().await.auth.two_factor.totp_enabled
    {
        return Err(ApiError::Unprocessable(
            "auth.two_factor.totp_enabled tem de estar ativo antes de exigir um segundo fator a uma \
             conta; caso contrário a conta ficaria sem forma de o configurar"
                .to_owned(),
        ));
    }
    let user = {
        let mut users = state.users.write().await;
        // Last-active-user guard: reject deactivating the final active user (checked under the
        // write lock so two concurrent deactivations can't both pass).
        if req.active == Some(false) {
            let target = users.get(&UserId(id)).ok_or(ApiError::NotFound)?;
            if target.active && users.values().filter(|u| u.active).count() <= 1 {
                return Err(ApiError::Conflict(
                    "não pode desativar o último utilizador ativo".to_owned(),
                ));
            }
            // Last-Owner guard (t64 §5): deactivating the last ACTIVE administrative Owner
            // (Owner@Global) would strip the instance of any super-user — an inactive user confers
            // no authority and cannot sign in to recover, so the instance would be permanently
            // un-administrable. Refuse (mirrors the unassign-Owner guard). Only active Owner holders
            // count; the target is still active here, so being the sole active holder ⇒ blocked.
            if target.active
                && target
                    .role_assignments
                    .iter()
                    .any(RoleAssignment::is_owner_admin)
            {
                let active_owner_holders =
                    count_owner_admin_holders(users.values().filter(|u| u.active).flat_map(|u| {
                        let uid = AuthzUserId(u.id.0);
                        u.role_assignments.iter().map(move |a| (uid, a))
                    }));
                if !last_owner_guard(active_owner_holders) {
                    return Err(ApiError::Conflict(
                        "não pode desativar o último Proprietário".to_owned(),
                    ));
                }
            }
        }
        let user = users.get_mut(&UserId(id)).ok_or(ApiError::NotFound)?;
        if let Some(display_name) = req.display_name {
            let trimmed = display_name.trim();
            if !trimmed.is_empty() {
                user.display_name = trimmed.to_owned();
            }
        }
        if let Some(email) = req.email {
            user.email = crate::email::normalize_optional_email(email, "email")?;
        }
        if let Some(active) = req.active {
            user.active = active;
        }
        // t71: `"auto"` is a real value here — it sets the preference back to "keep detecting"
        // rather than clearing the field, so a user can undo a fixed choice.
        if let Some(language) = req.language {
            user.language = language;
        }
        if let Some(required) = req.two_factor_required {
            user.two_factor_required = required;
        }
        user.clone()
    };

    record_user_update(&state, &user, "user updated", &actor, &attestor).await?;
    Ok(Json(UserView::from(&user)))
}
