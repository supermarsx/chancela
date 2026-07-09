//! Named user profiles + actor attribution (contract §2.8).
//!
//! Chancela is a local-first, single-operator / small-office app on loopback. User profiles serve
//! two purposes: **attribution** (DAT-10 — identify *who* performed each mutation so the audit
//! ledger names a real person instead of the fixed `"api"` fallback) and, since t41,
//! **access control** — every domain mutation requires a valid session, and users may hold an
//! optional argon2id sign-in secret (t29). This is no longer a passwordless, authorization-free
//! surface: an operator signs in before doing any work.
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
    /// How the current secret was established (t51). Additive; defaults to `Password`.
    #[serde(default)]
    pub secret_source: SecretSource,
    /// argon2id **verifier** for the user's recovery phrase (t51 Phase B), or `None` when no
    /// recovery credential is established. Stores ONLY the verifier — never the plaintext phrase and
    /// never anything reversible. Independent of the password: possession of the phrase is its own
    /// proof. Consumed (set back to `None`) after a successful recovery-authorized reset (single-use).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_hash: Option<String>,
    /// The user's scoped RBAC role assignments (t64). **Additive** — `#[serde(default)]` keeps every
    /// pre-t64 `users.json` loadable (an absent value reads as an empty vec), which the one-time
    /// [`crate::roles::migrate_roles`] pass then brings forward (sole/first user ⇒ Owner\@Global,
    /// the rest ⇒ Gestor\@Global). A freshly bootstrapped user is assigned here at creation.
    #[serde(default)]
    pub role_assignments: Vec<chancela_authz::RoleAssignment>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_key_fingerprint: Option<String>,
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
            attestation_key_fingerprint: u.attestation_key.as_ref().map(|k| k.fingerprint.clone()),
        }
    }
}

#[derive(Deserialize)]
pub struct CreateUser {
    pub username: String,
    pub display_name: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
}

#[derive(Deserialize)]
pub struct PatchUser {
    pub display_name: Option<String>,
    #[serde(default, deserialize_with = "crate::dto::double_option")]
    pub email: Option<Option<String>>,
    pub active: Option<bool>,
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
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
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
    if let Some(path) = &state.users_path {
        let users = state.users.read().await;
        write_users_atomic(path, &users)
            .map_err(|e| ApiError::Internal(format!("failed to persist users: {e}")))?;
    }
    Ok(())
}

/// `POST /v1/users` — create a profile. **Bootstrap (t41):** when no users exist yet, callable
/// WITHOUT a session. Once at least one user exists, a valid session is required.
pub async fn create_user(
    State(state): State<AppState>,
    parts: axum::http::HeaderMap,
    attestor: CurrentAttestor,
    Json(req): Json<CreateUser>,
) -> Result<(StatusCode, Json<UserView>), ApiError> {
    let username = validate_username(&req.username)?;
    let display_name = req
        .display_name
        .map(|d| d.trim().to_owned())
        .filter(|d| !d.is_empty())
        .unwrap_or_else(|| username.clone());
    let email = crate::email::normalize_optional_email(req.email, "email")?;

    let (session_username, is_bootstrap) = {
        let user_count = state.users.read().await.len();
        if user_count == 0 {
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
    // gate composes with the same principal seam as every other endpoint.
    if !is_bootstrap {
        let actor = CurrentActor::from_session_username(session_username.clone());
        require_permission(&state, &actor, Permission::UserManage, Scope::Global).await?;
    }
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
        // Owner@Global; every subsequent user is Gestor@Global. Determined under the write lock so
        // exactly one bootstrap Owner can ever be minted.
        let bootstrap = users.is_empty();
        let user = User {
            id: UserId(Uuid::new_v4()),
            username,
            display_name,
            email,
            created_at: OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .unwrap_or_default(),
            active: true,
            password_hash: None,
            attestation_key: None,
            secret_source: SecretSource::default(),
            recovery_hash: None,
            role_assignments: vec![crate::roles::bootstrap_assignment(bootstrap)],
        };
        users.insert(user.id, user.clone());
        user
    };

    persist(&state).await?;

    let payload = serde_json::to_vec(&user)?;
    {
        let mut ledger = state.ledger.write().await;
        ledger.append(
            &request_actor,
            "user",
            "user.created",
            Some("user created"),
            &payload,
        );
        state.persist_write_through(&mut ledger, 1, |_tx| Ok(()))?;
        state.attest_latest(&attestor, &ledger).await;
    }

    Ok((StatusCode::CREATED, Json(UserView::from(&user))))
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
    state.persist_write_through(&mut ledger, 1, |_tx| Ok(()))?;
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
    state.persist_write_through(&mut ledger, 1, |_tx| Ok(()))?;
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

    let new_hash = attestation::hash_secret(&req.password)?;

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
            user.attestation_key = None;
        }
        user.password_hash = Some(new_hash);
        user.secret_source = source;
        if matches!(proof, Some(ProofKind::Recovery)) {
            user.recovery_hash = None; // single-use: the phrase is consumed on a successful reset.
        }
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

/// `DELETE /v1/users/{id}/secret` — remove the sign-in secret. **t41 H2:** argon2 outside lock.
///
/// **t51 authorization.** Self-service is unchanged (no-op when passwordless, else prove the current
/// password). A cross-user removal follows the same rule as [`set_secret`]: valid proof or a uniform
/// `403`. The self no-op short-circuit is applied ONLY for self — for a cross-user caller the
/// authorization runs first (constant-work), so a passwordless/keyless target is refused with `403`
/// (matrix #10) rather than leaking its state via a `200` no-op.
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
            if s.password_hash.is_none() {
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
        user.password_hash = None;
        user.attestation_key = None;
        user.secret_source = SecretSource::default();
        if consume_recovery {
            user.recovery_hash = None; // single-use.
        }
        user.clone()
    };

    match decision {
        SecretAuthz::CrossUser(kind) => {
            let justification = format!(
                "sign-in secret removed {} (attestation key cascaded)",
                kind.describe()
            );
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
        SecretAuthz::SelfService => {
            record_user_update(
                &state,
                &user,
                "sign-in secret removed (attestation key cascaded)",
                &actor,
                &attestor,
            )
            .await?;
        }
    }
    Ok(Json(UserView::from(&user)))
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
        user.attestation_key = None;
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
        // Self-service: prove the current password when the account has one (no-op if passwordless).
        let s = snapshot.as_ref().ok_or(ApiError::NotFound)?;
        verify_current(s, req.current_password.as_deref())?;
    }

    // Generate the phrase and its verifier OUTSIDE the write lock (argon2 discipline, t41 H2).
    let phrase = attestation::generate_recovery_phrase();
    let verifier = attestation::hash_secret(&phrase)?;

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
        user.clone()
    };

    record_user_update(&state, &user, "user updated", &actor, &attestor).await?;
    Ok(Json(UserView::from(&user)))
}
