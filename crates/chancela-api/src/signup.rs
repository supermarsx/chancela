//! Self-signup and invitations (t95 P1-A, plan §2.5 / §2.6 / §2.7).
//!
//! Three endpoints, all of them **evaluating policy from `state.settings` inside the handler**:
//!
//! | Route | Auth | What it does |
//! |---|---|---|
//! | `POST /v1/auth/signup` | none | A stranger creates their own account, on the single configured default role, at `Global` only. |
//! | `POST /v1/auth/invites` | `user.invite`\@scope | A permission holder issues a 7-day invitation addressed to one email, optionally carrying a role and a scope. |
//! | `POST /v1/auth/invite/accept` | none (the token *is* the credential) | The holder of a live invitation creates the invited account. |
//!
//! ## The bootstrap invariant (§2.7) — read this before editing anything here
//!
//! `POST /v1/users` is unauthenticated **only** on an instance with zero users, and that first user
//! is forced Owner\@Global ([`crate::users::create_user`], `bootstrap_state_for_insert`). Nothing in
//! this module may reach that path: [`refuse_on_an_uninitialised_instance`] refuses **every** route
//! here with `409` while the instance has no users, so the two are mutually exclusive by
//! construction — `create_user`'s unauthenticated path requires zero users, and signup requires at
//! least one. The first Owner is created through onboarding, never through signup, and no setting
//! (`signup.mode = public` included) can change that.
//!
//! ## Where the default-role ceiling is enforced
//!
//! Three sites, all sharing one predicate
//! ([`Role::signup_default_refusal`](chancela_authz::Role::signup_default_refusal)) so they cannot
//! drift apart:
//!
//! 1. **Settings validate** — `AuthSettings::validate_default_role_against`, from `put_settings`
//!    (t96 P0-1).
//! 2. **Role edit** — [`refuse_editing_the_signup_default_role`], called from
//!    [`crate::roles::patch_role`] and from the seeded-drift reconciliation apply. Without this the
//!    ceiling is *advisory*: configure Guest as the default (legal), then `PATCH` Guest to hold
//!    `settings.manage` and the configured default silently becomes a privileged role.
//! 3. **Grant time** — [`resolve_self_signup_role`], here, on every signup. Belt and braces: a
//!    catalog loaded from disk was never validated by either of the other two sites.
//!
//! ## What is deliberately NOT here
//!
//! - **No mail is sent.** Every email template in this tranche belongs to P1-D. An invitation's URL
//!   is therefore returned **once** to the authorized inviter (the `RecoveryIssued` precedent) for
//!   them to deliver, and self-signup — whose only honest reply is uniform (see below) — has no
//!   channel back to the applicant at all until P1-D lands. Both are noted in the task log.
//! - **No email-verification flow.** `auth.signup.require_email_verification` defaults to `true` and
//!   proving control of an address requires sending mail to it. So signup **refuses with `409` while
//!   that flag is set**, naming the reason, rather than quietly creating accounts whose address was
//!   never checked. Fail-closed: the operator must turn the flag off on purpose.
//! - **No persistence for tokens.** [`crate::auth_token::AuthTokenStore`] serializes, but wiring it
//!   into `sidecar_store` is not this task's file. Invitations therefore live in memory and a restart
//!   invalidates them, exactly as sessions and pairing codes already do. That fails closed.

use std::collections::BTreeMap;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use chancela_authz::{Permission, Role, RoleAssignment, RoleId, Scope};

use crate::AppState;
use crate::actor::{CurrentActor, CurrentAttestor};
use crate::attestation::{self, AttestationKeyBlob, MAX_SECRET_LEN, MIN_SECRET_LEN};
use crate::auth_token::{AuthTokenPurpose, AuthTokenSubject};
use crate::error::ApiError;
use crate::roles::RoleAssignmentInput;
use crate::session::ScopeView;
use crate::settings::SignupMode;
use crate::users::{SecretSource, User, UserId, UserLanguage, UserView};

/// The per-invitation detail that must **not** live on the token record.
///
/// [`crate::auth_token::AuthTokenRecord`] deliberately carries only id, purpose, subject and
/// lifetime — its doc comment asks callers to key their own detail by the record id rather than grow
/// the token store fields a later author might fill with something sensitive. This is that side
/// table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteGrant {
    /// The address the invitation was issued to, normalised. Redundant with the token's subject and
    /// kept anyway: the accept path compares the two, so a grant that ever disagreed with its token
    /// is refused rather than resolved in someone's favour.
    pub email: String,
    /// The single role the accepted account receives.
    pub role_id: RoleId,
    /// The scope that role is granted at. **An invitation may carry a scope; self-signup may not.**
    pub scope: Scope,
    /// Username of the inviter, for the audit trail.
    pub invited_by: String,
}

/// Live invitation detail, keyed by the token record's id.
pub type InviteGrants = BTreeMap<Uuid, InviteGrant>;

// --- Wire types ---------------------------------------------------------------------------------

/// Body of `POST /v1/auth/signup`.
///
/// **There is no `username` field, and that is a security decision, not an omission.** A
/// caller-chosen username makes signup answer "that name is taken" differently from "that name is
/// free", which is an account-existence oracle on an unauthenticated endpoint. The username is
/// derived from the address instead ([`derive_username_base`]), and collisions are resolved
/// server-side with a numeric suffix that the response never reveals.
#[derive(Deserialize)]
pub struct SignupRequest {
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub language: UserLanguage,
}

/// The **one** reply `POST /v1/auth/signup` ever produces on the non-refusal path — byte-identical
/// whether an account was created, or the address already had one and nothing was.
#[derive(Serialize)]
pub struct SignupAccepted {
    pub status: &'static str,
}

impl SignupAccepted {
    fn new() -> Self {
        SignupAccepted { status: "accepted" }
    }
}

/// Body of `POST /v1/auth/invites`.
#[derive(Deserialize)]
pub struct IssueInvite {
    pub email: String,
    /// The `(role, scope)` to grant on acceptance. Omitted ⇒ the configured
    /// `auth.signup.default_role` at `Global`. A named role additionally requires `role.assign` at
    /// the scope **and** the subset invariant, exactly as [`crate::roles::assign_role`] does — an
    /// inviter can never hand out authority it does not itself hold.
    #[serde(default)]
    pub role: Option<RoleAssignmentInput>,
}

/// Response of `POST /v1/auth/invites`: the invitation URL, returned **exactly once**.
///
/// The server keeps only the token's SHA-256 verifier, so this string is unrecoverable afterwards —
/// the [`crate::users::RecoveryIssued`] pattern. Until P1-D can mail it, the inviter is the delivery
/// channel; they already hold `user.invite`, and the value travels back over the same authenticated
/// connection that asked for it.
#[derive(Serialize)]
pub struct InviteIssued {
    pub invite_id: String,
    pub email: String,
    pub role_id: String,
    pub scope: ScopeView,
    pub expires_at: String,
    /// `{public_base_url}/invite?token={token}` — built **only** from the configured
    /// `platform.public_base_url`. Never from the `Host` header; see the module note and t96 P0-3.
    pub accept_url: String,
}

/// Body of `POST /v1/auth/invite/accept`.
#[derive(Deserialize)]
pub struct AcceptInvite {
    pub token: String,
    pub password: String,
    /// Optional confirmation of the address being claimed. When present it **must** equal the
    /// invitation's own subject; a mismatch is the uniform invalid-token refusal, so an invitation
    /// for one address can never be redeemed into an account for another.
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub language: UserLanguage,
}

// --- Refusals -----------------------------------------------------------------------------------

/// The uniform invalid-invitation refusal. Unknown, expired, spent, superseded, wrong-purpose,
/// cross-subject and detail-missing all produce **this** and nothing else, so a redeemer learns
/// nothing about which addresses have live invitations.
fn invalid_invite() -> ApiError {
    ApiError::Unprocessable("convite inválido ou expirado".to_owned())
}

/// §2.7. Every route in this module refuses while the instance has no users, so none of them can
/// ever stand in for the one unauthenticated `POST /v1/users` bootstrap that mints the first Owner.
async fn refuse_on_an_uninitialised_instance(state: &AppState) -> Result<(), ApiError> {
    if state.users.read().await.is_empty() {
        return Err(ApiError::Conflict(
            "esta instância ainda não tem qualquer conta: a primeira conta é criada na configuração \
             inicial, nunca por inscrição"
                .to_owned(),
        ));
    }
    Ok(())
}

/// A snapshot of everything this module reads out of the settings document, taken once under one
/// read lock **before any account state is touched** (§2.5).
struct SignupPolicy {
    mode: SignupMode,
    allowed_domains: Vec<String>,
    default_role: RoleId,
    require_email_verification: bool,
    invite_ttl: Duration,
    public_base_url: Option<String>,
}

async fn signup_policy(state: &AppState) -> SignupPolicy {
    let settings = state.settings.read().await;
    SignupPolicy {
        mode: settings.auth.signup.mode,
        allowed_domains: settings.auth.signup.normalized_domains(),
        default_role: settings.auth.signup.default_role,
        require_email_verification: settings.auth.signup.require_email_verification,
        invite_ttl: Duration::hours(i64::from(settings.auth.signup.invite_ttl_hours)),
        public_base_url: settings.platform.resolved_public_base_url(),
    }
}

impl SignupPolicy {
    /// Any self-service account creation at all, self-signup or invitation, is off while the mode is
    /// `disabled`. "Nobody" is the honest reading of the word, and it is the default.
    fn refuse_when_disabled(&self) -> Result<(), ApiError> {
        if matches!(self.mode, SignupMode::Disabled) {
            return Err(ApiError::Forbidden(
                "a criação de contas por inscrição está desativada nesta instância".to_owned(),
            ));
        }
        Ok(())
    }
}

// --- Email and username -------------------------------------------------------------------------

/// Normalise a **required** address. Reuses the shared validator so signup accepts exactly what the
/// rest of the product accepts, and rejects an absent or blank value rather than creating an account
/// with no address (the whole identity of a self-signed-up account is its address).
fn require_email(raw: &str, field: &'static str) -> Result<String, ApiError> {
    crate::email::normalize_optional_email(Some(raw.to_owned()), field)?.ok_or_else(|| {
        ApiError::Unprocessable(format!("{field} is required and must not be blank"))
    })
}

/// The domain of a normalised address (already lowercased by the validator).
fn domain_of(email: &str) -> &str {
    email.split('@').nth(1).unwrap_or_default()
}

/// The username stem derived from an address' local part.
///
/// Everything outside the `[a-z0-9._-]` alphabet `crate::users::validate_username` accepts becomes
/// `-`, the result is trimmed of separators and bounded, and an empty stem falls back to a constant.
/// The output is a valid username **by construction** — pinned by
/// [`tests::a_derived_username_is_always_a_valid_username`].
fn derive_username_base(email: &str) -> String {
    let local = email.split('@').next().unwrap_or_default();
    let mapped: String = local
        .chars()
        .map(|c| {
            let c = c.to_ascii_lowercase();
            if c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '-'
            }
        })
        .collect();
    let trimmed = mapped.trim_matches(|c| matches!(c, '.' | '_' | '-'));
    // 56 leaves room for the collision suffix inside the 64-character limit.
    let bounded: String = trimmed.chars().take(56).collect();
    if bounded.is_empty() {
        "user".to_owned()
    } else {
        bounded
    }
}

/// The first free username for `base`, matched case-insensitively exactly as `create_user`'s
/// conflict check does. Called under the users write lock.
fn allocate_username(
    users: &std::collections::HashMap<UserId, User>,
    base: &str,
) -> Result<String, ApiError> {
    let taken = |candidate: &str| {
        users
            .values()
            .any(|u| u.username.eq_ignore_ascii_case(candidate))
    };
    if !taken(base) {
        return Ok(base.to_owned());
    }
    for n in 2..=9999u32 {
        let candidate = format!("{base}{n}");
        if !taken(&candidate) {
            return Ok(candidate);
        }
    }
    // Unreachable in practice; a 500 rather than a silent collision.
    Err(ApiError::Conflict(
        "não foi possível atribuir um nome de utilizador".to_owned(),
    ))
}

/// Whether any existing account already claims this address (case-insensitive; stored addresses are
/// normalised lowercase, and this stays tolerant of a legacy record that is not).
fn address_is_claimed(users: &std::collections::HashMap<UserId, User>, email: &str) -> bool {
    users.values().any(|u| {
        u.email
            .as_deref()
            .is_some_and(|e| e.eq_ignore_ascii_case(email))
    })
}

// --- The default-role ceiling ---------------------------------------------------------------------

/// Ceiling site 3 — **grant time**. Resolve the configured self-signup default role and refuse if it
/// is not, at this instant, a role a stranger may be handed.
///
/// Settings-validate already checked this, and so does role-edit. Checking again costs one map
/// lookup and covers the case neither of the others can: a `roles.json` edited on disk, or restored
/// from a backup taken before the ceiling existed.
async fn resolve_self_signup_role(state: &AppState, id: RoleId) -> Result<Role, ApiError> {
    let role = state.roles.read().await.get(id).cloned().ok_or_else(|| {
        ApiError::Conflict(format!(
            "auth.signup.default_role {id} does not name a role in the catalog; self-signup \
                 cannot grant a role that does not exist"
        ))
    })?;
    if let Some(refusal) = role.signup_default_refusal() {
        return Err(ApiError::Conflict(format!(
            "auth.signup.default_role {:?} cannot be granted by self-signup because {refusal}",
            role.name
        )));
    }
    Ok(role)
}

/// Ceiling site 2 — **role edit**. Refuse an edit that would leave the *configured self-signup
/// default role* holding authority a stranger may not be handed.
///
/// This is the call the t96 P0 log flagged as missing and load-bearing. Without it the ceiling is
/// advisory: choose Guest as the signup default (legal at settings-validate time), then `PATCH`
/// Guest to hold `settings.manage`. Nothing re-validates the settings document on a role edit, so
/// the configured default silently becomes a privileged role and the next stranger to sign up gets
/// it.
///
/// Refusing the **edit** rather than the later signup is the right end to refuse at: the operator
/// asking for the change is present to read the message, whereas a signup refusal would surface
/// months later to someone who cannot act on it. The escape hatch is explicit and visible — point
/// `auth.signup.default_role` at a different role first, then edit this one.
///
/// `resulting` is the role **as it would be after the edit**, so the check runs against the outcome
/// and not the input.
pub(crate) async fn refuse_editing_the_signup_default_role(
    state: &AppState,
    resulting: &Role,
) -> Result<(), ApiError> {
    let configured = configured_signup_default_role(state).await;
    refuse_signup_default_role_edit(configured, resulting)
}

/// The configured `auth.signup.default_role`, read on its own so a caller that already holds the
/// roles write lock can take it **before** acquiring that lock rather than nesting the two.
pub(crate) async fn configured_signup_default_role(state: &AppState) -> RoleId {
    state.settings.read().await.auth.signup.default_role
}

/// The lock-free half of [`refuse_editing_the_signup_default_role`].
pub(crate) fn refuse_signup_default_role_edit(
    configured: RoleId,
    resulting: &Role,
) -> Result<(), ApiError> {
    if resulting.id != configured {
        return Ok(());
    }
    if let Some(refusal) = resulting.signup_default_refusal() {
        return Err(ApiError::Unprocessable(format!(
            "{:?} is the configured auth.signup.default_role, so this edit would hand every \
             self-signed-up account authority it must never have: {refusal}. Point \
             auth.signup.default_role at another role first, then edit this one",
            resulting.name
        )));
    }
    Ok(())
}

// --- Account creation ---------------------------------------------------------------------------

/// Everything the two creation paths share, minus policy. Runs the two argon2 costs **outside** the
/// users write lock (t41 H2) and before it, so a crypto fault leaves no account behind.
struct NewAccount {
    email: String,
    display_name: Option<String>,
    language: UserLanguage,
    password_hash: String,
    attestation_key: AttestationKeyBlob,
}

/// Validate the secret to the same bounds `create_user` applies, then spend the two argon2 costs.
///
/// **This is the constant-work anchor for the anti-enumeration property of signup** (§2.1): it runs
/// identically whether or not the address turns out to be claimed, and it dominates the request by
/// two orders of magnitude, so the branch taken afterwards is not visible in the response time.
fn prepare_account(
    state_seed: &crate::attestation::VerifierSeed,
    email: String,
    username_for_policy: &str,
    password: &str,
    display_name: Option<String>,
    language: UserLanguage,
) -> Result<NewAccount, ApiError> {
    let len = password.chars().count();
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
    crate::password_policy::enforce(
        password,
        username_for_policy,
        crate::password_policy::ALLOW_WEAK_PASSWORDS,
    )?;
    let password_hash = attestation::hash_secret_with_seed(password, state_seed)?;
    let attestation_key = AttestationKeyBlob::generate(password)?;
    Ok(NewAccount {
        email,
        display_name,
        language,
        password_hash,
        attestation_key,
    })
}

impl NewAccount {
    fn into_user(self, id: UserId, username: String, assignment: RoleAssignment) -> User {
        let display_name = self
            .display_name
            .map(|d| d.trim().to_owned())
            .filter(|d| !d.is_empty())
            .unwrap_or_else(|| username.clone());
        User {
            id,
            username,
            display_name,
            email: Some(self.email),
            created_at: OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .unwrap_or_default(),
            active: true,
            password_hash: Some(self.password_hash),
            attestation_key: Some(self.attestation_key),
            retired_attestation_keys: Vec::new(),
            totp: None,
            two_factor_required: false,
            force_password_change: false,
            secret_source: SecretSource::default(),
            recovery_hash: None,
            // Exactly one assignment. Self-signup pins it to `Global`; an invitation supplies its own
            // scope, which is the only way a new account lands inside a tenant.
            role_assignments: vec![assignment],
            language: self.language,
        }
    }
}

/// Append a `user.created` event for an account this module created.
///
/// Deliberately the **same kind** `create_user` uses, with the justification carrying the provenance:
/// every account creation stays one event kind, so nothing downstream that watches for new accounts
/// can miss the ones that arrived by signup. The payload is a [`UserView`], never a [`User`] — the
/// discipline every user handler follows — and it contains **no token material**. `justification` is
/// stored verbatim (t88), so it is a fixed string with nothing sensitive in it.
async fn record_account_created(
    state: &AppState,
    user: &User,
    actor: &str,
    justification: &str,
    attestor: &CurrentAttestor,
) -> Result<(), ApiError> {
    let payload = serde_json::to_vec(&UserView::from(user))?;
    let mut ledger = state.ledger.write().await;
    ledger.append(actor, "user", "user.created", Some(justification), &payload);
    state
        .persist_write_through(&mut ledger, 1, |_tx| Ok(()))
        .await?;
    state.attest_latest(attestor, &ledger).await;
    Ok(())
}

// --- POST /v1/auth/signup -------------------------------------------------------------------------

/// `POST /v1/auth/signup` — a stranger creates their own account. **Unauthenticated.**
///
/// Order of business, and every step of it server-side (§2.5 — the UI hiding the form is a
/// convenience only):
///
/// 1. **§2.7 bootstrap invariant** — refuse on an instance with zero users, before anything else and
///    regardless of mode.
/// 2. `signup.mode` — `disabled` refuses; `invite_only` refuses (there is an invitation endpoint for
///    that); `domain_allowlist` and `public` continue.
/// 3. `require_email_verification` — refuses while set, because no verification channel exists yet.
/// 4. The address is normalised, and in `domain_allowlist` mode its domain must be a **byte match**
///    against the stored-normalised list.
/// 5. **§2.6 ceiling at grant time** — the configured default role is resolved and re-checked.
/// 6. The account is created on that role at **`Global` only**.
///
/// ## Why the reply is always the same
///
/// A stranger must not be able to use this endpoint to ask "does this address have an account
/// here?". So the address-already-claimed case and the account-created case return the **identical**
/// `202` and the identical body, and the expensive work ([`prepare_account`]) runs before the branch
/// so the two are not distinguishable by timing either. The cost of that honesty is real and is
/// stated in the module note: with no mail sender in P1, an applicant whose address was already
/// taken is told nothing at all. §2.1 anticipates exactly this and puts the answer in the mail P1-D
/// will send, never in the HTTP response.
pub async fn signup(
    State(state): State<AppState>,
    attestor: CurrentAttestor,
    Json(req): Json<SignupRequest>,
) -> Result<(StatusCode, Json<SignupAccepted>), ApiError> {
    refuse_on_an_uninitialised_instance(&state).await?;

    let policy = signup_policy(&state).await;
    policy.refuse_when_disabled()?;
    if matches!(policy.mode, SignupMode::InviteOnly) {
        return Err(ApiError::Forbidden(
            "esta instância só aceita novas contas por convite".to_owned(),
        ));
    }
    if policy.require_email_verification {
        return Err(ApiError::Conflict(
            "auth.signup.require_email_verification está ativo e a verificação do endereço por \
             e-mail ainda não está disponível; desative-a explicitamente para permitir inscrições"
                .to_owned(),
        ));
    }

    let email = require_email(&req.email, "email")?;
    if matches!(policy.mode, SignupMode::DomainAllowlist) {
        let domain = domain_of(&email).to_owned();
        if !policy.allowed_domains.iter().any(|d| d == &domain) {
            return Err(ApiError::Forbidden(format!(
                "o domínio {domain:?} não consta da lista de domínios autorizados para inscrição"
            )));
        }
    }

    // §2.6 ceiling, third site. Before any account state is touched.
    let role = resolve_self_signup_role(&state, policy.default_role).await?;

    let base = derive_username_base(&email);
    let seed = state.verifier_seed.read().await.clone();
    // The constant-work anchor. Runs on both branches below.
    let account = prepare_account(
        &seed,
        email.clone(),
        &base,
        &req.password,
        req.display_name,
        req.language,
    )?;

    let created = {
        let mut users = state.users.write().await;
        // Re-check §2.7 under the write lock: a request that read "one user exists" must not be able
        // to insert into a map another request has since emptied.
        if users.is_empty() {
            return Err(ApiError::Conflict(
                "esta instância ainda não tem qualquer conta".to_owned(),
            ));
        }
        if address_is_claimed(&users, &email) {
            None
        } else {
            let username = allocate_username(&users, &base)?;
            let user = account.into_user(
                UserId(Uuid::new_v4()),
                username,
                RoleAssignment::new(role.id, Scope::Global),
            );
            users.insert(user.id, user.clone());
            Some(user)
        }
    };

    // Persist on **both** branches: the claimed-address branch writes the user directory unchanged,
    // so the two paths spend comparable I/O and the shape of the work does not betray the outcome.
    // The remaining difference is one ledger append, which is small beside the two argon2 costs
    // above; it is called out in the task log rather than papered over.
    crate::sidecar_store::persist_users(&state).await?;

    if let Some(user) = created {
        record_account_created(
            &state,
            &user,
            &user.username,
            "account created by self-signup",
            &attestor,
        )
        .await?;
    } else {
        // Not a ledger event: an unauthenticated endpoint that appends on demand is a chain-flooding
        // surface, and the ledger must not become the enumeration oracle the response refuses to be.
        // A warn line is server-side only and carries no address.
        tracing::warn!("a signup was refused because the address already has an account");
    }

    Ok((StatusCode::ACCEPTED, Json(SignupAccepted::new())))
}

// --- POST /v1/auth/invites ------------------------------------------------------------------------

/// `POST /v1/auth/invites` — issue an invitation. Requires **`user.invite` at the invitation's
/// scope**.
///
/// The authority rules, in order:
///
/// - `user.invite`\@scope. Distinct from `user.manage` on purpose (t96 P0-4): a Corporate Secretary
///   may invite without being able to administer accounts.
/// - A **named** role additionally requires `role.assign`\@scope *and* the subset invariant
///   (`can_assign_role`), the same pair [`crate::roles::assign_role`] applies. An inviter can never
///   hand out authority it does not itself hold at that scope.
/// - **No named role** ⇒ the configured `auth.signup.default_role` at `Global`, ceiling-checked. This
///   is the path a holder of only `user.invite` can use, and it can only ever produce the same role
///   a stranger would get by signing up.
///
/// `platform.public_base_url` must be configured, because an invitation is only useful as a link and
/// that link's origin is **never** derived from the request's `Host` header — that is host-header
/// injection, and on an endpoint that mails a live credential it means the victim receives a genuine
/// message pointing at the attacker (t96 P0-3). There is no request-derived accessor and there must
/// never be one.
pub async fn issue_invite(
    State(state): State<AppState>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<IssueInvite>,
) -> Result<(StatusCode, Json<InviteIssued>), ApiError> {
    refuse_on_an_uninitialised_instance(&state).await?;

    let policy = signup_policy(&state).await;
    policy.refuse_when_disabled()?;
    let Some(base_url) = policy.public_base_url.clone() else {
        return Err(ApiError::Conflict(
            "platform.public_base_url tem de estar configurado antes de emitir convites: a ligação \
             do convite nunca é derivada do cabeçalho Host"
                .to_owned(),
        ));
    };

    let scope: Scope = req
        .role
        .as_ref()
        .map_or(Scope::Global, |input| input.scope.into());

    let authz = crate::authz::authorizer(&state, &actor).await?;
    authz.require(Permission::UserInvite, scope)?;

    let role = match &req.role {
        Some(input) => {
            authz.require(Permission::RoleAssign, scope)?;
            let role = state
                .roles
                .read()
                .await
                .get(RoleId(input.role_id))
                .cloned()
                .ok_or(ApiError::NotFound)?;
            if !authz.can_assign_role(&role, scope) {
                return Err(crate::authz::forbidden());
            }
            role
        }
        // The default-role path is the one a `user.invite`-only holder has, so it must not be a way
        // around the ceiling either.
        None => resolve_self_signup_role(&state, policy.default_role).await?,
    };

    let email = require_email(&req.email, "email")?;
    let invited_by = actor.resolve("api");
    let now = OffsetDateTime::now_utc();

    // Issue and record the detail together, so a token can never exist without its grant. The token
    // store supersedes any earlier invitation for the same address by itself; the stale grant is
    // swept here.
    let (secret, record) = {
        let mut tokens = state.auth_tokens.write().await;
        let subject = AuthTokenSubject::email(&email);
        let live_before: Vec<Uuid> = tokens
            .live_for_subject(&subject, now)
            .iter()
            .map(|r| r.id)
            .collect();
        let issued = tokens.issue(AuthTokenPurpose::Invite, subject, policy.invite_ttl, now);
        let mut grants = state.invite_grants.write().await;
        for stale in live_before {
            grants.remove(&stale);
        }
        grants.insert(
            issued.1.id,
            InviteGrant {
                email: email.clone(),
                role_id: role.id,
                scope,
                invited_by: invited_by.clone(),
            },
        );
        issued
    };

    let accept_url = format!(
        "{}/invite?token={}",
        base_url.trim_end_matches('/'),
        secret.expose()
    );

    // The audit payload names who invited whom to what — and **no token material**. `justification`
    // is stored verbatim (t88), so it is a fixed string.
    let payload = serde_json::to_vec(&serde_json::json!({
        "invite_id": record.id.to_string(),
        "email": email,
        "role_id": role.id.0.to_string(),
        "scope": ScopeView::from(scope),
        "invited_by": invited_by,
        "expires_at": record.expires_at.format(&Rfc3339).unwrap_or_default(),
    }))?;
    {
        let mut ledger = state.ledger.write().await;
        ledger.append(
            &invited_by,
            "user",
            "user.invite.created",
            Some("account invitation issued"),
            &payload,
        );
        state
            .persist_write_through(&mut ledger, 1, |_tx| Ok(()))
            .await?;
        state.attest_latest(&attestor, &ledger).await;
    }

    Ok((
        StatusCode::CREATED,
        Json(InviteIssued {
            invite_id: record.id.to_string(),
            email,
            role_id: role.id.0.to_string(),
            scope: ScopeView::from(scope),
            expires_at: record.expires_at.format(&Rfc3339).unwrap_or_default(),
            accept_url,
        }),
    ))
}

// --- POST /v1/auth/invite/accept ------------------------------------------------------------------

/// `POST /v1/auth/invite/accept` — create the invited account. **Unauthenticated**: the token is the
/// credential.
///
/// The invitation, not the request, decides the address, the role and the scope. Redeeming is
/// single-use and atomic inside [`crate::auth_token::AuthTokenStore::redeem`] — the record is removed
/// *before* it is returned, so a replay, an expired token, a spent one, a recovery token presented
/// here, and an invitation for another address are all the same
/// [`invalid_invite`] refusal.
///
/// Unlike signup, a genuine `409` for "this address already has an account" is not an oracle here:
/// answering it requires holding a live invitation for that exact address, which is itself proof of
/// authorization. Telling the holder plainly is better than silence.
pub async fn accept_invite(
    State(state): State<AppState>,
    attestor: CurrentAttestor,
    Json(req): Json<AcceptInvite>,
) -> Result<(StatusCode, Json<UserView>), ApiError> {
    refuse_on_an_uninitialised_instance(&state).await?;

    let policy = signup_policy(&state).await;
    policy.refuse_when_disabled()?;

    let now = OffsetDateTime::now_utc();
    // Redeem first: the token is spent whatever happens next, so a failure downstream can never
    // leave it replayable, and probing is never free.
    let (record, grant) = {
        let mut tokens = state.auth_tokens.write().await;
        let record = tokens
            .redeem(AuthTokenPurpose::Invite, &req.token, now)
            .map_err(|_| invalid_invite())?;
        let grant = state.invite_grants.write().await.remove(&record.id);
        (record, grant)
    };
    let grant = grant.ok_or_else(invalid_invite)?;

    // The token's own subject and the side table must agree, and the request may confirm but never
    // choose. A stranger cannot redeem an invitation addressed elsewhere into an account of theirs.
    if record.subject != AuthTokenSubject::email(&grant.email) {
        return Err(invalid_invite());
    }
    if let Some(claimed) = req.email.as_deref() {
        let claimed = require_email(claimed, "email")?;
        if claimed != grant.email {
            return Err(invalid_invite());
        }
    }

    // The ceiling does **not** apply to an invited role: an invitation is an authorized act by a
    // permission holder, already subset-checked against that holder's own authority at issue time.
    // The role must still exist — a role deleted between issue and accept grants nothing, and
    // silently creating an account with a dangling assignment would be worse than refusing.
    let role = state
        .roles
        .read()
        .await
        .get(grant.role_id)
        .cloned()
        .ok_or_else(|| {
            ApiError::Conflict(
                "a função associada a este convite já não existe; peça um novo convite".to_owned(),
            )
        })?;

    let base = derive_username_base(&grant.email);
    let seed = state.verifier_seed.read().await.clone();
    let account = prepare_account(
        &seed,
        grant.email.clone(),
        &base,
        &req.password,
        req.display_name,
        req.language,
    )?;

    let user = {
        let mut users = state.users.write().await;
        if users.is_empty() {
            return Err(ApiError::Conflict(
                "esta instância ainda não tem qualquer conta".to_owned(),
            ));
        }
        if address_is_claimed(&users, &grant.email) {
            return Err(ApiError::Conflict(
                "já existe uma conta para este endereço".to_owned(),
            ));
        }
        let username = allocate_username(&users, &base)?;
        let user = account.into_user(
            UserId(Uuid::new_v4()),
            username,
            RoleAssignment::new(role.id, grant.scope),
        );
        users.insert(user.id, user.clone());
        user
    };

    crate::sidecar_store::persist_users(&state).await?;
    record_account_created(
        &state,
        &user,
        &user.username,
        "account created by accepting an invitation",
        &attestor,
    )
    .await?;

    Ok((StatusCode::CREATED, Json(UserView::from(&user))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_derived_username_is_always_a_valid_username() {
        // The alphabet `users::validate_username` accepts, restated here because that function is
        // private to its module: non-empty, ≤64, and `[a-z0-9._-]` only.
        for address in [
            "amelia.marques@example.pt",
            "Amelia_Marques+notes@Example.PT",
            "  ana@example.pt ",
            "ünïcödé@example.pt",
            "-.-@example.pt",
            "@example.pt",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@example.pt",
        ] {
            let base = derive_username_base(address.trim());
            assert!(!base.is_empty(), "{address}");
            assert!(base.len() <= 56, "{address}: {base}");
            assert!(
                base.chars().all(|c| c.is_ascii_lowercase()
                    || c.is_ascii_digit()
                    || matches!(c, '.' | '_' | '-')),
                "{address}: {base}"
            );
            // And a collision suffix keeps it inside the 64-character limit.
            assert!(format!("{base}9999").len() <= 64, "{address}");
        }
        assert_eq!(
            derive_username_base("amelia.marques@example.pt"),
            "amelia.marques"
        );
        assert_eq!(derive_username_base("-.-@example.pt"), "user");
    }

    #[test]
    fn a_username_collision_is_resolved_with_a_suffix_and_never_reused() {
        let mut users = std::collections::HashMap::new();
        for name in ["amelia.marques", "AMELIA.MARQUES2"] {
            let id = UserId(Uuid::new_v4());
            users.insert(
                id,
                User {
                    id,
                    username: name.to_owned(),
                    display_name: name.to_owned(),
                    email: None,
                    created_at: String::new(),
                    active: true,
                    password_hash: None,
                    attestation_key: None,
                    retired_attestation_keys: Vec::new(),
                    totp: None,
                    two_factor_required: false,
                    force_password_change: false,
                    secret_source: SecretSource::default(),
                    recovery_hash: None,
                    role_assignments: Vec::new(),
                    language: UserLanguage::default(),
                },
            );
        }
        // Case-insensitive, exactly like `create_user`'s conflict check — otherwise signup could
        // mint `AMELIA.MARQUES2`'s twin and `create_session`, which also matches case-insensitively,
        // would have two candidates.
        assert_eq!(
            allocate_username(&users, "amelia.marques").expect("allocates"),
            "amelia.marques3"
        );
        assert_eq!(allocate_username(&users, "ana").expect("allocates"), "ana");
    }

    #[test]
    fn a_claimed_address_is_recognised_whatever_its_case() {
        let mut users = std::collections::HashMap::new();
        let id = UserId(Uuid::new_v4());
        users.insert(
            id,
            User {
                id,
                username: "amelia.marques".to_owned(),
                display_name: "Amélia Marques".to_owned(),
                email: Some("Amelia.Marques@Example.PT".to_owned()),
                created_at: String::new(),
                active: true,
                password_hash: None,
                attestation_key: None,
                retired_attestation_keys: Vec::new(),
                totp: None,
                two_factor_required: false,
                force_password_change: false,
                secret_source: SecretSource::default(),
                recovery_hash: None,
                role_assignments: Vec::new(),
                language: UserLanguage::default(),
            },
        );
        assert!(address_is_claimed(&users, "amelia.marques@example.pt"));
        assert!(!address_is_claimed(&users, "ana@example.pt"));
    }

    #[test]
    fn the_domain_of_a_normalised_address_is_its_suffix() {
        assert_eq!(domain_of("amelia.marques@example.pt"), "example.pt");
        assert_eq!(domain_of("nonsense"), "");
    }

    /// The allow-list comparison is a byte match against the stored-normalized list, so a
    /// look-alike domain cannot slip through on case or padding — and, more importantly, a
    /// *subdomain* never matches its parent. `evil.example.pt` is not `example.pt`.
    #[test]
    fn the_domain_allow_list_matches_exactly_and_never_by_suffix() {
        let allowed = ["example.pt".to_owned()];
        let permits = |email: &str| allowed.iter().any(|d| d == domain_of(email));
        assert!(permits("amelia.marques@example.pt"));
        assert!(!permits("amelia.marques@evil.example.pt"));
        assert!(!permits("amelia.marques@example.pt.evil.example"));
        assert!(!permits("amelia.marques@notexample.pt"));
    }
}
