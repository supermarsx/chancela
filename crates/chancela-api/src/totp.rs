//! TOTP second factor: enrolment, confirmation, backup codes (t95 §2.3, P1-C).
//!
//! ## The shape of the feature, and why each safeguard is here
//!
//! A user enrols their **own** authenticator. The server generates a 160-bit secret, hands back a
//! provisioning URI once, and **the factor does not activate until the user proves the authenticator
//! works by entering a current code** ([`confirm_totp`]). Activating an unconfirmed secret would lock
//! out anyone who scanned nothing — the single worst failure this flow can have, because there is no
//! admin reset to climb back out of it.
//!
//! | Concern | How it is met |
//! |---|---|
//! | Secret at rest | AEAD-encrypted in the credential store ([`CredentialMode::TwoFactorTotp`]), keyed by user id, **never** in `users.json`, never in any response after enrolment. |
//! | Algorithm | RFC 6238 defaults — HMAC-SHA1, 6 digits, 30 s step — for authenticator-app compatibility. |
//! | Replay | Verification accepts a **±1 step** window, and a per-user `last_accepted_step` means a code cannot be replayed inside its own window: once step *n* is accepted, no step ≤ *n* is ever accepted again. |
//! | Rate limit | Verification reuses the sign-in backoff keyed on the user, so a wrong code costs escalating delay; the pending sign-in is throttled, never the account (a wrong code must not let an attacker lock a victim out). Enforced at the sign-in call site (P2), stated here so the two do not disagree. |
//! | Backup codes | 10 single-use codes, argon2id verifiers (the `RecoveryIssued` pattern), shown **once**. The remaining count is exposed; the values never are. |
//! | Lost authenticator, no backup codes | The recovery phrase, or nothing. **No admin reset** — adding one would be the first admin-recoverable credential in a product that has deliberately refused one for keys and phrases. An admin may disable TOTP **instance-wide** (a visible, ledgered act), not per user. |
//!
//! ## What this module does NOT do
//!
//! It does not touch sign-in. Verifying a code as a second factor at sign-in — carrying the unlocked
//! attestation key through a pending challenge without a session existing — is the delicate P2 work
//! in `session.rs`, and it is the *only* place [`verify_code_against_secret`] is called besides
//! [`confirm_totp`] here. This module builds the enrolment mechanism and the verifier; the sign-in
//! integration consumes them.
//!
//! ## Why not the emailed second factor here
//!
//! `AuthTokenPurpose::TwoFactorEmailCode` is a **full-entropy emailed token**, not a six-digit PIN —
//! `auth_token.rs`'s documented non-use stands: a digest-keyed store has nothing to hang an attempt
//! counter on, so a short code there is a million-guess wall. The emailed factor rides the same
//! `auth_token` primitive the invite and recovery links do; it is not a TOTP and is not built here.

use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use sha1::Sha1;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Bytes of the TOTP shared secret: 160 bits, the RFC 6238 / RFC 4226 reference size and what
/// authenticator apps expect.
const SECRET_BYTES: usize = 20;

/// RFC 6238 time step. 30 s is the authenticator-app default.
pub const STEP_SECONDS: i64 = 30;

/// Digits in a code. 6 is the authenticator-app default.
const DIGITS: u32 = 6;

/// How many steps either side of the current one a code is accepted at. ±1 absorbs the clock skew
/// between the server and the user's phone without widening the guess surface meaningfully.
const WINDOW_STEPS: i64 = 1;

/// Number of backup codes minted per enrolment.
pub const BACKUP_CODE_COUNT: usize = 10;

type HmacSha1 = Hmac<Sha1>;

// --- Base32 (RFC 4648, no padding) --------------------------------------------------------------
//
// Authenticator apps provision from a base32 secret, so the secret is generated, stored and shown in
// base32. Implemented here rather than pulled as a dependency: it is a dozen lines, and a new
// workspace dependency in a shared tree is a coordination cost out of proportion to the code.

const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Encode bytes as unpadded RFC 4648 base32 (upper-case).
fn base32_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let index = ((buffer >> bits) & 0x1f) as usize;
            out.push(BASE32_ALPHABET[index] as char);
        }
    }
    if bits > 0 {
        let index = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(BASE32_ALPHABET[index] as char);
    }
    out
}

/// Decode an unpadded RFC 4648 base32 string (case-insensitive; spaces and `=` padding tolerated).
/// Returns `None` on any character outside the alphabet, so a corrupt stored secret fails closed
/// rather than verifying against garbage.
fn base32_decode(text: &str) -> Option<Vec<u8>> {
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity(text.len() * 5 / 8);
    for c in text.chars() {
        if c == '=' || c == ' ' {
            continue;
        }
        let up = c.to_ascii_uppercase();
        let value = BASE32_ALPHABET.iter().position(|&a| a as char == up)? as u32;
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

// --- Secret -------------------------------------------------------------------------------------

/// A freshly generated TOTP secret, base32-encoded. Held in a zeroizing wrapper so it does not
/// linger in memory; the only legitimate readers are the credential-store write and the provisioning
/// URI, both at enrolment time.
pub struct TotpSecret(String);

impl TotpSecret {
    /// Generate 160 bits of OS entropy and base32-encode it.
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0u8; SECRET_BYTES];
        OsRng.fill_bytes(&mut bytes);
        let encoded = base32_encode(&bytes);
        bytes.zeroize();
        TotpSecret(encoded)
    }

    /// The base32 characters, for the credential-store write and the provisioning URI only.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// The `otpauth://totp/...` provisioning URI an authenticator app scans. Shown exactly once, at
    /// enrolment. `issuer` and `account` are percent-encoded so a label containing a space or `:`
    /// cannot break the URI or smuggle a second parameter.
    #[must_use]
    pub fn provisioning_uri(&self, issuer: &str, account: &str) -> String {
        let issuer_enc = percent_encode(issuer);
        let account_enc = percent_encode(account);
        format!(
            "otpauth://totp/{issuer_enc}:{account_enc}?secret={}&issuer={issuer_enc}&algorithm=SHA1&digits={DIGITS}&period={STEP_SECONDS}",
            self.0
        )
    }
}

impl std::fmt::Debug for TotpSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TotpSecret(<redacted>)")
    }
}

impl Drop for TotpSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Minimal percent-encoding for the URI label components: everything outside the unreserved set is
/// `%XX`-escaped. Deliberately conservative — a broader "safe" set risks leaving a `:` or `?` that
/// changes the URI's meaning.
fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push_str(&format!("{byte:02X}"));
        }
    }
    out
}

// --- The verifier -------------------------------------------------------------------------------

/// The RFC 6238 code for a base32 `secret` at Unix time `unix_seconds`, offset by `step_offset`
/// steps. `None` if the secret is not decodable.
fn code_at(secret: &str, unix_seconds: i64, step_offset: i64) -> Option<u32> {
    let key = base32_decode(secret)?;
    let counter = (unix_seconds.div_euclid(STEP_SECONDS)) + step_offset;
    Some(hotp(&key, counter as u64))
}

/// RFC 4226 HOTP over an 8-byte big-endian counter, truncated to [`DIGITS`] digits.
fn hotp(key: &[u8], counter: u64) -> u32 {
    let mut mac = HmacSha1::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    // Dynamic truncation (RFC 4226 §5.3).
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let binary = (u32::from(digest[offset] & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    binary % 10u32.pow(DIGITS)
}

/// The current TOTP step number for a Unix instant. The per-user `last_accepted_step` is compared
/// against this, so a used step (and any earlier one) can never be replayed.
#[must_use]
pub fn current_step(unix_seconds: i64) -> i64 {
    unix_seconds.div_euclid(STEP_SECONDS)
}

/// The 6-digit code a base32 `secret` produces at `unix_seconds`, or `None` if the secret is not
/// decodable. This is a **generator**, the inverse of the verifier — exposed for tests (which must
/// produce a live code to present) and available for a future "show the current code" diagnostic. It
/// is never used by the sign-in path, which only ever *verifies*.
#[must_use]
pub fn code_for_secret(secret: &str, unix_seconds: i64) -> Option<String> {
    code_at(secret, unix_seconds, 0).map(|code| format!("{code:0width$}", width = DIGITS as usize))
}

/// The outcome of verifying a presented code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// Accepted. Carries the step it matched, which the caller must store as the new
    /// `last_accepted_step` so this code (and any earlier step) cannot be replayed.
    Accepted { step: i64 },
    /// The code did not match any step in the window, or matched a step at or before
    /// `last_accepted_step` (a replay).
    Rejected,
}

/// Verify a presented 6-digit `code` against a base32 `secret` at `unix_seconds`, within the ±1
/// window, refusing any step `<= last_accepted_step` as a replay.
///
/// Comparison of the derived code is **constant-time**: the code is a low-entropy secret for the
/// length of one step, and a byte-wise early return would leak how many leading digits were right.
///
/// `last_accepted_step` is `None` for a never-used enrolment (the confirm step), and `Some(step)`
/// afterward. On `Accepted`, the caller stores `step`.
#[must_use]
pub fn verify_code_against_secret(
    secret: &str,
    code: &str,
    unix_seconds: i64,
    last_accepted_step: Option<i64>,
) -> VerifyOutcome {
    let trimmed = code.trim();
    // Only exact-width all-ASCII-digit input is a candidate; reject early to avoid parsing surprises,
    // not for timing (a malformed code is not a secret).
    if trimmed.len() != DIGITS as usize || !trimmed.bytes().all(|b| b.is_ascii_digit()) {
        return VerifyOutcome::Rejected;
    }
    let presented: [u8; DIGITS as usize] = trimmed.as_bytes().try_into().expect("width checked");

    let mut matched: Option<i64> = None;
    for offset in -WINDOW_STEPS..=WINDOW_STEPS {
        let step = current_step(unix_seconds) + offset;
        if last_accepted_step.is_some_and(|last| step <= last) {
            continue; // replay guard: never accept a step we have already spent
        }
        let Some(expected) = code_at(secret, unix_seconds, offset) else {
            return VerifyOutcome::Rejected; // undecodable secret: fail closed
        };
        let expected_digits = format!("{expected:0width$}", width = DIGITS as usize);
        // Constant-time over the fixed 6-byte width; `matched` is set without an early break so the
        // loop's timing does not reveal which step (if any) matched.
        if presented.ct_eq(expected_digits.as_bytes()).into() {
            matched = Some(step);
        }
    }
    match matched {
        Some(step) => VerifyOutcome::Accepted { step },
        None => VerifyOutcome::Rejected,
    }
}

// --- Backup codes -------------------------------------------------------------------------------

/// A freshly minted backup code, shown once. Ten characters from an unambiguous alphabet (no `0`,
/// `O`, `1`, `I`, `L`), grouped for readability.
#[must_use]
pub fn generate_backup_code() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";
    let mut code = String::with_capacity(11);
    for i in 0..10 {
        if i == 5 {
            code.push('-');
        }
        let mut buf = [0u8; 1];
        OsRng.fill_bytes(&mut buf);
        code.push(ALPHABET[(buf[0] as usize) % ALPHABET.len()] as char);
    }
    code
}

// =================================================================================================
// Enrolment endpoints (self-service). None of these touch sign-in — that is P2 in `session.rs`.
// =================================================================================================

use axum::Json;
use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::AppState;
use crate::actor::{CurrentActor, CurrentAttestor};
use crate::error::ApiError;
use crate::secretstore_persist::{CredentialFieldSet, FIELD_TOTP_SECRET, TotpCredentialFields};
use crate::users::{TotpEnrolment, User, UserId, UserView};
use crate::CredentialMode;

/// The one entry id per user's single TOTP record.
const TOTP_ENTRY_ID: &str = "default";

/// Response of `POST …/two-factor/totp/enrol`: the provisioning material, returned **exactly once**.
/// The factor is not active yet — it must be confirmed with a live code.
#[derive(Serialize)]
pub struct TotpEnrolmentStarted {
    /// The base32 secret, shown once for manual entry into an authenticator that cannot scan.
    pub secret: String,
    /// The `otpauth://` URI an authenticator app scans (contains the same secret).
    pub provisioning_uri: String,
    /// Always `false` here: enrolment is pending until [`confirm_totp`] succeeds.
    pub confirmed: bool,
}

/// Body of `POST …/two-factor/totp/confirm` and the sign-in verify (P2): a 6-digit code.
#[derive(Deserialize)]
pub struct TotpCode {
    pub code: String,
}

/// Response after confirming, or regenerating backup codes: the backup codes, shown **once**.
#[derive(Serialize)]
pub struct BackupCodesIssued {
    /// The plaintext backup codes, shown now and never retrievable again (only their argon2
    /// verifiers are stored).
    pub backup_codes: Vec<String>,
    /// How many remain unspent (equal to the length of `backup_codes` right after issuance).
    pub backup_codes_remaining: usize,
}

/// Read view of a user's TOTP state (`GET …/two-factor`). Carries no secret — it is the richer
/// sibling of the `has_totp` boolean on [`UserView`].
#[derive(Serialize)]
pub struct TwoFactorStatus {
    /// Whether an enrolment record exists at all (pending or confirmed).
    pub enrolled: bool,
    /// Whether the enrolment is confirmed and therefore an active factor.
    pub confirmed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirmed_at: Option<String>,
    /// Unspent backup codes. `null` unless the caller is looking at their own account.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup_codes_remaining: Option<usize>,
    /// Whether this account is required to hold a second factor.
    pub required: bool,
}

/// Resolve the requesting user's id (from the session username) and clone the target snapshot under
/// one users read lock. The requester is `None` for an API key or a session that resolves to no user.
async fn resolve_requester_and_target(
    state: &AppState,
    actor: &CurrentActor,
    target: UserId,
) -> (Option<UserId>, Option<User>) {
    let users = state.users.read().await;
    let requester = actor
        .session_username()
        .and_then(|name| users.values().find(|u| u.username == name).map(|u| u.id));
    (requester, users.get(&target).cloned())
}

/// **Self-only gate.** Enrolling, confirming, disabling or regenerating a second factor is
/// meaningful only for one's own account — the secret has to reach *your* authenticator. An API key
/// never opens an interactive session and can never enrol. Returns the target snapshot on success.
///
/// This is deliberately not `user.manage`: an admin cannot enrol a factor for someone else (there is
/// no channel to that person's phone), and per the plan there is **no admin reset** of another
/// user's TOTP — instance-wide disable, ledgered, or nothing.
async fn require_self(
    state: &AppState,
    actor: &CurrentActor,
    target: UserId,
) -> Result<User, ApiError> {
    if actor.is_api_key() {
        return Err(ApiError::Forbidden(
            "chave API não abre uma sessão interativa".to_owned(),
        ));
    }
    let (requester, snapshot) = resolve_requester_and_target(state, actor, target).await;
    match (requester, snapshot) {
        (Some(req), Some(user)) if req == target => Ok(user),
        // Uniform refusal whether the target exists or not, and whether the caller is a different
        // real user or an unresolved session: a second factor is a self-service surface, and telling
        // a caller "that user exists but isn't you" is an enumeration nicety with no upside.
        _ => Err(ApiError::Forbidden(
            "só o próprio titular da conta pode gerir o seu segundo fator".to_owned(),
        )),
    }
}

/// Blocking offload: write or clear this user's TOTP secret in the credential store.
async fn write_totp_secret(
    state: &AppState,
    user_id: UserId,
    secret: Option<Zeroizing<String>>,
    clear: &'static [&'static str],
) -> Result<(), ApiError> {
    let set = TotpCredentialFields { secret }.into_set_pairs();
    let provider = user_id.to_string();
    let credentials = state.provider_credentials.clone();
    tokio::task::spawn_blocking(move || {
        credentials.put_entry(
            CredentialMode::TwoFactorTotp,
            &provider,
            TOTP_ENTRY_ID,
            None,
            set,
            clear,
        )
    })
    .await
    .map_err(|e| std::panic::resume_unwind(e.into_panic()))
    .and_then(|r| r)
    .map_err(|e| crate::provider_credentials_write::map_store_err_for("the TOTP secret", e))
}

/// Blocking offload: read this user's decrypted TOTP secret, or `None` when there is none.
async fn read_totp_secret(
    state: &AppState,
    user_id: UserId,
) -> Result<Option<Zeroizing<String>>, ApiError> {
    let provider = user_id.to_string();
    let credentials = state.provider_credentials.clone();
    let record = tokio::task::spawn_blocking(move || {
        credentials.read_runtime(CredentialMode::TwoFactorTotp, &provider)
    })
    .await
    .map_err(|e| std::panic::resume_unwind(e.into_panic()))
    .and_then(|r| r)
    .map_err(|e| crate::provider_credentials_write::map_store_err_for("the TOTP secret", e))?;
    Ok(record.and_then(|record| {
        record
            .fields
            .get(FIELD_TOTP_SECRET)
            .map(|value| Zeroizing::new(value.to_string()))
    }))
}

/// Clear the enrolment record on the user, drop the stored secret, and persist. Shared by disable
/// and by the "abandon a pending enrolment then start again" path.
async fn clear_enrolment(state: &AppState, user_id: UserId) -> Result<(), ApiError> {
    {
        let mut users = state.users.write().await;
        if let Some(user) = users.get_mut(&user_id) {
            user.totp = None;
        }
    }
    write_totp_secret(state, user_id, None, &[FIELD_TOTP_SECRET]).await?;
    crate::sidecar_store::persist_users(state).await
}

async fn record_totp_event(
    state: &AppState,
    user: &User,
    kind: &str,
    justification: &str,
    actor: &CurrentActor,
    attestor: &CurrentAttestor,
) -> Result<(), ApiError> {
    // Payload is the UserView (no secret material, ever) — the same discipline every user event
    // follows. The justification is a fixed string; nothing sensitive goes there (t88 stores it
    // verbatim).
    let payload = serde_json::to_vec(&UserView::from(user))?;
    let actor_name = actor.resolve("api");
    let mut ledger = state.ledger.write().await;
    ledger.append(&actor_name, "user", kind, Some(justification), &payload);
    state
        .persist_write_through(&mut ledger, 1, |_tx| Ok(()))
        .await?;
    state.attest_latest(attestor, &ledger).await;
    Ok(())
}

/// `POST /v1/users/{id}/two-factor/totp/enrol` — begin TOTP enrolment (self-only).
///
/// Generates a fresh secret, stores it (pending) and returns the provisioning material **once**. The
/// factor is inert until [`confirm_totp`]. Re-enrolling while a *pending* enrolment exists replaces
/// it (the user rescanned); re-enrolling while a *confirmed* one exists is refused — disable first,
/// so a working factor is never silently swapped out from under an authenticator.
pub async fn enrol_totp(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    actor: CurrentActor,
) -> Result<(StatusCode, Json<TotpEnrolmentStarted>), ApiError> {
    let target = UserId(id);
    let user = require_self(&state, &actor, target).await?;
    if user.totp.as_ref().is_some_and(TotpEnrolment::is_active) {
        return Err(ApiError::Conflict(
            "já existe um segundo fator ativo; desative-o antes de configurar outro".to_owned(),
        ));
    }

    let secret = TotpSecret::generate();
    // Store the pending secret first: if the credential store cannot persist (no key, in-memory),
    // fail before touching the user, so an enrolment record never outlives its secret.
    write_totp_secret(
        &state,
        target,
        Some(Zeroizing::new(secret.expose().to_owned())),
        &[],
    )
    .await?;

    let issuer = {
        let settings = state.settings.read().await;
        settings
            .organization
            .name
            .as_deref()
            .map(str::trim)
            .filter(|n| !n.is_empty())
            .unwrap_or(crate::email_template::PRODUCT_NAME)
            .to_owned()
    };
    let provisioning_uri = secret.provisioning_uri(&issuer, &user.username);

    {
        let mut users = state.users.write().await;
        let user = users.get_mut(&target).ok_or(ApiError::NotFound)?;
        user.totp = Some(TotpEnrolment::pending());
    }
    crate::sidecar_store::persist_users(&state).await?;

    // No ledger event for a pending enrolment: it grants nothing and is superseded by confirm. The
    // auditable transition is activation.
    Ok((
        StatusCode::CREATED,
        Json(TotpEnrolmentStarted {
            secret: secret.expose().to_owned(),
            provisioning_uri,
            confirmed: false,
        }),
    ))
}

/// `POST /v1/users/{id}/two-factor/totp/confirm` — activate the factor by proving a live code
/// (self-only). On success the enrolment becomes confirmed, backup codes are minted and returned
/// **once**, and the activation is ledgered.
pub async fn confirm_totp(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<TotpCode>,
) -> Result<Json<BackupCodesIssued>, ApiError> {
    let target = UserId(id);
    let user = require_self(&state, &actor, target).await?;
    let Some(enrolment) = user.totp.clone() else {
        return Err(ApiError::Conflict(
            "não há uma configuração de segundo fator pendente; comece por gerar um segredo"
                .to_owned(),
        ));
    };
    if enrolment.confirmed {
        return Err(ApiError::Conflict(
            "o segundo fator já está ativo".to_owned(),
        ));
    }

    let Some(secret) = read_totp_secret(&state, target).await? else {
        // The enrolment record exists but the secret does not — a torn state. Clear it so the user
        // can start over rather than being stuck confirming a secret that is gone.
        clear_enrolment(&state, target).await?;
        return Err(ApiError::Conflict(
            "a configuração de segundo fator estava incompleta; recomece a inscrição".to_owned(),
        ));
    };

    let now = OffsetDateTime::now_utc();
    match verify_code_against_secret(&secret, &req.code, now.unix_timestamp(), None) {
        VerifyOutcome::Accepted { step } => {
            let (plaintext, hashes) = mint_backup_codes()?;
            let user = {
                let mut users = state.users.write().await;
                let user = users.get_mut(&target).ok_or(ApiError::NotFound)?;
                user.totp = Some(TotpEnrolment {
                    confirmed: true,
                    confirmed_at: Some(now.format(&Rfc3339).unwrap_or_default()),
                    last_accepted_step: Some(step),
                    backup_code_hashes: hashes,
                });
                user.clone()
            };
            crate::sidecar_store::persist_users(&state).await?;
            record_totp_event(
                &state,
                &user,
                "user.totp.enrolled",
                "second factor (TOTP) confirmed and activated",
                &actor,
                &attestor,
            )
            .await?;
            let remaining = plaintext.len();
            Ok(Json(BackupCodesIssued {
                backup_codes: plaintext,
                backup_codes_remaining: remaining,
            }))
        }
        VerifyOutcome::Rejected => Err(ApiError::Unauthorized(
            "código inválido — verifique o relógio do dispositivo e tente novamente".to_owned(),
        )),
    }
}

/// `DELETE /v1/users/{id}/two-factor/totp` — disable the factor (self-only).
///
/// Refused while the account carries `two_factor_required`: a user cannot opt out of a requirement
/// an administrator set. Everything else — clearing a pending enrolment, disabling a confirmed one —
/// is allowed, drops the stored secret, and (for a confirmed factor) is ledgered.
pub async fn disable_totp(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
) -> Result<Json<UserView>, ApiError> {
    let target = UserId(id);
    let user = require_self(&state, &actor, target).await?;
    if user.two_factor_required {
        return Err(ApiError::Conflict(
            "esta conta é obrigada a manter um segundo fator; não pode ser desativado".to_owned(),
        ));
    }
    let was_active = user.totp.as_ref().is_some_and(TotpEnrolment::is_active);
    clear_enrolment(&state, target).await?;
    let user = state
        .users
        .read()
        .await
        .get(&target)
        .cloned()
        .ok_or(ApiError::NotFound)?;
    if was_active {
        record_totp_event(
            &state,
            &user,
            "user.totp.disabled",
            "second factor (TOTP) disabled",
            &actor,
            &attestor,
        )
        .await?;
    }
    Ok(Json(UserView::from(&user)))
}

/// `POST /v1/users/{id}/two-factor/backup-codes` — regenerate backup codes (self-only).
///
/// Requires a **confirmed** factor. Every previous code is invalidated (they are replaced wholesale),
/// and the new set is returned **once**.
pub async fn regenerate_backup_codes(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
) -> Result<Json<BackupCodesIssued>, ApiError> {
    let target = UserId(id);
    let user = require_self(&state, &actor, target).await?;
    if !user.totp.as_ref().is_some_and(TotpEnrolment::is_active) {
        return Err(ApiError::Conflict(
            "não há um segundo fator ativo para o qual gerar códigos de recuperação".to_owned(),
        ));
    }

    let (plaintext, hashes) = mint_backup_codes()?;
    let user = {
        let mut users = state.users.write().await;
        let user = users.get_mut(&target).ok_or(ApiError::NotFound)?;
        if let Some(enrolment) = user.totp.as_mut() {
            enrolment.backup_code_hashes = hashes;
        }
        user.clone()
    };
    crate::sidecar_store::persist_users(&state).await?;
    record_totp_event(
        &state,
        &user,
        "user.totp.backup_codes_regenerated",
        "TOTP backup codes regenerated",
        &actor,
        &attestor,
    )
    .await?;
    let remaining = plaintext.len();
    Ok(Json(BackupCodesIssued {
        backup_codes: plaintext,
        backup_codes_remaining: remaining,
    }))
}

/// `GET /v1/users/{id}/two-factor` — read TOTP state. **Self** sees the full detail (including how
/// many backup codes remain); an **admin** (`user.manage`) sees the state of another account but not
/// its backup-code count. Any other caller is refused.
pub async fn get_two_factor(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    actor: CurrentActor,
) -> Result<Json<TwoFactorStatus>, ApiError> {
    let target = UserId(id);
    let (requester, snapshot) = resolve_requester_and_target(&state, &actor, target).await;
    let is_self = requester == Some(target) && !actor.is_api_key();
    if !is_self {
        // Cross-user read is an administrative view, gated like every other cross-user user op.
        crate::authz::require_permission(
            &state,
            &actor,
            chancela_authz::Permission::UserManage,
            chancela_authz::Scope::Global,
        )
        .await?;
    }
    let user = snapshot.ok_or(ApiError::NotFound)?;
    let (enrolled, confirmed, confirmed_at, remaining) = match &user.totp {
        Some(e) => (
            true,
            e.confirmed,
            e.confirmed_at.clone(),
            is_self.then(|| e.backup_codes_remaining()),
        ),
        None => (false, false, None, is_self.then_some(0)),
    };
    Ok(Json(TwoFactorStatus {
        enrolled,
        confirmed,
        confirmed_at,
        backup_codes_remaining: remaining,
        required: user.two_factor_required,
    }))
}

/// Mint [`BACKUP_CODE_COUNT`] backup codes: return the plaintexts (shown once) and their argon2id
/// verifiers (stored). The plaintext never touches disk.
fn mint_backup_codes() -> Result<(Vec<String>, Vec<String>), ApiError> {
    let mut plaintext = Vec::with_capacity(BACKUP_CODE_COUNT);
    let mut hashes = Vec::with_capacity(BACKUP_CODE_COUNT);
    for _ in 0..BACKUP_CODE_COUNT {
        let code = generate_backup_code();
        let hash = crate::attestation::hash_secret(&code)?;
        plaintext.push(code);
        hashes.push(hash);
    }
    Ok((plaintext, hashes))
}

/// Verify a presented backup code against a user's stored verifiers, returning the **index** of the
/// matching slot so the caller can consume it (single-use). Runs one argon2 verify per stored code;
/// there is no constant-work padding here because this is only reachable from an authenticated sign-in
/// second-factor step that is already rate-limited on the pending challenge (P2).
#[must_use]
pub fn find_matching_backup_code(hashes: &[String], presented: &str) -> Option<usize> {
    let candidate = presented.trim().to_ascii_uppercase();
    hashes
        .iter()
        .position(|h| crate::attestation::verify_secret(&candidate, h))
}

/// Verify a presented second-factor `code` for `user_id` at sign-in and, on success, **consume it** —
/// advancing the replay guard for a TOTP code, or spending a backup code — then persist. Returns
/// `Ok(true)` when accepted, `Ok(false)` when rejected.
///
/// This is the sign-in-time counterpart to [`confirm_totp`]: the pending-challenge handler
/// (`session.rs`, P2) calls it after the password has already proved out and the unlocked key is held
/// in the pending record. A 6-digit input is tried as a TOTP; anything else is tried as a backup
/// code, so a user whose authenticator is unavailable can still get in with a recovery code. The
/// throttle lives on the pending challenge (the caller), not here — a wrong code must speed-bump the
/// pending sign-in, never lock the account.
pub(crate) async fn verify_and_consume_second_factor(
    state: &AppState,
    user_id: UserId,
    code: &str,
    now: OffsetDateTime,
) -> Result<bool, ApiError> {
    let Some(enrolment) = state
        .users
        .read()
        .await
        .get(&user_id)
        .and_then(|u| u.totp.clone())
    else {
        return Ok(false); // no enrolment to verify against
    };
    if !enrolment.confirmed {
        return Ok(false);
    }

    let trimmed = code.trim();
    let is_totp_shaped = trimmed.len() == 6 && trimmed.bytes().all(|b| b.is_ascii_digit());

    if is_totp_shaped {
        let Some(secret) = read_totp_secret(state, user_id).await? else {
            return Ok(false);
        };
        match verify_code_against_secret(&secret, trimmed, now.unix_timestamp(), enrolment.last_accepted_step)
        {
            VerifyOutcome::Accepted { step } => {
                let mut users = state.users.write().await;
                if let Some(user) = users.get_mut(&user_id)
                    && let Some(e) = user.totp.as_mut()
                {
                    e.last_accepted_step = Some(step);
                }
                drop(users);
                crate::sidecar_store::persist_users(state).await?;
                Ok(true)
            }
            VerifyOutcome::Rejected => Ok(false),
        }
    } else {
        // Backup code path.
        let Some(index) = find_matching_backup_code(&enrolment.backup_code_hashes, trimmed) else {
            return Ok(false);
        };
        let mut users = state.users.write().await;
        if let Some(user) = users.get_mut(&user_id)
            && let Some(e) = user.totp.as_mut()
            && index < e.backup_code_hashes.len()
        {
            e.backup_code_hashes.remove(index);
        }
        drop(users);
        crate::sidecar_store::persist_users(state).await?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 Appendix B reference vectors for the SHA-1 variant. The shared secret is the ASCII
    /// string "12345678901234567890" (20 bytes); base32-encode it and assert the published codes at
    /// the published times. Truncated to 6 digits (the appendix prints 8).
    #[test]
    fn rfc6238_sha1_reference_vectors() {
        let secret = base32_encode(b"12345678901234567890");
        // (unix_seconds, expected 8-digit code) → take the low 6 digits.
        let vectors = [
            (59_i64, 94287082_u32),
            (1_111_111_109, 7081804),
            (1_111_111_111, 14050471),
            (1_234_567_890, 89005924),
            (2_000_000_000, 69279037),
        ];
        for (t, code8) in vectors {
            let got = code_at(&secret, t, 0).expect("decodable");
            assert_eq!(got, code8 % 1_000_000, "code at t={t}");
        }
    }

    #[test]
    fn base32_round_trips() {
        for sample in [&b"12345678901234567890"[..], b"\x00\xff\x10hello", b"", b"a"] {
            let encoded = base32_encode(sample);
            assert_eq!(base32_decode(&encoded).as_deref(), Some(sample));
        }
        // Case-insensitive and tolerant of spaces/padding.
        assert_eq!(
            base32_decode("gezdgnbvgy3tqojq").as_deref(),
            base32_decode("GEZD GNBV GY3T QOJQ").as_deref()
        );
        // A non-alphabet character fails closed.
        assert_eq!(base32_decode("!!!!"), None);
    }

    #[test]
    fn a_current_code_verifies_and_a_wrong_one_does_not() {
        let secret = TotpSecret::generate();
        let now = 1_700_000_000;
        let expected = code_at(secret.expose(), now, 0).expect("decodable");
        let code = format!("{expected:06}");
        assert_eq!(
            verify_code_against_secret(secret.expose(), &code, now, None),
            VerifyOutcome::Accepted {
                step: current_step(now)
            }
        );
        assert_eq!(
            verify_code_against_secret(secret.expose(), "000000", now, Some(-1)),
            VerifyOutcome::Rejected,
            "a wrong code (that isn't the real one) must be rejected"
        );
    }

    #[test]
    fn a_code_is_accepted_within_the_window_but_not_outside_it() {
        let secret = TotpSecret::generate();
        let now = 1_700_000_000;
        // One step in the past is inside the ±1 window.
        let past = code_at(secret.expose(), now - STEP_SECONDS, 0).expect("decodable");
        assert!(matches!(
            verify_code_against_secret(secret.expose(), &format!("{past:06}"), now, None),
            VerifyOutcome::Accepted { .. }
        ));
        // Two steps in the past is outside it.
        let older = code_at(secret.expose(), now - 2 * STEP_SECONDS, 0).expect("decodable");
        assert_eq!(
            verify_code_against_secret(secret.expose(), &format!("{older:06}"), now, None),
            VerifyOutcome::Rejected
        );
    }

    /// The replay guard: once a step is accepted, that step and every earlier one is refused, so a
    /// code captured and re-presented inside its own 30 s window does not work a second time.
    #[test]
    fn an_accepted_step_cannot_be_replayed() {
        let secret = TotpSecret::generate();
        let now = 1_700_000_000;
        let code = format!("{:06}", code_at(secret.expose(), now, 0).expect("decodable"));
        let VerifyOutcome::Accepted { step } =
            verify_code_against_secret(secret.expose(), &code, now, None)
        else {
            panic!("first presentation should be accepted");
        };
        // Same code, same window, now with last_accepted_step recorded → replay refused.
        assert_eq!(
            verify_code_against_secret(secret.expose(), &code, now, Some(step)),
            VerifyOutcome::Rejected,
            "a code must not be replayable inside its own window"
        );
    }

    #[test]
    fn malformed_codes_are_rejected_without_panicking() {
        let secret = TotpSecret::generate();
        let now = 1_700_000_000;
        for bad in ["", "12345", "1234567", "abcdef", "12 34 56", "000000x"] {
            assert_eq!(
                verify_code_against_secret(secret.expose(), bad, now, None),
                VerifyOutcome::Rejected,
                "{bad:?}"
            );
        }
    }

    #[test]
    fn a_provisioning_uri_is_well_formed_and_escapes_its_label() {
        let secret = TotpSecret::generate();
        let uri = secret.provisioning_uri("Encosto Estratégico Lda", "amelia.marques");
        assert!(uri.starts_with("otpauth://totp/"));
        assert!(uri.contains(&format!("secret={}", secret.expose())));
        assert!(uri.contains("algorithm=SHA1"));
        assert!(uri.contains("digits=6"));
        assert!(uri.contains("period=30"));
        // The space and the accented character are escaped, never emitted raw.
        assert!(!uri.contains("Encosto Estratégico"));
        assert!(uri.contains("Encosto%20Estrat"));
    }

    #[test]
    fn a_secret_never_prints_itself() {
        let secret = TotpSecret::generate();
        assert_eq!(format!("{secret:?}"), "TotpSecret(<redacted>)");
        assert!(!format!("{secret:?}").contains(secret.expose()));
    }

    #[test]
    fn backup_codes_are_unambiguous_and_unique() {
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..200 {
            let code = generate_backup_code();
            assert_eq!(code.len(), 11, "{code}");
            assert_eq!(code.as_bytes()[5], b'-');
            assert!(
                code.chars().all(|c| c == '-' || "ABCDEFGHJKMNPQRSTUVWXYZ23456789".contains(c)),
                "ambiguous character in {code}"
            );
            assert!(seen.insert(code), "the CSPRNG repeated a backup code");
        }
    }
}
