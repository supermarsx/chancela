//! The **saved CMD mobile number** — a user's own Chave Móvel Digital phone number, kept encrypted
//! so it does not have to be retyped at every signature.
//!
//! ## Opt-in, and only ever opt-in
//!
//! Nothing here is written unless the user explicitly asks for it. The CMD signing form carries an
//! unchecked "remember this number" box; the number reaches this module only when that box was
//! ticked. There is no implicit capture from a successful signature, and no backfill of numbers
//! already typed — a number the user never chose to save is not stored anywhere.
//!
//! ## Custody: the phone rides the attestation key's wraps, it does not invent its own
//!
//! The plaintext is sealed with [`SealedSecret`] — argon2id + XChaCha20-Poly1305, the *same* code
//! path [`AttestationKeyBlob`](crate::attestation::AttestationKeyBlob) uses — under a secret derived
//! from the session's **unlocked attestation scalar** ([`custody_secret`]).
//!
//! That indirection is the whole design, so it is worth stating what it buys. `docs/passkeys.md`
//! Invariant 2 requires that a PRF wrap is never the only wrap: an iOS-18.4-class event that moves a
//! vendor's PRF output must degrade to the password, never to data loss. The attestation scalar
//! already satisfies that invariant — it is wrapped by the password **always**
//! (`User.attestation_key`) and by a passkey's PRF output **additionally**
//! (`PasskeyCredential.prf_wrap`). Sealing the phone to that scalar therefore inherits exactly that
//! custody, structurally:
//!
//! - password → scalar → phone. Always available. The password wrap can never be absent, because a
//!   scalar with no password wrap does not exist.
//! - PRF → scalar → phone. Available additionally, for every passkey that holds a PRF wrap — and
//!   automatically for a passkey enrolled *after* the number was saved, with no re-seal.
//! - PRF destroyed → the password path is untouched. The phone survives.
//!
//! Sealing the phone under two of its own wraps (one keyed by the password, one by each passkey's
//! PRF output) would express the same rule as a *second* implementation that has to be kept correct
//! by hand — and it could not even be built without a new per-credential ceremony, since a `PUT`
//! that proves the password has no PRF output to hand and a passkey enrolled later has no password.
//! Chaining to the scalar makes the invariant hold by construction instead. This is the one place
//! that deviates from a literal reading of "two wraps of the phone", and it deviates *towards* the
//! guarantee, not away from it.
//!
//! The consequence to be honest about: the phone is reachable exactly when the attestation key is.
//! An account with no attestation key cannot save a number (refused loudly, never silently dropped),
//! and a credential reset that **replaces** the scalar takes the saved number with it — so
//! [`clear_for_user_id`] is called there rather than leaving a record no key can ever open. A
//! password *change* rewraps the same scalar, so a saved number survives it untouched.
//!
//! ## Storage: its own sidecar, not `UserView`, not `UserPreferences`
//!
//! [`UserView`](crate::users::UserView) is a ledger payload — a field there moves the digest of
//! every future user event — so the number is not stored on it, and no ledger event carries it.
//!
//! It is also not folded into [`UserPreferences`](crate::user_preferences::UserPreferences), whose
//! `PUT` is a whole-document replace: a client that wrote its column choices without echoing the
//! phone back would silently destroy the saved number. A dedicated sidecar (`cmd-saved-phones.json`,
//! keyed by user id, mirroring `user_preferences.json`'s atomic temp-file-plus-rename persistence)
//! has no such footgun, and keeps the ciphertext out of every `User`/`UserPreferences` clone that
//! flows into views, list endpoints and cluster state.
//!
//! ## Endpoints (self-scoped)
//!
//! `GET`/`PUT /v1/me/cmd-phone` act **only** on the acting session's own row. There is no
//! administrative path to another user's number and no list endpoint: the sidecar is never
//! enumerated over the wire, and the only reader of a plaintext number is a session that can open
//! the seal — which means a session that unlocked that user's own attestation key.
//!
//! `PUT` with `{"phone": null}` clears the row. A separate `DELETE` would be the tidier verb, but
//! clearing has to carry the same step-up proof as saving, and a `DELETE` body is stripped by enough
//! intermediaries that the proof would arrive missing; one path with one body shape avoids that.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use axum::Json;
use axum::extract::State;
use p256::ecdsa::SigningKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use crate::AppState;
use crate::actor::{CurrentActor, CurrentAttestor};
use crate::attestation::SealedSecret;
use crate::data::{ReAuth, require_step_up};
use crate::error::ApiError;
use crate::users::UserId;

/// The file name holding the saved-CMD-phone sidecar inside the data directory.
pub const CMD_SAVED_PHONES_FILE: &str = "cmd-saved-phones.json";

/// Schema version of the sidecar document.
pub const CMD_SAVED_PHONES_SCHEMA_VERSION: u32 = 1;

/// Longest accepted number, in characters. A Portuguese mobile in international form is 13 with the
/// `+351 ` prefix; this leaves room for separators and a longer foreign number without accepting a
/// payload.
const MAX_PHONE_CHARS: usize = 32;
/// Fewest digits an accepted number may carry. Below this it cannot be a dialable mobile, and
/// storing it would only guarantee a failed signature later.
const MIN_PHONE_DIGITS: usize = 6;

// --- Stable error codes ---------------------------------------------------------------------
//
// Server prose is invisible to the web's `noLiteralUiCopy` / `catalogLeakGate` checks, so every
// refusal a user can provoke is emitted as a code the client resolves through its own catalog
// (`apiErrorFallback.ts`). The Portuguese message stays as the honest fallback for a non-web caller.

/// The session holds no unlocked attestation key, so there is no scalar to seal the number under.
pub(crate) const CMD_PHONE_NO_UNLOCKED_KEY_CODE: &str = "cmd_phone_no_unlocked_key";
/// The submitted number is not a usable mobile number (empty, too long, too few digits, or carrying
/// characters a dialable number cannot contain).
pub(crate) const CMD_PHONE_INVALID_CODE: &str = "cmd_phone_invalid";
/// A stored number exists but this session cannot open it — the seal was made under a different
/// attestation scalar (a credential reset replaced the key). Reported, never silently swallowed.
pub(crate) const CMD_PHONE_UNREADABLE_CODE: &str = "cmd_phone_unreadable";

// --- The document ---------------------------------------------------------------------------

/// The whole sidecar: user id (canonical UUID string) → that user's sealed number.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SavedCmdPhoneStore {
    pub schema_version: u32,
    pub users: BTreeMap<String, SavedCmdPhone>,
}

impl Default for SavedCmdPhoneStore {
    fn default() -> Self {
        SavedCmdPhoneStore {
            schema_version: CMD_SAVED_PHONES_SCHEMA_VERSION,
            users: BTreeMap::new(),
        }
    }
}

impl SavedCmdPhoneStore {
    /// This user's saved number, if any.
    pub(crate) fn get(&self, user_id: UserId) -> Option<&SavedCmdPhone> {
        self.users.get(&user_id.to_string())
    }

    fn set(&mut self, user_id: UserId, saved: SavedCmdPhone) {
        self.schema_version = CMD_SAVED_PHONES_SCHEMA_VERSION;
        self.users.insert(user_id.to_string(), saved);
    }

    fn clear(&mut self, user_id: UserId) -> bool {
        self.schema_version = CMD_SAVED_PHONES_SCHEMA_VERSION;
        self.users.remove(&user_id.to_string()).is_some()
    }

    /// Drop rows a hand-edited or truncated file cannot describe: a non-UUID key, or a record with
    /// an empty ciphertext/fingerprint. Never errors — a corrupt sidecar must not stop the server.
    fn sanitized(mut self) -> Self {
        self.schema_version = CMD_SAVED_PHONES_SCHEMA_VERSION;
        self.users
            .retain(|key, saved| Uuid::parse_str(key).is_ok() && saved.is_well_formed());
        self
    }
}

/// One user's saved number: the sealed bytes, plus the non-secret facts needed to reason about the
/// seal without opening it.
///
/// There is deliberately **no cleartext hint** — not even a masked suffix. A stored mask would be
/// readable by anyone who can read the sidecar or a privacy-officer export, and the feature does not
/// need one: the only surface that displays the number is the owner's own session, which can open
/// the seal and show the real thing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedCmdPhone {
    /// The 32-hex fingerprint of the attestation key whose scalar this seal is keyed to.
    ///
    /// Not needed to decrypt — the AEAD tag already rejects a wrong key — but it lets a stale row be
    /// identified *before* a decrypt attempt, so a replaced attestation key produces an honest
    /// "saved under a key this account no longer has" instead of an indistinguishable crypto error.
    pub key_fingerprint: String,
    /// The number itself, sealed. The plaintext exists nowhere else at rest.
    pub sealed: SealedSecret,
    /// RFC 3339 instant the user saved it.
    pub saved_at: String,
}

impl SavedCmdPhone {
    fn is_well_formed(&self) -> bool {
        !self.key_fingerprint.is_empty()
            && !self.sealed.ciphertext.is_empty()
            && !self.sealed.nonce.is_empty()
            && !self.sealed.kdf_salt.is_empty()
    }
}

// --- Custody ---------------------------------------------------------------------------------

/// Derive the seal secret from the unlocked attestation scalar.
///
/// Domain-separated (`chancela.cmd.phone.custody.v1`) and hashed, so the raw scalar is never handed
/// to another subsystem as a string and a value derived here can never collide with the PRF-derived
/// KEK or any other use of the same key. The scalar is 256 bits of uniform secret, so the argon2id
/// pass inside [`SealedSecret`] adds no strength here — it is kept because using the identical seal
/// primitive is worth more than saving one KDF, and because a divergent "fast path" is exactly how
/// two crypto schemes come to exist where the design says there is one.
fn custody_secret(key: &SigningKey) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"chancela.cmd.phone.custody.v1");
    hasher.update(key.to_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    crate::hex::hex(&digest)
}

// --- Validation ------------------------------------------------------------------------------

/// Normalise and check a submitted number.
///
/// Accepts an optional leading `+` followed by digits, spaces, hyphens and parentheses — the shapes
/// people actually type — and stores the **trimmed original**, not a reformatted version: the value
/// is replayed into the CMD lane verbatim, so rewriting it would be this module deciding what the
/// user's number is. Anything outside that character set, or with too few digits, is refused rather
/// than repaired.
fn validate_phone(raw: &str) -> Result<String, ApiError> {
    let trimmed = raw.trim();
    let invalid = || {
        ApiError::Unprocessable(
            "número de telemóvel inválido: indique o número em formato internacional, por exemplo \
             +351 900 000 000"
                .to_owned(),
        )
        .with_code(CMD_PHONE_INVALID_CODE)
    };
    if trimmed.is_empty() || trimmed.chars().count() > MAX_PHONE_CHARS {
        return Err(invalid());
    }
    let mut digits = 0usize;
    for (index, ch) in trimmed.chars().enumerate() {
        match ch {
            '+' if index == 0 => {}
            '0'..='9' => digits += 1,
            ' ' | '-' | '(' | ')' => {}
            _ => return Err(invalid()),
        }
    }
    if digits < MIN_PHONE_DIGITS {
        return Err(invalid());
    }
    Ok(trimmed.to_owned())
}

// --- Persistence -----------------------------------------------------------------------------

/// Read the sidecar, returning `None` when absent or unreadable and falling back to defaults (with a
/// warning) when present but malformed. Mirrors [`crate::user_preferences::load_user_preferences`].
pub(crate) fn load_saved_cmd_phones(path: &Path) -> Option<SavedCmdPhoneStore> {
    let bytes = std::fs::read(path).ok()?;
    match serde_json::from_slice::<SavedCmdPhoneStore>(&bytes) {
        Ok(store) => Some(store.sanitized()),
        Err(e) => {
            eprintln!(
                "warning: {} is not a valid saved CMD phone document ({e}); using defaults",
                path.display()
            );
            None
        }
    }
}

/// Atomically write the sidecar: unique temp file in the same directory, then rename.
pub(crate) fn write_saved_cmd_phones_atomic(
    path: &Path,
    store: &SavedCmdPhoneStore,
) -> std::io::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_vec_pretty(store).map_err(std::io::Error::other)?;
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
        .unwrap_or_else(|| CMD_SAVED_PHONES_FILE.into());
    name.push(format!(".{}.tmp", Uuid::new_v4()));
    path.with_file_name(name)
}

/// Persist the in-memory sidecar when the state is file-backed. A no-op in memory.
async fn persist(state: &AppState) -> Result<(), ApiError> {
    if let Some(path) = &state.saved_cmd_phones_path {
        let store = state.saved_cmd_phones.read().await;
        write_saved_cmd_phones_atomic(path, &store).map_err(|e| {
            ApiError::Internal(format!("failed to persist the saved CMD phone: {e}"))
        })?;
    }
    Ok(())
}

/// Discard a user's saved number, if any, and persist. Returns whether a row was removed.
///
/// Called from the credential-reset path, where the attestation key is **replaced** with a freshly
/// generated scalar: the old seal becomes permanently unopenable at that instant, so leaving the row
/// behind would only preserve a record that lies about being recoverable.
pub(crate) async fn clear_for_user_id(state: &AppState, user_id: UserId) -> Result<bool, ApiError> {
    let removed = state.saved_cmd_phones.write().await.clear(user_id);
    if removed {
        persist(state).await?;
    }
    Ok(removed)
}

/// Open a user's saved number with an unlocked attestation scalar.
///
/// `Ok(None)` means "no number saved". `Err` means a number IS saved and could not be opened — the
/// caller must surface that, never treat it as absence (see [`CMD_PHONE_UNREADABLE_CODE`]).
pub(crate) async fn open_saved_phone(
    state: &AppState,
    user_id: UserId,
    key: &SigningKey,
) -> Result<Option<String>, ApiError> {
    let saved = {
        let store = state.saved_cmd_phones.read().await;
        match store.get(user_id) {
            Some(saved) => saved.clone(),
            None => return Ok(None),
        }
    };
    let unreadable = || {
        ApiError::Conflict(
            "o número guardado foi cifrado com uma chave de atestação que esta conta já não tem; \
             volte a guardá-lo"
                .to_owned(),
        )
        .with_code(CMD_PHONE_UNREADABLE_CODE)
    };
    if saved.key_fingerprint != crate::attestation::key_fingerprint(key) {
        return Err(unreadable());
    }
    // The error is deliberately dropped rather than propagated: `AttestationError`'s Display carries
    // the underlying crypto fault, and this is a path an unauthenticated guess could reach.
    let bytes = saved
        .sealed
        .open(&custody_secret(key))
        .map_err(|_| unreadable())?;
    let phone = String::from_utf8(bytes).map_err(|_| unreadable())?;
    Ok(Some(phone))
}

// --- Wire shapes -----------------------------------------------------------------------------

/// `GET /v1/me/cmd-phone` / `PUT /v1/me/cmd-phone` response.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct SavedCmdPhoneView {
    /// Whether a number is stored for this account at all. Answerable without opening the seal, so
    /// it stays honest even for a session that cannot decrypt.
    pub saved: bool,
    /// RFC 3339 instant it was saved; null when nothing is saved.
    pub saved_at: Option<String>,
    /// The number itself — present **only** when this session opened the seal. Null when nothing is
    /// saved, and null (with `saved: true` and `readable: false`) when a number exists but this
    /// session holds no unlocked key for it.
    pub phone: Option<String>,
    /// Whether `phone` above could be produced. Distinguishes "nothing saved" from "saved, but this
    /// session cannot open it" without inventing a value for either.
    pub readable: bool,
}

impl SavedCmdPhoneView {
    fn empty() -> Self {
        SavedCmdPhoneView {
            saved: false,
            saved_at: None,
            phone: None,
            readable: false,
        }
    }
}

/// Body of `PUT /v1/me/cmd-phone`.
#[derive(Deserialize, Default)]
pub struct SaveCmdPhone {
    /// The number to save, or `null` to clear the saved number.
    #[serde(default)]
    pub phone: Option<String>,
    /// Step-up re-auth proof — required for both saving and clearing.
    #[serde(default)]
    pub reauth: ReAuth,
}

// --- Handlers --------------------------------------------------------------------------------

/// Resolve the acting session to its own [`UserId`]. An API key is refused: it is a machine
/// principal with no personal signing number. Mirrors `user_preferences::resolve_self`.
async fn resolve_self(state: &AppState, actor: &CurrentActor) -> Result<UserId, ApiError> {
    let Some(username) = actor.session_username() else {
        return Err(ApiError::Forbidden(
            "uma chave API não abre uma sessão interativa com um número de assinatura pessoal"
                .to_owned(),
        ));
    };
    let users = state.users.read().await;
    if let Some(user_id) = actor.session_user_id() {
        return users
            .get(&user_id)
            .filter(|user| user.active && user.username == username)
            .map(|user| user.id)
            .ok_or_else(|| ApiError::Unauthorized("sessão inválida".to_owned()));
    }
    users
        .values()
        .find(|user| user.active && user.username == username)
        .map(|user| user.id)
        .ok_or_else(|| ApiError::Unauthorized("sessão inválida".to_owned()))
}

/// `GET /v1/me/cmd-phone` — the acting user's own saved CMD number.
///
/// **Session-only, deliberately no step-up.** Requiring a re-auth to read would defeat the entire
/// feature: the number exists precisely so the signing form can prefill it. What a session-bound
/// read exposes to a stolen session is the account's own phone number, which is the same class of
/// fact as the account's e-mail that the profile endpoint already returns on the session alone. The
/// step-up wall is on `PUT`, because *writing* is the direction that can redirect an SMS OTP to an
/// attacker's handset — see [`put_me_cmd_phone`].
///
/// **This read never fails on an unopenable seal.** A stale row (sealed to a scalar this account no
/// longer has) reports `saved: true, readable: false`, not an error. An error here would be worse
/// than useless: the client treats a failed read as "no number saved", so a `409` would *hide* the
/// very fact the row proves — that the account holds a number — and offer the user no way to reach
/// the control that clears it. `readable: false` states both halves and leaves the clear reachable.
pub async fn get_me_cmd_phone(
    State(state): State<AppState>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
) -> Result<Json<SavedCmdPhoneView>, ApiError> {
    let user_id = resolve_self(&state, &actor).await?;
    let saved_at = {
        let store = state.saved_cmd_phones.read().await;
        match store.get(user_id) {
            Some(saved) => saved.saved_at.clone(),
            None => return Ok(Json(SavedCmdPhoneView::empty())),
        }
    };
    let Some((_, key)) = attestor.signer() else {
        // A number is saved, but this session never unlocked the scalar (signed in without a
        // password and without a PRF-capable passkey). Honest: it exists, we cannot show it.
        return Ok(Json(SavedCmdPhoneView {
            saved: true,
            saved_at: Some(saved_at),
            phone: None,
            readable: false,
        }));
    };
    // A failure here is a stale seal, and it is reported as unreadable rather than raised — see the
    // doc note above on why a `409` would hide the row instead of explaining it.
    let phone = open_saved_phone(&state, user_id, key).await.unwrap_or(None);
    Ok(Json(SavedCmdPhoneView {
        saved: true,
        saved_at: Some(saved_at),
        readable: phone.is_some(),
        phone,
    }))
}

/// `PUT /v1/me/cmd-phone` — save (or, with `{"phone": null}`, clear) the acting user's own number.
///
/// ## Why this takes step-up and `PATCH /v1/me/profile` does not
///
/// A saved number is prefilled into the CMD signing form, and CMD sends its confirmation OTP to
/// whatever number that form submits. An attacker holding a stolen session who could quietly swap
/// the saved number would be redirecting the second factor of a **qualified signature** to their own
/// handset, and the user's only cue would be a prefilled field they have been trained to accept. So
/// this is not the "wrong display name an administrator undoes" class that leaves `/v1/me/profile`
/// unguarded — it is the `/v1/me/suspend` class, and it takes
/// [`require_step_up`](crate::data::require_step_up) for the same reason.
///
/// Clearing carries the same proof. It is the less dangerous direction, but a gate that is easy to
/// reason about is worth more here than one extra branch: both mutations of the stored secret
/// require the strongest proof the acting user can give.
pub async fn put_me_cmd_phone(
    State(state): State<AppState>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<SaveCmdPhone>,
) -> Result<Json<SavedCmdPhoneView>, ApiError> {
    // Step-up first, exactly as `suspend_me` does: an API key never reaches the state below because
    // `require_step_up` refuses a caller with no session username, and `resolve_self` refuses again.
    require_step_up(&state, &actor, &req.reauth).await?;
    let user_id = resolve_self(&state, &actor).await?;

    let Some(phone) = req.phone.as_deref() else {
        clear_for_user_id(&state, user_id).await?;
        return Ok(Json(SavedCmdPhoneView::empty()));
    };
    let phone = validate_phone(phone)?;

    // The scalar to seal under is the session's unlocked attestation key — the same scalar the
    // password wrap holds and every PRF wrap holds. A session that never unlocked it cannot save.
    let Some((_, key)) = attestor.signer() else {
        return Err(ApiError::Forbidden(
            "para guardar o número, volte a autenticar-se com a palavra-passe: o número é cifrado \
             com a chave de atestação, que tem de estar aberta na sessão"
                .to_owned(),
        )
        .with_code(CMD_PHONE_NO_UNLOCKED_KEY_CODE));
    };

    let sealed = SealedSecret::seal(&custody_secret(key), phone.as_bytes())
        .map_err(|e| ApiError::Internal(format!("could not seal the CMD phone: {e}")))?;
    let saved_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default();
    let record = SavedCmdPhone {
        key_fingerprint: crate::attestation::key_fingerprint(key),
        sealed,
        saved_at: saved_at.clone(),
    };
    state.saved_cmd_phones.write().await.set(user_id, record);
    persist(&state).await?;

    // Echo the stored value back by re-opening the seal, so a caller learns the round-trip really
    // worked rather than being told so by the value it just sent. No ledger event is appended: this
    // is personal convenience data, not an evidentiary act.
    //
    // Unlike the GET, a failure here is NOT reported as "unreadable": the row was sealed under this
    // very key a line ago, so it cannot be the stale-key case, and the honest answer is that the
    // server stored something it cannot read back. That is a fault, and it is raised as one rather
    // than handed back as a state the user could act on.
    let phone = open_saved_phone(&state, user_id, key).await.map_err(|_| {
        ApiError::Internal(
            "the CMD phone was sealed but could not be read back immediately".to_owned(),
        )
    })?;
    Ok(Json(SavedCmdPhoneView {
        saved: true,
        saved_at: Some(saved_at),
        readable: phone.is_some(),
        phone,
    }))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use p256::ecdsa::SigningKey;
    use rand_core::OsRng;
    use uuid::Uuid;

    use super::*;
    use crate::attestation::AttestationKeyBlob;
    use crate::users::{User, UserId};

    /// A clearly-synthetic number. Never a real one, in any fixture, anywhere in this repo.
    const FAKE_PHONE: &str = "+351 900 000 000";

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("chancela-cmd-phone-{}", Uuid::new_v4()));
            std::fs::create_dir_all(&path).expect("create temp dir");
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    async fn seed_user(state: &AppState, username: &str, password: Option<&str>) -> UserId {
        let uid = UserId(Uuid::new_v4());
        let attestation_key = password.map(|p| AttestationKeyBlob::generate(p).expect("key"));
        let password_hash = password.map(|p| crate::attestation::hash_secret(p).expect("hash"));
        state.users.write().await.insert(
            uid,
            User {
                passkeys: Vec::new(),
                id: uid,
                username: username.to_owned(),
                display_name: "Amélia Marques".to_owned(),
                email: None,
                created_at: "2026-01-01T00:00:00Z".to_owned(),
                active: true,
                password_hash,
                attestation_key,
                retired_attestation_keys: Vec::new(),
                totp: None,
                two_factor_required: false,
                force_password_change: false,
                secret_source: Default::default(),
                recovery_hash: None,
                role_assignments: Vec::new(),
                language: Default::default(),
            },
        );
        uid
    }

    /// The unlocked scalar a signed-in session would hold for `password`.
    async fn unlocked(state: &AppState, user_id: UserId, password: &str) -> SigningKey {
        let users = state.users.read().await;
        users
            .get(&user_id)
            .and_then(|u| u.attestation_key.as_ref())
            .expect("user has an attestation key")
            .unlock(password)
            .expect("password opens the wrap")
    }

    fn attestor_for(username: &str, key: &SigningKey) -> CurrentAttestor {
        CurrentAttestor::from_signer(username.to_owned(), key.clone())
    }

    fn save_body(phone: Option<&str>, password: &str) -> SaveCmdPhone {
        SaveCmdPhone {
            phone: phone.map(str::to_owned),
            reauth: ReAuth {
                password: Some(password.to_owned()),
                ..Default::default()
            },
        }
    }

    #[test]
    fn validate_accepts_typed_shapes_and_refuses_the_rest() {
        assert_eq!(validate_phone("  +351 900 000 000 ").unwrap(), FAKE_PHONE);
        assert_eq!(
            validate_phone("+351-900-000-000").unwrap(),
            "+351-900-000-000"
        );
        assert_eq!(
            validate_phone("(351) 900000000").unwrap(),
            "(351) 900000000"
        );
        // The stored value is the trimmed original, never reformatted.
        assert_eq!(validate_phone("900000000").unwrap(), "900000000");

        for bad in [
            "",
            "   ",
            "12345",                   // too few digits
            "+351 900 000 000 ext. 4", // letters
            "+351\n900000000",         // control characters
            "9000000+00",              // '+' anywhere but the front
        ] {
            assert!(validate_phone(bad).is_err(), "must refuse {bad:?}");
        }
        let too_long = format!("+{}", "9".repeat(MAX_PHONE_CHARS));
        assert!(validate_phone(&too_long).is_err());
    }

    #[test]
    fn custody_secret_is_derived_and_key_specific() {
        let a = SigningKey::random(&mut OsRng);
        let b = SigningKey::random(&mut OsRng);
        let secret = custody_secret(&a);
        // 32 bytes of SHA-256, hex.
        assert_eq!(secret.len(), 64);
        assert_eq!(secret, custody_secret(&a), "derivation is deterministic");
        assert_ne!(secret, custody_secret(&b));
        // The raw scalar never appears in the derived secret.
        let scalar: [u8; 32] = a.to_bytes().into();
        assert!(!secret.contains(&crate::hex::hex(&scalar)));
    }

    /// The key-integrity proof for the whole feature: one scalar, sealed once, recoverable through
    /// **both** of the scalar's own wraps — and still recoverable through the password after the PRF
    /// wrap is destroyed. This is the iOS-18.4 case stated as an executable claim.
    #[test]
    fn phone_survives_prf_destruction_and_is_recoverable_by_password() {
        // The account's attestation key: password wrap always.
        let password_wrap = AttestationKeyBlob::generate("s3cret-pass").unwrap();
        let scalar = password_wrap.unlock("s3cret-pass").unwrap();
        // A passkey's PRF wrap of the SAME scalar: the additional, never-only wrap.
        let prf_wrap = AttestationKeyBlob::wrap_key("prf-derived-kek", &scalar).unwrap();
        assert_eq!(prf_wrap.fingerprint, password_wrap.fingerprint);

        // Seal the number once, under the scalar.
        let sealed = SealedSecret::seal(&custody_secret(&scalar), FAKE_PHONE.as_bytes()).unwrap();

        // Path 1 — password → scalar → phone.
        let via_password = password_wrap.unlock("s3cret-pass").unwrap();
        assert_eq!(
            String::from_utf8(sealed.open(&custody_secret(&via_password)).unwrap()).unwrap(),
            FAKE_PHONE
        );
        // Path 2 — PRF → scalar → phone. The same one ciphertext, no second seal.
        let via_prf = prf_wrap.unlock("prf-derived-kek").unwrap();
        assert_eq!(
            String::from_utf8(sealed.open(&custody_secret(&via_prf)).unwrap()).unwrap(),
            FAKE_PHONE
        );

        // The iOS-18.4 event: the vendor moves the PRF output. The PRF wrap is now dead…
        assert!(prf_wrap.unlock("a-moved-prf-output").is_err());
        // …and destroying the wrap record entirely changes nothing for the password path.
        drop(prf_wrap);
        let still = password_wrap.unlock("s3cret-pass").unwrap();
        assert_eq!(
            String::from_utf8(sealed.open(&custody_secret(&still)).unwrap()).unwrap(),
            FAKE_PHONE,
            "a destroyed PRF wrap must degrade to the password, never to loss of the number"
        );

        // An unrelated account's scalar opens nothing.
        let stranger = AttestationKeyBlob::generate("other").unwrap();
        let stranger_scalar = stranger.unlock("other").unwrap();
        assert!(sealed.open(&custody_secret(&stranger_scalar)).is_err());
    }

    #[test]
    fn store_sanitize_drops_non_uuid_keys_and_malformed_rows() {
        let mut store = SavedCmdPhoneStore::default();
        let key = SigningKey::random(&mut OsRng);
        let good = SavedCmdPhone {
            key_fingerprint: crate::attestation::key_fingerprint(&key),
            sealed: SealedSecret::seal(&custody_secret(&key), FAKE_PHONE.as_bytes()).unwrap(),
            saved_at: "2026-01-01T00:00:00Z".to_owned(),
        };
        let good_key = Uuid::new_v4().to_string();
        store.users.insert(good_key.clone(), good.clone());
        store.users.insert("not-a-uuid".to_owned(), good.clone());
        let empty_key = Uuid::new_v4().to_string();
        store.users.insert(
            empty_key.clone(),
            SavedCmdPhone {
                sealed: SealedSecret {
                    kdf_salt: String::new(),
                    nonce: String::new(),
                    ciphertext: String::new(),
                },
                ..good
            },
        );

        let clean = store.sanitized();
        assert!(clean.users.contains_key(&good_key));
        assert!(!clean.users.contains_key("not-a-uuid"));
        assert!(!clean.users.contains_key(&empty_key));
    }

    #[tokio::test]
    async fn save_then_read_round_trips_and_the_file_holds_no_plaintext() {
        let dir = TempDir::new();
        let path = dir.0.join(CMD_SAVED_PHONES_FILE);
        let state = AppState {
            saved_cmd_phones_path: Some(std::sync::Arc::new(path.clone())),
            ..AppState::default()
        };
        let uid = seed_user(&state, "amelia.marques", Some("s3cret-pass")).await;
        let key = unlocked(&state, uid, "s3cret-pass").await;
        let actor = CurrentActor::from_session_username(Some("amelia.marques".to_owned()));
        let attestor = attestor_for("amelia.marques", &key);

        let stored = put_me_cmd_phone(
            State(state.clone()),
            actor.clone(),
            attestor.clone(),
            Json(save_body(Some(FAKE_PHONE), "s3cret-pass")),
        )
        .await
        .expect("save succeeds")
        .0;
        assert!(stored.saved);
        assert!(stored.readable);
        assert_eq!(stored.phone.as_deref(), Some(FAKE_PHONE));

        // Read back byte-identically.
        let got = get_me_cmd_phone(State(state.clone()), actor.clone(), attestor.clone())
            .await
            .expect("read")
            .0;
        assert_eq!(got.phone.as_deref(), Some(FAKE_PHONE));
        assert_eq!(got.saved_at, stored.saved_at);

        // At rest: ciphertext only. The number is not in the file in any form.
        let on_disk = std::fs::read_to_string(&path).expect("sidecar written");
        assert!(
            !on_disk.contains("900"),
            "the number must not be at rest in cleartext"
        );
        assert!(!on_disk.contains(FAKE_PHONE));
        assert!(on_disk.contains("ciphertext"));
        // And it reloads.
        let reloaded = load_saved_cmd_phones(&path).expect("reload");
        assert_eq!(reloaded, *state.saved_cmd_phones.read().await);
    }

    #[tokio::test]
    async fn clearing_discards_the_row_and_all_of_its_wraps() {
        let state = AppState::default();
        let uid = seed_user(&state, "amelia.marques", Some("s3cret-pass")).await;
        let key = unlocked(&state, uid, "s3cret-pass").await;
        let actor = CurrentActor::from_session_username(Some("amelia.marques".to_owned()));
        let attestor = attestor_for("amelia.marques", &key);

        let _ = put_me_cmd_phone(
            State(state.clone()),
            actor.clone(),
            attestor.clone(),
            Json(save_body(Some(FAKE_PHONE), "s3cret-pass")),
        )
        .await
        .expect("save");
        assert!(state.saved_cmd_phones.read().await.get(uid).is_some());

        let cleared = put_me_cmd_phone(
            State(state.clone()),
            actor.clone(),
            attestor.clone(),
            Json(save_body(None, "s3cret-pass")),
        )
        .await
        .expect("clear")
        .0;
        assert_eq!(cleared, SavedCmdPhoneView::empty());
        assert!(
            state.saved_cmd_phones.read().await.get(uid).is_none(),
            "clearing must leave no ciphertext behind"
        );
        // And a read now honestly reports nothing saved.
        let got = get_me_cmd_phone(State(state), actor, attestor)
            .await
            .expect("read")
            .0;
        assert_eq!(got, SavedCmdPhoneView::empty());
    }

    #[tokio::test]
    async fn another_user_cannot_read_or_overwrite_the_saved_number() {
        let state = AppState::default();
        let amelia = seed_user(&state, "amelia.marques", Some("amelia-pass")).await;
        let bruno = seed_user(&state, "bruno.costa", Some("bruno-pass")).await;
        let amelia_key = unlocked(&state, amelia, "amelia-pass").await;
        let bruno_key = unlocked(&state, bruno, "bruno-pass").await;

        let _ = put_me_cmd_phone(
            State(state.clone()),
            CurrentActor::from_session_username(Some("amelia.marques".to_owned())),
            attestor_for("amelia.marques", &amelia_key),
            Json(save_body(Some(FAKE_PHONE), "amelia-pass")),
        )
        .await
        .expect("amelia saves");

        // Bruno's own session sees nothing at all — not a masked hint, not a timestamp.
        let bruno_view = get_me_cmd_phone(
            State(state.clone()),
            CurrentActor::from_session_username(Some("bruno.costa".to_owned())),
            attestor_for("bruno.costa", &bruno_key),
        )
        .await
        .expect("bruno reads")
        .0;
        assert_eq!(bruno_view, SavedCmdPhoneView::empty());

        // Bruno saving his own number leaves Amélia's row untouched.
        let _ = put_me_cmd_phone(
            State(state.clone()),
            CurrentActor::from_session_username(Some("bruno.costa".to_owned())),
            attestor_for("bruno.costa", &bruno_key),
            Json(save_body(Some("+351 900 000 001"), "bruno-pass")),
        )
        .await
        .expect("bruno saves");
        assert_eq!(
            open_saved_phone(&state, amelia, &amelia_key).await.unwrap(),
            Some(FAKE_PHONE.to_owned())
        );
        // And Bruno's unlocked scalar cannot open Amélia's row.
        assert!(open_saved_phone(&state, amelia, &bruno_key).await.is_err());
    }

    #[tokio::test]
    async fn a_wrong_step_up_proof_never_writes() {
        let state = AppState::default();
        let uid = seed_user(&state, "amelia.marques", Some("s3cret-pass")).await;
        let key = unlocked(&state, uid, "s3cret-pass").await;
        let actor = CurrentActor::from_session_username(Some("amelia.marques".to_owned()));
        let attestor = attestor_for("amelia.marques", &key);

        let error = put_me_cmd_phone(
            State(state.clone()),
            actor.clone(),
            attestor.clone(),
            Json(save_body(Some(FAKE_PHONE), "not-the-password")),
        )
        .await
        .expect_err("a wrong password is refused");
        assert!(matches!(error.as_uncoded(), ApiError::Forbidden(_)));
        assert!(state.saved_cmd_phones.read().await.users.is_empty());

        // A session with no proof at all is refused the same way.
        let error = put_me_cmd_phone(
            State(state.clone()),
            actor,
            attestor,
            Json(SaveCmdPhone {
                phone: Some(FAKE_PHONE.to_owned()),
                reauth: ReAuth::default(),
            }),
        )
        .await
        .expect_err("no proof is refused");
        assert!(matches!(error.as_uncoded(), ApiError::Forbidden(_)));
        assert!(state.saved_cmd_phones.read().await.users.is_empty());
    }

    #[tokio::test]
    async fn a_session_with_no_unlocked_key_cannot_save() {
        let state = AppState::default();
        // No password ⇒ no attestation key ⇒ step-up is vacuous, but there is no scalar to seal to.
        seed_user(&state, "legacy.user", None).await;
        let actor = CurrentActor::from_session_username(Some("legacy.user".to_owned()));

        let error = put_me_cmd_phone(
            State(state.clone()),
            actor,
            CurrentAttestor::default(),
            Json(SaveCmdPhone {
                phone: Some(FAKE_PHONE.to_owned()),
                reauth: ReAuth::default(),
            }),
        )
        .await
        .expect_err("no unlocked key refuses the save");
        assert!(matches!(error.as_uncoded(), ApiError::Forbidden(_)));
        assert!(state.saved_cmd_phones.read().await.users.is_empty());
    }

    /// A replaced attestation scalar (a credential reset, not a password change) leaves a row no key
    /// can open. It must be reported, never reported as "nothing saved".
    #[tokio::test]
    async fn a_stale_seal_is_reported_not_silently_treated_as_absent() {
        let state = AppState::default();
        let uid = seed_user(&state, "amelia.marques", Some("s3cret-pass")).await;
        let key = unlocked(&state, uid, "s3cret-pass").await;
        let actor = CurrentActor::from_session_username(Some("amelia.marques".to_owned()));

        let _ = put_me_cmd_phone(
            State(state.clone()),
            actor.clone(),
            attestor_for("amelia.marques", &key),
            Json(save_body(Some(FAKE_PHONE), "s3cret-pass")),
        )
        .await
        .expect("save");

        // The credential-reset path regenerates the scalar.
        let replacement = AttestationKeyBlob::generate("s3cret-pass").unwrap();
        let new_key = replacement.unlock("s3cret-pass").unwrap();
        let error = open_saved_phone(&state, uid, &new_key)
            .await
            .expect_err("a stale seal is an error, not an absence");
        assert!(matches!(error.as_uncoded(), ApiError::Conflict(_)));

        // The *read*, however, must not fail on it. A `409` here would be read by the client as
        // "the request failed" and rendered as "no number saved" — hiding the one fact the row
        // proves, and hiding the control that clears it. So the handler reports the honest pair:
        // a number exists, and this session cannot show it.
        let view = get_me_cmd_phone(
            State(state.clone()),
            actor,
            attestor_for("amelia.marques", &new_key),
        )
        .await
        .expect("a stale seal must not fail the read")
        .0;
        assert!(view.saved, "the row must not be hidden by being unreadable");
        assert!(!view.readable);
        assert_eq!(view.phone, None);

        // …and the reset path clears it rather than leaving the lie in place.
        assert!(clear_for_user_id(&state, uid).await.unwrap());
        assert_eq!(open_saved_phone(&state, uid, &new_key).await.unwrap(), None);
    }

    #[tokio::test]
    async fn an_api_key_has_no_personal_signing_number() {
        let state = AppState::default();
        let error = get_me_cmd_phone(
            State(state.clone()),
            CurrentActor::default(),
            CurrentAttestor::default(),
        )
        .await
        .expect_err("api key is refused");
        assert!(matches!(error.as_uncoded(), ApiError::Forbidden(_)));
    }

    /// A row written before a future field is added must keep loading, or the sidecar becomes silent
    /// data loss the first time its shape moves. Pin an old row explicitly.
    #[test]
    fn a_pre_existing_row_loads_unchanged() {
        let raw = serde_json::json!({
            "schema_version": 1,
            "users": {
                "11111111-2222-3333-4444-555555555555": {
                    "key_fingerprint": "0123456789abcdef0123456789abcdef",
                    "sealed": { "kdf_salt": "c2FsdA==", "nonce": "bm9uY2U=", "ciphertext": "Y3Q=" },
                    "saved_at": "2026-01-01T00:00:00Z",
                    "a_field_a_later_version_added": true
                }
            }
        });
        let store: SavedCmdPhoneStore = serde_json::from_value(raw).expect("an old row loads");
        let clean = store.sanitized();
        assert_eq!(
            clean.users.len(),
            1,
            "an unknown field must not drop the row"
        );
        let row = clean
            .users
            .get("11111111-2222-3333-4444-555555555555")
            .expect("row survives");
        assert_eq!(row.saved_at, "2026-01-01T00:00:00Z");
    }
}
