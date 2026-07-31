//! **WebAuthn passkeys** — credential storage, both ceremonies, and the step-up proof arm.
//!
//! This is the server half of the design ruling in `docs/passkeys.md`. That document decided the
//! shape; this module implements it, and the four decisions it is easiest to undo by accident are
//! called out where they live rather than only here:
//!
//! 1. **The RP ID is an operator setting, validated against `public_base_url` *and* the Public
//!    Suffix List, at configuration time** — [`PasskeySettings::validate_against`]. Neither check
//!    is provided by the library, and the failure mode of getting it wrong is invisible
//!    server-side, so this is load-bearing rather than defence in depth.
//! 2. **A ceremony challenge is purpose-scoped and single-use** — [`CeremonyStore`]. A sign-in
//!    assertion must not be replayable into a factory reset, and the only thing standing between
//!    those two is that the purposes do not match.
//! 3. **A UV-absent assertion is a *degraded* success, never a wrong credential** —
//!    [`VerifiedAssertion::user_verified`]. CTAP2.1 derives PRF from a different seed depending on
//!    whether user verification happened, so a UV-less assertion is a real assertion by the real
//!    credential that simply cannot unwrap anything.
//! 4. **A signature-counter regression is recorded, never fatal** — [`SIGN_COUNTER_REGRESSION_KIND`].
//!
//! ## The PRF-derived unwrap (t10 follow-up, wired)
//!
//! A passkey with a working PRF extension unlocks the attestation key **without a password** at
//! sign-in. This is the true-passwordless path of `docs/passkeys.md` shape A, and it holds the four
//! invariants that made the deferral safe to lift:
//!
//! 1. **A PRF wrap is NEVER the only wrap.** [`PasskeyCredential::prf_wrap`] is an *additional* wrap
//!    of the same attestation scalar; the password wrap on the user record always survives it (the
//!    key-custody clause of [`crate::credentials::ensure_removal_leaves_account_usable`] refuses to
//!    remove the password while a key exists). A PRF output a vendor moves out from under us (iOS
//!    18.4) therefore degrades to **the password prompt**, never to key loss.
//! 2. **Constant salt** ([`PRF_EVAL_SALT`]), not per-credential — the discoverable-sign-in ruling,
//!    not a preference.
//! 3. **UV required.** A UV-less assertion derives a *different* PRF secret (CTAP2.1's
//!    `CredRandomWithoutUV`), so it can never unlock. [`verify_authentication`] treats a UV-absent
//!    assertion as usable for authentication but **not** for the unwrap, and the ceremony already
//!    forces `userVerification: "required"`, so a UV-less assertion is refused before it arrives.
//! 4. **No hand-rolled crypto.** The web side is one `crypto.subtle.deriveBits` HKDF call; the Rust
//!    side reuses [`AttestationKeyBlob::wrap_key`]/[`AttestationKeyBlob::unlock`] with the derived
//!    bytes as the secret. Nothing new in the crypto layer.
//!
//! ### Where the derived KEK comes from, and why enrolment needs a second ceremony
//!
//! `webauthn_rp` cannot evaluate PRF at `create()` — its registration options serialise `prf` as an
//! empty map, so a browser never returns a PRF output from enrolment (`docs/passkeys.md` claimed
//! `create()`-time PRF was "usually available"; with this library it is *never* available, and that
//! correction is recorded there). So the wrap is added through a **second, `get()`-based ceremony**
//! bound to [`CeremonyPurpose::PrfWrap`]: after `create()` stores the credential, the browser runs a
//! `get()`, **adds `prf` itself** (see the module-top note on why the server cannot), reads
//! `prf.results.first`, derives the KEK client-side, and posts it to [`finish_prf_wrap`], which seals
//! the session's *already-unlocked* attestation scalar (the [`CurrentAttestor`]) under it. The server
//! never sees the PRF output — only the derived KEK — exactly as it only ever sees the password.
//!
//! Sign-in ([`begin_sign_in`]/[`complete_sign_in`]) works the same way: the browser adds `prf`, and a
//! usable (present, UV) PRF output derives the KEK, which opens [`PasskeyCredential::prf_wrap`] and
//! the session is minted with the unlocked key — no password. If the output is absent, UV is clear,
//! or the wrap does not open, the sign-in still succeeds but unlocks nothing, and the session is
//! asked for the **password** at first attestation. Step-up ([`begin_step_up`]) neither unlocks a key
//! nor accepts a `prf` extension: it verifies strictly (`error_on_unsolicited_extensions: true`).
//!
//! On the sign-in and PRF-wrap paths the server verifies with `error_on_unsolicited_extensions:
//! false`, so a PRF-capable credential's client-solicited `hmac-secret` output is accepted while a
//! non-PRF credential's empty output is too — the property that keeps shape-C credentials signing in.
//!
//! ### The capability is provisioned at enrolment and cannot be added later
//!
//! Enrolment asks the authenticator to provision an `hmac-secret` ([`registration_extensions`]) and
//! records whether it did ([`PasskeyCredential::prf_capable`]). CTAP2 only lets an RP ask at
//! **creation** time, so a credential enrolled without it is permanently PRF-incapable with no
//! migration — which is why the request is unconditional even for the degraded (shape-C) path.
//!
//! **The password wrap is not built here.** [`crate::credentials::WrapRole`] already declares that a
//! passkey's PRF wrap can never satisfy key custody, and
//! [`crate::credentials::ensure_removal_leaves_account_usable`] already refuses to remove the
//! password while an attestation key exists. This module adds a wrap; it never removes one, and it
//! leans on that guard rather than building a second.

use std::collections::HashMap;
use std::sync::Arc;

use axum::Json;
use axum::extract::{Path as AxumPath, State};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::sync::RwLock;
use uuid::Uuid;

use webauthn_rp::bin::{Decode as _, Encode as _};
use webauthn_rp::request::auth::{AuthenticationVerificationOptions, SignatureCounterEnforcement};
use webauthn_rp::request::register::{
    PublicKeyCredentialCreationOptions, PublicKeyCredentialUserEntity,
    RegistrationVerificationOptions, USER_HANDLE_MAX_LEN, UserHandle64, Username,
};
use webauthn_rp::request::{
    AsciiDomain, ExtensionInfo, PublicKeyCredentialDescriptor, RpId, TimedCeremony,
};
use webauthn_rp::response::auth::AuthenticatorData;
use webauthn_rp::response::register::{CompressedPubKey, DynamicState, StaticState};
use webauthn_rp::response::{
    AuthTransports, AuthenticatorAttachment, AuthenticatorTransport, Backup, CredentialId,
};
use webauthn_rp::{
    AuthenticatedCredential, DiscoverableAuthentication64, DiscoverableAuthenticationServerState,
    DiscoverableCredentialRequestOptions, Registration, RegistrationServerState,
};

use crate::AppState;
use crate::actor::CurrentActor;
use crate::actor::CurrentAttestor;
use p256::ecdsa::SigningKey;

use crate::attestation::AttestationKeyBlob;
use crate::credentials::{
    AttestationKeyState, CredentialKind, HeldCredentials, ensure_removal_leaves_account_usable,
};
use crate::error::ApiError;
use crate::users::{User, UserId};

// ── Why the server does NOT request `prf`, and the client adds it instead ────────────────────────
//
// `docs/passkeys.md` says "the server must request `prf` on the `get()` ceremony
// (`webauthn_rp::request::auth::Extension::prf`)". **That is wrong for this library, and the reason
// is structural, not a bug we can route around.** `webauthn_rp`'s verify refuses an assertion from a
// credential that is *not* PRF-capable when the ceremony requested `prf`
// (`ServerPrfInfo::validate` → `HmacSecretForPrfIncapableCred`), and it does so unconditionally — no
// verification flag relaxes it. In a discoverable sign-in the server cannot know which credential
// will answer, so requesting `prf` globally would break sign-in for every non-PRF authenticator —
// exactly the shape-C credentials that must keep working. So this instance requests nothing, and the
// **client** adds `extensions.prf.eval.first = <constant salt>` (a web constant — the salt is domain
// separation only, per the discoverable-credential ruling, so a fixed value is sound and there is no
// `prf_salt` on [`PasskeyCredential`]). The server then verifies with
// `error_on_unsolicited_extensions: false` on the paths that expect a PRF output, so a PRF-capable
// credential's solicited-by-the-client `hmac-secret` output is accepted while a non-PRF credential's
// empty output is too. The server never sees the PRF output — only the derived KEK the client posts.
// This is reported back to the doc's author as a correction.

// =================================================================================================
// Ledger event kinds
// =================================================================================================

/// A passkey was enrolled. Named as a constant rather than written as a literal at the append site:
/// `apps/web/src/api/labels.test.ts` has two rules that see a `*_KIND` constant and only one that
/// sees a bare string, so a constant is the shape that fails loudly when its label is missing
/// (memory: `ledger-kind-constants-beat-literals`).
pub(crate) const PASSKEY_ENROLLED_KIND: &str = "user.passkey.enrolled";
/// A passkey was revoked by its holder or an administrator.
pub(crate) const PASSKEY_REVOKED_KIND: &str = "user.passkey.revoked";
/// A passkey's display label was changed. The credential itself is untouched.
///
/// Recorded even though the label is display-only and never trusted for anything: the label is
/// what the revocation event names ("chave de acesso «portátil» removida"), so a rename with no
/// record would make two audit lines about the same credential irreconcilable.
pub(crate) const PASSKEY_RENAMED_KIND: &str = "user.passkey.renamed";
/// A passkey completed an authentication ceremony — sign-in or step-up.
pub(crate) const PASSKEY_USED_KIND: &str = "user.passkey.used";
/// An assertion's signature counter did not advance when both the stored and returned values were
/// non-zero.
///
/// **This is a record, not a refusal.** WebAuthn L2 §6.1.1 already skips the check when both values
/// are zero, which is every synced passkey on every assertion forever; and a device that
/// legitimately reset its counter would lock its owner out if this were a gate. So the ceremony
/// succeeds and an operator gets to see the anomaly. See [`note_sign_counter`].
pub(crate) const PASSKEY_COUNTER_REGRESSION_KIND: &str = "user.passkey.counter_regression";

/// Every kind this module can append. `labels.test.ts` asserts that each kind the Rust side emits
/// has a web label, and this list is what a reader checks that assertion against.
///
/// Read only by the test below, deliberately: the production code appends through the individual
/// constants, and a list that the emitters were *obliged* to consult would be one more thing to
/// keep in step rather than one place to look.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) const ALL_PASSKEY_EVENT_KINDS: &[&str] = &[
    PASSKEY_ENROLLED_KIND,
    PASSKEY_REVOKED_KIND,
    PASSKEY_RENAMED_KIND,
    PASSKEY_USED_KIND,
    PASSKEY_COUNTER_REGRESSION_KIND,
];

// =================================================================================================
// Refusal codes
// =================================================================================================

/// The instance has no `platform.public_base_url`, so no RP ID can be validated against anything.
pub(crate) const PASSKEYS_NO_PUBLIC_BASE_URL_CODE: &str = "passkeys_public_base_url_unset";
/// The instance has a `public_base_url` but no operator-chosen `auth.passkeys.rp_id`.
pub(crate) const PASSKEYS_NO_RP_ID_CODE: &str = "passkeys_rp_id_unset";
/// A ceremony could not be completed: unknown, expired, already spent, or issued for a different
/// purpose. Deliberately one code for all four — see [`CeremonyStore::take`].
pub(crate) const PASSKEY_CEREMONY_INVALID_CODE: &str = "passkey_ceremony_invalid";
/// The assertion did not verify, or named a credential this instance does not hold.
pub(crate) const PASSKEY_ASSERTION_INVALID_CODE: &str = "passkey_assertion_invalid";
/// The credential was enrolled under a different RP ID — the operator moved the instance.
pub(crate) const PASSKEY_RP_ID_CHANGED_CODE: &str = "passkey_rp_id_changed";
/// A `public_base_url` host change would strand enrolled credentials and was not confirmed.
pub(crate) const PASSKEY_DOMAIN_CHANGE_CODE: &str = "passkey_domain_change_unconfirmed";
/// A PRF wrap was requested but the session holds no unlocked attestation key to seal — the
/// operator must re-authenticate with their password so the scalar is in memory to be wrapped.
pub(crate) const PASSKEY_PRF_NO_UNLOCKED_KEY_CODE: &str = "passkey_prf_no_unlocked_key";
/// The base64url the client posted as the PRF-derived KEK was unreadable, so nothing could be
/// wrapped. A malformed derivation is refused rather than silently producing a wrap no sign-in can
/// ever open.
pub(crate) const PASSKEY_PRF_SECRET_INVALID_CODE: &str = "passkey_prf_secret_invalid";
/// A rename supplied a label that is empty once trimmed.
///
/// Refused rather than silently defaulted to "Chave de acesso". At enrolment a default is the
/// honest answer to "the user did not name it"; on a rename the user *did* act, and quietly
/// replacing their input with a generic label would show them a credential named something they
/// did not type.
pub(crate) const PASSKEY_NAME_EMPTY_CODE: &str = "passkey_name_empty";

// =================================================================================================
// The RP ID setting
// =================================================================================================

/// The typed phrase an operator transcribes to move this instance to a different host while
/// passkeys are enrolled.
///
/// Fixed, non-localised pt-PT, exactly like `confirmation.rs`'s `ASSINAR TESTE`: the phrase is a
/// token to reproduce, not prose to read, and translating it would mean the same act needs a
/// different phrase per operator locale.
pub const DOMAIN_CHANGE_PHRASE: &str = "PERDER CHAVES";

/// Passkey policy for this deployment.
///
/// One field, and it is the one the library cannot supply: **which RP ID this instance asserts**.
/// Everything else about the ceremony is frozen by the ruling and emitted by
/// `PublicKeyCredentialCreationOptions::passkey` with no configuration, so there is nothing else
/// here for an operator to get wrong.
///
/// Additive and serde-defaulted, and `is_default` keeps the whole `auth` slice off the wire while
/// nothing is configured — so `contracts/settings.json` is unchanged by this feature's arrival.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PasskeySettings {
    /// The Relying Party ID this instance asserts, or `None` while an operator has not chosen one.
    ///
    /// ## It is chosen, never derived
    ///
    /// The tempting one-liner is to strip a label off `public_base_url`'s host to get a
    /// "registrable parent". That is correct for `livros.example.pt` → `example.pt` and
    /// catastrophic for `chancela.pt` → `pt`: a public suffix is not a valid RP ID, server-side
    /// validation passes because nothing server-side knows what a public suffix is, and **every
    /// enrolment then fails in the browser with a `SecurityError` the server never sees**. So the
    /// value is an operator's deliberate choice, checked against the list that knows.
    ///
    /// ## The choice is one-way
    ///
    /// A credential is strictly scoped to the RP ID it was created under and cannot be used with
    /// any other. Choosing the registrable parent (`example.pt`) rather than the host
    /// (`livros.example.pt`) is what lets a later subdomain move survive; choosing the host and
    /// widening later invalidates everything already enrolled. Neither this module nor anything
    /// else can rebind a credential — the credentials live in users' authenticators.
    pub rp_id: Option<String>,
}

impl PasskeySettings {
    /// Whether the slice is untouched, so the enclosing `auth` slice can stay off the wire.
    #[must_use]
    pub fn is_default(&self) -> bool {
        *self == PasskeySettings::default()
    }

    /// Validate the configured RP ID against the instance's public base URL.
    ///
    /// **Both halves of this are ours, and that is the finding rather than a precaution.**
    /// `webauthn_rp` does not cross-check the RP ID against the origin at all — a full ceremony
    /// completes with RP ID `example.com` against origin `https://livros.example.pt` — and no Rust
    /// WebAuthn crate consults the Public Suffix List. With the library performing neither check,
    /// nothing else in the stack catches a mis-set RP ID before it reaches users.
    ///
    /// Refuses, by name:
    ///
    /// - an RP ID that is not the host of `public_base_url` nor a registrable suffix of it;
    /// - an RP ID that **is** a public suffix (`pt`, `co.uk`, `com`), which no browser will accept;
    /// - an RP ID carrying a scheme, port, path, or uppercase — the browser compares an
    ///   already-canonicalised effective domain, so these never match rather than nearly matching;
    /// - an RP ID configured while `public_base_url` is unset, because there is then nothing to
    ///   validate it against and the pair could only be checked once users were already failing.
    pub(crate) fn validate_against(&self, public_base_url: Option<&str>) -> Result<(), ApiError> {
        let Some(rp_id) = self
            .rp_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        else {
            return Ok(()); // Unset is a valid configuration; it just means passkeys are off.
        };
        let refuse = |why: String| {
            Err(ApiError::Unprocessable(format!(
                "auth.passkeys.rp_id must be the host of platform.public_base_url or a registrable \
                 parent of it, because a passkey is permanently bound to the RP ID it was created \
                 under and a wrong value fails inside the browser where this server never sees it: \
                 {why} (got {rp_id:?})"
            )))
        };

        let Some(base) = public_base_url else {
            return Err(ApiError::Unprocessable(
                "auth.passkeys.rp_id cannot be set while platform.public_base_url is unset: the \
                 RP ID is only meaningful relative to the origin this instance is served from, and \
                 validating it against nothing would defer the error to every user's first \
                 enrolment"
                    .to_owned(),
            )
            .with_code(PASSKEYS_NO_PUBLIC_BASE_URL_CODE));
        };

        if rp_id != rp_id.to_lowercase() {
            return refuse(
                "it contains uppercase characters, and the browser compares against an \
                 already-lowercased effective domain"
                    .to_owned(),
            );
        }
        if rp_id.contains("://") || rp_id.contains('/') || rp_id.contains(':') {
            return refuse(
                "it carries a scheme, port or path — an RP ID is a bare domain".to_owned(),
            );
        }
        let Some(host) = host_of(base) else {
            return refuse(format!(
                "platform.public_base_url {base:?} has no host to validate it against"
            ));
        };

        // The suffix rule: the RP ID must be the effective domain or a registrable suffix of it.
        // `example.pt` is a suffix of `livros.example.pt`; `pt` is too, arithmetically — which is
        // exactly why the PSL check below is not redundant with this one.
        if host != rp_id && !host.ends_with(&format!(".{rp_id}")) {
            return refuse(format!("it is neither {host:?} nor a parent domain of it"));
        }

        // **`localhost` is exempt from both list checks, and it has to come first.** It appears in
        // the Public Suffix List as a suffix in its own right, so the check below would refuse it —
        // correctly by the letter of the rule, and wrongly in fact: `localhost` is the one name
        // browsers special-case as a secure, valid RP ID, which is what makes local development
        // possible at all. Ordering this after the check is a silent regression, so it is here.
        if rp_id == "localhost" {
            return Ok(());
        }

        // The Public Suffix List. `psl::suffix_str` answers "what is the public suffix of this
        // name" — so an RP ID that *is* its own public suffix is a public suffix, and no browser
        // will ever accept it.
        if psl::suffix_str(rp_id) == Some(rp_id) {
            return refuse(format!(
                "{rp_id:?} is a public suffix, so no browser will accept it as an RP ID — choose \
                 {host:?} or a registrable parent of it that is not itself a suffix"
            ));
        }
        // A name with no known public suffix is not necessarily wrong (a private network name, an
        // `.internal` deployment) — but it is also not something the list can vouch for, and a
        // silent pass would make this check meaningless on exactly the deployments most likely to
        // get it wrong.
        if psl::suffix_str(rp_id).is_none() {
            return refuse(format!(
                "{rp_id:?} has no recognised public suffix, so it cannot be checked against the \
                 Public Suffix List"
            ));
        }
        Ok(())
    }
}

/// The host of an `https://…` base URL, lowercased and without its port.
///
/// Deliberately not a URL-crate parse: `validate_public_base_url` in `settings.rs` has already
/// refused everything that would make parsing interesting (userinfo, whitespace, query, fragment,
/// non-https), so this reads the one component that survives.
fn host_of(base_url: &str) -> Option<String> {
    let rest = base_url.trim().strip_prefix("https://")?;
    let authority = rest.split('/').next().unwrap_or(rest);
    let host = authority.rsplit_once(':').map_or(authority, |(h, _)| h);
    if host.is_empty() {
        None
    } else {
        Some(host.to_lowercase())
    }
}

/// The RP ID and expected origin this instance will run a ceremony with, or a named refusal.
///
/// **The origin is `public_base_url`'s and is never widened by CORS.** `CHANCELA_CORS_ALLOWED_ORIGINS`
/// exists so a companion app can call the API; letting one of those satisfy a WebAuthn origin check
/// would discard the phishing binding that is the entire point of the ceremony.
pub(crate) struct RpContext {
    pub(crate) rp_id: RpId,
    /// The RP ID as configured, for storing on a credential and comparing at assertion time.
    pub(crate) rp_id_str: String,
    /// **The expected origin, and it must be passed explicitly on every verification.**
    ///
    /// This is not optional plumbing. `RegistrationVerificationOptions::allowed_origins` and its
    /// authentication twin default to *empty*, and an empty list does not mean "any origin" — it
    /// means the library derives one from the **RP ID**. With the RP ID set to the registrable
    /// parent (`example.pt`), which is the ruling's recommended choice precisely so a subdomain
    /// move survives, the derived origin is `https://example.pt` while the instance is actually
    /// served from `https://livros.example.pt`. Every ceremony then fails.
    ///
    /// The failure is loud, so the danger is not that it ships broken — it is the fix someone
    /// reaches for. Setting the RP ID to the host makes the derived origin correct by coincidence,
    /// and the origin check silently becomes "whatever the RP ID says" rather than "where this
    /// instance is served from". Those coincide only until they do not.
    pub(crate) allowed_origins: [String; 1],
}

/// Resolve the ceremony context from live settings, refusing by name when it is not configured.
pub(crate) async fn rp_context(state: &AppState) -> Result<RpContext, ApiError> {
    let (rp_id, base) = {
        let settings = state.settings.read().await;
        (
            settings.auth.passkeys.rp_id.clone(),
            settings.platform.resolved_public_base_url(),
        )
    };
    let Some(origin) = base.as_deref().and_then(origin_of) else {
        return Err(ApiError::Unprocessable(
            "as chaves de acesso exigem que o endereço público desta instância esteja configurado \
             (platform.public_base_url)"
                .to_owned(),
        )
        .with_code(PASSKEYS_NO_PUBLIC_BASE_URL_CODE));
    };
    let Some(rp_id) = rp_id.map(|s| s.trim().to_owned()).filter(|s| !s.is_empty()) else {
        return Err(ApiError::Unprocessable(
            "as chaves de acesso exigem que um administrador escolha o domínio a que ficarão \
             associadas (auth.passkeys.rp_id). Esta escolha é definitiva: uma chave de acesso não \
             pode ser transferida para outro domínio."
                .to_owned(),
        )
        .with_code(PASSKEYS_NO_RP_ID_CODE));
    };
    let domain = AsciiDomain::try_from(rp_id.clone()).map_err(|_| {
        ApiError::Unprocessable(format!(
            "auth.passkeys.rp_id {rp_id:?} is not a valid domain"
        ))
    })?;
    Ok(RpContext {
        rp_id: RpId::Domain(domain),
        rp_id_str: rp_id,
        allowed_origins: [origin],
    })
}

/// The serialized origin of an `https://…` base URL — scheme, host and any non-default port, with
/// no path and no trailing slash.
///
/// That is the exact string a browser puts in `clientDataJSON.origin`, and the comparison the
/// library makes is equality rather than a prefix or substring test. A trailing slash or a retained
/// path would simply never match, so this trims both.
fn origin_of(base_url: &str) -> Option<String> {
    let rest = base_url.trim().strip_prefix("https://")?;
    let authority = rest.split('/').next().unwrap_or(rest);
    if authority.is_empty() {
        return None;
    }
    // The host is lowercased (browsers canonicalise it) while an explicit port is left alone.
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) && !port.is_empty() => {
            (host, Some(port))
        }
        _ => (authority, None),
    };
    if host.is_empty() {
        return None;
    }
    Some(match port {
        // 443 is the default for https and a browser omits it from the origin, so keeping it here
        // would produce a string no client ever sends.
        Some("443") | None => format!("https://{}", host.to_lowercase()),
        Some(port) => format!("https://{}:{port}", host.to_lowercase()),
    })
}

// =================================================================================================
// The stored credential
// =================================================================================================

/// One enrolled passkey, stored on the **user record** rather than the credential store.
///
/// A WebAuthn public key is not a secret. `CredentialMode::TwoFactorTotp` exists in
/// `secretstore_persist.rs` because a TOTP shared secret *is* one, and that store is write-only
/// with fail-closed reads by design; putting a public key behind it would mean every render of the
/// security screen reads through a door built to refuse. This is the same kind of thing as
/// `AttestationKeyBlob::public_key_sec1`, which already sits in the clear on this record.
///
/// **Every field is `#[serde(default)]`-reachable and the struct is additive**, because the store
/// *skips rows it cannot parse* — so a non-defaulted field is not a deserialisation error, it is
/// silent data loss on every pre-existing user (memory: `store-skips-unparseable-rows`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeyCredential {
    /// Base64url of the raw credential id, as the authenticator minted it.
    ///
    /// Taken from `authData`, never from the client-supplied `id`/`rawId` — `webauthn_rp`'s
    /// `Registration` type does not accept those fields at all, which is one of the reasons it was
    /// chosen.
    pub credential_id: String,
    /// Base64url of the opaque per-user handle this credential was enrolled against.
    ///
    /// Not the user id. It is random, stable for one account across all of its credentials, and it
    /// is what a discoverable sign-in returns instead of a username — so it must never be
    /// something an observer could map back to anything else.
    pub user_handle: String,
    /// Base64url of `StaticState::encode()` — the COSE public key plus the registration-time
    /// extension outputs that authentication needs. Stored as the library's own encoding rather
    /// than a hand-rolled one so there is no second parser of this data.
    pub static_state: String,
    /// The last signature counter this credential returned. Zero forever for a synced passkey.
    #[serde(default)]
    pub sign_count: u32,
    /// Whether this credential has ever produced a user-verified assertion.
    #[serde(default)]
    pub user_verified: bool,
    /// Backup eligibility and state, as a single three-state value — the illegal BE=0/BS=1
    /// combination is unrepresentable rather than merely rejected.
    #[serde(default)]
    pub backup: PasskeyBackup,
    /// Whether the credential lives on a platform authenticator, a roaming one, or did not say.
    #[serde(default)]
    pub attachment: PasskeyAttachment,
    /// **The RP ID this credential was enrolled under.**
    ///
    /// Stored per credential rather than read from settings at assertion time, so that after an
    /// operator moves the instance the refusal can *name the change* instead of reading as "my
    /// passkey is broken". Nothing can migrate a credential between RP IDs.
    pub rp_id: String,
    /// Transport hints, stored as the library's own single-byte encoding of `AuthTransports`.
    ///
    /// One representation rather than two. The obvious alternative — a `Vec<String>` of wire names
    /// — would need a hand-written mapping in both directions, and the direction that matters is
    /// the one that feeds `excludeCredentials` back to the authenticator, where a name this
    /// codebase spelled slightly differently is a credential silently overwritten. The display
    /// names are derived from this on the way out ([`transport_names`]) and never stored.
    #[serde(default)]
    pub transports: u8,
    /// The user-supplied label. **Never trusted for anything but display** — it is chosen by
    /// whoever enrolled the credential and is echoed back to them.
    pub name: String,
    /// RFC 3339 stamp of enrolment.
    pub created_at: String,
    /// RFC 3339 stamp of the last successful assertion, or `None` if it has never been used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<String>,
    /// Whether the authenticator provisioned an `hmac-secret` at creation, i.e. whether this
    /// credential could ever carry a PRF wrap.
    ///
    /// Recorded at enrolment because it can only be *asked for* at enrolment: an authenticator that
    /// was not asked to create the secret cannot be asked later. A credential enrolled without this
    /// is permanently incapable of holding a [`prf_wrap`](Self::prf_wrap).
    #[serde(default)]
    pub prf_capable: bool,
    /// A **second wrap of the account's attestation scalar**, sealed under the KEK derived from this
    /// credential's PRF output — the thing that makes a passwordless sign-in able to attest.
    ///
    /// `None` for a credential that never completed the PRF-wrap ceremony ([`finish_prf_wrap`]): a
    /// non-PRF authenticator, an account with no attestation key to wrap, or one enrolled before this
    /// path shipped. Such a credential signs the user in and the session is asked for the password at
    /// first attestation — shape C's degraded arm.
    ///
    /// **It is an *additional* wrap and never the only one** (`docs/passkeys.md`, Invariant 2). The
    /// user record keeps its password wrap regardless, so if this credential's PRF output ever
    /// changes — a lost device, a revoked credential, an OS update that moves the output (iOS 18.4) —
    /// the unlock here simply fails and the sign-in degrades to the password. Stored as a full
    /// [`AttestationKeyBlob`] so the same fingerprint proves it wraps the same scalar; the KEK is
    /// derived from the PRF output client-side and never stored. `#[serde(default)]` like every field
    /// here, because the store skips rows it cannot parse (memory: `store-skips-unparseable-rows`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prf_wrap: Option<AttestationKeyBlob>,
}

/// Backup eligibility and state as one value.
///
/// Three states rather than two independent booleans, so `BE=0, BS=1` — "not eligible for backup,
/// but backed up" — cannot be written down at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PasskeyBackup {
    /// Device-bound: losing the device loses the credential.
    #[default]
    NotEligible,
    /// Eligible for backup but not currently backed up.
    Eligible,
    /// Synced. This is the credential that survives a lost phone, and also the one whose signature
    /// counter is zero forever.
    Exists,
}

impl From<Backup> for PasskeyBackup {
    fn from(value: Backup) -> Self {
        match value {
            Backup::NotEligible => PasskeyBackup::NotEligible,
            Backup::Eligible => PasskeyBackup::Eligible,
            Backup::Exists => PasskeyBackup::Exists,
        }
    }
}

impl From<PasskeyBackup> for Backup {
    fn from(value: PasskeyBackup) -> Self {
        match value {
            PasskeyBackup::NotEligible => Backup::NotEligible,
            PasskeyBackup::Eligible => Backup::Eligible,
            PasskeyBackup::Exists => Backup::Exists,
        }
    }
}

/// Where the credential lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PasskeyAttachment {
    /// The client did not say.
    #[default]
    Unknown,
    /// Built into the device (Windows Hello, Touch ID, Android).
    Platform,
    /// A roaming authenticator (a security key, or a phone by hybrid transport).
    CrossPlatform,
}

impl From<AuthenticatorAttachment> for PasskeyAttachment {
    fn from(value: AuthenticatorAttachment) -> Self {
        match value {
            AuthenticatorAttachment::None => PasskeyAttachment::Unknown,
            AuthenticatorAttachment::Platform => PasskeyAttachment::Platform,
            AuthenticatorAttachment::CrossPlatform => PasskeyAttachment::CrossPlatform,
        }
    }
}

impl From<PasskeyAttachment> for AuthenticatorAttachment {
    fn from(value: PasskeyAttachment) -> Self {
        match value {
            PasskeyAttachment::Unknown => AuthenticatorAttachment::None,
            PasskeyAttachment::Platform => AuthenticatorAttachment::Platform,
            PasskeyAttachment::CrossPlatform => AuthenticatorAttachment::CrossPlatform,
        }
    }
}

impl PasskeyCredential {
    /// The raw credential id, or `None` if the stored base64url is unreadable.
    #[must_use]
    pub(crate) fn raw_id(&self) -> Option<Vec<u8>> {
        B64URL.decode(&self.credential_id).ok()
    }

    /// The stored transport hints, decoded back through the library's own codec.
    fn transport_set(&self) -> AuthTransports {
        AuthTransports::decode(self.transports).unwrap_or_else(|_| {
            AuthTransports::decode(0)
                .unwrap_or_else(|_| unreachable!("an empty AuthTransports is always decodable"))
        })
    }

    /// The stored `DynamicState`, reassembled for a verification.
    fn dynamic_state(&self) -> DynamicState {
        DynamicState {
            user_verified: self.user_verified,
            backup: self.backup.into(),
            sign_count: self.sign_count,
            authenticator_attachment: self.attachment.into(),
        }
    }
}

// =================================================================================================
// The wire view
// =================================================================================================

/// One credential as the security screen sees it.
///
/// **Its own endpoint, and deliberately not a `UserView` field.** `UserView` is the `user.created` /
/// `user.updated` ledger payload, so a field added there moves the payload digest of every future
/// user event and sweeps 23 files carrying a `UserView` literal, three of them contract fixtures
/// asserted from both ends. None of that buys anything: the `has_*` booleans exist because the
/// *roster* needs them cross-user, and nothing about a passkey belongs on a roster row.
#[derive(Debug, Clone, Serialize)]
pub struct PasskeyView {
    pub credential_id: String,
    pub name: String,
    pub created_at: String,
    /// RFC 3339 stamp of the last successful assertion, or `null` if it has never been used.
    ///
    /// **Always emitted, deliberately — no `skip_serializing_if` here.** It carries one on the
    /// *stored* [`PasskeyCredential`], where an absent key keeps `users.json` small and nothing
    /// compares key sets. On the wire it would be a latent defect: `assert_shape` in the contract
    /// harness does strict **key-set equality** per object, so a field that is present or absent
    /// depending on the row makes the key set vary *between elements of the same array*. A list
    /// whose first credential happened to be never-used would fail the contract journey, and a
    /// list whose first credential happened to be used would pass — which is a test whose verdict
    /// depends on fixture ordering rather than on the shape.
    ///
    /// `contracts/pairing.json`'s `revoked_at` is the in-tree precedent: nullable, always present.
    pub last_used_at: Option<String>,
    pub rp_id: String,
    /// `false` once an operator has moved the instance to a different RP ID. The credential is
    /// still listed — it is still enrolled, and the user needs to be able to see and remove it —
    /// but it can no longer authenticate anything.
    pub usable: bool,
    pub backup: PasskeyBackup,
    pub attachment: PasskeyAttachment,
    pub transports: Vec<String>,
    pub prf_capable: bool,
    /// **Whether this credential actually signs in without a password**, i.e. whether it holds a PRF
    /// wrap of the attestation scalar. This — not [`prf_capable`](Self::prf_capable) — is what the
    /// security screen keys the signing-note copy on: a credential that can attest passwordless says
    /// «sem palavra-passe», one that falls back says the password is still asked. `prf_capable`
    /// records only that the *authenticator* could provision the secret; a capable authenticator
    /// whose PRF-wrap ceremony never completed still falls back, and the copy must reflect the wrap
    /// that exists, not the capability that might have.
    pub unlocks_without_password: bool,
    pub sign_count: u32,
}

impl PasskeyView {
    fn of(credential: &PasskeyCredential, current_rp_id: Option<&str>) -> Self {
        PasskeyView {
            credential_id: credential.credential_id.clone(),
            name: credential.name.clone(),
            created_at: credential.created_at.clone(),
            last_used_at: credential.last_used_at.clone(),
            rp_id: credential.rp_id.clone(),
            usable: current_rp_id.is_some_and(|rp| rp == credential.rp_id),
            backup: credential.backup,
            attachment: credential.attachment,
            transports: transport_names(credential.transport_set()),
            prf_capable: credential.prf_capable,
            unlocks_without_password: credential.prf_wrap.is_some(),
            sign_count: credential.sign_count,
        }
    }
}

/// `GET /v1/users/{id}/passkeys` response.
#[derive(Debug, Clone, Serialize)]
pub struct PasskeyListView {
    pub passkeys: Vec<PasskeyView>,
    /// The RP ID this instance currently asserts, or `null` while passkeys are unconfigured. The
    /// client needs it to explain a `usable: false` row without inventing a reason.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rp_id: Option<String>,
    /// Whether enrolment is available at all right now — i.e. whether `public_base_url` and
    /// `rp_id` are both configured. `false` means the button is disabled with an explanation, not
    /// that the user has done anything wrong.
    pub enrolment_available: bool,
}

// =================================================================================================
// The ceremony (challenge) store
// =================================================================================================

/// What a ceremony was started for.
///
/// **This is the replay boundary, and it is the reason the enum exists rather than a boolean.** A
/// passkey assertion captured during a sign-in is a valid, correctly-signed assertion; the only
/// thing preventing it from being replayed into a factory reset is that the challenge it answers
/// was issued for [`CeremonyPurpose::SignIn`] and the factory reset demands one issued for
/// [`CeremonyPurpose::StepUp`]. The purpose is part of the lookup, exactly as it is in
/// [`crate::auth_token::AuthTokenPurpose`], so a cross-purpose presentation is not a weaker match —
/// it is not a match at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CeremonyPurpose {
    /// Enrolling a new credential for a known, already-authenticated user.
    Registration,
    /// Signing in. Satisfies no gate beyond minting a session.
    SignIn,
    /// Re-authenticating for a destructive operation. **Never satisfied by a sign-in challenge.**
    StepUp,
    /// Obtaining a PRF output to seal a *second* wrap of the attestation scalar, immediately after
    /// enrolment. A `get()` because `webauthn_rp` cannot evaluate PRF at `create()`; bound to the
    /// session's user and never able to mint a session, so it is not a sign-in by another door.
    PrfWrap,
}

impl CeremonyPurpose {
    const fn as_str(self) -> &'static str {
        match self {
            CeremonyPurpose::Registration => "registration",
            CeremonyPurpose::SignIn => "sign_in",
            CeremonyPurpose::StepUp => "step_up",
            CeremonyPurpose::PrfWrap => "prf_wrap",
        }
    }
}

/// The ceremony state a challenge maps to.
enum CeremonyState {
    Registration(RegistrationServerState<USER_HANDLE_MAX_LEN>),
    Authentication(DiscoverableAuthenticationServerState),
}

/// One outstanding ceremony.
struct CeremonyRecord {
    purpose: CeremonyPurpose,
    state: CeremonyState,
    /// The user this ceremony is bound to. `Some` for registration and step-up (both start from an
    /// authenticated session); `None` for sign-in, where the whole point is that the server was
    /// never told who is signing in.
    ///
    /// **For step-up this is checked, not trusted.** A redeemed challenge proves the ceremony was
    /// started; it does not prove *who* started it, so the subject is compared against the acting
    /// user before the assertion counts (memory: `token-redemption-proves-purpose-not-identity`).
    user_id: Option<UserId>,
    expires_at: OffsetDateTime,
}

/// Outstanding WebAuthn ceremonies, keyed by the challenge the client will echo back.
///
/// Process-local and never persisted, exactly like [`crate::session::PendingTwoFactor`]: a restart
/// or failover mid-ceremony loses it and the user retries, which is the fail-closed direction.
///
/// The library offers its own `FixedCapHashSet` for this, and it is deliberately not used. That
/// collection keys on the challenge alone and has no notion of *what the ceremony was for*, so a
/// sign-in state and a step-up state would be interchangeable inside it — which is precisely the
/// replay this feature must not permit. Enabling `serializable_server_state` turns the library's
/// ceremony state into bytes we own, and this store adds the purpose and subject binding around it.
///
/// Keyed on the library's own `SentChallenge` — a `u128` — rather than on a re-encoding of it.
/// Both the ceremony state and the parsed response yield that value directly, so there is no
/// encoding for the two sides to disagree about.
#[derive(Default)]
pub struct CeremonyStore {
    records: HashMap<u128, CeremonyRecord>,
}

/// How long a ceremony stays redeemable.
///
/// The library's own five-minute timeout is inside the encoded state and is enforced by `verify`;
/// this is the store's independent bound, so an entry cannot outlive its usefulness even if it is
/// never presented.
const CEREMONY_TTL_SECS: i64 = 5 * 60;

/// The largest number of outstanding ceremonies before new ones are refused.
///
/// A ceremony can be started by an unauthenticated caller (sign-in), so this is a bound on what a
/// stranger can make this process allocate.
const MAX_CEREMONIES: usize = 10_000;

impl CeremonyStore {
    /// Record a ceremony, returning the challenge that indexes it.
    fn insert(
        &mut self,
        challenge: u128,
        purpose: CeremonyPurpose,
        state: CeremonyState,
        user_id: Option<UserId>,
        now: OffsetDateTime,
    ) -> Result<(), ApiError> {
        self.prune(now);
        if self.records.len() >= MAX_CEREMONIES {
            return Err(ApiError::TooManyRequests(
                "demasiadas cerimónias em curso — tente novamente dentro de momentos".to_owned(),
            ));
        }
        self.records.insert(
            challenge,
            CeremonyRecord {
                purpose,
                state,
                user_id,
                expires_at: now + time::Duration::seconds(CEREMONY_TTL_SECS),
            },
        );
        Ok(())
    }

    /// Take the ceremony for `challenge`, **removing it first and unconditionally**.
    ///
    /// The record is gone before this function decides whether it was any good, on every path
    /// including the expired and wrong-purpose ones. That ordering is the single-use guarantee: a
    /// caller cannot structure its code so that a failure mid-ceremony leaves the challenge
    /// replayable, because by the time it holds a record the challenge is already spent. A second
    /// presentation finds nothing.
    ///
    /// Unknown, expired, already spent and issued-for-another-purpose all return the same refusal.
    /// Distinguishing them would tell a caller whether a given challenge is live, and — for the
    /// step-up path specifically — whether a captured sign-in challenge is worth replaying.
    fn take(
        &mut self,
        challenge: u128,
        purpose: CeremonyPurpose,
        now: OffsetDateTime,
    ) -> Result<CeremonyRecord, ApiError> {
        let Some(record) = self.records.remove(&challenge) else {
            return Err(ceremony_invalid());
        };
        if record.purpose != purpose || now >= record.expires_at {
            return Err(ceremony_invalid());
        }
        Ok(record)
    }

    fn prune(&mut self, now: OffsetDateTime) {
        self.records.retain(|_, record| now < record.expires_at);
    }

    /// Drop every outstanding ceremony. Called when sessions are invalidated wholesale.
    pub fn clear(&mut self) {
        self.records.clear();
    }

    /// How many ceremonies are outstanding. Test and diagnostics only.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether no ceremony is outstanding.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

/// The single uniform ceremony refusal. See [`CeremonyStore::take`].
fn ceremony_invalid() -> ApiError {
    ApiError::Unauthorized(
        "cerimónia de chave de acesso inválida ou expirada; volte a iniciar".to_owned(),
    )
    .with_code(PASSKEY_CEREMONY_INVALID_CODE)
}

/// The single uniform assertion refusal.
///
/// One message for a signature that does not verify, a credential this instance does not hold, a
/// credential belonging to a different account, and a malformed response. A caller learns that the
/// assertion was not accepted and nothing else — in particular not whether a given credential id
/// exists here, which would be an enumeration oracle over the very thing discoverable credentials
/// were chosen to avoid building.
fn assertion_invalid() -> ApiError {
    ApiError::Unauthorized("chave de acesso não reconhecida".to_owned())
        .with_code(PASSKEY_ASSERTION_INVALID_CODE)
}

// =================================================================================================
// Ceremony construction
// =================================================================================================

/// The extensions requested at enrolment.
///
/// `prf` is requested with [`ExtensionInfo::AllowDontEnforceValue`], and both halves of that choice
/// matter:
///
/// - **Requested**, because CTAP2 provisions the `hmac-secret` an authenticator would later derive
///   PRF from *at creation time*. A credential enrolled without asking can never be asked again —
///   so not requesting it here would permanently foreclose the PRF path for every passkey enrolled
///   before someone noticed, and no migration exists.
/// - **Not enforced**, because a non-PRF authenticator must still enrol. The ruling's shape C is
///   "PRF when available, degrade with the degradation stated at enrolment"; enforcing the value
///   would turn that degradation into a refusal.
///
/// The library refuses `prf` combined with anything less than `userVerification: "required"`, which
/// `passkey()` already sets — so the seed the PRF output would be derived from is the UV seed, and
/// Invariant 1 holds by construction rather than by a check someone has to remember.
fn registration_extensions() -> webauthn_rp::request::register::Extension {
    webauthn_rp::request::register::Extension {
        prf: Some(ExtensionInfo::AllowDontEnforceValue),
        ..Default::default()
    }
}

/// The challenge that indexes a ceremony, as the library's own value.
fn challenge_key<C: TimedCeremony>(ceremony: &C) -> u128 {
    ceremony.sent_challenge().0
}

// =================================================================================================
// Verification outcomes
// =================================================================================================

/// What a verified assertion established.
pub(crate) struct VerifiedAssertion {
    /// The account the credential belongs to.
    pub(crate) user_id: UserId,
    /// The credential's display name, for a ledger justification that names the label rather than
    /// the id.
    pub(crate) name: String,
    /// **Whether the authenticator performed user verification for this specific assertion.**
    ///
    /// Not the credential's sticky "has ever been user-verified" flag — that is a different
    /// question and answering it here would be the bug. This drives two decisions:
    ///
    /// - a UV assertion is already possession *and* verification, so demanding a TOTP code after it
    ///   is theatre and no `PendingTwoFactor` is raised;
    /// - a UV-less assertion derives a **different** PRF secret (CTAP2.1 keeps `CredRandomWithUV`
    ///   and `CredRandomWithoutUV` separately), so it can authenticate but can never unwrap. The
    ///   correct response is "ask for the password", never "wrong credential" — the latter is a
    ///   diagnostic dead end in which the user is told their credential is bad when it was fine.
    pub(crate) user_verified: bool,
    /// **The attestation signing key, unlocked from this credential's PRF wrap** — `Some` only when a
    /// usable PRF output was supplied (present, UV set) *and* it opened
    /// [`PasskeyCredential::prf_wrap`]. `None` — no PRF output, UV clear, no wrap, or an output that
    /// did not open the wrap — is the shape-C degradation: the assertion still authenticates, and the
    /// session it mints is asked for the password at first attestation. A failed unlock **never**
    /// fails the sign-in; it just declines to hand back a key, which is the whole point of keeping
    /// the password wrap alongside (Invariant 2).
    pub(crate) unlocked_key: Option<SigningKey>,
}

/// Verify a discoverable authentication assertion against this instance's enrolled credentials.
///
/// Resolves the credential from the assertion itself — the raw credential id and the user handle,
/// both of which the library derives rather than trusting the client's `id` field — and refuses
/// uniformly for every way that can fail.
async fn verify_authentication(
    state: &AppState,
    ceremony: DiscoverableAuthenticationServerState,
    assertion: &DiscoverableAuthentication64,
    rp: &RpContext,
    prf_secret: Option<&str>,
    allow_prf_extension: bool,
    now: OffsetDateTime,
) -> Result<VerifiedAssertion, ApiError> {
    let raw_id = assertion.raw_id();
    let credential_id = B64URL.encode(raw_id.as_ref());
    let user_handle = assertion.response().user_handle();

    // Locate the credential. A miss here is indistinguishable from a bad signature by design.
    let (user_id, stored) = {
        let users = state.users.read().await;
        let found = users.values().find_map(|user| {
            user.passkeys
                .iter()
                .find(|c| c.credential_id == credential_id)
                .map(|c| (user.id, c.clone()))
        });
        found.ok_or_else(assertion_invalid)?
    };

    // The credential was enrolled under a different RP ID: an operator moved the instance. This is
    // the one assertion failure that gets its own code, because "the administrator moved this
    // instance and your passkey cannot come with it" and "your passkey is broken" send a user to
    // two entirely different places, and only the first is true.
    if stored.rp_id != rp.rp_id_str {
        return Err(ApiError::Unauthorized(format!(
            "esta chave de acesso foi criada para o domínio {:?} e esta instância responde agora \
             em {:?}. Uma chave de acesso não pode ser transferida entre domínios: remova-a e crie \
             uma nova.",
            stored.rp_id, rp.rp_id_str
        ))
        .with_code(PASSKEY_RP_ID_CHANGED_CODE));
    }

    let stored_handle = decode_user_handle(&stored.user_handle).ok_or_else(assertion_invalid)?;
    if &stored_handle != user_handle {
        return Err(assertion_invalid());
    }

    let static_state = decode_static_state(&stored)?;
    let previous_sign_count = stored.sign_count;
    let raw_id_bytes = stored.raw_id().ok_or_else(assertion_invalid)?;
    let mut credential = AuthenticatedCredential::new(
        CredentialId::decode(raw_id_bytes.as_slice()).map_err(|_| assertion_invalid())?,
        &stored_handle,
        static_state,
        stored.dynamic_state(),
    )
    .map_err(|_| assertion_invalid())?;

    // The counter is `Ignore`d rather than enforced, and the regression is recorded below.
    // `Fail` would lock out the owner of a device that legitimately reset its counter, and there is
    // no counter at all on a synced passkey — every assertion from iCloud Keychain and Google
    // Password Manager returns zero, forever.
    let options = AuthenticationVerificationOptions::<String, String> {
        // **Explicit, and never widened by CORS.** See `RpContext::allowed_origins` for why the
        // empty default is wrong here rather than merely lax. `CHANCELA_CORS_ALLOWED_ORIGINS`
        // exists so a companion app can call this API; letting one of those satisfy a WebAuthn
        // origin check would discard the phishing binding that is the whole point of the ceremony,
        // so that setting is deliberately not consulted.
        allowed_origins: &rp.allowed_origins,
        // On the paths that expect a PRF output (sign-in, PRF-wrap) the client adds `prf` and a
        // PRF-capable authenticator answers with a solicited-by-the-client `hmac-secret` output. The
        // library would otherwise refuse it as unsolicited, so those paths pass `true` here; step-up
        // adds no extension and stays strict (`false`). A non-PRF credential returns no output and is
        // accepted either way — see the module header for why the server cannot request `prf` itself.
        error_on_unsolicited_extensions: !allow_prf_extension,
        sig_counter_enforcement: SignatureCounterEnforcement::Ignore,
        update_uv: true,
        ..Default::default()
    };
    ceremony
        .verify(&rp.rp_id, assertion, &mut credential, &options)
        .map_err(|error| {
            // Same posture as the registration path: uniform on the wire, specific in the log.
            // `UserNotVerified` in particular is worth an operator seeing — it means the
            // authenticator skipped user verification, which is a *device* problem, not a wrong
            // credential, and the uniform refusal cannot say so without becoming an oracle.
            tracing::warn!(
                target: "chancela::passkeys",
                error = ?error,
                "passkey authentication ceremony failed verification"
            );
            assertion_invalid()
        })?;

    // Past this point the assertion is verified, so the authenticator data is authenticated bytes
    // rather than client input, and reading the UV flag and counter out of it is safe. This is the
    // *per-assertion* UV bit, which is a different question from the credential's sticky flag.
    let auth_data = AuthenticatorData::try_from(assertion.response().authenticator_data())
        .map_err(|_| assertion_invalid())?;
    let user_verified = auth_data.flags().user_verified;
    let returned_sign_count = auth_data.sign_count();

    let dynamic = credential.dynamic_state();
    let name = stored.name.clone();
    persist_assertion(state, user_id, &credential_id, dynamic, user_verified, now).await?;
    note_sign_counter(
        state,
        user_id,
        &name,
        previous_sign_count,
        returned_sign_count,
    )
    .await;

    // The PRF-derived unwrap. Only attempted for a **user-verified** assertion — a UV-less one
    // derives a different PRF secret (CTAP2.1's `CredRandomWithoutUV`), so the KEK would not open the
    // wrap and the failure would be indistinguishable from a wrong output. A missing wrap, a missing
    // secret, or an output that does not open the wrap all land in the same place: `None`, a sign-in
    // that authenticated but did not unlock, degrading to the password at first attestation. **A
    // failed unlock is never a failed sign-in** — that is the whole reason the password wrap is kept.
    let unlocked_key = match (prf_secret, user_verified, &stored.prf_wrap) {
        (Some(secret), true, Some(prf_wrap)) => match prf_wrap.unlock(secret) {
            Ok(key) => Some(key),
            Err(error) => {
                tracing::warn!(
                    target: "chancela::passkeys",
                    error = %error,
                    "a PRF output did not open the stored wrap; degrading this sign-in to the \
                     password at first attestation"
                );
                None
            }
        },
        _ => None,
    };

    Ok(VerifiedAssertion {
        user_id,
        name,
        user_verified,
        unlocked_key,
    })
}

/// Rebuild the library's `StaticState` from what is on the record.
fn decode_static_state(stored: &PasskeyCredential) -> Result<StoredPublicKey, ApiError> {
    let bytes = B64URL
        .decode(&stored.static_state)
        .map_err(|_| assertion_invalid())?;
    StaticState::decode(bytes.as_slice()).map_err(|_| assertion_invalid())
}

/// The shape `StaticState::decode` produces: fixed-size arrays for the curve keys it knows the
/// length of, a `Vec` for RSA. Spelled out once so the two places that name it cannot drift.
type StoredPublicKey = StaticState<CompressedPubKey<[u8; 32], [u8; 32], [u8; 48], Vec<u8>>>;

/// Write back what the assertion changed: the counter, the sticky UV flag, and the last-used stamp.
async fn persist_assertion(
    state: &AppState,
    user_id: UserId,
    credential_id: &str,
    dynamic: DynamicState,
    user_verified: bool,
    now: OffsetDateTime,
) -> Result<(), ApiError> {
    let stamp = now.format(&Rfc3339).unwrap_or_default();
    let updated = {
        let mut users = state.users.write().await;
        let Some(user) = users.get_mut(&user_id) else {
            return Ok(());
        };
        let Some(credential) = user
            .passkeys
            .iter_mut()
            .find(|c| c.credential_id == credential_id)
        else {
            return Ok(());
        };
        credential.sign_count = dynamic.sign_count;
        credential.user_verified = credential.user_verified || user_verified;
        credential.backup = dynamic.backup.into();
        credential.last_used_at = Some(stamp);
        user.clone()
    };
    crate::users::persist_user(state, &updated).await
}

/// Record a signature-counter regression, without failing anything.
///
/// The check applies **only when both the stored and the returned counter are non-zero**. WebAuthn
/// L2 §6.1.1 says that when both are zero the authenticator does not implement the counter and the
/// check is skipped — which covers every synced passkey in existence, since a credential replicated
/// across devices has no single coherent counter to increment. Treating a constant zero as
/// suspicious would flag every iCloud Keychain and Google Password Manager passkey on every
/// assertion.
async fn note_sign_counter(
    state: &AppState,
    user_id: UserId,
    credential_name: &str,
    previous: u32,
    returned: u32,
) {
    if previous == 0 || returned == 0 || returned > previous {
        return;
    }
    let Some(user) = state.users.read().await.get(&user_id).cloned() else {
        return;
    };
    let justification = format!(
        "o contador de assinaturas da chave de acesso «{credential_name}» não avançou \
         ({previous} → {returned})"
    );
    let _ = crate::users::record_passkey_event(
        state,
        &user,
        PASSKEY_COUNTER_REGRESSION_KIND,
        &justification,
    )
    .await;
}

// =================================================================================================
// Step-up
// =================================================================================================

/// A passkey assertion offered as a step-up proof.
///
/// Carried on [`crate::data::ReAuth`] beside `password` and `recovery_phrase`, which is the
/// existing "with what" axis. It is deliberately **not** a new
/// [`crate::confirmation::ConfirmationStrictness`] rung: that ladder answers *how hard*, and adding
/// a rung would mean every deployment that had chosen a strictness level silently got a different
/// one. The precedent is [`crate::confirmation::PairingConfirmationMethod`].
#[derive(Deserialize)]
pub struct PasskeyAssertionProof {
    /// The `PublicKeyCredential` the browser produced, verbatim, as JSON.
    ///
    /// Passed through rather than re-modelled: the library's relaxed deserialiser is the one that
    /// knows which of these fields may be absent and which encodings are acceptable, and a
    /// hand-rolled intermediate shape would be a second parser of attacker-controlled input.
    pub credential: serde_json::Value,
}

/// Whether a supplied passkey assertion satisfied step-up.
///
/// A three-state value rather than a boolean, because "none was offered" and "one was offered and
/// did not verify" must be distinguishable *to the caller's logging* while producing the identical
/// uniform `403` to the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PasskeyStepUp {
    /// No assertion was supplied.
    NotSupplied,
    /// An assertion was supplied and verified against the acting user's own credential, answering
    /// a challenge issued for [`CeremonyPurpose::StepUp`].
    Verified,
    /// An assertion was supplied and did not satisfy the gate.
    Refused,
}

impl PasskeyStepUp {
    /// Whether this outcome satisfies the gate.
    pub(crate) const fn is_verified(self) -> bool {
        matches!(self, PasskeyStepUp::Verified)
    }
}

/// Verify the passkey arm of a step-up re-auth for `username`.
///
/// **Three bindings, and dropping any one of them reopens the replay.**
///
/// 1. The challenge must have been issued for [`CeremonyPurpose::StepUp`]. A sign-in challenge is
///    not a weaker match, it is not a match — so an assertion captured at sign-in answers nothing.
/// 2. The challenge is spent by the attempt, not by the success.
/// 3. The credential that signed must belong to **the acting user**. Redeeming the challenge proves
///    only that *a* step-up ceremony was started, never by whom; without this check any user's
///    passkey would satisfy any other user's gate.
pub(crate) async fn verify_step_up_assertion(
    state: &AppState,
    acting_user: UserId,
    proof: Option<&PasskeyAssertionProof>,
    now: OffsetDateTime,
) -> PasskeyStepUp {
    let Some(proof) = proof else {
        return PasskeyStepUp::NotSupplied;
    };
    match verify_step_up_inner(state, acting_user, proof, now).await {
        Ok(true) => PasskeyStepUp::Verified,
        Ok(false) | Err(_) => PasskeyStepUp::Refused,
    }
}

async fn verify_step_up_inner(
    state: &AppState,
    acting_user: UserId,
    proof: &PasskeyAssertionProof,
    now: OffsetDateTime,
) -> Result<bool, ApiError> {
    let rp = rp_context(state).await?;
    let bytes = serde_json::to_vec(&proof.credential)?;
    // `from_json_relaxed` takes the nested shape a browser produces; `from_json_custom` takes a
    // different, flat one. See the note at the registration parse site.
    let assertion = DiscoverableAuthentication64::from_json_relaxed(bytes.as_slice())
        .map_err(|_| assertion_invalid())?;
    let challenge = assertion
        .challenge_relaxed()
        .map_err(|_| ceremony_invalid())?;
    let key = challenge.0;

    let record = {
        let mut store = state.passkey_ceremonies.write().await;
        store.take(key, CeremonyPurpose::StepUp, now)?
    };
    // The challenge was issued to a session; that session's user is the only one it can speak for.
    if record.user_id != Some(acting_user) {
        return Ok(false);
    }
    let CeremonyState::Authentication(ceremony) = record.state else {
        return Ok(false);
    };
    // No PRF secret and no PRF extension on the step-up path — a re-auth unlocks no key, so it stays
    // strict (`allow_prf_extension: false`). `unlocked_key` on the result is always `None` here.
    let verified =
        verify_authentication(state, ceremony, &assertion, &rp, None, false, now).await?;
    if verified.user_id != acting_user {
        return Ok(false);
    }
    // A step-up proof must be user-verified. Without UV the assertion proves possession of the
    // authenticator but not that the person in front of it is the account holder, which is exactly
    // what a destructive operation is asking about.
    if !verified.user_verified {
        return Ok(false);
    }
    // The guard is taken and dropped in its own statement rather than held across the append. In
    // edition 2024 an `if let` still holds its scrutinee's temporaries for the body, and holding a
    // `users` read lock while `record_passkey_event` takes the `ledger` write lock would introduce
    // a second lock order into a codebase that has exactly one.
    let user = state.users.read().await.get(&acting_user).cloned();
    if let Some(user) = user {
        let justification = format!("re-autenticação com a chave de acesso «{}»", verified.name);
        let _ = crate::users::record_passkey_event(state, &user, PASSKEY_USED_KIND, &justification)
            .await;
    }
    Ok(true)
}

// =================================================================================================
// Domain-change gate
// =================================================================================================

/// Refuse a `public_base_url` host change that would strand enrolled passkeys, unless the operator
/// transcribed [`DOMAIN_CHANGE_PHRASE`] and the count of what breaks.
///
/// **This is a wall, not a prohibition.** An operator may genuinely need to move an instance, and
/// refusing outright would leave them editing `settings.json` by hand with no record of what it
/// cost. So the gate states the exact number of credentials that become permanently unusable —
/// not "some", not "any enrolled passkeys" — and makes the operator write the phrase.
///
/// Nothing recovers them. The credentials live in users' authenticators, bound to the old RP ID;
/// no server-side action can rebind them and no migration exists. Each affected user must enrol
/// again, and until they do their account falls back to whatever else it holds — which the
/// account-lifecycle invariant has already guaranteed is something.
pub(crate) async fn guard_domain_change(
    state: &AppState,
    previous_base_url: Option<&str>,
    next_base_url: Option<&str>,
    confirm_phrase: Option<&str>,
) -> Result<(), ApiError> {
    let previous_host = previous_base_url.and_then(host_of);
    let next_host = next_base_url.and_then(host_of);
    if previous_host == next_host {
        return Ok(());
    }
    let affected = enrolled_credential_count(state).await;
    if affected == 0 {
        return Ok(());
    }
    if confirm_phrase.map(str::trim) == Some(DOMAIN_CHANGE_PHRASE) {
        return Ok(());
    }
    let credentials_pt = if affected == 1 {
        "1 chave de acesso".to_owned()
    } else {
        format!("{affected} chaves de acesso")
    };
    Err(ApiError::Conflict(format!(
        "mudar o endereço público desta instância torna {credentials_pt} permanentemente \
         inutilizáveis, e não há forma de as recuperar: uma chave de acesso está presa ao domínio \
         em que foi criada e vive no autenticador do utilizador. Cada utilizador afetado terá de \
         criar uma nova. Para confirmar, escreva exatamente {DOMAIN_CHANGE_PHRASE:?}."
    ))
    .with_code(PASSKEY_DOMAIN_CHANGE_CODE))
}

/// How many passkeys are enrolled across every account.
async fn enrolled_credential_count(state: &AppState) -> usize {
    state
        .users
        .read()
        .await
        .values()
        .map(|user| user.passkeys.len())
        .sum()
}

// =================================================================================================
// Routes
// =================================================================================================

/// The client-facing options blob plus the challenge that indexes the ceremony.
#[derive(Serialize)]
pub struct CeremonyOptionsView {
    /// The `PublicKeyCredentialCreationOptions` / `PublicKeyCredentialRequestOptions` JSON, ready
    /// to hand to `navigator.credentials` after the client decodes its base64url members.
    ///
    /// The challenge is inside this object and is deliberately not surfaced beside it: a second
    /// copy is a second thing that can disagree with the one the browser will actually echo, and
    /// the client has no use for it — the server looks the ceremony up from `clientDataJSON`.
    pub public_key: serde_json::Value,
    /// What this ceremony may be completed for. A client that sends a sign-in ceremony's result to
    /// the step-up endpoint gets a refusal, and this field is how it can tell before trying.
    pub purpose: &'static str,
}

/// Resolve the target user for a self-or-admin passkey operation.
///
/// Self-service by default; another account's list is behind `user.manage`, exactly as the TOTP
/// read is. Enrolment and revocation stay self-only — a passkey is created by touching an
/// authenticator that is physically present, so "enrol a passkey for someone else" is not a
/// coherent operation, and an administrator who could revoke one silently could lock a colleague
/// out without the lifecycle guard ever being consulted for their own account.
async fn require_self(
    state: &AppState,
    actor: &CurrentActor,
    target: UserId,
) -> Result<User, ApiError> {
    let username = actor
        .session_username()
        .ok_or_else(|| ApiError::Forbidden("sessão necessária".to_owned()))?;
    let users = state.users.read().await;
    let user = users.get(&target).cloned().ok_or(ApiError::NotFound)?;
    if !user.username.eq_ignore_ascii_case(username) {
        return Err(ApiError::Forbidden(
            "as chaves de acesso só podem ser geridas pelo próprio titular da conta".to_owned(),
        ));
    }
    Ok(user)
}

/// `GET /v1/users/{id}/passkeys` — the credential list.
pub async fn list_passkeys(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    actor: CurrentActor,
) -> Result<Json<PasskeyListView>, ApiError> {
    let target = UserId(id);
    let user = read_self_or_manage(&state, &actor, target).await?;
    let rp = rp_context(&state).await.ok();
    let rp_id = rp.as_ref().map(|c| c.rp_id_str.clone());
    Ok(Json(PasskeyListView {
        passkeys: user
            .passkeys
            .iter()
            .map(|c| PasskeyView::of(c, rp_id.as_deref()))
            .collect(),
        enrolment_available: rp_id.is_some(),
        rp_id,
    }))
}

/// The list is self-or-`user.manage`; everything that changes a credential is self-only.
async fn read_self_or_manage(
    state: &AppState,
    actor: &CurrentActor,
    target: UserId,
) -> Result<User, ApiError> {
    match require_self(state, actor, target).await {
        Ok(user) => Ok(user),
        Err(_) => {
            crate::authz::require_permission(
                state,
                actor,
                chancela_authz::Permission::UserManage,
                chancela_authz::Scope::Global,
            )
            .await?;
            state
                .users
                .read()
                .await
                .get(&target)
                .cloned()
                .ok_or(ApiError::NotFound)
        }
    }
}

/// `POST /v1/users/{id}/passkeys/options` — begin enrolment.
pub async fn begin_enrolment(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    actor: CurrentActor,
) -> Result<Json<CeremonyOptionsView>, ApiError> {
    let target = UserId(id);
    let user = require_self(&state, &actor, target).await?;
    let rp = rp_context(&state).await?;
    let now = OffsetDateTime::now_utc();

    // One handle per account, reused across every credential it enrols, so a discoverable sign-in
    // resolves to one identity rather than to one credential.
    let handle = user_handle_for(&user)?;
    let username: Username<'_> = user
        .username
        .as_str()
        .try_into()
        .map_err(|_| ApiError::Unprocessable("nome de utilizador inválido".to_owned()))?;

    // `exclude_credentials` must name every credential this account already holds, or the
    // authenticator may silently overwrite one of them.
    let exclude: Vec<PublicKeyCredentialDescriptor<Vec<u8>>> = user
        .passkeys
        .iter()
        .filter_map(|credential| {
            let id = CredentialId::decode(credential.raw_id()?).ok()?;
            Some(PublicKeyCredentialDescriptor {
                id,
                transports: credential.transport_set(),
            })
        })
        .collect();

    let mut options = PublicKeyCredentialCreationOptions::passkey(
        &rp.rp_id,
        PublicKeyCredentialUserEntity {
            name: username,
            id: &handle,
            display_name: None,
        },
        exclude,
    );
    options.extensions = registration_extensions();
    let (server_state, client_state) = options
        .start_ceremony()
        .map_err(|e| ApiError::Internal(format!("passkey ceremony could not start: {e}")))?;
    let challenge = challenge_key(&server_state);
    let public_key = serde_json::to_value(&client_state)?;
    state.passkey_ceremonies.write().await.insert(
        challenge,
        CeremonyPurpose::Registration,
        CeremonyState::Registration(server_state),
        Some(target),
        now,
    )?;
    Ok(Json(CeremonyOptionsView {
        public_key,
        purpose: CeremonyPurpose::Registration.as_str(),
    }))
}

/// A stored user handle, decoded through the library's own codec.
fn decode_user_handle(encoded: &str) -> Option<UserHandle64> {
    let bytes: [u8; USER_HANDLE_MAX_LEN] = B64URL.decode(encoded).ok()?.try_into().ok()?;
    UserHandle64::decode(bytes).ok()
}

/// The stable per-account user handle, minted on the first enrolment and reused thereafter.
///
/// **One handle per account, not per credential.** A discoverable sign-in returns the handle
/// instead of a username, and the server resolves an *identity* from it; a per-credential handle
/// would make the same person look like a different account to each of their own authenticators.
///
/// It is random rather than derived from the user id. Nothing needs the mapping server-side — the
/// credential record carries it — and a handle that is a user id is a durable identifier this
/// product handed to a third-party password manager for no benefit.
fn user_handle_for(user: &User) -> Result<UserHandle64, ApiError> {
    match user.passkeys.first() {
        Some(existing) => decode_user_handle(&existing.user_handle).ok_or_else(|| {
            ApiError::Internal("stored passkey user handle is unreadable".to_owned())
        }),
        None => Ok(UserHandle64::new()),
    }
}

/// Body of `POST /v1/users/{id}/passkeys`.
#[derive(Deserialize)]
pub struct FinishEnrolment {
    /// The `PublicKeyCredential` the browser produced, verbatim.
    pub credential: serde_json::Value,
    /// The user's label for this credential. Display only, and never trusted.
    #[serde(default)]
    pub name: Option<String>,
}

/// `POST /v1/users/{id}/passkeys` — finish enrolment.
pub async fn finish_enrolment(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<FinishEnrolment>,
) -> Result<Json<PasskeyView>, ApiError> {
    let target = UserId(id);
    let user = require_self(&state, &actor, target).await?;
    let rp = rp_context(&state).await?;
    let now = OffsetDateTime::now_utc();

    // **`from_json_relaxed`, not `from_json_custom`, and the names are misleading.**
    //
    // `from_json_custom` does not mean "relaxed with extras" — it deserialises a *different,
    // flat* object (`{attestationObject, clientDataJSON, clientExtensionResults, transports,
    // type}`) for deployments whose client reshapes the credential before sending it.
    // `from_json_relaxed` is the one that takes the nested `RegistrationResponseJSON` a browser
    // actually produces from `PublicKeyCredential.toJSON()`, ignoring members it does not need.
    // Choosing the wrong one fails every ceremony with a missing-field error that surfaces as the
    // same uniform refusal as a bad signature, which is a long way to walk for a name.
    let bytes = serde_json::to_vec(&req.credential)?;
    let registration =
        Registration::from_json_relaxed(bytes.as_slice()).map_err(|_| assertion_invalid())?;
    let challenge = registration
        .challenge_relaxed()
        .map_err(|_| ceremony_invalid())?;
    let key = challenge.0;

    let record = {
        let mut store = state.passkey_ceremonies.write().await;
        store.take(key, CeremonyPurpose::Registration, now)?
    };
    if record.user_id != Some(target) {
        return Err(ceremony_invalid());
    }
    let CeremonyState::Registration(ceremony) = record.state else {
        return Err(ceremony_invalid());
    };

    let prf_capable = registration
        .client_extension_results()
        .prf
        .is_some_and(|prf| prf.enabled);

    let verified = ceremony
        .verify(
            &rp.rp_id,
            &registration,
            &RegistrationVerificationOptions::<String, String> {
                // Same reasoning as the authentication path — see `RpContext::allowed_origins`.
                allowed_origins: &rp.allowed_origins,
                ..Default::default()
            },
        )
        .map_err(|error| {
            // The client is told one uniform thing; an operator is told which of the ~25
            // registration obligations was not met. Without this, a deployment whose enrolments
            // all fail for a structural reason — a browser sending a shape the relaxed
            // deserialiser accepts but the ceremony rejects, say — has no way to find out what,
            // because the failure is deliberately opaque on the wire.
            tracing::warn!(
                target: "chancela::passkeys",
                error = ?error,
                "passkey registration ceremony failed verification"
            );
            assertion_invalid()
        })?;

    let credential_id = B64URL.encode(verified.id().as_ref());
    let static_state = verified.static_state().encode().map_err(|_| {
        ApiError::Internal("passkey public key could not be encoded for storage".to_owned())
    })?;
    let dynamic = verified.dynamic_state();
    let name =
        normalize_credential_name(req.name.as_deref()).unwrap_or_else(default_credential_name);

    let credential = PasskeyCredential {
        credential_id: credential_id.clone(),
        user_handle: B64URL.encode(verified.user_id().as_ref()),
        static_state: B64URL.encode(static_state),
        sign_count: dynamic.sign_count,
        user_verified: dynamic.user_verified,
        backup: dynamic.backup.into(),
        attachment: dynamic.authenticator_attachment.into(),
        rp_id: rp.rp_id_str.clone(),
        transports: verified.transports().encode().unwrap_or(0),
        name: name.clone(),
        created_at: now.format(&Rfc3339).unwrap_or_default(),
        last_used_at: None,
        prf_capable,
        // The wrap is sealed by a later `get()` (`finish_prf_wrap`) because PRF cannot be evaluated
        // at `create()`; a freshly-enrolled credential holds none yet.
        prf_wrap: None,
    };

    let updated = {
        let mut users = state.users.write().await;
        let Some(record) = users.get_mut(&target) else {
            return Err(ApiError::NotFound);
        };
        // A credential id is globally unique for an RP; a duplicate means a replayed registration.
        if record
            .passkeys
            .iter()
            .any(|c| c.credential_id == credential_id)
        {
            return Err(ceremony_invalid());
        }
        record.passkeys.push(credential.clone());
        record.clone()
    };
    let _ = user;
    crate::users::record_passkey_event_attested(
        &state,
        &updated,
        PASSKEY_ENROLLED_KIND,
        &format!("chave de acesso «{name}» adicionada"),
        &actor,
        &attestor,
    )
    .await?;

    Ok(Json(PasskeyView::of(&credential, Some(&rp.rp_id_str))))
}

// =================================================================================================
// The PRF wrap (passwordless enablement)
// =================================================================================================

/// `POST /v1/users/{id}/passkeys/{credential_id}/prf/options` — begin the `get()` that yields the
/// PRF output used to seal a second wrap of the attestation scalar.
///
/// It is a **`get()` and not part of `create()`** because `webauthn_rp` cannot evaluate PRF at
/// creation time (its registration options carry an empty `prf` map), so no PRF output ever comes
/// back from enrolment. The ceremony is bound to [`CeremonyPurpose::PrfWrap`] and to this session's
/// user, and can never mint a session — it is not a sign-in reached by another door.
pub async fn begin_prf_wrap(
    State(state): State<AppState>,
    AxumPath((id, _credential_id)): AxumPath<(Uuid, String)>,
    actor: CurrentActor,
) -> Result<Json<CeremonyOptionsView>, ApiError> {
    let target = UserId(id);
    let user = require_self(&state, &actor, target).await?;
    begin_authentication(&state, CeremonyPurpose::PrfWrap, Some(user.id)).await
}

/// Body of `POST /v1/users/{id}/passkeys/{credential_id}/prf`.
#[derive(Deserialize)]
pub struct FinishPrfWrap {
    /// The `PublicKeyCredential` the browser produced for the PRF-wrap `get()`, verbatim.
    pub credential: serde_json::Value,
    /// The base64url of the PRF-derived KEK the browser computed from `prf.results.first`.
    pub prf_secret: String,
}

/// `POST /v1/users/{id}/passkeys/{credential_id}/prf` — seal a PRF wrap of the attestation scalar.
///
/// Self-only, and it needs the session to hold the **unlocked attestation key** ([`CurrentAttestor`]):
/// the scalar is sealed a *second* time under the PRF-derived KEK, so it must already be in memory —
/// which it is right after a password sign-in, when enrolment happens. The password wrap on the user
/// record is untouched (Invariant 2), so this only ever *adds* the ability to sign in without a
/// password; it never removes the password's hold on the key.
///
/// The assertion is verified under a [`CeremonyPurpose::PrfWrap`]-scoped, single-use challenge bound
/// to the acting user and resolving to the credential named in the path, and it must be
/// user-verified — the same seed discipline the unlock depends on. The posted `prf_secret` is then
/// used verbatim as the wrap secret; the server never sees the raw PRF output it was derived from.
pub async fn finish_prf_wrap(
    State(state): State<AppState>,
    AxumPath((id, credential_id)): AxumPath<(Uuid, String)>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<FinishPrfWrap>,
) -> Result<Json<PasskeyView>, ApiError> {
    let target = UserId(id);
    let user = require_self(&state, &actor, target).await?;
    let rp = rp_context(&state).await?;
    let now = OffsetDateTime::now_utc();

    let Some(existing) = user
        .passkeys
        .iter()
        .find(|c| c.credential_id == credential_id)
        .cloned()
    else {
        return Err(ApiError::NotFound);
    };

    // An account with no attestation key has nothing to wrap. Not an error — some accounts hold no
    // key — so the ceremony is simply a no-op and the credential comes back exactly as it was.
    let Some(account_key) = user.attestation_key.clone() else {
        return Ok(Json(PasskeyView::of(&existing, Some(&rp.rp_id_str))));
    };

    // The scalar to seal is the session's unlocked key — the same scalar the password wrap holds. A
    // session that read but never unlocked (no password this sign-in) cannot supply it.
    let Some((_, signing_key)) = attestor.signer() else {
        return Err(ApiError::Forbidden(
            "para ativar o início de sessão sem palavra-passe nesta chave de acesso, volte a \
             autenticar-se com a palavra-passe: a chave de atestação tem de estar aberta na sessão \
             para poder ser protegida também pela chave de acesso"
                .to_owned(),
        )
        .with_code(PASSKEY_PRF_NO_UNLOCKED_KEY_CODE));
    };
    // The unlocked key must be *this account's* key, or the wrap would be of a different scalar than
    // the one every existing attestation was signed under. It always is (the session unlocked this
    // user's key); the check is defensive because this is key custody.
    if crate::attestation::key_fingerprint(signing_key) != account_key.fingerprint {
        return Err(ApiError::Internal(
            "the session's unlocked key does not match this account's attestation key".to_owned(),
        ));
    }

    verify_prf_wrap_assertion(&state, target, &credential_id, &req.credential, &rp, now).await?;

    let secret = req.prf_secret.trim();
    if secret.is_empty() {
        return Err(ApiError::Unprocessable(
            "a chave derivada da chave de acesso está vazia".to_owned(),
        )
        .with_code(PASSKEY_PRF_SECRET_INVALID_CODE));
    }
    let prf_wrap = AttestationKeyBlob::wrap_key(secret, signing_key)
        .map_err(|e| ApiError::Internal(format!("could not seal the PRF wrap: {e}")))?;

    // The users write lock is taken and released before `persist_user`, which reads users itself —
    // holding it across that await would re-enter the lock and deadlock (as `persist_assertion` is
    // careful to do too).
    let (updated_user, updated_credential) = {
        let mut users = state.users.write().await;
        let Some(record) = users.get_mut(&target) else {
            return Err(ApiError::NotFound);
        };
        let Some(credential) = record
            .passkeys
            .iter_mut()
            .find(|c| c.credential_id == credential_id)
        else {
            return Err(ApiError::NotFound);
        };
        credential.prf_wrap = Some(prf_wrap);
        let updated_credential = credential.clone();
        (record.clone(), updated_credential)
    };
    crate::users::persist_user(&state, &updated_user).await?;

    Ok(Json(PasskeyView::of(
        &updated_credential,
        Some(&rp.rp_id_str),
    )))
}

/// Verify the PRF-wrap `get()` assertion: purpose-scoped, single-use, bound to the acting user, and
/// resolving to the credential named in the path, user-verified. Mirrors [`verify_step_up_inner`].
async fn verify_prf_wrap_assertion(
    state: &AppState,
    acting_user: UserId,
    credential_id: &str,
    credential: &serde_json::Value,
    rp: &RpContext,
    now: OffsetDateTime,
) -> Result<(), ApiError> {
    let bytes = serde_json::to_vec(credential)?;
    let assertion = DiscoverableAuthentication64::from_json_relaxed(bytes.as_slice())
        .map_err(|_| assertion_invalid())?;
    let challenge = assertion
        .challenge_relaxed()
        .map_err(|_| ceremony_invalid())?;
    let key = challenge.0;
    let record = {
        let mut store = state.passkey_ceremonies.write().await;
        store.take(key, CeremonyPurpose::PrfWrap, now)?
    };
    if record.user_id != Some(acting_user) {
        return Err(assertion_invalid());
    }
    let CeremonyState::Authentication(ceremony) = record.state else {
        return Err(ceremony_invalid());
    };
    // The credential that answered must be the one being wrapped, or a user with two passkeys could
    // seal credential A's slot with credential B's PRF output — which would then never open at
    // sign-in with A.
    if B64URL.encode(assertion.raw_id().as_ref()) != credential_id {
        return Err(assertion_invalid());
    }
    // The PRF-wrap `get()` carries a client-added `prf` extension, so its output is expected here.
    let verified = verify_authentication(state, ceremony, &assertion, rp, None, true, now).await?;
    if verified.user_id != acting_user || !verified.user_verified {
        return Err(assertion_invalid());
    }
    Ok(())
}

/// The label an unnamed credential gets at enrolment.
///
/// Only ever a *default*: the rename path refuses a blank label rather than reaching for this, so
/// no credential is ever silently renamed to it.
fn default_credential_name() -> String {
    "Chave de acesso".to_owned()
}

/// A user-supplied credential label, trimmed and bounded, or `None` when it is blank.
///
/// Bounded in **characters, not bytes**: `take(64)` over `chars()` cannot split a multi-byte
/// sequence, which a byte truncation of `«Portátil»` would. The label is display-only and never
/// trusted for anything, so the bound exists to keep a table cell and a ledger justification
/// legible rather than to make the value safe.
fn normalize_credential_name(supplied: Option<&str>) -> Option<String> {
    let trimmed = supplied.map(str::trim).filter(|s| !s.is_empty())?;
    Some(trimmed.chars().take(64).collect())
}

/// Body of `PATCH /v1/users/{id}/passkeys/{credential_id}`.
#[derive(Deserialize)]
pub struct RenamePasskey {
    /// The new display label.
    pub name: String,
}

/// `PATCH /v1/users/{id}/passkeys/{credential_id}` — relabel one credential.
///
/// **Self-only, and deliberately without step-up.** The self-only rule matches every other
/// mutation here for the same reason: an administrator who could relabel someone else's
/// credentials could make the revocation confirmation name the wrong device. Step-up is *not*
/// demanded, and the asymmetry with revocation is the point — revoking removes a way to sign in
/// and is therefore a credential operation, while a rename changes a string the server never reads
/// back for any decision. Demanding a password to fix a typo would teach operators to type their
/// password at prompts that do not need it, which is the habit every step-up gate depends on them
/// not having.
///
/// Without this route a credential can be created and deleted but not relabelled, so with several
/// enrolled the only remedy for "which one is the work laptop?" is revoke-and-re-enrol — a
/// destructive act to fix a label.
pub async fn rename_passkey(
    State(state): State<AppState>,
    AxumPath((id, credential_id)): AxumPath<(Uuid, String)>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<RenamePasskey>,
) -> Result<Json<PasskeyView>, ApiError> {
    let target = UserId(id);
    let user = require_self(&state, &actor, target).await?;
    let Some(name) = normalize_credential_name(Some(req.name.as_str())) else {
        return Err(ApiError::Unprocessable(
            "a chave de acesso precisa de um nome — é assim que a distingue das outras quando \
             tiver de remover uma"
                .to_owned(),
        )
        .with_code(PASSKEY_NAME_EMPTY_CODE));
    };

    let previous = user
        .passkeys
        .iter()
        .find(|c| c.credential_id == credential_id)
        .map(|c| c.name.clone())
        .ok_or(ApiError::NotFound)?;

    let (updated, renamed) = {
        let mut users = state.users.write().await;
        let Some(record) = users.get_mut(&target) else {
            return Err(ApiError::NotFound);
        };
        let Some(credential) = record
            .passkeys
            .iter_mut()
            .find(|c| c.credential_id == credential_id)
        else {
            return Err(ApiError::NotFound);
        };
        credential.name = name.clone();
        let renamed = credential.clone();
        (record.clone(), renamed)
    };

    // Both labels, because the ledger's other passkey lines name a credential by its label alone.
    // A rename that recorded only the new one would leave an earlier "«portátil» utilizada" with
    // nothing to attach it to.
    crate::users::record_passkey_event_attested(
        &state,
        &updated,
        PASSKEY_RENAMED_KIND,
        &format!("chave de acesso «{previous}» renomeada para «{name}»"),
        &actor,
        &attestor,
    )
    .await?;

    let rp_id = rp_context(&state).await.ok().map(|c| c.rp_id_str);
    Ok(Json(PasskeyView::of(&renamed, rp_id.as_deref())))
}

/// The library's transport set as the stable WebAuthn wire strings the client uses.
///
/// The strings are the spec's `AuthenticatorTransport` enumeration values verbatim, because the
/// client hands them straight back to `navigator.credentials` — this is not a place to be
/// descriptive.
fn transport_names(transports: AuthTransports) -> Vec<String> {
    [
        (AuthenticatorTransport::Usb, "usb"),
        (AuthenticatorTransport::Nfc, "nfc"),
        (AuthenticatorTransport::Ble, "ble"),
        (AuthenticatorTransport::SmartCard, "smart-card"),
        (AuthenticatorTransport::Hybrid, "hybrid"),
        (AuthenticatorTransport::Internal, "internal"),
    ]
    .into_iter()
    .filter(|(transport, _)| transports.contains(*transport))
    .map(|(_, name)| name.to_owned())
    .collect()
}

/// Body of `DELETE /v1/users/{id}/passkeys/{credential_id}`.
#[derive(Deserialize, Default)]
pub struct RevokePasskey {
    /// Step-up re-auth. Revoking a credential is a credential operation and must not ride a session
    /// alone.
    #[serde(default)]
    pub reauth: crate::data::ReAuth,
}

/// `DELETE /v1/users/{id}/passkeys/{credential_id}` — revoke one credential.
pub async fn revoke_passkey(
    State(state): State<AppState>,
    AxumPath((id, credential_id)): AxumPath<(Uuid, String)>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    body: Option<Json<RevokePasskey>>,
) -> Result<Json<PasskeyListView>, ApiError> {
    let target = UserId(id);
    let user = require_self(&state, &actor, target).await?;
    let req = body.map(|Json(b)| b).unwrap_or_default();
    crate::data::require_step_up(&state, &actor, &req.reauth).await?;

    let Some(credential) = user
        .passkeys
        .iter()
        .find(|c| c.credential_id == credential_id)
        .cloned()
    else {
        return Err(ApiError::NotFound);
    };

    // The account-lifecycle invariant, in the operation rather than in the UI. Revoking one of
    // several passkeys removes no *kind* and passes; revoking the last one removes the kind, and
    // the guard refuses if that would leave the account with no way to sign in or no way back.
    let before = HeldCredentials::held_by(&user);
    let remaining = user.passkeys.len().saturating_sub(1);
    let after = if remaining == 0 {
        before.clone().without(CredentialKind::Passkey)
    } else {
        before.clone()
    };
    ensure_removal_leaves_account_usable(&before, &after, AttestationKeyState::held_by(&user))?;

    let updated = {
        let mut users = state.users.write().await;
        let Some(record) = users.get_mut(&target) else {
            return Err(ApiError::NotFound);
        };
        record.passkeys.retain(|c| c.credential_id != credential_id);
        record.clone()
    };
    crate::users::record_passkey_event_attested(
        &state,
        &updated,
        PASSKEY_REVOKED_KIND,
        // The label, never the id: an id in an audit line is noise, and the label is what the
        // person who revoked it will recognise.
        &format!("chave de acesso «{}» removida", credential.name),
        &actor,
        &attestor,
    )
    .await?;

    let rp_id = rp_context(&state).await.ok().map(|c| c.rp_id_str);
    Ok(Json(PasskeyListView {
        passkeys: updated
            .passkeys
            .iter()
            .map(|c| PasskeyView::of(c, rp_id.as_deref()))
            .collect(),
        enrolment_available: rp_id.is_some(),
        rp_id,
    }))
}

/// `POST /v1/session/passkey/options` — begin a sign-in ceremony.
///
/// **Unauthenticated, and it takes no identifier.** That is the whole reason discoverable
/// credentials were chosen: a username-first flow would need an endpoint answering "does this
/// account have a passkey?", which is a user-enumeration oracle, and `create_session` spends real
/// effort (a dummy verifier, matched argon2 work) closing exactly that. Here the browser decides
/// what to offer from what it holds and the server is never asked who exists.
pub async fn begin_sign_in(
    State(state): State<AppState>,
) -> Result<Json<CeremonyOptionsView>, ApiError> {
    begin_authentication(&state, CeremonyPurpose::SignIn, None).await
}

/// `POST /v1/reauth/passkey/options` — begin a **step-up-scoped** ceremony.
///
/// The resulting challenge is bound to this session's user and to
/// [`CeremonyPurpose::StepUp`], and no other. See [`verify_step_up_assertion`].
pub async fn begin_step_up(
    State(state): State<AppState>,
    actor: CurrentActor,
) -> Result<Json<CeremonyOptionsView>, ApiError> {
    let username = actor
        .session_username()
        .ok_or_else(|| ApiError::Forbidden("sessão necessária".to_owned()))?;
    let user_id = {
        let users = state.users.read().await;
        users
            .values()
            .find(|u| u.username == username)
            .map(|u| u.id)
            .ok_or_else(|| ApiError::Forbidden("sessão necessária".to_owned()))?
    };
    begin_authentication(&state, CeremonyPurpose::StepUp, Some(user_id)).await
}

async fn begin_authentication(
    state: &AppState,
    purpose: CeremonyPurpose,
    user_id: Option<UserId>,
) -> Result<Json<CeremonyOptionsView>, ApiError> {
    let rp = rp_context(state).await?;
    let now = OffsetDateTime::now_utc();
    // The server requests no extensions — see the note at the top of this module on why `prf` is
    // added by the client, not here. The browser adds `extensions.prf.eval` for the sign-in and
    // PRF-wrap ceremonies; step-up adds nothing.
    let (server_state, client_state) = DiscoverableCredentialRequestOptions::passkey(&rp.rp_id)
        .start_ceremony()
        .map_err(|e| ApiError::Internal(format!("passkey ceremony could not start: {e}")))?;
    let challenge = challenge_key(&server_state);
    let public_key = serde_json::to_value(&client_state)?;
    state.passkey_ceremonies.write().await.insert(
        challenge,
        purpose,
        CeremonyState::Authentication(server_state),
        user_id,
        now,
    )?;
    Ok(Json(CeremonyOptionsView {
        public_key,
        purpose: purpose.as_str(),
    }))
}

/// Body of `POST /v1/session/passkey`.
#[derive(Deserialize)]
pub struct PasskeySignIn {
    /// The `PublicKeyCredential` the browser produced, verbatim.
    pub credential: serde_json::Value,
    /// The base64url of the **PRF-derived KEK** (`HKDF-SHA256(prf.results.first, …)`), when the
    /// browser obtained a PRF output for this assertion. Absent for a credential that carries no PRF
    /// output — the shape-C fallback. It is a secret in a request body and gets the same redaction
    /// and zeroize treatment as `password`; the server uses it only to open a credential's
    /// [`PasskeyCredential::prf_wrap`] and never stores it. A UV-less assertion's secret would derive
    /// from the wrong seed, so it is never trusted (see [`VerifiedAssertion::unlocked_key`]).
    #[serde(default)]
    pub prf_secret: Option<String>,
}

/// Complete a passkey sign-in, returning what the caller needs to mint a session.
///
/// Kept separate from the handler so `session.rs` owns session minting and this module owns the
/// ceremony — there is exactly one place that decides what a session is.
pub(crate) async fn complete_sign_in(
    state: &AppState,
    credential: &serde_json::Value,
    prf_secret: Option<&str>,
    now: OffsetDateTime,
) -> Result<VerifiedAssertion, ApiError> {
    let rp = rp_context(state).await?;
    let bytes = serde_json::to_vec(credential)?;
    // `from_json_relaxed` takes the nested shape a browser produces; `from_json_custom` takes a
    // different, flat one. See the note at the registration parse site.
    let assertion = DiscoverableAuthentication64::from_json_relaxed(bytes.as_slice())
        .map_err(|_| assertion_invalid())?;
    let challenge = assertion
        .challenge_relaxed()
        .map_err(|_| ceremony_invalid())?;
    let key = challenge.0;
    let record = {
        let mut store = state.passkey_ceremonies.write().await;
        store.take(key, CeremonyPurpose::SignIn, now)?
    };
    let CeremonyState::Authentication(ceremony) = record.state else {
        return Err(ceremony_invalid());
    };
    let verified =
        verify_authentication(state, ceremony, &assertion, &rp, prf_secret, true, now).await?;
    // Same reason as in `verify_step_up_inner`: never hold the `users` guard across a ledger write.
    let user = state.users.read().await.get(&verified.user_id).cloned();
    if let Some(user) = user {
        let justification = format!("sessão iniciada com a chave de acesso «{}»", verified.name);
        let _ = crate::users::record_passkey_event(state, &user, PASSKEY_USED_KIND, &justification)
            .await;
    }
    Ok(verified)
}

/// The shared handle type for the ceremony store, as `AppState` holds it.
pub type CeremonyStoreHandle = Arc<RwLock<CeremonyStore>>;

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "https://livros.example.pt";

    fn settings(rp_id: Option<&str>) -> PasskeySettings {
        PasskeySettings {
            rp_id: rp_id.map(str::to_owned),
        }
    }

    // ── The RP ID, refused at configuration time ─────────────────────────────────────────────

    #[test]
    fn the_host_and_a_registrable_parent_are_both_valid() {
        for good in ["livros.example.pt", "example.pt"] {
            settings(Some(good))
                .validate_against(Some(BASE))
                .unwrap_or_else(|error| panic!("{good:?} must be accepted: {error:?}"));
        }
    }

    /// **The trap a one-line "registrable parent" derivation walks into.**
    ///
    /// Stripping the first label off `chancela.pt` yields `pt`, which is arithmetically a suffix of
    /// the host and passes every check a pure suffix test can make. It is a public suffix, no
    /// browser will accept it, and the failure happens where this server cannot see it.
    /// Each pair is an origin and the public suffix that a "strip one label" derivation would
    /// produce for it — so every case here genuinely *reaches* the PSL check, having already
    /// passed the arithmetic suffix test. That is the whole point: a suffix test cannot catch
    /// these, because they really are suffixes.
    #[test]
    fn a_public_suffix_is_refused() {
        for (origin, suffix) in [
            ("https://livros.example.pt", "pt"),
            ("https://chancela.pt", "pt"),
            ("https://livros.example.com", "com"),
            ("https://livros.example.co.uk", "co.uk"),
            ("https://livros.example.com.br", "com.br"),
        ] {
            let error = settings(Some(suffix))
                .validate_against(Some(origin))
                .expect_err("a public suffix is never a valid RP ID");
            assert!(
                format!("{error:?}").contains("public suffix"),
                "the refusal must say why, or an operator reads it as a typo: {error:?}"
            );
        }
    }

    /// The sharpest version: a host whose registrable parent *is* a public suffix. `chancela.pt` is
    /// fine as an RP ID and `pt` is not, and the only difference a suffix test can see is a label.
    #[test]
    fn a_host_whose_parent_is_a_public_suffix_is_still_valid_itself() {
        settings(Some("chancela.pt"))
            .validate_against(Some("https://chancela.pt"))
            .expect("the host itself is always a valid RP ID");
        settings(Some("pt"))
            .validate_against(Some("https://chancela.pt"))
            .expect_err("its parent is not");
    }

    #[test]
    fn a_domain_that_is_not_a_suffix_of_the_origin_is_refused() {
        for bad in [
            "example.com",                // a different registrable domain
            "wrong.example.pt",           // a sibling
            "deep.livros.example.pt",     // a child, which is the wrong direction
            "livros.example.pt.evil.com", // a superstring, which a naive `contains` would accept
        ] {
            settings(Some(bad))
                .validate_against(Some(BASE))
                .unwrap_err();
        }
    }

    #[test]
    fn a_malformed_rp_id_is_refused_before_it_can_silently_not_match() {
        // Each of these *nearly* matches, which is the dangerous kind of wrong: the browser
        // compares against an already-canonicalised effective domain, so none of them ever match
        // and none of them look wrong to a human reading the settings page.
        for bad in [
            "Example.pt",
            "EXAMPLE.PT",
            "https://example.pt",
            "example.pt:443",
            "example.pt/livros",
        ] {
            settings(Some(bad))
                .validate_against(Some(BASE))
                .unwrap_err();
        }
    }

    #[test]
    fn an_rp_id_cannot_be_configured_without_a_public_base_url() {
        let error = settings(Some("example.pt"))
            .validate_against(None)
            .expect_err("there is nothing to validate it against");
        assert_eq!(error.code(), PASSKEYS_NO_PUBLIC_BASE_URL_CODE);
    }

    #[test]
    fn an_unset_rp_id_is_a_valid_configuration() {
        // Unset means passkeys are unavailable, which is a state an instance is allowed to be in —
        // and is the state every instance is in until an operator makes the one-way choice.
        settings(None)
            .validate_against(Some(BASE))
            .expect("unset is fine");
        settings(None)
            .validate_against(None)
            .expect("unset is fine with no base url either");
        assert!(
            settings(None).is_default(),
            "so the slice stays off the wire"
        );
    }

    /// `localhost` is itself a public suffix, so the check that refuses `pt` would refuse it too —
    /// correctly by the letter of the rule and wrongly in fact, since browsers special-case it as a
    /// valid, secure RP ID. This pins the exemption *and* the ordering that makes it work.
    #[test]
    fn localhost_is_allowed_because_browsers_special_case_it() {
        assert_eq!(
            psl::suffix_str("localhost"),
            Some("localhost"),
            "if this stops being true the exemption below is dead code rather than a carve-out"
        );
        settings(Some("localhost"))
            .validate_against(Some("https://localhost"))
            .expect("a development origin must remain workable");
        settings(Some("localhost"))
            .validate_against(Some("https://localhost:5173"))
            .expect("and with a dev-server port");
        // The carve-out is that one name, not "anything the list refuses".
        settings(Some("pt"))
            .validate_against(Some("https://livros.example.pt"))
            .expect_err("no other public suffix is exempted");
    }

    #[test]
    fn host_of_reads_the_authority_and_nothing_else() {
        assert_eq!(
            host_of("https://livros.example.pt").as_deref(),
            Some("livros.example.pt")
        );
        assert_eq!(
            host_of("https://livros.example.pt:8443/livros/").as_deref(),
            Some("livros.example.pt")
        );
        assert_eq!(
            host_of("https://LIVROS.Example.PT").as_deref(),
            Some("livros.example.pt")
        );
        assert_eq!(
            host_of("http://livros.example.pt"),
            None,
            "plain http is already refused upstream and must never reach here"
        );
    }

    /// **The expected origin is derived from `public_base_url`, never from the RP ID.**
    ///
    /// With the RP ID at the registrable parent — the ruling's recommendation, so a subdomain move
    /// survives — the two differ, and the library's empty-list default would derive
    /// `https://example.pt` for an instance served at `https://livros.example.pt`.
    #[test]
    fn the_expected_origin_comes_from_the_base_url_and_not_the_rp_id() {
        assert_eq!(
            origin_of("https://livros.example.pt").as_deref(),
            Some("https://livros.example.pt")
        );
        // A path and a trailing slash are trimmed: the browser sends a bare origin, and the
        // comparison is equality, so anything extra simply never matches.
        assert_eq!(
            origin_of("https://livros.example.pt/livros/").as_deref(),
            Some("https://livros.example.pt")
        );
        // A non-default port is part of the origin and must survive.
        assert_eq!(
            origin_of("https://livros.example.pt:8443").as_deref(),
            Some("https://livros.example.pt:8443")
        );
        // 443 is not: a browser omits the default port, so keeping it would build a string no
        // client ever sends.
        assert_eq!(
            origin_of("https://livros.example.pt:443").as_deref(),
            Some("https://livros.example.pt")
        );
        assert_eq!(
            origin_of("https://LIVROS.Example.PT").as_deref(),
            Some("https://livros.example.pt")
        );
        assert_eq!(origin_of("http://livros.example.pt"), None);
        assert_eq!(origin_of("https://"), None);
    }

    // ── The ceremony store: purpose scoping and single use ───────────────────────────────────

    fn authentication_state() -> CeremonyState {
        let rp = RpId::Domain(AsciiDomain::try_from("example.pt".to_owned()).expect("domain"));
        let (server, _client) = DiscoverableCredentialRequestOptions::passkey(&rp)
            .start_ceremony()
            .expect("ceremony starts");
        CeremonyState::Authentication(server)
    }

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_785_000_000).expect("fixed instant")
    }

    /// **The replay boundary.** A challenge minted for a sign-in is not a weaker match for a
    /// step-up — it is not a match at all, and the attempt spends it either way.
    #[test]
    fn a_sign_in_challenge_cannot_be_taken_as_a_step_up() {
        let mut store = CeremonyStore::default();
        store
            .insert(
                7,
                CeremonyPurpose::SignIn,
                authentication_state(),
                None,
                now(),
            )
            .expect("insert");
        assert!(
            store.take(7, CeremonyPurpose::StepUp, now()).is_err(),
            "a sign-in assertion must not be replayable into a destructive operation"
        );
        assert!(
            store.take(7, CeremonyPurpose::SignIn, now()).is_err(),
            "and the wrong-purpose attempt still spent it, so it cannot be probed until the \
             purpose suits"
        );
    }

    #[test]
    fn a_step_up_challenge_cannot_be_taken_as_a_sign_in() {
        // The other direction matters less but must also hold: a step-up ceremony is bound to a
        // session's user, and letting it mint a session would launder that binding away.
        let mut store = CeremonyStore::default();
        store
            .insert(
                9,
                CeremonyPurpose::StepUp,
                authentication_state(),
                Some(UserId(Uuid::new_v4())),
                now(),
            )
            .expect("insert");
        assert!(store.take(9, CeremonyPurpose::SignIn, now()).is_err());
    }

    #[test]
    fn a_challenge_is_spent_by_the_attempt() {
        let mut store = CeremonyStore::default();
        store
            .insert(
                11,
                CeremonyPurpose::SignIn,
                authentication_state(),
                None,
                now(),
            )
            .expect("insert");
        assert!(store.take(11, CeremonyPurpose::SignIn, now()).is_ok());
        assert!(
            store.take(11, CeremonyPurpose::SignIn, now()).is_err(),
            "single use, and the second presentation is indistinguishable from an unknown one"
        );
        assert!(store.is_empty());
    }

    #[test]
    fn an_expired_challenge_is_refused_and_still_spent() {
        let mut store = CeremonyStore::default();
        store
            .insert(
                13,
                CeremonyPurpose::SignIn,
                authentication_state(),
                None,
                now(),
            )
            .expect("insert");
        let later = now() + time::Duration::seconds(CEREMONY_TTL_SECS + 1);
        assert!(store.take(13, CeremonyPurpose::SignIn, later).is_err());
        assert!(
            store.take(13, CeremonyPurpose::SignIn, now()).is_err(),
            "an expired hit is still a spent challenge; leaving it behind would let a caller wait \
             for the clock to suit"
        );
    }

    #[test]
    fn every_refusal_reads_identically() {
        // Unknown, expired, spent and wrong-purpose share one code and one message. Splitting them
        // would tell a caller whether a captured challenge is live — the one thing worth knowing
        // before deciding to replay it.
        let mut store = CeremonyStore::default();
        store
            .insert(
                15,
                CeremonyPurpose::SignIn,
                authentication_state(),
                None,
                now(),
            )
            .expect("insert");
        // `CeremonyRecord` deliberately has no `Debug` — it holds ceremony state — so the errors
        // are pulled out by hand rather than with `expect_err`.
        let err = |result: Result<CeremonyRecord, ApiError>, what: &str| match result {
            Ok(_) => panic!("{what} must be refused"),
            Err(error) => error,
        };
        let unknown = err(
            store.take(999, CeremonyPurpose::SignIn, now()),
            "an unknown challenge",
        );
        let wrong_purpose = err(
            store.take(15, CeremonyPurpose::StepUp, now()),
            "a wrongly scoped challenge",
        );
        let spent = err(
            store.take(15, CeremonyPurpose::SignIn, now()),
            "an already-spent challenge",
        );
        assert_eq!(unknown.code(), PASSKEY_CEREMONY_INVALID_CODE);
        assert_eq!(wrong_purpose.code(), unknown.code());
        assert_eq!(spent.code(), unknown.code());
        assert_eq!(format!("{wrong_purpose:?}"), format!("{unknown:?}"));
        assert_eq!(format!("{spent:?}"), format!("{unknown:?}"));
    }

    #[test]
    fn expired_ceremonies_are_pruned_so_a_stranger_cannot_grow_the_process() {
        // A sign-in ceremony can be started unauthenticated, so this store's size is something a
        // stranger influences.
        let mut store = CeremonyStore::default();
        for i in 0..5 {
            store
                .insert(
                    i,
                    CeremonyPurpose::SignIn,
                    authentication_state(),
                    None,
                    now(),
                )
                .expect("insert");
        }
        assert_eq!(store.len(), 5);
        let later = now() + time::Duration::seconds(CEREMONY_TTL_SECS + 1);
        store
            .insert(
                100,
                CeremonyPurpose::SignIn,
                authentication_state(),
                None,
                later,
            )
            .expect("insert");
        assert_eq!(store.len(), 1, "inserting prunes what has expired");
    }

    // ── Ledger kinds ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn every_emitted_kind_is_listed_and_well_formed() {
        // `apps/web/src/api/labels.test.ts` sweeps the crate sources for kinds and fails if one has
        // no web label. This list is what a reader checks that obligation against, and this test is
        // what stops it drifting from the constants above.
        //
        // **One test, not two.** The web-UI lane briefly added a second copy of this check beside
        // `normalize_credential_name`'s tests when it landed the rename kind. Two tests over one
        // list is the exact drift the list exists to prevent: the next kind needs both updated, and
        // whichever is forgotten still passes. Merged here, where the per-constant membership loop
        // below already makes forgetting one impossible.
        assert_eq!(ALL_PASSKEY_EVENT_KINDS.len(), 5);
        for kind in ALL_PASSKEY_EVENT_KINDS {
            assert!(
                kind.starts_with("user.passkey."),
                "{kind} is not in the user-scoped namespace its `UserView` payload implies"
            );
            assert!(
                kind.chars()
                    .all(|c| c.is_ascii_lowercase() || c == '.' || c == '_'),
                "{kind} is not a lowercase dotted identifier, so the web sweep will not see it"
            );
        }
        for kind in [
            PASSKEY_ENROLLED_KIND,
            PASSKEY_REVOKED_KIND,
            PASSKEY_USED_KIND,
            PASSKEY_COUNTER_REGRESSION_KIND,
            PASSKEY_RENAMED_KIND,
        ] {
            assert!(
                ALL_PASSKEY_EVENT_KINDS.contains(&kind),
                "{kind} is emitted but not listed"
            );
        }
    }

    // ── Stored shapes ────────────────────────────────────────────────────────────────────────

    fn credential_fixture() -> PasskeyCredential {
        PasskeyCredential {
            credential_id: "Y3JlZGVudGlhbC1pZC0zMi1ieXRlcy1sb25nLW9r".to_owned(),
            user_handle: "aGFuZGxl".to_owned(),
            static_state: "c3RhdGlj".to_owned(),
            sign_count: 0,
            user_verified: true,
            backup: PasskeyBackup::Exists,
            attachment: PasskeyAttachment::Platform,
            rp_id: "example.pt".to_owned(),
            transports: 0,
            name: "Telemóvel".to_owned(),
            created_at: "2026-07-31T09:00:00Z".to_owned(),
            last_used_at: None,
            prf_capable: true,
            prf_wrap: None,
        }
    }

    #[test]
    fn backup_state_round_trips_and_keeps_the_illegal_pair_unrepresentable() {
        for state in [
            PasskeyBackup::NotEligible,
            PasskeyBackup::Eligible,
            PasskeyBackup::Exists,
        ] {
            assert_eq!(PasskeyBackup::from(Backup::from(state)), state);
        }
        // Three states, not two booleans: there is no value here meaning "not eligible for backup,
        // but backed up", so the illegal combination cannot be written down at all.
        assert_eq!(
            serde_json::to_string(&PasskeyBackup::Exists).expect("serialise"),
            "\"exists\""
        );
    }

    #[test]
    fn attachment_round_trips() {
        for state in [
            PasskeyAttachment::Unknown,
            PasskeyAttachment::Platform,
            PasskeyAttachment::CrossPlatform,
        ] {
            assert_eq!(
                PasskeyAttachment::from(AuthenticatorAttachment::from(state)),
                state
            );
        }
    }

    #[test]
    fn transport_hints_round_trip_through_the_librarys_own_codec() {
        // One stored representation. The names are derived on the way out and never stored, so
        // there is no second spelling of "smart-card" for the two sides to disagree about.
        assert!(transport_names(credential_fixture().transport_set()).is_empty());
        let all = AuthTransports::decode(0x3f).expect("all six transports");
        let names = transport_names(all);
        assert_eq!(names.len(), 6, "{names:?}");
        assert!(names.contains(&"smart-card".to_owned()));
        assert!(names.contains(&"internal".to_owned()));
    }

    #[test]
    fn an_unreadable_transport_byte_degrades_to_none_rather_than_panicking() {
        // The byte comes off disk. A value the codec rejects means an empty hint set — the client
        // simply gets no routing advice — never a panic on the sign-in path.
        let mut credential = credential_fixture();
        credential.transports = 0xff;
        assert!(transport_names(credential.transport_set()).is_empty());
    }

    /// A credential enrolled under a different RP ID is **listed but not usable**. It is still
    /// enrolled and its holder still needs to see and remove it; what it cannot do is authenticate.
    #[test]
    fn a_credential_from_a_previous_domain_is_listed_as_unusable() {
        let credential = credential_fixture();
        assert!(PasskeyView::of(&credential, Some("example.pt")).usable);
        assert!(!PasskeyView::of(&credential, Some("example.com")).usable);
        assert!(
            !PasskeyView::of(&credential, None).usable,
            "with no RP ID configured nothing can authenticate, and saying otherwise is a lie"
        );
    }

    #[test]
    fn a_stored_credential_round_trips_through_serde() {
        let credential = credential_fixture();
        let json = serde_json::to_value(&credential).expect("serialise");
        let back: PasskeyCredential = serde_json::from_value(json).expect("deserialise");
        assert_eq!(back, credential);
    }

    /// The `#[serde(default)]`s are load-bearing rather than tidy: the store *skips rows it cannot
    /// parse*, so a field that failed to default would not error — it would silently drop the whole
    /// account from the read model.
    #[test]
    fn a_credential_row_missing_every_optional_field_still_loads() {
        let minimal = serde_json::json!({
            "credential_id": "Y3JlZA",
            "user_handle": "aGFuZGxl",
            "static_state": "c3RhdGlj",
            "rp_id": "example.pt",
            "name": "Telemóvel",
            "created_at": "2026-07-31T09:00:00Z",
        });
        let credential: PasskeyCredential =
            serde_json::from_value(minimal).expect("a minimal row must load");
        assert_eq!(credential.sign_count, 0);
        assert_eq!(credential.backup, PasskeyBackup::NotEligible);
        assert_eq!(credential.attachment, PasskeyAttachment::Unknown);
        assert!(!credential.prf_capable);
        assert!(credential.last_used_at.is_none());
    }

    // ── The credential label ─────────────────────────────────────────────────────────────────

    /// The asymmetry between enrolment and rename, pinned so it cannot be "tidied" into one rule.
    /// A missing label at enrolment means the user did not name it, and a default is honest. A
    /// blank label on a rename means the user *acted*, and defaulting would show them a credential
    /// named something they never typed.
    #[test]
    fn a_blank_label_defaults_at_enrolment_and_is_refused_on_a_rename() {
        for blank in [None, Some(""), Some("   "), Some("\t\n")] {
            assert_eq!(
                normalize_credential_name(blank),
                None,
                "{blank:?} carries no label"
            );
        }
        // The enrolment path's fallback, and the only place it is ever reached.
        assert_eq!(
            normalize_credential_name(None).unwrap_or_else(default_credential_name),
            "Chave de acesso"
        );
    }

    #[test]
    fn a_label_is_trimmed_and_bounded_without_splitting_a_character() {
        assert_eq!(
            normalize_credential_name(Some("  Portátil do escritório  ")).as_deref(),
            Some("Portátil do escritório")
        );
        // 64 *characters*, not bytes: every one of these is two bytes, so a byte bound would cut
        // one in half and produce a label that is not valid UTF-8 at all.
        let long = "á".repeat(200);
        let bounded = normalize_credential_name(Some(&long)).expect("non-empty");
        assert_eq!(bounded.chars().count(), 64);
        assert_eq!(bounded, "á".repeat(64));
    }

    // The kind-list check lives with the other ledger-kind assertions above, in
    // `every_emitted_kind_is_listed_and_well_formed` — see the note there on why it is one test.
}
