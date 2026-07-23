//! The single issue/redeem primitive for **emailed bearer credentials** (t95 §2.2).
//!
//! An invite link, a password-recovery link and an emailed two-factor confirmation are the same
//! object wearing three hats: a high-entropy secret that the server mails to an address, that the
//! recipient hands back once, and that authorizes exactly one act. Building three of those is how
//! two of them end up missing a rule. So there is one type, one store, one redeem path, and a
//! [`AuthTokenPurpose`] discriminator.
//!
//! **This module ships with its full test suite and deliberately no callers.** It is P0 of the t95
//! tranche: the signup, recovery and two-factor handlers (P1) are the callers, and they are written
//! against a primitive that already enforces the rules rather than re-deriving them three times.
//! It is not dead code — it is the code the next phase is blocked on.
//!
//! ## What the primitive guarantees
//!
//! | Property | How |
//! |---|---|
//! | Entropy | 256 bits from the OS CSPRNG per token ([`TOKEN_ENTROPY_BYTES`]). |
//! | Storage | **Verifier only** — SHA-256 of the token bytes. The plaintext exists in exactly one place, the outbound message, and is unrecoverable from the store. |
//! | Single use | [`AuthTokenStore::redeem`] removes the record *before* returning it, so the effect can never run twice off one token. |
//! | Supersession | Issuing a token invalidates every earlier token of the same purpose for the same subject. |
//! | Expiry | Every record carries an absolute `expires_at`; the caller supplies `now`, so time is testable and never read from the wall clock inside the store. |
//! | Uniform failure | Unknown, expired, superseded, wrong-purpose and cross-subject all produce the *same* [`AuthTokenError::Invalid`]. A redeemer learns nothing about why. |
//! | Secrecy in transit through this process | [`AuthTokenSecret`] has no `Serialize`, a redacting `Debug`/`Display`, and zeroes itself on drop. Logging one, or putting one in an [`ApiError`](crate::error::ApiError) or a ledger payload, requires calling [`AuthTokenSecret::expose`] on purpose. |
//!
//! ## Why SHA-256 and not argon2
//!
//! The stored verifier is a plain SHA-256 digest, and that is correct here rather than a lapse. A
//! slow KDF exists to make *guessable* secrets expensive to attack. These secrets are 256 bits of
//! CSPRNG output — there is no dictionary, and no amount of iteration count changes an attack that
//! is already infeasible. Argon2 is used for passwords and recovery phrases (`attestation.rs`)
//! because a human chose or transcribed those; nobody chose this.
//!
//! ## What this primitive is NOT for
//!
//! A **short human-typed code** (a six-digit emailed PIN) must not be routed through this store as
//! it stands. Lookup here is by digest of the presented secret, so a failed redeem matches no
//! record — which means there is nothing to hang a per-credential attempt counter on, and a
//! six-digit code with unlimited attempts is a million-guess wall an attacker walks straight
//! through. A low-entropy code needs a server-issued challenge id to count attempts against
//! ([t95 §2.3 says the same thing about TOTP throttling]). [`AuthTokenPurpose::TwoFactorEmailCode`]
//! therefore means *a full-entropy emailed confirmation token*, not a PIN.
//!
//! Magic link is **not** a purpose here: it was dropped from the tranche.

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;
use zeroize::Zeroize;

/// Bytes of OS entropy behind every token: 32 bytes = **256 bits**.
pub const TOKEN_ENTROPY_BYTES: usize = 32;

/// What a token authorizes. The purpose is part of the lookup, so a recovery token presented to the
/// invite endpoint is simply not found — cross-purpose replay fails as an unknown token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AuthTokenPurpose {
    /// An invitation to create an account. Addressed to an email that may not have a user yet.
    #[serde(rename = "invite")]
    Invite,
    /// A password-recovery link. Authorizes setting a new secret for one existing user.
    #[serde(rename = "password_recovery")]
    PasswordRecovery,
    /// A full-entropy emailed second-factor confirmation. See the module note on why this is not a
    /// six-digit PIN.
    #[serde(rename = "two_factor_email_code")]
    TwoFactorEmailCode,
}

impl AuthTokenPurpose {
    /// The stable dotted-free id used in serde and in operator-facing messages.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            AuthTokenPurpose::Invite => "invite",
            AuthTokenPurpose::PasswordRecovery => "password_recovery",
            AuthTokenPurpose::TwoFactorEmailCode => "two_factor_email_code",
        }
    }

    /// The default lifetime for this purpose (t95 §2.2): invites are a scheduling problem measured
    /// in days, recovery and second-factor confirmations are measured in minutes because they are
    /// acted on immediately or not at all.
    #[must_use]
    pub const fn default_ttl(self) -> Duration {
        match self {
            AuthTokenPurpose::Invite => Duration::hours(168),
            AuthTokenPurpose::PasswordRecovery => Duration::minutes(15),
            AuthTokenPurpose::TwoFactorEmailCode => Duration::minutes(10),
        }
    }

    /// The inclusive bounds a configured lifetime is clamped to. A settings document — or a bug —
    /// can never produce a token that lives longer than this, nor one that has already expired by
    /// the time the mail is delivered.
    #[must_use]
    pub const fn ttl_bounds(self) -> (Duration, Duration) {
        match self {
            AuthTokenPurpose::Invite => (Duration::hours(1), Duration::days(30)),
            AuthTokenPurpose::PasswordRecovery => (Duration::minutes(5), Duration::hours(1)),
            AuthTokenPurpose::TwoFactorEmailCode => (Duration::minutes(2), Duration::minutes(30)),
        }
    }

    /// Clamp a requested lifetime into [`ttl_bounds`](Self::ttl_bounds). Deliberately clamping
    /// rather than erroring: this runs at issue time, where the alternative to a shorter-than-asked
    /// token is no token at all, and settings validation has already refused out-of-range values at
    /// configuration time.
    #[must_use]
    pub fn clamp_ttl(self, requested: Duration) -> Duration {
        let (min, max) = self.ttl_bounds();
        requested.clamp(min, max)
    }
}

impl std::fmt::Display for AuthTokenPurpose {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Who a token is for.
///
/// An invite is addressed to an **email that has no account yet**, so the subject cannot always be
/// a user id. Both forms compare by value, which is what makes "supersede the previous token for
/// this subject" and "invalidate everything for this user" single-line operations.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuthTokenSubject {
    /// An existing account.
    User { id: Uuid },
    /// An address with no account yet (invite). Stored lowercased and trimmed so
    /// `Ana@Example.PT` and `ana@example.pt` are the same subject and cannot each hold a live
    /// invite.
    Email { address: String },
}

impl AuthTokenSubject {
    /// A subject for an existing user.
    #[must_use]
    pub fn user(id: Uuid) -> Self {
        AuthTokenSubject::User { id }
    }

    /// A subject for an invited address, normalised.
    #[must_use]
    pub fn email(address: &str) -> Self {
        AuthTokenSubject::Email {
            address: address.trim().to_lowercase(),
        }
    }

    /// The user id, when this subject names an existing account.
    #[must_use]
    pub fn user_id(&self) -> Option<Uuid> {
        match self {
            AuthTokenSubject::User { id } => Some(*id),
            AuthTokenSubject::Email { .. } => None,
        }
    }
}

/// The plaintext token. **The only place a plaintext token legitimately exists in this process.**
///
/// Deliberately hostile to accidental disclosure: no `Serialize` (so it cannot reach a ledger
/// payload, an `Event.justification`, or any response body by derive), no `Clone` (so it cannot be
/// quietly duplicated into a log line), a `Debug`/`Display` that prints a fixed placeholder, and a
/// `Drop` that zeroes the buffer. Getting the characters out requires [`expose`](Self::expose),
/// which is greppable.
pub struct AuthTokenSecret(String);

impl AuthTokenSecret {
    /// The token characters, for the one legitimate consumer: building the outbound email body.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// This token's verifier, for callers that want to correlate without holding the plaintext.
    #[must_use]
    pub fn verifier(&self) -> AuthTokenVerifier {
        AuthTokenVerifier::of(&self.0)
    }
}

impl std::fmt::Debug for AuthTokenSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthTokenSecret(<redacted>)")
    }
}

impl std::fmt::Display for AuthTokenSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

impl Drop for AuthTokenSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// The SHA-256 verifier of a token: what the server stores, and all it ever stores.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AuthTokenVerifier(#[serde(with = "verifier_hex")] [u8; 32]);

impl AuthTokenVerifier {
    /// Hash a presented token into its verifier.
    #[must_use]
    pub fn of(presented: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(presented.as_bytes());
        let digest: [u8; 32] = hasher.finalize().into();
        AuthTokenVerifier(digest)
    }

    /// Constant-time equality. The store looks records up by verifier, so this is not the last line
    /// of defence — but comparing 32-byte digests with `==` is exactly the habit that becomes a
    /// timing oracle the day someone reuses this type against a low-entropy secret.
    #[must_use]
    pub fn matches(&self, other: &AuthTokenVerifier) -> bool {
        let mut diff = 0u8;
        for (a, b) in self.0.iter().zip(other.0.iter()) {
            diff |= a ^ b;
        }
        diff == 0
    }
}

/// Redacted: a verifier is not the secret, but keeping it out of logs keeps the rule ("no token
/// material in logs") flat and unarguable.
impl std::fmt::Debug for AuthTokenVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthTokenVerifier(<redacted>)")
    }
}

mod verifier_hex {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&crate::hex::hex(bytes))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let raw = String::deserialize(d)?;
        crate::hex::parse_hex32(&raw).ok_or_else(|| {
            serde::de::Error::custom("auth token verifier must be 64-char sha256 hex")
        })
    }
}

/// A stored token: everything except the token itself.
///
/// Safe to persist — it holds a verifier, not a credential — which is what lets the store survive a
/// restart without a live recovery link silently becoming unredeemable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthTokenRecord {
    /// Stable id for this issuance. P1 keys its own per-purpose detail (an invite's role and scope,
    /// say) by this id rather than putting that detail here, so the token store never grows fields
    /// that a future author might be tempted to fill with something sensitive.
    pub id: Uuid,
    pub purpose: AuthTokenPurpose,
    pub subject: AuthTokenSubject,
    #[serde(with = "time::serde::rfc3339")]
    pub issued_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    verifier: AuthTokenVerifier,
}

impl AuthTokenRecord {
    /// Whether this record is still live at `now`.
    #[must_use]
    pub fn is_live_at(&self, now: OffsetDateTime) -> bool {
        now < self.expires_at
    }
}

/// The one failure a redeemer ever sees.
///
/// Single-variant on purpose. Unknown, expired, already-used, superseded, wrong-purpose and
/// belongs-to-someone-else must be indistinguishable, or the endpoint becomes an oracle for which
/// addresses have live invites.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthTokenError {
    /// The presented token is not redeemable. No further detail, by design.
    Invalid,
}

impl std::fmt::Display for AuthTokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // pt-PT, user-facing: the same sentence for every cause.
        f.write_str("ligação inválida ou expirada")
    }
}

impl std::error::Error for AuthTokenError {}

/// The live token set, keyed by verifier.
///
/// Keyed by verifier rather than by id because the redeem path only ever has the presented secret,
/// and a map lookup on a full-entropy digest is both the fastest and the least branchy way to find
/// (or not find) it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AuthTokenStore {
    records: BTreeMap<AuthTokenVerifier, AuthTokenRecord>,
}

impl AuthTokenStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// How many live-or-not records are held. Test/diagnostic surface only.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Issue a token: 256 bits of OS entropy, stored as a verifier, returned as a secret exactly
    /// once.
    ///
    /// Issuing **supersedes** every earlier token of the same purpose for the same subject. That is
    /// what makes "I clicked forgot-password three times, which mail is live?" have one answer, and
    /// it means a recovery link that leaked from an old mailbox copy is dead the moment a newer one
    /// is requested.
    ///
    /// `now` and `ttl` are parameters rather than reads of the clock and settings, so this function
    /// has no ambient inputs and its expiry behaviour is directly testable.
    pub fn issue(
        &mut self,
        purpose: AuthTokenPurpose,
        subject: AuthTokenSubject,
        ttl: Duration,
        now: OffsetDateTime,
    ) -> (AuthTokenSecret, AuthTokenRecord) {
        self.prune_expired(now);
        self.invalidate_purpose_for_subject(purpose, &subject);

        let mut bytes = [0u8; TOKEN_ENTROPY_BYTES];
        OsRng.fill_bytes(&mut bytes);
        let plaintext = B64URL.encode(bytes);
        bytes.zeroize();

        let verifier = AuthTokenVerifier::of(&plaintext);
        let record = AuthTokenRecord {
            id: Uuid::new_v4(),
            purpose,
            subject,
            issued_at: now,
            expires_at: now.saturating_add(purpose.clamp_ttl(ttl)),
            verifier,
        };
        self.records.insert(verifier, record.clone());
        (AuthTokenSecret(plaintext), record)
    }

    /// Issue with this purpose's default lifetime.
    pub fn issue_default_ttl(
        &mut self,
        purpose: AuthTokenPurpose,
        subject: AuthTokenSubject,
        now: OffsetDateTime,
    ) -> (AuthTokenSecret, AuthTokenRecord) {
        self.issue(purpose, subject, purpose.default_ttl(), now)
    }

    /// Redeem a presented token for `purpose`.
    ///
    /// **Removes the record before returning it**, unconditionally and including on the expired
    /// path. The caller therefore cannot structure its code so that a failure mid-effect leaves the
    /// token replayable: by the time it has a record in hand, that token is already spent. A second
    /// presentation of the same string finds nothing and gets the identical
    /// [`AuthTokenError::Invalid`] as a token that never existed.
    ///
    /// Every rejection is the same error. Callers must not translate it into a more specific
    /// message — "expired" versus "unknown" tells a stranger whether the address has an account.
    pub fn redeem(
        &mut self,
        purpose: AuthTokenPurpose,
        presented: &str,
        now: OffsetDateTime,
    ) -> Result<AuthTokenRecord, AuthTokenError> {
        let verifier = AuthTokenVerifier::of(presented);
        // Take it out first: an expired or wrong-purpose hit is still a spent token, and leaving it
        // behind would let an attacker probe the same string until the clock or the purpose suited.
        let Some(record) = self.records.remove(&verifier) else {
            return Err(AuthTokenError::Invalid);
        };
        if !record.verifier.matches(&verifier)
            || record.purpose != purpose
            || !record.is_live_at(now)
        {
            return Err(AuthTokenError::Invalid);
        }
        Ok(record)
    }

    /// Drop every token for a subject, whatever its purpose. Returns how many were dropped.
    ///
    /// This is the hook for the events that must kill outstanding links (t95 §2.2): **password
    /// change or set-secret**, recovery-phrase reset, user deactivation, and "sign out everywhere".
    /// A recovery link that survives the password change it caused is a second, quieter password.
    pub fn invalidate_subject(&mut self, subject: &AuthTokenSubject) -> usize {
        let before = self.records.len();
        self.records.retain(|_, record| &record.subject != subject);
        before - self.records.len()
    }

    /// Drop every token for a user id, whatever its purpose. Convenience over
    /// [`invalidate_subject`](Self::invalidate_subject) for the common call site.
    pub fn invalidate_user(&mut self, user_id: Uuid) -> usize {
        self.invalidate_subject(&AuthTokenSubject::user(user_id))
    }

    /// Drop every token of one purpose for one subject. Returns how many were dropped.
    pub fn invalidate_purpose_for_subject(
        &mut self,
        purpose: AuthTokenPurpose,
        subject: &AuthTokenSubject,
    ) -> usize {
        let before = self.records.len();
        self.records
            .retain(|_, record| !(record.purpose == purpose && &record.subject == subject));
        before - self.records.len()
    }

    /// Drop everything already expired at `now`. Called at the head of [`issue`](Self::issue) so
    /// the store cannot grow without bound on an instance that never redeems anything.
    pub fn prune_expired(&mut self, now: OffsetDateTime) -> usize {
        let before = self.records.len();
        self.records.retain(|_, record| record.is_live_at(now));
        before - self.records.len()
    }

    /// The live records for a subject, for diagnostics and tests. Never exposes token material.
    #[must_use]
    pub fn live_for_subject(
        &self,
        subject: &AuthTokenSubject,
        now: OffsetDateTime,
    ) -> Vec<&AuthTokenRecord> {
        self.records
            .values()
            .filter(|record| &record.subject == subject && record.is_live_at(now))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t0() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_770_000_000).expect("valid timestamp")
    }

    fn user() -> AuthTokenSubject {
        AuthTokenSubject::user(Uuid::from_u128(0x5eed_0001))
    }

    #[test]
    fn an_issued_token_is_full_entropy_url_safe_and_unique() {
        let mut store = AuthTokenStore::new();
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..64 {
            let (secret, _) = store.issue_default_ttl(
                AuthTokenPurpose::Invite,
                AuthTokenSubject::email(&format!("{}@example.pt", Uuid::new_v4())),
                t0(),
            );
            let raw = secret.expose().to_owned();
            // 32 bytes base64url without padding is 43 characters.
            assert_eq!(raw.len(), 43, "unexpected token length: {}", raw.len());
            assert!(
                raw.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
                "token is not URL-safe: {raw}"
            );
            assert!(seen.insert(raw), "the CSPRNG repeated a token");
        }
    }

    #[test]
    fn the_store_never_holds_the_plaintext() {
        let mut store = AuthTokenStore::new();
        let (secret, record) =
            store.issue_default_ttl(AuthTokenPurpose::PasswordRecovery, user(), t0());
        let plaintext = secret.expose().to_owned();

        // The whole persisted form, exactly as it would reach disk or a Postgres row.
        let serialized = serde_json::to_string(&store).expect("store serialises");
        assert!(
            !serialized.contains(&plaintext),
            "the persisted store contains the plaintext token"
        );
        // And nothing on the record leaks it either — including its Debug rendering, which is what
        // a `tracing::warn!("{record:?}")` would emit.
        assert!(!format!("{record:?}").contains(&plaintext));
        assert!(!format!("{store:?}").contains(&plaintext));
        // The verifier is a hash, not the token.
        assert!(serialized.contains(&crate::hex::hex(&{
            let mut h = Sha256::new();
            h.update(plaintext.as_bytes());
            let d: [u8; 32] = h.finalize().into();
            d
        })));
    }

    /// The redaction guard the tranche's "never log a token" rule actually rests on: a token
    /// reaches a log line, an `ApiError` message or an `Event.justification` through `Display` or
    /// `Debug`, and both must be inert.
    #[test]
    fn secret_display_and_debug_are_redacted_and_it_does_not_serialize() {
        let mut store = AuthTokenStore::new();
        let (secret, _) = store.issue_default_ttl(AuthTokenPurpose::Invite, user(), t0());
        let plaintext = secret.expose().to_owned();
        assert_eq!(format!("{secret}"), "<redacted>");
        assert_eq!(format!("{secret:?}"), "AuthTokenSecret(<redacted>)");
        assert!(!format!("{secret} {secret:?}").contains(&plaintext));
        // `AuthTokenSecret: !Serialize` is enforced by the compiler; this is the runtime half —
        // formatting it into a justification string, the way t88 records one verbatim, is inert.
        let justification = format!("recovery link issued: {secret}");
        assert!(!justification.contains(&plaintext));
    }

    #[test]
    fn a_token_redeems_exactly_once() {
        let mut store = AuthTokenStore::new();
        let (secret, issued) =
            store.issue_default_ttl(AuthTokenPurpose::PasswordRecovery, user(), t0());
        let raw = secret.expose().to_owned();

        let redeemed = store
            .redeem(AuthTokenPurpose::PasswordRecovery, &raw, t0())
            .expect("first redeem succeeds");
        assert_eq!(redeemed.id, issued.id);
        assert_eq!(redeemed.subject, user());

        assert_eq!(
            store.redeem(AuthTokenPurpose::PasswordRecovery, &raw, t0()),
            Err(AuthTokenError::Invalid),
            "a replay must fail"
        );
        assert!(store.is_empty());
    }

    #[test]
    fn an_expired_token_fails_and_is_indistinguishable_from_an_unknown_one() {
        let mut store = AuthTokenStore::new();
        let (secret, _) = store.issue(
            AuthTokenPurpose::PasswordRecovery,
            user(),
            Duration::minutes(15),
            t0(),
        );
        let raw = secret.expose().to_owned();

        let expired = store.redeem(
            AuthTokenPurpose::PasswordRecovery,
            &raw,
            t0() + Duration::minutes(16),
        );
        let unknown = store.redeem(
            AuthTokenPurpose::PasswordRecovery,
            "totally-made-up-token-value",
            t0(),
        );
        assert_eq!(expired, Err(AuthTokenError::Invalid));
        assert_eq!(expired, unknown);
        assert_eq!(
            expired.unwrap_err().to_string(),
            unknown.unwrap_err().to_string()
        );
    }

    /// A token is still live one instant before it expires and dead at the instant itself, so a
    /// clock skew of one second cannot resurrect one.
    #[test]
    fn expiry_is_exclusive_at_the_boundary() {
        let mut store = AuthTokenStore::new();
        let (secret, _) = store.issue(
            AuthTokenPurpose::PasswordRecovery,
            user(),
            Duration::minutes(15),
            t0(),
        );
        let raw = secret.expose().to_owned();
        let mut probe = store.clone();
        assert!(
            probe
                .redeem(
                    AuthTokenPurpose::PasswordRecovery,
                    &raw,
                    t0() + Duration::minutes(15) - Duration::seconds(1)
                )
                .is_ok()
        );
        assert_eq!(
            store.redeem(
                AuthTokenPurpose::PasswordRecovery,
                &raw,
                t0() + Duration::minutes(15)
            ),
            Err(AuthTokenError::Invalid)
        );
    }

    #[test]
    fn a_token_cannot_be_redeemed_against_a_different_purpose() {
        let mut store = AuthTokenStore::new();
        let (secret, _) = store.issue_default_ttl(AuthTokenPurpose::Invite, user(), t0());
        let raw = secret.expose().to_owned();
        assert_eq!(
            store.redeem(AuthTokenPurpose::PasswordRecovery, &raw, t0()),
            Err(AuthTokenError::Invalid)
        );
        // And it is spent even though it was presented to the wrong door — probing must not be free.
        assert_eq!(
            store.redeem(AuthTokenPurpose::Invite, &raw, t0()),
            Err(AuthTokenError::Invalid)
        );
    }

    #[test]
    fn issuing_supersedes_the_previous_token_of_the_same_purpose_for_that_subject() {
        let mut store = AuthTokenStore::new();
        let (first, _) = store.issue_default_ttl(AuthTokenPurpose::PasswordRecovery, user(), t0());
        let first_raw = first.expose().to_owned();
        let (second, _) = store.issue_default_ttl(AuthTokenPurpose::PasswordRecovery, user(), t0());
        let second_raw = second.expose().to_owned();

        assert_eq!(
            store.redeem(AuthTokenPurpose::PasswordRecovery, &first_raw, t0()),
            Err(AuthTokenError::Invalid),
            "the older recovery link must be dead"
        );
        assert!(
            store
                .redeem(AuthTokenPurpose::PasswordRecovery, &second_raw, t0())
                .is_ok()
        );
    }

    /// Supersession is scoped: a new invite must not kill a live recovery link, and one user's
    /// tokens must not touch another's.
    #[test]
    fn supersession_does_not_cross_purposes_or_subjects() {
        let mut store = AuthTokenStore::new();
        let other = AuthTokenSubject::user(Uuid::from_u128(0x5eed_0002));
        let (recovery, _) =
            store.issue_default_ttl(AuthTokenPurpose::PasswordRecovery, user(), t0());
        let (theirs, _) =
            store.issue_default_ttl(AuthTokenPurpose::PasswordRecovery, other.clone(), t0());
        let recovery_raw = recovery.expose().to_owned();
        let theirs_raw = theirs.expose().to_owned();

        let _ = store.issue_default_ttl(AuthTokenPurpose::Invite, user(), t0());

        assert!(
            store
                .redeem(AuthTokenPurpose::PasswordRecovery, &recovery_raw, t0())
                .is_ok()
        );
        assert!(
            store
                .redeem(AuthTokenPurpose::PasswordRecovery, &theirs_raw, t0())
                .is_ok()
        );
    }

    /// The password-change hook. A recovery link that survives the reset it authorized is a second
    /// password sitting in a mailbox.
    #[test]
    fn invalidating_a_user_kills_every_purpose_for_that_user_only() {
        let mut store = AuthTokenStore::new();
        let other = AuthTokenSubject::user(Uuid::from_u128(0x5eed_0002));
        let (recovery, _) =
            store.issue_default_ttl(AuthTokenPurpose::PasswordRecovery, user(), t0());
        let (second_factor, _) =
            store.issue_default_ttl(AuthTokenPurpose::TwoFactorEmailCode, user(), t0());
        let (untouched, _) =
            store.issue_default_ttl(AuthTokenPurpose::PasswordRecovery, other, t0());
        let recovery_raw = recovery.expose().to_owned();
        let second_factor_raw = second_factor.expose().to_owned();
        let untouched_raw = untouched.expose().to_owned();

        assert_eq!(store.invalidate_user(Uuid::from_u128(0x5eed_0001)), 2);

        for (purpose, raw) in [
            (AuthTokenPurpose::PasswordRecovery, &recovery_raw),
            (AuthTokenPurpose::TwoFactorEmailCode, &second_factor_raw),
        ] {
            assert_eq!(
                store.redeem(purpose, raw, t0()),
                Err(AuthTokenError::Invalid),
                "{purpose} survived the password change"
            );
        }
        assert!(
            store
                .redeem(AuthTokenPurpose::PasswordRecovery, &untouched_raw, t0())
                .is_ok(),
            "another user's token must be untouched"
        );
    }

    #[test]
    fn an_invite_subject_is_normalised_so_one_address_holds_one_live_invite() {
        let mut store = AuthTokenStore::new();
        let (first, _) = store.issue_default_ttl(
            AuthTokenPurpose::Invite,
            AuthTokenSubject::email("  Amelia.Marques@Example.PT "),
            t0(),
        );
        let first_raw = first.expose().to_owned();
        let (_second, record) = store.issue_default_ttl(
            AuthTokenPurpose::Invite,
            AuthTokenSubject::email("amelia.marques@example.pt"),
            t0(),
        );
        assert_eq!(
            record.subject,
            AuthTokenSubject::Email {
                address: "amelia.marques@example.pt".to_owned()
            }
        );
        assert_eq!(
            store.redeem(AuthTokenPurpose::Invite, &first_raw, t0()),
            Err(AuthTokenError::Invalid),
            "a differently-cased address must be the same subject"
        );
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn ttls_are_clamped_into_their_purpose_bounds() {
        for purpose in [
            AuthTokenPurpose::Invite,
            AuthTokenPurpose::PasswordRecovery,
            AuthTokenPurpose::TwoFactorEmailCode,
        ] {
            let (min, max) = purpose.ttl_bounds();
            assert!(
                min <= purpose.default_ttl() && purpose.default_ttl() <= max,
                "{purpose}"
            );
            assert_eq!(purpose.clamp_ttl(Duration::days(3650)), max, "{purpose}");
            assert_eq!(purpose.clamp_ttl(Duration::ZERO), min, "{purpose}");
            assert_eq!(purpose.clamp_ttl(-Duration::days(1)), min, "{purpose}");
        }

        // A caller asking for an absurd lifetime gets the clamp, not the ask.
        let mut store = AuthTokenStore::new();
        let (_secret, record) = store.issue(
            AuthTokenPurpose::PasswordRecovery,
            user(),
            Duration::days(365),
            t0(),
        );
        assert_eq!(record.expires_at, t0() + Duration::hours(1));
    }

    #[test]
    fn pruning_drops_only_expired_records() {
        let mut store = AuthTokenStore::new();
        let _ = store.issue(
            AuthTokenPurpose::PasswordRecovery,
            user(),
            Duration::minutes(15),
            t0(),
        );
        let (live, _) = store.issue_default_ttl(
            AuthTokenPurpose::Invite,
            AuthTokenSubject::email("amelia.marques@example.pt"),
            t0(),
        );
        let live_raw = live.expose().to_owned();

        assert_eq!(store.prune_expired(t0() + Duration::hours(2)), 1);
        assert_eq!(store.len(), 1);
        assert!(
            store
                .redeem(
                    AuthTokenPurpose::Invite,
                    &live_raw,
                    t0() + Duration::hours(2)
                )
                .is_ok()
        );
    }

    #[test]
    fn the_store_round_trips_through_serde_with_tokens_still_redeemable() {
        let mut store = AuthTokenStore::new();
        let (secret, _) = store.issue_default_ttl(AuthTokenPurpose::PasswordRecovery, user(), t0());
        let raw = secret.expose().to_owned();

        let json = serde_json::to_string(&store).expect("serialise");
        let mut restored: AuthTokenStore = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(restored, store);
        assert!(
            restored
                .redeem(AuthTokenPurpose::PasswordRecovery, &raw, t0())
                .is_ok(),
            "a restart must not silently invalidate a live recovery link"
        );
    }

    #[test]
    fn verifier_comparison_is_value_based_and_purpose_ids_are_stable() {
        assert!(AuthTokenVerifier::of("abc").matches(&AuthTokenVerifier::of("abc")));
        assert!(!AuthTokenVerifier::of("abc").matches(&AuthTokenVerifier::of("abd")));
        assert!(!format!("{:?}", AuthTokenVerifier::of("abc")).contains("abc"));

        for (purpose, id) in [
            (AuthTokenPurpose::Invite, "invite"),
            (AuthTokenPurpose::PasswordRecovery, "password_recovery"),
            (
                AuthTokenPurpose::TwoFactorEmailCode,
                "two_factor_email_code",
            ),
        ] {
            assert_eq!(purpose.as_str(), id);
            assert_eq!(
                serde_json::to_string(&purpose).unwrap(),
                format!("\"{id}\"")
            );
            assert_eq!(
                serde_json::from_str::<AuthTokenPurpose>(&format!("\"{id}\"")).unwrap(),
                purpose
            );
        }
    }

    /// Magic link was dropped from the tranche by explicit ruling. If it comes back it must come
    /// back as a decision, not as a variant someone adds while passing through — and §1 of the plan
    /// says a magic-link session cannot attest, so that decision has consequences well beyond this
    /// file.
    #[test]
    fn there_is_no_magic_link_purpose() {
        let ids: Vec<&str> = [
            AuthTokenPurpose::Invite,
            AuthTokenPurpose::PasswordRecovery,
            AuthTokenPurpose::TwoFactorEmailCode,
        ]
        .iter()
        .map(|p| p.as_str())
        .collect();
        assert_eq!(ids.len(), 3);
        assert!(serde_json::from_str::<AuthTokenPurpose>("\"magic_link\"").is_err());
    }
}
