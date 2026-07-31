//! **The credential taxonomy** — what an account can hold, and what each kind is *for*.
//!
//! This module exists because two security rules were previously written in terms of the two
//! credential fields that happened to exist (`password_hash`, `recovery_hash`) rather than in terms
//! of the *question they were asking*. Both rules silently change meaning the moment a third kind
//! appears:
//!
//! 1. **The step-up vacuity exemption** ([`step_up_is_vacuous`], read by
//!    [`crate::data::require_step_up`] and by the device-pairing mail path in [`crate::pairing`]).
//!    Written as `password_hash.is_none() && recovery_hash.is_none()`, it says "this account holds
//!    nothing, so its session is the strongest proof it can offer". Add a credential kind that can
//!    start a session — a passkey — and the same expression starts saying "this account holds
//!    nothing *of the two kinds I was written for*", and every `ConfirmWithReauth` gate in the
//!    product (book close, ledger re-anchor, factory reset, privacy erasure) opens on a session
//!    token alone for its holder. Nothing about that widening is visible at the call sites; the
//!    predicate just quietly stops being true.
//! 2. **The account-lifecycle invariant** ([`ensure_removal_leaves_account_usable`]). *After an
//!    operation that removes a credential, the account must retain at least one credential that can
//!    start a session, one that can recover it, and — where an attestation key exists — at least one
//!    non-PRF wrap of that key.* `chancela_authz::last_owner_guard` does not cover this: it guards
//!    **role holding**, not **sign-in ability**, so it does not see the last Owner revoking their
//!    own last credential.
//!
//! So the two rules are derived from **per-kind declarations** instead. [`CredentialKind`] and its
//! [`ALL`](CredentialKind::ALL) list are generated from one list by [`credential_kinds!`], so a
//! variant cannot exist without being enumerated; and each of the four declarations
//! ([`step_up_role`](CredentialKind::step_up_role), [`session_role`](CredentialKind::session_role),
//! [`recovery_role`](CredentialKind::recovery_role), [`wrap_role`](CredentialKind::wrap_role), plus
//! [`is_held_by`](CredentialKind::is_held_by)) is an **exhaustive match with no wildcard arm**, so a
//! new kind fails to compile until its author has answered every question. There is deliberately no
//! `Default` and no `_ =>` fallback anywhere in this file: a default here is the bug, because the
//! defaulted answer ("cannot satisfy step-up") is precisely the widening.
//!
//! **Recovering the account and wrapping the key are two questions, and conflating them is the
//! documented trap.** A recovery-phrase reset *cannot* re-wrap the attestation key — it retires it
//! (`users.rs::set_secret`, the `CrossUser(ProofKind::Recovery)` arm) — so the phrase satisfies
//! "can recover the account" and contributes **nothing** to key custody. They are therefore separate
//! declarations, [`recovery_role`](CredentialKind::recovery_role) and
//! [`wrap_role`](CredentialKind::wrap_role), and no kind may answer one by answering the other.
//!
//! The consistency between the declarations is itself checked **at compile time** — see the
//! `const _` block below, which refuses a kind that can start a session but does not count toward
//! step-up.
//!
//! ## Where the passkey proof arm plugged in
//!
//! [`CredentialKind::Passkey`] was declared here one commit before it had any storage, deliberately:
//! the rules had to be right *before* an account could hold one, rather than be widened by the lane
//! that made it possible. Its step-up role was [`StepUpRole::ProofPending`] — counting toward
//! non-vacuity, so a passkey-only account could never be exempted on its session alone, while
//! [`crate::data::require_step_up`] had no arm that could verify an assertion. Fail-closed, and
//! admissible only while nobody could hold one.
//!
//! t10 closed it, and the two halves had to land together. [`crate::passkeys`] now stores
//! credentials on the user record ([`is_held_by`](CredentialKind::is_held_by) reads that list) and
//! `require_step_up` verifies an assertion bound to a server-issued, single-use, step-up-scoped
//! challenge — so the role is [`StepUpRole::VerifiedProof`]. Shipping the first half alone would
//! have locked passkey-only users out of every destructive operation; the second alone is the
//! widening this module exists to prevent.
//!
//! [`StepUpRole::ProofPending`] is kept, with no kind declaring it. It is the shape the *next*
//! credential kind will pass through, and its documentation is the checklist that got this one
//! right.

use std::collections::BTreeSet;

use crate::error::ApiError;
use crate::users::User;

/// Declares [`CredentialKind`] **and** its complete enumeration from a single list.
///
/// The point is that the two cannot drift: `ALL` is not a hand-maintained mirror of the enum, it is
/// the same list. A variant that is not in `ALL` is unreachable by every rule in this module, and
/// this makes writing one impossible rather than merely discouraged.
macro_rules! credential_kinds {
    ($( $(#[$meta:meta])* $variant:ident ),+ $(,)?) => {
        /// A kind of credential an account can hold.
        ///
        /// **Not** a kind of *proof* and not a second-factor taxonomy: this enumerates what the
        /// account record can carry, and the three role declarations below say what each carried
        /// thing is good for. A new kind must answer all three.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub(crate) enum CredentialKind {
            $( $(#[$meta])* $variant, )+
        }

        impl CredentialKind {
            /// Every credential kind, in declaration order. Generated from the same list as the
            /// enum itself, so it is complete by construction.
            pub(crate) const ALL: &'static [CredentialKind] = &[ $( CredentialKind::$variant, )+ ];
        }
    };
}

credential_kinds! {
    /// The account's sign-in password. Verified with argon2id against `User::password_hash`.
    Password,
    /// The single-use recovery phrase (`User::recovery_hash`) — an independent credential, not
    /// derived from and not wrapping the password. It resets a password; it does not start a
    /// session on its own.
    RecoveryPhrase,
    /// A **confirmed** TOTP second factor (`User::totp`). A pending enrolment is not a credential:
    /// it grants nothing and is not counted here.
    TwoFactorTotp,
    /// A WebAuthn passkey (`User::passkeys`). An account holds *the kind* while it holds at least
    /// one credential of it; "is this the last one" is a question only the revocation handler
    /// (`crate::passkeys::revoke_passkey`) has to answer, and it builds the post-state set itself.
    Passkey,
}

/// What [`crate::data::require_step_up`] can do with a credential of a given kind.
///
/// This is the declaration the vacuity exemption is derived from, and the one whose absent-by-
/// default answer was the bug: a kind that is not named is a kind that does not count, and a
/// session-capable kind that does not count opens every `ConfirmWithReauth` gate for its holder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StepUpRole {
    /// `require_step_up` has an arm that verifies a proof of this kind. Holding it makes step-up
    /// non-vacuous **and** its holder can satisfy the gate.
    VerifiedProof,
    /// Holding it makes step-up **non-vacuous**, but `require_step_up` has no arm that can verify
    /// it yet, so its holder cannot satisfy the gate. Fail-closed, and admissible **only** while no
    /// account can actually hold the kind.
    ///
    /// **No kind declares this today.** It is retained as the state the *next* credential kind
    /// passes through, and because the list below is the checklist that got the passkey one right.
    ///
    /// **What a proof arm owes, exactly** — this is what `t10` delivered for
    /// [`CredentialKind::Passkey`], and what any successor owes too:
    ///
    /// 1. An optional proof field on [`crate::data::ReAuth`], beside `password` and
    ///    `recovery_phrase` — **not** a new [`crate::confirmation::ConfirmationStrictness`] rung.
    ///    The ladder answers *how hard*; the user's choice answers *with what*. The existing
    ///    precedent is [`crate::confirmation::PairingConfirmationMethod`]
    ///    (`Password | TotpCode | EmailedCode`), including its deployment-narrowable accepted set.
    ///    *(The passkey field landed; the narrowable accepted set did not, and is the one item of
    ///    this list still outstanding — it is additive and changes no default.)*
    /// 2. A verification arm in `require_step_up` that accepts that proof for the acting user's
    ///    own enrolled credentials, and the kind flipped to [`Self::VerifiedProof`].
    /// 3. **A server-issued, single-use, short-TTL challenge scoped to step-up.** Not a sign-in
    ///    challenge, and never a client-chosen nonce: without this binding, a passkey assertion
    ///    captured at sign-in replays into a factory reset. This is the one detail that is not
    ///    optional and not deferrable. See [`crate::passkeys::CeremonyPurpose`].
    /// 4. [`CredentialKind::is_held_by`] reading the real credential list, so an account holding
    ///    only that kind is genuinely non-vacuous rather than non-vacuous in principle.
    ///
    /// (2) and (4) must land together with whatever endpoint lets the kind be established: (4)
    /// without (2) locks its holders out of every destructive operation, and (2) without (4) is
    /// the widening this module exists to prevent.
    #[cfg_attr(not(test), allow(dead_code))]
    ProofPending,
    /// Not a proof `require_step_up` can demand, and its presence must not make a gate
    /// unsatisfiable for its holder.
    ///
    /// **Why TOTP is here, and why that is not the same hole.** A confirmed TOTP factor is a real
    /// credential, and `require_step_up` has no arm for it — so counting it would make every
    /// `ConfirmWithReauth` gate unsatisfiable for an account that holds nothing else, which is a
    /// lockout, not a tightening. It is safe to leave outside *because TOTP cannot start a
    /// session*: `create_session` refuses an account with no `password_hash`, so there is no
    /// TOTP-only session for the exemption to widen. That is the whole difference from a passkey,
    /// and it is checked below rather than trusted — a kind that can start a session may not be
    /// declared `NotAProof`.
    NotAProof,
}

impl StepUpRole {
    /// Whether holding a credential in this role makes step-up **non-vacuous** — i.e. the account
    /// has something to prove beyond its session.
    #[must_use]
    const fn counts_toward_step_up(self) -> bool {
        match self {
            Self::VerifiedProof | Self::ProofPending => true,
            Self::NotAProof => false,
        }
    }
}

/// Whether a credential can begin an authenticated session on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionRole {
    /// Presenting this credential (plus any required second factor) signs the account in.
    StartsSession,
    /// It cannot: it resets, confirms or strengthens something else.
    CannotStartSession,
}

/// Whether a credential can bring an account back when every way of starting a session is gone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecoveryRole {
    /// It can re-establish access to a locked-out account.
    RecoversAccount,
    /// It cannot; losing the session credentials while holding only this strands the account.
    CannotRecover,
}

/// Whether a credential's secret **wraps the attestation scalar**, and whether that wrap can be
/// relied on to still open tomorrow.
///
/// This is a question about **key custody**, and it is deliberately *not* answerable by
/// [`RecoveryRole`]. An earlier draft of the design ruling wrote that the attestation key retains
/// "a password wrap **or** a recovery-phrase wrap"; there is no such thing. A recovery-phrase reset
/// has no old password in hand, cannot re-wrap the scalar, and therefore **retires** the key
/// (`users.rs::set_secret`). Counting the phrase here would let an account satisfy "can recover" and
/// "key stays openable" with one credential that only does the first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WrapRole {
    /// Its secret wraps the attestation scalar, and that secret is one the user supplies and the
    /// platform cannot change out from under them. **This is what satisfies key custody.**
    NonPrf,
    /// Its secret wraps the scalar, but it is a WebAuthn PRF output — which an OS update can and
    /// did change on shipping devices (iOS 18.0–18.3 → 18.4 returned different values and orphaned
    /// PRF-wrapped data, with no vendor migration path). A PRF wrap is only ever an *additional*
    /// wrap and **never satisfies key custody on its own**.
    Prf,
    /// It does not wrap the attestation scalar at all.
    None,
}

impl WrapRole {
    /// Whether holding this credential keeps the attestation key openable for the long run.
    #[must_use]
    const fn satisfies_key_custody(self) -> bool {
        match self {
            Self::NonPrf => true,
            // Deliberate and load-bearing: see the variant docs. A PRF wrap is additional, never
            // sufficient, and a credential that wraps nothing obviously keeps nothing open.
            Self::Prf | Self::None => false,
        }
    }
}

impl CredentialKind {
    /// **The step-up declaration.** Exhaustive on purpose: a new kind does not compile until its
    /// author has decided this, because the answer that would be defaulted in is the widening.
    #[must_use]
    pub(crate) const fn step_up_role(self) -> StepUpRole {
        match self {
            // Verified with argon2id in `require_step_up`.
            Self::Password => StepUpRole::VerifiedProof,
            // Likewise — possession of the phrase is its own proof.
            Self::RecoveryPhrase => StepUpRole::VerifiedProof,
            // See `StepUpRole::NotAProof`: no arm exists, and none is needed, because TOTP cannot
            // start a session.
            Self::TwoFactorTotp => StepUpRole::NotAProof,
            // t10 landed the arm `StepUpRole::ProofPending` described: `require_step_up` now
            // verifies a passkey assertion bound to a server-issued, single-use, step-up-scoped
            // challenge (`crate::passkeys::verify_step_up_assertion`), and `is_held_by` below
            // reads the real credential list. Those two had to move in the same change as the
            // enrolment endpoint — the first alone locks passkey-only users out of every
            // destructive operation, the second alone is the widening this module exists to
            // prevent.
            Self::Passkey => StepUpRole::VerifiedProof,
        }
    }

    /// **The sign-in declaration.**
    #[must_use]
    pub(crate) const fn session_role(self) -> SessionRole {
        match self {
            Self::Password => SessionRole::StartsSession,
            // A phrase resets a password; the reset password is what signs in.
            Self::RecoveryPhrase => SessionRole::CannotStartSession,
            // A second factor is only ever presented *after* a first one.
            Self::TwoFactorTotp => SessionRole::CannotStartSession,
            Self::Passkey => SessionRole::StartsSession,
        }
    }

    /// **The recovery declaration.**
    #[must_use]
    pub(crate) const fn recovery_role(self) -> RecoveryRole {
        match self {
            // A password one cannot present is not a way back in.
            Self::Password => RecoveryRole::CannotRecover,
            Self::RecoveryPhrase => RecoveryRole::RecoversAccount,
            // Backup codes recover a *factor*, not an account: they still need the first factor.
            Self::TwoFactorTotp => RecoveryRole::CannotRecover,
            // A lost passkey is exactly the case the recovery phrase exists for; another passkey is
            // a second way in, not a way back from having none.
            Self::Passkey => RecoveryRole::CannotRecover,
        }
    }

    /// **The key-custody declaration.** What this credential does for the attestation key's wrap.
    ///
    /// Exhaustive like the rest, and for the sharpest reason of the four: the answer a forgotten
    /// kind would default into is "wraps nothing", which is *safe*, while the answer an author is
    /// tempted to give is "the recovery phrase counts", which is *wrong*. Both are decided here,
    /// explicitly, per kind.
    #[must_use]
    pub(crate) const fn wrap_role(self) -> WrapRole {
        match self {
            // `AttestationKeyBlob` seals the scalar under a KEK = argon2id(password, kdf_salt).
            // This is the only wrap the product has today, and the only one that satisfies custody.
            Self::Password => WrapRole::NonPrf,
            // **Does not count, and this is the trap the ruling names.** A recovery-authorized reset
            // holds no old password, so it cannot re-wrap the scalar — it retires the key
            // (`User::retire_attestation_key`) and the user gets a new key only by generating one
            // with their new password. The phrase recovers the *account*, never the *key*.
            Self::RecoveryPhrase => WrapRole::None,
            Self::TwoFactorTotp => WrapRole::None,
            // At best a passkey carries a PRF wrap, which never satisfies custody; a passkey the
            // authenticator could not derive PRF for (shape C's degraded arm) wraps nothing at all.
            // Either way the answer is the same, which is why kind granularity is safe here: no
            // passkey, of either sort, can be the reason an attestation key stays openable.
            Self::Passkey => WrapRole::Prf,
        }
    }

    /// Whether `user` currently holds a credential of this kind.
    ///
    /// Exhaustive for the same reason as the declarations above: a kind whose detection was
    /// forgotten would be held by nobody, and every rule in this module would silently agree.
    #[must_use]
    pub(crate) fn is_held_by(self, user: &User) -> bool {
        match self {
            Self::Password => user.password_hash.is_some(),
            Self::RecoveryPhrase => user.recovery_hash.is_some(),
            // Only a *confirmed* enrolment is a factor; a pending one grants nothing.
            Self::TwoFactorTotp => user
                .totp
                .as_ref()
                .is_some_and(crate::users::TotpEnrolment::is_active),
            // Kind granularity, deliberately: an account holds *the kind* while it holds at least
            // one credential of it. The revocation handler is what reasons about "the last one"
            // (`crate::passkeys::revoke_passkey` builds the post-state set), because that is the
            // only place the difference between revoking one of three and revoking the last one
            // exists.
            Self::Passkey => !user.passkeys.is_empty(),
        }
    }

    /// The pt-PT name of this credential, for a refusal that has to say what would be left.
    ///
    /// Used **only** inside a colon-introduced list («… que restariam: palavra-passe, frase de
    /// recuperação»), never dropped into a sentence: a noun that arrives at runtime cannot agree
    /// with the article, adjective or participle around it, and a cited list after a colon is not
    /// grammatically incorporated (memory: `i18n-interpolated-nouns-break-agreement`).
    #[must_use]
    const fn name_pt(self) -> &'static str {
        match self {
            Self::Password => "palavra-passe",
            Self::RecoveryPhrase => "frase de recuperação",
            Self::TwoFactorTotp => "código do autenticador",
            Self::Passkey => "chave de acesso",
        }
    }
}

/// **The consistency invariant, enforced by the compiler.**
///
/// A credential that can start a session but does not count toward step-up *is* the widening this
/// module exists to prevent: its holder signs in, and then passes every `ConfirmWithReauth` gate on
/// the session that credential just minted. Declaring the pair is therefore not enough — the pair
/// has to be coherent, and a build that declares an incoherent one does not compile.
const _: () = {
    let mut i = 0;
    let mut any_non_prf_wrap = false;
    while i < CredentialKind::ALL.len() {
        let kind = CredentialKind::ALL[i];
        assert!(
            !matches!(kind.session_role(), SessionRole::StartsSession)
                || kind.step_up_role().counts_toward_step_up(),
            "a credential kind that can start a session must count toward step-up: declaring it \
             `NotAProof` lets its holder pass every ConfirmWithReauth gate on the session alone"
        );
        if kind.wrap_role().satisfies_key_custody() {
            any_non_prf_wrap = true;
        }
        i += 1;
    }
    // **The key-custody clause must be satisfiable.** If no kind wraps the attestation key durably,
    // every account holding one is frozen: no credential removal could ever leave a wrap behind, so
    // the guard would refuse operations no user could make legal. That is the unsatisfiable-policy
    // shape `AuthSettings::validate` already refuses for an empty pairing `accepted` set, closed
    // here at compile time instead.
    assert!(
        any_non_prf_wrap,
        "no credential kind satisfies key custody, so the attestation-key clause of the \
         account-lifecycle invariant can never be satisfied by any account"
    );
};

/// The credential kinds an account holds — the *membership* the two rules in this module are
/// written against, in place of the two named fields they used to name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct HeldCredentials {
    kinds: BTreeSet<CredentialKind>,
}

impl HeldCredentials {
    /// What `user` holds right now.
    #[must_use]
    pub(crate) fn held_by(user: &User) -> Self {
        HeldCredentials {
            kinds: CredentialKind::ALL
                .iter()
                .copied()
                .filter(|kind| kind.is_held_by(user))
                .collect(),
        }
    }

    /// An explicit set — for describing the state an operation *would* leave behind, and for tests
    /// that need an account shape the current record cannot yet express.
    ///
    /// Only tests build one today (the two live call sites derive the post-state from the record
    /// with [`with`](Self::with)/[`without`](Self::without)); the passkey revocation handler will
    /// build one from the surviving credential list.
    #[must_use]
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn of(kinds: impl IntoIterator<Item = CredentialKind>) -> Self {
        HeldCredentials {
            kinds: kinds.into_iter().collect(),
        }
    }

    /// This set plus `kind` (the post-state of an operation that establishes one).
    #[must_use]
    pub(crate) fn with(mut self, kind: CredentialKind) -> Self {
        self.kinds.insert(kind);
        self
    }

    /// This set minus `kind` (the post-state of an operation that removes one).
    #[must_use]
    pub(crate) fn without(mut self, kind: CredentialKind) -> Self {
        self.kinds.remove(&kind);
        self
    }

    /// The held kinds, in declaration order.
    pub(crate) fn iter(&self) -> impl Iterator<Item = CredentialKind> + '_ {
        self.kinds.iter().copied()
    }

    fn any(&self, predicate: impl Fn(CredentialKind) -> bool) -> bool {
        self.iter().any(predicate)
    }

    /// The pt-PT list of what is held, or «nenhuma» when nothing is. Only ever emitted after a
    /// colon — see [`CredentialKind::name_pt`].
    #[must_use]
    fn describe_pt(&self) -> String {
        if self.kinds.is_empty() {
            return "nenhuma".to_owned();
        }
        self.iter()
            .map(CredentialKind::name_pt)
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// **The t69 step-up exemption, as a membership test over every credential kind.**
///
/// True when the account holds nothing that [`crate::data::require_step_up`] could demand — in
/// which case a valid authenticated self session already *is* the strongest proof available, and
/// demanding more would lock out an operator for lacking a credential they never set. False the
/// moment the account holds one, including a kind whose proof arm is still
/// [`StepUpRole::ProofPending`]: an account that has something to prove must prove it, and being
/// unable to is a refusal, not an exemption.
///
/// This is the **single definition** of the exemption. Its readers are `require_step_up` and the
/// device-pairing mail path in [`crate::pairing`], which needs to reason about the exemption
/// because for that one feature a vacuous step-up is not a neutral outcome.
#[must_use]
pub(crate) fn step_up_is_vacuous(held: &HeldCredentials) -> bool {
    !held.any(|kind| kind.step_up_role().counts_toward_step_up())
}

/// Refusal code: the operation would leave the account with no way to sign in.
pub(crate) const NO_SIGN_IN_CREDENTIAL_CODE: &str = "account_would_have_no_sign_in_credential";
/// Refusal code: the operation would remove a way to sign in with no way to recover the account.
pub(crate) const NO_RECOVERY_CREDENTIAL_CODE: &str = "account_would_have_no_recovery_credential";
/// Refusal code: the operation would leave the account's attestation key with no wrap that can be
/// relied on to open.
pub(crate) const NO_KEY_WRAP_CODE: &str = "account_attestation_key_would_have_no_wrap";

/// Whether an account holds an attestation key **after** the operation being guarded.
///
/// Always the *post*-state: an operation that retires the key (a recovery-authorized reset, an
/// explicit key removal) leaves nothing that needs a wrap, so the key-custody clause correctly does
/// not apply to it. Retired keys are irrelevant — `retired_attestation_keys` holds public halves
/// only, with no ciphertext left to open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AttestationKeyState {
    /// The account still has an attestation key, so its wraps are load-bearing.
    Held,
    /// It has none, so there is nothing to keep a wrap for.
    Absent,
}

impl AttestationKeyState {
    /// The state as `user`'s record stands right now.
    #[must_use]
    pub(crate) fn held_by(user: &User) -> Self {
        if user.attestation_key.is_some() {
            AttestationKeyState::Held
        } else {
            AttestationKeyState::Absent
        }
    }
}

/// **The account-lifecycle invariant.** Refuse a credential removal that would strand the account.
///
/// *After this operation the account retains at least one credential that can start a session; if
/// the operation removed a credential that could start one, at least one credential that can recover
/// it; and — where an attestation key still exists — at least one non-PRF wrap of that key.*
///
/// The third clause is what makes the first two safe rather than merely tidy. Without it an account
/// can satisfy "can sign in" and "can recover" while its signing identity hangs on a PRF output a
/// vendor can move out from under it — which already happened (iOS 18.4). Its practical consequence:
/// **the password may not be removed while an attestation key exists**, whatever else the account
/// holds. "Passwordless" means no password *at sign-in*; it never means no password *wrap*.
///
/// A **wall, not a lockout** — the same posture as `RequiredAction::EnrolTwoFactor`, whose comment
/// is exactly right: enrol-on-next-sign-in, never a lockout, so even the last Owner can always get
/// far enough. So this refuses the *operation*, names what the account would be left holding, and
/// leaves the account exactly as it was.
///
/// **Monotone by construction:** every clause only refuses an operation that makes the account
/// strictly worse. An account that already holds no way to sign in is not made whole by refusing to
/// touch it, so an operation that removes nothing session-capable from such an account still passes
/// — otherwise a legacy no-hash account could never have its recovery phrase consumed, which is an
/// existing and correct flow. The same shape applies to the key-custody clause.
///
/// **Not covered by `last_owner_guard`.** That guard counts *role holders*; this one counts *ways
/// in*. The last Owner revoking their own last credential passes the former and must be caught by
/// this.
pub(crate) fn ensure_removal_leaves_account_usable(
    before: &HeldCredentials,
    after: &HeldCredentials,
    attestation_key_after: AttestationKeyState,
) -> Result<(), ApiError> {
    let removed: Vec<CredentialKind> = before
        .iter()
        .filter(|kind| !after.any(|held| held == *kind))
        .collect();
    if removed.is_empty() {
        return Ok(()); // Not a removal: nothing to guard.
    }

    let starts_session =
        |kind: CredentialKind| matches!(kind.session_role(), SessionRole::StartsSession);
    let recovers =
        |kind: CredentialKind| matches!(kind.recovery_role(), RecoveryRole::RecoversAccount);

    if before.any(starts_session) && !after.any(starts_session) {
        return Err(ApiError::Conflict(format!(
            "operação recusada: removeria a última credencial com que esta conta pode iniciar \
             sessão. Credenciais que restariam: {}. Estabeleça outra forma de iniciar sessão antes \
             de remover esta.",
            after.describe_pt()
        ))
        .with_code(NO_SIGN_IN_CREDENTIAL_CODE));
    }

    if removed.iter().copied().any(starts_session) && !after.any(recovers) {
        return Err(ApiError::Conflict(format!(
            "operação recusada: removeria uma credencial de início de sessão sem que a conta \
             ficasse com forma de ser recuperada. Credenciais que restariam: {}. Emita uma frase \
             de recuperação antes de remover esta credencial.",
            after.describe_pt()
        ))
        .with_code(NO_RECOVERY_CREDENTIAL_CODE));
    }

    // Key custody. Only reachable when the account still holds an attestation key after the
    // operation, and only refuses when this operation is what takes the last durable wrap away —
    // an account whose key is already unopenable is not helped by refusing to touch it.
    let wraps_durably = |kind: CredentialKind| kind.wrap_role().satisfies_key_custody();
    if matches!(attestation_key_after, AttestationKeyState::Held)
        && before.any(wraps_durably)
        && !after.any(wraps_durably)
    {
        return Err(ApiError::Conflict(format!(
            "operação recusada: a chave de atestação desta conta deixaria de ter qualquer proteção \
             que se possa abrir, e as assinaturas futuras seriam impossíveis. Credenciais que \
             restariam: {}. A palavra-passe protege a chave mesmo quando não é usada para iniciar \
             sessão, por isso não pode ser removida enquanto a chave existir.",
            after.describe_pt()
        ))
        .with_code(NO_KEY_WRAP_CODE));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::UserId;
    use crate::users::TotpEnrolment;

    fn user() -> User {
        User {
            passkeys: Vec::new(),
            id: UserId(uuid::Uuid::new_v4()),
            username: "amelia.marques".to_owned(),
            display_name: "Amélia Marques".to_owned(),
            email: None,
            created_at: "2026-07-30T09:00:00Z".to_owned(),
            active: true,
            password_hash: None,
            attestation_key: None,
            retired_attestation_keys: Vec::new(),
            secret_source: Default::default(),
            recovery_hash: None,
            role_assignments: Vec::new(),
            language: Default::default(),
            totp: None,
            two_factor_required: false,
            force_password_change: false,
        }
    }

    fn confirmed_totp() -> TotpEnrolment {
        TotpEnrolment {
            confirmed: true,
            confirmed_at: Some("2026-07-30T09:00:00Z".to_owned()),
            last_accepted_step: None,
            backup_code_hashes: Vec::new(),
        }
    }

    /// The predicate exactly as it stood before this lane (`9045d118`), kept verbatim so the tests
    /// below can state what changed rather than assert it from memory. It is the thing being
    /// replaced; nothing in `src/` may call it.
    fn legacy_step_up_is_vacuous(password_hash: Option<&str>, recovery_hash: Option<&str>) -> bool {
        password_hash.is_none() && recovery_hash.is_none()
    }

    // ── The four account shapes expressible today ────────────────────────────────────────────

    #[test]
    fn password_only_is_not_vacuous() {
        let mut u = user();
        u.password_hash = Some("phc".to_owned());
        assert!(!step_up_is_vacuous(&HeldCredentials::held_by(&u)));
    }

    #[test]
    fn recovery_only_is_not_vacuous() {
        let mut u = user();
        u.recovery_hash = Some("phc".to_owned());
        assert!(!step_up_is_vacuous(&HeldCredentials::held_by(&u)));
    }

    #[test]
    fn both_is_not_vacuous() {
        let mut u = user();
        u.password_hash = Some("phc".to_owned());
        u.recovery_hash = Some("phc".to_owned());
        assert!(!step_up_is_vacuous(&HeldCredentials::held_by(&u)));
    }

    #[test]
    fn neither_is_vacuous_so_the_t69_exemption_survives() {
        // The legacy no-hash operator. A valid self session is the strongest proof they can give,
        // and demanding more would lock them out of their own instance.
        assert!(step_up_is_vacuous(&HeldCredentials::held_by(&user())));
    }

    #[test]
    fn a_confirmed_totp_factor_alone_stays_vacuous() {
        // Deliberate and unchanged: `require_step_up` has no TOTP arm, so counting it would make
        // every gate unsatisfiable for its holder. Safe because TOTP cannot start a session.
        let mut u = user();
        u.totp = Some(confirmed_totp());
        assert!(step_up_is_vacuous(&HeldCredentials::held_by(&u)));
        assert!(HeldCredentials::held_by(&u).any(|k| k == CredentialKind::TwoFactorTotp));
    }

    #[test]
    fn a_pending_totp_enrolment_is_not_a_held_credential() {
        let mut u = user();
        u.totp = Some(TotpEnrolment::pending());
        assert!(!HeldCredentials::held_by(&u).any(|k| k == CredentialKind::TwoFactorTotp));
    }

    /// **No caller's behaviour changes.** For every account shape the record can express today, the
    /// new membership predicate answers exactly what the two-field predicate answered — so
    /// `bundles.rs`, `data.rs` (×2), `data_status.rs`, `privacy.rs`, `recovery.rs` (×2),
    /// `zk_repository.rs` and `confirmation.rs::require_confirmation` all still enforce what they
    /// enforced.
    #[test]
    fn agrees_with_the_legacy_predicate_on_every_shape_expressible_today() {
        for password in [None, Some("phc")] {
            for recovery in [None, Some("phc")] {
                for totp in [None, Some(confirmed_totp()), Some(TotpEnrolment::pending())] {
                    let mut u = user();
                    u.password_hash = password.map(str::to_owned);
                    u.recovery_hash = recovery.map(str::to_owned);
                    u.totp = totp;
                    assert_eq!(
                        step_up_is_vacuous(&HeldCredentials::held_by(&u)),
                        legacy_step_up_is_vacuous(password, recovery),
                        "membership predicate diverged from the legacy one on an account shape \
                         that exists today (password: {password:?}, recovery: {recovery:?})"
                    );
                }
            }
        }
    }

    // ── The red-proof: the widening a passkey-only account would have created ─────────────────

    /// **The whole point of this lane.** An account with neither a password nor a recovery phrase,
    /// holding a credential that can start a session, is exempted by the old predicate and gated by
    /// the new one.
    ///
    /// The first assertion is the red-proof: it states, in the test, what the predicate being
    /// replaced answered for this account. If anyone restores that predicate, the second assertion
    /// fails — this test cannot pass against the old rule.
    #[test]
    fn a_session_capable_credential_alone_is_no_longer_vacuous() {
        // No password, no recovery phrase — the two fields the old predicate named.
        assert!(
            legacy_step_up_is_vacuous(None, None),
            "the predicate being replaced exempted this account, which is the widening"
        );
        let held = HeldCredentials::of([CredentialKind::Passkey]);
        assert!(
            !step_up_is_vacuous(&held),
            "an account holding a session-capable credential must not pass a ConfirmWithReauth \
             gate on its session token alone"
        );
    }

    #[test]
    fn the_gate_itself_refuses_a_passkey_only_account_that_offers_nothing() {
        // Runs the real decision `require_step_up` runs, on the account shape enrolment makes
        // possible: session-capable, no argon2id verifier of either named kind, and no assertion
        // offered. The session token alone must not be enough.
        let held = HeldCredentials::of([CredentialKind::Passkey]);
        let outcome = crate::data::decide_step_up(
            &held,
            None,
            None,
            &crate::data::ReAuth::default(),
            crate::passkeys::PasskeyStepUp::NotSupplied,
        );
        assert!(
            outcome.is_err(),
            "a passkey-only account passed a step-up gate on its session alone"
        );
    }

    #[test]
    fn a_refused_assertion_does_not_satisfy_the_gate() {
        // The fail-closed direction, and the one an "if a passkey was supplied, trust it" shortcut
        // would break: offering an assertion that did not verify must land in the same uniform
        // refusal as offering nothing at all.
        let held = HeldCredentials::of([CredentialKind::Passkey]);
        assert!(
            crate::data::decide_step_up(
                &held,
                None,
                None,
                &crate::data::ReAuth::default(),
                crate::passkeys::PasskeyStepUp::Refused,
            )
            .is_err()
        );
    }

    #[test]
    fn a_verified_assertion_satisfies_the_gate_for_a_passkey_only_account() {
        // The other half of the pair, and the reason both had to land together: making a
        // passkey-only account non-vacuous without giving it a way to prove itself would have
        // locked its holder out of every destructive operation in the product.
        let held = HeldCredentials::of([CredentialKind::Passkey]);
        assert!(
            crate::data::decide_step_up(
                &held,
                None,
                None,
                &crate::data::ReAuth::default(),
                crate::passkeys::PasskeyStepUp::Verified,
            )
            .is_ok()
        );
    }

    #[test]
    fn holding_a_passkey_is_read_from_the_credential_list() {
        // `is_held_by` answered `false` for every account until t10 gave it storage to read. That
        // it now reads the real list is what makes every rule in this module true of a real
        // account rather than true in principle.
        let mut u = user();
        assert!(!CredentialKind::Passkey.is_held_by(&u));
        u.passkeys.push(crate::passkeys::PasskeyCredential {
            credential_id: "Y3JlZC1pZA".to_owned(),
            user_handle: "aGFuZGxl".to_owned(),
            static_state: "c3RhdGlj".to_owned(),
            sign_count: 0,
            user_verified: true,
            backup: crate::passkeys::PasskeyBackup::Exists,
            attachment: crate::passkeys::PasskeyAttachment::Platform,
            rp_id: "example.pt".to_owned(),
            transports: 0,
            name: "Telemóvel".to_owned(),
            created_at: "2026-07-31T09:00:00Z".to_owned(),
            last_used_at: None,
            prf_capable: true,
            prf_wrap: None,
        });
        assert!(CredentialKind::Passkey.is_held_by(&u));
        assert!(HeldCredentials::held_by(&u).any(|k| k == CredentialKind::Passkey));
        // And the account is no longer exempt on its session alone — the widening this module
        // exists to prevent, closed against a record that can now actually express it.
        assert!(!step_up_is_vacuous(&HeldCredentials::held_by(&u)));
    }

    // ── Membership, not the current pair ──────────────────────────────────────────────────────

    /// A hypothetical future credential kind, declared the way a real one is. The predicate is a
    /// fold over per-kind declarations, so it accounts for this kind rather than ignoring it — the
    /// property that the two-field predicate did not have.
    #[test]
    fn the_predicate_accounts_for_a_hypothetical_new_kind() {
        #[derive(Clone, Copy)]
        enum Hypothetical {
            /// e.g. a smart-card credential: starts a session, so it must count.
            SmartCard,
            /// e.g. a printed audit token: not a proof of anything.
            Decorative,
        }
        impl Hypothetical {
            const fn step_up_role(self) -> StepUpRole {
                match self {
                    Self::SmartCard => StepUpRole::ProofPending,
                    Self::Decorative => StepUpRole::NotAProof,
                }
            }
        }

        // The rule, applied to declarations that are not `CredentialKind`'s: a kind that counts
        // makes step-up non-vacuous, and one that does not, does not.
        let vacuous = |kinds: &[Hypothetical]| {
            !kinds
                .iter()
                .any(|k| k.step_up_role().counts_toward_step_up())
        };
        assert!(!vacuous(&[Hypothetical::SmartCard]));
        assert!(vacuous(&[Hypothetical::Decorative]));
        assert!(vacuous(&[]));
    }

    #[test]
    fn every_kind_declares_all_four_roles_and_appears_in_all() {
        // `ALL` is generated from the same list as the enum, so this cannot fail by omission —
        // it fails if someone replaces the macro with a hand-written pair that drifts.
        assert_eq!(CredentialKind::ALL.len(), 4);
        for kind in CredentialKind::ALL {
            // Every declaration is total: reaching here at all means each match had an arm.
            let _ = kind.step_up_role();
            let _ = kind.session_role();
            let _ = kind.recovery_role();
            let _ = kind.wrap_role();
            assert!(!kind.name_pt().is_empty());
        }
    }

    /// **The error the design ruling caught in its own draft, pinned.** "Retains a password wrap
    /// *or* a recovery-phrase wrap" describes something that does not exist: a recovery-authorized
    /// reset holds no old password, cannot re-wrap the scalar, and retires the key instead. So the
    /// phrase recovers the account and wraps nothing, and those are two declarations rather than
    /// one.
    #[test]
    fn the_recovery_phrase_recovers_the_account_and_wraps_nothing() {
        assert_eq!(
            CredentialKind::RecoveryPhrase.recovery_role(),
            RecoveryRole::RecoversAccount
        );
        assert_eq!(
            CredentialKind::RecoveryPhrase.wrap_role(),
            WrapRole::None,
            "a recovery-phrase reset retires the attestation key; counting it for key custody \
             would let one credential answer two different questions"
        );
        assert!(
            !CredentialKind::RecoveryPhrase
                .wrap_role()
                .satisfies_key_custody()
        );
    }

    #[test]
    fn a_passkey_never_satisfies_key_custody_and_the_password_always_does() {
        // A PRF wrap is additional, never sufficient: an OS update changed PRF output on shipping
        // devices. A passkey with no PRF wrap at all lands in the same place, which is why the
        // kind-level answer is safe.
        assert_eq!(CredentialKind::Passkey.wrap_role(), WrapRole::Prf);
        assert!(!CredentialKind::Passkey.wrap_role().satisfies_key_custody());
        assert_eq!(CredentialKind::Password.wrap_role(), WrapRole::NonPrf);
        assert!(CredentialKind::Password.wrap_role().satisfies_key_custody());
    }

    #[test]
    fn at_least_one_kind_can_satisfy_key_custody() {
        // The same satisfiability check the `const _` block makes at compile time: if no kind could
        // ever keep the key openable, the third clause would freeze every account holding one.
        assert!(
            CredentialKind::ALL
                .iter()
                .any(|kind| kind.wrap_role().satisfies_key_custody()),
            "the key-custody clause would be unsatisfiable by any account"
        );
    }

    #[test]
    fn a_session_capable_kind_may_never_be_declared_not_a_proof() {
        // The same invariant the `const _` block enforces at compile time, restated as a test so a
        // reader sees it and a `cargo test` failure names it.
        for kind in CredentialKind::ALL {
            if matches!(kind.session_role(), SessionRole::StartsSession) {
                assert!(
                    kind.step_up_role().counts_toward_step_up(),
                    "{kind:?} can start a session but does not count toward step-up"
                );
            }
        }
    }

    #[test]
    fn no_declaration_in_this_module_has_a_wildcard_arm() {
        // A catch-all arm would restore exactly the default this module exists to remove: a new
        // kind would compile, silently answering "cannot satisfy step-up". The needle is assembled
        // from two pieces so this test's own source does not contain it.
        const WILDCARD: &str = concat!("_ ", "=>");
        // Comment lines are stripped first — the module *discusses* the arm it forbids in three
        // places, and a check that cannot tell prose from code fires on its own documentation
        // (memory: `cfg-test-split-truncates-source`). The length floor is the guard on the filter:
        // if it ever eats the module, this fails loudly instead of passing on an empty string.
        let code_only = include_str!("credentials.rs")
            .lines()
            .map(str::trim_start)
            .filter(|line| !line.starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            code_only.len() > 2_000,
            "the comment filter swallowed the module, so this check is proving nothing"
        );
        assert!(
            !code_only.contains(WILDCARD),
            "a wildcard match arm in credentials.rs lets a new credential kind default into \
             'cannot satisfy step-up', which is the bug this module exists to prevent"
        );
        // The needle is real: prove the check can fire.
        assert!(format!("match x {{ {WILDCARD} () }}").contains(WILDCARD));
    }

    // ── The account-lifecycle invariant ───────────────────────────────────────────────────────

    /// The guard, for an account with no attestation key — so clauses 1 and 2 can be exercised
    /// without clause 3 answering first.
    fn guard_keyless(before: &HeldCredentials, after: &HeldCredentials) -> Result<(), ApiError> {
        ensure_removal_leaves_account_usable(before, after, AttestationKeyState::Absent)
    }

    /// The guard, for an account that still holds an attestation key afterwards.
    fn guard_keyed(before: &HeldCredentials, after: &HeldCredentials) -> Result<(), ApiError> {
        ensure_removal_leaves_account_usable(before, after, AttestationKeyState::Held)
    }

    #[test]
    fn removing_the_last_way_to_sign_in_is_refused_and_names_what_remains() {
        let before = HeldCredentials::of([CredentialKind::Password, CredentialKind::TwoFactorTotp]);
        let after = before.clone().without(CredentialKind::Password);
        let error = guard_keyless(&before, &after)
            .expect_err("removing the only sign-in credential must be refused");
        assert_eq!(error.code(), NO_SIGN_IN_CREDENTIAL_CODE);
        let message = format!("{error:?}");
        assert!(
            message.contains("código do autenticador"),
            "the refusal must name what the account would be left holding: {message}"
        );
    }

    #[test]
    fn removing_the_last_way_to_sign_in_names_nenhuma_when_nothing_would_remain() {
        let before = HeldCredentials::of([CredentialKind::Password]);
        let after = HeldCredentials::default();
        let error = guard_keyless(&before, &after).expect_err("refused");
        assert!(format!("{error:?}").contains("nenhuma"), "{error:?}");
    }

    #[test]
    fn removing_a_sign_in_credential_without_a_recovery_credential_is_refused() {
        // The passkey-era case the design names: a password removed while a passkey remains still
        // leaves a way in — but no way back if that passkey is lost.
        let before = HeldCredentials::of([CredentialKind::Password, CredentialKind::Passkey]);
        let after = before.clone().without(CredentialKind::Password);
        let error = guard_keyless(&before, &after).expect_err(
            "removing a sign-in credential with no recovery credential must be refused",
        );
        assert_eq!(error.code(), NO_RECOVERY_CREDENTIAL_CODE);
        assert!(
            format!("{error:?}").contains("chave de acesso"),
            "{error:?}"
        );
    }

    #[test]
    fn removing_a_sign_in_credential_is_allowed_when_a_recovery_credential_remains() {
        let before = HeldCredentials::of([
            CredentialKind::Password,
            CredentialKind::Passkey,
            CredentialKind::RecoveryPhrase,
        ]);
        let after = before.clone().without(CredentialKind::Password);
        assert!(guard_keyless(&before, &after).is_ok());
    }

    #[test]
    fn revoking_one_of_several_passkeys_removes_no_kind_and_passes() {
        // Kind-granular by design: the set only loses `Passkey` when the *last* one goes.
        let before = HeldCredentials::of([CredentialKind::Passkey, CredentialKind::RecoveryPhrase]);
        assert!(guard_keyless(&before, &before.clone()).is_ok());
    }

    #[test]
    fn revoking_the_last_passkey_of_a_passkey_only_account_is_refused() {
        let before = HeldCredentials::of([CredentialKind::Passkey]);
        let after = HeldCredentials::default();
        let error = guard_keyless(&before, &after).expect_err("refused");
        assert_eq!(error.code(), NO_SIGN_IN_CREDENTIAL_CODE);
    }

    #[test]
    fn consuming_a_recovery_phrase_while_a_password_remains_passes() {
        // The existing single-use recovery reset (`users::set_secret`, recovery arm). It removes a
        // credential, but not a session-capable one, and a password remains.
        let before =
            HeldCredentials::of([CredentialKind::Password, CredentialKind::RecoveryPhrase]);
        let after = before.clone().without(CredentialKind::RecoveryPhrase);
        assert!(guard_keyless(&before, &after).is_ok());
    }

    #[test]
    fn consuming_the_recovery_phrase_of_an_account_that_could_never_sign_in_passes() {
        // Monotonicity: the account already held no way to start a session, so refusing here would
        // block an existing, correct cross-user flow without making the account any more usable.
        let before = HeldCredentials::of([CredentialKind::RecoveryPhrase]);
        let after = HeldCredentials::default();
        assert!(guard_keyless(&before, &after).is_ok());
    }

    // ── Clause 3: key custody ─────────────────────────────────────────────────────────────────

    /// **The consequence the ruling spells out.** Removing the password is refused while an
    /// attestation key exists, whatever else the account holds — here it holds *both* another way
    /// in and a way to be recovered, so clauses 1 and 2 are satisfied and only clause 3 refuses.
    #[test]
    fn removing_the_password_is_refused_while_an_attestation_key_exists() {
        let before = HeldCredentials::of([
            CredentialKind::Password,
            CredentialKind::Passkey,
            CredentialKind::RecoveryPhrase,
        ]);
        let after = before.clone().without(CredentialKind::Password);
        // Clauses 1 and 2 do not object: the same removal on a keyless account is allowed.
        assert!(guard_keyless(&before, &after).is_ok());
        let error = guard_keyed(&before, &after)
            .expect_err("the password wrap is what keeps the attestation key openable");
        assert_eq!(error.code(), NO_KEY_WRAP_CODE);
        let message = format!("{error:?}");
        assert!(
            message.contains("chave de acesso") && message.contains("frase de recuperação"),
            "the refusal must name what the account would be left holding: {message}"
        );
    }

    /// The specific error the ruling corrected: a recovery phrase left behind does **not** satisfy
    /// key custody, because a recovery reset retires the key rather than re-wrapping it.
    #[test]
    fn a_remaining_recovery_phrase_does_not_satisfy_key_custody() {
        let before =
            HeldCredentials::of([CredentialKind::Password, CredentialKind::RecoveryPhrase]);
        let after = before.clone().without(CredentialKind::Password);
        let error = guard_keyed(&before, &after).expect_err(
            "a recovery phrase recovers the account; it is not a wrap of the attestation key",
        );
        // Clause 1 answers first here — the account would have no way to sign in at all — which is
        // itself correct. The point of this test is the *wrap* question, so assert it directly too.
        assert_eq!(error.code(), NO_SIGN_IN_CREDENTIAL_CODE);
        assert!(!after.any(|kind| kind.wrap_role().satisfies_key_custody()));
    }

    /// A PRF wrap is never sufficient on its own, so a passkey left behind does not rescue the
    /// removal either.
    #[test]
    fn a_remaining_passkey_does_not_satisfy_key_custody() {
        let before = HeldCredentials::of([
            CredentialKind::Password,
            CredentialKind::Passkey,
            CredentialKind::RecoveryPhrase,
        ]);
        let after = before.clone().without(CredentialKind::Password);
        assert!(after.any(|kind| kind == CredentialKind::Passkey));
        assert!(!after.any(|kind| kind.wrap_role().satisfies_key_custody()));
        assert_eq!(
            guard_keyed(&before, &after).expect_err("refused").code(),
            NO_KEY_WRAP_CODE
        );
    }

    #[test]
    fn key_custody_does_not_object_when_the_password_stays() {
        // Revoking the last passkey from an account that still types its password: the key keeps
        // the wrap that matters, so clause 3 is silent.
        let before = HeldCredentials::of([
            CredentialKind::Password,
            CredentialKind::Passkey,
            CredentialKind::RecoveryPhrase,
        ]);
        let after = before.clone().without(CredentialKind::Passkey);
        assert!(guard_keyed(&before, &after).is_ok());
    }

    #[test]
    fn key_custody_is_monotone_when_the_key_was_already_unopenable() {
        // No durable wrap existed before either, so refusing the operation would not make the key
        // any more openable — it would only block an operation for no benefit.
        let before = HeldCredentials::of([CredentialKind::Passkey, CredentialKind::RecoveryPhrase]);
        let after = before.clone().without(CredentialKind::RecoveryPhrase);
        assert!(guard_keyed(&before, &after).is_ok());
    }

    #[test]
    fn retiring_the_key_in_the_same_operation_leaves_nothing_to_protect() {
        // The existing recovery-authorized reset: it consumes the phrase AND retires the key, so
        // the post-state holds no key and clause 3 correctly does not apply.
        let before =
            HeldCredentials::of([CredentialKind::Password, CredentialKind::RecoveryPhrase]);
        let after = before.clone().without(CredentialKind::RecoveryPhrase);
        assert!(guard_keyless(&before, &after).is_ok());
    }

    #[test]
    fn attestation_key_state_reads_the_current_key_not_the_retired_ones() {
        let mut u = user();
        assert_eq!(
            AttestationKeyState::held_by(&u),
            AttestationKeyState::Absent
        );
        u.retired_attestation_keys
            .push(crate::attestation::RetiredAttestationKey {
                public_key_sec1: "AQID".to_owned(),
                fingerprint: "ff".to_owned(),
                retired_at: "2026-07-30T09:00:00Z".to_owned(),
            });
        assert_eq!(
            AttestationKeyState::held_by(&u),
            AttestationKeyState::Absent,
            "a retired key holds only a public half; there is no ciphertext left to keep a wrap for"
        );
    }

    #[test]
    fn establishing_a_credential_is_never_refused() {
        let before = HeldCredentials::of([CredentialKind::Password]);
        let after = before.clone().with(CredentialKind::RecoveryPhrase);
        assert!(guard_keyless(&before, &after).is_ok());
    }
}
