//! The crate error type ([`SmartcardError`]).

/// How many user-PIN attempts remain before the card locks, insofar as the token
/// reveals it.
///
/// PKCS#11 exposes this only **qualitatively** through token flags
/// (`CKF_USER_PIN_COUNT_LOW` / `_FINAL_TRY` / `_LOCKED`), never an exact numeric
/// count, and a token is permitted to hide it entirely (all flags clear). So this
/// is a best-effort hint for an honest "wrong PIN — N tries left" message, never a
/// guaranteed count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinTriesLeft {
    /// The token reports the user PIN is locked (`CKF_USER_PIN_LOCKED`): no
    /// attempts remain. Usually accompanies [`SmartcardError::PinBlocked`].
    Locked,
    /// The next incorrect attempt will lock the card (`CKF_USER_PIN_FINAL_TRY`).
    FinalTry,
    /// The attempt counter is low but not final (`CKF_USER_PIN_COUNT_LOW`).
    Low,
    /// The token does not reveal the remaining-attempt state.
    Unknown,
}

impl std::fmt::Display for PinTriesLeft {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            PinTriesLeft::Locked => "the card is now locked",
            PinTriesLeft::FinalTry => "one attempt remains before the card locks",
            PinTriesLeft::Low => "few attempts remain",
            PinTriesLeft::Unknown => "remaining attempts unknown",
        };
        f.write_str(msg)
    }
}

/// Errors surfaced by the Cartão de Cidadão signing layer.
///
/// Every variant is non-panicking; reader/middleware absence and card-state
/// problems are reported here rather than aborting (spec 04, SIG-01/SIG-03).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SmartcardError {
    /// The PC/SC resource manager is unavailable (service stopped / not
    /// installed). Distinct from "zero readers", which is a clean empty result.
    #[error("PC/SC resource manager unavailable: {0}")]
    PcscUnavailable(String),

    /// A PC/SC operation failed for a reason other than service availability.
    #[error("PC/SC error: {0}")]
    Pcsc(String),

    /// The PKCS#11 module could not be loaded from the resolved path. The
    /// Autenticação.gov middleware is likely not installed (see `TESTING.md`).
    #[error("failed to load PKCS#11 module at {path}: {reason}")]
    ModuleLoad {
        /// The resolved module path that failed to load.
        path: String,
        /// The underlying loader error, stringified.
        reason: String,
    },

    /// A PKCS#11 (`cryptoki`) operation failed.
    #[error("PKCS#11 error: {0}")]
    Pkcs11(String),

    /// The in-app PIN presented to `C_Login` was incorrect (`CKR_PIN_INCORRECT`).
    ///
    /// Carries the token's best-effort remaining-attempt hint ([`PinTriesLeft`]).
    /// **The PIN value is never included** — neither this variant nor its
    /// `Display` ever echoes the entered PIN (plan §6).
    #[error("incorrect PIN: {tries_left}")]
    WrongPin {
        /// The token's best-effort remaining-attempt state.
        tries_left: PinTriesLeft,
    },

    /// The card's user PIN is blocked (`CKR_PIN_LOCKED`, or the token reports
    /// `CKF_USER_PIN_LOCKED`): no further attempts are possible until the PIN is
    /// unblocked with the PUK. Carries no PIN value.
    #[error("PIN blocked: the card is locked after too many incorrect attempts")]
    PinBlocked,

    /// No token (card) is present in any slot.
    #[error("no smart card present in any reader")]
    NoCardPresent,

    /// The requested certificate (by usage/label) was not found on the card.
    #[error("certificate not found on card: {0}")]
    CertificateNotFound(String),

    /// No private key on the card matched the selected certificate.
    #[error("no private key matched certificate {0:?}")]
    KeyNotFound(String),

    /// The certificate's public-key algorithm is not one we can sign with
    /// (only RSA and P-256 ECDSA are supported: CC v1 and CC v2).
    #[error("unsupported key algorithm (OID {0}); expected RSA or EC P-256")]
    UnsupportedKeyAlgorithm(String),

    /// An X.509 certificate could not be parsed.
    #[error("failed to parse X.509 certificate: {0}")]
    CertificateParse(String),

    /// A raw signature value returned by the card was malformed (e.g. an
    /// ECDSA `r‖s` block of the wrong length).
    #[error("malformed signature value from card: {0}")]
    MalformedSignature(String),

    /// DER encoding of a value (e.g. the ECDSA `Ecdsa-Sig-Value`) failed.
    #[error("DER encoding failed: {0}")]
    DerEncoding(String),
}
