//! The crate error type ([`SmartcardError`]).

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
