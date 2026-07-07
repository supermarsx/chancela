//! The crate error type ([`CadesError`]).

/// Errors raised while building or validating a CAdES-B `SignedData`.
///
/// Covers spec/04 SIG-01 (advanced signature construction) and SIG-24 (signature validation);
/// this crate does **crypto**, not trust decisions — qualified-status and chain trust belong to
/// the caller (see `chancela-tsl`).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CadesError {
    /// ASN.1/DER encoding or decoding failed.
    #[error("ASN.1 DER error: {0}")]
    Der(#[from] der::Error),

    /// The outer `ContentInfo` was not an RFC 5652 `id-signedData`.
    #[error("unexpected CMS content type (expected id-signedData)")]
    UnexpectedContentType,

    /// A CAdES-B signature must carry signed attributes; none were present.
    #[error("SignerInfo is missing the required signed attributes")]
    MissingSignedAttributes,

    /// The `SignedData` did not contain exactly one `SignerInfo`.
    #[error("expected exactly one SignerInfo, found {0}")]
    SignerInfoCount(usize),

    /// The mandatory `content-type` signed attribute was absent.
    #[error("missing content-type signed attribute")]
    MissingContentType,

    /// The `content-type` signed attribute did not equal `id-data`.
    #[error("content-type signed attribute is not id-data")]
    UnexpectedContentTypeAttr,

    /// The mandatory `message-digest` signed attribute was absent.
    #[error("missing message-digest signed attribute")]
    MissingMessageDigest,

    /// The `message-digest` signed attribute did not match the supplied content digest.
    #[error("message-digest signed attribute does not match the content digest")]
    MessageDigestMismatch,

    /// The signing certificate referenced by the `SignerInfo` was not embedded in the message.
    #[error("signing certificate not found in the SignedData certificate set")]
    SignerCertNotFound,

    /// The signing certificate could not be parsed as X.509.
    #[error("invalid signing certificate")]
    InvalidCertificate,

    /// The signing certificate's public key could not be decoded for the chosen algorithm.
    #[error("invalid or unsupported signer public key")]
    InvalidPublicKey,

    /// The raw signature bytes were not valid for the declared algorithm.
    #[error("invalid signature encoding")]
    InvalidSignatureEncoding,

    /// The signature did not verify against the signing certificate's public key.
    #[error("signature verification failed")]
    SignatureVerification,

    /// The `SignerInfo` signature algorithm is not one of the supported profiles
    /// (RSA-PKCS1-SHA256 or ECDSA-P256-SHA256).
    #[error("unsupported signature algorithm: {oid}")]
    UnsupportedAlgorithm {
        /// The offending algorithm OID.
        oid: der::asn1::ObjectIdentifier,
    },

    /// A signing-time value was present but could not be interpreted.
    #[error("invalid signing-time attribute")]
    InvalidSigningTime,
}
