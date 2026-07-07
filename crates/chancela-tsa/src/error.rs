//! The crate error type.

/// Errors raised while building, sending, or verifying an RFC 3161 timestamp (spec 04, SIG-22).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TsaError {
    /// The `TimeStampReq` could not be DER-encoded.
    #[error("failed to encode RFC 3161 TimeStampReq: {0}")]
    EncodeRequest(#[source] der::Error),

    /// The `TimeStampResp` could not be DER-decoded.
    #[error("failed to decode RFC 3161 TimeStampResp: {0}")]
    DecodeResponse(#[source] der::Error),

    /// The transport (HTTP or mock) failed to deliver the request or read the response.
    #[error("TSA transport error: {0}")]
    Transport(String),

    /// The TSA returned a non-success `PKIStatus` (anything other than granted(0) /
    /// grantedWithMods(1) per RFC 3161 §2.4.2).
    #[error("TSA rejected the request (PKIStatus = {status})")]
    Rejected {
        /// The `PKIStatus` integer value.
        status: u8,
    },

    /// The response carried no `TimeStampToken` (yet reported success).
    #[error("TimeStampResp contained no TimeStampToken")]
    MissingToken,

    /// The token's `ContentInfo` was not a CMS `SignedData`.
    #[error("TimeStampToken is not a CMS SignedData (content-type OID {0})")]
    NotSignedData(String),

    /// The `SignedData` did not encapsulate a `TSTInfo`.
    #[error("SignedData does not encapsulate a TSTInfo (eContentType {0})")]
    NotTstInfo(String),

    /// The `SignedData` had no encapsulated content octets.
    #[error("TimeStampToken has no encapsulated content")]
    EmptyContent,

    /// A nested ASN.1 structure (`SignedData`, `TstInfo`, or an attribute) was malformed.
    #[error("malformed timestamp token: {0}")]
    Malformed(#[source] der::Error),

    /// The token's message imprint does not cover the digest we asked to be timestamped.
    #[error("message imprint mismatch: token does not cover the requested digest")]
    ImprintMismatch,

    /// The token's message imprint is not a SHA-256 imprint.
    #[error("hash algorithm mismatch: TSTInfo imprint is not SHA-256")]
    HashAlgorithmMismatch,

    /// The token's nonce does not equal the nonce we sent (RFC 3161 §2.4.2 replay check).
    #[error("nonce mismatch: TSTInfo nonce does not equal the request nonce")]
    NonceMismatch,

    /// The `SignedData` had no `SignerInfo`.
    #[error("SignedData contains no SignerInfo")]
    MissingSignerInfo,

    /// A required signed attribute was absent from the `SignerInfo`.
    #[error("SignerInfo is missing the {0} signed attribute")]
    MissingSignedAttribute(&'static str),

    /// The `message-digest` signed attribute does not equal SHA-256 of the encapsulated `TstInfo`.
    #[error("message-digest signed attribute does not match the encapsulated TSTInfo")]
    MessageDigestMismatch,

    /// The `content-type` signed attribute is not `id-ct-TSTInfo`.
    #[error("content-type signed attribute is not id-ct-TSTInfo")]
    ContentTypeMismatch,

    /// `certReq` was set but the token embeds no TSA signing certificate.
    #[error("certReq was set but the token embeds no TSA signing certificate")]
    NoTsaCertificate,

    /// The token's TSA policy OID is not among the accepted qualified-TSA policies (SIG-22).
    #[error("timestamp policy {got} is not an accepted qualified-TSA policy")]
    PolicyRejected {
        /// The policy OID the token actually carried, in dotted form.
        got: String,
    },

    /// The token's `genTime` was not a representable timestamp.
    #[error("invalid genTime in TSTInfo: {0}")]
    InvalidGenTime(String),
}
