//! The crate error type ([`CscError`]).

use thiserror::Error;

/// Errors raised by the Cloud Signature Consortium (CSC) v2 REST client.
///
/// Covers transport/HTTP failures, malformed or oversized JSON, CSC service-level error
/// bodies (`{ "error", "error_description" }`), OTP/SAD rejection, configuration, and
/// certificate decoding. Relates to spec 04 SIG-01/02: the OTP/SAD activation is a
/// confirmation step inside the qualified flow, never the signature artifact.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CscError {
    /// The underlying HTTP transport failed (connection, TLS, timeout). Carries a
    /// human-readable description of the cause. **Never** carries a request body (which would
    /// hold the client secret / OTP / SAD).
    #[error("CSC transport error: {0}")]
    Transport(String),

    /// The CSC response body exceeded the safety limit. CSC JSON responses are small
    /// (certificates + short status payloads); a larger body signals a misbehaving or hostile
    /// endpoint and is rejected before the full body is buffered.
    #[error("CSC response body too large: {content_length} bytes (limit {limit} bytes)")]
    ResponseTooLarge {
        /// The Content-Length the endpoint advertised (or the buffered byte count), in bytes.
        content_length: u64,
        /// The enforced limit, in bytes.
        limit: u64,
    },

    /// A non-2xx HTTP status with no parseable CSC error body.
    #[error("CSC endpoint returned HTTP {status}")]
    HttpStatus {
        /// The HTTP status code.
        status: u16,
    },

    /// The CSC service returned a structured error body (`{ "error", "error_description" }`).
    #[error("CSC service error '{error}': {description}")]
    Service {
        /// The CSC `error` code (e.g. `"invalid_otp"`, `"invalid_request"`).
        error: String,
        /// The CSC `error_description` message.
        description: String,
    },

    /// A CSC response JSON could not be parsed, or a required member was absent.
    #[error("failed to parse CSC response: {0}")]
    ResponseParse(String),

    /// Configuration was missing or malformed (e.g. absent client credentials, bad base URL).
    #[error("configuration error: {0}")]
    Config(String),

    /// No signing credential could be resolved (empty `credentials/list`, and none configured).
    #[error("no signing credential available for provider '{provider_id}'")]
    NoCredential {
        /// The provider whose credential list was empty.
        provider_id: String,
    },

    /// `signatures/signHash` returned no signature value.
    #[error("signHash returned no signature")]
    NoSignature,

    /// A certificate returned by `credentials/info` was missing or not valid X.509 DER.
    #[error("certificate error: {0}")]
    Certificate(String),

    /// A base64 wire field (certificate, hash, signature, SAD) could not be decoded.
    #[error("base64 decode error: {0}")]
    Base64(String),
}
