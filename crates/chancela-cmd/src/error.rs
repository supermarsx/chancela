//! The crate error type ([`CmdError`]).

use thiserror::Error;

/// Errors raised by the Chave Movel Digital (SCMD) SOAP client.
///
/// Covers transport/HTTP failures, malformed SOAP, service-level status codes
/// (`CCMovelSign` / `ValidateOtp`), OTP rejection, configuration, and the
/// PROD field-encryption hook. Relates to spec 04 SIG-02 (the OTP is a
/// possession-factor confirmation step, never the signature artifact).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CmdError {
    /// The underlying HTTP transport failed (connection, TLS, timeout, non-fault
    /// error status). Carries a human-readable description of the cause.
    #[error("SCMD transport error: {0}")]
    Transport(String),

    /// The SCMD response body exceeded the safety limit (t41-e4 H4). CMD SOAP
    /// responses are small; a body larger than 1 MiB signals a misbehaving or
    /// hostile endpoint and is rejected before the full body is buffered.
    #[error("SCMD response body too large: declared {content_length} bytes (limit {limit} bytes)")]
    ResponseTooLarge {
        /// The Content-Length the endpoint advertised (or the buffered byte count), in bytes.
        content_length: u64,
        /// The enforced limit, in bytes.
        limit: u64,
    },

    /// A SOAP request envelope could not be constructed.
    #[error("failed to build SOAP request: {0}")]
    RequestBuild(String),

    /// A SOAP response could not be parsed or a required element was absent.
    #[error("failed to parse SOAP response: {0}")]
    ResponseParse(String),

    /// The service returned a SOAP `Fault` (e.g. invalid `ApplicationId`).
    #[error("SOAP fault: {0}")]
    SoapFault(String),

    /// `CCMovelSign` returned a non-success `SignStatus` code (signature not started).
    #[error("SCMD service returned status {code}: {message}")]
    ServiceStatus {
        /// The SCMD `Code` field (success is `"200"`).
        code: String,
        /// The SCMD `Message` field.
        message: String,
    },

    /// `ValidateOtp` rejected the OTP (wrong / expired code) — SIG-02 possession factor failed.
    #[error("OTP validation rejected (status {code}): {message}")]
    OtpRejected {
        /// The SCMD `Status.Code` field.
        code: String,
        /// The SCMD `Status.Message` field.
        message: String,
    },

    /// Configuration was missing or malformed (e.g. absent `CHANCELA_CMD_APPLICATION_ID`).
    #[error("configuration error: {0}")]
    Config(String),

    /// The PROD field-encryption hook failed (bad AMA cert, RSA error).
    #[error("field encryption error: {0}")]
    Encryption(String),

    /// A certificate returned by `GetCertificate` was missing or not valid X.509.
    #[error("certificate error: {0}")]
    Certificate(String),

    /// A base64 wire field (signature, hash) could not be decoded.
    #[error("base64 decode error: {0}")]
    Base64(String),
}
