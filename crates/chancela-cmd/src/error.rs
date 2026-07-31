//! The crate error type ([`CmdError`]).

use thiserror::Error;

/// Errors raised by the Chave Movel Digital (SCMD) JSON/REST client.
///
/// Covers transport/HTTP failures, malformed JSON, service-level status codes
/// (`SCMDSign` / `ValidateOtp`), OTP rejection, configuration, and the
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

    /// A JSON request body could not be constructed.
    #[error("failed to build SCMD request: {0}")]
    RequestBuild(String),

    /// A JSON response could not be parsed or a required member was absent.
    #[error("failed to parse SCMD response: {0}")]
    ResponseParse(String),

    /// A SOAP `Fault`. **Legacy:** the JSON `AppSCMDService` never returns one, so the flow no
    /// longer produces this variant; it is retained because [`error_class`](CmdError) consumers
    /// (e.g. `chancela-api`'s credential resolver) still classify it.
    #[error("SOAP fault: {0}")]
    SoapFault(String),

    /// `SCMDSign` returned a non-success `SignStatus` code (signature not started).
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

// --- Stable wire codes for CMD errors surfaced to an operator -------------------------------------
//
// # Why these exist
//
// A `CmdError` that reaches an operator does so through `chancela-api`'s `map_signing_error`, which
// wrapped its `Display` — raw English — inside a Portuguese sentence ("a Chave Móvel Digital recusou
// o pedido: {detail}"). The headline was translated; the detail was not, so a non-pt-PT operator read
// a half-Portuguese, half-English line. This is the same class of half-translated error the provider
// probe diagnostics (`provider_probe_codes.rs`) already fixed, and the fix is the same shape: **the
// wire carries a stable machine code, and the client maps that code to a sentence in its own
// language.**
//
// These name the CMD error VOCABULARY — one code per distinct operator sentence — and are English,
// snake_case, and never translated. They are append-only: renaming one silently changes what a
// client renders, and deleting one strands an older client's translation. `chancela-api`'s
// `map_signing_error` classifies a surfaced `CmdError` to one of these (see
// [`CmdError::stable_code`]); the client's `apiErrorFallback.ts` maps each to a catalog key, and
// `apiErrorFallback.test.ts` reads [`ALL_CMD_ERROR_CODES`] out of this file to prove none is left
// untranslated.

/// The HTTP transport to AMA failed (connection, TLS, timeout, non-fault error status).
pub const CMD_TRANSPORT_FAILED: &str = "cmd_transport_failed";
/// AMA's response exceeded the response-size safety limit and was refused.
pub const CMD_RESPONSE_TOO_LARGE: &str = "cmd_response_too_large";
/// The JSON request to AMA could not be constructed.
pub const CMD_REQUEST_BUILD_FAILED: &str = "cmd_request_build_failed";
/// AMA's response could not be parsed, or a required member was absent.
pub const CMD_RESPONSE_UNREADABLE: &str = "cmd_response_unreadable";
/// A SOAP fault (legacy; the JSON service never returns one, but the variant is classified).
pub const CMD_SOAP_FAULT: &str = "cmd_soap_fault";
/// `SCMDSign` returned a non-success status — the signature was not started (e.g. a wrong PIN).
pub const CMD_SERVICE_REJECTED: &str = "cmd_service_rejected";
/// `ValidateOtp` rejected the OTP — the possession factor was wrong or expired.
pub const CMD_OTP_REJECTED: &str = "cmd_otp_rejected";
/// The CMD configuration was missing or malformed.
pub const CMD_CONFIGURATION_INVALID: &str = "cmd_configuration_invalid";
/// The PROD field-encryption hook failed (bad AMA cert, RSA error).
pub const CMD_FIELD_ENCRYPTION_FAILED: &str = "cmd_field_encryption_failed";
/// A certificate AMA returned was missing or not valid X.509.
pub const CMD_CERTIFICATE_CHAIN_INVALID: &str = "cmd_certificate_chain_invalid";
/// A base64 wire field could not be decoded.
pub const CMD_BASE64_INVALID: &str = "cmd_base64_invalid";
/// The classify-miss fallback: a provider message that did not match any known `CmdError` shape.
/// Kept in the vocabulary so the client has a translated headline for it too, rather than falling to
/// a bare status tier.
pub const CMD_REFUSED: &str = "cmd_refused";

/// Every stable CMD error code, in one closed list.
///
/// Read by this module's own tests and — as the file's text — by
/// `apps/web/src/i18n/apiErrorFallback.test.ts`, which proves the client maps each to a catalog key.
/// Append-only.
pub const ALL_CMD_ERROR_CODES: &[&str] = &[
    CMD_TRANSPORT_FAILED,
    CMD_RESPONSE_TOO_LARGE,
    CMD_REQUEST_BUILD_FAILED,
    CMD_RESPONSE_UNREADABLE,
    CMD_SOAP_FAULT,
    CMD_SERVICE_REJECTED,
    CMD_OTP_REJECTED,
    CMD_CONFIGURATION_INVALID,
    CMD_FIELD_ENCRYPTION_FAILED,
    CMD_CERTIFICATE_CHAIN_INVALID,
    CMD_BASE64_INVALID,
    CMD_REFUSED,
];

impl CmdError {
    /// The stable machine code for this error, English and never translated.
    ///
    /// Every arm returns a per-variant code from [`ALL_CMD_ERROR_CODES`]; it never returns
    /// [`CMD_REFUSED`], which is only the classify-miss fallback used by
    /// [`CmdError::stable_code_from_display`].
    pub fn stable_code(&self) -> &'static str {
        match self {
            CmdError::Transport(_) => CMD_TRANSPORT_FAILED,
            CmdError::ResponseTooLarge { .. } => CMD_RESPONSE_TOO_LARGE,
            CmdError::RequestBuild(_) => CMD_REQUEST_BUILD_FAILED,
            CmdError::ResponseParse(_) => CMD_RESPONSE_UNREADABLE,
            CmdError::SoapFault(_) => CMD_SOAP_FAULT,
            CmdError::ServiceStatus { .. } => CMD_SERVICE_REJECTED,
            CmdError::OtpRejected { .. } => CMD_OTP_REJECTED,
            CmdError::Config(_) => CMD_CONFIGURATION_INVALID,
            CmdError::Encryption(_) => CMD_FIELD_ENCRYPTION_FAILED,
            CmdError::Certificate(_) => CMD_CERTIFICATE_CHAIN_INVALID,
            CmdError::Base64(_) => CMD_BASE64_INVALID,
        }
    }

    /// Recover the stable code from a flattened `CmdError` [`Display`](std::fmt::Display) string.
    ///
    /// The signing layer captures a `CmdError` as its `Display` string
    /// (`SigningError::Provider(e.to_string())`), so by the time the API surfaces it the typed
    /// variant is gone. This classifies that string back to a code by its stable English prefix.
    /// A message that matches no known shape yields [`CMD_REFUSED`], so the operator still gets a
    /// translated headline rather than a bare status tier.
    ///
    /// The prefixes are the fixed leading text of each variant's `#[error(...)]`; a unit test formats
    /// every variant and asserts this recovers exactly [`stable_code`](CmdError::stable_code), so the
    /// two cannot drift.
    pub fn stable_code_from_display(display: &str) -> &'static str {
        // Order is irrelevant: every prefix below is unambiguous against the others.
        const PREFIXES: &[(&str, &str)] = &[
            ("SCMD transport error:", CMD_TRANSPORT_FAILED),
            ("SCMD response body too large:", CMD_RESPONSE_TOO_LARGE),
            ("SCMD service returned status", CMD_SERVICE_REJECTED),
            ("failed to build SCMD request:", CMD_REQUEST_BUILD_FAILED),
            ("failed to parse SCMD response:", CMD_RESPONSE_UNREADABLE),
            ("SOAP fault:", CMD_SOAP_FAULT),
            ("OTP validation rejected", CMD_OTP_REJECTED),
            ("configuration error:", CMD_CONFIGURATION_INVALID),
            ("field encryption error:", CMD_FIELD_ENCRYPTION_FAILED),
            ("certificate error:", CMD_CERTIFICATE_CHAIN_INVALID),
            ("base64 decode error:", CMD_BASE64_INVALID),
        ];
        for (prefix, code) in PREFIXES {
            if display.starts_with(prefix) {
                return code;
            }
        }
        CMD_REFUSED
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// One `CmdError` of every variant, so a test that iterates them cannot silently miss one added
    /// later — a new variant makes this match fail to compile until it is listed.
    fn one_of_each_variant() -> Vec<CmdError> {
        let sample = |e: &CmdError| -> CmdError {
            match e {
                CmdError::Transport(_) => CmdError::Transport("boom".into()),
                CmdError::ResponseTooLarge { .. } => CmdError::ResponseTooLarge {
                    content_length: 2_000_000,
                    limit: 1_048_576,
                },
                CmdError::RequestBuild(_) => CmdError::RequestBuild("boom".into()),
                CmdError::ResponseParse(_) => CmdError::ResponseParse("boom".into()),
                CmdError::SoapFault(_) => CmdError::SoapFault("boom".into()),
                CmdError::ServiceStatus { .. } => CmdError::ServiceStatus {
                    code: "401".into(),
                    message: "PIN invalido".into(),
                },
                CmdError::OtpRejected { .. } => CmdError::OtpRejected {
                    code: "402".into(),
                    message: "OTP invalido".into(),
                },
                CmdError::Config(_) => CmdError::Config("boom".into()),
                CmdError::Encryption(_) => CmdError::Encryption("boom".into()),
                CmdError::Certificate(_) => CmdError::Certificate("boom".into()),
                CmdError::Base64(_) => CmdError::Base64("boom".into()),
            }
        };
        // Listing each variant here is the enumeration; `sample` just canonicalises the payloads.
        [
            CmdError::Transport(String::new()),
            CmdError::ResponseTooLarge {
                content_length: 0,
                limit: 0,
            },
            CmdError::RequestBuild(String::new()),
            CmdError::ResponseParse(String::new()),
            CmdError::SoapFault(String::new()),
            CmdError::ServiceStatus {
                code: String::new(),
                message: String::new(),
            },
            CmdError::OtpRejected {
                code: String::new(),
                message: String::new(),
            },
            CmdError::Config(String::new()),
            CmdError::Encryption(String::new()),
            CmdError::Certificate(String::new()),
            CmdError::Base64(String::new()),
        ]
        .iter()
        .map(sample)
        .collect()
    }

    #[test]
    fn every_code_is_a_unique_lowercase_identifier() {
        let unique: BTreeSet<&&str> = ALL_CMD_ERROR_CODES.iter().collect();
        assert_eq!(
            unique.len(),
            ALL_CMD_ERROR_CODES.len(),
            "two CMD error codes collide, so a client cannot tell their sentences apart"
        );
        for code in ALL_CMD_ERROR_CODES {
            assert!(
                !code.is_empty()
                    && code
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "CMD error code {code:?} is not lower_snake_case ascii"
            );
        }
    }

    #[test]
    fn every_variant_has_a_listed_stable_code() {
        for e in one_of_each_variant() {
            let code = e.stable_code();
            assert!(
                ALL_CMD_ERROR_CODES.contains(&code),
                "{e:?} yielded code {code:?}, which is not in ALL_CMD_ERROR_CODES"
            );
            assert_ne!(
                code, CMD_REFUSED,
                "{e:?} classified as the generic fallback; every variant needs its own code"
            );
        }
    }

    /// The load-bearing guarantee: the Display-prefix classifier recovers exactly what
    /// `stable_code` declares, for every variant. This is what lets the API attach the right code to
    /// a `CmdError` that was flattened to a string two crates ago, and it is what stops the classifier
    /// drifting from the `#[error(...)]` messages.
    #[test]
    fn the_display_classifier_recovers_the_stable_code_of_every_variant() {
        for e in one_of_each_variant() {
            let via_display = CmdError::stable_code_from_display(&e.to_string());
            assert_eq!(
                via_display,
                e.stable_code(),
                "classifying {:?} by its Display recovered the wrong code",
                e.to_string()
            );
        }
    }

    #[test]
    fn an_unknown_message_falls_back_to_cmd_refused() {
        assert_eq!(
            CmdError::stable_code_from_display("a smartcard PIN is blocked"),
            CMD_REFUSED
        );
        assert_eq!(CmdError::stable_code_from_display(""), CMD_REFUSED);
    }
}
