//! The API's JSON error type.
//!
//! Every failing handler returns an [`ApiError`], which renders as a JSON body with the
//! status code pinned in the contract (plan §2.1). The base shape is `{"error": "..."}`; two
//! variants used by the compliance/seal flow add a structured `issues` or `warnings` array
//! alongside it. Keeping one error type (ARC-02, thin API) means callers get a uniform shape
//! regardless of which layer failed.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use chancela_cae::CaeError;
use chancela_core::{BookError, NipcError, SealError};
use chancela_registry::RegistryError;
use serde::Serialize;

use crate::dto::IssueView;

/// A request could not be fulfilled. Each variant maps to one HTTP status.
#[derive(Debug)]
pub enum ApiError {
    /// The submitted NIPC failed format or control-digit validation (422).
    InvalidNipc(NipcError),
    /// The addressed resource does not exist (404).
    NotFound,
    /// A sign-in secret / current-secret check failed, or was required and absent (401). Used by
    /// the password-gated session and secret/attestation-key endpoints (plan t29 §4.2/§4.3). The
    /// message never echoes the submitted secret.
    Unauthorized(String),
    /// The session is valid but not authorized to perform this cross-user operation (403). Distinct
    /// from [`Unauthorized`](ApiError::Unauthorized) (401 = no/invalid session or a self-service
    /// wrong-password): a 403 means "you are signed in, but you may not do this to another user
    /// without the required proof" (t51). The message is honest and never echoes any secret. On the
    /// cross-user secret/attestation-key endpoints this is returned uniformly for every no-valid-proof
    /// case (wrong password, no proof, or a target that does not exist) so it never enumerates users.
    Forbidden(String),
    /// Too many failed sign-in attempts for this user; the caller is in backoff (429). Carries a
    /// human, PT message with the seconds remaining (plan t29 §4.5).
    TooManyRequests(String),
    /// A precondition on the resource's state was not met, e.g. drafting into a non-open
    /// book or sealing an act that is not `Signing` (409).
    Conflict(String),
    /// The addressed resource existed but is no longer available — a single-use, TTL-bounded
    /// pending signing session that has expired or been consumed (410, t57-S3). Distinct from a
    /// [`NotFound`](ApiError::NotFound) so the client can tell "never existed" from "expired".
    Gone(String),
    /// The request was well-formed but semantically invalid, e.g. a malformed date or a
    /// compliance-blocked seal (422).
    Unprocessable(String),
    /// A candidate password failed the strength policy (422, t68). Carries the per-rule failures so
    /// the client can point at exactly which requirements were not met. **Additive + self-contained:**
    /// no `contracts/**` fixture describes this body — the base `error` field is preserved and a
    /// `failed_rules` array is added alongside it.
    PasswordPolicy {
        /// Human-readable summary (mirrors the base `error` field).
        message: String,
        /// The requirements the candidate did not satisfy.
        failures: Vec<crate::password_policy::PasswordRuleFailure>,
    },
    /// Sealing was blocked by `Error`-severity compliance issues (422). The offending issues
    /// are returned as a structured `issues` array so the UI can cite each legal basis.
    ComplianceBlocked {
        /// Human-readable summary (mirrors the base `error` field).
        message: String,
        /// The blocking issues (all `Error` severity).
        issues: Vec<IssueView>,
    },
    /// Sealing carried unacknowledged `Warning`-severity issues (409). The warnings are
    /// returned as a structured `warnings` array so the UI can prompt for acknowledgement.
    WarningsNotAcknowledged {
        /// Human-readable summary (mirrors the base `error` field).
        message: String,
        /// The warnings awaiting acknowledgement.
        warnings: Vec<IssueView>,
    },
    /// An in-app Cartão de Cidadão PIN was rejected or the card is blocked (422, t67-e8). Carries a
    /// structured, machine-readable `pin_status` (`"wrong_pin"`/`"blocked"`) and a best-effort
    /// `tries_left` hint alongside the base `error` message. **Never carries the PIN** — the message
    /// and every field are reconstructed from the smartcard's guaranteed PIN-free error, so a wrong
    /// PIN can never leak through the body. Additive + self-contained (no `contracts/**` fixture).
    PinRejected {
        /// Human-readable, PIN-free summary (mirrors the base `error` field).
        message: String,
        /// `"wrong_pin"` (an incorrect PIN was presented) or `"blocked"` (the card is locked).
        pin_status: &'static str,
        /// Best-effort remaining-attempt hint (`"low"`/`"final_try"`/`"locked"`/`"unknown"`), or
        /// `None` when the card revealed nothing.
        tries_left: Option<&'static str>,
    },
    /// An unexpected internal failure, e.g. payload serialization (500). The string is a
    /// short, non-sensitive description safe to return to the caller.
    Internal(String),
    /// A dependency upstream of the API failed — currently the certidão permanente registry
    /// consultation (network/HTTP failure, or a response that was not a recognisable
    /// certidão). Maps to `502 Bad Gateway` (contract §2.7).
    Upstream(String),
}

/// The base JSON body every error renders to.
#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

/// Error body with a structured `issues` array (compliance-blocked seal).
#[derive(Serialize)]
struct ErrorWithIssues<'a> {
    error: &'a str,
    issues: &'a [IssueView],
}

/// Error body with a structured `warnings` array (unacknowledged warnings).
#[derive(Serialize)]
struct ErrorWithWarnings<'a> {
    error: &'a str,
    warnings: &'a [IssueView],
}

/// Error body with a structured `failed_rules` array (password strength policy, t68). Additive: the
/// base `error` field is preserved so a plain-envelope client still reads a message.
#[derive(Serialize)]
struct ErrorWithPasswordFailures<'a> {
    error: &'a str,
    failed_rules: &'a [crate::password_policy::PasswordRuleFailure],
}

/// Error body for a rejected/blocked in-app Cartão de Cidadão PIN (t67-e8). Additive: the base
/// `error` field is preserved and PIN-free machine-readable fields are added alongside it. **Never
/// carries the PIN.**
#[derive(Serialize)]
struct ErrorWithPinStatus<'a> {
    error: &'a str,
    pin_status: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    tries_left: Option<&'a str>,
}

impl ApiError {
    fn status(&self) -> StatusCode {
        match self {
            ApiError::InvalidNipc(_)
            | ApiError::Unprocessable(_)
            | ApiError::PasswordPolicy { .. }
            | ApiError::PinRejected { .. }
            | ApiError::ComplianceBlocked { .. } => StatusCode::UNPROCESSABLE_ENTITY,
            ApiError::NotFound => StatusCode::NOT_FOUND,
            ApiError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            ApiError::Forbidden(_) => StatusCode::FORBIDDEN,
            ApiError::TooManyRequests(_) => StatusCode::TOO_MANY_REQUESTS,
            ApiError::Conflict(_) | ApiError::WarningsNotAcknowledged { .. } => {
                StatusCode::CONFLICT
            }
            ApiError::Gone(_) => StatusCode::GONE,
            ApiError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ApiError::Upstream(_) => StatusCode::BAD_GATEWAY,
        }
    }

    fn message(&self) -> String {
        match self {
            ApiError::InvalidNipc(e) => e.to_string(),
            ApiError::NotFound => "resource not found".to_owned(),
            ApiError::Conflict(msg)
            | ApiError::Gone(msg)
            | ApiError::Unprocessable(msg)
            | ApiError::Unauthorized(msg)
            | ApiError::Forbidden(msg)
            | ApiError::TooManyRequests(msg)
            | ApiError::Internal(msg)
            | ApiError::Upstream(msg) => msg.clone(),
            ApiError::ComplianceBlocked { message, .. }
            | ApiError::WarningsNotAcknowledged { message, .. }
            | ApiError::PinRejected { message, .. }
            | ApiError::PasswordPolicy { message, .. } => message.clone(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status();
        // t41 M6: log internal/upstream errors server-side with full detail, return a generic
        // message to the client so internal state never leaks through the wire.
        let message = match &self {
            ApiError::Internal(msg) => {
                eprintln!("chancela-api internal error: {msg}");
                "erro interno".to_owned()
            }
            ApiError::Upstream(msg) => {
                eprintln!("chancela-api upstream error: {msg}");
                "erro de gateway".to_owned()
            }
            other => other.message(),
        };
        match &self {
            ApiError::ComplianceBlocked { message, issues } => (
                status,
                Json(ErrorWithIssues {
                    error: message,
                    issues,
                }),
            )
                .into_response(),
            ApiError::WarningsNotAcknowledged { message, warnings } => (
                status,
                Json(ErrorWithWarnings {
                    error: message,
                    warnings,
                }),
            )
                .into_response(),
            ApiError::PasswordPolicy { message, failures } => (
                status,
                Json(ErrorWithPasswordFailures {
                    error: message,
                    failed_rules: failures,
                }),
            )
                .into_response(),
            ApiError::PinRejected {
                message,
                pin_status,
                tries_left,
            } => (
                status,
                Json(ErrorWithPinStatus {
                    error: message,
                    pin_status,
                    tries_left: *tries_left,
                }),
            )
                .into_response(),
            _ => (status, Json(ErrorBody { error: message })).into_response(),
        }
    }
}

impl From<NipcError> for ApiError {
    fn from(e: NipcError) -> Self {
        ApiError::InvalidNipc(e)
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(e: serde_json::Error) -> Self {
        ApiError::Internal(format!("serialization failed: {e}"))
    }
}

/// An attestation crypto fault (a corrupt stored key blob, an RNG/serialization failure) is an
/// internal error (`500`). A *wrong password* is never this — the handler checks that with
/// [`verify_secret`](crate::attestation::verify_secret) and returns `401` itself.
impl From<crate::attestation::AttestationError> for ApiError {
    fn from(e: crate::attestation::AttestationError) -> Self {
        ApiError::Internal(e.to_string())
    }
}

/// Every `BookError` is a state-precondition failure → `409 Conflict` (contract §2.4/§2.5:
/// drafting into a non-open book, closing a non-open book, sealing across books).
impl From<BookError> for ApiError {
    fn from(e: BookError) -> Self {
        ApiError::Conflict(e.to_string())
    }
}

/// Default mapping for `SealError` used by book opening. The seal *handler* intercepts the
/// compliance variants itself to attach structured `issues`/`warnings` (contract §2.5), so
/// here they fall back to their plain-status forms.
impl From<SealError> for ApiError {
    fn from(e: SealError) -> Self {
        match e {
            SealError::Book(b) => b.into(),
            // Act-state failures at seal time (e.g. not `Signing`, wrong book) are conflicts.
            SealError::Act(a) => ApiError::Conflict(a.to_string()),
            SealError::ComplianceBlocked(msg) => ApiError::Unprocessable(msg),
            SealError::WarningsNotAcknowledged(msg) => ApiError::Conflict(msg),
            SealError::Serialize(msg) => ApiError::Internal(msg),
        }
    }
}

/// Registry consultation failures (contract §2.7): a malformed access code is the caller's
/// fault (`422`); every upstream/recognition/config failure is a bad gateway (`502`). The
/// message never echoes the raw code — `RegistryError::InvalidCode` reports only the digit
/// count, so a mistyped secret cannot leak through the error body.
impl From<RegistryError> for ApiError {
    fn from(e: RegistryError) -> Self {
        let msg = e.to_string();
        match e {
            RegistryError::InvalidCode(_) => ApiError::Unprocessable(msg),
            // Upstream / Unrecognized / Config (and any future variant) → 502.
            _ => ApiError::Upstream(msg),
        }
    }
}

/// CAE auto-update failures on `POST /v1/cae/refresh` (contract §2.7): a fetch/parse/integrity
/// failure is a bad gateway (`502`); a config error (e.g. `CHANCELA_CAE_URL` unset) is a server
/// misconfiguration (`500`).
impl From<CaeError> for ApiError {
    fn from(e: CaeError) -> Self {
        let msg = e.to_string();
        match e {
            CaeError::Config(_) => ApiError::Internal(msg),
            // Http / Parse / Integrity (and any future variant) → 502.
            _ => ApiError::Upstream(msg),
        }
    }
}
