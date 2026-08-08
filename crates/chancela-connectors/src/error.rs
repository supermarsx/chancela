use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::codes::GatedTransport;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorClass {
    Cancelled,
    Configuration,
    Authentication,
    NotFound,
    Conflict,
    RateLimited,
    Transient,
    Permanent,
    Integrity,
}

#[derive(Debug, Error)]
#[error("{class:?}: {message}")]
pub struct ConnectorError {
    pub class: ErrorClass,
    /// Sanitized message only. Callers must never place response bodies,
    /// authorization headers, signed upload URLs, or credentials here.
    pub message: String,
    pub retry_after_seconds: Option<u64>,
    /// Stable machine identifier for this failure, drawn from [`crate::codes`], for the failures
    /// a client has to render in the operator's language. `None` for the failures that still
    /// carry only the English `message` — see that module for why a code exists at all.
    pub code: Option<&'static str>,
}

impl ConnectorError {
    pub fn new(class: ErrorClass, message: impl Into<String>) -> Self {
        Self {
            class,
            message: message.into(),
            retry_after_seconds: None,
            code: None,
        }
    }

    pub fn transient(message: impl Into<String>) -> Self {
        Self::new(ErrorClass::Transient, message)
    }

    pub fn configuration(message: impl Into<String>) -> Self {
        Self::new(ErrorClass::Configuration, message)
    }

    pub fn cancelled() -> Self {
        Self::new(ErrorClass::Cancelled, "operation cancelled")
    }

    /// The target is configured and valid, but this binary was built without the protocol client
    /// that dials it.
    ///
    /// Classified [`ErrorClass::Configuration`] — permanent, and therefore never retried by
    /// [`is_retryable`](Self::is_retryable). A backup aimed at a transport this build cannot
    /// speak has to fail and stay failed; retrying it forever, or letting it pass, would both
    /// end the same way — an operator discovering during a restore that nothing was ever
    /// uploaded.
    pub fn transport_not_compiled(transport: GatedTransport) -> Self {
        Self {
            class: ErrorClass::Configuration,
            message: format!(
                "this build was compiled without the {feature} transport; rebuild with the \
                 chancela-connectors \"{feature}\" cargo feature (the published server and worker \
                 images enable all four)",
                feature = transport.cargo_feature(),
            ),
            retry_after_seconds: None,
            code: Some(transport.not_compiled_code()),
        }
    }

    /// Whether this is the "the client for this transport was not compiled into this binary"
    /// refusal from [`Self::transport_not_compiled`].
    ///
    /// Callers need this to tell a *deployment* fault from a *request* fault: the stored target
    /// is valid, so the honest answer is a failed probe naming the build, not a rejection of the
    /// operator's input.
    pub fn is_transport_not_compiled(&self) -> bool {
        self.code.is_some_and(|code| {
            crate::codes::ALL_GATED_TRANSPORTS
                .iter()
                .any(|transport| transport.not_compiled_code() == code)
        })
    }

    pub fn is_retryable(&self) -> bool {
        matches!(self.class, ErrorClass::RateLimited | ErrorClass::Transient)
    }

    pub(crate) fn from_http(status: reqwest::StatusCode, operation: &str) -> Self {
        let class = match status.as_u16() {
            401 | 403 => ErrorClass::Authentication,
            404 => ErrorClass::NotFound,
            409 | 412 => ErrorClass::Conflict,
            429 => ErrorClass::RateLimited,
            500..=599 => ErrorClass::Transient,
            _ => ErrorClass::Permanent,
        };
        Self::new(class, format!("{operation} returned HTTP {status}"))
    }

    pub(crate) fn io(operation: &str, error: &std::io::Error) -> Self {
        let class = if error.kind() == std::io::ErrorKind::NotFound {
            ErrorClass::NotFound
        } else {
            ErrorClass::Permanent
        };
        Self::new(class, format!("{operation}: {}", error.kind()))
    }
}
