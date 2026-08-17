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

impl ErrorClass {
    /// Whether a failure of this class is worth attempting again.
    ///
    /// The single definition in the codebase: [`ConnectorError::is_retryable`] delegates here, and
    /// so does every caller that only has a class in hand — a queued job's recorded `error_class`,
    /// for instance. A resolution failure and an upload failure must not be able to disagree about
    /// what "retryable" means, so the answer is a property of the class and nowhere else.
    ///
    /// The line is drawn at *decidability*: a class that states something about the environment at
    /// this instant is retryable; a class that states something about the request or the
    /// configuration is not, because the same inputs would produce the same answer forever.
    #[must_use]
    pub fn is_retryable(self) -> bool {
        matches!(self, Self::RateLimited | Self::Transient)
    }
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
        self.class.is_retryable()
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Every class, decided one way or the other, on purpose.
    ///
    /// Written as an exhaustive `match` rather than a list of the two retryable ones so that adding
    /// a variant to [`ErrorClass`] does not compile until someone has said which side it falls on.
    /// The queue's behaviour hangs off this answer: a class marked retryable costs a job
    /// `max_job_attempts` backed-off retries before it dead-letters, and a class marked permanent
    /// dead-letters a job on its first attempt — a backup that then exists only as a failed row
    /// until an operator stages and confirms a retry for it.
    #[test]
    fn every_error_class_declares_whether_it_is_worth_trying_again() {
        for class in [
            ErrorClass::Cancelled,
            ErrorClass::Configuration,
            ErrorClass::Authentication,
            ErrorClass::NotFound,
            ErrorClass::Conflict,
            ErrorClass::RateLimited,
            ErrorClass::Transient,
            ErrorClass::Permanent,
            ErrorClass::Integrity,
        ] {
            let expected = match class {
                // The environment declined to answer, or asked us to come back later. Nothing about
                // the request is wrong, so the same request may well succeed.
                ErrorClass::RateLimited | ErrorClass::Transient => true,
                // Everything else is a decided fact about the request, the credentials, the
                // configuration or the bytes. Re-asking produces the same answer and only delays
                // the moment an operator is told.
                ErrorClass::Cancelled
                | ErrorClass::Configuration
                | ErrorClass::Authentication
                | ErrorClass::NotFound
                | ErrorClass::Conflict
                | ErrorClass::Permanent
                | ErrorClass::Integrity => false,
            };
            assert_eq!(class.is_retryable(), expected, "{class:?}");
            assert_eq!(
                ConnectorError::new(class, "probe").is_retryable(),
                expected,
                "{class:?}: the error and its class must never disagree"
            );
        }
    }
}
