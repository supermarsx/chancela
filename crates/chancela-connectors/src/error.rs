use serde::{Deserialize, Serialize};
use thiserror::Error;

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
}

impl ConnectorError {
    pub fn new(class: ErrorClass, message: impl Into<String>) -> Self {
        Self {
            class,
            message: message.into(),
            retry_after_seconds: None,
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
