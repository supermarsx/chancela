//! The crate error type ([`RegistryError`]).

/// Failure modes of a registry consultation.
///
/// `InvalidCode` messages MUST NOT echo the raw access code (mask or omit it) — the whole code is
/// a secret credential (LEG-22 / GDPR).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RegistryError {
    /// The access code failed validation (not 12 digits). Maps to `422` at the API.
    #[error("invalid access code: {0}")]
    InvalidCode(String),
    /// Network/HTTP/empty-body failure consulting the registry. Maps to `502`.
    #[error("registry upstream failure: {0}")]
    Upstream(String),
    /// The response was not a recognisable certidão (e.g. an error/expired page). Maps to `502`.
    #[error("response was not a recognisable certidão: {0}")]
    Unrecognized(String),
    /// Misconfiguration (bad base URL, missing required env). Maps to `500`/`502`.
    #[error("config error: {0}")]
    Config(String),
}
