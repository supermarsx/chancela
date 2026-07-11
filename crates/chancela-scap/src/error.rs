//! Crate error type.
//!
//! Errors never carry credential material: transport/config messages are built from non-secret
//! context only (URLs, field names, status codes), never from the application secret.

/// Errors produced while talking to SCAP or building/verifying an attribute-qualified signature.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ScapError {
    /// A transport call (HTTP or mock fixture) failed.
    #[error("scap transport error: {0}")]
    Transport(String),

    /// The SCAP configuration was invalid or incomplete (e.g. PROD without credentials).
    #[error("scap configuration error: {0}")]
    Config(String),

    /// Attribute verification did not yield a Granted result.
    #[error("scap verification error: {0}")]
    Verification(String),

    /// Building or assembling the attribute-qualified signature failed (via the cades seam).
    #[error("scap signature error: {0}")]
    Signature(String),
}
