//! Crate error type. Filled out alongside the module bodies by t67-e4.

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
}
