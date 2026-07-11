//! Crate error type. Filled out alongside the module bodies by t67-e2.

/// Errors produced while canonicalizing, building, or validating XMLDSig/XAdES.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum XadesError {
    /// XML could not be parsed.
    #[error("xml parse error: {0}")]
    XmlParse(String),

    /// Canonicalization failed.
    #[error("canonicalization error: {0}")]
    Canonicalization(String),

    /// A signature or digest did not verify.
    #[error("verification error: {0}")]
    Verification(String),
}
