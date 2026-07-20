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

    /// A requested XAdES level or feature is defined but not yet implemented in this crate.
    ///
    /// Used for XAdES-LT/LTA (scheduled for later t67 slices) so callers get a typed, non-panicking
    /// signal instead of a silent downgrade.
    #[error("not yet supported: {0}")]
    NotYetSupported(String),
}
