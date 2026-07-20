//! Error taxonomy for the law corpus. Mirrors [`chancela_cae::CaeError`]: `Http`/`Parse`/
//! `Integrity` map to a 502 at the API, `Config` to a 500/502.

use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum LawError {
    /// The source (network/file) could not be read.
    #[error("law source failure: {0}")]
    Http(String),
    /// The corpus bytes did not deserialize into a [`LawCorpus`](crate::LawCorpus).
    #[error("law corpus parse error: {0}")]
    Parse(String),
    /// The corpus deserialized but failed the integrity / **authenticity** gate — e.g. a `Verified`
    /// article whose [`LawSource`](crate::LawSource) is incomplete, a duplicate article key, or an
    /// article tagged to the wrong diploma.
    #[error("law corpus failed integrity check: {0}")]
    Integrity(String),
    /// Missing/invalid configuration (e.g. the fetch URL env var is unset).
    #[error("law config error: {0}")]
    Config(String),
}
