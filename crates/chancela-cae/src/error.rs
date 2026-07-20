//! Error taxonomy (§2.3). Each variant maps to an HTTP status at the API: `Http`/`Parse`/
//! `Integrity` → 502, `Config` → 500/502.

use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CaeError {
    /// The source (network/file) could not be read.
    #[error("cae source failure: {0}")]
    Http(String),
    /// The dataset bytes did not deserialize into a [`CaeDataset`](crate::CaeDataset).
    #[error("cae dataset parse error: {0}")]
    Parse(String),
    /// The dataset deserialized but failed the structural integrity check (bad level shape,
    /// unresolved parent, duplicate code, …).
    #[error("cae dataset failed integrity check: {0}")]
    Integrity(String),
    /// Missing/invalid configuration (e.g. `CHANCELA_CAE_URL` unset, client build failed).
    #[error("cae config error: {0}")]
    Config(String),
}
