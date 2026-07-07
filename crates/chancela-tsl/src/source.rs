//! Trusted List transport: the [`TslSource`] trait plus a network source and a file source.
//!
//! Fetching is abstracted behind a trait so the parse/status/cache/query logic is fully testable
//! offline against a bundled fixture ([`FileTslSource`]); the live network fetch
//! ([`HttpTslSource`]) is exercised only by a feature-gated, `#[ignore]`d test.

use std::path::PathBuf;

use crate::error::TslError;

/// The default location of the Portuguese Trusted List published by the Gabinete Nacional de
/// Seguranca (GNS). Overridable via the `CHANCELA_TSL_URL` environment variable (§2.3). The URL
/// is also resolvable from the EU List of Trusted Lists (LOTL); it is pinned here so an offline
/// build has a sane default.
///
/// **Verified live 2026-07-07**: this returns the current `TrustServiceStatusList` (scheme
/// operator "Gabinete Nacional de Segurança"). GNS periodically **renames the published asset**
/// — the previous pin `media/2793/TSL_PT.xml` now 404s because the CMS id path and filename
/// changed (`TSL_PT.xml` → `TSLPT.xml`). The un-numbered `media/TSLPT.xml` form is the stabler
/// one, but this is a remote we do not control: if it 404s again, override it with
/// `CHANCELA_TSL_URL` (the escape hatch) and re-resolve the current URL from the EU LOTL.
pub const DEFAULT_PT_TSL_URL: &str = "https://www.gns.gov.pt/media/TSLPT.xml";

/// The environment variable that overrides [`DEFAULT_PT_TSL_URL`] (§2.3).
pub const ENV_TSL_URL: &str = "CHANCELA_TSL_URL";

/// A source of Trusted List XML bytes. Implemented by the live network fetcher and by the
/// on-disk/fixture loader; production code and tests both program against this trait.
pub trait TslSource {
    /// Fetch the raw Trusted List XML.
    fn fetch(&self) -> Result<Vec<u8>, TslError>;
}

/// Fetches the Trusted List over HTTPS with a blocking `reqwest` client.
///
/// Constructed from [`CHANCELA_TSL_URL`](ENV_TSL_URL) or [`DEFAULT_PT_TSL_URL`]. Only the
/// feature-gated, `#[ignore]`d network test drives this against the live endpoint; nothing in CI
/// touches the network.
#[derive(Debug, Clone)]
pub struct HttpTslSource {
    url: String,
}

impl HttpTslSource {
    /// Build a source for an explicit URL.
    pub fn new(url: impl Into<String>) -> Self {
        Self { url: url.into() }
    }

    /// Build a source from `CHANCELA_TSL_URL`, falling back to [`DEFAULT_PT_TSL_URL`].
    pub fn from_env() -> Self {
        let url = std::env::var(ENV_TSL_URL).unwrap_or_else(|_| DEFAULT_PT_TSL_URL.to_owned());
        Self::new(url)
    }

    /// The URL this source will fetch.
    pub fn url(&self) -> &str {
        &self.url
    }
}

impl TslSource for HttpTslSource {
    fn fetch(&self) -> Result<Vec<u8>, TslError> {
        let bytes = reqwest::blocking::get(&self.url)?
            .error_for_status()?
            .bytes()?;
        Ok(bytes.to_vec())
    }
}

/// Loads Trusted List XML from a local file — used for the bundled test fixture and for pinning a
/// downloaded list on disk.
#[derive(Debug, Clone)]
pub struct FileTslSource {
    path: PathBuf,
}

impl FileTslSource {
    /// Build a source that reads `path`.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl TslSource for FileTslSource {
    fn fetch(&self) -> Result<Vec<u8>, TslError> {
        Ok(std::fs::read(&self.path)?)
    }
}

/// A source backed by in-memory bytes (handy for tests that hold the XML directly).
#[derive(Debug, Clone)]
pub struct BytesTslSource {
    bytes: Vec<u8>,
}

impl BytesTslSource {
    /// Wrap raw XML bytes as a source.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            bytes: bytes.into(),
        }
    }
}

impl TslSource for BytesTslSource {
    fn fetch(&self) -> Result<Vec<u8>, TslError> {
        Ok(self.bytes.clone())
    }
}

/// **Phase-2 stub (SIG-11).** Validate the Trusted List's own XML-DSig signature against the GNS
/// scheme-operator certificate.
///
/// This is intentionally unimplemented: `chancela-tsl` currently parses, resolves status, caches
/// and queries the list, but does **not** verify that the list is authentic. Until this lands, a
/// production deployment MUST obtain the list over an authenticated channel and treat the parsed
/// result as advisory. Always returns [`TslError::SignatureValidationNotImplemented`].
pub fn validate_tsl_signature(_xml: &[u8]) -> Result<(), TslError> {
    Err(TslError::SignatureValidationNotImplemented)
}
