//! The DRE fetch-behind-trait ([`DreSource`]) that E1b / a future refresh program against to pull
//! a [`LawCorpus`] update, plus file/in-memory/HTTP implementations. Mirrors `chancela_cae`'s
//! `CaeSource` (the name differs to avoid colliding with the per-article [`LawSource`] data
//! struct: this is the *transport*, that is the *provenance*).
//!
//! There is no single machine-readable law feed — E1b vendors per diploma from the Diário da
//! República Eletrónico (see `data/source/PROVENANCE.md`) — so the offline embedded corpus is the
//! default and the network source is opt-in behind the `network` feature.

use std::path::PathBuf;

use crate::dataset::LawCorpus;
use crate::error::LawError;

/// Environment variable naming a corpus-update URL for [`HttpDreSource::from_env`].
pub const ENV_LAW_URL: &str = "CHANCELA_LAW_URL";

/// A source of a [`LawCorpus`] update. Production code and tests both program against this trait.
pub trait DreSource: Send + Sync {
    /// Fetch and parse a corpus. Network/read failures are [`LawError::Http`]; malformed bytes are
    /// [`LawError::Parse`]. Integrity + authenticity are checked later by
    /// [`LawCatalog::from_corpus`](crate::LawCatalog::from_corpus).
    fn fetch(&self) -> Result<LawCorpus, LawError>;
}

/// Reads a corpus from a local file (a vendored batch or a test fixture).
#[derive(Debug, Clone)]
pub struct FileLawSource {
    path: PathBuf,
}

impl FileLawSource {
    /// Build a source that reads `path`.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl DreSource for FileLawSource {
    fn fetch(&self) -> Result<LawCorpus, LawError> {
        let bytes = std::fs::read(&self.path)
            .map_err(|e| LawError::Http(format!("read {}: {e}", self.path.display())))?;
        LawCorpus::from_slice(&bytes)
    }
}

/// A source backed by in-memory bytes (handy for tests that hold the JSON directly).
#[derive(Debug, Clone)]
pub struct BytesLawSource {
    bytes: Vec<u8>,
}

impl BytesLawSource {
    /// Wrap raw corpus JSON bytes as a source.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            bytes: bytes.into(),
        }
    }
}

impl DreSource for BytesLawSource {
    fn fetch(&self) -> Result<LawCorpus, LawError> {
        LawCorpus::from_slice(&self.bytes)
    }
}

/// Fetches a corpus update over HTTP from a configurable URL (opt-in `network` feature). The
/// blocking client is built and dropped inside [`fetch`](HttpDreSource::fetch); run it off any
/// tokio runtime (a dedicated `std::thread`) to avoid the "drop a runtime in an async context"
/// panic, exactly like `chancela-cae`'s `HttpCaeSource`.
#[cfg(feature = "network")]
#[derive(Debug, Clone)]
pub struct HttpDreSource {
    url: String,
    user_agent: String,
}

#[cfg(feature = "network")]
impl HttpDreSource {
    /// Maximum response body size (50 MB) accepted from an HTTP fetch (DOS guard).
    pub const MAX_RESPONSE_BYTES: u64 = 50 * 1024 * 1024;

    /// Build a source for an explicit URL.
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            user_agent: concat!("chancela-law/", env!("CARGO_PKG_VERSION")).to_owned(),
        }
    }

    /// Build a source from [`CHANCELA_LAW_URL`](ENV_LAW_URL). Errors [`LawError::Config`] if unset.
    pub fn from_env() -> Result<Self, LawError> {
        let url = std::env::var(ENV_LAW_URL)
            .map_err(|_| LawError::Config(format!("{ENV_LAW_URL} is not set")))?;
        if url.trim().is_empty() {
            return Err(LawError::Config(format!("{ENV_LAW_URL} is empty")));
        }
        Ok(Self::new(url))
    }

    /// The URL this source will fetch.
    pub fn url(&self) -> &str {
        &self.url
    }
}

#[cfg(feature = "network")]
impl DreSource for HttpDreSource {
    fn fetch(&self) -> Result<LawCorpus, LawError> {
        use std::io::Read as _;
        let client = reqwest::blocking::Client::builder()
            .user_agent(&self.user_agent)
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| LawError::Config(e.to_string()))?;
        let response = client
            .get(&self.url)
            .send()
            .map_err(|e| LawError::Http(e.to_string()))?
            .error_for_status()
            .map_err(|e| LawError::Http(e.to_string()))?;
        let mut bytes = Vec::new();
        response
            .take(Self::MAX_RESPONSE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| LawError::Http(e.to_string()))?;
        if bytes.len() as u64 > Self::MAX_RESPONSE_BYTES {
            return Err(LawError::Http(format!(
                "response exceeded size limit of {} bytes",
                Self::MAX_RESPONSE_BYTES
            )));
        }
        LawCorpus::from_slice(&bytes)
    }
}
