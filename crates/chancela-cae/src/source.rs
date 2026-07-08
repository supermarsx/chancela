//! Fetch-behind-trait sources (§2.3): HTTP (configurable `CHANCELA_CAE_URL`), file, and in-memory.
//!
//! There is no official machine-readable CAE feed, so the default remote is an ops decision: the
//! mechanism is fully built and tested against a fixture URL/file, and a real remote is supplied
//! via `CHANCELA_CAE_URL` (an honest boundary, mirroring `chancela-registry`'s live path).

use std::io::Read;
use std::path::PathBuf;
use std::time::Duration;

use crate::dataset::CaeDataset;
use crate::error::CaeError;

/// Maximum response body size (50 MB) accepted from any HTTP fetch. Prevents memory-exhaustion
/// (DOS-01) via a malicious server streaming gigabytes of data.
pub(crate) const MAX_RESPONSE_BYTES: u64 = 50 * 1024 * 1024;

/// Read an HTTP response body with a hard size cap. Checks `Content-Length` first (rejecting
/// oversized responses before allocating), then bounds the stream read at `MAX_RESPONSE_BYTES + 1`
/// so an overshoot is detected without unbounded memory allocation (defense-in-depth for servers
/// that omit or lie about `Content-Length`).
pub(crate) fn read_bounded(response: reqwest::blocking::Response) -> Result<Vec<u8>, CaeError> {
    if let Some(len) = response.content_length() {
        if len > MAX_RESPONSE_BYTES {
            return Err(CaeError::Http(format!(
                "response exceeds size limit: {len} bytes (max {MAX_RESPONSE_BYTES})"
            )));
        }
    }
    let mut bytes = Vec::new();
    response
        .take(MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| CaeError::Http(e.to_string()))?;
    if bytes.len() as u64 > MAX_RESPONSE_BYTES {
        return Err(CaeError::Http(format!(
            "response exceeded size limit of {MAX_RESPONSE_BYTES} bytes"
        )));
    }
    Ok(bytes)
}

/// Environment variable naming the dataset URL for [`HttpCaeSource::from_env`].
pub const ENV_CAE_URL: &str = "CHANCELA_CAE_URL";

/// A source of a [`CaeDataset`]. Production code and tests both program against this trait.
pub trait CaeSource: Send + Sync {
    /// Fetch and parse a dataset. Network/read failures are [`CaeError::Http`]; malformed bytes are
    /// [`CaeError::Parse`]. Integrity is checked later by [`CaeCatalog::from_dataset`](crate::CaeCatalog::from_dataset).
    fn fetch(&self) -> Result<CaeDataset, CaeError>;
}

/// Fetches a dataset over HTTP from a configurable URL with a blocking `reqwest` client.
///
/// The blocking client is built and dropped inside [`fetch`](HttpCaeSource::fetch) so it never
/// outlives the call; run `fetch` off any tokio runtime (a dedicated `std::thread`, as
/// [`spawn_background_refresh`](crate::spawn_background_refresh) does) to avoid the
/// "drop a runtime in an async context" panic.
#[derive(Debug, Clone)]
pub struct HttpCaeSource {
    url: String,
    user_agent: String,
}

impl HttpCaeSource {
    /// Build a source for an explicit URL.
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            user_agent: default_user_agent(),
        }
    }

    /// Build a source from [`CHANCELA_CAE_URL`](ENV_CAE_URL). Errors [`CaeError::Config`] if unset
    /// (there is no default remote — the feed is an ops decision).
    pub fn from_env() -> Result<Self, CaeError> {
        let url = std::env::var(ENV_CAE_URL).map_err(|_| {
            CaeError::Config(format!(
                "{ENV_CAE_URL} is not set (no default CAE dataset URL)"
            ))
        })?;
        if url.trim().is_empty() {
            return Err(CaeError::Config(format!("{ENV_CAE_URL} is empty")));
        }
        Ok(Self::new(url))
    }

    /// The URL this source will fetch.
    pub fn url(&self) -> &str {
        &self.url
    }
}

impl CaeSource for HttpCaeSource {
    fn fetch(&self) -> Result<CaeDataset, CaeError> {
        let client = reqwest::blocking::Client::builder()
            .user_agent(&self.user_agent)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| CaeError::Config(e.to_string()))?;
        let response = client
            .get(&self.url)
            .send()
            .map_err(|e| CaeError::Http(e.to_string()))?
            .error_for_status()
            .map_err(|e| CaeError::Http(e.to_string()))?;
        let bytes = read_bounded(response)?;
        CaeDataset::from_slice(&bytes)
    }
}

/// Reads a dataset from a local file (a pinned download or a test fixture).
#[derive(Debug, Clone)]
pub struct FileCaeSource {
    path: PathBuf,
}

impl FileCaeSource {
    /// Build a source that reads `path`.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl CaeSource for FileCaeSource {
    fn fetch(&self) -> Result<CaeDataset, CaeError> {
        let bytes = std::fs::read(&self.path)
            .map_err(|e| CaeError::Http(format!("read {}: {e}", self.path.display())))?;
        CaeDataset::from_slice(&bytes)
    }
}

/// A source backed by in-memory bytes (handy for tests that hold the JSON directly).
#[derive(Debug, Clone)]
pub struct BytesCaeSource {
    bytes: Vec<u8>,
}

impl BytesCaeSource {
    /// Wrap raw dataset JSON bytes as a source.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            bytes: bytes.into(),
        }
    }
}

impl CaeSource for BytesCaeSource {
    fn fetch(&self) -> Result<CaeDataset, CaeError> {
        CaeDataset::from_slice(&self.bytes)
    }
}

fn default_user_agent() -> String {
    concat!("chancela-cae/", env!("CARGO_PKG_VERSION")).to_string()
}
