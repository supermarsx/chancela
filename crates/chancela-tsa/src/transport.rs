//! The [`TsaTransport`] trait and a blocking `reqwest` implementation.

use std::time::Duration;

use crate::error::TsaError;

/// Environment variable holding the RFC 3161 TSA endpoint (spec 04, §2.3).
pub const TSA_URL_ENV: &str = "CHANCELA_TSA_URL";

/// Default RFC 3161 timestamping authority when [`TSA_URL_ENV`] is unset: AMA's Cartão de Cidadão
/// qualified timestamp service (Entidade de Validação Cronológica do CC), the Portuguese state's
/// free public endpoint.
///
/// Mirror of `chancela_api::settings::DEFAULT_PT_TSA_URL` (kept in sync by hand rather than
/// depending on the whole api crate for one string). Notes:
/// - **Plain `http://` is correct here and MUST NOT be "upgraded" to https.** RFC 3161 tokens are
///   cryptographically signed, so integrity does not rely on TLS; there is no https listener and
///   switching the scheme would break it.
/// - **Rate-limited: ~20 requests / 20-minute window; exceeding it blocks the caller for 24h.**
///   This matters only for live use, which is feature-gated and operator-initiated (the client
///   never contacts the TSA at rest). A test endpoint exists at `http://ts.teste.cartaodecidadao.pt/`;
///   we deliberately do not default to it.
pub const DEFAULT_PT_TSA_URL: &str = "http://ts.cartaodecidadao.pt/tsa/server";

/// Abstracts the transport that POSTs a DER `TimeStampReq` and returns the DER `TimeStampResp`.
///
/// RFC 3161 over HTTP is a plain synchronous request/response, so this trait is deliberately
/// blocking — the real client uses `reqwest::blocking`, and tests use
/// [`MockTsaTransport`](crate::mock::MockTsaTransport). Implementors are expected to be `Send +
/// Sync` so a [`TsaClient`](crate::client::TsaClient) can be shared.
pub trait TsaTransport {
    /// POST `der_req` (media type `application/timestamp-query`) and return the raw response body
    /// (media type `application/timestamp-reply`).
    fn send(&self, der_req: &[u8]) -> Result<Vec<u8>, TsaError>;
}

/// A blocking `reqwest`-backed transport that POSTs to an RFC 3161 HTTP TSA endpoint.
#[derive(Debug, Clone)]
pub struct HttpTsaTransport {
    url: String,
    client: reqwest::blocking::Client,
}

impl HttpTsaTransport {
    /// Build a transport for the TSA at `url` with a 30-second timeout.
    pub fn new(url: impl Into<String>) -> Result<Self, TsaError> {
        Self::with_timeout(url, Duration::from_secs(30))
    }

    /// Build a transport for the TSA at `url` with an explicit request timeout.
    pub fn with_timeout(url: impl Into<String>, timeout: Duration) -> Result<Self, TsaError> {
        let client = reqwest::blocking::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| TsaError::Transport(e.to_string()))?;
        Ok(Self {
            url: url.into(),
            client,
        })
    }

    /// Build a transport from the [`TSA_URL_ENV`] environment variable, falling back to the official
    /// Portuguese default ([`DEFAULT_PT_TSA_URL`]) when the variable is unset or blank.
    ///
    /// A pre-filled default does not change runtime behaviour: nothing here contacts the TSA — the
    /// caller must explicitly issue a timestamp request. The fallback simply means a fresh install
    /// is pre-wired to AMA's free state TSA instead of failing to build a transport. Set
    /// `CHANCELA_TSA_URL` to point at a different endpoint (e.g. the test TSA).
    pub fn from_env() -> Result<Self, TsaError> {
        Self::new(env_url_or_default(std::env::var(TSA_URL_ENV).ok()))
    }

    /// The configured endpoint URL.
    pub fn url(&self) -> &str {
        &self.url
    }
}

/// Resolve the TSA URL from a configured [`TSA_URL_ENV`] value: a present, non-blank value (trimmed)
/// wins; an absent or blank value falls back to [`DEFAULT_PT_TSA_URL`]. Kept as a pure function so
/// the fallback is unit-testable without mutating process-global environment state.
fn env_url_or_default(configured: Option<String>) -> String {
    configured
        .map(|u| u.trim().to_owned())
        .filter(|u| !u.is_empty())
        .unwrap_or_else(|| DEFAULT_PT_TSA_URL.to_owned())
}

impl TsaTransport for HttpTsaTransport {
    fn send(&self, der_req: &[u8]) -> Result<Vec<u8>, TsaError> {
        let response = self
            .client
            .post(&self.url)
            .header(reqwest::header::CONTENT_TYPE, "application/timestamp-query")
            .header(reqwest::header::ACCEPT, "application/timestamp-reply")
            .body(der_req.to_vec())
            .send()
            .map_err(|e| TsaError::Transport(e.to_string()))?;

        let status = response.status();
        if !status.is_success() {
            return Err(TsaError::Transport(format!("TSA returned HTTP {status}")));
        }

        let bytes = response
            .bytes()
            .map_err(|e| TsaError::Transport(e.to_string()))?;
        Ok(bytes.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::{DEFAULT_PT_TSA_URL, HttpTsaTransport, env_url_or_default};

    #[test]
    fn env_value_wins_and_is_trimmed() {
        assert_eq!(
            env_url_or_default(Some("  http://ts.teste.cartaodecidadao.pt/  ".to_owned())),
            "http://ts.teste.cartaodecidadao.pt/"
        );
    }

    #[test]
    fn falls_back_to_default_when_unset_or_blank() {
        assert_eq!(env_url_or_default(None), DEFAULT_PT_TSA_URL);
        assert_eq!(
            env_url_or_default(Some("   ".to_owned())),
            DEFAULT_PT_TSA_URL
        );
        assert_eq!(env_url_or_default(Some(String::new())), DEFAULT_PT_TSA_URL);
    }

    #[test]
    fn default_is_the_official_ama_endpoint_over_plain_http() {
        // Guards the do-not-https invariant: the AMA CC TSA has no https listener.
        assert_eq!(
            DEFAULT_PT_TSA_URL,
            "http://ts.cartaodecidadao.pt/tsa/server"
        );
        assert!(DEFAULT_PT_TSA_URL.starts_with("http://"));
    }

    #[test]
    fn from_env_builds_a_transport_regardless_of_env() {
        // Whatever the ambient CHANCELA_TSA_URL is (set or not), from_env now resolves a URL and
        // builds a transport rather than erroring on an unset variable.
        let transport = HttpTsaTransport::from_env().expect("from_env falls back to a default URL");
        assert!(transport.url().starts_with("http"));
    }
}
