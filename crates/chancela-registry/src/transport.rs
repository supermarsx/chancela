//! Fetching the raw certidão ([`RegistryTransport`] + [`HttpRegistryTransport`]).

use std::time::Duration;

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::code::AccessCode;
use crate::error::RegistryError;

/// Base URL from `CHANCELA_REGISTRY_URL`, else this pinned default consultation endpoint.
///
/// NOTE: the live endpoint/params must be re-verified against a real code (plan t11 risk #2) — the
/// legacy `consultaCertidao.aspx?id=` page may be deprecated in favour of the new Plataforma de
/// Serviços do Registo SPA (which also needs an e-mail + session token). When that is confirmed,
/// the change is localised here + in `parse_certidao`; the API/UI contract is unaffected.
pub const DEFAULT_REGISTRY_URL: &str =
    "https://www2.gov.pt/RegistoOnline/Services/CertidaoPermanente/consultaCertidao.aspx";

/// Env var overriding [`DEFAULT_REGISTRY_URL`].
pub const ENV_REGISTRY_URL: &str = "CHANCELA_REGISTRY_URL";
/// Env var supplying the e-mail the new consultation platform requires.
pub const ENV_REGISTRY_EMAIL: &str = "CHANCELA_REGISTRY_EMAIL";
/// Env var carrying a real access code for the `network-tests` live seam.
pub const ENV_REGISTRY_TEST_CODE: &str = "CHANCELA_REGISTRY_TEST_CODE";

/// A descriptive User-Agent — the consultation is a courtesy over a human-facing page, so we
/// identify ourselves honestly rather than masquerading as a browser (plan t11 §1 "be polite").
const USER_AGENT: &str = concat!(
    "chancela-registry/",
    env!("CARGO_PKG_VERSION"),
    " (+certidao-permanente consultation; contact: chancela)"
);

/// Raw certidão document as fetched (before parsing).
#[derive(Debug, Clone)]
pub struct RegistryDocument {
    /// The certidão HTML.
    pub html: String,
    /// The consultation URL actually hit, with the secret access code stripped where possible.
    pub source_url: String,
    /// RFC 3339 UTC.
    pub retrieved_at: String,
}

/// Consults the registry for an access code and returns the raw certidão document.
pub trait RegistryTransport: Send + Sync {
    /// Consult the registry for `code` (optional `email` for the new platform). Returns the raw
    /// certidão document, or [`RegistryError::Upstream`] on any network/HTTP/empty-body failure.
    fn fetch(
        &self,
        code: &AccessCode,
        email: Option<&str>,
    ) -> Result<RegistryDocument, RegistryError>;
}

/// Live transport over blocking reqwest (mirrors chancela-cmd/tsl/tsa HTTP transports).
#[derive(Debug, Clone)]
pub struct HttpRegistryTransport {
    base_url: String,
    client: reqwest::blocking::Client,
}

impl HttpRegistryTransport {
    /// Build a transport against `base_url` with a 30-second timeout and a descriptive User-Agent.
    pub fn new(base_url: impl Into<String>) -> Result<Self, RegistryError> {
        let client = reqwest::blocking::Client::builder()
            .user_agent(USER_AGENT)
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| RegistryError::Config(e.to_string()))?;
        Ok(Self {
            base_url: base_url.into(),
            client,
        })
    }

    /// Base URL from [`ENV_REGISTRY_URL`], else [`DEFAULT_REGISTRY_URL`].
    pub fn from_env() -> Result<Self, RegistryError> {
        let base_url =
            std::env::var(ENV_REGISTRY_URL).unwrap_or_else(|_| DEFAULT_REGISTRY_URL.to_owned());
        Self::new(base_url)
    }

    /// The configured base URL (never carries a code).
    pub fn base_url(&self) -> &str {
        &self.base_url
    }
}

impl RegistryTransport for HttpRegistryTransport {
    fn fetch(
        &self,
        code: &AccessCode,
        email: Option<&str>,
    ) -> Result<RegistryDocument, RegistryError> {
        // The legacy consultation takes the code as the `id` query parameter. `expose_secret` is
        // used ONLY here, transiently, to build the request URL — the full code never leaves this
        // function (the returned `source_url` is the bare base URL, code stripped).
        let mut params: Vec<(&str, String)> = vec![("id", code.expose_secret())];
        if let Some(email) = email {
            params.push(("email", email.to_owned()));
        }
        let url = reqwest::Url::parse_with_params(&self.base_url, &params)
            .map_err(|e| RegistryError::Config(e.to_string()))?;

        let response = self
            .client
            .get(url)
            .send()
            .map_err(|e| RegistryError::Upstream(e.to_string()))?;

        let status = response.status();
        if !status.is_success() {
            return Err(RegistryError::Upstream(format!(
                "registry returned HTTP {status}"
            )));
        }

        let html = response
            .text()
            .map_err(|e| RegistryError::Upstream(e.to_string()))?;
        if html.trim().is_empty() {
            return Err(RegistryError::Upstream(
                "registry returned an empty body".to_owned(),
            ));
        }

        Ok(RegistryDocument {
            html,
            source_url: self.base_url.clone(),
            retrieved_at: now_rfc3339(),
        })
    }
}

/// Current UTC instant as an RFC 3339 string (mirrors the ledger's timestamp format).
pub(crate) fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default()
}
