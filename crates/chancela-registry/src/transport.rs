//! Fetching the raw certidão ([`RegistryTransport`] + [`HttpRegistryTransport`]).

use std::time::Duration;

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::code::AccessCode;
use crate::error::RegistryError;

/// Base URL from `CHANCELA_REGISTRY_URL`, else this pinned default consultation endpoint.
///
/// VERIFIED against a real access code: `consultaCertidao.aspx?id=<code>` is **live**, returns the
/// certidão as HTML on 200, and answers an unknown code with 200 + "Não existe qualquer certidão
/// com esse número" (so a bad code is *not* an HTTP error — see [`crate::parse_certidao`], which
/// classifies that page as [`RegistryError::CertidaoNotFound`]). No `email` parameter and no
/// session token were needed. The layout it returns is captured, anonymised, as
/// `fixtures/live_spq_certidao.html`.
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
    /// certidão document, or a transport-level failure: [`RegistryError::Unreachable`] when no
    /// answer arrived, [`RegistryError::CredentialsRejected`] on 401/403,
    /// [`RegistryError::QuotaExceeded`] on 429, else [`RegistryError::Upstream`].
    ///
    /// A **rejected access code is not a transport failure** — the consultation page reports it on
    /// 200, so it is classified by [`crate::parse_certidao`], not here.
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

        // A send() failure means we never got an answer at all — DNS, connect, TLS or timeout.
        // This is `Unreachable`, never `Upstream`: the caller must be able to say "we could not
        // reach the registry" without implying anything about whether the certidão exists.
        //
        // `describe_transport_error` — NOT `e.to_string()` — see its doc: the URL we just built
        // carries the full access code, and an error's Display may quote the URL it failed on.
        let response = self
            .client
            .get(url)
            .send()
            .map_err(|e| RegistryError::Unreachable(describe_transport_error(&e)))?;

        let status = response.status();
        if !status.is_success() {
            // Classify the statuses that mean something specific to an operator. Note that a bad
            // *access code* does NOT arrive here — the consultation page reports that on 200, in
            // the body (see `parse_certidao`) — so nothing in this branch is ever the code's fault.
            return Err(match status.as_u16() {
                401 | 403 => RegistryError::CredentialsRejected(format!(
                    "registry returned HTTP {status}; the consultation service refused this \
                     installation's credentials"
                )),
                429 => RegistryError::QuotaExceeded(format!(
                    "registry returned HTTP {status}; the consultation rate limit or quota is \
                     exhausted"
                )),
                _ => RegistryError::Upstream(format!("registry returned HTTP {status}")),
            });
        }

        let html = response
            .text()
            .map_err(|e| RegistryError::Unreachable(describe_transport_error(&e)))?;
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

/// Describe a transport failure **without ever quoting the underlying error's own text**.
///
/// This is a secrecy guard, not a formatting preference (LEG-22 / GDPR). The consultation URL is
/// built as `…/consultaCertidao.aspx?id=<FULL ACCESS CODE>`, and an HTTP client's error `Display`
/// may quote the URL it was working on. Passing `e.to_string()` outwards would therefore put the
/// código de acesso — a bearer credential granting full access to the registry record — into an
/// error message that is written to the server log and, for coded variants, returned to the client.
///
/// Whether a given client version happens to include the URL in `Display` is not something this
/// code should depend on: the classification below is derived only from reqwest's boolean kind
/// predicates, so **no upstream string reaches the message at all** and the leak is structurally
/// impossible rather than merely absent today.
///
/// The kinds are also more useful than the raw text: a timeout and a refused connection call for
/// different operator responses.
fn describe_transport_error(e: &reqwest::Error) -> String {
    if e.is_timeout() {
        "the registry did not respond before the 30-second timeout".to_owned()
    } else if e.is_connect() {
        "could not open a connection to the registry (DNS, network or TLS)".to_owned()
    } else if e.is_redirect() {
        "the registry's redirect chain could not be followed".to_owned()
    } else if e.is_body() || e.is_decode() {
        "the registry's response body could not be read or decoded".to_owned()
    } else {
        "the request to the registry failed before a usable response arrived".to_owned()
    }
}

/// Current UTC instant as an RFC 3339 string (mirrors the ledger's timestamp format).
pub(crate) fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default()
}
