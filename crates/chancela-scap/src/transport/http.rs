//! The real SCAP transport over a hardened blocking `reqwest` client, and the
//! [`AuthoritativeGrant`] witness.
//!
//! **This is the ONLY module that can mint an [`AuthoritativeGrant`]** (its field is private to this
//! module), which is what makes [`crate::ScapVerificationStatus::VerifiedByScap`] unreachable from
//! the mock. See the [`super`] module docs.
//!
//! The wire behaviour here is exercised only against a live AMA endpoint (real credentials, never in
//! CI): no test drives it. It is written to fail closed — a missing credential or a non-`Granted`
//! response yields [`super::VerificationDecision::Denied`] / an error, never a fabricated grant.

use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::Deserialize;

use super::{ScapTransport, VerificationDecision};
use crate::config::AmaScapConfig;
use crate::error::ScapError;
use crate::model::{AttributeProvider, CitizenRef, ProfessionalAttribute};

/// Maximum accepted SCAP response body size (1 MiB). SCAP JSON payloads are small; a larger body
/// signals a misbehaving or hostile endpoint and is rejected before the full body is buffered.
const MAX_SCAP_RESPONSE: u64 = 1024 * 1024;

/// A witness that SCAP granted an attribute over the authoritative transport.
///
/// The single field is **private to this module**, so only [`HttpScapTransport`] can construct the
/// value. A sibling transport (the mock) cannot — that is the compile-time guarantee that the mock
/// never yields a verified status. The client reads the authority reference via
/// [`Self::authority_reference`] but can never mint one.
pub struct AuthoritativeGrant {
    authority_reference: String,
}

impl AuthoritativeGrant {
    /// The granting-authority reference SCAP returned (a provider/decision id).
    pub fn authority_reference(&self) -> &str {
        &self.authority_reference
    }
}

/// Real SCAP transport: talks JSON to the AMA SCAP service over a hardened blocking `reqwest`
/// client. Requires credentials (validated at construction).
pub struct HttpScapTransport {
    config: AmaScapConfig,
    client: reqwest::blocking::Client,
}

impl HttpScapTransport {
    /// Build a transport from `config`. Fails closed if the config lacks the credentials the HTTP
    /// transport requires (see [`AmaScapConfig::validate_http_transport`]).
    pub fn new(config: AmaScapConfig) -> Result<Self, ScapError> {
        config.validate_http_transport()?;
        // Hardened client: bounded request lifetime, no redirect following (a redirect could move
        // credential-bearing requests to another host if the endpoint were ever compromised).
        let client = reqwest::blocking::Client::builder()
            .user_agent("chancela-scap")
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| ScapError::Transport(format!("failed to build HTTP client: {e}")))?;
        Ok(HttpScapTransport { config, client })
    }

    fn url_for(&self, path: &str) -> String {
        format!(
            "{}/{}",
            self.config.base_url.trim_end_matches('/'),
            path.trim_start_matches('/')
        )
    }

    /// The `Authorization` header value for the configured credentials.
    ///
    /// Built only when needed and never logged. `validate_http_transport` guarantees credentials
    /// are present, so a missing credential here is an internal invariant violation.
    fn authorization_header(&self) -> Result<String, ScapError> {
        let creds = self.config.credentials.as_ref().ok_or_else(|| {
            ScapError::Config("HTTP transport requires credentials (internal invariant)".to_owned())
        })?;
        let raw = format!("{}:{}", creds.application_id, creds.secret.as_str());
        Ok(format!("Basic {}", STANDARD.encode(raw.as_bytes())))
    }

    fn get_json(&self, path: &str) -> Result<String, ScapError> {
        let resp = self
            .client
            .get(self.url_for(path))
            .header("Accept", "application/json")
            .header("Authorization", self.authorization_header()?)
            .send()
            .map_err(|e| ScapError::Transport(e.to_string()))?;
        Self::read_body(resp)
    }

    fn post_json(&self, path: &str, body: String) -> Result<String, ScapError> {
        let resp = self
            .client
            .post(self.url_for(path))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .header("Authorization", self.authorization_header()?)
            .body(body)
            .send()
            .map_err(|e| ScapError::Transport(e.to_string()))?;
        Self::read_body(resp)
    }

    fn read_body(resp: reqwest::blocking::Response) -> Result<String, ScapError> {
        let status = resp.status();
        if let Some(len) = resp.content_length()
            && len > MAX_SCAP_RESPONSE
        {
            return Err(ScapError::Transport(format!(
                "response too large: {len} bytes exceeds {MAX_SCAP_RESPONSE}"
            )));
        }
        let bytes = resp
            .bytes()
            .map_err(|e| ScapError::Transport(format!("reading response body: {e}")))?;
        if (bytes.len() as u64) > MAX_SCAP_RESPONSE {
            return Err(ScapError::Transport(format!(
                "response too large: {} bytes exceeds {MAX_SCAP_RESPONSE}",
                bytes.len()
            )));
        }
        if !status.is_success() {
            return Err(ScapError::Transport(format!(
                "SCAP endpoint returned HTTP {}",
                status.as_u16()
            )));
        }
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }
}

/// The SCAP verification response shape (JSON). `decision` is `"Granted"` on success.
#[derive(Deserialize)]
struct VerifyResponse {
    decision: String,
    #[serde(default)]
    authority_reference: Option<String>,
}

impl ScapTransport for HttpScapTransport {
    fn list_providers(&self) -> Result<Vec<AttributeProvider>, ScapError> {
        let body = self.get_json("providers")?;
        let mut providers: Vec<AttributeProvider> =
            serde_json::from_str(&body).map_err(|e| ScapError::Transport(e.to_string()))?;
        if let Some(filter) = &self.config.provider_filter
            && !filter.is_empty()
        {
            providers.retain(|p| filter.iter().any(|id| id == &p.id));
        }
        Ok(providers)
    }

    fn fetch_attributes(
        &self,
        citizen: &CitizenRef,
    ) -> Result<Vec<ProfessionalAttribute>, ScapError> {
        let body = serde_json::json!({ "citizen": citizen.identifier }).to_string();
        let resp = self.post_json("attributes", body)?;
        serde_json::from_str(&resp).map_err(|e| ScapError::Transport(e.to_string()))
    }

    fn verify_attribute(
        &self,
        attribute: &ProfessionalAttribute,
        citizen: &CitizenRef,
    ) -> Result<VerificationDecision, ScapError> {
        let body = serde_json::json!({
            "citizen": citizen.identifier,
            "provider_id": attribute.provider_id,
            "attribute": attribute.name,
        })
        .to_string();
        let resp = self.post_json("verify", body)?;
        let parsed: VerifyResponse =
            serde_json::from_str(&resp).map_err(|e| ScapError::Transport(e.to_string()))?;
        // Fail closed: only an explicit "Granted" mints the authoritative witness.
        if parsed.decision == "Granted" {
            let authority_reference = parsed
                .authority_reference
                .unwrap_or_else(|| attribute.provider_id.clone());
            Ok(VerificationDecision::Granted(AuthoritativeGrant {
                authority_reference,
            }))
        } else {
            Ok(VerificationDecision::Denied)
        }
    }
}
