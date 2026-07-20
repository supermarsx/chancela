//! The [`CscTransport`] boundary and the real [`HttpCscTransport`] over `reqwest`.
//!
//! Putting the wire behind a trait makes the whole CSC v2 flow mock-testable offline (see
//! [`crate::mock::MockCscTransport`]). Only the real HTTP path touches the network, and it is
//! exercised solely by `network-tests` + `#[ignore]` integration tests (never CI).

use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use crate::error::CscError;
use crate::rest::Authorization;

/// Maximum accepted CSC response body size (1 MiB). CSC JSON responses are small (certificates +
/// short status payloads); a larger body signals a misbehaving or hostile endpoint and is
/// rejected before the full body is buffered.
pub(crate) const MAX_CSC_RESPONSE: u64 = 1024 * 1024;

/// A synchronous JSON transport for a CSC v2 endpoint.
///
/// `path` is the CSC operation path (e.g. [`crate::rest::PATH_SIGNATURES_SIGN_HASH`]); `auth`
/// selects the `Authorization` header (Basic for the token call, Bearer otherwise); `body` is the
/// complete JSON request. The returned string is the raw JSON response body, which the client
/// layer parses.
///
/// Implementors MUST NOT log `body` (it may carry the client secret, PIN, OTP, or SAD).
pub trait CscTransport {
    /// POST `body` (JSON) to `path` under `auth`, returning the response body.
    fn post_json(
        &self,
        path: &str,
        auth: Authorization<'_>,
        body: &str,
    ) -> Result<String, CscError>;
}

/// Real CSC transport: POSTs JSON over a hardened blocking `reqwest` client.
pub struct HttpCscTransport {
    base_url: String,
    client: reqwest::blocking::Client,
}

impl HttpCscTransport {
    /// Build a transport pointed at `base_url` (the provider's CSC v2 API base).
    pub fn new(base_url: impl Into<String>) -> Result<Self, CscError> {
        // Hardened client: bounded request lifetime, no redirect following. A CSC endpoint is a
        // fixed operator-configured base; following a redirect would silently move the
        // secret/OTP/SAD-bearing body to another host if the endpoint were ever compromised.
        let client = reqwest::blocking::Client::builder()
            .user_agent("chancela-csc")
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| CscError::Transport(format!("failed to build HTTP client: {e}")))?;
        Ok(HttpCscTransport {
            base_url: base_url.into(),
            client,
        })
    }

    /// Join the base URL and a CSC operation path with exactly one `/`.
    fn url_for(&self, path: &str) -> String {
        format!(
            "{}/{}",
            self.base_url.trim_end_matches('/'),
            path.trim_start_matches('/')
        )
    }
}

impl CscTransport for HttpCscTransport {
    fn post_json(
        &self,
        path: &str,
        auth: Authorization<'_>,
        body: &str,
    ) -> Result<String, CscError> {
        let mut req = self
            .client
            .post(self.url_for(path))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .body(body.to_owned());
        req = match auth {
            Authorization::None => req,
            Authorization::Basic {
                client_id,
                client_secret,
            } => {
                // RFC 6749 §2.3.1 client_secret_basic: base64(client_id:client_secret).
                let raw = format!("{client_id}:{client_secret}");
                let encoded = STANDARD.encode(raw.as_bytes());
                req.header("Authorization", format!("Basic {encoded}"))
            }
            Authorization::Bearer(token) => req.header("Authorization", format!("Bearer {token}")),
        };
        let resp = req.send().map_err(|e| CscError::Transport(e.to_string()))?;
        let status = resp.status();
        // Reject oversized bodies before buffering.
        if let Some(len) = resp.content_length()
            && len > MAX_CSC_RESPONSE
        {
            return Err(CscError::ResponseTooLarge {
                content_length: len,
                limit: MAX_CSC_RESPONSE,
            });
        }
        let bytes = resp
            .bytes()
            .map_err(|e| CscError::Transport(format!("reading response body: {e}")))?;
        if (bytes.len() as u64) > MAX_CSC_RESPONSE {
            return Err(CscError::ResponseTooLarge {
                content_length: bytes.len() as u64,
                limit: MAX_CSC_RESPONSE,
            });
        }
        let text = String::from_utf8_lossy(&bytes).into_owned();
        // A CSC error is delivered as a non-2xx status with a `{ "error", "error_description" }`
        // body; pass the body through so the client layer can surface the structured error. A
        // bare non-2xx with no parseable error body becomes `CscError::HttpStatus`.
        if !status.is_success() && text.trim().is_empty() {
            return Err(CscError::HttpStatus {
                status: status.as_u16(),
            });
        }
        Ok(text)
    }
}
