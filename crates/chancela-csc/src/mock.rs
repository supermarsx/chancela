//! [`MockCscTransport`] — canned JSON responses so the full CSC v2
//! token → list → info → sendOTP → authorize → signHash round-trip is unit-tested offline (no
//! network). Also records the requests it received (path + auth kind + body) so tests can assert
//! the flow wired the credential id, hash, OTP, etc. correctly.
//!
//! Static fixtures cover the responses with no per-test crypto (token, list, sendOTP, authorize,
//! errors). The certificate-bearing `credentials/info` and the signature-bearing
//! `signatures/signHash` responses are built per-test with [`credentials_info_response`] /
//! [`sign_hash_response`] from an ephemeral in-test key — mirroring `chancela-cmd`'s mock.

use std::cell::RefCell;
use std::collections::HashMap;

use crate::error::CscError;
use crate::rest::{
    self, Authorization, PATH_CREDENTIALS_AUTHORIZE, PATH_CREDENTIALS_LIST,
    PATH_CREDENTIALS_SEND_OTP, PATH_OAUTH2_TOKEN,
};
use crate::transport::CscTransport;

/// Canned `oauth2/token` success (a bearer access token).
pub const OAUTH_TOKEN_OK: &str = include_str!("../fixtures/oauth_token.json");
/// Canned `credentials/list` success (one credential id).
pub const CREDENTIALS_LIST_OK: &str = include_str!("../fixtures/credentials_list.json");
/// Canned `credentials/sendOTP` success (empty body).
pub const SEND_OTP_OK: &str = include_str!("../fixtures/send_otp.json");
/// Canned `credentials/authorize` success (a SAD).
pub const AUTHORIZE_OK: &str = include_str!("../fixtures/authorize.json");
/// Canned CSC error body — `invalid_otp` (a rejected OTP at `credentials/authorize`).
pub const ERROR_INVALID_OTP: &str = include_str!("../fixtures/error_invalid_otp.json");
/// Canned CSC error body — `invalid_request`.
pub const ERROR_INVALID_REQUEST: &str = include_str!("../fixtures/error_invalid_request.json");

/// Build a `credentials/info` response from a base64-DER certificate chain (leaf first) and the
/// signing key's algorithm OIDs.
pub fn credentials_info_response(certs_b64: &[String], key_algo_oids: &[&str]) -> String {
    let certs = certs_b64
        .iter()
        .map(|c| format!("\"{c}\""))
        .collect::<Vec<_>>()
        .join(",");
    let algos = key_algo_oids
        .iter()
        .map(|o| format!("\"{o}\""))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        r#"{{
  "key": {{ "status": "enabled", "algo": [{algos}] }},
  "cert": {{ "status": "valid", "certificates": [{certs}] }},
  "authMode": "explicit",
  "SCAL": "2",
  "PIN": {{ "presence": "false" }},
  "OTP": {{ "presence": "true", "type": "offline" }}
}}"#
    )
}

/// Build a `signatures/signHash` response from a single base64 signature value.
pub fn sign_hash_response(signature_b64: &str) -> String {
    format!(r#"{{ "signatures": ["{signature_b64}"] }}"#)
}

/// A request the mock received, for post-hoc assertions. Records the auth **kind** (never the
/// secret) and the JSON body.
#[derive(Debug, Clone)]
pub struct RecordedCall {
    /// The CSC operation path.
    pub path: String,
    /// The authorization kind used (`"none"` | `"basic"` | `"bearer"`) — never the secret value.
    pub auth_kind: &'static str,
    /// The full JSON request body the flow sent.
    pub body: String,
}

/// An offline [`CscTransport`] returning per-path canned JSON responses.
#[derive(Default)]
pub struct MockCscTransport {
    responses: HashMap<String, String>,
    recorded: RefCell<Vec<RecordedCall>>,
}

impl MockCscTransport {
    /// An empty mock (no canned responses); add them with [`Self::with_response`].
    pub fn empty() -> Self {
        Self::default()
    }

    /// A happy-path mock: all six operations succeed. `info_json` / `sign_hash_json` are the
    /// per-test certificate/signature responses (see [`credentials_info_response`] /
    /// [`sign_hash_response`]).
    pub fn happy_path(info_json: impl Into<String>, sign_hash_json: impl Into<String>) -> Self {
        Self::empty()
            .with_response(PATH_OAUTH2_TOKEN, OAUTH_TOKEN_OK)
            .with_response(PATH_CREDENTIALS_LIST, CREDENTIALS_LIST_OK)
            .with_response(rest::PATH_CREDENTIALS_INFO, info_json)
            .with_response(PATH_CREDENTIALS_SEND_OTP, SEND_OTP_OK)
            .with_response(PATH_CREDENTIALS_AUTHORIZE, AUTHORIZE_OK)
            .with_response(rest::PATH_SIGNATURES_SIGN_HASH, sign_hash_json)
    }

    /// Set (or override) the canned response for a CSC operation path.
    pub fn with_response(mut self, path: &str, json: impl Into<String>) -> Self {
        self.responses.insert(path.to_string(), json.into());
        self
    }

    /// All calls the mock received, in order.
    pub fn calls(&self) -> Vec<RecordedCall> {
        self.recorded.borrow().clone()
    }

    /// The most recent request body sent for `path`, if any.
    pub fn last_body_for(&self, path: &str) -> Option<String> {
        self.recorded
            .borrow()
            .iter()
            .rev()
            .find(|c| c.path == path)
            .map(|c| c.body.clone())
    }
}

impl CscTransport for MockCscTransport {
    fn post_json(
        &self,
        path: &str,
        auth: Authorization<'_>,
        body: &str,
    ) -> Result<String, CscError> {
        let auth_kind = match auth {
            Authorization::None => "none",
            Authorization::Basic { .. } => "basic",
            Authorization::Bearer(_) => "bearer",
        };
        self.recorded.borrow_mut().push(RecordedCall {
            path: path.to_string(),
            auth_kind,
            body: body.to_string(),
        });
        self.responses.get(path).cloned().ok_or_else(|| {
            CscError::Transport(format!(
                "MockCscTransport has no response for path '{path}'"
            ))
        })
    }
}
