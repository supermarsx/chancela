//! The [`ScmdTransport`] boundary and the real [`HttpScmdTransport`] over `reqwest`.
//!
//! Putting the wire behind a trait makes the whole SIG-02 flow mock-testable offline
//! (see [`crate::mock::MockScmdTransport`]). Only the real HTTP path touches the network,
//! and it is exercised solely by `network-tests` + `#[ignore]` integration tests.

use std::time::Duration;

use crate::error::CmdError;

/// Maximum accepted SCMD response body size (1 MiB). CMD SOAP responses are small
/// (certificates + status payloads); a larger body signals a misbehaving or hostile
/// endpoint. Enforced against both `Content-Length` and the buffered bytes (t41-e4 H4).
pub(crate) const MAX_CMD_RESPONSE: u64 = 1024 * 1024;

/// A synchronous SOAP transport for the SCMD service.
///
/// `action` is the SOAPAction URI; `soap_body` is the **complete** SOAP 1.1 envelope XML
/// (built by [`crate::soap`]). The returned string is the raw SOAP response XML, which the
/// flow layer parses. Faults (HTTP 500 with a `<Fault>` body) are returned as the response
/// string for the flow to interpret; connection/TLS/timeout failures surface as
/// [`CmdError::Transport`].
pub trait ScmdTransport {
    /// POST `soap_body` under SOAPAction `action`, returning the response envelope XML.
    fn call(&self, action: &str, soap_body: &str) -> Result<String, CmdError>;
}

/// Real SCMD transport: POSTs hand-built SOAP 1.1 over a blocking `reqwest` client.
pub struct HttpScmdTransport {
    endpoint: String,
    client: reqwest::blocking::Client,
}

impl HttpScmdTransport {
    /// Build a transport pointed at `endpoint` (e.g. [`crate::config::PREPROD_ENDPOINT`]).
    pub fn new(endpoint: impl Into<String>) -> Result<Self, CmdError> {
        // Hardened client (t41-e4): bounded request lifetime (H2), no redirect following
        // (M5). SCMD is a single fixed SOAP endpoint; redirects are never legitimate, and
        // following one would silently move the PIN/OTP-bearing body to an attacker-
        // controlled host if the endpoint were ever misconfigured or compromised.
        let client = reqwest::blocking::Client::builder()
            .user_agent("chancela-cmd")
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| CmdError::Transport(format!("failed to build HTTP client: {e}")))?;
        Ok(HttpScmdTransport {
            endpoint: endpoint.into(),
            client,
        })
    }

    /// Build a transport for the endpoint implied by `cfg`.
    pub fn from_config(cfg: &crate::config::CmdConfig) -> Result<Self, CmdError> {
        Self::new(cfg.endpoint())
    }
}

impl ScmdTransport for HttpScmdTransport {
    fn call(&self, action: &str, soap_body: &str) -> Result<String, CmdError> {
        // WCF requires a non-empty, quoted SOAPAction matching the operation.
        let soap_action = format!("\"{action}\"");
        let resp = self
            .client
            .post(&self.endpoint)
            .header("Content-Type", "text/xml; charset=utf-8")
            .header("SOAPAction", soap_action)
            .body(soap_body.to_owned())
            .send()
            .map_err(|e| CmdError::Transport(e.to_string()))?;
        let status = resp.status();
        // Reject oversized bodies before buffering (t41-e4 H4). A declared Content-Length
        // over the limit is a fast-fail; an absent/chunked Content-Length is caught after
        // the read by capping the buffered bytes.
        if let Some(len) = resp.content_length() {
            if len > MAX_CMD_RESPONSE {
                return Err(CmdError::ResponseTooLarge {
                    content_length: len,
                    limit: MAX_CMD_RESPONSE,
                });
            }
        }
        let bytes = resp
            .bytes()
            .map_err(|e| CmdError::Transport(format!("reading response body: {e}")))?;
        if (bytes.len() as u64) > MAX_CMD_RESPONSE {
            return Err(CmdError::ResponseTooLarge {
                content_length: bytes.len() as u64,
                limit: MAX_CMD_RESPONSE,
            });
        }
        let text = String::from_utf8_lossy(&bytes).into_owned();
        // WCF SOAP faults come back as HTTP 500 with a <Fault> body — pass those through so
        // the flow layer can extract the fault message. Only bare error statuses fail here.
        if !status.is_success() && !text.contains("Fault") {
            return Err(CmdError::Transport(format!(
                "HTTP {status} from SCMD endpoint"
            )));
        }
        Ok(text)
    }
}
