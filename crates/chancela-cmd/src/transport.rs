//! The [`ScmdTransport`] boundary and the real [`HttpScmdTransport`] over `reqwest`.
//!
//! Putting the wire behind a trait makes the whole SIG-02 flow mock-testable offline
//! (see [`crate::mock::MockScmdTransport`]). Only the real HTTP path touches the network,
//! and it is exercised solely by `network-tests` + `#[ignore]` integration tests.

use crate::error::CmdError;

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
        let client = reqwest::blocking::Client::builder()
            .user_agent("chancela-cmd")
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
        let text = resp
            .text()
            .map_err(|e| CmdError::Transport(format!("reading response body: {e}")))?;
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
