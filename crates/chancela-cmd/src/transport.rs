//! The [`ScmdTransport`] boundary and the real [`HttpScmdTransport`] over `reqwest`.
//!
//! Putting the wire behind a trait makes the whole SIG-02 flow mock-testable offline
//! (see [`crate::mock::MockScmdTransport`]). Only the real HTTP path touches the network,
//! and it is exercised solely by `network-tests` + `#[ignore]` integration tests.
//!
//! The SCMD `AppSCMDService.svc` service is JSON/REST: each operation is a sibling path segment
//! under the `.svc` endpoint, so the transport POSTs `body` (a JSON string) to
//! `{endpoint}/{operation}` with `Content-Type: application/json`. There is no SOAPAction header.

use std::time::Duration;

use crate::error::CmdError;

/// Maximum accepted SCMD response body size (1 MiB). CMD SOAP responses are small
/// (certificates + status payloads); a larger body signals a misbehaving or hostile
/// endpoint. Enforced against both `Content-Length` and the buffered bytes (t41-e4 H4).
pub(crate) const MAX_CMD_RESPONSE: u64 = 1024 * 1024;

/// A synchronous JSON transport for the SCMD service.
///
/// `action` is the operation name / path segment (`GetCertificate`, `SCMDSign`, `ValidateOtp` —
/// the `OP_*` constants in [`crate::wire`]); `body` is the JSON request string (built by
/// [`crate::wire`]). The returned string is the raw JSON response body, which the flow layer
/// parses. A non-2xx HTTP status surfaces as [`CmdError::Transport`]; connection/TLS/timeout
/// failures do too.
pub trait ScmdTransport {
    /// POST `body` to the `action` operation, returning the raw JSON response body.
    fn call(&self, action: &str, body: &str) -> Result<String, CmdError>;
}

/// Real SCMD transport: POSTs JSON over a blocking `reqwest` client.
pub struct HttpScmdTransport {
    endpoint: String,
    basic_auth: Option<crate::config::CmdBasicAuth>,
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
            basic_auth: None,
            client,
        })
    }

    /// Build a transport pointed at `endpoint` with HTTP BasicAuth credentials.
    pub fn with_basic_auth(
        endpoint: impl Into<String>,
        basic_auth: crate::config::CmdBasicAuth,
    ) -> Result<Self, CmdError> {
        let mut transport = Self::new(endpoint)?;
        transport.basic_auth = Some(basic_auth);
        Ok(transport)
    }

    /// Build a transport for the endpoint implied by `cfg`.
    pub fn from_config(cfg: &crate::config::CmdConfig) -> Result<Self, CmdError> {
        cfg.validate_http_transport()?;
        match cfg.basic_auth.clone() {
            Some(basic_auth) => Self::with_basic_auth(cfg.endpoint(), basic_auth),
            None => Self::new(cfg.endpoint()),
        }
    }
}

impl ScmdTransport for HttpScmdTransport {
    fn call(&self, action: &str, body: &str) -> Result<String, CmdError> {
        // Each operation is a sibling path under the `.svc` endpoint (e.g. `.../AppSCMDService.svc/
        // SCMDSign`). No SOAPAction header: the service is JSON/REST.
        let url = format!("{}/{}", self.endpoint.trim_end_matches('/'), action);
        let mut req = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .body(body.to_owned());
        if let Some(auth) = &self.basic_auth {
            req = req.basic_auth(&auth.username, Some(auth.password.as_str()));
        }
        let resp = req.send().map_err(|e| CmdError::Transport(e.to_string()))?;
        let status = resp.status();
        // Reject oversized bodies before buffering (t41-e4 H4). A declared Content-Length
        // over the limit is a fast-fail; an absent/chunked Content-Length is caught after
        // the read by capping the buffered bytes.
        if let Some(len) = resp.content_length()
            && len > MAX_CMD_RESPONSE
        {
            return Err(CmdError::ResponseTooLarge {
                content_length: len,
                limit: MAX_CMD_RESPONSE,
            });
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
        // The JSON service reports business errors as a status `Code` inside a 2xx body (parsed by
        // the flow layer). A non-2xx HTTP status is a hard transport failure — there is no fault
        // body to interpret, matching the working reference (recov-pt `src/cli/cmd_verify.rs`).
        if !status.is_success() {
            return Err(CmdError::Transport(format!(
                "HTTP {status} from SCMD endpoint"
            )));
        }
        Ok(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CmdBasicAuth, CmdConfig, CmdEnv};
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;

    #[test]
    fn posts_json_to_the_operation_path_with_basic_auth() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!(
            "http://{}/Ama.Authentication.Frontend/AppSCMDService.svc",
            listener.local_addr().unwrap()
        );
        let (tx, rx) = mpsc::channel();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0_u8; 4096];
            let mut request = Vec::new();
            loop {
                let n = stream.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&buf[..n]);
                if request.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            tx.send(String::from_utf8_lossy(&request).into_owned())
                .unwrap();
            let body = r#"{"d":"ok"}"#;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        });

        let transport = HttpScmdTransport::with_basic_auth(
            endpoint,
            CmdBasicAuth::new("ama-user", "ama-password"),
        )
        .unwrap();
        let response = transport
            .call("SCMDSign", r#"{"ApplicationId":"a"}"#)
            .unwrap();
        assert_eq!(response, r#"{"d":"ok"}"#);
        let request = rx.recv().unwrap();
        server.join().unwrap();

        // POSTed to the per-operation path segment, as JSON, with no SOAPAction header.
        assert!(
            request.starts_with("POST /Ama.Authentication.Frontend/AppSCMDService.svc/SCMDSign "),
            "request line was not the operation path: {request}"
        );
        let request_lower = request.to_ascii_lowercase();
        assert!(request_lower.contains("content-type: application/json"));
        assert!(!request_lower.contains("soapaction"));
        assert!(request_lower.contains("authorization: basic yw1hlxvzzxi6yw1hlxbhc3n3b3jk"));
    }

    #[test]
    fn from_config_rejects_prod_without_basic_auth() {
        let cfg = CmdConfig {
            env: CmdEnv::Prod,
            application_id: "APPID".to_string(),
            basic_auth: None,
            ama_cert_pem: Some(include_str!("../fixtures/ama_encryption_cert.pem").to_string()),
        };

        match HttpScmdTransport::from_config(&cfg) {
            Err(CmdError::Config(msg)) => assert!(msg.contains("PROD HTTP transport requires")),
            Err(other) => panic!("expected config error, got {other:?}"),
            Ok(_) => panic!("expected config error"),
        }
    }
}
