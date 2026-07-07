//! [`MockScmdTransport`] — canned SOAP responses so the full request -> OTP -> retrieve
//! round-trip is unit-tested offline (no network). Also records the requests it received
//! so tests can assert the flow wired the `ProcessId`, encrypted fields, etc. correctly.

use std::cell::RefCell;
use std::collections::HashMap;

use crate::error::CmdError;
use crate::soap::{ACTION_CCMOVEL_SIGN, ACTION_GET_CERTIFICATE, ACTION_VALIDATE_OTP};
use crate::transport::ScmdTransport;

/// Canned `GetCertificate` success (leaf + issuer PEM chain).
pub const GET_CERTIFICATE_OK: &str = include_str!("../fixtures/get_certificate_response.xml");
/// Canned `CCMovelSign` success (`Code` 200 + `ProcessId`).
pub const CCMOVEL_SIGN_OK: &str = include_str!("../fixtures/ccmovelsign_response.xml");
/// Canned `ValidateOtp` success (base64 signature + `Status.Code` 200).
pub const VALIDATE_OTP_OK: &str = include_str!("../fixtures/validateotp_response.xml");
/// Canned `CCMovelSign` failure (`Code` 401, invalid PIN).
pub const CCMOVEL_SIGN_ERROR: &str = include_str!("../fixtures/ccmovelsign_error.xml");
/// Canned `ValidateOtp` rejection (`Status.Code` 402, invalid OTP).
pub const VALIDATE_OTP_REJECTED: &str = include_str!("../fixtures/validateotp_rejected.xml");
/// A SOAP `Fault` (invalid ApplicationId).
pub const SOAP_FAULT: &str = include_str!("../fixtures/soap_fault.xml");

/// A request the mock received, for post-hoc assertions.
#[derive(Debug, Clone)]
pub struct RecordedCall {
    /// The SOAPAction the flow used.
    pub action: String,
    /// The full request envelope the flow sent.
    pub envelope: String,
}

/// An offline [`ScmdTransport`] returning per-action canned responses.
#[derive(Default)]
pub struct MockScmdTransport {
    responses: HashMap<String, String>,
    recorded: RefCell<Vec<RecordedCall>>,
}

impl MockScmdTransport {
    /// An empty mock (no canned responses); add them with [`Self::with_response`].
    pub fn empty() -> Self {
        Self::default()
    }

    /// A mock where all three operations succeed — the happy-path round trip.
    pub fn preprod_success() -> Self {
        Self::empty()
            .with_response(ACTION_GET_CERTIFICATE, GET_CERTIFICATE_OK)
            .with_response(ACTION_CCMOVEL_SIGN, CCMOVEL_SIGN_OK)
            .with_response(ACTION_VALIDATE_OTP, VALIDATE_OTP_OK)
    }

    /// Success mock, but `CCMovelSign` fails with an invalid-PIN status.
    pub fn ccmovel_sign_error() -> Self {
        Self::preprod_success().with_response(ACTION_CCMOVEL_SIGN, CCMOVEL_SIGN_ERROR)
    }

    /// Success mock, but `ValidateOtp` rejects the OTP.
    pub fn otp_rejected() -> Self {
        Self::preprod_success().with_response(ACTION_VALIDATE_OTP, VALIDATE_OTP_REJECTED)
    }

    /// Set (or override) the canned response for a SOAPAction.
    pub fn with_response(mut self, action: &str, xml: impl Into<String>) -> Self {
        self.responses.insert(action.to_string(), xml.into());
        self
    }

    /// All calls the mock received, in order.
    pub fn calls(&self) -> Vec<RecordedCall> {
        self.recorded.borrow().clone()
    }

    /// The most recent request envelope sent for `action`, if any.
    pub fn last_envelope_for(&self, action: &str) -> Option<String> {
        self.recorded
            .borrow()
            .iter()
            .rev()
            .find(|c| c.action == action)
            .map(|c| c.envelope.clone())
    }
}

impl ScmdTransport for MockScmdTransport {
    fn call(&self, action: &str, soap_body: &str) -> Result<String, CmdError> {
        self.recorded.borrow_mut().push(RecordedCall {
            action: action.to_string(),
            envelope: soap_body.to_string(),
        });
        self.responses.get(action).cloned().ok_or_else(|| {
            CmdError::Transport(format!(
                "MockScmdTransport has no response for action '{action}'"
            ))
        })
    }
}
