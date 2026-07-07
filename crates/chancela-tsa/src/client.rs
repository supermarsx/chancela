//! The [`TsaClient`] — ties a transport, request, and qualified-policy hook into one call.

use crate::error::TsaError;
use crate::request::TimestampRequest;
use crate::transport::TsaTransport;
use crate::verify::{QualifiedTimestampPolicy, Timestamp, verify_response};

/// An RFC 3161 timestamp client over a pluggable [`TsaTransport`] (spec 04, SIG-22).
///
/// ```no_run
/// use chancela_tsa::{HttpTsaTransport, TsaClient};
///
/// // `digest` is the SHA-256 of the content you want timestamped.
/// let digest: [u8; 32] = [0u8; 32];
/// let client = TsaClient::new(HttpTsaTransport::from_env()?);
/// let timestamp = client.timestamp(digest)?;
/// # Ok::<(), chancela_tsa::TsaError>(())
/// ```
#[derive(Debug, Clone)]
pub struct TsaClient<T: TsaTransport> {
    transport: T,
    policy: QualifiedTimestampPolicy,
}

impl<T: TsaTransport> TsaClient<T> {
    /// A client that accepts any TSA policy (qualified-status enforcement delegated to the trust
    /// layer). Use [`with_policy`](Self::with_policy) to require a specific qualified policy OID.
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            policy: QualifiedTimestampPolicy::Any,
        }
    }

    /// Set the qualified-timestamp policy hook (SIG-22).
    pub fn with_policy(mut self, policy: QualifiedTimestampPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// The configured qualified-timestamp policy hook.
    pub fn policy(&self) -> &QualifiedTimestampPolicy {
        &self.policy
    }

    /// The underlying transport.
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Timestamp a precomputed SHA-256 `digest`, asking the TSA to embed its certificate and
    /// including a generated nonce. For an explicit nonce or policy, build a [`TimestampRequest`]
    /// and call [`stamp`](Self::stamp).
    pub fn timestamp(&self, digest: [u8; 32]) -> Result<Timestamp, TsaError> {
        self.stamp(&TimestampRequest::new(digest).with_generated_nonce())
    }

    /// Timestamp using an explicit [`TimestampRequest`]: encode it, send it over the transport, and
    /// verify the response against the request and the configured policy hook.
    pub fn stamp(&self, request: &TimestampRequest) -> Result<Timestamp, TsaError> {
        let der_req = request.to_der()?;
        let der_resp = self.transport.send(&der_req)?;
        verify_response(&der_resp, request, &self.policy)
    }
}
