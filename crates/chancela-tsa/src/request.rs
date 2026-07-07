//! RFC 3161 `TimeStampReq` construction over a SHA-256 message imprint (spec 04, SIG-22).

use der::{
    Encode,
    asn1::{Any, Int, OctetString},
    oid::ObjectIdentifier,
};
use sha2::{Digest, Sha256};
use x509_cert::spki::AlgorithmIdentifierOwned;
use x509_tsp::{MessageImprint, TimeStampReq, TspVersion};

use crate::error::TsaError;
use crate::oid;

/// A request for a qualified timestamp over a SHA-256 digest.
///
/// Built fluently, then DER-encoded with [`to_der`](Self::to_der) into the
/// `application/timestamp-query` body. The same `TimestampRequest` is handed to
/// [`verify_response`](crate::verify::verify_response) so the digest and nonce we asked for can be
/// checked against the returned token.
#[derive(Clone, Debug)]
pub struct TimestampRequest {
    digest: [u8; 32],
    nonce: Option<u64>,
    cert_req: bool,
    req_policy: Option<ObjectIdentifier>,
}

impl TimestampRequest {
    /// A request over a precomputed SHA-256 `digest`.
    ///
    /// Defaults: `certReq = true` (ask the TSA to embed its signing certificate so the token is
    /// self-contained), no nonce, no requested policy.
    pub fn new(digest: [u8; 32]) -> Self {
        Self {
            digest,
            nonce: None,
            cert_req: true,
            req_policy: None,
        }
    }

    /// A request over the SHA-256 digest of `data`.
    pub fn over_data(data: &[u8]) -> Self {
        Self::new(Sha256::digest(data).into())
    }

    /// The digest to be timestamped.
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// The nonce this request carries, if any.
    pub fn nonce(&self) -> Option<u64> {
        self.nonce
    }

    /// Whether the TSA is asked to embed its signing certificate (`certReq`).
    pub fn cert_req(&self) -> bool {
        self.cert_req
    }

    /// Set an explicit nonce for RFC 3161 replay protection. Callers SHOULD supply a
    /// cryptographically random value.
    pub fn with_nonce(mut self, nonce: u64) -> Self {
        self.nonce = Some(nonce);
        self
    }

    /// Derive a best-effort nonce by hashing the current time with the digest.
    ///
    /// This is **not** a CSPRNG: it exists only so the crate carries no `rand` dependency. For
    /// high-assurance replay protection, generate a random value and pass it to
    /// [`with_nonce`](Self::with_nonce).
    pub fn with_generated_nonce(mut self) -> Self {
        let now = time::OffsetDateTime::now_utc().unix_timestamp_nanos();
        let mut hasher = Sha256::new();
        hasher.update(now.to_le_bytes());
        hasher.update(self.digest);
        let mut b = [0u8; 8];
        b.copy_from_slice(&hasher.finalize()[..8]);
        // Keep the high bit clear so the DER INTEGER is positive and needs no 0x00 padding.
        b[0] = (b[0] & 0x7f) | 0x01;
        self.nonce = Some(u64::from_be_bytes(b));
        self
    }

    /// Do not ask the TSA to embed its certificate (`certReq = false`).
    pub fn without_certificate(mut self) -> Self {
        self.cert_req = false;
        self
    }

    /// Request a specific TSA policy OID (`reqPolicy`).
    pub fn with_policy(mut self, policy: ObjectIdentifier) -> Self {
        self.req_policy = Some(policy);
        self
    }

    /// DER-encode the `TimeStampReq` (the `application/timestamp-query` body).
    pub fn to_der(&self) -> Result<Vec<u8>, TsaError> {
        self.to_asn1()?.to_der().map_err(TsaError::EncodeRequest)
    }

    fn to_asn1(&self) -> Result<TimeStampReq, TsaError> {
        let hash_algorithm = AlgorithmIdentifierOwned {
            oid: oid::ID_SHA256,
            // RFC 5754: SHA-2 identifiers SHOULD omit parameters, but OpenSSL/most TSAs emit an
            // explicit NULL. Match the common wire form for maximum interoperability.
            parameters: Some(Any::null()),
        };
        let hashed_message =
            OctetString::new(self.digest.as_slice()).map_err(TsaError::EncodeRequest)?;
        let nonce = match self.nonce {
            Some(v) => Some(u64_to_int(v)?),
            None => None,
        };
        Ok(TimeStampReq {
            version: TspVersion::V1,
            message_imprint: MessageImprint {
                hash_algorithm,
                hashed_message,
            },
            req_policy: self.req_policy,
            nonce,
            cert_req: self.cert_req,
            extensions: None,
        })
    }
}

/// Encode a `u64` as the body of a positive DER `INTEGER`.
pub(crate) fn u64_to_int(v: u64) -> Result<Int, TsaError> {
    let be = v.to_be_bytes();
    // Minimal big-endian encoding: drop leading zero bytes, but keep at least one.
    let start = be.iter().position(|&b| b != 0).unwrap_or(be.len() - 1);
    let mut bytes = be[start..].to_vec();
    // A leading byte with the high bit set would be read as negative; prepend 0x00 to stay positive.
    if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0x00);
    }
    Int::new(&bytes).map_err(TsaError::EncodeRequest)
}
