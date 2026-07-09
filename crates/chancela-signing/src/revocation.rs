//! Validated CRL/OCSP revocation evidence collection for PAdES DSS attachment.
//!
//! This module extracts URI CDP/AIA metadata from the signer certificate, fetches CRLs through a
//! bounded/mocked transport, fetches OCSP responses with unsigned RFC 6960 requests, and only
//! returns DSS evidence after validating issuer/responder trust, freshness, status, and signatures.

use std::io::Read;
use std::time::Duration;

use der::asn1::{Null, ObjectIdentifier, OctetString};
use der::referenced::OwnedToRef;
use der::{Decode, Encode};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use spki::AlgorithmIdentifierOwned;
use time::OffsetDateTime;
use x509_cert::certificate::Certificate;
use x509_cert::crl::CertificateList;
use x509_cert::ext::pkix::AuthorityInfoAccessSyntax;
use x509_cert::ext::pkix::crl::CrlDistributionPoints;
use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName, GeneralNames};
use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage};
use x509_cert::time::Time;
use x509_ocsp::{
    BasicOcspResponse, CertId, CertStatus, OcspRequest, OcspResponse, OcspResponseStatus,
    Request as OcspSingleRequest, ResponderId, TbsRequest,
};

use crate::DssEvidence;

const OID_CRL_DISTRIBUTION_POINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.31");
const OID_AUTHORITY_INFO_ACCESS: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.1");
const OID_OCSP: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1");
const OID_OCSP_BASIC: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.1");
const OID_OCSP_SIGNING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.9");
const OID_SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
const OID_SHA256_WITH_RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const OID_ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const OID_BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
const OID_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");
const OID_EXTENDED_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");

/// Network limits used by the default HTTP transport and enforced by the provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationFetchLimits {
    /// Maximum number of CRL distribution-point URLs attempted from one signer certificate.
    pub max_crl_urls: usize,
    /// Maximum number of OCSP AIA URLs attempted from one signer certificate.
    pub max_ocsp_urls: usize,
    /// Maximum response body size accepted for one CRL.
    pub max_response_bytes: usize,
    /// Per-request timeout for the default blocking HTTP transport.
    pub timeout: Duration,
}

impl Default for RevocationFetchLimits {
    fn default() -> Self {
        Self {
            max_crl_urls: 4,
            max_ocsp_urls: 4,
            max_response_bytes: 1024 * 1024,
            timeout: Duration::from_secs(10),
        }
    }
}

/// URI metadata discovered in a signer certificate.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DiscoveredRevocationUris {
    /// HTTP(S) CRL distribution-point URLs.
    pub crl_urls: Vec<String>,
    /// HTTP(S) AIA OCSP responder URLs.
    pub ocsp_urls: Vec<String>,
}

/// Source and freshness metadata for one validated CRL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationSource {
    /// The CRL URL that supplied the accepted bytes.
    pub url: String,
    /// The CRL `thisUpdate` value.
    pub this_update: OffsetDateTime,
    /// The CRL `nextUpdate` value, when present.
    pub next_update: Option<OffsetDateTime>,
    /// SHA-256 of the accepted DER CRL.
    pub sha256: [u8; 32],
}

/// Source and freshness metadata for one validated OCSP response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OcspRevocationSource {
    /// The OCSP responder URL that supplied the accepted bytes.
    pub url: String,
    /// `producedAt` from the BasicOCSPResponse `tbsResponseData`.
    pub produced_at: OffsetDateTime,
    /// Matching SingleResponse `thisUpdate`.
    pub this_update: OffsetDateTime,
    /// Matching SingleResponse `nextUpdate`.
    pub next_update: OffsetDateTime,
    /// SHA-256 of the accepted DER OCSPResponse.
    pub sha256: [u8; 32],
    /// Whether the BasicOCSPResponse was signed directly by the issuer certificate.
    pub direct_responder: bool,
}

/// Validated revocation evidence ready for PAdES DSS insertion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationEvidence {
    /// DSS payload. `ocsp_responses` is always empty until OCSP validation is fully implemented.
    pub dss: DssEvidence,
    /// Validation time used for CRL freshness checks and PAdES `/TU` metadata.
    pub validation_time: OffsetDateTime,
    /// URI metadata discovered on the signer certificate.
    pub discovered: DiscoveredRevocationUris,
    /// Accepted CRL source records.
    pub sources: Vec<RevocationSource>,
    /// Accepted OCSP source records.
    pub ocsp_sources: Vec<OcspRevocationSource>,
}

/// Minimal HTTP response used by mock and real revocation transports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationHttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response body bytes.
    pub body: Vec<u8>,
}

/// Mockable transport for CRL fetching.
pub trait RevocationHttpTransport {
    /// Fetch `url`, respecting `limits`.
    fn get_crl(
        &self,
        url: &str,
        limits: &RevocationFetchLimits,
    ) -> Result<RevocationHttpResponse, RevocationError>;

    /// POST an unsigned OCSP request DER to `url`, respecting `limits`.
    fn post_ocsp(
        &self,
        url: &str,
        request_der: &[u8],
        limits: &RevocationFetchLimits,
    ) -> Result<RevocationHttpResponse, RevocationError>;
}

/// Blocking HTTP transport with timeout and response-size checks.
#[derive(Debug, Clone, Default)]
pub struct BoundedHttpRevocationTransport;

impl RevocationHttpTransport for BoundedHttpRevocationTransport {
    fn get_crl(
        &self,
        url: &str,
        limits: &RevocationFetchLimits,
    ) -> Result<RevocationHttpResponse, RevocationError> {
        let client = reqwest::blocking::Client::builder()
            .timeout(limits.timeout)
            .redirect(reqwest::redirect::Policy::limited(3))
            .build()
            .map_err(|e| RevocationError::Http(e.to_string()))?;
        let mut response = client
            .get(url)
            .send()
            .map_err(|e| RevocationError::Http(e.to_string()))?;
        let status = response.status().as_u16();
        if let Some(len) = response.content_length() {
            if len > limits.max_response_bytes as u64 {
                return Err(RevocationError::HttpLimitExceeded {
                    url: url.to_string(),
                    limit: limits.max_response_bytes,
                });
            }
        }

        let mut body = Vec::new();
        response
            .by_ref()
            .take(limits.max_response_bytes as u64 + 1)
            .read_to_end(&mut body)
            .map_err(|e| RevocationError::Http(e.to_string()))?;
        if body.len() > limits.max_response_bytes {
            return Err(RevocationError::HttpLimitExceeded {
                url: url.to_string(),
                limit: limits.max_response_bytes,
            });
        }

        Ok(RevocationHttpResponse { status, body })
    }

    fn post_ocsp(
        &self,
        url: &str,
        request_der: &[u8],
        limits: &RevocationFetchLimits,
    ) -> Result<RevocationHttpResponse, RevocationError> {
        let client = reqwest::blocking::Client::builder()
            .timeout(limits.timeout)
            .redirect(reqwest::redirect::Policy::limited(3))
            .build()
            .map_err(|e| RevocationError::Http(e.to_string()))?;
        let mut response = client
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/ocsp-request")
            .header(reqwest::header::ACCEPT, "application/ocsp-response")
            .body(request_der.to_vec())
            .send()
            .map_err(|e| RevocationError::Http(e.to_string()))?;
        let status = response.status().as_u16();
        if let Some(len) = response.content_length() {
            if len > limits.max_response_bytes as u64 {
                return Err(RevocationError::HttpLimitExceeded {
                    url: url.to_string(),
                    limit: limits.max_response_bytes,
                });
            }
        }

        let mut body = Vec::new();
        response
            .by_ref()
            .take(limits.max_response_bytes as u64 + 1)
            .read_to_end(&mut body)
            .map_err(|e| RevocationError::Http(e.to_string()))?;
        if body.len() > limits.max_response_bytes {
            return Err(RevocationError::HttpLimitExceeded {
                url: url.to_string(),
                limit: limits.max_response_bytes,
            });
        }

        Ok(RevocationHttpResponse { status, body })
    }
}

/// CRL evidence collection and validation errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RevocationError {
    /// The signer or issuer certificate could not be decoded.
    #[error("invalid {kind} certificate DER")]
    InvalidCertificate {
        /// `signer` or `issuer`.
        kind: &'static str,
    },
    /// The signer certificate has no URI CRL distribution point.
    #[error("signer certificate has no HTTP(S) CRL distribution point")]
    NoCrlDistributionPoint,
    /// The signer certificate has neither HTTP(S) OCSP AIA nor CRL distribution point.
    #[error("signer certificate has no HTTP(S) revocation endpoint")]
    NoRevocationEndpoint,
    /// The signer certificate has no URI OCSP AIA endpoint.
    #[error("signer certificate has no HTTP(S) OCSP responder URL")]
    NoOcspResponder,
    /// The requested CRL URL is not HTTP(S).
    #[error("unsupported CRL URL scheme: {0}")]
    UnsupportedCrlUrl(String),
    /// More CRL URLs were available than the configured bound allows.
    #[error("CRL URL limit exceeded: discovered {discovered}, limit {limit}")]
    CrlUrlLimitExceeded {
        /// Number of discovered CRL URLs.
        discovered: usize,
        /// Configured maximum.
        limit: usize,
    },
    /// More OCSP URLs were available than the configured bound allows.
    #[error("OCSP URL limit exceeded: discovered {discovered}, limit {limit}")]
    OcspUrlLimitExceeded {
        /// Number of discovered OCSP URLs.
        discovered: usize,
        /// Configured maximum.
        limit: usize,
    },
    /// The HTTP transport failed.
    #[error("CRL HTTP fetch failed: {0}")]
    Http(String),
    /// The HTTP transport returned a non-success status.
    #[error("CRL HTTP fetch returned status {status} for {url}")]
    HttpStatus {
        /// CRL URL.
        url: String,
        /// HTTP status code.
        status: u16,
    },
    /// The HTTP response body exceeded the configured bound.
    #[error("CRL response exceeded {limit} bytes for {url}")]
    HttpLimitExceeded {
        /// CRL URL.
        url: String,
        /// Configured maximum response size.
        limit: usize,
    },
    /// The CRL DER could not be decoded.
    #[error("invalid CRL DER from {url}")]
    InvalidCrl {
        /// CRL URL.
        url: String,
    },
    /// The OCSP request could not be encoded.
    #[error("OCSP request encoding failed")]
    OcspRequestEncoding,
    /// The OCSP response DER could not be decoded.
    #[error("invalid OCSP response DER from {url}")]
    InvalidOcsp {
        /// OCSP responder URL.
        url: String,
    },
    /// The OCSP responder returned a non-success protocol status.
    #[error("OCSP responder returned {status:?} for {url}")]
    OcspStatus {
        /// OCSP responder URL.
        url: String,
        /// OCSP protocol status.
        status: OcspResponseStatus,
    },
    /// The OCSP response was not BasicOCSPResponse.
    #[error("OCSP response is not BasicOCSPResponse for {url}")]
    UnsupportedOcspResponseType {
        /// OCSP responder URL.
        url: String,
    },
    /// The OCSP response did not contain a SingleResponse for the requested certificate.
    #[error("OCSP response CertID mismatch for {url}")]
    OcspCertIdMismatch {
        /// OCSP responder URL.
        url: String,
    },
    /// The OCSP response says the signer certificate is revoked.
    #[error("signer certificate is revoked according to OCSP responder {url}")]
    OcspSignerRevoked {
        /// OCSP responder URL.
        url: String,
    },
    /// The OCSP response says the signer certificate status is unknown.
    #[error("signer certificate status is unknown according to OCSP responder {url}")]
    OcspSignerUnknown {
        /// OCSP responder URL.
        url: String,
    },
    /// The OCSP response freshness fields are not acceptable at validation time.
    #[error("OCSP response freshness check failed for {url}: {reason}")]
    OcspFreshness {
        /// OCSP responder URL.
        url: String,
        /// Stable reason for diagnostics.
        reason: &'static str,
    },
    /// The OCSP responder identity could not be trusted under the supplied issuer certificate.
    #[error("OCSP responder is not trusted under issuer for {url}")]
    OcspResponderUntrusted {
        /// OCSP responder URL.
        url: String,
    },
    /// The OCSP responder signature algorithm is unsupported by this slice.
    #[error("unsupported OCSP responder signature algorithm: {oid}")]
    UnsupportedOcspSignatureAlgorithm {
        /// Signature algorithm OID.
        oid: ObjectIdentifier,
    },
    /// The OCSP responder signature failed validation.
    #[error("OCSP responder signature verification failed for {url}")]
    OcspSignatureInvalid {
        /// OCSP responder URL.
        url: String,
    },
    /// The CRL was not issued by the supplied issuer certificate.
    #[error("CRL issuer mismatch for {url}")]
    CrlIssuerMismatch {
        /// CRL URL.
        url: String,
    },
    /// The CRL `thisUpdate` is in the future at validation time.
    #[error("CRL is not yet valid for {url}")]
    CrlNotYetValid {
        /// CRL URL.
        url: String,
    },
    /// The CRL is stale at validation time.
    #[error("CRL is stale for {url}")]
    StaleCrl {
        /// CRL URL.
        url: String,
    },
    /// The signer's serial number appears in the CRL.
    #[error("signer certificate is revoked according to {url}")]
    SignerRevoked {
        /// CRL URL.
        url: String,
    },
    /// The CRL signature algorithm is unsupported by this slice.
    #[error("unsupported CRL signature algorithm: {oid}")]
    UnsupportedCrlSignatureAlgorithm {
        /// Signature algorithm OID.
        oid: ObjectIdentifier,
    },
    /// The CRL signature failed validation.
    #[error("CRL signature verification failed for {url}")]
    CrlSignatureInvalid {
        /// CRL URL.
        url: String,
    },
}

/// Validated CRL revocation evidence provider.
#[derive(Debug, Clone)]
pub struct RevocationEvidenceProvider<T = BoundedHttpRevocationTransport> {
    transport: T,
    limits: RevocationFetchLimits,
}

type ValidatedOcspFetch = (Vec<u8>, Vec<Vec<u8>>, OcspRevocationSource);

impl RevocationEvidenceProvider<BoundedHttpRevocationTransport> {
    /// Create a provider using the default bounded blocking HTTP transport.
    pub fn http() -> Self {
        Self::new(
            BoundedHttpRevocationTransport,
            RevocationFetchLimits::default(),
        )
    }
}

impl<T> RevocationEvidenceProvider<T> {
    /// Create a provider with caller-supplied transport and limits.
    pub fn new(transport: T, limits: RevocationFetchLimits) -> Self {
        Self { transport, limits }
    }

    /// Current fetch limits.
    pub fn limits(&self) -> &RevocationFetchLimits {
        &self.limits
    }
}

impl<T: RevocationHttpTransport> RevocationEvidenceProvider<T> {
    /// Collect validated CRL evidence for `signer_cert_der`, using `issuer_cert_der` to validate
    /// the CRL issuer and signature.
    pub fn collect_for_signer(
        &self,
        signer_cert_der: &[u8],
        issuer_cert_der: &[u8],
        validation_time: OffsetDateTime,
    ) -> Result<RevocationEvidence, RevocationError> {
        let signer = Certificate::from_der(signer_cert_der)
            .map_err(|_| RevocationError::InvalidCertificate { kind: "signer" })?;
        let issuer = Certificate::from_der(issuer_cert_der)
            .map_err(|_| RevocationError::InvalidCertificate { kind: "issuer" })?;
        let discovered = discover_revocation_uris(&signer);

        if discovered.ocsp_urls.is_empty() && discovered.crl_urls.is_empty() {
            return Err(RevocationError::NoRevocationEndpoint);
        }
        if discovered.ocsp_urls.len() > self.limits.max_ocsp_urls {
            return Err(RevocationError::OcspUrlLimitExceeded {
                discovered: discovered.ocsp_urls.len(),
                limit: self.limits.max_ocsp_urls,
            });
        }
        if discovered.crl_urls.len() > self.limits.max_crl_urls {
            return Err(RevocationError::CrlUrlLimitExceeded {
                discovered: discovered.crl_urls.len(),
                limit: self.limits.max_crl_urls,
            });
        }

        let mut last_error = None;
        for url in &discovered.ocsp_urls {
            match self.fetch_and_validate_ocsp(url, &signer, &issuer, validation_time) {
                Ok((ocsp_der, responder_certs, source)) => {
                    let mut certificates = vec![signer_cert_der.to_vec(), issuer_cert_der.to_vec()];
                    certificates.extend(responder_certs);
                    certificates.sort();
                    certificates.dedup();
                    return Ok(RevocationEvidence {
                        dss: DssEvidence {
                            certificates,
                            ocsp_responses: vec![ocsp_der],
                            crls: Vec::new(),
                        },
                        validation_time,
                        discovered,
                        sources: Vec::new(),
                        ocsp_sources: vec![source],
                    });
                }
                Err(RevocationError::OcspSignerRevoked { url }) => {
                    return Err(RevocationError::OcspSignerRevoked { url });
                }
                Err(e) => last_error = Some(e),
            }
        }

        for url in &discovered.crl_urls {
            match self.fetch_and_validate_crl(url, &signer, &issuer, validation_time) {
                Ok((crl_der, source)) => {
                    return Ok(RevocationEvidence {
                        dss: DssEvidence {
                            certificates: vec![signer_cert_der.to_vec(), issuer_cert_der.to_vec()],
                            ocsp_responses: Vec::new(),
                            crls: vec![crl_der],
                        },
                        validation_time,
                        discovered,
                        sources: vec![source],
                        ocsp_sources: Vec::new(),
                    });
                }
                Err(RevocationError::SignerRevoked { url }) => {
                    return Err(RevocationError::SignerRevoked { url });
                }
                Err(e) => last_error = Some(e),
            }
        }

        Err(last_error.unwrap_or(RevocationError::NoRevocationEndpoint))
    }

    fn fetch_and_validate_ocsp(
        &self,
        url: &str,
        signer: &Certificate,
        issuer: &Certificate,
        validation_time: OffsetDateTime,
    ) -> Result<ValidatedOcspFetch, RevocationError> {
        if !is_http_url(url) {
            return Err(RevocationError::UnsupportedCrlUrl(url.to_string()));
        }

        let requested_cert_id = ocsp_cert_id(signer, issuer)?;
        let request_der = ocsp_request_der(requested_cert_id.clone())?;
        let response = self.transport.post_ocsp(url, &request_der, &self.limits)?;
        if !(200..300).contains(&response.status) {
            return Err(RevocationError::HttpStatus {
                url: url.to_string(),
                status: response.status,
            });
        }
        if response.body.len() > self.limits.max_response_bytes {
            return Err(RevocationError::HttpLimitExceeded {
                url: url.to_string(),
                limit: self.limits.max_response_bytes,
            });
        }

        let (responder_certs, source) = validate_ocsp_response(
            url,
            &response.body,
            &requested_cert_id,
            signer,
            issuer,
            validation_time,
        )?;
        Ok((response.body, responder_certs, source))
    }

    fn fetch_and_validate_crl(
        &self,
        url: &str,
        signer: &Certificate,
        issuer: &Certificate,
        validation_time: OffsetDateTime,
    ) -> Result<(Vec<u8>, RevocationSource), RevocationError> {
        if !is_http_url(url) {
            return Err(RevocationError::UnsupportedCrlUrl(url.to_string()));
        }

        let response = self.transport.get_crl(url, &self.limits)?;
        if !(200..300).contains(&response.status) {
            return Err(RevocationError::HttpStatus {
                url: url.to_string(),
                status: response.status,
            });
        }
        if response.body.len() > self.limits.max_response_bytes {
            return Err(RevocationError::HttpLimitExceeded {
                url: url.to_string(),
                limit: self.limits.max_response_bytes,
            });
        }

        let crl =
            CertificateList::from_der(&response.body).map_err(|_| RevocationError::InvalidCrl {
                url: url.to_string(),
            })?;
        validate_crl(url, &crl, &response.body, signer, issuer, validation_time)?;

        let this_update = x509_time_to_offset(crl.tbs_cert_list.this_update);
        let next_update = crl.tbs_cert_list.next_update.map(x509_time_to_offset);
        let sha256 = Sha256::digest(&response.body).into();
        Ok((
            response.body,
            RevocationSource {
                url: url.to_string(),
                this_update,
                next_update,
                sha256,
            },
        ))
    }
}

/// Extract CRL distribution-point and OCSP AIA URIs from a signer certificate.
pub fn discover_revocation_uris(cert: &Certificate) -> DiscoveredRevocationUris {
    let mut discovered = DiscoveredRevocationUris::default();
    let Some(extensions) = &cert.tbs_certificate.extensions else {
        return discovered;
    };

    for ext in extensions {
        if ext.extn_id == OID_CRL_DISTRIBUTION_POINTS {
            if let Ok(cdp) = CrlDistributionPoints::from_der(ext.extn_value.as_bytes()) {
                for dp in cdp.0 {
                    if let Some(DistributionPointName::FullName(names)) = dp.distribution_point {
                        push_http_uris(&mut discovered.crl_urls, &names);
                    }
                }
            }
        } else if ext.extn_id == OID_AUTHORITY_INFO_ACCESS {
            if let Ok(aia) = AuthorityInfoAccessSyntax::from_der(ext.extn_value.as_bytes()) {
                for access in aia.0 {
                    if access.access_method == OID_OCSP {
                        push_http_uri(&mut discovered.ocsp_urls, &access.access_location);
                    }
                }
            }
        }
    }

    discovered.crl_urls.sort();
    discovered.crl_urls.dedup();
    discovered.ocsp_urls.sort();
    discovered.ocsp_urls.dedup();
    discovered
}

fn push_http_uris(out: &mut Vec<String>, names: &GeneralNames) {
    for name in names {
        push_http_uri(out, name);
    }
}

fn push_http_uri(out: &mut Vec<String>, name: &GeneralName) {
    if let GeneralName::UniformResourceIdentifier(uri) = name {
        let uri = uri.as_str();
        if is_http_url(uri) {
            out.push(uri.to_string());
        }
    }
}

fn is_http_url(url: &str) -> bool {
    url.starts_with("http://") || url.starts_with("https://")
}

fn validate_crl(
    url: &str,
    crl: &CertificateList,
    crl_der: &[u8],
    signer: &Certificate,
    issuer: &Certificate,
    validation_time: OffsetDateTime,
) -> Result<(), RevocationError> {
    if crl.tbs_cert_list.issuer != issuer.tbs_certificate.subject {
        return Err(RevocationError::CrlIssuerMismatch {
            url: url.to_string(),
        });
    }

    let this_update = x509_time_to_offset(crl.tbs_cert_list.this_update);
    if validation_time < this_update {
        return Err(RevocationError::CrlNotYetValid {
            url: url.to_string(),
        });
    }
    if let Some(next_update) = crl.tbs_cert_list.next_update.map(x509_time_to_offset) {
        if validation_time > next_update {
            return Err(RevocationError::StaleCrl {
                url: url.to_string(),
            });
        }
    } else {
        return Err(RevocationError::StaleCrl {
            url: url.to_string(),
        });
    }

    if let Some(revoked) = &crl.tbs_cert_list.revoked_certificates {
        let signer_serial = signer.tbs_certificate.serial_number.as_bytes();
        if revoked
            .iter()
            .any(|entry| entry.serial_number.as_bytes() == signer_serial)
        {
            return Err(RevocationError::SignerRevoked {
                url: url.to_string(),
            });
        }
    }

    verify_crl_signature(url, crl, crl_der, issuer)
}

fn ocsp_request_der(cert_id: CertId) -> Result<Vec<u8>, RevocationError> {
    OcspRequest {
        tbs_request: TbsRequest {
            version: x509_ocsp::Version::V1,
            requestor_name: None,
            request_list: vec![OcspSingleRequest {
                req_cert: cert_id,
                single_request_extensions: None,
            }],
            request_extensions: None,
        },
        optional_signature: None,
    }
    .to_der()
    .map_err(|_| RevocationError::OcspRequestEncoding)
}

/// Generate an unsigned OCSP request DER for `signer` under `issuer`.
pub fn unsigned_ocsp_request_der(
    signer_cert_der: &[u8],
    issuer_cert_der: &[u8],
) -> Result<Vec<u8>, RevocationError> {
    let signer = Certificate::from_der(signer_cert_der)
        .map_err(|_| RevocationError::InvalidCertificate { kind: "signer" })?;
    let issuer = Certificate::from_der(issuer_cert_der)
        .map_err(|_| RevocationError::InvalidCertificate { kind: "issuer" })?;
    ocsp_request_der(ocsp_cert_id(&signer, &issuer)?)
}

fn ocsp_cert_id(signer: &Certificate, issuer: &Certificate) -> Result<CertId, RevocationError> {
    Ok(CertId {
        hash_algorithm: AlgorithmIdentifierOwned {
            oid: OID_SHA1,
            parameters: Some(Null.into()),
        },
        issuer_name_hash: OctetString::new(
            Sha1::digest(
                issuer
                    .tbs_certificate
                    .subject
                    .to_der()
                    .map_err(|_| RevocationError::OcspRequestEncoding)?,
            )
            .to_vec(),
        )
        .map_err(|_| RevocationError::OcspRequestEncoding)?,
        issuer_key_hash: OctetString::new(
            Sha1::digest(
                issuer
                    .tbs_certificate
                    .subject_public_key_info
                    .subject_public_key
                    .raw_bytes(),
            )
            .to_vec(),
        )
        .map_err(|_| RevocationError::OcspRequestEncoding)?,
        serial_number: signer.tbs_certificate.serial_number.clone(),
    })
}

fn validate_ocsp_response(
    url: &str,
    ocsp_der: &[u8],
    requested_cert_id: &CertId,
    _signer: &Certificate,
    issuer: &Certificate,
    validation_time: OffsetDateTime,
) -> Result<(Vec<Vec<u8>>, OcspRevocationSource), RevocationError> {
    let ocsp = OcspResponse::from_der(ocsp_der).map_err(|_| RevocationError::InvalidOcsp {
        url: url.to_string(),
    })?;
    if ocsp.response_status != OcspResponseStatus::Successful {
        return Err(RevocationError::OcspStatus {
            url: url.to_string(),
            status: ocsp.response_status,
        });
    }
    let response_bytes = ocsp
        .response_bytes
        .ok_or_else(|| RevocationError::InvalidOcsp {
            url: url.to_string(),
        })?;
    if response_bytes.response_type != OID_OCSP_BASIC {
        return Err(RevocationError::UnsupportedOcspResponseType {
            url: url.to_string(),
        });
    }
    let basic = BasicOcspResponse::from_der(response_bytes.response.as_bytes()).map_err(|_| {
        RevocationError::InvalidOcsp {
            url: url.to_string(),
        }
    })?;

    let single = basic
        .tbs_response_data
        .responses
        .iter()
        .find(|single| single.cert_id == *requested_cert_id)
        .ok_or_else(|| RevocationError::OcspCertIdMismatch {
            url: url.to_string(),
        })?;

    match &single.cert_status {
        CertStatus::Good(_) => {}
        CertStatus::Revoked(_) => {
            return Err(RevocationError::OcspSignerRevoked {
                url: url.to_string(),
            });
        }
        CertStatus::Unknown(_) => {
            return Err(RevocationError::OcspSignerUnknown {
                url: url.to_string(),
            });
        }
    }

    let produced_at = ocsp_generalized_to_offset(basic.tbs_response_data.produced_at);
    let this_update = ocsp_generalized_to_offset(single.this_update);
    let next_update = single
        .next_update
        .map(ocsp_generalized_to_offset)
        .ok_or_else(|| RevocationError::OcspFreshness {
            url: url.to_string(),
            reason: "missing nextUpdate",
        })?;
    validate_ocsp_freshness(url, produced_at, this_update, next_update, validation_time)?;

    let (responder, direct_responder) =
        trusted_ocsp_responder(url, &basic, issuer, validation_time)?;
    verify_basic_ocsp_signature(url, &basic, responder)?;

    let responder_certs = if direct_responder {
        Vec::new()
    } else {
        vec![
            responder
                .to_der()
                .map_err(|_| RevocationError::OcspResponderUntrusted {
                    url: url.to_string(),
                })?,
        ]
    };
    let sha256 = Sha256::digest(ocsp_der).into();
    Ok((
        responder_certs,
        OcspRevocationSource {
            url: url.to_string(),
            produced_at,
            this_update,
            next_update,
            sha256,
            direct_responder,
        },
    ))
}

fn validate_ocsp_freshness(
    url: &str,
    produced_at: OffsetDateTime,
    this_update: OffsetDateTime,
    next_update: OffsetDateTime,
    validation_time: OffsetDateTime,
) -> Result<(), RevocationError> {
    if produced_at > validation_time {
        return Err(RevocationError::OcspFreshness {
            url: url.to_string(),
            reason: "producedAt is in the future",
        });
    }
    if this_update > validation_time {
        return Err(RevocationError::OcspFreshness {
            url: url.to_string(),
            reason: "thisUpdate is in the future",
        });
    }
    if produced_at < this_update {
        return Err(RevocationError::OcspFreshness {
            url: url.to_string(),
            reason: "producedAt precedes thisUpdate",
        });
    }
    if validation_time > next_update {
        return Err(RevocationError::OcspFreshness {
            url: url.to_string(),
            reason: "nextUpdate is stale",
        });
    }
    Ok(())
}

fn trusted_ocsp_responder<'a>(
    url: &str,
    basic: &'a BasicOcspResponse,
    issuer: &'a Certificate,
    validation_time: OffsetDateTime,
) -> Result<(&'a Certificate, bool), RevocationError> {
    if responder_id_matches(&basic.tbs_response_data.responder_id, issuer) {
        return Ok((issuer, true));
    }

    let certs = basic
        .certs
        .as_ref()
        .ok_or_else(|| RevocationError::OcspResponderUntrusted {
            url: url.to_string(),
        })?;
    for candidate in certs {
        if !responder_id_matches(&basic.tbs_response_data.responder_id, candidate) {
            continue;
        }
        validate_delegated_ocsp_responder(url, candidate, issuer, validation_time)?;
        return Ok((candidate, false));
    }

    Err(RevocationError::OcspResponderUntrusted {
        url: url.to_string(),
    })
}

fn validate_delegated_ocsp_responder(
    url: &str,
    responder: &Certificate,
    issuer: &Certificate,
    validation_time: OffsetDateTime,
) -> Result<(), RevocationError> {
    if responder.tbs_certificate.issuer != issuer.tbs_certificate.subject {
        return Err(RevocationError::OcspResponderUntrusted {
            url: url.to_string(),
        });
    }
    let not_before = x509_time_to_offset(responder.tbs_certificate.validity.not_before);
    let not_after = x509_time_to_offset(responder.tbs_certificate.validity.not_after);
    if validation_time < not_before || validation_time > not_after {
        return Err(RevocationError::OcspResponderUntrusted {
            url: url.to_string(),
        });
    }
    if is_ca_certificate(url, responder)? {
        return Err(RevocationError::OcspResponderUntrusted {
            url: url.to_string(),
        });
    }
    if !has_ocsp_signing_eku(url, responder)? {
        return Err(RevocationError::OcspResponderUntrusted {
            url: url.to_string(),
        });
    }
    if !allows_digital_signature(url, responder)? {
        return Err(RevocationError::OcspResponderUntrusted {
            url: url.to_string(),
        });
    }
    verify_certificate_signature(url, responder, issuer).map_err(|_| {
        RevocationError::OcspResponderUntrusted {
            url: url.to_string(),
        }
    })
}

fn responder_id_matches(responder_id: &ResponderId, cert: &Certificate) -> bool {
    match responder_id {
        ResponderId::ByName(name) => name == &cert.tbs_certificate.subject,
        ResponderId::ByKey(key_hash) => {
            let actual = Sha1::digest(
                cert.tbs_certificate
                    .subject_public_key_info
                    .subject_public_key
                    .raw_bytes(),
            );
            key_hash.as_bytes() == actual.as_slice()
        }
    }
}

fn is_ca_certificate(url: &str, cert: &Certificate) -> Result<bool, RevocationError> {
    let Some(extensions) = &cert.tbs_certificate.extensions else {
        return Ok(false);
    };
    let Some(ext) = extensions
        .iter()
        .find(|ext| ext.extn_id == OID_BASIC_CONSTRAINTS)
    else {
        return Ok(false);
    };
    BasicConstraints::from_der(ext.extn_value.as_bytes())
        .map(|bc| bc.ca)
        .map_err(|_| RevocationError::OcspResponderUntrusted {
            url: url.to_string(),
        })
}

fn has_ocsp_signing_eku(url: &str, cert: &Certificate) -> Result<bool, RevocationError> {
    let Some(extensions) = &cert.tbs_certificate.extensions else {
        return Ok(false);
    };
    let Some(ext) = extensions
        .iter()
        .find(|ext| ext.extn_id == OID_EXTENDED_KEY_USAGE)
    else {
        return Ok(false);
    };
    ExtendedKeyUsage::from_der(ext.extn_value.as_bytes())
        .map(|eku| eku.0.contains(&OID_OCSP_SIGNING))
        .map_err(|_| RevocationError::OcspResponderUntrusted {
            url: url.to_string(),
        })
}

fn allows_digital_signature(url: &str, cert: &Certificate) -> Result<bool, RevocationError> {
    let Some(extensions) = &cert.tbs_certificate.extensions else {
        return Ok(true);
    };
    let Some(ext) = extensions.iter().find(|ext| ext.extn_id == OID_KEY_USAGE) else {
        return Ok(true);
    };
    KeyUsage::from_der(ext.extn_value.as_bytes())
        .map(|usage| usage.digital_signature())
        .map_err(|_| RevocationError::OcspResponderUntrusted {
            url: url.to_string(),
        })
}

fn verify_certificate_signature(
    url: &str,
    cert: &Certificate,
    issuer: &Certificate,
) -> Result<(), RevocationError> {
    if cert.signature_algorithm.oid != cert.tbs_certificate.signature.oid {
        return Err(RevocationError::OcspResponderUntrusted {
            url: url.to_string(),
        });
    }
    let tbs_der =
        cert.tbs_certificate
            .to_der()
            .map_err(|_| RevocationError::OcspResponderUntrusted {
                url: url.to_string(),
            })?;
    let signature =
        cert.signature
            .as_bytes()
            .ok_or_else(|| RevocationError::OcspResponderUntrusted {
                url: url.to_string(),
            })?;
    verify_signature_with_cert(issuer, cert.signature_algorithm.oid, signature, &tbs_der).map_err(
        |_| RevocationError::OcspResponderUntrusted {
            url: url.to_string(),
        },
    )
}

fn verify_basic_ocsp_signature(
    url: &str,
    basic: &BasicOcspResponse,
    responder: &Certificate,
) -> Result<(), RevocationError> {
    let tbs_der =
        basic
            .tbs_response_data
            .to_der()
            .map_err(|_| RevocationError::OcspSignatureInvalid {
                url: url.to_string(),
            })?;
    let signature =
        basic
            .signature
            .as_bytes()
            .ok_or_else(|| RevocationError::OcspSignatureInvalid {
                url: url.to_string(),
            })?;
    verify_signature_with_cert(
        responder,
        basic.signature_algorithm.oid,
        signature,
        &tbs_der,
    )
    .map_err(|err| match err {
        SignatureVerifyError::Unsupported(oid) => {
            RevocationError::UnsupportedOcspSignatureAlgorithm { oid }
        }
        SignatureVerifyError::Invalid => RevocationError::OcspSignatureInvalid {
            url: url.to_string(),
        },
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SignatureVerifyError {
    Unsupported(ObjectIdentifier),
    Invalid,
}

fn verify_signature_with_cert(
    cert: &Certificate,
    algorithm_oid: ObjectIdentifier,
    signature: &[u8],
    message: &[u8],
) -> Result<(), SignatureVerifyError> {
    if algorithm_oid == OID_SHA256_WITH_RSA_ENCRYPTION {
        verify_rsa_signature(cert, signature, message)
    } else if algorithm_oid == OID_ECDSA_WITH_SHA256 {
        verify_ecdsa_signature(cert, signature, message)
    } else {
        Err(SignatureVerifyError::Unsupported(algorithm_oid))
    }
}

fn verify_rsa_signature(
    cert: &Certificate,
    signature: &[u8],
    message: &[u8],
) -> Result<(), SignatureVerifyError> {
    use rsa::{Pkcs1v15Sign, RsaPublicKey};

    const SHA256_DIGEST_INFO_PREFIX: [u8; 19] = [
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];

    let spki = cert.tbs_certificate.subject_public_key_info.owned_to_ref();
    let public_key = RsaPublicKey::try_from(spki).map_err(|_| SignatureVerifyError::Invalid)?;
    let hash = Sha256::digest(message);
    let mut digest_info = Vec::with_capacity(SHA256_DIGEST_INFO_PREFIX.len() + hash.len());
    digest_info.extend_from_slice(&SHA256_DIGEST_INFO_PREFIX);
    digest_info.extend_from_slice(&hash);

    public_key
        .verify(Pkcs1v15Sign::new_unprefixed(), &digest_info, signature)
        .map_err(|_| SignatureVerifyError::Invalid)
}

fn verify_ecdsa_signature(
    cert: &Certificate,
    signature: &[u8],
    message: &[u8],
) -> Result<(), SignatureVerifyError> {
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};
    use p256::pkcs8::DecodePublicKey;

    let spki_der = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| SignatureVerifyError::Invalid)?;
    let verifying_key =
        VerifyingKey::from_public_key_der(&spki_der).map_err(|_| SignatureVerifyError::Invalid)?;
    let sig = Signature::from_der(signature).map_err(|_| SignatureVerifyError::Invalid)?;
    verifying_key
        .verify(message, &sig)
        .map_err(|_| SignatureVerifyError::Invalid)
}

fn verify_crl_signature(
    url: &str,
    crl: &CertificateList,
    _crl_der: &[u8],
    issuer: &Certificate,
) -> Result<(), RevocationError> {
    if crl.signature_algorithm.oid != crl.tbs_cert_list.signature.oid {
        return Err(RevocationError::CrlSignatureInvalid {
            url: url.to_string(),
        });
    }

    let tbs_der = crl
        .tbs_cert_list
        .to_der()
        .map_err(|_| RevocationError::CrlSignatureInvalid {
            url: url.to_string(),
        })?;
    let signature =
        crl.signature
            .as_bytes()
            .ok_or_else(|| RevocationError::CrlSignatureInvalid {
                url: url.to_string(),
            })?;

    if crl.signature_algorithm.oid == OID_SHA256_WITH_RSA_ENCRYPTION {
        verify_rsa_crl_signature(url, issuer, signature, &tbs_der)
    } else if crl.signature_algorithm.oid == OID_ECDSA_WITH_SHA256 {
        verify_ecdsa_crl_signature(url, issuer, signature, &tbs_der)
    } else {
        Err(RevocationError::UnsupportedCrlSignatureAlgorithm {
            oid: crl.signature_algorithm.oid,
        })
    }
}

fn verify_rsa_crl_signature(
    url: &str,
    issuer: &Certificate,
    signature: &[u8],
    message: &[u8],
) -> Result<(), RevocationError> {
    use rsa::{Pkcs1v15Sign, RsaPublicKey};

    const SHA256_DIGEST_INFO_PREFIX: [u8; 19] = [
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];

    let spki = issuer
        .tbs_certificate
        .subject_public_key_info
        .owned_to_ref();
    let public_key =
        RsaPublicKey::try_from(spki).map_err(|_| RevocationError::CrlSignatureInvalid {
            url: url.to_string(),
        })?;
    let hash = Sha256::digest(message);
    let mut digest_info = Vec::with_capacity(SHA256_DIGEST_INFO_PREFIX.len() + hash.len());
    digest_info.extend_from_slice(&SHA256_DIGEST_INFO_PREFIX);
    digest_info.extend_from_slice(&hash);

    public_key
        .verify(Pkcs1v15Sign::new_unprefixed(), &digest_info, signature)
        .map_err(|_| RevocationError::CrlSignatureInvalid {
            url: url.to_string(),
        })
}

fn verify_ecdsa_crl_signature(
    url: &str,
    issuer: &Certificate,
    signature: &[u8],
    message: &[u8],
) -> Result<(), RevocationError> {
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};
    use p256::pkcs8::DecodePublicKey;

    let spki_der = issuer
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| RevocationError::CrlSignatureInvalid {
            url: url.to_string(),
        })?;
    let verifying_key = VerifyingKey::from_public_key_der(&spki_der).map_err(|_| {
        RevocationError::CrlSignatureInvalid {
            url: url.to_string(),
        }
    })?;
    let sig = Signature::from_der(signature).map_err(|_| RevocationError::CrlSignatureInvalid {
        url: url.to_string(),
    })?;
    verifying_key
        .verify(message, &sig)
        .map_err(|_| RevocationError::CrlSignatureInvalid {
            url: url.to_string(),
        })
}

fn x509_time_to_offset(time: Time) -> OffsetDateTime {
    let duration = time.to_unix_duration();
    OffsetDateTime::from_unix_timestamp(duration.as_secs() as i64)
        .expect("x509-cert time is representable as a Unix timestamp")
}

fn ocsp_generalized_to_offset(time: x509_ocsp::OcspGeneralizedTime) -> OffsetDateTime {
    let duration = time.0.to_unix_duration();
    OffsetDateTime::from_unix_timestamp(duration.as_secs() as i64)
        .expect("OCSP time is representable as a Unix timestamp")
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::time::Duration as StdDuration;

    use der::Encode;
    use der::asn1::{Any, BitString, Ia5String, OctetString};
    use rsa::pkcs8::EncodePublicKey;
    use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
    use x509_cert::certificate::{Certificate, TbsCertificate, Version};
    use x509_cert::ext::Extension;
    use x509_cert::ext::pkix::crl::dp::DistributionPoint;
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::time::Validity;

    use super::*;

    #[derive(Debug)]
    struct PanicTransport;

    impl RevocationHttpTransport for PanicTransport {
        fn get_crl(
            &self,
            _url: &str,
            _limits: &RevocationFetchLimits,
        ) -> Result<RevocationHttpResponse, RevocationError> {
            panic!("transport must not be called before URL limit validation")
        }

        fn post_ocsp(
            &self,
            _url: &str,
            _request_der: &[u8],
            _limits: &RevocationFetchLimits,
        ) -> Result<RevocationHttpResponse, RevocationError> {
            panic!("transport must not be called before URL limit validation")
        }
    }

    #[derive(Debug, Clone)]
    struct StaticOcspTransport {
        body: Vec<u8>,
    }

    impl RevocationHttpTransport for StaticOcspTransport {
        fn get_crl(
            &self,
            _url: &str,
            _limits: &RevocationFetchLimits,
        ) -> Result<RevocationHttpResponse, RevocationError> {
            panic!("CRL fallback should not run for this OCSP test")
        }

        fn post_ocsp(
            &self,
            _url: &str,
            request_der: &[u8],
            limits: &RevocationFetchLimits,
        ) -> Result<RevocationHttpResponse, RevocationError> {
            assert!(
                request_der.len() <= limits.max_response_bytes,
                "request stays bounded"
            );
            let request = OcspRequest::from_der(request_der).expect("valid OCSP request");
            assert!(request.optional_signature.is_none());
            assert_eq!(request.tbs_request.request_list.len(), 1);
            Ok(RevocationHttpResponse {
                status: 200,
                body: self.body.clone(),
            })
        }
    }

    fn uri(value: &str) -> GeneralName {
        GeneralName::UniformResourceIdentifier(Ia5String::new(value).expect("ia5 uri"))
    }

    fn extension(oid: ObjectIdentifier, value: Vec<u8>) -> Extension {
        Extension {
            extn_id: oid,
            critical: false,
            extn_value: OctetString::new(value).expect("extension value"),
        }
    }

    fn test_cert(crl_urls: &[&str], ocsp_urls: &[&str]) -> Certificate {
        let key = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).expect("rsa key");
        let public = rsa::RsaPublicKey::from(key);
        let spki = SubjectPublicKeyInfoOwned::from_der(
            public
                .to_public_key_der()
                .expect("public key der")
                .as_bytes(),
        )
        .expect("spki");
        let sig_alg = AlgorithmIdentifierOwned {
            oid: OID_SHA256_WITH_RSA_ENCRYPTION,
            parameters: Some(Any::null()),
        };
        let name = Name::from_str("CN=Revocation Test").expect("name");
        let validity = Validity::from_now(StdDuration::from_secs(3600)).expect("validity");

        let mut extensions = Vec::new();
        if !crl_urls.is_empty() {
            let points = crl_urls
                .iter()
                .map(|url| DistributionPoint {
                    distribution_point: Some(DistributionPointName::FullName(vec![uri(url)])),
                    reasons: None,
                    crl_issuer: None,
                })
                .collect();
            let cdp = CrlDistributionPoints(points);
            extensions.push(extension(
                OID_CRL_DISTRIBUTION_POINTS,
                cdp.to_der().expect("cdp der"),
            ));
        }
        if !ocsp_urls.is_empty() {
            let access = ocsp_urls
                .iter()
                .map(|url| x509_cert::ext::pkix::AccessDescription {
                    access_method: OID_OCSP,
                    access_location: uri(url),
                })
                .collect();
            let aia = AuthorityInfoAccessSyntax(access);
            extensions.push(extension(
                OID_AUTHORITY_INFO_ACCESS,
                aia.to_der().expect("aia der"),
            ));
        }

        Certificate {
            tbs_certificate: TbsCertificate {
                version: Version::V3,
                serial_number: SerialNumber::new(&[1]).expect("serial"),
                signature: sig_alg.clone(),
                issuer: name.clone(),
                validity,
                subject: name,
                subject_public_key_info: spki,
                issuer_unique_id: None,
                subject_unique_id: None,
                extensions: Some(extensions),
            },
            signature_algorithm: sig_alg,
            signature: BitString::from_bytes(&[0; 256]).expect("signature"),
        }
    }

    #[test]
    fn discovers_http_cdp_and_ocsp_uris() {
        let cert = test_cert(
            &[
                "ldap://example.invalid/ignored",
                "https://ca.example/crl.der",
                "http://ca.example/crl.der",
                "https://ca.example/crl.der",
            ],
            &[
                "mailto:ignored@example.invalid",
                "https://ocsp.example",
                "http://ocsp.example",
            ],
        );

        let discovered = discover_revocation_uris(&cert);

        assert_eq!(
            discovered.crl_urls,
            vec!["http://ca.example/crl.der", "https://ca.example/crl.der"]
        );
        assert_eq!(
            discovered.ocsp_urls,
            vec!["http://ocsp.example", "https://ocsp.example"]
        );
    }

    #[test]
    fn enforces_crl_url_limit_before_fetching() {
        let cert = test_cert(
            &["https://ca.example/a.crl", "https://ca.example/b.crl"],
            &[],
        );
        let cert_der = cert.to_der().expect("cert der");
        let provider = RevocationEvidenceProvider::new(
            PanicTransport,
            RevocationFetchLimits {
                max_crl_urls: 1,
                max_ocsp_urls: 1,
                max_response_bytes: 4096,
                timeout: StdDuration::from_secs(1),
            },
        );

        let err = provider
            .collect_for_signer(&cert_der, &cert_der, OffsetDateTime::now_utc())
            .unwrap_err();

        assert!(matches!(
            err,
            RevocationError::CrlUrlLimitExceeded {
                discovered: 2,
                limit: 1
            }
        ));
    }

    #[test]
    fn builds_unsigned_ocsp_request_for_signer_and_issuer() {
        let cert = test_cert(&[], &["https://ocsp.example"]);
        let cert_der = cert.to_der().expect("cert der");

        let request_der = unsigned_ocsp_request_der(&cert_der, &cert_der).expect("OCSP request");
        let request = OcspRequest::from_der(&request_der).expect("request der");

        assert!(request.optional_signature.is_none());
        assert_eq!(request.tbs_request.request_list.len(), 1);
        assert_eq!(
            request.tbs_request.request_list[0].req_cert.serial_number,
            cert.tbs_certificate.serial_number
        );
        assert_eq!(
            request.tbs_request.request_list[0]
                .req_cert
                .hash_algorithm
                .oid,
            OID_SHA1
        );
    }

    #[test]
    fn rejects_non_successful_ocsp_protocol_status() {
        let cert = test_cert(&[], &["https://ocsp.example"]);
        let cert_der = cert.to_der().expect("cert der");
        let provider = RevocationEvidenceProvider::new(
            StaticOcspTransport {
                body: OcspResponse::unauthorized().to_der().expect("ocsp der"),
            },
            RevocationFetchLimits {
                max_crl_urls: 1,
                max_ocsp_urls: 1,
                max_response_bytes: 4096,
                timeout: StdDuration::from_secs(1),
            },
        );

        let err = provider
            .collect_for_signer(&cert_der, &cert_der, OffsetDateTime::now_utc())
            .unwrap_err();

        assert!(matches!(
            err,
            RevocationError::OcspStatus {
                status: OcspResponseStatus::Unauthorized,
                ..
            }
        ));
    }
}
