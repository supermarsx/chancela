//! Validated CRL revocation evidence collection for PAdES DSS attachment.
//!
//! This module extracts URI CDP/AIA metadata from the signer certificate, fetches CRLs through a
//! bounded/mocked transport, and only returns DSS evidence after validating CRL issuer, time,
//! signer revocation status, and the CRL signature against the supplied issuer certificate. OCSP
//! URLs are reported for callers but raw OCSP responses are not trusted or inserted here.

use std::io::Read;
use std::time::Duration;

use der::asn1::ObjectIdentifier;
use der::referenced::OwnedToRef;
use der::{Decode, Encode};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use x509_cert::certificate::Certificate;
use x509_cert::crl::CertificateList;
use x509_cert::ext::pkix::AuthorityInfoAccessSyntax;
use x509_cert::ext::pkix::crl::CrlDistributionPoints;
use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName, GeneralNames};
use x509_cert::time::Time;

use crate::DssEvidence;

const OID_CRL_DISTRIBUTION_POINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.31");
const OID_AUTHORITY_INFO_ACCESS: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.1");
const OID_OCSP: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1");
const OID_SHA256_WITH_RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const OID_ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

/// Network limits used by the default HTTP transport and enforced by the provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationFetchLimits {
    /// Maximum number of CRL distribution-point URLs attempted from one signer certificate.
    pub max_crl_urls: usize,
    /// Maximum response body size accepted for one CRL.
    pub max_response_bytes: usize,
    /// Per-request timeout for the default blocking HTTP transport.
    pub timeout: Duration,
}

impl Default for RevocationFetchLimits {
    fn default() -> Self {
        Self {
            max_crl_urls: 4,
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
    /// AIA OCSP responder URLs. Reported only; this slice does not validate or embed OCSP.
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

        if discovered.crl_urls.is_empty() {
            return Err(RevocationError::NoCrlDistributionPoint);
        }
        if discovered.crl_urls.len() > self.limits.max_crl_urls {
            return Err(RevocationError::CrlUrlLimitExceeded {
                discovered: discovered.crl_urls.len(),
                limit: self.limits.max_crl_urls,
            });
        }

        let mut last_error = None;
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
                    });
                }
                Err(RevocationError::SignerRevoked { url }) => {
                    return Err(RevocationError::SignerRevoked { url });
                }
                Err(e) => last_error = Some(e),
            }
        }

        Err(last_error.unwrap_or(RevocationError::NoCrlDistributionPoint))
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
}
