//! Internal: CAdES-B signed-attribute construction and the RFC 5035 ESS types.
//!
//! The builder and validator both go through [`build_signed_attributes`] so the DER bytes that
//! are hashed for signing are identical to the bytes embedded in the `SignerInfo`.

use der::asn1::{Any, ObjectIdentifier, OctetString, SetOfVec, UtcTime};
use der::{Decode, Sequence};
use sha2::{Digest, Sha256};
use spki::AlgorithmIdentifierOwned;
use x509_cert::attr::{Attribute, Attributes};
use x509_cert::certificate::Certificate;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::serial_number::SerialNumber;

use crate::error::CadesError;
use crate::oids;

/// SHA-256 helper returning a fixed-size digest.
pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// The `AlgorithmIdentifier` for SHA-256, parameters absent (RFC 5754 §2).
pub(crate) fn alg_sha256() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: oids::ID_SHA256,
        parameters: None,
    }
}

/// RFC 5035 `IssuerSerial` — identifies the signing certificate by issuer name + serial.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub(crate) struct IssuerSerial {
    /// The certificate issuer, as a single `directoryName` GeneralName.
    pub issuer: Vec<GeneralName>,
    /// The certificate serial number.
    pub serial_number: SerialNumber,
}

/// RFC 5035 `ESSCertIDv2`.
///
/// `hashAlgorithm` has DEFAULT `id-sha256`; per DER we omit it when SHA-256, so on encode the
/// field is `None`. On decode we accept an explicit algorithm for third-party interoperability.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub(crate) struct EssCertIdV2 {
    /// Absent means the SHA-256 default (the only algorithm this crate emits).
    #[asn1(optional = "true")]
    pub hash_algorithm: Option<AlgorithmIdentifierOwned>,
    /// The certificate hash (SHA-256 of the DER certificate).
    pub cert_hash: OctetString,
    /// Optional issuer/serial reference to the signing certificate.
    #[asn1(optional = "true")]
    pub issuer_serial: Option<IssuerSerial>,
}

/// RFC 5035 `SigningCertificateV2` (policies field omitted — not emitted by this crate).
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub(crate) struct SigningCertificateV2 {
    /// One or more ESSCertIDv2 references; we emit exactly the signer.
    pub certs: Vec<EssCertIdV2>,
}

/// Convert an `OffsetDateTime` into a CMS `signing-time` value.
///
/// RFC 5652 §11.3 mandates UTCTime for 1950-01-01..=2049-12-31, GeneralizedTime otherwise. We
/// return the raw [`Any`] carrying whichever encoding applies.
pub(crate) fn signing_time_value(signing_time: time::OffsetDateTime) -> Result<Any, CadesError> {
    let secs = signing_time.unix_timestamp();
    if !(-631_152_000..=2_524_607_999).contains(&secs) {
        // Outside 1950-01-01..=2049-12-31: use GeneralizedTime.
        let dur = core::time::Duration::from_secs(secs.max(0) as u64);
        let gt = der::asn1::GeneralizedTime::from_unix_duration(dur)
            .map_err(|_| CadesError::InvalidSigningTime)?;
        return Ok(Any::encode_from(&gt)?);
    }
    let dur = core::time::Duration::from_secs(secs as u64);
    let utc = UtcTime::from_unix_duration(dur).map_err(|_| CadesError::InvalidSigningTime)?;
    Ok(Any::encode_from(&utc)?)
}

/// Build a single-valued attribute.
fn attribute(oid: ObjectIdentifier, value: Any) -> Result<Attribute, CadesError> {
    Ok(Attribute {
        oid,
        values: SetOfVec::try_from(vec![value])?,
    })
}

/// Build the CAdES-B signed attributes: content-type, message-digest, signing-time, and
/// signing-certificate-v2 (ESSCertIDv2). Deterministic for identical inputs — the returned
/// `SetOfVec` is DER-sorted so [`Attributes::to_der`] yields canonical bytes.
pub(crate) fn build_signed_attributes(
    content_digest: &[u8; 32],
    signing_cert_der: &[u8],
    signing_time: time::OffsetDateTime,
) -> Result<Attributes, CadesError> {
    let cert =
        Certificate::from_der(signing_cert_der).map_err(|_| CadesError::InvalidCertificate)?;

    // content-type = id-data
    let content_type = attribute(oids::ID_CONTENT_TYPE, Any::encode_from(&oids::ID_DATA)?)?;

    // message-digest = OCTET STRING of the content digest
    let md_octets = OctetString::new(content_digest.as_slice())?;
    let message_digest = attribute(oids::ID_MESSAGE_DIGEST, Any::encode_from(&md_octets)?)?;

    // signing-time
    let signing_time_attr = attribute(oids::ID_SIGNING_TIME, signing_time_value(signing_time)?)?;

    // signing-certificate-v2 (ESSCertIDv2)
    let cert_hash = OctetString::new(sha256(signing_cert_der).to_vec())?;
    let issuer_serial = IssuerSerial {
        issuer: vec![GeneralName::DirectoryName(
            cert.tbs_certificate.issuer.clone(),
        )],
        serial_number: cert.tbs_certificate.serial_number.clone(),
    };
    let ess = SigningCertificateV2 {
        certs: vec![EssCertIdV2 {
            hash_algorithm: None,
            cert_hash,
            issuer_serial: Some(issuer_serial),
        }],
    };
    let signing_cert_v2 = attribute(oids::ID_AA_SIGNING_CERTIFICATE_V2, Any::encode_from(&ess)?)?;

    let attrs = SetOfVec::try_from(vec![
        content_type,
        message_digest,
        signing_time_attr,
        signing_cert_v2,
    ])?;
    Ok(attrs)
}
