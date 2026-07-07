//! `TimeStampResp` parsing and `TimeStampToken` verification (spec 04, SIG-22).
//!
//! See the crate-level "Verification boundary" note: this verifies token *structure* and the
//! *binding* to the requested digest, not the TSA's asymmetric signature or certificate chain.

use cms::cert::CertificateChoices;
use cms::signed_data::{SignedData, SignerInfo};
use der::asn1::OctetString;
use der::oid::ObjectIdentifier;
use der::{Decode, Encode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use x509_cert::attr::{Attribute, Attributes};
use x509_tsp::{TimeStampResp, TstInfo};

use crate::error::TsaError;
use crate::oid;
use crate::request::{TimestampRequest, u64_to_int};

/// The qualified-timestamp policy hook (SIG-22).
///
/// A *qualified* timestamp is one issued by a qualified trust-service provider under a qualified
/// timestamp policy. Whether the signing TSA is currently a granted qualified TSA is a trust-list
/// decision delegated to `chancela-tsl`; this hook enforces the complementary check that the token
/// was issued under an *expected policy OID*.
#[derive(Clone, Debug, Default)]
pub enum QualifiedTimestampPolicy {
    /// Accept any `TSTInfo.policy`. Qualified-status enforcement is left entirely to the trust
    /// layer. This is the default.
    #[default]
    Any,
    /// Require `TSTInfo.policy` to be one of these OIDs (the qualified-TSA's timestamp policy
    /// OIDs). An empty list rejects every token.
    RequireOneOf(Vec<ObjectIdentifier>),
}

impl QualifiedTimestampPolicy {
    /// Check a token's policy OID against this hook.
    pub fn check(&self, policy: &ObjectIdentifier) -> Result<(), TsaError> {
        match self {
            QualifiedTimestampPolicy::Any => Ok(()),
            QualifiedTimestampPolicy::RequireOneOf(allowed) => {
                if allowed.contains(policy) {
                    Ok(())
                } else {
                    Err(TsaError::PolicyRejected {
                        got: policy.to_string(),
                    })
                }
            }
        }
    }
}

/// A verified RFC 3161 timestamp.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Timestamp {
    /// The full `TimeStampToken` (`ContentInfo`) DER — embed this as a CAdES/PAdES
    /// signature-timestamp or archive it as standalone evidence.
    pub token_der: Vec<u8>,
    /// `TSTInfo.genTime` — the time the TSA asserts the digest existed.
    #[serde(with = "time::serde::timestamp")]
    pub gen_time: OffsetDateTime,
    /// `TSTInfo.serialNumber` bytes (up to 160 bits; RFC 3161 §2.4.2).
    pub serial_number: Vec<u8>,
    /// `TSTInfo.policy` OID in dotted form.
    pub policy: String,
    /// The TSA signing certificate DER, if the token embedded one (`certReq`).
    pub tsa_certificate_der: Option<Vec<u8>>,
}

/// Parse and verify a DER `TimeStampResp` against the request that produced it.
///
/// On success the token is structurally sound, reports PKIStatus granted, covers exactly
/// `request.digest()` under SHA-256, echoes the request nonce, and its `content-type` /
/// `message-digest` signed attributes bind to the encapsulated `TstInfo`. The `policy` hook
/// enforces the qualified-timestamp policy (SIG-22).
pub fn verify_response(
    der_resp: &[u8],
    request: &TimestampRequest,
    policy: &QualifiedTimestampPolicy,
) -> Result<Timestamp, TsaError> {
    let resp = TimeStampResp::from_der(der_resp).map_err(TsaError::DecodeResponse)?;

    // 1. PKIStatus must be granted(0) or grantedWithMods(1). `PkiStatus` is a field-less
    //    `#[repr(u8)]` enum, so we read its discriminant without pulling in `cmpv2` by name.
    let status = resp.status.status as u8;
    if status > 1 {
        return Err(TsaError::Rejected { status });
    }

    // 2. Extract the TimeStampToken (a CMS ContentInfo wrapping SignedData).
    let token = resp.time_stamp_token.ok_or(TsaError::MissingToken)?;
    if token.content_type != oid::ID_SIGNED_DATA {
        return Err(TsaError::NotSignedData(token.content_type.to_string()));
    }
    let token_der = token.to_der().map_err(TsaError::Malformed)?;
    let sd_der = token.content.to_der().map_err(TsaError::Malformed)?;
    let signed_data = SignedData::from_der(&sd_der).map_err(TsaError::Malformed)?;

    // 3. The encapsulated content must be a TSTInfo.
    if signed_data.encap_content_info.econtent_type != oid::ID_CT_TST_INFO {
        return Err(TsaError::NotTstInfo(
            signed_data.encap_content_info.econtent_type.to_string(),
        ));
    }
    let econtent = signed_data
        .encap_content_info
        .econtent
        .as_ref()
        .ok_or(TsaError::EmptyContent)?;
    // `econtent` is the eContent OCTET STRING; its value octets are the TstInfo DER, and are also
    // exactly what the `message-digest` signed attribute is computed over (RFC 5652 §5.4).
    let tst_der = econtent.value();
    let tst = TstInfo::from_der(tst_der).map_err(TsaError::Malformed)?;

    // 4. The imprint must be a SHA-256 imprint over the digest we asked to be timestamped.
    if tst.message_imprint.hash_algorithm.oid != oid::ID_SHA256 {
        return Err(TsaError::HashAlgorithmMismatch);
    }
    if tst.message_imprint.hashed_message.as_bytes() != request.digest() {
        return Err(TsaError::ImprintMismatch);
    }

    // 5. If we sent a nonce, the token MUST echo it (RFC 3161 §2.4.2 replay protection).
    if let Some(expected) = request.nonce() {
        let expected = u64_to_int(expected)?;
        match &tst.nonce {
            Some(actual) if actual.as_bytes() == expected.as_bytes() => {}
            _ => return Err(TsaError::NonceMismatch),
        }
    }

    // 6. Signed-attribute binding: the SignerInfo's content-type attr is id-ct-TSTInfo and its
    //    message-digest attr equals SHA-256(eContent). This proves the signature commits to this
    //    exact TstInfo (the asymmetric signature value itself is checked by the crypto layer).
    let signer = signed_data
        .signer_infos
        .0
        .iter()
        .next()
        .ok_or(TsaError::MissingSignerInfo)?;
    verify_signed_attribute_binding(signer, tst_der)?;

    // 7. Qualified-timestamp policy hook (SIG-22).
    policy.check(&tst.policy)?;

    // 8. TSA certificate, if embedded. `certReq` implies it must be present.
    let tsa_certificate_der = extract_tsa_certificate(&signed_data)?;
    if request.cert_req() && tsa_certificate_der.is_none() {
        return Err(TsaError::NoTsaCertificate);
    }

    // 9. genTime.
    let gen_time = generalized_to_offset(&tst)?;

    Ok(Timestamp {
        token_der,
        gen_time,
        serial_number: tst.serial_number.as_bytes().to_vec(),
        policy: tst.policy.to_string(),
        tsa_certificate_der,
    })
}

/// Check the SignerInfo's `content-type` and `message-digest` signed attributes bind to `tst_der`.
fn verify_signed_attribute_binding(signer: &SignerInfo, tst_der: &[u8]) -> Result<(), TsaError> {
    let signed_attrs = signer
        .signed_attrs
        .as_ref()
        .ok_or(TsaError::MissingSignedAttribute("signedAttrs"))?;

    let content_type: ObjectIdentifier = decode_attribute_value(
        find_attribute(signed_attrs, &oid::ID_CONTENT_TYPE)
            .ok_or(TsaError::MissingSignedAttribute("content-type"))?,
    )?;
    if content_type != oid::ID_CT_TST_INFO {
        return Err(TsaError::ContentTypeMismatch);
    }

    let message_digest: OctetString = decode_attribute_value(
        find_attribute(signed_attrs, &oid::ID_MESSAGE_DIGEST)
            .ok_or(TsaError::MissingSignedAttribute("message-digest"))?,
    )?;
    if message_digest.as_bytes() != Sha256::digest(tst_der).as_slice() {
        return Err(TsaError::MessageDigestMismatch);
    }
    Ok(())
}

fn find_attribute<'a>(attrs: &'a Attributes, oid: &ObjectIdentifier) -> Option<&'a Attribute> {
    attrs.iter().find(|attr| &attr.oid == oid)
}

/// Decode the first value of a single-valued signed attribute.
fn decode_attribute_value<'a, T>(attr: &'a Attribute) -> Result<T, TsaError>
where
    T: der::Choice<'a> + der::DecodeValue<'a>,
{
    attr.values
        .iter()
        .next()
        .ok_or(TsaError::MissingSignedAttribute("attribute value"))?
        .decode_as::<T>()
        .map_err(TsaError::Malformed)
}

fn extract_tsa_certificate(signed_data: &SignedData) -> Result<Option<Vec<u8>>, TsaError> {
    let Some(certificates) = &signed_data.certificates else {
        return Ok(None);
    };
    for choice in certificates.0.iter() {
        if let CertificateChoices::Certificate(certificate) = choice {
            return Ok(Some(certificate.to_der().map_err(TsaError::Malformed)?));
        }
    }
    Ok(None)
}

fn generalized_to_offset(tst: &TstInfo) -> Result<OffsetDateTime, TsaError> {
    let secs = i64::try_from(tst.gen_time.to_unix_duration().as_secs())
        .map_err(|e| TsaError::InvalidGenTime(e.to_string()))?;
    OffsetDateTime::from_unix_timestamp(secs).map_err(|e| TsaError::InvalidGenTime(e.to_string()))
}
