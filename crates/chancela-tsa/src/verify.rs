//! `TimeStampResp` parsing and `TimeStampToken` verification (spec 04, SIG-22).
//!
//! See the crate-level "Verification boundary" note: this verifies token *structure*, the
//! *binding* to the requested digest, and the CMS signature value when the TSA signer certificate
//! is embedded. It does not build or validate the TSA certificate chain.

use cms::cert::CertificateChoices;
use cms::signed_data::{SignedData, SignerIdentifier, SignerInfo};
use der::asn1::OctetString;
use der::oid::ObjectIdentifier;
use der::{Decode, Encode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use x509_cert::Certificate;
use x509_cert::attr::{Attribute, Attributes};
use x509_tsp::{TimeStampResp, TstInfo};

use crate::error::TsaError;
use crate::oid;
use crate::request::{TimestampRequest, u64_to_int};

const SKI_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");

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
/// `message-digest` signed attributes bind to the encapsulated `TstInfo`. When the token embeds
/// the TSA signer certificate referenced by `SignerInfo.sid`, this also verifies the CMS signature
/// value over the signed attributes. The `policy` hook enforces the qualified-timestamp policy
/// (SIG-22).
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
    //    message-digest attr equals SHA-256(eContent). This proves the signed attributes commit to
    //    this exact TstInfo; if the signer certificate is embedded below, the CMS signature value
    //    is then verified over these attributes.
    let signer = signed_data
        .signer_infos
        .0
        .iter()
        .next()
        .ok_or(TsaError::MissingSignerInfo)?;
    verify_signed_attribute_binding(signer, tst_der)?;

    // 7. Qualified-timestamp policy hook (SIG-22).
    policy.check(&tst.policy)?;

    // 8. TSA certificate, if embedded. Select by SignerInfo.sid; do not trust "first cert wins".
    //    `certReq` implies a matching embedded signer certificate must be present.
    let signer_cert = extract_tsa_certificate(&signed_data, &signer.sid)?;
    if request.cert_req() && signer_cert.is_none() {
        return Err(TsaError::NoTsaCertificate);
    }
    let tsa_certificate_der = signer_cert
        .as_ref()
        .map(|cert| cert.to_der().map_err(TsaError::Malformed))
        .transpose()?;

    // 9. CMS signature value, when dependencies and embedded material allow it. Tokens without an
    //    embedded certificate can still be structurally checked unless the request set certReq.
    if let Some(cert) = &signer_cert {
        let signed_attrs_der = signer
            .signed_attrs
            .as_ref()
            .expect("checked by verify_signed_attribute_binding")
            .to_der()
            .map_err(TsaError::Malformed)?;
        verify_signature(
            cert,
            &signer.signature_algorithm.oid,
            signer.signature.as_bytes(),
            &signed_attrs_der,
        )?;
    }

    // 10. genTime.
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

fn extract_tsa_certificate(
    signed_data: &SignedData,
    sid: &SignerIdentifier,
) -> Result<Option<Certificate>, TsaError> {
    let Some(certificates) = &signed_data.certificates else {
        return Ok(None);
    };

    for choice in certificates.0.iter() {
        if let CertificateChoices::Certificate(certificate) = choice {
            if certificate_matches_sid(certificate, sid)? {
                return Ok(Some(certificate.clone()));
            }
        }
    }

    Err(TsaError::SignerCertNotEmbedded)
}

fn certificate_matches_sid(cert: &Certificate, sid: &SignerIdentifier) -> Result<bool, TsaError> {
    match sid {
        SignerIdentifier::IssuerAndSerialNumber(ias) => Ok(cert.tbs_certificate.issuer
            == ias.issuer
            && cert.tbs_certificate.serial_number == ias.serial_number),
        SignerIdentifier::SubjectKeyIdentifier(ski) => {
            Ok(subject_key_identifier(cert)?.as_deref() == Some(ski.0.as_bytes()))
        }
    }
}

fn subject_key_identifier(cert: &Certificate) -> Result<Option<Vec<u8>>, TsaError> {
    let Some(extensions) = cert.tbs_certificate.extensions.as_ref() else {
        return Ok(None);
    };
    let Some(ext) = extensions.iter().find(|ext| ext.extn_id == SKI_OID) else {
        return Ok(None);
    };
    let inner = OctetString::from_der(ext.extn_value.as_bytes())
        .map_err(|e| TsaError::InvalidTsaCertificate(e.to_string()))?;
    Ok(Some(inner.as_bytes().to_vec()))
}

fn verify_signature(
    cert: &Certificate,
    sig_alg_oid: &ObjectIdentifier,
    signature: &[u8],
    message: &[u8],
) -> Result<(), TsaError> {
    if *sig_alg_oid == oid::RSA_ENCRYPTION || *sig_alg_oid == oid::SHA256_WITH_RSA_ENCRYPTION {
        verify_rsa(cert, signature, message)
    } else if *sig_alg_oid == oid::ECDSA_WITH_SHA256 {
        verify_ecdsa(cert, signature, message)
    } else {
        Err(TsaError::UnsupportedSignatureAlgorithm {
            oid: sig_alg_oid.to_string(),
        })
    }
}

fn verify_rsa(cert: &Certificate, signature: &[u8], message: &[u8]) -> Result<(), TsaError> {
    use der::referenced::OwnedToRef;
    use rsa::{Pkcs1v15Sign, RsaPublicKey};

    const SHA256_DIGEST_INFO_PREFIX: [u8; 19] = [
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];

    let spki = cert.tbs_certificate.subject_public_key_info.owned_to_ref();
    let public_key =
        RsaPublicKey::try_from(spki).map_err(|e| TsaError::InvalidTsaCertificate(e.to_string()))?;

    let hash = Sha256::digest(message);
    let mut digest_info = Vec::with_capacity(SHA256_DIGEST_INFO_PREFIX.len() + hash.len());
    digest_info.extend_from_slice(&SHA256_DIGEST_INFO_PREFIX);
    digest_info.extend_from_slice(&hash);

    public_key
        .verify(Pkcs1v15Sign::new_unprefixed(), &digest_info, signature)
        .map_err(|_| TsaError::SignatureVerificationFailed)
}

fn verify_ecdsa(cert: &Certificate, signature: &[u8], message: &[u8]) -> Result<(), TsaError> {
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};
    use p256::pkcs8::DecodePublicKey;

    let spki_der = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(TsaError::Malformed)?;
    let verifying_key = VerifyingKey::from_public_key_der(&spki_der)
        .map_err(|e| TsaError::InvalidTsaCertificate(e.to_string()))?;
    let sig = Signature::from_der(signature).map_err(|_| TsaError::InvalidSignatureEncoding)?;
    verifying_key
        .verify(message, &sig)
        .map_err(|_| TsaError::SignatureVerificationFailed)
}

fn generalized_to_offset(tst: &TstInfo) -> Result<OffsetDateTime, TsaError> {
    let secs = i64::try_from(tst.gen_time.to_unix_duration().as_secs())
        .map_err(|e| TsaError::InvalidGenTime(e.to_string()))?;
    OffsetDateTime::from_unix_timestamp(secs).map_err(|e| TsaError::InvalidGenTime(e.to_string()))
}
