//! Structural + cryptographic validation of a detached CAdES-B `SignedData` (SIG-24).
//!
//! This crate validates the **signature and its bound attributes** only. Trust-chain building and
//! qualified-status resolution are the caller's responsibility (via `chancela-tsl`); a successful
//! [`validate_cades_b`] means "the embedded signature is cryptographically valid over the given
//! content digest and carries well-formed CAdES-B signed attributes", not "the signer is trusted".

use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerIdentifier, SignerInfo};
use der::asn1::{Any, ObjectIdentifier, OctetString};
use der::{Decode, Encode};
use x509_cert::attr::Attributes;
use x509_cert::certificate::Certificate;

use crate::error::CadesError;
use crate::oids;

/// The result of a successful [`validate_cades_b`] — details extracted from a signature that has
/// already been verified (the function returns `Err` on any structural or cryptographic failure).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct CadesValidation {
    /// The signer's certificate, DER-encoded (as embedded in the `SignedData`).
    pub signer_cert_der: Vec<u8>,
    /// The `signing-time` signed attribute, if present.
    pub signing_time: Option<time::OffsetDateTime>,
    /// Whether the mandatory CAdES-B signed attributes were present and consistent
    /// (content-type = id-data, message-digest matched, signing-certificate-v2 present). Always
    /// `true` on a successful return; retained for explicit SIG-24 reporting.
    pub attrs_ok: bool,
    /// Whether the `signing-certificate-v2` (ESSCertIDv2) attribute was present.
    pub signing_certificate_v2_present: bool,
}

/// Fetch the first value of the signed attribute with the given OID.
fn first_attr_value(attrs: &Attributes, oid: ObjectIdentifier) -> Option<Any> {
    attrs
        .iter()
        .find(|a| a.oid == oid)
        .and_then(|a| a.values.iter().next().cloned())
}

/// Structurally and cryptographically validate a detached CAdES-B `SignedData` over
/// `content_digest` (the SHA-256 of the detached content) — SIG-24.
///
/// Returns `Err` if the message is malformed, an attribute is missing/inconsistent, the signer
/// certificate is absent, or the signature does not verify.
pub fn validate_cades_b(
    cms_der: &[u8],
    content_digest: &[u8; 32],
) -> Result<CadesValidation, CadesError> {
    let content_info = ContentInfo::from_der(cms_der)?;
    if content_info.content_type != oids::ID_SIGNED_DATA {
        return Err(CadesError::UnexpectedContentType);
    }
    let signed_data: SignedData = content_info.content.decode_as()?;

    let signer_infos = &signed_data.signer_infos.0;
    if signer_infos.len() != 1 {
        return Err(CadesError::SignerInfoCount(signer_infos.len()));
    }
    let signer_info: &SignerInfo = signer_infos.iter().next().expect("checked len == 1");

    let signed_attrs = signer_info
        .signed_attrs
        .as_ref()
        .ok_or(CadesError::MissingSignedAttributes)?;

    // content-type must be id-data.
    let content_type = first_attr_value(signed_attrs, oids::ID_CONTENT_TYPE)
        .ok_or(CadesError::MissingContentType)?;
    let content_type_oid: ObjectIdentifier = content_type.decode_as()?;
    if content_type_oid != oids::ID_DATA {
        return Err(CadesError::UnexpectedContentTypeAttr);
    }

    // message-digest must equal the supplied content digest.
    let md_value = first_attr_value(signed_attrs, oids::ID_MESSAGE_DIGEST)
        .ok_or(CadesError::MissingMessageDigest)?;
    let md_octets: OctetString = md_value.decode_as()?;
    if md_octets.as_bytes() != content_digest.as_slice() {
        return Err(CadesError::MessageDigestMismatch);
    }

    // signing-certificate-v2 presence (CAdES-B requirement).
    let signing_certificate_v2_present =
        first_attr_value(signed_attrs, oids::ID_AA_SIGNING_CERTIFICATE_V2).is_some();

    // Locate the signing certificate referenced by the SignerInfo sid.
    let signer_cert = find_signer_cert(&signed_data, &signer_info.sid)?;
    let signer_cert_der = signer_cert.to_der()?;

    // Re-encode the signed attributes as an explicit SET OF for verification (RFC 5652 §5.4).
    let signed_attrs_der = signed_attrs.to_der()?;

    verify_signature(
        &signer_cert,
        &signer_info.signature_algorithm.oid,
        signer_info.signature.as_bytes(),
        &signed_attrs_der,
    )?;

    // signing-time (optional).
    let signing_time = match first_attr_value(signed_attrs, oids::ID_SIGNING_TIME) {
        Some(v) => {
            // `Time` is an ASN.1 CHOICE (UTCTime | GeneralizedTime), so decode the full TLV.
            let t = x509_cert::time::Time::from_der(&v.to_der()?)?;
            let dur = t.to_unix_duration();
            Some(
                time::OffsetDateTime::from_unix_timestamp(dur.as_secs() as i64)
                    .map_err(|_| CadesError::InvalidSigningTime)?,
            )
        }
        None => None,
    };

    Ok(CadesValidation {
        signer_cert_der,
        signing_time,
        attrs_ok: true,
        signing_certificate_v2_present,
    })
}

/// Find the embedded certificate matching a `SignerIdentifier`.
fn find_signer_cert(
    signed_data: &SignedData,
    sid: &SignerIdentifier,
) -> Result<Certificate, CadesError> {
    let certs = signed_data
        .certificates
        .as_ref()
        .ok_or(CadesError::SignerCertNotFound)?;

    match sid {
        SignerIdentifier::IssuerAndSerialNumber(ias) => {
            for choice in certs.0.iter() {
                if let CertificateChoices::Certificate(cert) = choice {
                    if cert.tbs_certificate.issuer == ias.issuer
                        && cert.tbs_certificate.serial_number == ias.serial_number
                    {
                        return Ok(cert.clone());
                    }
                }
            }
            Err(CadesError::SignerCertNotFound)
        }
        // SubjectKeyIdentifier-based selection is not emitted by this crate; unsupported here.
        SignerIdentifier::SubjectKeyIdentifier(_) => Err(CadesError::SignerCertNotFound),
    }
}

/// Verify the signature value against the signing certificate's public key for the two supported
/// profiles (RSA-PKCS1-SHA256, ECDSA-P256-SHA256). `message` is the DER `SET OF` of the signed
/// attributes; the verifiers hash it with SHA-256 internally.
fn verify_signature(
    cert: &Certificate,
    sig_alg_oid: &ObjectIdentifier,
    signature: &[u8],
    message: &[u8],
) -> Result<(), CadesError> {
    if *sig_alg_oid == oids::RSA_ENCRYPTION || *sig_alg_oid == oids::SHA256_WITH_RSA_ENCRYPTION {
        verify_rsa(cert, signature, message)
    } else if *sig_alg_oid == oids::ECDSA_WITH_SHA256 {
        verify_ecdsa(cert, signature, message)
    } else {
        Err(CadesError::UnsupportedAlgorithm { oid: *sig_alg_oid })
    }
}

fn verify_rsa(cert: &Certificate, signature: &[u8], message: &[u8]) -> Result<(), CadesError> {
    use der::referenced::OwnedToRef;
    use rsa::{Pkcs1v15Sign, RsaPublicKey};
    use sha2::{Digest, Sha256};

    // DER `DigestInfo` prefix for SHA-256 (RFC 8017 §9.2). We build the DigestInfo explicitly and
    // verify with the unprefixed scheme so we do not depend on `sha2/oid` (not enabled in the
    // workspace) for the prefixed `VerifyingKey`.
    const SHA256_DIGEST_INFO_PREFIX: [u8; 19] = [
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];

    let spki = cert.tbs_certificate.subject_public_key_info.owned_to_ref();
    let public_key = RsaPublicKey::try_from(spki).map_err(|_| CadesError::InvalidPublicKey)?;

    let hash = Sha256::digest(message);
    let mut digest_info = Vec::with_capacity(SHA256_DIGEST_INFO_PREFIX.len() + hash.len());
    digest_info.extend_from_slice(&SHA256_DIGEST_INFO_PREFIX);
    digest_info.extend_from_slice(&hash);

    public_key
        .verify(Pkcs1v15Sign::new_unprefixed(), &digest_info, signature)
        .map_err(|_| CadesError::SignatureVerification)
}

fn verify_ecdsa(cert: &Certificate, signature: &[u8], message: &[u8]) -> Result<(), CadesError> {
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};
    use p256::pkcs8::DecodePublicKey;

    let spki_der = cert.tbs_certificate.subject_public_key_info.to_der()?;
    let verifying_key =
        VerifyingKey::from_public_key_der(&spki_der).map_err(|_| CadesError::InvalidPublicKey)?;
    let sig = Signature::from_der(signature).map_err(|_| CadesError::InvalidSignatureEncoding)?;
    verifying_key
        .verify(message, &sig)
        .map_err(|_| CadesError::SignatureVerification)
}
