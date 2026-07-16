//! Conservative offline TSA certificate-path validation.
//!
//! This module validates only the technical path properties needed before trusting a timestamp
//! token against a cached TSL-provided anchor. It does not fetch AIA, check revocation, consult an
//! OS trust store, or make a legal qualified-status claim.

use der::oid::ObjectIdentifier;
use der::{Decode, Encode};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use x509_cert::Certificate;
use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage};

use crate::error::TsaError;
use crate::oid;

const ID_KP_TIME_STAMPING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.8");

/// Successful offline certificate-path validation result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificatePathValidation {
    /// Validated path from TSA signer certificate to trust anchor, inclusive.
    pub path_der: Vec<Vec<u8>>,
    /// Index of the trust anchor selected from the supplied anchors.
    pub trust_anchor_index: usize,
}

/// Validate a TSA signer certificate path to one of the supplied trust anchors.
///
/// `intermediate_cert_ders` is optional issuer material already available to the caller, typically
/// from the timestamp token's CMS certificate set. `trust_anchor_ders` must be trusted by the
/// caller, for example because a cached and authenticated TSL returned them for a granted QTST
/// service. No issuer discovery or revocation lookup is performed.
pub fn validate_tsa_certificate_path(
    tsa_signer_cert_der: &[u8],
    intermediate_cert_ders: &[Vec<u8>],
    trust_anchor_ders: &[Vec<u8>],
    gen_time: OffsetDateTime,
) -> Result<CertificatePathValidation, TsaError> {
    if trust_anchor_ders.is_empty() {
        return Err(path_error("no trust anchors supplied"));
    }

    let leaf = parse_cert(tsa_signer_cert_der, "TSA signer")?;
    check_validity(&leaf, gen_time, "TSA signer")?;
    check_leaf_purpose(&leaf)?;

    let intermediates = intermediate_cert_ders
        .iter()
        .enumerate()
        .map(|(i, der)| parse_cert(der, &format!("intermediate {i}")).map(|cert| (i, der, cert)))
        .collect::<Result<Vec<_>, _>>()?;
    let anchors = trust_anchor_ders
        .iter()
        .enumerate()
        .map(|(i, der)| parse_cert(der, &format!("trust anchor {i}")).map(|cert| (i, der, cert)))
        .collect::<Result<Vec<_>, _>>()?;

    let mut path_der = vec![tsa_signer_cert_der.to_vec()];
    let mut current = leaf;
    let mut used_intermediates = vec![false; intermediates.len()];
    let mut ca_count_below_current = 0usize;

    loop {
        for (anchor_index, anchor_der, anchor) in &anchors {
            if current.tbs_certificate.issuer == anchor.tbs_certificate.subject {
                check_validity(anchor, gen_time, "trust anchor")?;
                check_ca_constraints(anchor, ca_count_below_current, "trust anchor")?;
                verify_child_signature(&current, anchor)?;
                path_der.push((*anchor_der).clone());
                return Ok(CertificatePathValidation {
                    path_der,
                    trust_anchor_index: *anchor_index,
                });
            }
        }

        let Some((pos, _, issuer)) = intermediates.iter().find(|(pos, _, candidate)| {
            !used_intermediates[*pos]
                && current.tbs_certificate.issuer == candidate.tbs_certificate.subject
        }) else {
            return Err(path_error(
                "no supplied issuer links TSA signer to a trust anchor",
            ));
        };

        check_validity(issuer, gen_time, "intermediate")?;
        check_ca_constraints(issuer, ca_count_below_current, "intermediate")?;
        verify_child_signature(&current, issuer)?;
        path_der.push(intermediate_cert_ders[*pos].clone());
        used_intermediates[*pos] = true;
        current = issuer.clone();
        ca_count_below_current += 1;
    }
}

fn parse_cert(der: &[u8], label: &str) -> Result<Certificate, TsaError> {
    Certificate::from_der(der).map_err(|e| path_error(format!("{label} certificate DER: {e}")))
}

fn check_validity(cert: &Certificate, when: OffsetDateTime, label: &str) -> Result<(), TsaError> {
    let not_before = offset_from_x509_time(cert.tbs_certificate.validity.not_before)?;
    let not_after = offset_from_x509_time(cert.tbs_certificate.validity.not_after)?;
    if when < not_before {
        return Err(path_error(format!(
            "{label} certificate is not yet valid at genTime"
        )));
    }
    if when > not_after {
        return Err(path_error(format!(
            "{label} certificate is expired at genTime"
        )));
    }
    Ok(())
}

fn offset_from_x509_time(t: x509_cert::time::Time) -> Result<OffsetDateTime, TsaError> {
    let secs = i64::try_from(t.to_unix_duration().as_secs())
        .map_err(|e| path_error(format!("certificate validity time out of range: {e}")))?;
    OffsetDateTime::from_unix_timestamp(secs)
        .map_err(|e| path_error(format!("certificate validity time out of range: {e}")))
}

fn check_leaf_purpose(cert: &Certificate) -> Result<(), TsaError> {
    let eku = cert
        .tbs_certificate
        .get::<ExtendedKeyUsage>()
        .map_err(|e| path_error(format!("TSA signer EKU extension: {e}")))?
        .ok_or_else(|| path_error("TSA signer certificate has no extendedKeyUsage"))?
        .1;
    if !eku.0.contains(&ID_KP_TIME_STAMPING) {
        return Err(path_error(
            "TSA signer EKU does not include id-kp-timeStamping",
        ));
    }

    if let Some((_, usage)) = cert
        .tbs_certificate
        .get::<KeyUsage>()
        .map_err(|e| path_error(format!("TSA signer keyUsage extension: {e}")))?
        && !usage.digital_signature()
    {
        return Err(path_error(
            "TSA signer keyUsage is present but does not allow digitalSignature",
        ));
    }

    Ok(())
}

fn check_ca_constraints(
    cert: &Certificate,
    ca_count_below: usize,
    label: &str,
) -> Result<(), TsaError> {
    let basic = cert
        .tbs_certificate
        .get::<BasicConstraints>()
        .map_err(|e| path_error(format!("{label} basicConstraints extension: {e}")))?
        .ok_or_else(|| path_error(format!("{label} certificate has no basicConstraints")))?;
    if !basic.1.ca {
        return Err(path_error(format!(
            "{label} basicConstraints does not mark a CA"
        )));
    }
    if let Some(max) = basic.1.path_len_constraint
        && ca_count_below > usize::from(max)
    {
        return Err(path_error(format!("{label} pathLenConstraint exceeded")));
    }

    if let Some((_, usage)) = cert
        .tbs_certificate
        .get::<KeyUsage>()
        .map_err(|e| path_error(format!("{label} keyUsage extension: {e}")))?
        && !usage.key_cert_sign()
    {
        return Err(path_error(format!(
            "{label} keyUsage is present but does not allow keyCertSign"
        )));
    }

    Ok(())
}

fn verify_child_signature(child: &Certificate, issuer: &Certificate) -> Result<(), TsaError> {
    if child.signature_algorithm.oid != child.tbs_certificate.signature.oid {
        return Err(path_error(
            "certificate signatureAlgorithm does not match TBSCertificate signature",
        ));
    }
    let signature = child
        .signature
        .as_bytes()
        .ok_or_else(|| path_error("certificate signature BIT STRING has unused bits"))?;
    let tbs_der = child
        .tbs_certificate
        .to_der()
        .map_err(|e| path_error(format!("TBSCertificate DER: {e}")))?;

    if child.signature_algorithm.oid == oid::SHA256_WITH_RSA_ENCRYPTION {
        verify_cert_rsa_sha256(issuer, signature, &tbs_der)
    } else if child.signature_algorithm.oid == oid::ECDSA_WITH_SHA256 {
        verify_cert_ecdsa_sha256(issuer, signature, &tbs_der)
    } else {
        Err(TsaError::UnsupportedSignatureAlgorithm {
            oid: child.signature_algorithm.oid.to_string(),
        })
    }
}

fn verify_cert_rsa_sha256(
    issuer: &Certificate,
    signature: &[u8],
    message: &[u8],
) -> Result<(), TsaError> {
    use der::referenced::OwnedToRef;
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
        RsaPublicKey::try_from(spki).map_err(|e| path_error(format!("issuer RSA key: {e}")))?;
    let hash = Sha256::digest(message);
    let mut digest_info = Vec::with_capacity(SHA256_DIGEST_INFO_PREFIX.len() + hash.len());
    digest_info.extend_from_slice(&SHA256_DIGEST_INFO_PREFIX);
    digest_info.extend_from_slice(&hash);
    public_key
        .verify(Pkcs1v15Sign::new_unprefixed(), &digest_info, signature)
        .map_err(|_| TsaError::SignatureVerificationFailed)
}

fn verify_cert_ecdsa_sha256(
    issuer: &Certificate,
    signature: &[u8],
    message: &[u8],
) -> Result<(), TsaError> {
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};
    use p256::pkcs8::DecodePublicKey;

    let spki_der = issuer
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| path_error(format!("issuer SPKI DER: {e}")))?;
    let verifying_key = VerifyingKey::from_public_key_der(&spki_der)
        .map_err(|e| path_error(format!("issuer ECDSA key: {e}")))?;
    let sig = Signature::from_der(signature).map_err(|_| TsaError::InvalidSignatureEncoding)?;
    verifying_key
        .verify(message, &sig)
        .map_err(|_| TsaError::SignatureVerificationFailed)
}

fn path_error(message: impl Into<String>) -> TsaError {
    TsaError::CertificatePath(message.into())
}
