//! XAdES validation: parse, re-canonicalize, verify each `Reference` digest, verify the signature
//! over `SignedInfo`, and introspect the conformance level.
//!
//! Like `chancela-cades`, this verifies the **signature and its bound references** only: a valid
//! report means "the signature is cryptographically valid over the referenced content and carries a
//! well-formed XAdES `SignedProperties`", not "the signer is trusted" (trust-chain and
//! qualified-status resolution belong to `chancela-tsl`). RSA-SHA256 and ECDSA-P256-SHA256 are
//! verified, mirroring the `chancela-cades` verify patterns.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use der::{Decode, Encode};
use time::OffsetDateTime;
use x509_cert::certificate::Certificate;

use crate::c14n::{self, C14nAlgorithm};
use crate::error::XadesError;
use crate::xades::XadesLevel;
use crate::xmldsig::{DS_NS, SIG_ECDSA_SHA256, SIG_RSA_SHA256, XADES_NS, sha256};

/// The outcome of validating a XAdES signature.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct XadesValidationReport {
    /// The detected conformance level (B, or T when a signature timestamp is present).
    pub level: XadesLevel,
    /// The signature value verified over the canonical `SignedInfo`.
    pub signature_valid: bool,
    /// Every dereferenceable `Reference` digest matched its recomputed value.
    pub references_valid: bool,
    /// Number of `Reference` elements in `SignedInfo`.
    pub reference_count: usize,
    /// Number of references this call could dereference and check (external detached references in a
    /// bare signature cannot be checked without their bytes).
    pub references_checked: usize,
    /// `xades:SignedProperties` is present.
    pub signed_properties_present: bool,
    /// `xades:SigningCertificateV2` is present.
    pub signing_certificate_v2_present: bool,
    /// The `xades:SigningTime`, if present and parseable.
    pub signing_time: Option<OffsetDateTime>,
    /// The signer certificate DER recovered from `KeyInfo`, if any.
    pub signer_cert_der: Option<Vec<u8>>,
    /// A `xades:SignatureTimeStamp` (XAdES-T) is present.
    pub signature_timestamp_present: bool,
}

impl XadesValidationReport {
    /// Whether the signature is valid at XAdES-B: signature verified, all checkable references
    /// matched, and the mandatory `SignedProperties`/`SigningCertificateV2` present.
    pub fn is_valid_b(&self) -> bool {
        self.signature_valid
            && self.references_valid
            && self.signed_properties_present
            && self.signing_certificate_v2_present
    }
}

/// Validate a XAdES (or plain XMLDSig) signature document.
pub fn validate_xades(xml: &[u8]) -> Result<XadesValidationReport, XadesError> {
    let text = std::str::from_utf8(xml)
        .map_err(|_| XadesError::XmlParse("document is not UTF-8".into()))?;
    let doc = roxmltree::Document::parse(text).map_err(|e| XadesError::XmlParse(e.to_string()))?;

    let signature = doc
        .descendants()
        .find(|n| n.has_tag_name((DS_NS, "Signature")))
        .ok_or_else(|| XadesError::Verification("no ds:Signature element".into()))?;
    let signature_id = signature.attribute("Id");

    let signed_info = signature
        .children()
        .find(|n| n.has_tag_name((DS_NS, "SignedInfo")))
        .ok_or_else(|| XadesError::Verification("no ds:SignedInfo".into()))?;
    let signed_info_id = signed_info.attribute("Id").ok_or_else(|| {
        XadesError::Verification("ds:SignedInfo has no Id to canonicalize".into())
    })?;

    // --- Signature value over canonical SignedInfo ------------------------------------------------
    let signature_method = signed_info
        .children()
        .find(|n| n.has_tag_name((DS_NS, "SignatureMethod")))
        .and_then(|n| n.attribute("Algorithm"))
        .ok_or_else(|| XadesError::Verification("no SignatureMethod".into()))?
        .to_string();

    let sig_value_b64: String = signature
        .children()
        .find(|n| n.has_tag_name((DS_NS, "SignatureValue")))
        .and_then(|n| n.text())
        .ok_or_else(|| XadesError::Verification("no SignatureValue".into()))?
        .split_whitespace()
        .collect();
    let sig_value = B64
        .decode(sig_value_b64.as_bytes())
        .map_err(|_| XadesError::Verification("SignatureValue is not base64".into()))?;

    let signer_cert_der = first_x509_certificate(&signature)?;

    let si_c14n = c14n::canonicalize_element_by_id(
        xml,
        signed_info_id,
        C14nAlgorithm::ExclusiveWithoutComments,
        &[],
    )?;

    let signature_valid = match &signer_cert_der {
        Some(der) => verify_signature(der, &signature_method, &sig_value, &si_c14n).is_ok(),
        None => false,
    };

    // --- Reference digests ------------------------------------------------------------------------
    let references: Vec<roxmltree::Node> = signed_info
        .children()
        .filter(|n| n.has_tag_name((DS_NS, "Reference")))
        .collect();
    let reference_count = references.len();
    let mut references_checked = 0usize;
    let mut references_valid = true;

    for r in &references {
        let uri = r.attribute("URI").unwrap_or("");
        let expected_b64: String = r
            .descendants()
            .find(|n| n.has_tag_name((DS_NS, "DigestValue")))
            .and_then(|n| n.text())
            .ok_or_else(|| XadesError::Verification("reference without DigestValue".into()))?
            .split_whitespace()
            .collect();
        let expected = B64
            .decode(expected_b64.as_bytes())
            .map_err(|_| XadesError::Verification("DigestValue is not base64".into()))?;

        let c14n_alg = reference_c14n_algorithm(r);

        let computed: Option<[u8; 32]> = if let Some(id) = uri.strip_prefix('#') {
            Some(sha256(&c14n::canonicalize_element_by_id(
                xml,
                id,
                c14n_alg,
                &[],
            )?))
        } else if uri.is_empty() {
            // Enveloped: strip the enclosing Signature and canonicalize the document.
            let exclude: Vec<&str> = signature_id.into_iter().collect();
            Some(sha256(&c14n::canonicalize_document_excluding_ids(
                xml,
                &exclude,
                c14n_alg,
                &[],
            )?))
        } else {
            // External detached reference — cannot dereference without the bytes.
            None
        };

        if let Some(computed) = computed {
            references_checked += 1;
            if computed.as_slice() != expected.as_slice() {
                references_valid = false;
            }
        }
    }

    // --- XAdES level introspection ----------------------------------------------------------------
    let signed_properties_present = doc
        .descendants()
        .any(|n| n.has_tag_name((XADES_NS, "SignedProperties")));
    let signing_certificate_v2_present = doc
        .descendants()
        .any(|n| n.has_tag_name((XADES_NS, "SigningCertificateV2")));
    let signature_timestamp_present = doc
        .descendants()
        .any(|n| n.has_tag_name((XADES_NS, "SignatureTimeStamp")));
    let signing_time = doc
        .descendants()
        .find(|n| n.has_tag_name((XADES_NS, "SigningTime")))
        .and_then(|n| n.text())
        .and_then(parse_signing_time);

    let level = if signature_timestamp_present {
        XadesLevel::T
    } else {
        XadesLevel::B
    };

    Ok(XadesValidationReport {
        level,
        signature_valid,
        references_valid,
        reference_count,
        references_checked,
        signed_properties_present,
        signing_certificate_v2_present,
        signing_time,
        signer_cert_der,
        signature_timestamp_present,
    })
}

/// The c14n algorithm named by a reference's transforms, defaulting to exclusive-without-comments.
fn reference_c14n_algorithm(reference: &roxmltree::Node) -> C14nAlgorithm {
    reference
        .descendants()
        .filter(|n| n.has_tag_name((DS_NS, "Transform")))
        .filter_map(|n| n.attribute("Algorithm"))
        .find_map(C14nAlgorithm::from_uri)
        .unwrap_or(C14nAlgorithm::ExclusiveWithoutComments)
}

/// The first `KeyInfo/X509Data/X509Certificate`, decoded to DER.
fn first_x509_certificate(signature: &roxmltree::Node) -> Result<Option<Vec<u8>>, XadesError> {
    let cert_node = signature
        .descendants()
        .find(|n| n.has_tag_name((DS_NS, "X509Certificate")));
    match cert_node.and_then(|n| n.text()) {
        Some(b64) => {
            let compact: String = b64.split_whitespace().collect();
            let der = B64
                .decode(compact.as_bytes())
                .map_err(|_| XadesError::Verification("X509Certificate is not base64".into()))?;
            Ok(Some(der))
        }
        None => Ok(None),
    }
}

fn parse_signing_time(s: &str) -> Option<OffsetDateTime> {
    let s = s.trim();
    OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok()
}

/// Verify the XMLDSig `SignatureValue` over the canonical `SignedInfo` (`message`).
fn verify_signature(
    cert_der: &[u8],
    signature_method: &str,
    signature: &[u8],
    message: &[u8],
) -> Result<(), XadesError> {
    let cert = Certificate::from_der(cert_der)
        .map_err(|_| XadesError::Verification("signer certificate is not valid DER".into()))?;
    if signature_method == SIG_RSA_SHA256 {
        verify_rsa(&cert, signature, message)
    } else if signature_method == SIG_ECDSA_SHA256 {
        verify_ecdsa(&cert, signature, message)
    } else {
        Err(XadesError::Verification(format!(
            "unsupported SignatureMethod {signature_method}"
        )))
    }
}

fn verify_rsa(cert: &Certificate, signature: &[u8], message: &[u8]) -> Result<(), XadesError> {
    use der::referenced::OwnedToRef;
    use rsa::{Pkcs1v15Sign, RsaPublicKey};
    use sha2::{Digest, Sha256};

    // DER `DigestInfo` prefix for SHA-256 (RFC 8017 §9.2), verified with the unprefixed scheme —
    // the same approach as `chancela-cades` (avoids depending on `sha2/oid`).
    const SHA256_DIGEST_INFO_PREFIX: [u8; 19] = [
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];

    let spki = cert.tbs_certificate.subject_public_key_info.owned_to_ref();
    let public_key =
        RsaPublicKey::try_from(spki).map_err(|_| XadesError::Verification("bad RSA key".into()))?;
    let hash = Sha256::digest(message);
    let mut digest_info = Vec::with_capacity(SHA256_DIGEST_INFO_PREFIX.len() + hash.len());
    digest_info.extend_from_slice(&SHA256_DIGEST_INFO_PREFIX);
    digest_info.extend_from_slice(&hash);
    public_key
        .verify(Pkcs1v15Sign::new_unprefixed(), &digest_info, signature)
        .map_err(|_| XadesError::Verification("RSA signature did not verify".into()))
}

fn verify_ecdsa(cert: &Certificate, signature: &[u8], message: &[u8]) -> Result<(), XadesError> {
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};
    use p256::pkcs8::DecodePublicKey;

    let spki_der = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| XadesError::Verification("cannot re-encode SPKI".into()))?;
    let verifying_key = VerifyingKey::from_public_key_der(&spki_der)
        .map_err(|_| XadesError::Verification("bad P-256 key".into()))?;
    // XMLDSig `ecdsa-sha256` carries the fixed-width r||s value, not DER.
    let sig = Signature::from_slice(signature)
        .map_err(|_| XadesError::Verification("bad ECDSA signature encoding".into()))?;
    verifying_key
        .verify(message, &sig)
        .map_err(|_| XadesError::Verification("ECDSA signature did not verify".into()))
}
