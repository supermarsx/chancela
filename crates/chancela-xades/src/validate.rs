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
use crate::xmldsig::{
    DS_NS, DigestAlgorithm, SIG_ECDSA_SHA256, SIG_ECDSA_SHA384, SIG_ECDSA_SHA512, SIG_RSA_SHA256,
    XADES_NS,
};

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
    /// `xades:SignedProperties` is present somewhere in the document (a presence check only — see
    /// [`Self::signed_properties_signed`] for the security-relevant "is it actually signed").
    pub signed_properties_present: bool,
    /// `xades:SigningCertificateV2` is present somewhere in the document (presence only).
    pub signing_certificate_v2_present: bool,
    /// A digest-verified `ds:Reference` covers the `xades:SignedProperties` that carries the mandatory
    /// `SigningCertificateV2`/`SigningTime` — i.e. the signer actually committed to those signed
    /// properties. This is what XAdES-B validity requires; an unsigned `SignedProperties` blob
    /// appended anywhere in the document does **not** set it.
    pub signed_properties_signed: bool,
    /// The `xades:SigningTime`, if present and parseable.
    pub signing_time: Option<OffsetDateTime>,
    /// The signer certificate DER recovered from `KeyInfo`, if any.
    pub signer_cert_der: Option<Vec<u8>>,
    /// A `xades:SignatureTimeStamp` (XAdES-T) is present.
    pub signature_timestamp_present: bool,
    /// A `xades:CertificateValues` block (XAdES-LT chain material) is present.
    pub certificate_values_present: bool,
    /// A `xades:RevocationValues` block (XAdES-LT OCSP/CRL material) is present — the marker that
    /// distinguishes LT from T.
    pub revocation_values_present: bool,
}

impl XadesValidationReport {
    /// Whether the signature is valid at XAdES-B: the signature verified over `SignedInfo`, at least
    /// one reference was dereferenced and every checkable reference matched, and — the security-
    /// critical condition — a digest-verified reference actually covers the `SignedProperties`
    /// carrying the mandatory `SigningCertificateV2`/`SigningTime`. Mere presence of those elements
    /// somewhere in the document is not enough: an unsigned blob appended anywhere must not qualify.
    pub fn is_valid_b(&self) -> bool {
        self.signature_valid
            && self.references_valid
            && self.references_checked > 0
            && self.signed_properties_signed
    }
}

/// Validate a XAdES (or plain XMLDSig) signature document.
pub fn validate_xades(xml: &[u8]) -> Result<XadesValidationReport, XadesError> {
    let text = std::str::from_utf8(xml)
        .map_err(|_| XadesError::XmlParse("document is not UTF-8".into()))?;
    let doc = roxmltree::Document::parse(text).map_err(|e| XadesError::XmlParse(e.to_string()))?;

    // Fail closed on ambiguous XMLDSig `Id`s before dereferencing anything: a duplicate `Id` is the
    // lever for signature-wrapping (XSW), letting the validator digest one element while a consumer
    // reads the attacker's. Reject the whole document rather than resolve to a first-match guess.
    c14n::check_unique_ids(xml)?;

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
    let mut signed_properties_signed = false;

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
        let digest_alg = reference_digest_algorithm(r)?;

        let computed: Option<Vec<u8>> = if let Some(id) = uri.strip_prefix('#') {
            Some(digest_alg.digest(&c14n::canonicalize_element_by_id(xml, id, c14n_alg, &[])?))
        } else if uri.is_empty() {
            // Enveloped: strip the enclosing Signature and canonicalize the document.
            let exclude: Vec<&str> = signature_id.into_iter().collect();
            Some(
                digest_alg.digest(&c14n::canonicalize_document_excluding_ids(
                    xml,
                    &exclude,
                    c14n_alg,
                    &[],
                )?),
            )
        } else {
            // External detached reference — cannot dereference without the bytes.
            None
        };

        if let Some(computed) = computed {
            references_checked += 1;
            if computed.as_slice() != expected.as_slice() {
                references_valid = false;
            } else if let Some(id) = uri.strip_prefix('#') {
                // The reference's digest matched. It proves the signer committed to the
                // `SignedProperties` only when the resolved, digest-verified element actually *is*
                // the `xades:SignedProperties` carrying the mandatory `SigningCertificateV2`/
                // `SigningTime`. Resolving by the same `#id` the digest covered (Id uniqueness was
                // enforced above) prevents an unsigned blob elsewhere from satisfying the check.
                if let Some(node) = find_element_by_id(&doc, id) {
                    if node.has_tag_name((XADES_NS, "SignedProperties"))
                        && node
                            .descendants()
                            .any(|n| n.has_tag_name((XADES_NS, "SigningCertificateV2")))
                        && node
                            .descendants()
                            .any(|n| n.has_tag_name((XADES_NS, "SigningTime")))
                    {
                        signed_properties_signed = true;
                    }
                }
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
    let certificate_values_present = doc
        .descendants()
        .any(|n| n.has_tag_name((XADES_NS, "CertificateValues")));
    let revocation_values_present = doc
        .descendants()
        .any(|n| n.has_tag_name((XADES_NS, "RevocationValues")));
    let signing_time = doc
        .descendants()
        .find(|n| n.has_tag_name((XADES_NS, "SigningTime")))
        .and_then(|n| n.text())
        .and_then(parse_signing_time);

    // Level precedence: RevocationValues (+ the required T timestamp) → LT; timestamp only → T;
    // otherwise B. LTA (archive timestamp) detection is deferred with its generation.
    let level = if signature_timestamp_present && revocation_values_present {
        XadesLevel::LT
    } else if signature_timestamp_present {
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
        signed_properties_signed,
        signing_time,
        signer_cert_der,
        signature_timestamp_present,
        certificate_values_present,
        revocation_values_present,
    })
}

/// The single element carrying `Id="id"`, if any. Id uniqueness is enforced at validation entry
/// (`c14n::check_unique_ids`), so a first match is the only match.
fn find_element_by_id<'a, 'input>(
    doc: &'a roxmltree::Document<'input>,
    id: &str,
) -> Option<roxmltree::Node<'a, 'input>> {
    doc.descendants()
        .find(|n| n.is_element() && n.attribute("Id") == Some(id))
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

/// The message-digest algorithm named by a reference's `ds:DigestMethod`.
fn reference_digest_algorithm(reference: &roxmltree::Node) -> Result<DigestAlgorithm, XadesError> {
    let method = reference
        .children()
        .find(|n| n.has_tag_name((DS_NS, "DigestMethod")))
        .ok_or_else(|| XadesError::Verification("reference without DigestMethod".into()))?;
    let algorithm = method
        .attribute("Algorithm")
        .ok_or_else(|| XadesError::Verification("DigestMethod without Algorithm".into()))?;
    DigestAlgorithm::from_uri(algorithm)
        .ok_or_else(|| XadesError::Verification(format!("unsupported DigestMethod {algorithm}")))
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
        verify_ecdsa_p256(&cert, signature, message)
    } else if signature_method == SIG_ECDSA_SHA384 {
        verify_ecdsa_p384(&cert, signature, message)
    } else if signature_method == SIG_ECDSA_SHA512 {
        verify_ecdsa_p521(&cert, signature, message)
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

/// Re-encode the certificate's SPKI as DER (the form the RustCrypto `from_public_key_der` wants).
fn spki_der(cert: &Certificate) -> Result<Vec<u8>, XadesError> {
    cert.tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| XadesError::Verification("cannot re-encode SPKI".into()))
}

fn verify_ecdsa_p256(
    cert: &Certificate,
    signature: &[u8],
    message: &[u8],
) -> Result<(), XadesError> {
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};
    use p256::pkcs8::DecodePublicKey;

    let verifying_key = VerifyingKey::from_public_key_der(&spki_der(cert)?)
        .map_err(|_| XadesError::Verification("bad P-256 key".into()))?;
    // XMLDSig `ecdsa-sha256` carries the fixed-width r||s value (64 bytes), not DER. `Verifier`
    // hashes `message` with SHA-256 (the curve's associated digest).
    let sig = Signature::from_slice(signature)
        .map_err(|_| XadesError::Verification("bad ECDSA signature encoding".into()))?;
    verifying_key
        .verify(message, &sig)
        .map_err(|_| XadesError::Verification("ECDSA signature did not verify".into()))
}

fn verify_ecdsa_p384(
    cert: &Certificate,
    signature: &[u8],
    message: &[u8],
) -> Result<(), XadesError> {
    use p384::ecdsa::signature::Verifier;
    use p384::ecdsa::{Signature, VerifyingKey};
    use p384::pkcs8::DecodePublicKey;

    let verifying_key = VerifyingKey::from_public_key_der(&spki_der(cert)?)
        .map_err(|_| XadesError::Verification("bad P-384 key".into()))?;
    // `ecdsa-sha384`: fixed-width r||s (96 bytes); `Verifier` hashes with SHA-384.
    let sig = Signature::from_slice(signature)
        .map_err(|_| XadesError::Verification("bad ECDSA signature encoding".into()))?;
    verifying_key
        .verify(message, &sig)
        .map_err(|_| XadesError::Verification("ECDSA signature did not verify".into()))
}

fn verify_ecdsa_p521(
    cert: &Certificate,
    signature: &[u8],
    message: &[u8],
) -> Result<(), XadesError> {
    use p521::ecdsa::signature::Verifier;
    use p521::ecdsa::{Signature, VerifyingKey};

    // p521 0.13 has no SPKI `DecodePublicKey`; take the SEC1 public-key point straight from the
    // certificate's SubjectPublicKeyInfo BIT STRING (the uncompressed `04 || X || Y` encoding).
    let point = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| XadesError::Verification("P-521 SPKI is not octet-aligned".into()))?;
    let verifying_key = VerifyingKey::from_sec1_bytes(point)
        .map_err(|_| XadesError::Verification("bad P-521 key".into()))?;
    // `ecdsa-sha512`: fixed-width r||s (132 bytes); `Verifier` hashes with SHA-512.
    let sig = Signature::from_slice(signature)
        .map_err(|_| XadesError::Verification("bad ECDSA signature encoding".into()))?;
    verifying_key
        .verify(message, &sig)
        .map_err(|_| XadesError::Verification("ECDSA signature did not verify".into()))
}
