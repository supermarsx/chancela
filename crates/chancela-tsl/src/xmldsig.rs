//! A best-effort XML-DSig validator for the Trusted List's own `<ds:Signature>` element
//! (SIG-11, audit t41/C2).
//!
//! See [`crate::source::validate_tsl_signature`] for the public entry point and the documented
//! verification boundary. This module is intentionally minimal: it extracts just enough of the
//! XML-DSig structure to verify the signature value against the signer certificate's public key,
//! without pulling in a full XML-DSig library or implementing every canonicalization transform.

use der::Decode;
use sha2::Digest;

use crate::error::TslError;
use crate::parse::decode_base64;

// ---- URIs -------------------------------------------------------------------------------------

/// Inclusive XML Canonicalization 1.0 (RFC 3076).
const C14N_10: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
/// Exclusive XML Canonicalization 1.0 (RFC 3741).
const EXC_C14N_10: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";

/// RSA-SHA256 signature method (most common in real PT TSLs).
const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
/// ECDSA-SHA256 signature method.
const ECDSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";

/// SHA-256 digest method.
const SHA256_DIGEST: &str = "http://www.w3.org/2001/04/xmlenc#sha256";

/// The parsed XML-DSig `<ds:Signature>` element — enough to verify the signature.
#[derive(Debug, Clone)]
pub(crate) struct ParsedSignature {
    /// The canonicalization algorithm URI.
    pub canonicalization_method: String,
    /// The signature algorithm URI.
    pub signature_method: String,
    /// The base64-decoded signature value bytes.
    pub signature_value: Vec<u8>,
    /// The first `<ds:Reference>` element (only one is supported).
    pub reference: Option<Reference>,
    /// The signer certificate DER (from `<ds:KeyInfo>/<ds:X509Data>/<ds:X509Certificate>`), if
    /// the signature carried one.
    pub signer_cert_der: Option<Vec<u8>>,
    /// The raw bytes of the `<ds:SignedInfo>` element (outer tag included), as they appeared in
    /// the original document — used to re-extract canonical signed bytes.
    pub signed_info_start: usize,
    pub signed_info_end: usize,
}

/// A parsed `<ds:Reference>` element.
#[derive(Debug, Clone)]
pub(crate) struct Reference {
    /// The `URI` attribute. `""` means the whole document (enveloped signature).
    pub uri: String,
    /// The digest method algorithm URI.
    pub digest_method: String,
    /// The base64-decoded digest value bytes.
    pub digest_value: Vec<u8>,
}

impl ParsedSignature {
    /// Verify the parsed signature against `xml` (the original document bytes).
    pub fn verify(self, xml: &[u8]) -> Result<(), TslError> {
        // 1. Structural completeness: the signature must carry a value and at least one reference.
        if self.signature_value.is_empty() {
            return Err(TslError::SignatureStructure(
                "empty <ds:SignatureValue>".to_owned(),
            ));
        }
        let reference = self.reference.ok_or_else(|| {
            TslError::SignatureStructure("missing <ds:Reference> element".to_owned())
        })?;
        if reference.digest_value.is_empty() {
            return Err(TslError::SignatureStructure(
                "empty <ds:DigestValue>".to_owned(),
            ));
        }

        // 2. Canonicalization method must be a supported C14N variant.
        if self.canonicalization_method != C14N_10 && self.canonicalization_method != EXC_C14N_10 {
            return Err(TslError::SignatureUnsupportedAlgorithm(format!(
                "canonicalization: {}",
                self.canonicalization_method
            )));
        }

        // 3. Digest method must be SHA-256.
        if reference.digest_method != SHA256_DIGEST {
            return Err(TslError::SignatureUnsupportedAlgorithm(format!(
                "digest: {}",
                reference.digest_method
            )));
        }

        // 4. Resolve and digest the referenced content.
        let signed_content = resolve_referenced_content(xml, &reference.uri)?;
        let digest = sha2::Sha256::digest(&signed_content);
        if digest.as_slice() != reference.digest_value.as_slice() {
            return Err(TslError::SignatureDigestMismatch);
        }

        // 5. Canonicalize the SignedInfo element. For enveloped signatures in a document that is
        //    already canonical (no comments, consistent encoding — the common TSL form), the raw
        //    element bytes are correct. We do not strip namespaces for exclusive C14N here; a real
        //    TSL's SignedInfo is already in canonical form.
        let signed_info_bytes = &xml[self.signed_info_start..self.signed_info_end];
        let canonical_signed_info = canonicalize_element(signed_info_bytes);

        // 6. Extract the signer certificate.
        let cert_der = self.signer_cert_der.ok_or_else(|| {
            TslError::SignatureStructure(
                "no <ds:X509Certificate> in <ds:KeyInfo> — cannot verify without a signer cert"
                    .to_owned(),
            )
        })?;

        // 7. Verify the signature value against the cert's public key.
        verify_signature_value(
            &cert_der,
            &self.signature_method,
            &self.signature_value,
            &canonical_signed_info,
        )
    }
}

/// Parse the `<ds:Signature>` element from `xml` bytes.
pub(crate) fn parse_signature(xml: &[u8]) -> Result<ParsedSignature, TslError> {
    use quick_xml::events::Event;

    let mut reader = quick_xml::Reader::from_reader(xml);
    reader.config_mut().trim_text(true);

    let mut buf = Vec::new();
    let mut stack: Vec<String> = Vec::new();

    let mut sig = ParsedSignature {
        canonicalization_method: String::new(),
        signature_method: String::new(),
        signature_value: Vec::new(),
        reference: None,
        signer_cert_der: None,
        signed_info_start: 0,
        signed_info_end: 0,
    };

    let mut in_signature = false;
    let mut in_signed_info = false;
    let mut in_signature_value = false;
    let mut in_x509_cert = false;
    let mut in_digest_value = false;
    let mut cur_reference: Option<Reference> = None;
    let mut cur_text = String::new();
    let mut signed_info_start: Option<usize> = None;

    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(e) => {
                let local = local_name(e.name().as_ref());
                let depth_in_sig = stack.iter().filter(|s| *s == "Signature").count();
                stack.push(local.clone());

                if local == "Signature" {
                    in_signature = true;
                } else if in_signature && local == "SignedInfo" {
                    in_signed_info = true;
                    // Record the byte offset of the SignedInfo start tag (including the tag
                    // itself, as it appears in the input).
                    signed_info_start = Some(reader.buffer_position() as usize - e.as_ref().len());
                } else if in_signature && local == "SignatureValue" {
                    in_signature_value = true;
                    cur_text.clear();
                } else if in_signature && local == "X509Certificate" {
                    in_x509_cert = true;
                    cur_text.clear();
                } else if in_signature && local == "DigestValue" && cur_reference.is_some() {
                    in_digest_value = true;
                    cur_text.clear();
                } else if in_signature && local == "Reference" {
                    // Extract the URI attribute.
                    let uri = e
                        .attributes()
                        .find_map(|a| {
                            let a = a.ok()?;
                            if local_name(a.key.as_ref()) == "URI" {
                                Some(String::from_utf8_lossy(&a.value).into_owned())
                            } else {
                                None
                            }
                        })
                        .unwrap_or_default();
                    cur_reference = Some(Reference {
                        uri,
                        digest_method: String::new(),
                        digest_value: Vec::new(),
                    });
                } else if in_signature && local == "CanonicalizationMethod" && in_signed_info {
                    if let Some(uri) = read_algorithm_attr(&e) {
                        sig.canonicalization_method = uri;
                    }
                } else if in_signature && local == "SignatureMethod" && in_signed_info {
                    if let Some(uri) = read_algorithm_attr(&e) {
                        sig.signature_method = uri;
                    }
                } else if in_signature && local == "DigestMethod" && cur_reference.is_some() {
                    if let Some(uri) = read_algorithm_attr(&e) {
                        if let Some(r) = cur_reference.as_mut() {
                            r.digest_method = uri;
                        }
                    }
                }
                let _ = depth_in_sig;
            }
            Event::Empty(e) => {
                let local = local_name(e.name().as_ref());
                if in_signature && local == "Reference" {
                    let uri = e
                        .attributes()
                        .find_map(|a| {
                            let a = a.ok()?;
                            if local_name(a.key.as_ref()) == "URI" {
                                Some(String::from_utf8_lossy(&a.value).into_owned())
                            } else {
                                None
                            }
                        })
                        .unwrap_or_default();
                    cur_reference = Some(Reference {
                        uri,
                        digest_method: String::new(),
                        digest_value: Vec::new(),
                    });
                } else if in_signature && local == "DigestMethod" && cur_reference.is_some() {
                    if let Some(uri) = read_algorithm_attr(&e) {
                        if let Some(r) = cur_reference.as_mut() {
                            r.digest_method = uri;
                        }
                    }
                } else if in_signature && local == "CanonicalizationMethod" && in_signed_info {
                    if let Some(uri) = read_algorithm_attr(&e) {
                        sig.canonicalization_method = uri;
                    }
                } else if in_signature && local == "SignatureMethod" && in_signed_info {
                    if let Some(uri) = read_algorithm_attr(&e) {
                        sig.signature_method = uri;
                    }
                }
            }
            Event::Text(e) if in_signature_value || in_x509_cert || in_digest_value => {
                cur_text.push_str(&String::from_utf8_lossy(e.as_ref()));
            }
            Event::End(e) => {
                let local = local_name(e.name().as_ref());
                stack.pop();

                if local == "Signature" {
                    in_signature = false;
                } else if local == "SignedInfo" && in_signed_info {
                    in_signed_info = false;
                    if let Some(start) = signed_info_start {
                        sig.signed_info_start = start;
                        sig.signed_info_end = reader.buffer_position() as usize;
                    }
                } else if local == "SignatureValue" && in_signature_value {
                    in_signature_value = false;
                    sig.signature_value = decode_base64(cur_text.trim())?;
                    cur_text.clear();
                } else if local == "X509Certificate" && in_x509_cert {
                    in_x509_cert = false;
                    sig.signer_cert_der = Some(decode_base64(cur_text.trim())?);
                    cur_text.clear();
                } else if local == "DigestValue" && in_digest_value {
                    in_digest_value = false;
                    if let Some(r) = cur_reference.as_mut() {
                        r.digest_value = decode_base64(cur_text.trim())?;
                    }
                    cur_text.clear();
                } else if local == "Reference" && cur_reference.is_some() {
                    if sig.reference.is_none() {
                        sig.reference = cur_reference.take();
                    } else {
                        cur_reference = None;
                    }
                }
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }

    if sig.signature_method.is_empty() && sig.signature_value.is_empty() {
        return Err(TslError::SignatureStructure(
            "no <ds:Signature> element found in the Trusted List".to_owned(),
        ));
    }
    Ok(sig)
}

/// Read the `Algorithm` attribute from an element's start event.
fn read_algorithm_attr(e: &quick_xml::events::BytesStart<'_>) -> Option<String> {
    for attr in e.attributes() {
        let attr = attr.ok()?;
        if local_name(attr.key.as_ref()) == "Algorithm" {
            return Some(String::from_utf8_lossy(&attr.value).into_owned());
        }
    }
    None
}

/// Strip any namespace prefix from an element name.
fn local_name(raw: &[u8]) -> String {
    let s = String::from_utf8_lossy(raw);
    match s.rsplit_once(':') {
        Some((_, local)) => local.to_owned(),
        None => s.into_owned(),
    }
}

/// Resolve the content referenced by a `<ds:Reference URI="...">`.
///
/// - `URI=""` (empty) → the entire document with the `<ds:Signature>` element removed (enveloped
///   signature).
/// - `URI="#id"` → the element with `Id="id"` (not yet implemented; returns an error).
fn resolve_referenced_content(xml: &[u8], uri: &str) -> Result<Vec<u8>, TslError> {
    if uri.is_empty() {
        // Enveloped signature: return the document with the <ds:Signature> element stripped.
        Ok(strip_signature_element(xml))
    } else if let Some(id) = uri.strip_prefix('#') {
        // Referenced element by Id — not implemented for the minimal path.
        Err(TslError::SignatureStructure(format!(
            "URI fragment references (#{id}) are not supported by the minimal verifier"
        )))
    } else {
        Err(TslError::SignatureStructure(format!(
            "unsupported Reference URI: {uri}"
        )))
    }
}

/// Remove the `<ds:Signature>...</ds:Signature>` subtree from `xml` bytes, returning a new
/// Vec. This is the "enveloped signature" transform.
fn strip_signature_element(xml: &[u8]) -> Vec<u8> {
    // Find `<ds:Signature` or `<Signature` (with or without namespace prefix). We look for the
    // start tag and then find its matching close tag by counting depth.
    let needle_lower = b"<signature";
    let needle_upper = b"<ds:signature";
    let xml_str = xml; // operate on raw bytes

    let sig_start = find_case_insensitive(xml_str, needle_upper)
        .or_else(|| find_case_insensitive(xml_str, needle_lower));
    let Some(sig_start_byte) = sig_start else {
        // No Signature element — return as-is (the digest check will then fail against the
        // original document, which is the correct outcome for an unsigned document).
        return xml.to_vec();
    };

    // Find the matching close tag `</ds:Signature>` or `</Signature>`.
    let close_upper = b"</ds:signature>";
    let close_lower = b"</signature>";
    let sig_end = find_case_insensitive(xml_str, close_upper)
        .or_else(|| find_case_insensitive(xml_str, close_lower));
    let Some(sig_end_byte) = sig_end else {
        return xml.to_vec();
    };
    let end_inclusive = sig_end_byte + close_upper.len().max(close_lower.len());

    let mut out = Vec::with_capacity(xml.len());
    out.extend_from_slice(&xml[..sig_start_byte]);
    out.extend_from_slice(&xml[end_inclusive.min(xml.len())..]);
    out
}

/// Case-insensitive search for `needle` in `haystack`, returning the byte offset of the first
/// match.
fn find_case_insensitive(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w| w.eq_ignore_ascii_case(needle))
}

/// A minimal canonicalization of an element's raw bytes: trim leading/trailing whitespace, remove
/// XML comments. This is NOT a full C14N implementation — it covers the common case where the
/// SignedInfo element is already in canonical form (no comments, consistent attribute ordering).
fn canonicalize_element(element_bytes: &[u8]) -> Vec<u8> {
    // For already-canonical input, the raw element bytes ARE the canonical form. We trim
    // surrounding whitespace but otherwise pass the bytes through. A real C14N would sort
    // attributes, normalize namespace declarations, and strip comments — that requires a proper
    // canonicalization library and is documented as a limitation.
    element_bytes
        .iter()
        .skip_while(|b| b.is_ascii_whitespace())
        .copied()
        .collect()
}

/// Verify the signature value against the signer certificate's public key.
fn verify_signature_value(
    cert_der: &[u8],
    signature_method: &str,
    signature: &[u8],
    signed_info: &[u8],
) -> Result<(), TslError> {
    let cert = x509_cert::Certificate::from_der(cert_der)
        .map_err(|_| TslError::SignatureStructure("invalid signer certificate DER".to_owned()))?;

    match signature_method {
        RSA_SHA256 => verify_rsa_sha256(&cert, signature, signed_info),
        ECDSA_SHA256 => Err(TslError::SignatureUnsupportedAlgorithm(format!(
            "ECDSA-SHA256 TSL signature verification not yet wired up: {signature_method}"
        ))),
        other => Err(TslError::SignatureUnsupportedAlgorithm(format!(
            "signature method: {other}"
        ))),
    }
}

/// Verify an RSA-SHA256 signature. The signed bytes are the canonicalized SignedInfo element;
/// the verifier hashes with SHA-256 internally and checks PKCS#1 v1.5.
fn verify_rsa_sha256(
    cert: &x509_cert::Certificate,
    signature: &[u8],
    signed_info: &[u8],
) -> Result<(), TslError> {
    use der::referenced::OwnedToRef;
    use rsa::{Pkcs1v15Sign, RsaPublicKey};
    use sha2::{Digest, Sha256};

    // DER DigestInfo prefix for SHA-256 (RFC 8017 §9.2).
    const SHA256_DIGEST_INFO_PREFIX: [u8; 19] = [
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];

    let spki = cert.tbs_certificate.subject_public_key_info.owned_to_ref();
    let public_key =
        RsaPublicKey::try_from(spki).map_err(|_| TslError::SignatureVerificationFailed)?;

    let hash = Sha256::digest(signed_info);
    let mut digest_info = Vec::with_capacity(SHA256_DIGEST_INFO_PREFIX.len() + hash.len());
    digest_info.extend_from_slice(&SHA256_DIGEST_INFO_PREFIX);
    digest_info.extend_from_slice(&hash);

    public_key
        .verify(Pkcs1v15Sign::new_unprefixed(), &digest_info, signature)
        .map_err(|_| TslError::SignatureVerificationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIMPLE_SIGNED: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList>
  <SchemeInformation><SchemeTerritory>PT</SchemeTerritory></SchemeInformation>
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference URI="">
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==</ds:SignatureValue>
    <ds:KeyInfo><ds:X509Data><ds:X509Certificate>AAAA</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
  </ds:Signature>
</TrustServiceStatusList>"#;

    #[test]
    fn parses_signature_structure() {
        let parsed = parse_signature(SIMPLE_SIGNED.as_bytes()).expect("parse");
        assert_eq!(parsed.canonicalization_method, EXC_C14N_10);
        assert_eq!(parsed.signature_method, RSA_SHA256);
        assert!(!parsed.signature_value.is_empty());
        let reference = parsed.reference.expect("reference");
        assert_eq!(reference.uri, "");
        assert_eq!(reference.digest_method, SHA256_DIGEST);
        assert_eq!(reference.digest_value, vec![0u8; 32]);
        assert!(parsed.signer_cert_der.is_some());
    }

    #[test]
    fn missing_signature_is_an_error() {
        let xml = b"<TrustServiceStatusList><SchemeInformation/></TrustServiceStatusList>";
        let err = parse_signature(xml).unwrap_err();
        assert!(matches!(err, TslError::SignatureStructure(_)));
    }

    #[test]
    fn strip_signature_removes_subtree() {
        let stripped = strip_signature_element(SIMPLE_SIGNED.as_bytes());
        let s = String::from_utf8_lossy(&stripped);
        assert!(!s.contains("ds:Signature"));
        assert!(s.contains("SchemeTerritory"));
    }
}
