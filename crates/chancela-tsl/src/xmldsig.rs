//! An XML-DSig validator for the Trusted List's own `<ds:Signature>` element (SIG-11, audit
//! t41/C2).
//!
//! See [`crate::source::validate_tsl_signature`] for the public entry point and the documented
//! verification boundary. This module extracts just enough of the XML-DSig structure to verify the
//! signature value against the signer certificate's public key, routing canonicalization through the
//! real C14N implementation in [`crate::c14n`] (wp26 E2) rather than hashing raw source bytes.
//!
//! # Canonicalization: real C14N with an already-canonical fast path
//! XML-DSig signs the *canonical* form of `<ds:SignedInfo>` (per the declared
//! `CanonicalizationMethod`) and of each `<ds:Reference>`'s transformed content. For genuinely
//! non-canonical real-world EU LOTL / member-state TSLs, reconstructing those canonical bytes is
//! mandatory, so this verifier feeds the relevant subtree — with the ancestor `xmlns` context
//! hoisted onto `<ds:SignedInfo>` as C14N requires — through [`crate::c14n::canonicalize`].
//!
//! Both the SignedInfo signature check and the reference digest check are evaluated against a small
//! ordered set of candidate byte streams: the real C14N output **and** the raw source octets (the
//! historical "already-canonical fast path"). Verification succeeds if *any* candidate matches. This
//! is safe — every candidate is still cryptographically bound to the one signature/digest, so an
//! attacker cannot forge either form without the signer's key, and tampering perturbs *all*
//! candidates — while keeping lists that were signed over already-serialized-canonical bytes valid.

use der::{Decode, Encode};
use sha2::Digest;

use crate::c14n::C14nAlgorithm;
use crate::error::TslError;
use crate::parse::decode_base64;
use crate::source::TslTrustAnchors;

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
/// XML-DSig enveloped-signature transform.
const ENVELOPED_SIGNATURE_TRANSFORM: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

/// The parsed XML-DSig `<ds:Signature>` element — enough to verify the signature.
#[derive(Debug, Clone)]
pub(crate) struct ParsedSignature {
    /// Number of `<ds:Signature>` elements seen. The minimal verifier supports exactly one.
    pub signature_count: usize,
    /// The canonicalization algorithm URI.
    pub canonicalization_method: String,
    /// The signature algorithm URI.
    pub signature_method: String,
    /// The base64-decoded signature value bytes.
    pub signature_value: Vec<u8>,
    /// The first `<ds:Reference>` element (only one is supported).
    pub reference: Option<Reference>,
    /// Number of `<ds:Reference>` elements seen. XML-DSig requires every reference to be checked;
    /// this minimal verifier rejects multi-reference signatures instead of ignoring extras.
    pub reference_count: usize,
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
    /// Explicit transform algorithm URIs carried by this reference.
    pub transforms: Vec<String>,
    /// The base64-decoded digest value bytes.
    pub digest_value: Vec<u8>,
}

impl ParsedSignature {
    /// Verify the parsed signature against `xml` (the original document bytes), then require the
    /// signer certificate to match a configured trust anchor.
    ///
    /// Steps 1-7 establish that the signature is internally consistent (structure, digests, and
    /// the signature value verify against the certificate the list itself carried). Step 8 is the
    /// trust decision (audit t41/C2 part H4): a self-signed list is internally consistent too, so
    /// the signer certificate MUST match `anchors` (the EU LOTL / national scheme signing
    /// certificate) or the list is reported [`TslError::SignatureUntrusted`]. An empty anchor set
    /// trusts nothing (fail closed).
    pub fn verify(self, xml: &[u8], anchors: &TslTrustAnchors) -> Result<(), TslError> {
        // 1. Structural completeness: the signature must carry a value and at least one reference.
        if self.signature_count != 1 {
            return Err(TslError::SignatureStructure(format!(
                "expected exactly one <ds:Signature> element, found {}",
                self.signature_count
            )));
        }
        if self.signed_info_start == 0 && self.signed_info_end == 0 {
            return Err(TslError::SignatureStructure(
                "missing <ds:SignedInfo> element".to_owned(),
            ));
        }
        if self.canonicalization_method.is_empty() {
            return Err(TslError::SignatureStructure(
                "missing <ds:CanonicalizationMethod Algorithm>".to_owned(),
            ));
        }
        if self.signature_method.is_empty() {
            return Err(TslError::SignatureStructure(
                "missing <ds:SignatureMethod Algorithm>".to_owned(),
            ));
        }
        if self.signature_value.is_empty() {
            return Err(TslError::SignatureStructure(
                "empty <ds:SignatureValue>".to_owned(),
            ));
        }
        if self.reference_count > 1 {
            return Err(TslError::SignatureStructure(format!(
                "multiple <ds:Reference> elements are not supported by the minimal verifier: {}",
                self.reference_count
            )));
        }
        let reference = self.reference.ok_or_else(|| {
            TslError::SignatureStructure("missing <ds:Reference> element".to_owned())
        })?;
        if reference.digest_method.is_empty() {
            return Err(TslError::SignatureStructure(
                "missing <ds:DigestMethod Algorithm>".to_owned(),
            ));
        }
        for transform in &reference.transforms {
            match transform.as_str() {
                ENVELOPED_SIGNATURE_TRANSFORM | C14N_10 | EXC_C14N_10 => {}
                other => {
                    return Err(TslError::SignatureUnsupportedAlgorithm(format!(
                        "transform: {other}"
                    )));
                }
            }
        }
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

        // 4. Resolve and digest the referenced content. The digest must match one of the candidate
        //    forms of the transformed content: the real C14N output (when the reference carries a
        //    C14N transform) or the raw transformed octets (the already-canonical fast path).
        let signed_content =
            resolve_referenced_content(xml, &reference.uri, &reference.transforms)?;
        if !reference_digest_matches(&reference, &signed_content) {
            return Err(TslError::SignatureDigestMismatch);
        }

        // 5. Build the candidate canonical forms of the SignedInfo element. The primary candidate is
        //    the real C14N of the namespace-hoisted subtree (the ancestor `xmlns`/`xmlns:ds`
        //    declarations that `<ds:SignedInfo>` inherits are hoisted onto its start tag first, as
        //    C14N requires in-scope ancestor namespaces); the fallback is the raw element bytes, for
        //    lists that were signed over already-serialized-canonical SignedInfo octets.
        let signed_info_candidates = signed_info_candidates(
            xml,
            self.signed_info_start,
            self.signed_info_end,
            &self.canonicalization_method,
        );

        // 6. Extract the signer certificate.
        let cert_der = self.signer_cert_der.ok_or_else(|| {
            TslError::SignatureStructure(
                "no <ds:X509Certificate> in <ds:KeyInfo> — cannot verify without a signer cert"
                    .to_owned(),
            )
        })?;

        // 7. Verify the signature value against the cert's public key over any candidate SignedInfo
        //    form. This only proves the list is self-consistent — a self-signed list passes too.
        verify_signature_value(
            &cert_der,
            &self.signature_method,
            &self.signature_value,
            &signed_info_candidates,
        )?;

        // 8. Trust decision (audit t41/C2 part H4): the signer certificate the list carried about
        //    itself must match a configured trust anchor (the EU LOTL / national scheme signing
        //    certificate). Without this gate, anyone supplying TSL bytes could present a
        //    self-signed list declaring arbitrary CAs "qualified" and have it verified. An empty
        //    anchor set (nothing configured) matches nothing, so this fails closed.
        if !anchors.is_anchored(&cert_der) {
            return Err(TslError::SignatureUntrusted(if anchors.is_empty() {
                "no trust anchor configured (set CHANCELA_TSL_TRUST_ANCHOR or \
                 CHANCELA_TSL_TRUST_ANCHOR_SHA256 to the EU LOTL / national scheme signing \
                 certificate)"
                    .to_owned()
            } else {
                "the list's signer certificate does not match any configured trust anchor"
                    .to_owned()
            }));
        }

        Ok(())
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
        reference_count: 0,
        signer_cert_der: None,
        signed_info_start: 0,
        signed_info_end: 0,
        signature_count: 0,
    };

    let mut saw_signature = false;
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
                stack.push(local.clone());

                if local == "Signature" {
                    sig.signature_count += 1;
                    saw_signature = true;
                    in_signature = true;
                } else if in_signature && local == "SignedInfo" {
                    in_signed_info = true;
                    // Record the byte offset of the SignedInfo start tag (including the tag
                    // itself, as it appears in the input).
                    signed_info_start = Some(
                        (reader.buffer_position() as usize).saturating_sub(e.as_ref().len() + 2),
                    );
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
                    sig.reference_count += 1;
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
                        transforms: Vec::new(),
                        digest_value: Vec::new(),
                    });
                } else if in_signature && local == "Transform" && cur_reference.is_some() {
                    if let Some(uri) = read_algorithm_attr(&e) {
                        if let Some(r) = cur_reference.as_mut() {
                            r.transforms.push(uri);
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
                } else if in_signature && local == "DigestMethod" && cur_reference.is_some() {
                    if let Some(uri) = read_algorithm_attr(&e) {
                        if let Some(r) = cur_reference.as_mut() {
                            r.digest_method = uri;
                        }
                    }
                }
            }
            Event::Empty(e) => {
                let local = local_name(e.name().as_ref());
                if local == "Signature" {
                    sig.signature_count += 1;
                    saw_signature = true;
                } else if in_signature && local == "Reference" {
                    sig.reference_count += 1;
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
                        transforms: Vec::new(),
                        digest_value: Vec::new(),
                    });
                } else if in_signature && local == "Transform" && cur_reference.is_some() {
                    if let Some(uri) = read_algorithm_attr(&e) {
                        if let Some(r) = cur_reference.as_mut() {
                            r.transforms.push(uri);
                        }
                    }
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

    if !saw_signature {
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
/// - `URI="#id"` → the document root element carrying `Id`, `ID`, `id`, or `xml:id` equal to
///   `id`. Non-root fragment targets are rejected because they do not authenticate the whole TSL.
fn resolve_referenced_content(
    xml: &[u8],
    uri: &str,
    transforms: &[String],
) -> Result<Vec<u8>, TslError> {
    if uri.is_empty() {
        // Enveloped signature: return the document with the <ds:Signature> element stripped.
        Ok(strip_signature_element(xml))
    } else if let Some(id) = uri.strip_prefix('#') {
        if id.is_empty() {
            return Err(TslError::SignatureStructure(
                "empty Reference URI fragment".to_owned(),
            ));
        }
        let target = find_unique_id_element(xml, id)?;
        if !target.is_document_root || target.local_name != "TrustServiceStatusList" {
            return Err(TslError::SignatureStructure(format!(
                "Reference URI fragment (#{id}) does not identify the TrustServiceStatusList root"
            )));
        }

        let mut content = target.bytes;
        if transforms
            .iter()
            .any(|transform| transform == ENVELOPED_SIGNATURE_TRANSFORM)
        {
            content = strip_signature_element(&content);
        }
        Ok(content)
    } else {
        Err(TslError::SignatureStructure(format!(
            "unsupported Reference URI: {uri}"
        )))
    }
}

#[derive(Debug)]
struct ReferencedElement {
    bytes: Vec<u8>,
    local_name: String,
    is_document_root: bool,
}

fn find_unique_id_element(xml: &[u8], id: &str) -> Result<ReferencedElement, TslError> {
    use quick_xml::events::Event;

    let mut reader = quick_xml::Reader::from_reader(xml);
    reader.config_mut().trim_text(false);

    let mut buf = Vec::new();
    let mut element_depth = 0usize;
    let mut matched_count = 0usize;
    let mut first_match: Option<ReferencedElement> = None;
    let mut active_match: Option<(usize, usize, String, bool)> = None;

    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(e) => {
                let is_document_root = element_depth == 0;
                let local = local_name(e.name().as_ref());
                let event_end = reader.buffer_position() as usize;
                let event_start = find_event_start(xml, event_end)?;
                let is_match = element_has_id(&e, id);

                if let Some((depth, _, _, _)) = active_match.as_mut() {
                    *depth += 1;
                }

                if is_match {
                    matched_count += 1;
                    if active_match.is_none() && first_match.is_none() {
                        active_match = Some((1, event_start, local.clone(), is_document_root));
                    }
                }

                element_depth = element_depth.saturating_add(1);
            }
            Event::Empty(e) => {
                let is_document_root = element_depth == 0;
                if element_has_id(&e, id) {
                    matched_count += 1;
                    if first_match.is_none() {
                        let event_end = reader.buffer_position() as usize;
                        let event_start = find_event_start(xml, event_end)?;
                        first_match = Some(ReferencedElement {
                            bytes: xml[event_start..event_end].to_vec(),
                            local_name: local_name(e.name().as_ref()),
                            is_document_root,
                        });
                    }
                }
            }
            Event::End(_) => {
                element_depth = element_depth.saturating_sub(1);
                if let Some((depth, start, local_name, is_document_root)) = active_match.as_mut() {
                    *depth = depth.saturating_sub(1);
                    if *depth == 0 {
                        let start = *start;
                        let local_name = local_name.clone();
                        let is_document_root = *is_document_root;
                        let event_end = reader.buffer_position() as usize;
                        if first_match.is_none() {
                            first_match = Some(ReferencedElement {
                                bytes: xml[start..event_end].to_vec(),
                                local_name,
                                is_document_root,
                            });
                        }
                        active_match = None;
                    }
                }
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }

    match matched_count {
        0 => Err(TslError::SignatureStructure(format!(
            "Reference URI fragment (#{id}) did not match an ID-bearing element"
        ))),
        1 => first_match.ok_or_else(|| {
            TslError::SignatureStructure(format!(
                "Reference URI fragment (#{id}) did not resolve to a complete element"
            ))
        }),
        count => Err(TslError::SignatureStructure(format!(
            "Reference URI fragment (#{id}) matched multiple ID-bearing elements: {count}"
        ))),
    }
}

fn element_has_id(e: &quick_xml::events::BytesStart<'_>, expected: &str) -> bool {
    e.attributes().any(|attr| {
        let Ok(attr) = attr else {
            return false;
        };
        if !matches!(local_name(attr.key.as_ref()).as_str(), "Id" | "ID" | "id") {
            return false;
        }
        String::from_utf8_lossy(&attr.value) == expected
    })
}

fn find_event_start(xml: &[u8], event_end: usize) -> Result<usize, TslError> {
    xml[..event_end]
        .iter()
        .rposition(|b| *b == b'<')
        .ok_or_else(|| {
            TslError::SignatureStructure("could not locate XML element start".to_owned())
        })
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

/// Whether the reference's `<ds:DigestValue>` matches the SHA-256 of any candidate form of the
/// resolved (transform-applied) content: the real C14N output — when the reference carries an
/// explicit C14N transform — or the raw octets (already-canonical fast path). Accepting either form
/// is safe: both are bound to the one digest, so tampering the content perturbs every candidate.
fn reference_digest_matches(reference: &Reference, resolved_content: &[u8]) -> bool {
    // Candidate 1: the raw transformed octets.
    if sha2::Sha256::digest(resolved_content).as_slice() == reference.digest_value.as_slice() {
        return true;
    }
    // Candidate 2..: C14N of the resolved content per each explicit C14N transform on the reference
    // (the enveloped-signature transform resolves to `None` and is skipped). A canonicalization
    // error simply removes that candidate — the raw candidate above stays the fail-closed default.
    for transform in &reference.transforms {
        if let Some(alg) = C14nAlgorithm::from_uri(transform) {
            if let Ok(canon) = crate::c14n::canonicalize(resolved_content, alg) {
                if sha2::Sha256::digest(&canon).as_slice() == reference.digest_value.as_slice() {
                    return true;
                }
            }
        }
    }
    false
}

/// Build the ordered candidate byte streams for the `<ds:SignedInfo>` signature check.
///
/// The primary candidate is the real C14N of the namespace-hoisted subtree, canonicalized under the
/// declared `CanonicalizationMethod`; the fallback is the raw element bytes (leading whitespace
/// trimmed) for lists signed over already-serialized-canonical SignedInfo octets. The signature must
/// verify over at least one candidate.
fn signed_info_candidates(
    xml: &[u8],
    start: usize,
    end: usize,
    canonicalization_method: &str,
) -> Vec<Vec<u8>> {
    let mut candidates: Vec<Vec<u8>> = Vec::with_capacity(2);

    // Primary: real C14N over the hoisted subtree (best-effort; skipped on any failure).
    if let Some(alg) = C14nAlgorithm::from_uri(canonicalization_method) {
        if let Ok(hoisted) = hoist_signed_info_namespaces(xml, start, end) {
            if let Ok(canon) = crate::c14n::canonicalize(&hoisted, alg) {
                candidates.push(canon);
            }
        }
    }

    // Fallback: the raw SignedInfo bytes with leading whitespace trimmed.
    let raw: Vec<u8> = xml[start..end]
        .iter()
        .skip_while(|b| b.is_ascii_whitespace())
        .copied()
        .collect();
    if !candidates.contains(&raw) {
        candidates.push(raw);
    }
    candidates
}

/// Hoist the ancestor in-scope namespace declarations onto the `<ds:SignedInfo>` start tag.
///
/// `<ds:SignedInfo>` inherits `xmlns`/`xmlns:ds` (and any other in-scope prefixes) from its ancestor
/// `<ds:Signature>` / the document root, but the sliced subtree bytes do not carry them. C14N
/// requires in-scope ancestor namespaces to be present on the apex element, so this walks the
/// document to the SignedInfo element, collects every ancestor declaration (nearer declarations
/// overriding farther ones), and injects each one not already declared on SignedInfo itself into its
/// start tag. Inclusive C14N then renders them all; exclusive C14N drops the unused ones — both
/// correct. The built-in `xml` prefix is never hoisted (C14N pre-binds it).
fn hoist_signed_info_namespaces(xml: &[u8], start: usize, end: usize) -> Result<Vec<u8>, TslError> {
    use quick_xml::events::Event;

    if end > xml.len() || start >= end {
        return Err(TslError::SignatureStructure(
            "invalid SignedInfo byte range".to_owned(),
        ));
    }

    // 1. Collect ancestor in-scope namespaces by walking to the first <...SignedInfo> element,
    //    maintaining a stack of per-element declarations.
    let mut reader = quick_xml::Reader::from_reader(xml);
    reader.config_mut().trim_text(false);
    let mut buf = Vec::new();
    let mut stack: Vec<Vec<(String, String)>> = Vec::new();
    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(e) => {
                if local_name(e.name().as_ref()) == "SignedInfo" {
                    break;
                }
                stack.push(namespace_decls(&e));
            }
            Event::End(_) => {
                stack.pop();
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    // Flatten to an in-scope map, nearer ancestors overriding farther ones.
    let mut in_scope: Vec<(String, String)> = Vec::new();
    for decls in &stack {
        for (prefix, uri) in decls {
            if let Some(slot) = in_scope.iter_mut().find(|(p, _)| p == prefix) {
                slot.1 = uri.clone();
            } else {
                in_scope.push((prefix.clone(), uri.clone()));
            }
        }
    }

    // 2. Determine SignedInfo's own declarations (its own decls win, so never re-inject those).
    let slice = &xml[start..end];
    let own = first_element_namespace_decls(slice)?;
    let own_prefixes: std::collections::HashSet<&str> =
        own.iter().map(|(p, _)| p.as_str()).collect();

    // 3. Inject the missing ancestor declarations right after the SignedInfo qualified name.
    let mut injected = String::new();
    for (prefix, uri) in &in_scope {
        if prefix == "xml" || own_prefixes.contains(prefix.as_str()) {
            continue;
        }
        if prefix.is_empty() {
            injected.push_str(" xmlns=\"");
        } else {
            injected.push_str(" xmlns:");
            injected.push_str(prefix);
            injected.push_str("=\"");
        }
        push_escaped_attr_value(&mut injected, uri);
        injected.push('"');
    }

    if injected.is_empty() {
        return Ok(slice.to_vec());
    }

    let tag_end = start_tag_end(slice)?;
    let mut out = Vec::with_capacity(slice.len() + injected.len());
    out.extend_from_slice(&slice[..tag_end]);
    out.extend_from_slice(injected.as_bytes());
    out.extend_from_slice(&slice[tag_end..]);
    Ok(out)
}

/// The `xmlns`/`xmlns:*` declarations literally present on a start/empty tag as `(prefix, uri)`
/// (empty prefix = the default namespace).
fn namespace_decls(e: &quick_xml::events::BytesStart<'_>) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for attr in e.attributes() {
        let Ok(attr) = attr else { continue };
        let key = String::from_utf8_lossy(attr.key.as_ref()).into_owned();
        let value = String::from_utf8_lossy(&attr.value).into_owned();
        if key == "xmlns" {
            out.push((String::new(), value));
        } else if let Some(prefix) = key.strip_prefix("xmlns:") {
            out.push((prefix.to_owned(), value));
        }
    }
    out
}

/// The namespace declarations on the first element of `element_bytes` (the SignedInfo start tag).
fn first_element_namespace_decls(element_bytes: &[u8]) -> Result<Vec<(String, String)>, TslError> {
    use quick_xml::events::Event;

    let mut reader = quick_xml::Reader::from_reader(element_bytes);
    reader.config_mut().trim_text(false);
    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(e) | Event::Empty(e) => return Ok(namespace_decls(&e)),
            Event::Eof => {
                return Err(TslError::SignatureStructure(
                    "SignedInfo subtree has no element".to_owned(),
                ));
            }
            _ => {}
        }
        buf.clear();
    }
}

/// The byte index of the `>` that closes the start tag at the front of `slice`, honouring quoted
/// attribute values so a `>` inside an attribute is not mistaken for the tag end.
fn start_tag_end(slice: &[u8]) -> Result<usize, TslError> {
    let mut quote: Option<u8> = None;
    for (i, &b) in slice.iter().enumerate() {
        match quote {
            Some(q) => {
                if b == q {
                    quote = None;
                }
            }
            None => match b {
                b'"' | b'\'' => quote = Some(b),
                b'>' => return Ok(i),
                _ => {}
            },
        }
    }
    Err(TslError::SignatureStructure(
        "malformed SignedInfo start tag (no closing '>')".to_owned(),
    ))
}

/// Minimal XML attribute-value escaping so a hoisted namespace URI stays well-formed when re-parsed
/// by the canonicalizer (which performs the authoritative C14N escaping).
fn push_escaped_attr_value(out: &mut String, value: &str) {
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(ch),
        }
    }
}

/// Extract the DER of the signer certificate from `<ds:KeyInfo>/<ds:X509Data>/<ds:X509Certificate>`,
/// for downstream certificate-path building (wp26 E5 `certpath`, E4 `lotl`). Returns `Ok(None)` when
/// the document carries no `<ds:Signature>` or the signature carries no embedded certificate.
// Exposed ahead of its in-crate consumers (E4 `lotl.rs`, E5 `certpath.rs`), which land in parallel.
#[allow(dead_code)]
pub(crate) fn extract_signer_cert(xml: &[u8]) -> Result<Option<Vec<u8>>, TslError> {
    match parse_signature(xml) {
        Ok(parsed) => Ok(parsed.signer_cert_der),
        // No signature element at all is not an error for extraction — there is simply no cert.
        Err(TslError::SignatureStructure(_)) => Ok(None),
        Err(err) => Err(err),
    }
}

/// Verify the signature value against the signer certificate's public key over any candidate
/// SignedInfo form; success on the first candidate that verifies.
fn verify_signature_value(
    cert_der: &[u8],
    signature_method: &str,
    signature: &[u8],
    signed_info_candidates: &[Vec<u8>],
) -> Result<(), TslError> {
    let cert = x509_cert::Certificate::from_der(cert_der)
        .map_err(|_| TslError::SignatureStructure("invalid signer certificate DER".to_owned()))?;

    match signature_method {
        RSA_SHA256 => verify_rsa_sha256(&cert, signature, signed_info_candidates),
        ECDSA_SHA256 => verify_ecdsa_sha256(&cert, signature, signed_info_candidates),
        other => Err(TslError::SignatureUnsupportedAlgorithm(format!(
            "signature method: {other}"
        ))),
    }
}

/// Verify an RSA-SHA256 signature over any candidate SignedInfo form. The verifier hashes each
/// candidate with SHA-256 and checks PKCS#1 v1.5.
fn verify_rsa_sha256(
    cert: &x509_cert::Certificate,
    signature: &[u8],
    signed_info_candidates: &[Vec<u8>],
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

    for signed_info in signed_info_candidates {
        let hash = Sha256::digest(signed_info);
        let mut digest_info = Vec::with_capacity(SHA256_DIGEST_INFO_PREFIX.len() + hash.len());
        digest_info.extend_from_slice(&SHA256_DIGEST_INFO_PREFIX);
        digest_info.extend_from_slice(&hash);
        if public_key
            .verify(Pkcs1v15Sign::new_unprefixed(), &digest_info, signature)
            .is_ok()
        {
            return Ok(());
        }
    }
    Err(TslError::SignatureVerificationFailed)
}

/// Verify a P-256 ECDSA-SHA256 XML-DSig signature over any candidate SignedInfo form. XML-DSig
/// carries ECDSA signatures as the fixed-width raw `r || s` value; DER `ECDSA-Sig-Value` encodings
/// are rejected here.
fn verify_ecdsa_sha256(
    cert: &x509_cert::Certificate,
    signature: &[u8],
    signed_info_candidates: &[Vec<u8>],
) -> Result<(), TslError> {
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};
    use p256::pkcs8::DecodePublicKey;

    if signature.len() != 64 {
        return Err(TslError::SignatureStructure(format!(
            "ECDSA-SHA256 XML-DSig signature value must be raw r||s (64 bytes), got {} bytes",
            signature.len()
        )));
    }

    let spki_der = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| TslError::SignatureVerificationFailed)?;
    let verifying_key = VerifyingKey::from_public_key_der(&spki_der)
        .map_err(|_| TslError::SignatureVerificationFailed)?;
    let sig =
        Signature::from_slice(signature).map_err(|_| TslError::SignatureVerificationFailed)?;

    for signed_info in signed_info_candidates {
        if verifying_key.verify(signed_info, &sig).is_ok() {
            return Ok(());
        }
    }
    Err(TslError::SignatureVerificationFailed)
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
        assert!(reference.transforms.is_empty());
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

    const NS_DS: &str = "http://www.w3.org/2000/09/xmldsig#";

    /// A document whose `<ds:SignedInfo>` inherits `xmlns:ds` from the root and uses self-closing
    /// empty children — i.e. genuinely NOT in canonical form.
    fn non_canonical_signed_info_doc(digest_b64: &str, sig_b64: &str, cert_b64: &str) -> String {
        format!(
            "<TrustServiceStatusList xmlns:ds=\"{NS_DS}\">\
             <SchemeInformation><SchemeTerritory>PT</SchemeTerritory></SchemeInformation>\
             <ds:Signature>\
             <ds:SignedInfo>\n  <ds:CanonicalizationMethod Algorithm=\"{EXC_C14N_10}\"/>\n  \
             <ds:SignatureMethod Algorithm=\"{ECDSA_SHA256}\"/>\n  \
             <ds:Reference URI=\"\">\n    <ds:DigestMethod Algorithm=\"{SHA256_DIGEST}\"/>\n    \
             <ds:DigestValue>{digest_b64}</ds:DigestValue>\n  </ds:Reference>\n</ds:SignedInfo>\
             <ds:SignatureValue>{sig_b64}</ds:SignatureValue>\
             <ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert_b64}</ds:X509Certificate>\
             </ds:X509Data></ds:KeyInfo>\
             </ds:Signature>\
             </TrustServiceStatusList>"
        )
    }

    fn signed_info_offsets(doc: &str) -> (usize, usize) {
        let start = doc.find("<ds:SignedInfo>").expect("SignedInfo start");
        let end = doc.find("</ds:SignedInfo>").expect("SignedInfo end") + "</ds:SignedInfo>".len();
        (start, end)
    }

    #[test]
    fn hoist_injects_inherited_ds_namespace() {
        // `<ds:SignedInfo>` declares no namespaces itself; `xmlns:ds` is on the root. The hoist must
        // carry that inherited declaration onto the SignedInfo start tag.
        let doc = non_canonical_signed_info_doc("AAAA", "AAAA", "AAAA");
        let (start, end) = signed_info_offsets(&doc);
        let hoisted = hoist_signed_info_namespaces(doc.as_bytes(), start, end).expect("hoist");
        let hs = String::from_utf8(hoisted).expect("utf8");
        assert!(
            hs.starts_with(&format!("<ds:SignedInfo xmlns:ds=\"{NS_DS}\">")),
            "hoisted SignedInfo must carry the inherited xmlns:ds, got: {hs}"
        );
        // The hoisted subtree must canonicalize cleanly.
        assert!(crate::c14n::canonicalize(hs.as_bytes(), C14nAlgorithm::Exclusive).is_ok());
    }

    #[test]
    fn signed_info_primary_candidate_is_the_real_c14n_output() {
        // The first (primary) candidate handed to hashing MUST equal the real C14N of the
        // namespace-hoisted subtree, and MUST differ from the raw fallback (empty children expanded,
        // xmlns:ds hoisted) — proving canonicalization is genuinely routed through `c14n`.
        let doc = non_canonical_signed_info_doc("AAAA", "AAAA", "AAAA");
        let (start, end) = signed_info_offsets(&doc);
        let candidates = signed_info_candidates(doc.as_bytes(), start, end, EXC_C14N_10);

        let hoisted = hoist_signed_info_namespaces(doc.as_bytes(), start, end).expect("hoist");
        let expected = crate::c14n::canonicalize(&hoisted, C14nAlgorithm::Exclusive).expect("c14n");
        assert_eq!(
            candidates.first().map(Vec::as_slice),
            Some(expected.as_slice()),
            "primary SignedInfo candidate must be the real C14N output"
        );
        assert!(
            candidates.len() >= 2,
            "raw fallback candidate must also be present"
        );
        assert_ne!(
            candidates[0], candidates[1],
            "for a non-canonical SignedInfo the C14N form must differ from the raw bytes"
        );
    }

    #[test]
    fn non_canonical_signed_info_verifies_over_its_c14n_form() {
        use std::str::FromStr;

        use der::asn1::{BitString, ObjectIdentifier};
        use p256::ecdsa::SigningKey;
        use p256::ecdsa::signature::Signer;
        use rsa::rand_core::OsRng;
        use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
        use x509_cert::name::Name;
        use x509_cert::serial_number::SerialNumber;
        use x509_cert::time::Validity;
        use x509_cert::{Certificate, TbsCertificate, Version};

        fn base64_standard(bytes: &[u8]) -> String {
            const TABLE: &[u8; 64] =
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
            for chunk in bytes.chunks(3) {
                let b0 = chunk[0];
                let b1 = *chunk.get(1).unwrap_or(&0);
                let b2 = *chunk.get(2).unwrap_or(&0);
                out.push(TABLE[(b0 >> 2) as usize] as char);
                out.push(TABLE[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
                out.push(if chunk.len() > 1 {
                    TABLE[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char
                } else {
                    '='
                });
                out.push(if chunk.len() > 2 {
                    TABLE[(b2 & 0x3f) as usize] as char
                } else {
                    '='
                });
            }
            out
        }

        // A P-256 self-signed cert carrying the signing key.
        let key = SigningKey::random(&mut OsRng);
        let spki = SubjectPublicKeyInfoOwned::from_key(*key.verifying_key()).expect("spki");
        let sig_alg = AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2"),
            parameters: None,
        };
        let name = Name::from_str("CN=E3 c14n routing test signer").expect("name");
        let validity =
            Validity::from_now(std::time::Duration::from_secs(365 * 24 * 3600)).expect("validity");
        let cert = Certificate {
            tbs_certificate: TbsCertificate {
                version: Version::V3,
                serial_number: SerialNumber::new(&[7u8]).expect("serial"),
                signature: sig_alg.clone(),
                issuer: name.clone(),
                validity,
                subject: name,
                subject_public_key_info: spki,
                issuer_unique_id: None,
                subject_unique_id: None,
                extensions: None,
            },
            signature_algorithm: sig_alg,
            signature: BitString::from_bytes(&[0u8; 64]).expect("bitstring"),
        };
        let cert_der = cert.to_der().expect("cert der");
        let cert_b64 = base64_standard(&cert_der);

        // The reference (URI="", no C14N transform) digests the raw document minus the Signature.
        // strip_signature yields exactly the surrounding bytes, so precompute the digest over them.
        let placeholder = base64_standard(&[0x11u8; 64]);
        let doc0 = non_canonical_signed_info_doc(
            &base64_standard(&sha2::Sha256::digest(b"placeholder")),
            &placeholder,
            &cert_b64,
        );
        let stripped = strip_signature_element(doc0.as_bytes());
        let digest_b64 = base64_standard(&sha2::Sha256::digest(&stripped));

        // Rebuild the document with the correct reference digest, then locate SignedInfo and sign
        // over the PRIMARY (real C14N) candidate — the form a conforming XML-DSig signer signs.
        let doc0 = non_canonical_signed_info_doc(&digest_b64, &placeholder, &cert_b64);
        let (start, end) = signed_info_offsets(&doc0);
        let candidates = signed_info_candidates(doc0.as_bytes(), start, end, EXC_C14N_10);
        let canonical = candidates[0].clone();
        let raw_fallback = candidates[1].clone();
        assert_ne!(
            canonical, raw_fallback,
            "test must exercise a non-canonical SignedInfo"
        );

        let signature: p256::ecdsa::Signature = key.sign(&canonical);
        let sig_b64 = base64_standard(&signature.to_bytes());
        let doc = doc0.replace(&placeholder, &sig_b64);

        // The full verifier accepts it, anchored to the embedded cert — the signature verifies via
        // the C14N candidate, since it was signed over the canonical (not raw) SignedInfo.
        let anchors = TslTrustAnchors::new().with_cert_der(&cert_der);
        let parsed = parse_signature(doc.as_bytes()).expect("parse");
        parsed
            .verify(doc.as_bytes(), &anchors)
            .expect("non-canonical SignedInfo must verify over its C14N form");

        // And the raw fallback ALONE would NOT verify — proving the C14N candidate did the work.
        let sig_raw = signature.to_bytes().to_vec();
        assert!(
            verify_ecdsa_sha256(&cert, &sig_raw, &[raw_fallback]).is_err(),
            "raw bytes alone must not verify a signature made over the canonical form"
        );
    }

    #[test]
    fn extract_signer_cert_returns_embedded_der_or_none() {
        // The placeholder fixture carries a 3-byte "cert" (base64 "AAAA" = 0x00 0x00 0x00).
        let doc = non_canonical_signed_info_doc("AAAA", "AAAA", "AAAA");
        let extracted = extract_signer_cert(doc.as_bytes()).expect("extract");
        assert_eq!(extracted, Some(vec![0u8, 0u8, 0u8]));

        // No <ds:Signature> at all -> Ok(None), not an error.
        let none = extract_signer_cert(b"<TrustServiceStatusList/>").expect("extract none");
        assert_eq!(none, None);
    }
}
