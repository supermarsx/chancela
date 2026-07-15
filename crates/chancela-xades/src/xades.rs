//! XAdES QualifyingProperties over the XMLDSig core in [`crate::xmldsig`].
//!
//! Level **B** is implemented fully: `SignedProperties` carrying `SigningTime` and
//! `SigningCertificateV2` (certificate digest + `IssuerSerialV2`), wired into `SignedInfo` as a
//! `Reference` of `Type` [`crate::xmldsig::REF_TYPE_SIGNED_PROPERTIES`] and embedded as a
//! `<ds:Object><xades:QualifyingProperties>`. Enveloping, detached, and enveloped packaging are all
//! supported (ASiC-E consumes the detached form).
//!
//! Level **T** is implemented on top of B (decision recorded in `.orchestration/logs/t67-e2.md`):
//! after the signature value exists, the exclusive-C14N of `<ds:SignatureValue>` is timestamped via
//! an RFC 3161 token (obtained by the caller from `chancela-tsa`) and embedded as an
//! `UnsignedSignatureProperties/SignatureTimeStamp/EncapsulatedTimeStamp`. The unsigned-properties
//! container is structured so LT (revocation values) and LTA (archive timestamp) slot in without
//! re-architecture; their constructors currently return [`XadesError::NotYetSupported`] (owned by
//! t67-e10 / e7 per the plan timeline).

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use chancela_cades::{RawSignature, SignatureAlgorithm};
use der::{Decode, Encode, Sequence};
use time::OffsetDateTime;
use time::macros::format_description;
use x509_cert::certificate::Certificate;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::serial_number::SerialNumber;

use crate::c14n::{self, C14nAlgorithm};
use crate::error::XadesError;
use crate::xmldsig::{
    self, DS_NS, DigestAlgorithm, REF_TYPE_SIGNED_PROPERTIES, Reference, XADES_NS, XmlDsigBuilder,
    sha256,
};

/// The XAdES conformance level.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum XadesLevel {
    /// Baseline (`SignedProperties` only).
    B,
    /// B + a signature timestamp over `SignatureValue`.
    T,
    /// T + validation material (`CertificateValues` + `RevocationValues`). Finalized via
    /// [`AssembledXades::with_lt`].
    LT,
    /// LT + an archive timestamp. Deferred (see `crates/chancela-xades/TESTING.md`).
    LTA,
}

/// Signing-time and canonicalization context for a XAdES signature.
#[derive(Clone, Debug)]
pub struct XadesContext {
    /// The `SigningTime` asserted in `SignedProperties`.
    pub signing_time: OffsetDateTime,
}

/// Validation material embedded in a XAdES-LT signature: the certificate chain plus the OCSP
/// responses and/or CRLs that establish the signer chain's revocation status, so the signature
/// stays verifiable long-term without re-fetching from the (possibly retired) CA endpoints.
///
/// The shapes map one-to-one onto `chancela_signing::revocation`'s validated output
/// (`DssEvidence { certificates, ocsp_responses, crls }`): the ASiC/API layers collect the material
/// through that module and pass it here — this crate does not fetch revocation itself.
#[derive(Clone, Debug, Default)]
pub struct ValidationMaterial {
    /// DER X.509 certificates for `xades:CertificateValues` (the issuer/CA chain and any OCSP
    /// responder certificate — material a validator needs but that is not in `ds:KeyInfo`).
    pub certificates: Vec<Vec<u8>>,
    /// DER `OCSPResponse` bytes for `xades:RevocationValues/OCSPValues/EncapsulatedOCSPValue`.
    pub ocsp_responses: Vec<Vec<u8>>,
    /// DER `CertificateList` (CRL) bytes for `xades:RevocationValues/CRLValues/EncapsulatedCRLValue`.
    pub crls: Vec<Vec<u8>>,
}

impl ValidationMaterial {
    /// Whether there is no revocation evidence at all (no OCSP and no CRL). LT requires at least one.
    pub fn has_revocation(&self) -> bool {
        !self.ocsp_responses.is_empty() || !self.crls.is_empty()
    }
}

/// How the signed data objects relate to the signature.
pub enum SignaturePackaging {
    /// The data objects are embedded in the signature as `<ds:Object>` elements.
    Enveloping(Vec<EnvelopingObject>),
    /// The data objects are external; each `Reference` names one by URI and the digest is taken over
    /// the supplied bytes (ASiC-E consumes this form).
    Detached(Vec<DetachedRef>),
    /// The signature is inserted as the last child of the supplied XML document's root element.
    Enveloped(EnvelopedDocument),
}

/// An embedded (enveloping) data object.
pub struct EnvelopingObject {
    /// The `Id` of the `<ds:Object>` (referenced as `URI="#id"`).
    pub id: String,
    /// The object's content.
    pub content: ObjectContent,
}

/// The content of an enveloping `<ds:Object>`.
pub enum ObjectContent {
    /// Character data (escaped on emit).
    Text(String),
    /// Verbatim, well-formed XML markup (must be namespace self-contained).
    Xml(String),
}

/// A detached reference to external data.
pub struct DetachedRef {
    /// The `URI` attribute value (e.g. a file name inside an ASiC container).
    pub uri: String,
    /// The referenced bytes, hashed as-is for `DigestValue`.
    pub bytes: Vec<u8>,
}

/// A document to be enveloped-signed.
pub struct EnvelopedDocument {
    /// The XML document; the `<ds:Signature>` is spliced in as the root's last child.
    pub xml: Vec<u8>,
}

/// A XAdES signing request.
pub struct XadesSignRequest {
    /// The `Id` assigned to `<ds:Signature>`.
    pub signature_id: String,
    /// The signer's DER certificate (for `SigningCertificateV2` and `KeyInfo`).
    pub signing_cert_der: Vec<u8>,
    /// The algorithm the signer will use — must match the returned [`RawSignature`].
    pub sig_alg: SignatureAlgorithm,
    /// The requested conformance level.
    pub level: XadesLevel,
    /// Signing-time context.
    pub context: XadesContext,
    /// How the data objects are packaged.
    pub packaging: SignaturePackaging,
}

/// RFC 5035 `IssuerSerial` (`SEQUENCE { issuer GeneralNames, serialNumber CertificateSerialNumber }`),
/// the DER content carried, base64-encoded, in XAdES `IssuerSerialV2`.
#[derive(Sequence)]
struct IssuerSerial {
    issuer: Vec<GeneralName>,
    serial_number: SerialNumber,
}

/// A XAdES signature prepared up to the point of signing: the `SignedInfo` digest is exposed for
/// the card/CMD/CSC/soft signer, and [`Self::assemble`] wraps the returned [`RawSignature`].
pub struct PreparedXades {
    builder: XmlDsigBuilder,
    packaging: SignaturePackaging,
    level: XadesLevel,
    sig_alg: SignatureAlgorithm,
    signed_info_digest: Vec<u8>,
}

impl PreparedXades {
    /// The digest the signing device signs: the exclusive-C14N of `<ds:SignedInfo>` hashed under the
    /// signature's matched digest (SHA-256 for RSA/P-256 → 32 bytes, SHA-384 for P-384 → 48 bytes,
    /// SHA-512 for P-521 → 64 bytes).
    pub fn signed_info_digest(&self) -> Vec<u8> {
        self.signed_info_digest.clone()
    }

    /// Assemble the signature around `raw`. For enveloping/detached packaging the result is a
    /// standalone `<ds:Signature>` document; for enveloped packaging it is the original document
    /// with the signature spliced in.
    pub fn assemble(self, raw: &RawSignature) -> Result<AssembledXades, XadesError> {
        if raw.algorithm != self.sig_alg {
            return Err(XadesError::Verification(format!(
                "signer produced {:?} but the SignedInfo declares {:?}",
                raw.algorithm, self.sig_alg
            )));
        }
        let signature_xml = self.builder.assemble(raw)?;
        let signature_value_id = self.builder.signature_value_element_id();

        let xml = match &self.packaging {
            SignaturePackaging::Enveloping(_) | SignaturePackaging::Detached(_) => signature_xml,
            SignaturePackaging::Enveloped(doc) => splice_enveloped(&doc.xml, &signature_xml)?,
        };

        Ok(AssembledXades {
            xml,
            level: self.level,
            signature_value_id,
        })
    }
}

/// An assembled XAdES signature. At level B it is complete; at level T the caller obtains an RFC
/// 3161 token over [`Self::signature_timestamp_digest`] and finalizes with
/// [`Self::with_signature_timestamp`].
pub struct AssembledXades {
    xml: Vec<u8>,
    level: XadesLevel,
    signature_value_id: String,
}

impl AssembledXades {
    /// The requested conformance level.
    pub fn level(&self) -> XadesLevel {
        self.level
    }

    /// The finished XML for a level-B signature. Returns [`XadesError::NotYetSupported`] if the level
    /// requires a timestamp / validation material that has not been applied.
    pub fn into_bytes(self) -> Result<Vec<u8>, XadesError> {
        match self.level {
            XadesLevel::B => Ok(self.xml),
            XadesLevel::T => Err(XadesError::NotYetSupported(
                "XAdES-T requires a signature timestamp; call with_signature_timestamp".into(),
            )),
            XadesLevel::LT => Err(XadesError::NotYetSupported(
                "XAdES-LT requires a signature timestamp and validation material; call with_lt"
                    .into(),
            )),
            XadesLevel::LTA => Err(XadesError::NotYetSupported("XAdES-LTA (deferred)".into())),
        }
    }

    /// The digest to timestamp for XAdES-T: SHA-256 over the exclusive-C14N of `<ds:SignatureValue>`.
    pub fn signature_timestamp_digest(&self) -> Result<[u8; 32], XadesError> {
        let c14n = c14n::canonicalize_element_by_id(
            &self.xml,
            &self.signature_value_id,
            C14nAlgorithm::ExclusiveWithoutComments,
            &[],
        )?;
        Ok(sha256(&c14n))
    }

    /// Embed an RFC 3161 `TimeStampToken` (DER `ContentInfo`, e.g. `chancela_tsa::Timestamp::token_der`)
    /// as the XAdES-T `SignatureTimeStamp`, producing the finished XAdES-T XML.
    pub fn with_signature_timestamp(self, token_der: &[u8]) -> Result<Vec<u8>, XadesError> {
        let usp = signature_timestamp_property(token_der);
        splice_unsigned_signature_properties(self.xml, &usp)
    }

    /// Finalize a XAdES-**LT** signature: the XAdES-T `SignatureTimeStamp` plus
    /// `xades:CertificateValues` (the chain) and `xades:RevocationValues` (OCSP responses / CRLs)
    /// under `UnsignedSignatureProperties`, so the signature carries the material a validator needs
    /// to establish revocation status long-term. LT presupposes the T timestamp; `material` must
    /// carry at least one OCSP response or CRL ([`ValidationMaterial::has_revocation`]).
    ///
    /// `timestamp_token_der` is the same RFC 3161 token XAdES-T uses (over
    /// [`Self::signature_timestamp_digest`]). This crate does not fetch revocation — the caller
    /// collects `material` (e.g. via `chancela_signing::revocation`).
    pub fn with_lt(
        self,
        timestamp_token_der: &[u8],
        material: &ValidationMaterial,
    ) -> Result<Vec<u8>, XadesError> {
        if !material.has_revocation() {
            return Err(XadesError::Verification(
                "XAdES-LT requires at least one OCSP response or CRL in the validation material"
                    .into(),
            ));
        }
        let mut usp = signature_timestamp_property(timestamp_token_der);
        if !material.certificates.is_empty() {
            usp.push_str("<xades:CertificateValues>");
            for cert in &material.certificates {
                usp.push_str("<xades:EncapsulatedX509Certificate>");
                usp.push_str(&B64.encode(cert));
                usp.push_str("</xades:EncapsulatedX509Certificate>");
            }
            usp.push_str("</xades:CertificateValues>");
        }
        usp.push_str("<xades:RevocationValues>");
        if !material.crls.is_empty() {
            usp.push_str("<xades:CRLValues>");
            for crl in &material.crls {
                usp.push_str("<xades:EncapsulatedCRLValue>");
                usp.push_str(&B64.encode(crl));
                usp.push_str("</xades:EncapsulatedCRLValue>");
            }
            usp.push_str("</xades:CRLValues>");
        }
        if !material.ocsp_responses.is_empty() {
            usp.push_str("<xades:OCSPValues>");
            for ocsp in &material.ocsp_responses {
                usp.push_str("<xades:EncapsulatedOCSPValue>");
                usp.push_str(&B64.encode(ocsp));
                usp.push_str("</xades:EncapsulatedOCSPValue>");
            }
            usp.push_str("</xades:OCSPValues>");
        }
        usp.push_str("</xades:RevocationValues>");
        splice_unsigned_signature_properties(self.xml, &usp)
    }
}

/// The `xades:SignatureTimeStamp/EncapsulatedTimeStamp` property carrying an RFC 3161 token.
fn signature_timestamp_property(token_der: &[u8]) -> String {
    format!(
        "<xades:SignatureTimeStamp><xades:EncapsulatedTimeStamp>{}</xades:EncapsulatedTimeStamp>\
         </xades:SignatureTimeStamp>",
        B64.encode(token_der)
    )
}

/// Splice `usp_inner` (a sequence of `UnsignedSignatureProperties` child elements) into the
/// assembled signature as `<xades:UnsignedProperties><xades:UnsignedSignatureProperties>…`, placed
/// immediately before the closing `</xades:QualifyingProperties>`.
fn splice_unsigned_signature_properties(
    xml: Vec<u8>,
    usp_inner: &str,
) -> Result<Vec<u8>, XadesError> {
    let unsigned = format!(
        "<xades:UnsignedProperties><xades:UnsignedSignatureProperties>{usp_inner}\
         </xades:UnsignedSignatureProperties></xades:UnsignedProperties>"
    );
    let text = String::from_utf8(xml)
        .map_err(|_| XadesError::Verification("assembled XML is not UTF-8".into()))?;
    let marker = "</xades:QualifyingProperties>";
    let pos = text.find(marker).ok_or_else(|| {
        XadesError::Verification("no QualifyingProperties to attach unsigned properties to".into())
    })?;
    let mut out = String::with_capacity(text.len() + unsigned.len());
    out.push_str(&text[..pos]);
    out.push_str(&unsigned);
    out.push_str(&text[pos..]);
    Ok(out.into_bytes())
}

/// Format an `OffsetDateTime` as an XML Schema `dateTime` in UTC (`YYYY-MM-DDThh:mm:ssZ`).
fn format_signing_time(t: OffsetDateTime) -> Result<String, XadesError> {
    let fmt = format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z");
    t.to_offset(time::UtcOffset::UTC)
        .format(&fmt)
        .map_err(|e| XadesError::Verification(format!("signing-time formatting: {e}")))
}

/// XML-escape character data for element content.
fn escape_xml_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            c => out.push(c),
        }
    }
    out
}

/// Build the `<xades:SignedProperties>` element (with an `Id`). The `CertDigest` is taken under the
/// signature's matched `digest_alg`, so the whole XAdES profile uses a single hash.
fn build_signed_properties(
    signed_props_id: &str,
    signing_cert_der: &[u8],
    signing_time: OffsetDateTime,
    digest_alg: DigestAlgorithm,
) -> Result<String, XadesError> {
    let cert = Certificate::from_der(signing_cert_der)
        .map_err(|_| XadesError::Verification("signer certificate is not valid DER".into()))?;

    let cert_digest = digest_alg.digest(signing_cert_der);
    let issuer_serial = IssuerSerial {
        issuer: vec![GeneralName::DirectoryName(
            cert.tbs_certificate.issuer.clone(),
        )],
        serial_number: cert.tbs_certificate.serial_number.clone(),
    };
    let issuer_serial_der = issuer_serial
        .to_der()
        .map_err(|e| XadesError::Verification(format!("IssuerSerialV2 DER: {e}")))?;

    let mut s = String::new();
    s.push_str(&format!(
        "<xades:SignedProperties Id=\"{signed_props_id}\">"
    ));
    s.push_str("<xades:SignedSignatureProperties>");
    s.push_str(&format!(
        "<xades:SigningTime>{}</xades:SigningTime>",
        format_signing_time(signing_time)?
    ));
    s.push_str("<xades:SigningCertificateV2><xades:Cert>");
    s.push_str("<xades:CertDigest>");
    s.push_str(&format!(
        "<ds:DigestMethod Algorithm=\"{}\"></ds:DigestMethod>",
        digest_alg.uri()
    ));
    s.push_str(&format!(
        "<ds:DigestValue>{}</ds:DigestValue>",
        B64.encode(cert_digest)
    ));
    s.push_str("</xades:CertDigest>");
    s.push_str(&format!(
        "<xades:IssuerSerialV2>{}</xades:IssuerSerialV2>",
        B64.encode(&issuer_serial_der)
    ));
    s.push_str("</xades:Cert></xades:SigningCertificateV2>");
    s.push_str("</xades:SignedSignatureProperties>");
    // SignedDataObjectProperties is optional at B; emitted empty for structural completeness.
    s.push_str("<xades:SignedDataObjectProperties></xades:SignedDataObjectProperties>");
    s.push_str("</xades:SignedProperties>");
    Ok(s)
}

/// The digest of `<xades:SignedProperties>` over its exclusive-C14N, computed exactly as a validator
/// would from the assembled document (namespaces declared in an ancestor context), under
/// `digest_alg`.
fn signed_properties_digest(
    signed_props_xml: &str,
    signed_props_id: &str,
    signature_id: &str,
    digest_alg: DigestAlgorithm,
) -> Result<Vec<u8>, XadesError> {
    let wrapper = format!(
        "<xades:QualifyingProperties xmlns:ds=\"{DS_NS}\" xmlns:xades=\"{XADES_NS}\" \
         Target=\"#{signature_id}\">{signed_props_xml}</xades:QualifyingProperties>"
    );
    let c14n = c14n::canonicalize_element_by_id(
        wrapper.as_bytes(),
        signed_props_id,
        C14nAlgorithm::ExclusiveWithoutComments,
        &[],
    )?;
    Ok(digest_alg.digest(&c14n))
}

/// The digest of an enveloping `<ds:Object>` over its exclusive-C14N, under `digest_alg`.
fn object_digest(
    object_xml: &str,
    object_id: &str,
    digest_alg: DigestAlgorithm,
) -> Result<Vec<u8>, XadesError> {
    let wrapper = format!("<ds:Signature xmlns:ds=\"{DS_NS}\">{object_xml}</ds:Signature>");
    let c14n = c14n::canonicalize_element_by_id(
        wrapper.as_bytes(),
        object_id,
        C14nAlgorithm::ExclusiveWithoutComments,
        &[],
    )?;
    Ok(digest_alg.digest(&c14n))
}

/// Splice a `<ds:Signature>` as the last child of an XML document's root element.
fn splice_enveloped(document: &[u8], signature_xml: &[u8]) -> Result<Vec<u8>, XadesError> {
    let doc = std::str::from_utf8(document)
        .map_err(|_| XadesError::XmlParse("enveloped document is not UTF-8".into()))?;
    let sig = std::str::from_utf8(signature_xml)
        .map_err(|_| XadesError::XmlParse("signature is not UTF-8".into()))?;
    let close = doc
        .rfind("</")
        .ok_or_else(|| XadesError::XmlParse("enveloped document has no closing tag".into()))?;
    let mut out = String::with_capacity(doc.len() + sig.len());
    out.push_str(&doc[..close]);
    out.push_str(sig);
    out.push_str(&doc[close..]);
    Ok(out.into_bytes())
}

/// Prepare a XAdES signature: build `SignedProperties`, compute every `Reference` digest, and expose
/// the `SignedInfo` digest for signing.
pub fn prepare_xades(req: XadesSignRequest) -> Result<PreparedXades, XadesError> {
    if matches!(req.level, XadesLevel::LTA) {
        return Err(XadesError::NotYetSupported(
            "XAdES-LTA (archive timestamp) is deferred; see crates/chancela-xades/TESTING.md"
                .into(),
        ));
    }

    let digest_alg = xmldsig::digest_algorithm_for(req.sig_alg)?;

    let signed_props_id = format!("{}-signedprops", req.signature_id);
    let signed_props_xml = build_signed_properties(
        &signed_props_id,
        &req.signing_cert_der,
        req.context.signing_time,
        digest_alg,
    )?;
    let sp_digest = signed_properties_digest(
        &signed_props_xml,
        &signed_props_id,
        &req.signature_id,
        digest_alg,
    )?;

    let mut builder = XmlDsigBuilder::new(req.signature_id.clone(), req.sig_alg);
    builder.declare_ns("xades", XADES_NS);
    builder.add_cert(req.signing_cert_der.clone());

    // Data-object references (packaging-specific), plus embedded objects for the enveloping form.
    match &req.packaging {
        SignaturePackaging::Enveloping(objects) => {
            for obj in objects {
                let inner = match &obj.content {
                    ObjectContent::Text(t) => escape_xml_text(t),
                    ObjectContent::Xml(x) => x.clone(),
                };
                let object_xml = format!("<ds:Object Id=\"{}\">{}</ds:Object>", obj.id, inner);
                let digest = object_digest(&object_xml, &obj.id, digest_alg)?;
                builder.add_reference(Reference {
                    uri: format!("#{}", obj.id),
                    id: None,
                    ref_type: None,
                    transforms: vec![C14nAlgorithm::ExclusiveWithoutComments.uri().to_string()],
                    digest,
                });
                builder.add_object(object_xml);
            }
        }
        SignaturePackaging::Detached(refs) => {
            for r in refs {
                builder.add_reference(Reference {
                    uri: r.uri.clone(),
                    id: None,
                    ref_type: None,
                    transforms: Vec::new(),
                    digest: digest_alg.digest(&r.bytes),
                });
            }
        }
        SignaturePackaging::Enveloped(doc) => {
            let c14n = c14n::canonicalize_document(
                &doc.xml,
                C14nAlgorithm::ExclusiveWithoutComments,
                &[],
            )?;
            builder.add_reference(Reference {
                uri: String::new(),
                id: None,
                ref_type: None,
                transforms: vec![
                    xmldsig::TRANSFORM_ENVELOPED.to_string(),
                    C14nAlgorithm::ExclusiveWithoutComments.uri().to_string(),
                ],
                digest: digest_alg.digest(&c14n),
            });
        }
    }

    // The XAdES SignedProperties reference (must come after data references per ETSI, but order is
    // not signature-critical).
    builder.add_reference(Reference {
        uri: format!("#{signed_props_id}"),
        id: None,
        ref_type: Some(REF_TYPE_SIGNED_PROPERTIES.to_string()),
        transforms: vec![C14nAlgorithm::ExclusiveWithoutComments.uri().to_string()],
        digest: sp_digest,
    });

    // Embed the QualifyingProperties (SignedProperties) as a ds:Object.
    builder.add_object(format!(
        "<ds:Object><xades:QualifyingProperties Target=\"#{}\">{}</xades:QualifyingProperties></ds:Object>",
        req.signature_id, signed_props_xml
    ));

    let signed_info_digest = builder.signed_info_digest()?;

    Ok(PreparedXades {
        builder,
        packaging: req.packaging,
        level: req.level,
        sig_alg: req.sig_alg,
        signed_info_digest,
    })
}
