//! XMLDSig build: `<Signature>` / `<SignedInfo>` / `<Reference>` / `<KeyInfo>` over a
//! [`chancela_cades::RawSignature`], in enveloped / detached / enveloping forms.
//!
//! The two-phase seam mirrors CAdES/PAdES: build the `<SignedInfo>`, expose its canonical-form
//! digest for the card/CMD/CSC/soft signer via [`XmlDsigBuilder::signed_info_digest`], then wrap
//! the returned [`RawSignature`] into the finished `<Signature>` via [`XmlDsigBuilder::assemble`].
//!
//! Canonicalization of `SignedInfo` (and of same-document references) uses exclusive C14N without a
//! PrefixList: exclusive C14N is context-independent for the visibly-utilized `ds` namespace, so
//! the `SignedInfo` canonical form is identical whether computed standalone at signing time or
//! re-extracted from the assembled document at validation time.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use chancela_cades::{RawSignature, SignatureAlgorithm};
use sha2::{Digest, Sha256};

use crate::c14n::{self, C14nAlgorithm};
use crate::error::XadesError;

/// The XMLDSig namespace.
pub const DS_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
/// The XAdES v1.3.2 namespace.
pub const XADES_NS: &str = "http://uri.etsi.org/01903/v1.3.2#";

/// `DigestMethod` algorithm URI for SHA-256.
pub const DIGEST_SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
/// `SignatureMethod` algorithm URI for RSASSA-PKCS1-v1_5 over SHA-256.
pub const SIG_RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
/// `SignatureMethod` algorithm URI for ECDSA-P256 over SHA-256.
pub const SIG_ECDSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
/// Enveloped-signature transform URI.
pub const TRANSFORM_ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
/// `Type` attribute value marking a `Reference` to the XAdES `SignedProperties`.
pub const REF_TYPE_SIGNED_PROPERTIES: &str = "http://uri.etsi.org/01903#SignedProperties";

/// The `SignatureMethod` algorithm URI for a [`RawSignature`] profile.
pub fn signature_method_uri(alg: SignatureAlgorithm) -> Result<&'static str, XadesError> {
    match alg {
        SignatureAlgorithm::RsaPkcs1Sha256 => Ok(SIG_RSA_SHA256),
        SignatureAlgorithm::EcdsaP256Sha256 => Ok(SIG_ECDSA_SHA256),
        other => Err(XadesError::NotYetSupported(format!(
            "no XMLDSig SignatureMethod for {other:?}"
        ))),
    }
}

/// SHA-256 of `bytes`.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

/// Convert a signing device's [`RawSignature`] signature value into the raw form XMLDSig requires
/// for `SignatureValue`.
///
/// XMLDSig's `ecdsa-sha256` carries the fixed-width `r || s` concatenation (64 bytes for P-256),
/// **not** the DER `ECDSA-Sig-Value` that [`RawSignature`] holds (that DER form is what CMS/CAdES
/// use). RSA-PKCS1 signatures are identical in both encodings.
pub fn signature_value_bytes(raw: &RawSignature) -> Result<Vec<u8>, XadesError> {
    match raw.algorithm {
        SignatureAlgorithm::RsaPkcs1Sha256 => Ok(raw.signature.clone()),
        SignatureAlgorithm::EcdsaP256Sha256 => {
            use p256::ecdsa::Signature;
            let sig = Signature::from_der(&raw.signature)
                .map_err(|_| XadesError::Verification("ECDSA signature is not valid DER".into()))?;
            Ok(sig.to_bytes().to_vec())
        }
        other => Err(XadesError::NotYetSupported(format!(
            "no XMLDSig SignatureValue encoding for {other:?}"
        ))),
    }
}

/// A prepared XMLDSig `<Reference>`: URI + ordered transforms + the digest of the transformed,
/// canonicalized referenced content.
#[derive(Clone, Debug)]
pub struct Reference {
    /// The `URI` attribute value (`""` for a whole-document enveloped reference).
    pub uri: String,
    /// Optional `Id` on the reference.
    pub id: Option<String>,
    /// Optional `Type` attribute (e.g. [`REF_TYPE_SIGNED_PROPERTIES`]).
    pub ref_type: Option<String>,
    /// Transform algorithm URIs, applied in order.
    pub transforms: Vec<String>,
    /// SHA-256 `DigestValue` over the (transformed) referenced content.
    pub digest: [u8; 32],
}

/// Builder for a single `<ds:Signature>` over a set of prepared references and embedded objects.
pub struct XmlDsigBuilder {
    signature_id: String,
    sig_alg: SignatureAlgorithm,
    references: Vec<Reference>,
    /// Serialized `<ds:Object>…</ds:Object>` fragments to embed (enveloping data + XAdES props).
    objects: Vec<String>,
    cert_ders: Vec<Vec<u8>>,
    /// Extra namespace declarations placed on `<ds:Signature>` (prefix, uri) — e.g. `xades`.
    signature_ns: Vec<(String, String)>,
}

impl XmlDsigBuilder {
    /// Start a builder for signature `signature_id` signed under `sig_alg`.
    pub fn new(signature_id: impl Into<String>, sig_alg: SignatureAlgorithm) -> Self {
        Self {
            signature_id: signature_id.into(),
            sig_alg,
            references: Vec::new(),
            objects: Vec::new(),
            cert_ders: Vec::new(),
            signature_ns: Vec::new(),
        }
    }

    /// The signature's `Id`.
    pub fn signature_id(&self) -> &str {
        &self.signature_id
    }

    /// Add a prepared reference.
    pub fn add_reference(&mut self, r: Reference) -> &mut Self {
        self.references.push(r);
        self
    }

    /// Add a serialized `<ds:Object>…</ds:Object>` fragment.
    pub fn add_object(&mut self, object_xml: impl Into<String>) -> &mut Self {
        self.objects.push(object_xml.into());
        self
    }

    /// Add a DER certificate to `KeyInfo/X509Data`.
    pub fn add_cert(&mut self, der: Vec<u8>) -> &mut Self {
        self.cert_ders.push(der);
        self
    }

    /// Declare an extra namespace on `<ds:Signature>` (e.g. `("xades", XADES_NS)`).
    pub fn declare_ns(&mut self, prefix: impl Into<String>, uri: impl Into<String>) -> &mut Self {
        self.signature_ns.push((prefix.into(), uri.into()));
        self
    }

    fn signed_info_id(&self) -> String {
        format!("{}-signedinfo", self.signature_id)
    }

    fn signature_value_id(&self) -> String {
        format!("{}-sigvalue", self.signature_id)
    }

    /// Serialize the `<ds:SignedInfo>` element (with an `Id` so it can be located for
    /// canonicalization).
    fn signed_info_xml(&self) -> Result<String, XadesError> {
        let mut s = String::new();
        s.push_str(&format!("<ds:SignedInfo Id=\"{}\">", self.signed_info_id()));
        s.push_str(&format!(
            "<ds:CanonicalizationMethod Algorithm=\"{}\"></ds:CanonicalizationMethod>",
            C14nAlgorithm::ExclusiveWithoutComments.uri()
        ));
        s.push_str(&format!(
            "<ds:SignatureMethod Algorithm=\"{}\"></ds:SignatureMethod>",
            signature_method_uri(self.sig_alg)?
        ));
        for r in &self.references {
            s.push_str("<ds:Reference");
            if let Some(id) = &r.id {
                s.push_str(&format!(" Id=\"{id}\""));
            }
            s.push_str(&format!(" URI=\"{}\"", r.uri));
            if let Some(t) = &r.ref_type {
                s.push_str(&format!(" Type=\"{t}\""));
            }
            s.push('>');
            if !r.transforms.is_empty() {
                s.push_str("<ds:Transforms>");
                for t in &r.transforms {
                    s.push_str(&format!("<ds:Transform Algorithm=\"{t}\"></ds:Transform>"));
                }
                s.push_str("</ds:Transforms>");
            }
            s.push_str(&format!(
                "<ds:DigestMethod Algorithm=\"{DIGEST_SHA256}\"></ds:DigestMethod>"
            ));
            s.push_str(&format!(
                "<ds:DigestValue>{}</ds:DigestValue>",
                B64.encode(r.digest)
            ));
            s.push_str("</ds:Reference>");
        }
        s.push_str("</ds:SignedInfo>");
        Ok(s)
    }

    /// Wrap `SignedInfo` in a minimal `<ds:Signature>` so its exclusive-C14N form can be computed
    /// exactly as a validator would compute it from the assembled document.
    fn signed_info_c14n(&self) -> Result<Vec<u8>, XadesError> {
        let mut wrapper = String::new();
        wrapper.push_str(&format!("<ds:Signature xmlns:ds=\"{DS_NS}\""));
        for (p, u) in &self.signature_ns {
            wrapper.push_str(&format!(" xmlns:{p}=\"{u}\""));
        }
        wrapper.push('>');
        wrapper.push_str(&self.signed_info_xml()?);
        wrapper.push_str("</ds:Signature>");
        c14n::canonicalize_element_by_id(
            wrapper.as_bytes(),
            &self.signed_info_id(),
            C14nAlgorithm::ExclusiveWithoutComments,
            &[],
        )
    }

    /// The digest the signer signs: SHA-256 over the exclusive-C14N of `<ds:SignedInfo>`.
    pub fn signed_info_digest(&self) -> Result<[u8; 32], XadesError> {
        Ok(sha256(&self.signed_info_c14n()?))
    }

    /// Assemble the finished `<ds:Signature>` around `raw`. The embedded `SignedInfo` is byte-identical
    /// to the one whose digest was signed, so validation re-canonicalizes to the same bytes.
    pub fn assemble(&self, raw: &RawSignature) -> Result<Vec<u8>, XadesError> {
        let sig_value = B64.encode(signature_value_bytes(raw)?);
        let mut s = String::new();
        s.push_str(&format!("<ds:Signature xmlns:ds=\"{DS_NS}\""));
        for (p, u) in &self.signature_ns {
            s.push_str(&format!(" xmlns:{p}=\"{u}\""));
        }
        s.push_str(&format!(" Id=\"{}\">", self.signature_id));
        s.push_str(&self.signed_info_xml()?);
        s.push_str(&format!(
            "<ds:SignatureValue Id=\"{}\">{}</ds:SignatureValue>",
            self.signature_value_id(),
            sig_value
        ));
        s.push_str(&self.key_info_xml());
        for obj in &self.objects {
            s.push_str(obj);
        }
        s.push_str("</ds:Signature>");
        Ok(s.into_bytes())
    }

    fn key_info_xml(&self) -> String {
        if self.cert_ders.is_empty() {
            return String::new();
        }
        let mut s = String::from("<ds:KeyInfo><ds:X509Data>");
        for der in &self.cert_ders {
            s.push_str(&format!(
                "<ds:X509Certificate>{}</ds:X509Certificate>",
                B64.encode(der)
            ));
        }
        s.push_str("</ds:X509Data></ds:KeyInfo>");
        s
    }

    /// The `Id` assigned to the `<ds:SignatureValue>` (the element a XAdES-T timestamp covers).
    pub fn signature_value_element_id(&self) -> String {
        self.signature_value_id()
    }
}
