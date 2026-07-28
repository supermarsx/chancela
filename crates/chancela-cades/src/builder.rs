//! Signed-attributes digesting and detached CAdES-B `SignedData` assembly (SIG-01/02).

use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
use cms::content_info::{CmsVersion, ContentInfo};
use cms::signed_data::{
    CertificateSet, EncapsulatedContentInfo, SignedData, SignerIdentifier, SignerInfo, SignerInfos,
};
use der::asn1::{Any, OctetString, SetOfVec};
use der::{Decode, Encode};
use spki::AlgorithmIdentifierOwned;
use x509_cert::certificate::Certificate;

use crate::attrs::{alg_sha256, build_signed_attributes};
use crate::error::CadesError;
use crate::oids;
use crate::raw_signature::{RawSignature, SignatureAlgorithm};

/// Which signature profile the signed attributes are being built for.
///
/// The two profiles differ in exactly one attribute, the RFC 5652 `signing-time`:
///
/// * **CAdES** (ETSI EN 319 122-1) and the ASiC containers built on it permit `signing-time`, and
///   a detached CMS has nowhere else to carry the claimed instant — so [`Cades`] emits it.
/// * **PAdES** (ETSI EN 319 142-1 V1.2.1, Table 1) states that `signing-time` **shall not be
///   present** — at every level, B-B through B-LTA — because the claimed instant belongs in the
///   PDF Signature Dictionary `/M` entry, which the same table requires. So [`Pades`] omits it.
///   `/M` is written by `chancela_pades` from the same instant, so nothing is lost.
///
/// The profile decides the attribute *set*, which decides the bytes that get signed. It therefore
/// **must be identical** at the [`signed_attributes_digest`] call that produces the digest a signer
/// signs and at the [`assemble_cades_b`] call that embeds the attributes — exactly like
/// `content_digest` and the signing certificate. A mismatch produces a `SignerInfo` whose embedded
/// attributes are not the ones that were signed; [`crate::validate_cades_b`] rejects it.
///
/// [`Cades`]: SignedAttrsProfile::Cades
/// [`Pades`]: SignedAttrsProfile::Pades
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignedAttrsProfile {
    /// CAdES / ASiC: emit `signing-time` carrying this instant.
    Cades(time::OffsetDateTime),
    /// PAdES: omit `signing-time`; the PDF Signature Dictionary `/M` entry carries the instant.
    Pades,
}

impl SignedAttrsProfile {
    /// The instant this profile puts in the CMS `signing-time` attribute, if any.
    ///
    /// `None` for [`Pades`](SignedAttrsProfile::Pades) — not because the signature has no claimed
    /// time, but because the CMS is not where PAdES carries it.
    pub fn cms_signing_time(&self) -> Option<time::OffsetDateTime> {
        match self {
            SignedAttrsProfile::Cades(t) => Some(*t),
            SignedAttrsProfile::Pades => None,
        }
    }
}

/// Compute the SHA-256 digest of the CAdES-B signed attributes, to be handed to a remote/token
/// signer (SIG-01/02).
///
/// The signer signs **this** digest; the resulting [`RawSignature`] is then wrapped by
/// [`assemble_cades_b`], which rebuilds byte-identical attributes from the same inputs — including
/// the same `profile`. The digest is over the DER `SET OF` encoding of the attributes, per RFC 5652
/// §5.4 (the EXPLICIT `SET OF` tag, not the `[0]` implicit tag carried inside the `SignerInfo`).
pub fn signed_attributes_digest(
    content_digest: &[u8; 32],
    signing_cert_der: &[u8],
    profile: SignedAttrsProfile,
) -> Result<[u8; 32], CadesError> {
    let attrs = build_signed_attributes(content_digest, signing_cert_der, profile)?;
    let der = attrs.to_der()?;
    Ok(crate::attrs::sha256(&der))
}

/// The `SignerInfo.signatureAlgorithm` identifier for a given profile.
///
/// CAdES-B here is fixed to a SHA-256 signed-attributes digest (see [`signed_attributes_digest`]),
/// so only the two SHA-256 profiles are assemblable. The P-384/SHA-384 and P-521/SHA-512 profiles
/// exist for XML-signing (XAdES) and are rejected here rather than silently mislabelled over a
/// SHA-256 imprint — keeping CAdES/PAdES honest and unchanged.
fn signature_algorithm_id(
    algorithm: SignatureAlgorithm,
) -> Result<AlgorithmIdentifierOwned, CadesError> {
    match algorithm {
        SignatureAlgorithm::RsaPkcs1Sha256 => Ok(AlgorithmIdentifierOwned {
            oid: oids::RSA_ENCRYPTION,
            // rsaEncryption carries NULL parameters (RFC 3370 §3.2).
            parameters: Some(Any::null()),
        }),
        SignatureAlgorithm::EcdsaP256Sha256 => Ok(AlgorithmIdentifierOwned {
            oid: oids::ECDSA_WITH_SHA256,
            parameters: None,
        }),
        // ecdsa-with-SHA384 (1.2.840.10045.4.3.3) / ecdsa-with-SHA512 (1.2.840.10045.4.3.4):
        // valid XAdES profiles, but CAdES-B here only digests signed attributes with SHA-256.
        SignatureAlgorithm::EcdsaP384Sha384 => Err(CadesError::UnsupportedAlgorithm {
            oid: der::asn1::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3"),
        }),
        SignatureAlgorithm::EcdsaP521Sha512 => Err(CadesError::UnsupportedAlgorithm {
            oid: der::asn1::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4"),
        }),
    }
}

/// Assemble a detached CAdES-B `SignedData` from a [`RawSignature`] produced over the signed
/// attributes (SIG-01/02).
///
/// `content_digest` is the SHA-256 of the detached content; `profile` **must** match the value
/// passed to [`signed_attributes_digest`] so the embedded attributes hash to the digest the signer
/// actually signed. Returns the DER-encoded outer `ContentInfo`.
pub fn assemble_cades_b(
    raw: &RawSignature,
    content_digest: &[u8; 32],
    profile: SignedAttrsProfile,
) -> Result<Vec<u8>, CadesError> {
    let signer_cert =
        Certificate::from_der(&raw.signing_cert_der).map_err(|_| CadesError::InvalidCertificate)?;

    let signed_attrs = build_signed_attributes(content_digest, &raw.signing_cert_der, profile)?;

    let sid = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
        issuer: signer_cert.tbs_certificate.issuer.clone(),
        serial_number: signer_cert.tbs_certificate.serial_number.clone(),
    });

    let signer_info = SignerInfo {
        version: CmsVersion::V1,
        sid,
        digest_alg: alg_sha256(),
        signed_attrs: Some(signed_attrs),
        signature_algorithm: signature_algorithm_id(raw.algorithm)?,
        signature: OctetString::new(raw.signature.clone())?,
        unsigned_attrs: None,
    };

    // Certificate set: signer leaf first, then the issuer chain.
    let mut cert_choices = vec![CertificateChoices::Certificate(signer_cert)];
    for der in &raw.chain_der {
        let cert = Certificate::from_der(der).map_err(|_| CadesError::InvalidCertificate)?;
        cert_choices.push(CertificateChoices::Certificate(cert));
    }
    let certificates = Some(CertificateSet(SetOfVec::try_from(cert_choices)?));

    let encap_content_info = EncapsulatedContentInfo {
        econtent_type: oids::ID_DATA,
        econtent: None, // detached
    };

    let signed_data = SignedData {
        version: CmsVersion::V1,
        digest_algorithms: SetOfVec::try_from(vec![alg_sha256()])?,
        encap_content_info,
        certificates,
        crls: None,
        signer_infos: SignerInfos(SetOfVec::try_from(vec![signer_info])?),
    };

    let content_info = ContentInfo {
        content_type: oids::ID_SIGNED_DATA,
        content: Any::encode_from(&signed_data)?,
    };
    Ok(content_info.to_der()?)
}
