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

/// Compute the SHA-256 digest of the CAdES-B signed attributes, to be handed to a remote/token
/// signer (SIG-01/02).
///
/// The signer signs **this** digest; the resulting [`RawSignature`] is then wrapped by
/// [`assemble_cades_b`], which rebuilds byte-identical attributes from the same inputs. The
/// digest is over the DER `SET OF` encoding of the attributes, per RFC 5652 §5.4 (the EXPLICIT
/// `SET OF` tag, not the `[0]` implicit tag carried inside the `SignerInfo`).
pub fn signed_attributes_digest(
    content_digest: &[u8; 32],
    signing_cert_der: &[u8],
    signing_time: time::OffsetDateTime,
) -> Result<[u8; 32], CadesError> {
    let attrs = build_signed_attributes(content_digest, signing_cert_der, signing_time)?;
    let der = attrs.to_der()?;
    Ok(crate::attrs::sha256(&der))
}

/// The `SignerInfo.signatureAlgorithm` identifier for a given profile.
fn signature_algorithm_id(algorithm: SignatureAlgorithm) -> AlgorithmIdentifierOwned {
    match algorithm {
        SignatureAlgorithm::RsaPkcs1Sha256 => AlgorithmIdentifierOwned {
            oid: oids::RSA_ENCRYPTION,
            // rsaEncryption carries NULL parameters (RFC 3370 §3.2).
            parameters: Some(Any::null()),
        },
        SignatureAlgorithm::EcdsaP256Sha256 => AlgorithmIdentifierOwned {
            oid: oids::ECDSA_WITH_SHA256,
            parameters: None,
        },
    }
}

/// Assemble a detached CAdES-B `SignedData` from a [`RawSignature`] produced over the signed
/// attributes (SIG-01/02).
///
/// `content_digest` is the SHA-256 of the detached content; `signing_time` **must** match the
/// value passed to [`signed_attributes_digest`] so the embedded attributes hash to the digest the
/// signer actually signed. Returns the DER-encoded outer `ContentInfo`.
pub fn assemble_cades_b(
    raw: &RawSignature,
    content_digest: &[u8; 32],
    signing_time: time::OffsetDateTime,
) -> Result<Vec<u8>, CadesError> {
    let signer_cert =
        Certificate::from_der(&raw.signing_cert_der).map_err(|_| CadesError::InvalidCertificate)?;

    let signed_attrs =
        build_signed_attributes(content_digest, &raw.signing_cert_der, signing_time)?;

    let sid = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
        issuer: signer_cert.tbs_certificate.issuer.clone(),
        serial_number: signer_cert.tbs_certificate.serial_number.clone(),
    });

    let signer_info = SignerInfo {
        version: CmsVersion::V1,
        sid,
        digest_alg: alg_sha256(),
        signed_attrs: Some(signed_attrs),
        signature_algorithm: signature_algorithm_id(raw.algorithm),
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
