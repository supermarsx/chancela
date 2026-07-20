//! The attribute-signature binding seam — the small in-crate trait that the XAdES hook slots into.
//!
//! ## Why a trait here (the XAdES hook)
//!
//! A professional-attribute signature binds the signer's attribute *into* the signature. The
//! CAdES form of that binding is implemented here in [`CadesAttributeBinder`] over the
//! `chancela-cades` public API. The XAdES form belongs in `chancela-xades`, whose public surface is
//! being built concurrently (t67-e2) and is not yet stable. Rather than depend on that moving
//! surface, this crate defines the [`AttributeSignatureBinder`] trait: the API layer (t67-e10) can
//! supply a XAdES-backed implementation once `chancela-xades` stabilises, **without editing this
//! crate**. (See `.orchestration/plans/t67.md` §1.2 / e4.)
//!
//! ## Binding model (mock-first, honest)
//!
//! `chancela-cades` builds RFC 5652 signed attributes (content-type, message-digest, signing-time,
//! signing-certificate-v2) but has no signer-attribute field. So the attribute is bound by folding
//! its canonical encoding **and the honesty status** into the content digest that CAdES then signs
//! ([`attribute_bound_content_digest`]). This is a pragmatic binding for the mock-first crate, not a
//! claim of ETSI signer-attributes-v2 conformance; a real XAdES binder can carry the attribute in
//! the proper `SignedProperties` instead.

use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use chancela_cades::{RawSignature, assemble_cades_b, signed_attributes_digest};

use crate::error::ScapError;
use crate::model::ScapSignatureEvidence;

/// The digest a signing device must sign, and the assembly of the finished attribute-qualified
/// signature once the device returns a [`RawSignature`].
///
/// Two phases mirror the rest of the signing stack: expose a digest for the token/remote signer,
/// then assemble around the returned signature. Implementors bind the attribute **and its honesty
/// status** so neither can be swapped after signing.
pub trait AttributeSignatureBinder {
    /// The digest the signing device must sign to bind `evidence` over the content whose SHA-256 is
    /// `content_digest`, using `signing_cert_der` (DER X.509) and `signing_time`.
    fn binding_digest(
        &self,
        content_digest: &[u8; 32],
        evidence: &ScapSignatureEvidence,
        signing_cert_der: &[u8],
        signing_time: OffsetDateTime,
    ) -> Result<[u8; 32], ScapError>;

    /// Assemble the finished attribute-qualified signature from the device's `raw` signature. The
    /// `content_digest`, `evidence`, and `signing_time` MUST match those passed to
    /// [`Self::binding_digest`].
    fn assemble(
        &self,
        raw: &RawSignature,
        content_digest: &[u8; 32],
        evidence: &ScapSignatureEvidence,
        signing_time: OffsetDateTime,
    ) -> Result<Vec<u8>, ScapError>;
}

/// The attribute-bound content digest: SHA-256 over the content digest, the attribute's canonical
/// binding bytes, and the honesty-status marker.
///
/// Folding the status in means a signature produced under a *declared-only* evidence cannot later
/// be presented as *verified-by-SCAP* without invalidating the signature.
pub fn attribute_bound_content_digest(
    content_digest: &[u8; 32],
    evidence: &ScapSignatureEvidence,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"chancela-scap:attr-bound-v1");
    hasher.update(content_digest);
    hasher.update(b"\x00attribute\x00");
    hasher.update(evidence.attribute.canonical_binding_bytes());
    hasher.update(b"\x00status\x00");
    hasher.update(evidence.status.verification_status_marker().as_bytes());
    hasher.finalize().into()
}

/// The default binder: binds the attribute into a detached CAdES-B `SignedData` via the
/// `chancela-cades` public API.
#[derive(Debug, Default, Clone, Copy)]
pub struct CadesAttributeBinder;

impl AttributeSignatureBinder for CadesAttributeBinder {
    fn binding_digest(
        &self,
        content_digest: &[u8; 32],
        evidence: &ScapSignatureEvidence,
        signing_cert_der: &[u8],
        signing_time: OffsetDateTime,
    ) -> Result<[u8; 32], ScapError> {
        let bound = attribute_bound_content_digest(content_digest, evidence);
        signed_attributes_digest(&bound, signing_cert_der, signing_time)
            .map_err(|e| ScapError::Signature(e.to_string()))
    }

    fn assemble(
        &self,
        raw: &RawSignature,
        content_digest: &[u8; 32],
        evidence: &ScapSignatureEvidence,
        signing_time: OffsetDateTime,
    ) -> Result<Vec<u8>, ScapError> {
        let bound = attribute_bound_content_digest(content_digest, evidence);
        assemble_cades_b(raw, &bound, signing_time).map_err(|e| ScapError::Signature(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ProfessionalAttribute, ScapVerificationStatus};

    fn evidence(status: ScapVerificationStatus) -> ScapSignatureEvidence {
        ScapSignatureEvidence {
            attribute: ProfessionalAttribute {
                provider_id: "OA".to_owned(),
                provider_name: "Ordem".to_owned(),
                name: "Advogado".to_owned(),
                valid_from: None,
                valid_until: None,
                sub_attributes: vec![],
            },
            status,
            verification_source: None,
            verified_at: None,
            authority_reference: None,
        }
    }

    /// A fictional self-signed P-256 test certificate (DER). No private key is retained; the cades
    /// binding only needs the certificate to parse and be hashed into the signed attributes.
    const SIGNER_CERT_DER: &[u8] = include_bytes!("../tests/fixtures/signer_cert.der");

    #[test]
    fn cades_binding_and_assembly_go_through_the_cades_seam() {
        let content_digest = [3u8; 32];
        let signing_time = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let ev = evidence(ScapVerificationStatus::DeclaredOnly);
        let binder = CadesAttributeBinder;

        // binding_digest drives chancela_cades::signed_attributes_digest over the fixture cert.
        let digest = binder
            .binding_digest(&content_digest, &ev, SIGNER_CERT_DER, signing_time)
            .expect("binding digest via cades");

        // A different evidence produces a different to-be-signed digest.
        let other = evidence(ScapVerificationStatus::VerifiedByScap);
        let other_digest = binder
            .binding_digest(&content_digest, &other, SIGNER_CERT_DER, signing_time)
            .unwrap();
        assert_ne!(digest, other_digest);

        // assemble drives chancela_cades::assemble_cades_b into a detached CAdES-B ContentInfo.
        let raw = RawSignature::new(
            chancela_cades::SignatureAlgorithm::EcdsaP256Sha256,
            vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01],
            SIGNER_CERT_DER.to_vec(),
            vec![],
        );
        let der = binder
            .assemble(&raw, &content_digest, &ev, signing_time)
            .expect("assemble via cades");
        assert!(!der.is_empty());
    }

    #[test]
    fn status_and_attribute_change_the_bound_digest() {
        let content = [7u8; 32];
        let declared = evidence(ScapVerificationStatus::DeclaredOnly);
        let d1 = attribute_bound_content_digest(&content, &declared);

        // Same inputs are deterministic.
        assert_eq!(d1, attribute_bound_content_digest(&content, &declared));

        // Flipping the honesty status changes the digest — status cannot be swapped post-signing.
        let verified = evidence(ScapVerificationStatus::VerifiedByScap);
        assert_ne!(d1, attribute_bound_content_digest(&content, &verified));

        // A different attribute changes the digest.
        let mut other = declared.clone();
        other.attribute.name = "Engenheiro".to_owned();
        assert_ne!(d1, attribute_bound_content_digest(&content, &other));
    }
}
