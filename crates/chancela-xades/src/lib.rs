//! `chancela-xades` — XMLDSig + XAdES (B/T/LT/LTA) over the existing `RawSignature` seam
//! (spec 04; t67 §1.1).
//!
//! Card / CMD / CSC / soft-cert sources all sign a digest already, so XAdES is layered on the same
//! two-phase seam as CAdES/PAdES: build the `<SignedInfo>`, expose its digest for the signer, then
//! assemble the finished `<Signature>` around the returned [`chancela_cades::RawSignature`].
//!
//! ## The load-bearing piece: exclusive XML canonicalization
//!
//! XMLDSig/XAdES require **Exclusive XML Canonicalization** (excl-c14n, W3C REC) over `SignedInfo`
//! and each `Reference`. No workspace crate provides C14N (`quick-xml`/`roxmltree` parse/emit only),
//! and none is added blindly (der-0.7 pin discipline). It is therefore implemented in-crate over
//! `roxmltree` in [`c14n`] and gated on a committed reference-vector suite before any XAdES level is
//! trusted (see `.orchestration/plans/t67.md` §0.2).
//!
//! ## Layout
//!
//! - [`c14n`] — excl-c14n (W3C REC) + inclusive c14n1.1; the fixture-tested core.
//! - [`xmldsig`] — `<Signature>`/`<SignedInfo>`/`<Reference>`/`<KeyInfo>` build over a `RawSignature`.
//! - [`xades`] — QualifyingProperties (SignedSignatureProperties, SignedDataObjectProperties) and
//!   the UnsignedProperties for T/LT/LTA.
//! - [`validate`] — parse + re-canonicalize + verify digests/signature + level introspection.
//! - [`error`] — the crate error type.
//!
//! **Status:** skeleton (t67-e0). The module bodies are filled by t67-e2.

#![forbid(unsafe_code)]

pub mod c14n;
pub mod error;
pub mod validate;
pub mod xades;
pub mod xmldsig;

pub use c14n::{
    C14nAlgorithm, canonicalize_document, canonicalize_document_excluding_ids,
    canonicalize_element_by_id,
};
pub use error::XadesError;
pub use validate::{XadesValidationReport, validate_xades};
pub use xades::{
    AssembledXades, DetachedRef, EnvelopedDocument, EnvelopingObject, ObjectContent, PreparedXades,
    SignaturePackaging, XadesContext, XadesLevel, XadesSignRequest, prepare_xades,
};
pub use xmldsig::{Reference, XmlDsigBuilder};

#[cfg(test)]
mod tests;
