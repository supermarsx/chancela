//! `chancela-pades` — PAdES-B PDF signing (incremental update) + structural validation (spec 04).
//!
//! This crate signs an existing PDF by **incremental update** ([`sign_pdf`]): it appends an
//! AcroForm signature field and a `/Sig` dictionary, computes the `/ByteRange` around a fixed-size
//! zero-filled `/Contents` placeholder, hashes the covered bytes with SHA-256, and hands that
//! digest to a caller-supplied callback that builds the detached CMS (via `chancela-cades`). The
//! CMS is hex-filled into the placeholder. [`add_signature_timestamp`] upgrades a B-B signature to
//! **B-T** by embedding an RFC 3161 token (from `chancela-tsa`) as the
//! `id-aa-signatureTimeStampToken` unsigned attribute. [`validate_pdf_signature`] locates the
//! signature, recomputes the ByteRange digest, and delegates the cryptographic check to
//! `chancela-cades`.
//!
//! ## Scope (SIG-21)
//!
//! - **PAdES-B-B** — implemented.
//! - **PAdES-B-T** — implemented (signature timestamp as a CMS unsigned attribute).
//! - **PAdES-B-LT / B-LTA** — not claimed as production-grade legal LTV. The crate can append
//!   and inspect deterministic, caller-supplied `/DSS` + `/VRI` evidence via [`add_dss_revision`]
//!   and [`inspect_dss`], but it does not fetch OCSP/CRL data, validate revocation freshness or
//!   trust, or claim B-LT sufficiency. It can also append and report caller-supplied
//!   `/DocTimeStamp` archive timestamp revisions via [`add_doc_timestamp_revision`] /
//!   [`inspect_doc_timestamps`], without renewal policy or B-LTA/legal LTV claims.
//! - **Offline LTV completeness verification** — [`verify_ltv_offline`] checks, with **no network**
//!   and using only the material embedded in the PDF, that a B-LT/B-LTA signature is long-term
//!   *complete offline*: it rebuilds the signer certificate chain from the embedded `/DSS /Certs`
//!   (issuer/subject-name + key-identifier linkage) and **cryptographically verifies each CA link's
//!   signature** (RSA-PKCS1-SHA256 / ECDSA-P256-SHA256 only, unknown algorithms rejected), confirms
//!   each non-root link is covered by an embedded OCSP response or CRL, and verifies the
//!   `/DocTimeStamp` renewal chain is contiguous (each archive timestamp covers the prior revision,
//!   including its DSS). It **verifies embedded LTV completeness**; it does **not** fetch or refresh
//!   revocation and does **not** anchor the chain to a trusted list. Live B-LT population
//!   (fetching/validating OCSP/CRL, building the chain to a live TSL anchor) and trust anchoring stay
//!   in `chancela-signing` (`dss_collect`) + `chancela-tsl` (LOTL/certpath); qualified *issuance*
//!   remains external (QTSP). This is a technical completeness result, not a qualified-status or
//!   legal long-term-validation claim.
//!
//! ## Layering
//!
//! This crate owns PDF mechanics (incremental update, ByteRange arithmetic, `/Sig` dictionary,
//! CMS embedding, and caller-supplied DSS/VRI append mechanics) and delegates all CMS assembly and
//! cryptography to `chancela-cades`, and all RFC 3161 timestamp production to `chancela-tsa`.
//! `chancela-signing` (t4-e8) wires the callbacks, selecting a signer provider and a TSA.
//!
//! ## Input requirements (phase-1)
//!
//! The input PDF must use a classic cross-reference table (not an xref stream), must not already
//! carry an AcroForm, and its first page's `/Annots` (if any) must be an inline array. These cover
//! the PDFs Chancela generates; broader inputs are a documented follow-up (see `TESTING.md`).

#![forbid(unsafe_code)]

pub mod appearance;
pub mod archive_timestamp;
pub mod dss;
pub mod error;
pub mod renewal;
pub mod sign;
pub mod validate;

mod pdf;

#[cfg(test)]
mod tests;

pub use appearance::{
    ImageSeal, SealAppearance, SealContent, SealImageFormat, SealPlacement, SealTextLine, TextSeal,
};
pub use archive_timestamp::{
    DocTimeStampFailureReason, DocTimeStampReport, DocTimeStampSemanticStatus,
    DocTimeStampValidation, add_doc_timestamp_revision, inspect_doc_timestamps,
};
pub use dss::{
    DssEvidence, DssReport, add_dss_revision, add_dss_revision_with_validation_time, inspect_dss,
};
pub use error::PadesError;
pub use renewal::{
    LtvRenewalPlan, LtvRenewalPlanAction, LtvRenewalPlanInput, LtvRenewalPlanScope,
    plan_ltv_renewal,
};
pub use sign::{
    MAX_CONTENTS_BYTES, PreparedSignature, SignOptions, add_signature_timestamp, embed_signature,
    prepare_signature, prepare_signature_with_appearance, sign_pdf, sign_pdf_with_appearance,
};
pub use validate::{
    LTV_OFFLINE_SCOPE_NOTE, LtvUncoveredLink, LtvUncoveredReason, LtvVerificationReport,
    PdfSignatureReport, validate_pdf_signature, verify_ltv_offline,
};
