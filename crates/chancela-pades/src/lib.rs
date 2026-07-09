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
//! - **PAdES-B-LT / B-LTA** — explicit phase-2 follow-up ([`PadesError::LongTermNotImplemented`]);
//!   DSS / VRI, document timestamps, and revocation embedding are not yet built.
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

pub mod dss;
pub mod error;
pub mod sign;
pub mod validate;

mod pdf;

#[cfg(test)]
mod tests;

pub use dss::{DssEvidence, DssReport, add_dss_revision, inspect_dss};
pub use error::PadesError;
pub use sign::{
    MAX_CONTENTS_BYTES, PreparedSignature, SignOptions, add_signature_timestamp, embed_signature,
    prepare_signature, sign_pdf,
};
pub use validate::{PdfSignatureReport, validate_pdf_signature};
