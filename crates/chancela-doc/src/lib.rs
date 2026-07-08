//! # chancela-doc — the PDF/A-2u writer (t48 / DOC-01, Wave C batch-0)
//!
//! Skeleton published by **t48-e0**. This crate consumes the frozen
//! [`chancela_core::DocumentModel`] seam (§3.1) and writes **PDF/A-2u** bytes directly over
//! `lopdf` — owning text layout, pagination, font embedding, the sRGB OutputIntent, the XMP
//! metadata packet (`pdfaid:part=2` / `pdfaid:conformance=U`), and structural self-verification.
//!
//! **Why lopdf-direct (D2):** it guarantees the byte-shape `chancela-pades::sign_pdf` requires —
//! a **classic cross-reference table (not an xref stream)**, no AcroForm, inline first-page
//! `/Annots` — *by construction*, because we write every object. That constraint is the whole
//! reason a purpose-built writer wins over typst/printpdf. e3 proves it with a generate→sign
//! round-trip.
//!
//! **Status: seam + signature only.** The real writer (layout, fonts, OutputIntent, XMP,
//! self-check) is **t48-e2**; the bundled OFL/SIL serif asset under `assets/fonts/` is **t48-e2a**.
//! [`pdfa::write`]'s body is `todo!()`.

/// The PDF/A-2u writer. Takes the PDF-agnostic [`chancela_core::DocumentModel`] and emits the
/// conformant bytes.
pub mod pdfa {
    use super::DocError;
    use chancela_core::DocumentModel;

    /// Write `doc` as PDF/A-2u bytes: classic-xref, no AcroForm, all fonts embedded with
    /// ToUnicode, sRGB OutputIntent + XMP part/conformance markers, structurally self-verified.
    /// The output is the exact byte-shape `chancela-pades` accepts. **Implemented by t48-e2.**
    pub fn write(doc: &DocumentModel) -> Result<Vec<u8>, DocError> {
        let _ = doc;
        todo!("t48-e2: lay out DocumentModel → PDF/A-2u bytes (classic xref, embedded fonts, XMP)")
    }
}

/// Errors from generating a PDF/A document.
#[derive(Debug, thiserror::Error)]
pub enum DocError {
    /// A document layout invariant was violated (e.g. a block that cannot be laid out).
    #[error("layout error: {0}")]
    Layout(String),
    /// Font loading/embedding failed (the bundled serif asset is missing or malformed).
    #[error("font error: {0}")]
    Font(String),
    /// The structural PDF/A-2u self-check failed (missing OutputIntent, XMP, unembedded font, …).
    #[error("PDF/A conformance self-check failed: {0}")]
    Conformance(String),
    /// The underlying `lopdf` writer failed.
    #[error("pdf serialization failed: {0}")]
    Pdf(#[from] lopdf::Error),
}
