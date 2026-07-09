//! The crate error type ([`PadesError`]) — spec 04, SIG-21.

/// Errors raised while signing or validating a PAdES signature.
///
/// The signing and timestamping callbacks carry their own error through the boxed
/// [`PadesError::Signer`] / [`PadesError::Timestamp`] variants, so a caller can surface a
/// `chancela_cades::CadesError` or `chancela_tsa::TsaError` without this crate depending on the
/// concrete type.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PadesError {
    /// The input bytes could not be parsed as a PDF document.
    #[error("failed to parse the input PDF: {0}")]
    PdfParse(String),

    /// The input PDF has no `startxref` cross-reference offset (cannot chain an incremental update).
    #[error("the input PDF has no cross-reference offset (missing startxref)")]
    MissingStartxref,

    /// The PDF catalog / page tree is missing, malformed, or uses a structure this crate does not
    /// yet support (e.g. cross-reference streams, a pre-existing AcroForm, or an indirect
    /// `/Annots` array).
    #[error("unsupported or malformed PDF structure: {0}")]
    MalformedStructure(String),

    /// The signing callback (which turns the ByteRange digest into a detached CMS) failed.
    #[error("the signing callback failed")]
    Signer(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// The timestamping callback (which turns a digest into an RFC 3161 token) failed.
    #[error("the timestamp callback failed")]
    Timestamp(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// The produced CMS does not fit the fixed-size `/Contents` placeholder reserved at sign time.
    #[error(
        "the produced CMS ({produced} bytes) exceeds the reserved /Contents placeholder ({capacity} bytes)"
    )]
    ContentsPlaceholderTooSmall {
        /// Size of the CMS the signer produced.
        produced: usize,
        /// Size of the reserved placeholder.
        capacity: usize,
    },

    /// No signature (`/Type /Sig`) dictionary was found in the PDF.
    #[error("no signature (/Sig) dictionary found in the PDF")]
    NoSignature,

    /// The signature `/ByteRange` is missing, malformed, or points outside the file.
    #[error("the signature /ByteRange is malformed or out of bounds")]
    InvalidByteRange,

    /// The `/Contents` entry is missing or is not a well-formed CMS DER object.
    #[error("the /Contents entry is missing or is not a well-formed CMS object")]
    InvalidContents,

    /// An ASN.1 / DER encoding or decoding error (CMS assembly for B-T, etc.).
    #[error("ASN.1/DER error: {0}")]
    Der(#[from] der::Error),

    /// The embedded CAdES signature failed cryptographic or structural validation.
    #[error("CAdES validation failed: {0}")]
    Cades(#[from] chancela_cades::CadesError),

    /// Long-term profiles (PAdES-B-LT / B-LTA, SIG-21 archival) are an explicit phase-2 follow-up.
    #[error("long-term PAdES profiles (B-LT / B-LTA) are not implemented (phase 2)")]
    LongTermNotImplemented,

    /// A caller asked to append a DSS revision but supplied no OCSP or CRL material.
    #[error("DSS evidence is empty: at least one OCSP response or CRL is required")]
    DssEvidenceEmpty,

    /// A caller-supplied DSS evidence blob is not a complete DER object.
    #[error("invalid DSS {kind} DER at index {index}")]
    InvalidDssEvidence {
        /// Evidence kind (`certificate`, `OCSP response`, or `CRL`).
        kind: &'static str,
        /// Zero-based index in the caller-supplied list.
        index: usize,
    },

    /// A caller-supplied `/DocTimeStamp` token is not a complete DER object.
    #[error("invalid /DocTimeStamp timestamp token DER")]
    InvalidDocTimeStampToken,
}
