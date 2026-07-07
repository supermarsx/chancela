//! The crate error type ([`TslError`]).

/// Errors from Trusted List ingestion, parsing, caching and querying (spec 04, SIG-10..13).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TslError {
    /// The underlying XML could not be read/parsed by `quick-xml`.
    #[error("malformed Trusted List XML: {0}")]
    Xml(#[from] quick_xml::Error),

    /// An XML attribute could not be decoded.
    #[error("malformed XML attribute: {0}")]
    Attr(#[from] quick_xml::events::attributes::AttrError),

    /// Element text was not valid UTF-8.
    #[error("non-UTF-8 text in Trusted List XML")]
    Utf8,

    /// The document parsed as XML but does not match the ETSI TS 119 612 structure we require
    /// (e.g. the root `TrustServiceStatusList` element is missing).
    #[error("Trusted List structure error: {0}")]
    Structure(String),

    /// A base64 field (`X509Certificate` / `X509SKI`) could not be decoded.
    #[error("invalid base64 in Trusted List: {0}")]
    Base64(String),

    /// Fetching the list over the network failed (real `HttpTslSource` only).
    #[error("failed to fetch Trusted List over the network: {0}")]
    Fetch(#[from] reqwest::Error),

    /// Reading a fixture/on-disk Trusted List failed (`FileTslSource`).
    #[error("failed to read Trusted List file: {0}")]
    Io(#[from] std::io::Error),

    /// **Phase-2 stub (SIG-11).** Validating the Trusted List's own XML-DSig signature is not yet
    /// implemented. Parsing, status resolution, caching and querying all work without it, but a
    /// production deployment MUST NOT trust a list whose signature has not been verified against
    /// the GNS scheme-operator certificate. See `crates/chancela-tsl/TESTING.md`.
    #[error("TSL XML-DSig signature validation is not implemented (phase-2, SIG-11)")]
    SignatureValidationNotImplemented,
}
