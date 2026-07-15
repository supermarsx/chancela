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

    /// The Trusted List's XML-DSig signature is missing or structurally malformed (SIG-11,
    /// audit t41/C2). The list MUST NOT be trusted.
    #[error("TSL XML-DSig signature is missing or malformed: {0}")]
    SignatureStructure(String),

    /// A digest in the TSL XML-DSig signature did not match the referenced content (SIG-11,
    /// audit t41/C2). The list has been tampered with in transit.
    #[error("TSL XML-DSig reference digest mismatch")]
    SignatureDigestMismatch,

    /// The TSL XML-DSig signature value did not verify against the signer certificate's public
    /// key (SIG-11, audit t41/C2). The list is not authentic.
    #[error("TSL XML-DSig signature verification failed")]
    SignatureVerificationFailed,

    /// The TSL XML-DSig uses an unsupported signature or digest algorithm (audit t41/C2).
    #[error("unsupported TSL XML-DSig algorithm: {0}")]
    SignatureUnsupportedAlgorithm(String),

    /// The Trusted List's XML-DSig signature verified against the certificate the list itself
    /// carried, but that signer certificate does not match a configured trust anchor — or no
    /// trust anchor is configured at all (audit t41/C2, part H4). The list is the system's root
    /// of trust; an unanchored (self-attested) list MUST NOT be trusted. This is the fail-closed
    /// result: absent a configured EU LOTL / national scheme anchor, every list is untrusted.
    #[error("TSL signer is not anchored to a configured trust anchor: {0}")]
    SignatureUntrusted(String),

    /// A configured TSL trust anchor could not be loaded/parsed (bad file path, malformed PEM/DER,
    /// or an invalid pinned SHA-256 fingerprint). Misconfiguration is treated as fail-closed: an
    /// anchor that cannot be loaded trusts nothing (audit t41/C2, part H4).
    #[error("invalid TSL trust-anchor configuration: {0}")]
    TrustAnchorConfig(String),

    /// A code path that is a frozen phase-A seam and not yet implemented by the owning Phase-B
    /// executor. Stub modules return this so downstream code compiles against a stable signature
    /// while the real implementation lands (wp26 §4). Never surfaced once the track is complete.
    #[error("TSL feature not yet implemented: {0}")]
    Unimplemented(&'static str),

    /// XML canonicalization (C14N) of a signed element failed (wp26 E2). A canonicalization error
    /// means the signed bytes could not be reconstructed, so the signature MUST NOT be trusted.
    #[error("XML canonicalization failed: {0}")]
    Canonicalization(String),

    /// Live EU LOTL (List of Trusted Lists) ingestion failed — fetch, XML-DSig verification against
    /// the pinned LOTL anchors, pointer parsing, or member-state traversal (wp26 E4). Fail-closed:
    /// a LOTL that cannot be authenticated yields no derived member-state trust.
    #[error("LOTL ingestion failed: {0}")]
    Lotl(String),

    /// X.509 certificate-path building from an end-entity signer to a Trusted List anchor failed
    /// (wp26 E5): no chain to a configured anchor, a broken issuer link, a validity/basic-constraints
    /// violation, or an unsupported signature algorithm. Fail-closed: no path means no trust.
    #[error("certificate path building failed: {0}")]
    CertPath(String),
}
