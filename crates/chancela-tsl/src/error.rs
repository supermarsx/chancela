//! The crate error type ([`TslError`]).

/// Render an error together with every distinct cause in its [`std::error::Error::source`] chain,
/// joined with `": "`.
///
/// Transport errors nest: `reqwest` reports `error sending request for url (…)` and hangs the fault
/// that actually happened — `dns error: …`, `tcp connect error: …`, `invalid peer certificate: …`,
/// `operation timed out` — one or more `source()` hops below. Formatting only the outermost error
/// discards exactly the part an operator needs, so this walks to the bottom.
///
/// A cause whose text is already contained in what has been collected is skipped: wrapper types
/// commonly re-`Display` their inner error verbatim, and repeating it adds length without adding
/// information. The walk is bounded ([`MAX_ERROR_CHAIN_DEPTH`]) so a cyclic or pathologically deep
/// chain cannot spin here — this runs while an operator is waiting on a failing signature.
pub fn describe_error_chain(err: &(dyn std::error::Error + 'static)) -> String {
    let mut parts: Vec<String> = Vec::new();
    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(err);
    let mut depth = 0usize;
    while let Some(e) = current {
        if depth >= MAX_ERROR_CHAIN_DEPTH {
            break;
        }
        depth += 1;
        let text = e.to_string();
        let trimmed = text.trim();
        if !trimmed.is_empty() && !parts.iter().any(|seen| seen.contains(trimmed)) {
            parts.push(trimmed.to_owned());
        }
        current = e.source();
    }
    parts.join(": ")
}

/// How many `source()` hops [`describe_error_chain`] will follow before it stops.
const MAX_ERROR_CHAIN_DEPTH: usize = 12;

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
    ///
    /// The message is the **whole** `source()` chain, not just `reqwest`'s outer sentence. That
    /// outer sentence is always `error sending request for url (…)`, which is the same text for a
    /// DNS failure, a refused connection, a TLS handshake rejection and a timeout — four faults
    /// that send an operator to four different places. The terminal cause is what tells them apart,
    /// and it is one `source()` hop below where the previous formatting stopped.
    #[error("failed to fetch Trusted List over the network: {}", describe_error_chain(.0))]
    Fetch(#[from] reqwest::Error),

    /// The HTTPS connection to the Trusted List host failed because that server did not send the
    /// intermediate certificate(s) linking its own certificate to a trusted root.
    ///
    /// Split out of [`Fetch`](Self::Fetch) because it is the one transport failure whose remedy is a
    /// **configuration change here** and whose fault is **at the other end**. Every other network
    /// error tells the operator to look at their address or their connectivity; this one tells them
    /// the remote server is misconfigured and that they can work around it by supplying the missing
    /// certificate. Sharing a code with "the list could not be fetched" made those instructions
    /// unreachable — and the terminal cause an operator does see (`UnknownIssuer`) reads like a
    /// verdict on the certificate rather than on the chain.
    ///
    /// The message is produced by the caller that owns the TLS stack (`chancela-api`), which is the
    /// only layer that can inspect the `rustls` error by type. It is fully rendered technical
    /// English, including the whole `source()` chain, so this variant carries a `String`.
    ///
    /// This is **not** a relaxation of anything: the connection was refused and no bytes were read.
    #[error("{0}")]
    TlsChainIncomplete(String),

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

#[cfg(test)]
mod error_chain_tests {
    use std::error::Error;
    use std::fmt;

    use super::*;

    /// A two-layer error mimicking the shape `reqwest` produces: a generic outer sentence, and the
    /// cause that actually says what happened one hop below.
    #[derive(Debug)]
    struct Layer {
        message: String,
        source: Option<Box<Layer>>,
    }

    impl Layer {
        fn new(message: &str, source: Option<Layer>) -> Self {
            Self {
                message: message.to_owned(),
                source: source.map(Box::new),
            }
        }
    }

    impl fmt::Display for Layer {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(&self.message)
        }
    }

    impl Error for Layer {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            self.source.as_deref().map(|s| s as &(dyn Error + 'static))
        }
    }

    /// The regression this exists for: two completely different faults used to read identically,
    /// because only the outer sentence was formatted. `error sending request for url (…)` sends an
    /// operator nowhere; `connection timed out` and `certificate verify failed` send them to two
    /// different places.
    #[test]
    fn the_terminal_cause_is_what_tells_two_faults_apart() {
        let outer = "error sending request for url (https://tsl.example.invalid/TSL.xml)";
        let timeout = Layer::new(
            outer,
            Some(Layer::new(
                "client error (Connect)",
                Some(Layer::new("connection timed out", None)),
            )),
        );
        let tls = Layer::new(
            outer,
            Some(Layer::new(
                "client error (Connect)",
                Some(Layer::new("invalid peer certificate: UnknownIssuer", None)),
            )),
        );

        let timeout = describe_error_chain(&timeout);
        let tls = describe_error_chain(&tls);
        assert!(timeout.ends_with("connection timed out"), "{timeout}");
        assert!(
            tls.ends_with("invalid peer certificate: UnknownIssuer"),
            "{tls}"
        );
        assert_ne!(
            timeout, tls,
            "a timeout and a rejected certificate must not read the same"
        );
        // The outer sentence is kept — it still names the URL that was attempted.
        assert!(timeout.starts_with(outer), "{timeout}");
    }

    #[test]
    fn a_cause_that_merely_repeats_its_parent_is_not_printed_twice() {
        let repeated = Layer::new(
            "dns error: failed to lookup address information",
            Some(Layer::new("failed to lookup address information", None)),
        );
        assert_eq!(
            describe_error_chain(&repeated),
            "dns error: failed to lookup address information"
        );
    }

    #[test]
    fn a_single_error_with_no_cause_is_unchanged() {
        assert_eq!(
            describe_error_chain(&Layer::new("builder error", None)),
            "builder error"
        );
    }

    /// A chain deeper than the bound is truncated rather than followed forever. This runs while an
    /// operator is waiting on a failing signature.
    #[test]
    fn a_pathologically_deep_chain_is_bounded() {
        let mut layer = Layer::new("cause-0", None);
        for i in 1..40 {
            layer = Layer::new(&format!("cause-{i}"), Some(layer));
        }
        let described = describe_error_chain(&layer);
        assert_eq!(described.matches(": ").count(), MAX_ERROR_CHAIN_DEPTH - 1);
    }
}
