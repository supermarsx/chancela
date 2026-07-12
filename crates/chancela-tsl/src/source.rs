//! Trusted List transport: the [`TslSource`] trait plus a network source and a file source.
//!
//! Fetching is abstracted behind a trait so the parse/status/cache/query logic is fully testable
//! offline against a bundled fixture ([`FileTslSource`]); the live network fetch
//! ([`HttpTslSource`]) is exercised only by a feature-gated, `#[ignore]`d test.

use std::path::PathBuf;

use sha2::{Digest, Sha256};

use crate::error::TslError;

/// The default location of the Portuguese Trusted List published by the Gabinete Nacional de
/// Seguranca (GNS). Overridable via the `CHANCELA_TSL_URL` environment variable (§2.3). The URL
/// is also resolvable from the EU List of Trusted Lists (LOTL); it is pinned here so an offline
/// build has a sane default.
///
/// **Verified live 2026-07-07**: this returns the current `TrustServiceStatusList` (scheme
/// operator "Gabinete Nacional de Segurança"). GNS periodically **renames the published asset**
/// — the previous pin `media/2793/TSL_PT.xml` now 404s because the CMS id path and filename
/// changed (`TSL_PT.xml` → `TSLPT.xml`). The un-numbered `media/TSLPT.xml` form is the stabler
/// one, but this is a remote we do not control: if it 404s again, override it with
/// `CHANCELA_TSL_URL` (the escape hatch) and re-resolve the current URL from the EU LOTL.
pub const DEFAULT_PT_TSL_URL: &str = "https://www.gns.gov.pt/media/TSLPT.xml";

/// The environment variable that overrides [`DEFAULT_PT_TSL_URL`] (§2.3).
pub const ENV_TSL_URL: &str = "CHANCELA_TSL_URL";

/// Environment variable naming a file of trust-anchor certificate(s) for the Trusted List's own
/// XML-DSig signature (SIG-11, audit t41/C2 part H4). The file may hold one or more PEM
/// `CERTIFICATE` blocks, or a single raw DER certificate. Each certificate is the EU LOTL /
/// national scheme's XML-DSig **signing certificate** (the leaf that signs the published list) —
/// the list's signer certificate must byte-match one of these, or the list is reported untrusted.
///
/// This is deliberately a **pin of the actual signing certificate(s)**, not a CA under which an
/// arbitrary leaf could be minted: the Trusted List is the system's root of trust, so anchoring to
/// the exact publishing certificate is the strongest, least-ambiguous check. Configure multiple
/// certificates (or fingerprints, see [`ENV_TSL_TRUST_ANCHOR_SHA256`]) to cover key rotation.
pub const ENV_TSL_TRUST_ANCHOR: &str = "CHANCELA_TSL_TRUST_ANCHOR";

/// Environment variable holding one or more hex SHA-256 fingerprints (over the DER encoding of the
/// signer certificate) to pin as trust anchors, as an alternative to shipping the certificate file
/// in [`ENV_TSL_TRUST_ANCHOR`]. Entries may be separated by commas, semicolons or whitespace, and
/// the bytes within one fingerprint may be colon-separated (`AB:CD:...`). Both variables are a
/// union: a signer matching **any** configured certificate or fingerprint is anchored.
pub const ENV_TSL_TRUST_ANCHOR_SHA256: &str = "CHANCELA_TSL_TRUST_ANCHOR_SHA256";

/// A source of Trusted List XML bytes. Implemented by the live network fetcher and by the
/// on-disk/fixture loader; production code and tests both program against this trait.
pub trait TslSource {
    /// Fetch the raw Trusted List XML.
    fn fetch(&self) -> Result<Vec<u8>, TslError>;
}

/// Fetches the Trusted List over HTTPS with a blocking `reqwest` client.
///
/// Constructed from [`CHANCELA_TSL_URL`](ENV_TSL_URL) or [`DEFAULT_PT_TSL_URL`]. Only the
/// feature-gated, `#[ignore]`d network test drives this against the live endpoint; nothing in CI
/// touches the network.
#[derive(Debug, Clone)]
pub struct HttpTslSource {
    url: String,
}

impl HttpTslSource {
    /// Build a source for an explicit URL.
    pub fn new(url: impl Into<String>) -> Self {
        Self { url: url.into() }
    }

    /// Build a source from `CHANCELA_TSL_URL`, falling back to [`DEFAULT_PT_TSL_URL`].
    pub fn from_env() -> Self {
        let url = std::env::var(ENV_TSL_URL).unwrap_or_else(|_| DEFAULT_PT_TSL_URL.to_owned());
        Self::new(url)
    }

    /// The URL this source will fetch.
    pub fn url(&self) -> &str {
        &self.url
    }
}

impl TslSource for HttpTslSource {
    fn fetch(&self) -> Result<Vec<u8>, TslError> {
        let bytes = reqwest::blocking::get(&self.url)?
            .error_for_status()?
            .bytes()?;
        Ok(bytes.to_vec())
    }
}

/// Loads Trusted List XML from a local file — used for the bundled test fixture and for pinning a
/// downloaded list on disk.
#[derive(Debug, Clone)]
pub struct FileTslSource {
    path: PathBuf,
}

impl FileTslSource {
    /// Build a source that reads `path`.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl TslSource for FileTslSource {
    fn fetch(&self) -> Result<Vec<u8>, TslError> {
        Ok(std::fs::read(&self.path)?)
    }
}

/// A source backed by in-memory bytes (handy for tests that hold the XML directly).
#[derive(Debug, Clone)]
pub struct BytesTslSource {
    bytes: Vec<u8>,
}

impl BytesTslSource {
    /// Wrap raw XML bytes as a source.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            bytes: bytes.into(),
        }
    }
}

impl TslSource for BytesTslSource {
    fn fetch(&self) -> Result<Vec<u8>, TslError> {
        Ok(self.bytes.clone())
    }
}

/// A configured set of trust anchors for the Trusted List's own XML-DSig signature (SIG-11, audit
/// t41/C2 part H4).
///
/// The Trusted List is the system's root of trust: it declares which CAs are "qualified". Its own
/// XML-DSig signature carries the signer certificate **inside the list** (`<ds:KeyInfo>`), so
/// verifying the signature against that embedded certificate only proves the bytes are
/// self-consistent — anyone can mint a self-signed list that verifies against its own embedded
/// key. To be authentic, the signer certificate must match a certificate the operator has
/// configured out-of-band: the EU LOTL / national scheme signing certificate.
///
/// Matching is by exact certificate (equivalently, by the SHA-256 fingerprint of the DER
/// encoding). An **empty** anchor set trusts nothing — [`is_anchored`](Self::is_anchored) always
/// returns `false` — which is the fail-closed default when no anchor is configured.
#[derive(Debug, Clone, Default)]
pub struct TslTrustAnchors {
    /// SHA-256 fingerprints (over DER) of the trusted signer certificate(s). Configured
    /// certificates are reduced to their fingerprint; pinned fingerprints are stored directly.
    fingerprints: Vec<[u8; 32]>,
}

impl TslTrustAnchors {
    /// An empty anchor set. On its own this trusts no list (fail closed); add anchors with
    /// [`with_cert_der`](Self::with_cert_der) / [`with_fingerprint`](Self::with_fingerprint) or
    /// load them from the environment with [`from_env`](Self::from_env).
    pub fn new() -> Self {
        Self::default()
    }

    /// `true` when no anchor is configured. A list can never be trusted against an empty set.
    pub fn is_empty(&self) -> bool {
        self.fingerprints.is_empty()
    }

    /// The number of distinct anchors configured.
    pub fn len(&self) -> usize {
        self.fingerprints.len()
    }

    /// Pin a trust anchor by the SHA-256 fingerprint of its DER encoding (deduplicated).
    pub fn with_fingerprint(mut self, fingerprint: [u8; 32]) -> Self {
        if !self.fingerprints.contains(&fingerprint) {
            self.fingerprints.push(fingerprint);
        }
        self
    }

    /// Pin a trust anchor by its DER-encoded certificate. The certificate is reduced to its
    /// SHA-256 fingerprint for matching.
    pub fn with_cert_der(self, cert_der: &[u8]) -> Self {
        let fingerprint: [u8; 32] = Sha256::digest(cert_der).into();
        self.with_fingerprint(fingerprint)
    }

    /// Load trust anchors from the environment, **failing closed**: reads
    /// [`ENV_TSL_TRUST_ANCHOR`] (a PEM/DER certificate file) and
    /// [`ENV_TSL_TRUST_ANCHOR_SHA256`] (pinned hex fingerprints), taking the union.
    ///
    /// Returns an **empty** set (which trusts nothing) when neither variable is set. Returns
    /// [`TslError::TrustAnchorConfig`] / [`TslError::Io`] when a variable *is* set but the file
    /// cannot be read or the value cannot be parsed — a misconfigured anchor trusts nothing rather
    /// than silently degrading to "unanchored".
    pub fn from_env() -> Result<Self, TslError> {
        let mut anchors = Self::new();

        if let Ok(path) = std::env::var(ENV_TSL_TRUST_ANCHOR) {
            let path = path.trim();
            if !path.is_empty() {
                let bytes = std::fs::read(path)?;
                for cert_der in parse_anchor_certs(&bytes)? {
                    anchors = anchors.with_cert_der(&cert_der);
                }
            }
        }

        if let Ok(list) = std::env::var(ENV_TSL_TRUST_ANCHOR_SHA256) {
            for entry in list
                .split([',', ';', ' ', '\t', '\n', '\r'])
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
            {
                anchors = anchors.with_fingerprint(parse_hex_sha256(entry)?);
            }
        }

        Ok(anchors)
    }

    /// `true` when `signer_cert_der` (the DER read from the list's `<ds:X509Certificate>`) matches
    /// a configured anchor. Always `false` for an empty set (fail closed).
    pub fn is_anchored(&self, signer_cert_der: &[u8]) -> bool {
        if self.fingerprints.is_empty() {
            return false;
        }
        let fingerprint: [u8; 32] = Sha256::digest(signer_cert_der).into();
        self.fingerprints.contains(&fingerprint)
    }
}

/// Extract one or more DER certificates from a trust-anchor file: parse every PEM
/// `-----BEGIN CERTIFICATE-----` block if present, else treat the whole file as a single DER
/// certificate.
fn parse_anchor_certs(bytes: &[u8]) -> Result<Vec<Vec<u8>>, TslError> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";

    let text = String::from_utf8_lossy(bytes);
    if !text.contains(BEGIN) {
        // No PEM armor: treat the raw bytes as a single DER certificate.
        if bytes.is_empty() {
            return Err(TslError::TrustAnchorConfig(
                "trust-anchor file is empty".to_owned(),
            ));
        }
        return Ok(vec![bytes.to_vec()]);
    }

    let mut certs = Vec::new();
    let mut rest: &str = &text;
    while let Some(begin) = rest.find(BEGIN) {
        let after = &rest[begin + BEGIN.len()..];
        let end = after.find(END).ok_or_else(|| {
            TslError::TrustAnchorConfig(
                "PEM trust anchor is missing an END CERTIFICATE marker".to_owned(),
            )
        })?;
        let body: String = after[..end].split_whitespace().collect();
        let der = crate::parse::decode_base64(&body)?;
        certs.push(der);
        rest = &after[end + END.len()..];
    }

    if certs.is_empty() {
        return Err(TslError::TrustAnchorConfig(
            "no PEM CERTIFICATE blocks found in trust-anchor file".to_owned(),
        ));
    }
    Ok(certs)
}

/// Parse a single hex SHA-256 fingerprint (64 hex nibbles, optional `:` byte separators).
fn parse_hex_sha256(s: &str) -> Result<[u8; 32], TslError> {
    let cleaned: String = s.chars().filter(|c| *c != ':').collect();
    let bytes = cleaned.as_bytes();
    if bytes.len() != 64 {
        return Err(TslError::TrustAnchorConfig(format!(
            "SHA-256 fingerprint must be 64 hex characters, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    for (i, pair) in bytes.chunks_exact(2).enumerate() {
        let hi = hex_nibble(pair[0])?;
        let lo = hex_nibble(pair[1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

/// Decode a single ASCII hex digit into its 0..=15 value.
fn hex_nibble(c: u8) -> Result<u8, TslError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        other => Err(TslError::TrustAnchorConfig(format!(
            "invalid hex character in SHA-256 fingerprint: {:?}",
            other as char
        ))),
    }
}

/// Validate the Trusted List's own XML-DSig signature against trust anchors read from the
/// environment (SIG-11, audit t41/C2 part H4).
///
/// This resolves [`TslTrustAnchors::from_env`] and delegates to
/// [`validate_tsl_signature_with_anchors`]. **It fails closed:** when no anchor is configured
/// (neither [`ENV_TSL_TRUST_ANCHOR`] nor [`ENV_TSL_TRUST_ANCHOR_SHA256`] is set), the anchor set
/// is empty and every list — including a cryptographically self-consistent, self-signed one —
/// is reported [`TslError::SignatureUntrusted`]. Callers that already hold a configured anchor
/// (e.g. sourced from application config) should call [`validate_tsl_signature_with_anchors`]
/// directly rather than round-tripping through the environment.
///
/// The public signature is unchanged from the pre-anchoring version (`&[u8] -> Result<(),
/// TslError>`), so existing callers keep compiling; their behaviour changes from "trusts any
/// self-consistent list" to "trusts only an anchored list, else untrusted".
///
/// # What is implemented
///
/// - Parsing the XML-DSig structure: `Signature`, `SignedInfo`, `SignatureValue`, `Reference`,
///   `DigestMethod`, `DigestValue`, `SignatureMethod`, `CanonicalizationMethod`, `KeyInfo`,
///   `X509Data`, `X509Certificate`.
/// - Extracting the signer certificate (base64 DER from `<ds:X509Certificate>`).
/// - Computing the digest of the referenced content. For `URI=""` (the whole document), the
///   signed content is the document with the `<ds:Signature>` element removed. For a simple
///   same-document fragment (`URI="#id"`), the signed content may be the
///   `TrustServiceStatusList` root element with a unique matching `Id`/`ID`/`id`/`xml:id`
///   attribute.
/// - Rejecting unsupported explicit reference transforms. The enveloped-signature transform and
///   C14N transform URIs are accepted only for already-canonical whole-document and root-fragment
///   paths.
/// - Verifying an RSA-SHA256 or P-256 ECDSA-SHA256 signature value against the embedded signer
///   certificate's public key. ECDSA XML-DSig values must be raw fixed-width `r||s` bytes; DER
///   `ECDSA-Sig-Value` encodings are rejected.
/// - **Signer trust anchoring.** After the signature verifies, the embedded signer certificate is
///   required to match a configured [`TslTrustAnchors`] entry (the EU LOTL / national scheme
///   signing certificate). A self-signed list that verifies against its own embedded key but is
///   not anchored is reported [`TslError::SignatureUntrusted`]; an empty anchor set trusts nothing
///   (fail closed).
///
/// # What is NOT implemented (limitations documented)
///
/// - **XML canonicalization (C14N).** Without a canonicalization library, this implementation
///   uses the raw bytes of the referenced content (with the Signature element stripped for
///   `URI=""`). This is correct for TSLs that are already in canonical form (no comments,
///   consistent attribute ordering, UTF-8 encoding) but MAY fail for TSLs that require
///   non-trivial canonicalization. The `CanonicalizationMethod` algorithm is checked: if it is
///   not `http://www.w3.org/TR/2001/REC-xml-c14n-20010315` (inclusive C14N) or
///   `http://www.w3.org/2001/10/xml-exc-c14n#` (exclusive C14N), an error is returned.
/// - **Certificate-path building / revocation.** Anchoring is by exact certificate (SHA-256
///   fingerprint) match, not by building a path to an issuing CA. The configured anchor must be
///   the actual XML-DSig signing certificate(s), and rotation is handled by configuring multiple
///   anchors. Revocation status and certificate validity policy of the signer are not checked.
/// - **Transform chains.** Enveloped-signature removal is applied for `URI=""` and for supported
///   root `URI="#id"` references when the reference explicitly carries the enveloped-signature
///   transform. Explicit C14N transform URIs are accepted as already-canonical no-ops; other
///   transforms are rejected.
/// - **Reference URI fragments.** Only simple same-document fragments that resolve uniquely to the
///   `TrustServiceStatusList` root are supported. External URIs, xpointer expressions, empty
///   fragments, duplicate IDs, and non-root fragment targets are rejected fail-closed.
/// - **Multiple references/signatures.** Rejected fail-closed; XML-DSig requires every reference to
///   be checked and this minimal verifier supports exactly one signature with one reference.
/// - **ECDSA scope.** Only P-256 ECDSA-SHA256 is supported, and only in XML-DSig's raw `r||s`
///   signature-value form.
///
/// For real-world Portuguese TSLs, the signature is typically a single enveloped signature over
/// the whole document (`URI=""`) with exclusive C14N, RSA-SHA256 or P-256 ECDSA-SHA256.
pub fn validate_tsl_signature(xml: &[u8]) -> Result<(), TslError> {
    let anchors = TslTrustAnchors::from_env()?;
    validate_tsl_signature_with_anchors(xml, &anchors)
}

/// Validate the Trusted List's own XML-DSig signature against an explicitly-supplied set of trust
/// anchors (SIG-11, audit t41/C2 part H4).
///
/// Behaves exactly like [`validate_tsl_signature`] but takes the [`TslTrustAnchors`] as a
/// parameter instead of resolving them from the environment. This is the entry point for callers
/// that source the anchor from application configuration, and the one used by tests. Passing an
/// empty anchor set fails closed: the signature is checked for internal consistency, then rejected
/// with [`TslError::SignatureUntrusted`] because no anchor could vouch for the signer.
pub fn validate_tsl_signature_with_anchors(
    xml: &[u8],
    anchors: &TslTrustAnchors,
) -> Result<(), TslError> {
    let parsed = crate::xmldsig::parse_signature(xml)?;
    parsed.verify(xml, anchors)
}

#[cfg(test)]
mod anchor_tests {
    use super::*;

    #[test]
    fn empty_anchor_set_is_never_anchored() {
        let anchors = TslTrustAnchors::new();
        assert!(anchors.is_empty());
        assert!(!anchors.is_anchored(b"any cert bytes"));
    }

    #[test]
    fn with_cert_der_anchors_that_exact_cert() {
        let cert = b"a specific DER certificate";
        let anchors = TslTrustAnchors::new().with_cert_der(cert);
        assert!(!anchors.is_empty());
        assert!(anchors.is_anchored(cert));
        assert!(!anchors.is_anchored(b"a different certificate"));
    }

    #[test]
    fn with_fingerprint_matches_cert_of_that_fingerprint() {
        let cert = b"another DER certificate";
        let fingerprint: [u8; 32] = Sha256::digest(cert).into();
        let anchors = TslTrustAnchors::new().with_fingerprint(fingerprint);
        assert!(anchors.is_anchored(cert));
    }

    #[test]
    fn duplicate_anchors_are_deduplicated() {
        let cert = b"dup";
        let anchors = TslTrustAnchors::new()
            .with_cert_der(cert)
            .with_cert_der(cert);
        assert_eq!(anchors.len(), 1);
    }

    #[test]
    fn parse_hex_sha256_accepts_plain_and_colon_separated() {
        let plain = "0".repeat(64);
        assert_eq!(parse_hex_sha256(&plain).unwrap(), [0u8; 32]);

        let colon = std::iter::repeat_n("ff", 32).collect::<Vec<_>>().join(":");
        assert_eq!(parse_hex_sha256(&colon).unwrap(), [0xffu8; 32]);
    }

    #[test]
    fn parse_hex_sha256_rejects_wrong_length_and_bad_chars() {
        assert!(matches!(
            parse_hex_sha256("abcd"),
            Err(TslError::TrustAnchorConfig(_))
        ));
        assert!(matches!(
            parse_hex_sha256(&"z".repeat(64)),
            Err(TslError::TrustAnchorConfig(_))
        ));
    }

    #[test]
    fn parse_anchor_certs_reads_raw_der_as_one_cert() {
        let der = vec![0x30u8, 0x03, 0x01, 0x01, 0xff];
        let certs = parse_anchor_certs(&der).unwrap();
        assert_eq!(certs, vec![der]);
    }

    #[test]
    fn parse_anchor_certs_reads_multiple_pem_blocks() {
        // Two PEM blocks whose bodies base64-decode to distinct byte strings.
        let pem = "\
-----BEGIN CERTIFICATE-----\nAAECAwQF\n-----END CERTIFICATE-----\n\
-----BEGIN CERTIFICATE-----\nBgcICQoL\n-----END CERTIFICATE-----\n";
        let certs = parse_anchor_certs(pem.as_bytes()).unwrap();
        assert_eq!(certs.len(), 2);
        assert_eq!(certs[0], vec![0, 1, 2, 3, 4, 5]);
        assert_eq!(certs[1], vec![6, 7, 8, 9, 10, 11]);
    }

    #[test]
    fn parse_anchor_certs_rejects_empty_and_unterminated_pem() {
        assert!(matches!(
            parse_anchor_certs(b""),
            Err(TslError::TrustAnchorConfig(_))
        ));
        assert!(matches!(
            parse_anchor_certs(b"-----BEGIN CERTIFICATE-----\nAAA\n"),
            Err(TslError::TrustAnchorConfig(_))
        ));
    }
}
