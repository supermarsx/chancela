//! An XML-DSig validator for the Trusted List's own `<ds:Signature>` element (SIG-11, audit
//! t41/C2).
//!
//! See [`crate::source::validate_tsl_signature`] for the public entry point and the documented
//! verification boundary. This module extracts just enough of the XML-DSig structure to verify the
//! signature value against the signer certificate's public key, routing canonicalization through the
//! real C14N implementation in [`crate::c14n`] (wp26 E2) rather than hashing raw source bytes.
//!
//! # Canonicalization: real C14N with an already-canonical fast path
//! XML-DSig signs the *canonical* form of `<ds:SignedInfo>` (per the declared
//! `CanonicalizationMethod`) and of each `<ds:Reference>`'s transformed content. For genuinely
//! non-canonical real-world EU LOTL / member-state TSLs, reconstructing those canonical bytes is
//! mandatory, so this verifier feeds the relevant subtree — with the ancestor `xmlns` context
//! hoisted onto `<ds:SignedInfo>` as C14N requires — through [`crate::c14n::canonicalize`].
//!
//! Both the SignedInfo signature check and the reference digest check are evaluated against a small
//! ordered set of candidate byte streams: the real C14N output **and** the raw source octets (the
//! historical "already-canonical fast path"). Verification succeeds if *any* candidate matches. This
//! is safe — every candidate is still cryptographically bound to the one signature/digest, so an
//! attacker cannot forge either form without the signer's key, and tampering perturbs *all*
//! candidates — while keeping lists that were signed over already-serialized-canonical bytes valid.
//!
//! # Multiple references
//! Real EU LOTL / member-state Trusted Lists routinely carry more than one `<ds:Reference>` — the
//! document itself plus a XAdES `SignedProperties` element, sometimes a `KeyInfo` reference. This
//! verifier supports that, under three rules that keep it sound rather than merely permissive:
//!
//! 1. **Every** reference inside `<ds:SignedInfo>` is resolved, transformed, canonicalized, digested
//!    and compared. One mismatch fails the whole signature; nothing is verified "best effort".
//! 2. At least one digest-verified reference must genuinely **cover the Trusted List document** (the
//!    same-document `URI=""` form, or a fragment resolving to the `TrustServiceStatusList` root).
//!    A signature whose references all point at auxiliary material authenticates nothing and is
//!    refused — the classic "valid signature over nothing" wrapping attack.
//! 3. A reference the verifier cannot evaluate (external `http(s)`/`ftp` URI, xpointer expression,
//!    unsupported transform or digest algorithm) is a hard failure naming the construct, never a
//!    silent skip.
//!
//! # Algorithms
//! Digest and signature algorithms are resolved through exact allowlists over complete URIs
//! ([`DigestAlgorithm::from_uri`], [`SignatureAlgorithm::from_uri`]) — never a prefix or substring
//! test, and never a default when the URI is unrecognised. Supported: SHA-256/384/512 digests;
//! `rsa-sha256`/`-sha384`/`-sha512`; `ecdsa-sha256`/`-sha384`/`-sha512` (P-256/P-384/P-521). SHA-1
//! and MD5 are absent by design and must stay absent — a list relying on them is refused by name.
//!
//! Each `<ds:Reference>` names its own `<ds:DigestMethod>`, so the digest is dispatched per
//! reference; the `<ds:SignedInfo>` hash comes from the declared `<ds:SignatureMethod>`, so it can
//! only ever be the one that method names. Both are read from inside `<ds:SignedInfo>`, which the
//! `<ds:SignatureValue>` commits to, so an attacker cannot downgrade either without invalidating
//! the signature.
//!
//! Only references inside `<ds:SignedInfo>` are collected: they are the ones the
//! `<ds:SignatureValue>` commits to. A `<ds:Reference>` elsewhere in the signature (e.g. inside a
//! `<ds:Manifest>` in a `<ds:Object>`) sits outside the signed scope, so it can neither be trusted
//! nor satisfy the coverage rule.

use der::{Decode, Encode};
use sha2::Digest;

use crate::c14n::C14nAlgorithm;
use crate::error::TslError;
use crate::parse::decode_base64;
use crate::source::TslTrustAnchors;

// ---- URIs -------------------------------------------------------------------------------------
//
// Canonicalization URIs are deliberately NOT listed here. `C14nAlgorithm::from_uri` is the single
// source of truth for what this build can actually canonicalize, so resolving through it makes it
// impossible to accept a canonicalization URI that `c14n.rs` cannot compute. In particular C14N 1.1
// (`http://www.w3.org/2006/12/xml-c14n11`) is NOT accepted: `c14n.rs` implements the 1.0 semantics,
// and 1.1 differs in how `xml:`-namespace attributes are inherited onto the apex element.

/// RSASSA-PKCS1-v1_5 over SHA-256 (RFC 4051).
const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
/// RSASSA-PKCS1-v1_5 over SHA-384 (RFC 4051).
const RSA_SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
/// RSASSA-PKCS1-v1_5 over SHA-512 (RFC 4051) — what the live GNS Portuguese Trusted List uses.
const RSA_SHA512: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";

/// RSASSA-PSS over SHA-256, MGF1-SHA-256 (RFC 9231 §2.3.9).
const RSA_PSS_SHA256: &str = "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1";
/// RSASSA-PSS over SHA-384, MGF1-SHA-384 (RFC 9231 §2.3.9).
const RSA_PSS_SHA384: &str = "http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1";
/// RSASSA-PSS over SHA-512, MGF1-SHA-512 (RFC 9231 §2.3.9).
const RSA_PSS_SHA512: &str = "http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1";
/// RSASSA-PSS over SHA3-256, MGF1-SHA3-256 (RFC 9231 §2.3.9).
const RSA_PSS_SHA3_256: &str = "http://www.w3.org/2007/05/xmldsig-more#sha3-256-rsa-MGF1";
/// RSASSA-PSS over SHA3-384, MGF1-SHA3-384 (RFC 9231 §2.3.9).
const RSA_PSS_SHA3_384: &str = "http://www.w3.org/2007/05/xmldsig-more#sha3-384-rsa-MGF1";
/// RSASSA-PSS over SHA3-512, MGF1-SHA3-512 (RFC 9231 §2.3.9).
const RSA_PSS_SHA3_512: &str = "http://www.w3.org/2007/05/xmldsig-more#sha3-512-rsa-MGF1";

/// ECDSA over SHA-256 (RFC 4051). Per RFC 9231 the URI names the **hash only** — the curve comes
/// from the signer's key, never from this URI.
const ECDSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
/// ECDSA over SHA-384 (RFC 4051); hash only, curve from the key.
const ECDSA_SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384";
/// ECDSA over SHA-512 (RFC 4051); hash only, curve from the key.
const ECDSA_SHA512: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512";

/// SHA-256 digest method (XML Encryption).
const SHA256_DIGEST: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
/// SHA-384 digest method (RFC 4051) — the URI Apache Santuario and the EU signature stacks emit.
const SHA384_DIGEST: &str = "http://www.w3.org/2001/04/xmldsig-more#sha384";
/// SHA-384 digest method as separately registered by XML Encryption 1.1 (§5.7.2). A second standard
/// URI naming the *same* algorithm — accepted so a conforming signer that picked the XML Encryption
/// spelling is not refused, and listed explicitly rather than pattern-matched.
const SHA384_DIGEST_XMLENC: &str = "http://www.w3.org/2001/04/xmlenc#sha384";
/// SHA-512 digest method (XML Encryption) — what the live GNS Portuguese Trusted List uses.
const SHA512_DIGEST: &str = "http://www.w3.org/2001/04/xmlenc#sha512";
/// SHA3-256 digest method (RFC 9231 §2.1).
const SHA3_256_DIGEST: &str = "http://www.w3.org/2007/05/xmldsig-more#sha3-256";
/// SHA3-384 digest method (RFC 9231 §2.1).
const SHA3_384_DIGEST: &str = "http://www.w3.org/2007/05/xmldsig-more#sha3-384";
/// SHA3-512 digest method (RFC 9231 §2.1).
const SHA3_512_DIGEST: &str = "http://www.w3.org/2007/05/xmldsig-more#sha3-512";

/// XML-DSig enveloped-signature transform.
const ENVELOPED_SIGNATURE_TRANSFORM: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

/// Canonical XML 1.1. Named here only so the refusal can explain itself: this build implements the
/// C14N 1.0 semantics, and 1.1 differs in how `xml:`-namespace attributes (`xml:base`, `xml:lang`,
/// `xml:space`) are inherited onto the apex element of a signed subtree.
const C14N_11: &str = "http://www.w3.org/2006/12/xml-c14n11";

// ---- Legacy (broken) algorithms ---------------------------------------------------------------

/// SHA-1 digest method — **cryptographically broken**. Refused unless an operator has explicitly
/// enabled this exact URI via [`TslAlgorithmPolicy`].
pub const LEGACY_SHA1_DIGEST: &str = "http://www.w3.org/2000/09/xmldsig#sha1";
/// RSASSA-PKCS1-v1_5 over SHA-1 — **cryptographically broken**; opt-in only.
pub const LEGACY_RSA_SHA1: &str = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
/// ECDSA over SHA-1 — **cryptographically broken**; opt-in only.
pub const LEGACY_ECDSA_SHA1: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1";

/// Every legacy algorithm URI an operator may enable, and the closed set the settings layer must
/// validate against.
///
/// Membership means exactly two things: the algorithm is **broken**, and this build can genuinely
/// compute it. MD5 and RIPEMD-160 are absent from this list and permanently refused — not as a
/// policy stance but because nothing in the dependency tree computes them, and allowlisting a URI
/// this verifier cannot evaluate would be strictly worse than refusing it.
///
/// This list is what makes the setting a closed vocabulary rather than an arbitrary-URI escape
/// hatch: an operator can name a *known* broken algorithm, never an unknown one.
pub const KNOWN_LEGACY_ALGORITHMS: &[&str] =
    &[LEGACY_SHA1_DIGEST, LEGACY_RSA_SHA1, LEGACY_ECDSA_SHA1];

/// Stable diagnostic code: a `<ds:Reference>` digest was verified with an operator-enabled broken
/// digest algorithm. Machine-readable and append-only; the web layer translates it.
pub const CODE_WEAK_DIGEST_PERMITTED: &str = "tsl_weak_digest_permitted";
/// Stable diagnostic code: the `<ds:SignatureValue>` was verified under an operator-enabled broken
/// signature method. Machine-readable and append-only; the web layer translates it.
pub const CODE_WEAK_SIGNATURE_METHOD_PERMITTED: &str = "tsl_weak_signature_method_permitted";

/// Which algorithms a Trusted List signature may be verified with.
///
/// Empty is the only default, and it is fail-closed in the sense that matters: the strong
/// algorithms are always available, and **no** broken algorithm is. An operator enables a broken
/// algorithm by naming its exact URI — never with a blanket switch, which would silently widen to
/// every weak primitive added later.
///
/// Enabling one algorithm permits that algorithm and nothing else. It relaxes no other check:
/// every reference is still digested, document coverage is still required, transforms and URIs are
/// still restricted, and the trust anchor must still match.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TslAlgorithmPolicy {
    enabled_legacy: Vec<String>,
}

impl TslAlgorithmPolicy {
    /// A policy permitting only strong algorithms. This is the default everywhere.
    pub fn new() -> Self {
        Self::default()
    }

    /// Permit one broken algorithm, named by its exact URI.
    ///
    /// Refuses anything outside [`KNOWN_LEGACY_ALGORITHMS`], so this cannot be used to smuggle an
    /// arbitrary URI past the exact-match allowlist the verifier is built on.
    pub fn with_legacy_algorithm(mut self, uri: &str) -> Result<Self, TslError> {
        if !KNOWN_LEGACY_ALGORITHMS.contains(&uri) {
            return Err(TslError::TrustAnchorConfig(format!(
                "unknown legacy TSL algorithm URI: {uri} — only these may be enabled: {}",
                KNOWN_LEGACY_ALGORITHMS.join(", ")
            )));
        }
        if !self.enabled_legacy.iter().any(|u| u == uri) {
            self.enabled_legacy.push(uri.to_owned());
        }
        Ok(self)
    }

    /// Whether this exact URI has been deliberately enabled.
    pub fn allows_legacy(&self, uri: &str) -> bool {
        self.enabled_legacy.iter().any(|u| u == uri)
    }

    /// Whether any broken algorithm is enabled at all.
    pub fn permits_any_legacy(&self) -> bool {
        !self.enabled_legacy.is_empty()
    }
}

/// Where a broken algorithm was relied upon.
///
/// Structured rather than prose: the web layer renders it from the parts, so no user-facing
/// sentence is emitted from Rust (server prose is invisible to the client copy gates).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "site", rename_all = "snake_case")]
pub enum WeakAlgorithmSite {
    /// The `<ds:SignatureMethod>` covering `<ds:SignedInfo>`.
    SignatureMethod,
    /// A `<ds:Reference>`'s `<ds:DigestMethod>`, at 1-based `index` of `total`.
    Reference {
        index: usize,
        total: usize,
        uri: String,
    },
}

/// One reliance on a broken algorithm that an operator had explicitly enabled.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WeakAlgorithmUse {
    /// Stable machine code ([`CODE_WEAK_DIGEST_PERMITTED`] /
    /// [`CODE_WEAK_SIGNATURE_METHOD_PERMITTED`]) for the web layer to translate.
    pub code: String,
    /// The exact algorithm URI relied upon.
    pub algorithm: String,
    /// Where it was relied upon.
    #[serde(flatten)]
    pub site: WeakAlgorithmSite,
}

/// The outcome of a successful Trusted List signature verification.
///
/// A signature can verify for two very different reasons, and this is what keeps them
/// distinguishable downstream: with strong algorithms throughout, or *because* an operator
/// permitted a broken one. `Ok(())` alone would erase that difference at exactly the point where
/// callers decide to call the list trustworthy, so success carries the evidence instead.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TslSignatureReport {
    /// Every reliance on an operator-enabled broken algorithm, in the order encountered. Empty
    /// means the whole signature verified under strong algorithms.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub weak_algorithms: Vec<WeakAlgorithmUse>,
}

impl TslSignatureReport {
    /// Whether this verification depended on a broken algorithm.
    pub fn relied_on_weak_algorithm(&self) -> bool {
        !self.weak_algorithms.is_empty()
    }
}

/// A message-digest algorithm this verifier can compute.
///
/// # Per-reference, not per-signature
/// XML-DSig lets every `<ds:Reference>` name its own `<ds:DigestMethod>`, and real lists do mix
/// them. The algorithm is therefore resolved from the URI *that reference* declares, not from a
/// single setting for the whole signature. Every such URI lives inside `<ds:SignedInfo>`, which the
/// `<ds:SignatureValue>` commits to, so the choice is signed: an attacker cannot downgrade a
/// reference's digest without invalidating the signature.
///
/// # Allowlist, and what `from_uri` does NOT decide
/// [`DigestAlgorithm::from_uri`] is an exact match over complete URIs — never a prefix match, a
/// substring test, or a fallback. An unrecognised URI resolves to `None` and becomes a hard refusal
/// naming both the URI and the reference carrying it.
///
/// Resolving a URI answers only "can this build compute it", **not** "may it be relied upon".
/// [`DigestAlgorithm::is_weak`] marks the broken ones, and the single policy check in
/// [`ParsedSignature::verify_with_policy`] refuses those unless an operator enabled that exact URI.
/// Keeping those two questions apart is what stops a weak algorithm from ever being permitted by
/// the mere fact that the code knows how to compute it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DigestAlgorithm {
    Sha256,
    Sha384,
    Sha512,
    Sha3_256,
    Sha3_384,
    Sha3_512,
    /// **Broken.** Only reachable when an operator enabled [`LEGACY_SHA1_DIGEST`].
    Sha1,
}

impl DigestAlgorithm {
    /// Resolve a `<ds:DigestMethod Algorithm>` URI, or `None` if this build cannot compute it.
    fn from_uri(uri: &str) -> Option<Self> {
        match uri {
            SHA256_DIGEST => Some(Self::Sha256),
            SHA384_DIGEST | SHA384_DIGEST_XMLENC => Some(Self::Sha384),
            SHA512_DIGEST => Some(Self::Sha512),
            SHA3_256_DIGEST => Some(Self::Sha3_256),
            SHA3_384_DIGEST => Some(Self::Sha3_384),
            SHA3_512_DIGEST => Some(Self::Sha3_512),
            LEGACY_SHA1_DIGEST => Some(Self::Sha1),
            _ => None,
        }
    }

    /// Whether this algorithm is cryptographically broken for signature use.
    fn is_weak(self) -> bool {
        matches!(self, Self::Sha1)
    }

    /// The digest of `bytes` under this algorithm.
    fn digest(self, bytes: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => sha2::Sha256::digest(bytes).to_vec(),
            Self::Sha384 => sha2::Sha384::digest(bytes).to_vec(),
            Self::Sha512 => sha2::Sha512::digest(bytes).to_vec(),
            Self::Sha3_256 => sha3::Sha3_256::digest(bytes).to_vec(),
            Self::Sha3_384 => sha3::Sha3_384::digest(bytes).to_vec(),
            Self::Sha3_512 => sha3::Sha3_512::digest(bytes).to_vec(),
            Self::Sha1 => sha1::Sha1::digest(bytes).to_vec(),
        }
    }
}

/// A `<ds:SignatureMethod>` this verifier can evaluate: the public-key scheme, plus the hash the
/// `<ds:SignedInfo>` must be reduced with.
///
/// The hash used over `SignedInfo` comes from here and nowhere else, so it can only ever be the one
/// the declared `SignatureMethod` names — a signature declaring `rsa-sha512` whose value was
/// actually produced over a SHA-256 reduction does not verify. The verifier never tries a second
/// hash looking for one that works, which would hand an attacker the weakest supported hash.
///
/// # ECDSA carries a hash, not a curve
/// RFC 9231 is explicit that `ecdsa-sha*` names the hash only; the curve is determined by the key.
/// An `ecdsa-sha512` signature over a P-384 key is legal. So [`SignatureAlgorithm::Ecdsa`] holds
/// the hash, and the curve is read separately from the signer certificate's SPKI.
///
/// # Deliberately refused
/// - `#rsa-pss` (the generic parameterized form): its parameters live in an `RSAPSSParams` element
///   this verifier does not parse, and RFC 9231 gives it a *SHA-1 default digest*. Only the
///   per-hash `#<hash>-rsa-MGF1` URIs, whose parameters are fixed by the spec, are accepted.
/// - EdDSA (`#eddsa-ed25519` and friends) and Ed448: no implementation in the dependency tree.
/// - SHA3-224 and any 224-bit digest: below the strength floor this verifier is widening *to*.
///
/// As with [`DigestAlgorithm`], resolving a URI says only that this build can compute it;
/// [`SignatureAlgorithm::is_weak`] plus the policy check decide whether it may be relied upon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SignatureAlgorithm {
    /// RSASSA-PKCS1-v1_5, reducing `SignedInfo` with the named hash.
    RsaPkcs1(DigestAlgorithm),
    /// RSASSA-PSS with MGF1 over the same hash and a salt the length of that hash (RFC 9231).
    RsaPss(DigestAlgorithm),
    /// ECDSA reducing `SignedInfo` with the named hash; the curve comes from the key.
    Ecdsa(DigestAlgorithm),
}

impl SignatureAlgorithm {
    /// Resolve a `<ds:SignatureMethod Algorithm>` URI, or `None` if this build cannot compute it.
    fn from_uri(uri: &str) -> Option<Self> {
        match uri {
            RSA_SHA256 => Some(Self::RsaPkcs1(DigestAlgorithm::Sha256)),
            RSA_SHA384 => Some(Self::RsaPkcs1(DigestAlgorithm::Sha384)),
            RSA_SHA512 => Some(Self::RsaPkcs1(DigestAlgorithm::Sha512)),
            LEGACY_RSA_SHA1 => Some(Self::RsaPkcs1(DigestAlgorithm::Sha1)),
            RSA_PSS_SHA256 => Some(Self::RsaPss(DigestAlgorithm::Sha256)),
            RSA_PSS_SHA384 => Some(Self::RsaPss(DigestAlgorithm::Sha384)),
            RSA_PSS_SHA512 => Some(Self::RsaPss(DigestAlgorithm::Sha512)),
            RSA_PSS_SHA3_256 => Some(Self::RsaPss(DigestAlgorithm::Sha3_256)),
            RSA_PSS_SHA3_384 => Some(Self::RsaPss(DigestAlgorithm::Sha3_384)),
            RSA_PSS_SHA3_512 => Some(Self::RsaPss(DigestAlgorithm::Sha3_512)),
            ECDSA_SHA256 => Some(Self::Ecdsa(DigestAlgorithm::Sha256)),
            ECDSA_SHA384 => Some(Self::Ecdsa(DigestAlgorithm::Sha384)),
            ECDSA_SHA512 => Some(Self::Ecdsa(DigestAlgorithm::Sha512)),
            LEGACY_ECDSA_SHA1 => Some(Self::Ecdsa(DigestAlgorithm::Sha1)),
            _ => None,
        }
    }

    /// The hash `<ds:SignedInfo>` is reduced with.
    fn hash(self) -> DigestAlgorithm {
        match self {
            Self::RsaPkcs1(h) | Self::RsaPss(h) | Self::Ecdsa(h) => h,
        }
    }

    /// Whether this method is cryptographically broken for signature use.
    fn is_weak(self) -> bool {
        self.hash().is_weak()
    }
}

/// The parsed XML-DSig `<ds:Signature>` element — enough to verify the signature.
#[derive(Debug, Clone)]
pub(crate) struct ParsedSignature {
    /// Number of `<ds:Signature>` elements seen. The minimal verifier supports exactly one.
    pub signature_count: usize,
    /// The canonicalization algorithm URI.
    pub canonicalization_method: String,
    /// The signature algorithm URI.
    pub signature_method: String,
    /// The base64-decoded signature value bytes.
    pub signature_value: Vec<u8>,
    /// Every `<ds:Reference>` carried **inside `<ds:SignedInfo>`**, in document order.
    ///
    /// XML-DSig requires every reference to be checked, and [`ParsedSignature::verify`] does exactly
    /// that. Only the SignedInfo references are collected because only they are inside the scope the
    /// `<ds:SignatureValue>` commits to — a `<ds:Reference>` living elsewhere in the signature
    /// (e.g. a `<ds:Manifest>` inside a `<ds:Object>`) is not signed, so an attacker could add one
    /// at will; it is neither verified nor allowed to satisfy the document-coverage rule.
    pub references: Vec<Reference>,
    /// The signer certificate DER (from `<ds:KeyInfo>/<ds:X509Data>/<ds:X509Certificate>`), if
    /// the signature carried one.
    pub signer_cert_der: Option<Vec<u8>>,
    /// The raw bytes of the `<ds:SignedInfo>` element (outer tag included), as they appeared in
    /// the original document — used to re-extract canonical signed bytes.
    pub signed_info_start: usize,
    pub signed_info_end: usize,
}

/// A parsed `<ds:Reference>` element.
#[derive(Debug, Clone)]
pub(crate) struct Reference {
    /// The `URI` attribute. `""` means the whole document (enveloped signature).
    pub uri: String,
    /// The digest method algorithm URI.
    pub digest_method: String,
    /// Explicit transform algorithm URIs carried by this reference.
    pub transforms: Vec<String>,
    /// The base64-decoded digest value bytes.
    pub digest_value: Vec<u8>,
}

impl ParsedSignature {
    /// Verify the parsed signature against `xml` (the original document bytes), then require the
    /// signer certificate to match a configured trust anchor.
    ///
    /// Steps 1-7 establish that the signature is internally consistent (structure, digests, and
    /// the signature value verify against the certificate the list itself carried). Step 8 is the
    /// trust decision (audit t41/C2 part H4): a self-signed list is internally consistent too, so
    /// the signer certificate MUST match `anchors` (the EU LOTL / national scheme signing
    /// certificate) or the list is reported [`TslError::SignatureUntrusted`]. An empty anchor set
    /// trusts nothing (fail closed).
    ///
    /// Verifies under strong algorithms only. Because [`TslAlgorithmPolicy::new`] enables no broken
    /// algorithm, success here provably relied on none, which is why this can keep returning `()`
    /// without losing information. Callers that let operators enable a legacy algorithm must use
    /// [`ParsedSignature::verify_with_policy`] and surface the report it returns.
    pub fn verify(self, xml: &[u8], anchors: &TslTrustAnchors) -> Result<(), TslError> {
        self.verify_with_policy(xml, anchors, &TslAlgorithmPolicy::new())
            .map(|_| ())
    }

    /// Verify under `policy`, returning what the verification depended on.
    ///
    /// Identical to [`ParsedSignature::verify`] in every check it performs; the policy only decides
    /// whether a *broken* algorithm may be relied upon, and every such reliance is recorded in the
    /// returned [`TslSignatureReport`] so callers can tell "valid" from "valid only because SHA-1
    /// was permitted".
    pub fn verify_with_policy(
        self,
        xml: &[u8],
        anchors: &TslTrustAnchors,
        policy: &TslAlgorithmPolicy,
    ) -> Result<TslSignatureReport, TslError> {
        let mut report = TslSignatureReport::default();
        // 1. Structural completeness: the signature must carry a value and at least one reference.
        if self.signature_count != 1 {
            return Err(TslError::SignatureStructure(format!(
                "expected exactly one <ds:Signature> element, found {}",
                self.signature_count
            )));
        }
        if self.signed_info_start == 0 && self.signed_info_end == 0 {
            return Err(TslError::SignatureStructure(
                "missing <ds:SignedInfo> element".to_owned(),
            ));
        }
        if self.canonicalization_method.is_empty() {
            return Err(TslError::SignatureStructure(
                "missing <ds:CanonicalizationMethod Algorithm>".to_owned(),
            ));
        }
        if self.signature_method.is_empty() {
            return Err(TslError::SignatureStructure(
                "missing <ds:SignatureMethod Algorithm>".to_owned(),
            ));
        }
        if self.signature_value.is_empty() {
            return Err(TslError::SignatureStructure(
                "empty <ds:SignatureValue>".to_owned(),
            ));
        }
        if self.references.is_empty() {
            return Err(TslError::SignatureStructure(
                "missing <ds:Reference> element".to_owned(),
            ));
        }

        // 2. Canonicalization method must be one this build can actually compute. Resolving through
        //    `C14nAlgorithm::from_uri` rather than a local list means the accepted set is exactly
        //    what `c14n.rs` implements — inclusive and exclusive C14N 1.0, each with and without
        //    comments. C14N 1.1 is not implemented and is therefore refused by name here.
        if C14nAlgorithm::from_uri(&self.canonicalization_method).is_none() {
            return Err(TslError::SignatureUnsupportedAlgorithm(format!(
                "canonicalization: {} — {}",
                self.canonicalization_method,
                unimplemented_canonicalization_reason(&self.canonicalization_method)
            )));
        }

        // 3./4. Resolve and digest EVERY reference listed in the signed `<ds:SignedInfo>`. Each one
        //    must have its transforms applied, be canonicalized, digested and compared against its
        //    own `<ds:DigestValue>`; one mismatch fails the whole signature. A reference the
        //    verifier cannot evaluate (external URI, xpointer, unsupported transform or digest) is a
        //    hard failure naming the construct — never a silent skip, which would leave
        //    attacker-controlled content inside the signed scope unchecked.
        //
        //    Alongside the digests, track whether any reference genuinely covers the Trusted List
        //    document. A set of references that all point at auxiliary material (a XAdES
        //    `SignedProperties` blob, a `KeyInfo` fragment) is a cryptographically valid signature
        //    over nothing, and must not authenticate the list.
        let reference_total = self.references.len();
        let mut covers_document = false;
        for (index, reference) in self.references.iter().enumerate() {
            let position = format!(
                "<ds:Reference {}/{reference_total} URI=\"{}\">",
                index + 1,
                reference.uri
            );
            if reference.digest_method.is_empty() {
                return Err(TslError::SignatureStructure(format!(
                    "missing <ds:DigestMethod Algorithm> on {position}"
                )));
            }
            // A transform is accepted only if it is the enveloped-signature transform or a
            // canonicalization `c14n.rs` implements — same single source of truth as step 2.
            for transform in &reference.transforms {
                if transform != ENVELOPED_SIGNATURE_TRANSFORM
                    && C14nAlgorithm::from_uri(transform).is_none()
                {
                    // A canonicalization we simply do not implement gets the same explanation here
                    // as it would as a `CanonicalizationMethod`, so the diagnosis does not depend on
                    // which slot of the signature the operator's signer happened to put it in.
                    let mut message = format!("transform: {transform} (on {position})");
                    if transform == C14N_11 {
                        message.push_str(" — ");
                        message.push_str(&unimplemented_canonicalization_reason(transform));
                    }
                    return Err(TslError::SignatureUnsupportedAlgorithm(message));
                }
            }
            if reference.digest_value.is_empty() {
                return Err(TslError::SignatureStructure(format!(
                    "empty <ds:DigestValue> on {position}"
                )));
            }
            // Digest method: resolved per reference from the URI THIS reference declares, against
            // an exact allowlist. Mixed digests across references are legal XML-DSig and are
            // handled; an unrecognised algorithm is a hard refusal naming the URI and the reference
            // position — never a default, never a skip.
            let Some(digest_algorithm) = DigestAlgorithm::from_uri(&reference.digest_method) else {
                return Err(TslError::SignatureUnsupportedAlgorithm(format!(
                    "digest: {} (on {position})",
                    reference.digest_method
                )));
            };
            // Knowing how to compute an algorithm is not permission to rely on it. A broken digest
            // is refused with the same message as an unknown one unless the operator enabled this
            // exact URI, and when they have, the reliance is recorded rather than passed over.
            if digest_algorithm.is_weak() {
                if !policy.allows_legacy(&reference.digest_method) {
                    return Err(TslError::SignatureUnsupportedAlgorithm(format!(
                        "digest: {} (on {position})",
                        reference.digest_method
                    )));
                }
                report.weak_algorithms.push(WeakAlgorithmUse {
                    code: CODE_WEAK_DIGEST_PERMITTED.to_owned(),
                    algorithm: reference.digest_method.clone(),
                    site: WeakAlgorithmSite::Reference {
                        index: index + 1,
                        total: reference_total,
                        uri: reference.uri.clone(),
                    },
                });
            }

            let resolved = resolve_referenced_content(xml, &reference.uri, &reference.transforms)?;
            if !reference_digest_matches(reference, digest_algorithm, &resolved) {
                return Err(TslError::SignatureDigestMismatch);
            }
            // Only a reference whose digest just verified may count towards coverage.
            if resolved.target.covers_document() {
                covers_document = true;
            }
        }

        if !covers_document {
            return Err(TslError::SignatureStructure(format!(
                "no <ds:Reference> covers the signed list: all {reference_total} reference(s) \
                 resolve to auxiliary material, none to the TrustServiceStatusList root (a \
                 same-document URI=\"\" reference, or a fragment identifying the root element). A \
                 signature that covers nothing MUST NOT authenticate the list"
            )));
        }

        // 5. Build the candidate canonical forms of the SignedInfo element. The primary candidate is
        //    the real C14N of the namespace-hoisted subtree (the ancestor `xmlns`/`xmlns:ds`
        //    declarations that `<ds:SignedInfo>` inherits are hoisted onto its start tag first, as
        //    C14N requires in-scope ancestor namespaces); the fallback is the raw element bytes, for
        //    lists that were signed over already-serialized-canonical SignedInfo octets.
        let signed_info_candidates = signed_info_candidates(
            xml,
            self.signed_info_start,
            self.signed_info_end,
            &self.canonicalization_method,
        );

        // 6. Extract the signer certificate.
        let cert_der = self.signer_cert_der.ok_or_else(|| {
            TslError::SignatureStructure(
                "no <ds:X509Certificate> in <ds:KeyInfo> — cannot verify without a signer cert"
                    .to_owned(),
            )
        })?;

        // 7. Verify the signature value against the cert's public key over any candidate SignedInfo
        //    form. This only proves the list is self-consistent — a self-signed list passes too.
        //
        //    The signature method is subject to the same two-stage rule as the reference digests:
        //    resolvable (this build can compute it) and then permitted (it is not broken, or the
        //    operator enabled this exact URI). Both reads come from inside `<ds:SignedInfo>`, which
        //    the `<ds:SignatureValue>` commits to, so neither can be steered by an attacker.
        let Some(signature_algorithm) = SignatureAlgorithm::from_uri(&self.signature_method) else {
            return Err(TslError::SignatureUnsupportedAlgorithm(format!(
                "signature method: {}",
                self.signature_method
            )));
        };
        if signature_algorithm.is_weak() {
            if !policy.allows_legacy(&self.signature_method) {
                return Err(TslError::SignatureUnsupportedAlgorithm(format!(
                    "signature method: {}",
                    self.signature_method
                )));
            }
            report.weak_algorithms.push(WeakAlgorithmUse {
                code: CODE_WEAK_SIGNATURE_METHOD_PERMITTED.to_owned(),
                algorithm: self.signature_method.clone(),
                site: WeakAlgorithmSite::SignatureMethod,
            });
        }
        verify_signature_value(
            &cert_der,
            signature_algorithm,
            &self.signature_value,
            &signed_info_candidates,
        )?;

        // 8. Trust decision (audit t41/C2 part H4): the signer certificate the list carried about
        //    itself must match a configured trust anchor (the EU LOTL / national scheme signing
        //    certificate). Without this gate, anyone supplying TSL bytes could present a
        //    self-signed list declaring arbitrary CAs "qualified" and have it verified. An empty
        //    anchor set (nothing configured) matches nothing, so this fails closed.
        if !anchors.is_anchored(&cert_der) {
            return Err(TslError::SignatureUntrusted(if anchors.is_empty() {
                "no trust anchor configured (set CHANCELA_TSL_TRUST_ANCHOR or \
                 CHANCELA_TSL_TRUST_ANCHOR_SHA256 to the EU LOTL / national scheme signing \
                 certificate)"
                    .to_owned()
            } else {
                "the list's signer certificate does not match any configured trust anchor"
                    .to_owned()
            }));
        }

        Ok(report)
    }
}

/// Parse the `<ds:Signature>` element from `xml` bytes.
pub(crate) fn parse_signature(xml: &[u8]) -> Result<ParsedSignature, TslError> {
    use quick_xml::events::Event;

    let mut reader = quick_xml::Reader::from_reader(xml);
    reader.config_mut().trim_text(true);

    let mut buf = Vec::new();
    let mut stack: Vec<String> = Vec::new();

    let mut sig = ParsedSignature {
        canonicalization_method: String::new(),
        signature_method: String::new(),
        signature_value: Vec::new(),
        references: Vec::new(),
        signer_cert_der: None,
        signed_info_start: 0,
        signed_info_end: 0,
        signature_count: 0,
    };

    let mut saw_signature = false;
    let mut in_signature = false;
    let mut in_signed_info = false;
    let mut in_signature_value = false;
    let mut in_x509_cert = false;
    let mut in_digest_value = false;
    let mut cur_reference: Option<Reference> = None;
    let mut cur_text = String::new();
    let mut signed_info_start: Option<usize> = None;

    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(e) => {
                let local = local_name(e.name().as_ref());
                stack.push(local.clone());

                if local == "Signature" {
                    sig.signature_count += 1;
                    saw_signature = true;
                    in_signature = true;
                } else if in_signature && local == "SignedInfo" {
                    in_signed_info = true;
                    // Record the byte offset of the SignedInfo start tag (including the tag
                    // itself, as it appears in the input).
                    signed_info_start = Some(
                        (reader.buffer_position() as usize).saturating_sub(e.as_ref().len() + 2),
                    );
                } else if in_signature && local == "SignatureValue" {
                    in_signature_value = true;
                    cur_text.clear();
                } else if in_signature && local == "X509Certificate" {
                    in_x509_cert = true;
                    cur_text.clear();
                } else if in_signed_info && local == "DigestValue" && cur_reference.is_some() {
                    in_digest_value = true;
                    cur_text.clear();
                } else if in_signed_info && local == "Reference" {
                    // Only references inside <ds:SignedInfo> are in the signature's scope; one
                    // sitting elsewhere (a <ds:Manifest> in a <ds:Object>) is unsigned material.
                    cur_reference = Some(new_reference(&e));
                } else if in_signed_info && local == "Transform" && cur_reference.is_some() {
                    if let Some(uri) = read_algorithm_attr(&e)
                        && let Some(r) = cur_reference.as_mut()
                    {
                        r.transforms.push(uri);
                    }
                } else if in_signature && local == "CanonicalizationMethod" && in_signed_info {
                    if let Some(uri) = read_algorithm_attr(&e) {
                        sig.canonicalization_method = uri;
                    }
                } else if in_signature && local == "SignatureMethod" && in_signed_info {
                    if let Some(uri) = read_algorithm_attr(&e) {
                        sig.signature_method = uri;
                    }
                } else if in_signed_info
                    && local == "DigestMethod"
                    && cur_reference.is_some()
                    && let Some(uri) = read_algorithm_attr(&e)
                    && let Some(r) = cur_reference.as_mut()
                {
                    r.digest_method = uri;
                }
            }
            Event::Empty(e) => {
                let local = local_name(e.name().as_ref());
                if local == "Signature" {
                    sig.signature_count += 1;
                    saw_signature = true;
                } else if in_signed_info && local == "Reference" {
                    // A self-closing `<ds:Reference/>` has no children, so it is complete here. It
                    // carries no DigestMethod/DigestValue and will therefore be refused by
                    // `verify` — recorded rather than dropped so it cannot be silently ignored.
                    sig.references.push(new_reference(&e));
                    cur_reference = None;
                } else if in_signed_info && local == "Transform" && cur_reference.is_some() {
                    if let Some(uri) = read_algorithm_attr(&e)
                        && let Some(r) = cur_reference.as_mut()
                    {
                        r.transforms.push(uri);
                    }
                } else if in_signed_info && local == "DigestMethod" && cur_reference.is_some() {
                    if let Some(uri) = read_algorithm_attr(&e)
                        && let Some(r) = cur_reference.as_mut()
                    {
                        r.digest_method = uri;
                    }
                } else if in_signature && local == "CanonicalizationMethod" && in_signed_info {
                    if let Some(uri) = read_algorithm_attr(&e) {
                        sig.canonicalization_method = uri;
                    }
                } else if in_signature
                    && local == "SignatureMethod"
                    && in_signed_info
                    && let Some(uri) = read_algorithm_attr(&e)
                {
                    sig.signature_method = uri;
                }
            }
            Event::Text(e) if in_signature_value || in_x509_cert || in_digest_value => {
                cur_text.push_str(&String::from_utf8_lossy(e.as_ref()));
            }
            Event::End(e) => {
                let local = local_name(e.name().as_ref());
                stack.pop();

                if local == "Signature" {
                    in_signature = false;
                } else if local == "SignedInfo" && in_signed_info {
                    in_signed_info = false;
                    if let Some(start) = signed_info_start {
                        sig.signed_info_start = start;
                        sig.signed_info_end = reader.buffer_position() as usize;
                    }
                } else if local == "SignatureValue" && in_signature_value {
                    in_signature_value = false;
                    sig.signature_value = decode_base64(cur_text.trim())?;
                    cur_text.clear();
                } else if local == "X509Certificate" && in_x509_cert {
                    in_x509_cert = false;
                    sig.signer_cert_der = Some(decode_base64(cur_text.trim())?);
                    cur_text.clear();
                } else if local == "DigestValue" && in_digest_value {
                    in_digest_value = false;
                    if let Some(r) = cur_reference.as_mut() {
                        r.digest_value = decode_base64(cur_text.trim())?;
                    }
                    cur_text.clear();
                } else if local == "Reference"
                    && let Some(reference) = cur_reference.take()
                {
                    // Every reference is kept: `verify` checks them all, and dropping one would
                    // leave signed-scope content unverified.
                    sig.references.push(reference);
                }
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }

    if !saw_signature {
        return Err(TslError::SignatureStructure(
            "no <ds:Signature> element found in the Trusted List".to_owned(),
        ));
    }
    Ok(sig)
}

/// Start a [`Reference`] from a `<ds:Reference>` start/empty event, taking its `URI` attribute
/// (absent `URI` = the empty same-document URI, per XML-DSig).
fn new_reference(e: &quick_xml::events::BytesStart<'_>) -> Reference {
    let uri = e
        .attributes()
        .find_map(|a| {
            let a = a.ok()?;
            if local_name(a.key.as_ref()) == "URI" {
                Some(String::from_utf8_lossy(&a.value).into_owned())
            } else {
                None
            }
        })
        .unwrap_or_default();
    Reference {
        uri,
        digest_method: String::new(),
        transforms: Vec::new(),
        digest_value: Vec::new(),
    }
}

/// Read the `Algorithm` attribute from an element's start event.
fn read_algorithm_attr(e: &quick_xml::events::BytesStart<'_>) -> Option<String> {
    for attr in e.attributes() {
        let attr = attr.ok()?;
        if local_name(attr.key.as_ref()) == "Algorithm" {
            return Some(String::from_utf8_lossy(&attr.value).into_owned());
        }
    }
    None
}

/// Strip any namespace prefix from an element name.
fn local_name(raw: &[u8]) -> String {
    let s = String::from_utf8_lossy(raw);
    match s.rsplit_once(':') {
        Some((_, local)) => local.to_owned(),
        None => s.into_owned(),
    }
}

/// What a `<ds:Reference>` resolved to, and therefore whether it authenticates the Trusted List.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReferenceTarget {
    /// The same-document `URI=""` form: the whole document (enveloped signature).
    WholeDocument,
    /// A same-document `#id` fragment resolving to the `TrustServiceStatusList` root element.
    DocumentRoot,
    /// A same-document `#id` fragment resolving to some other element — a XAdES
    /// `SignedProperties`, a `KeyInfo` fragment, and so on. Auxiliary material: it is still fully
    /// digest-verified, but on its own it authenticates none of the list's content.
    Auxiliary,
}

impl ReferenceTarget {
    /// Whether a digest-verified reference to this target authenticates the Trusted List itself.
    fn covers_document(self) -> bool {
        matches!(self, Self::WholeDocument | Self::DocumentRoot)
    }
}

/// The transform-applied octets a `<ds:Reference>` resolved to, plus what it points at.
#[derive(Debug)]
struct ResolvedReference {
    /// The transformed referenced octets exactly as they appear in the source document.
    content: Vec<u8>,
    /// The same octets with the ancestor in-scope `xmlns` declarations hoisted onto the apex
    /// element — the form real C14N needs for a fragment that inherits its namespaces from
    /// ancestors. `None` for the whole-document form (the root already carries every declaration)
    /// and whenever hoisting would change nothing.
    hoisted: Option<Vec<u8>>,
    target: ReferenceTarget,
}

/// Resolve the content referenced by a `<ds:Reference URI="...">`.
///
/// - `URI=""` (empty) → the entire document with the `<ds:Signature>` element removed (enveloped
///   signature); [`ReferenceTarget::WholeDocument`].
/// - `URI="#id"` → the unique element carrying `Id`, `ID`, `id`, or `xml:id` equal to `id`,
///   classified as [`ReferenceTarget::DocumentRoot`] when it is the `TrustServiceStatusList` root
///   and [`ReferenceTarget::Auxiliary`] otherwise. A duplicate `Id` is refused outright (the
///   signature-wrapping lever).
///
/// Anything else — an external `http(s)`/`ftp` URI, an xpointer expression, an empty fragment — is
/// refused with a message naming the construct. It is never skipped: a reference inside the signed
/// `SignedInfo` that the verifier cannot evaluate is content it cannot vouch for.
fn resolve_referenced_content(
    xml: &[u8],
    uri: &str,
    transforms: &[String],
) -> Result<ResolvedReference, TslError> {
    if uri.is_empty() {
        // Enveloped signature: return the document with the <ds:Signature> element stripped.
        return Ok(ResolvedReference {
            content: strip_signature_element(xml),
            hoisted: None,
            target: ReferenceTarget::WholeDocument,
        });
    }
    let Some(id) = uri.strip_prefix('#') else {
        return Err(TslError::SignatureStructure(unsupported_uri_message(uri)));
    };
    if id.is_empty() {
        return Err(TslError::SignatureStructure(
            "empty Reference URI fragment".to_owned(),
        ));
    }
    if id.starts_with("xpointer(") {
        return Err(TslError::SignatureStructure(format!(
            "unsupported Reference URI: xpointer expression (#{id}) — this verifier resolves only \
             bare same-document ID fragments, and refuses a reference it cannot evaluate rather \
             than skipping it"
        )));
    }

    let target = find_unique_id_element(xml, id)?;
    let kind = if target.is_document_root && target.local_name == "TrustServiceStatusList" {
        ReferenceTarget::DocumentRoot
    } else {
        ReferenceTarget::Auxiliary
    };

    let mut content = target.bytes;
    // The sliced subtree does not carry the `xmlns` declarations it inherits from its ancestors;
    // C14N requires them on the apex element, so keep a hoisted variant as an extra digest
    // candidate (real XAdES `SignedProperties` references are digested over exactly that form).
    let mut hoisted = hoist_element_namespaces(xml, target.start, target.end)
        .ok()
        .filter(|h| *h != content);
    if transforms
        .iter()
        .any(|transform| transform == ENVELOPED_SIGNATURE_TRANSFORM)
    {
        content = strip_signature_element(&content);
        hoisted = hoisted.map(|h| strip_signature_element(&h));
    }
    Ok(ResolvedReference {
        content,
        hoisted,
        target: kind,
    })
}

/// Why a canonicalization URI was refused.
///
/// This distinction matters to whoever reads the error. Every *algorithm* refusal in this verifier
/// is one of two very different things, and they call for opposite responses:
///
/// - a **policy** refusal — the algorithm is broken, and an operator may deliberately permit it via
///   [`TslAlgorithmPolicy`];
/// - a **capability gap** — this build does not implement the algorithm, so there is nothing to
///   enable and no setting will help.
///
/// Canonicalization refusals are always the second kind: no canonicalization is refused for being
/// weak. Saying so plainly stops an operator hunting for a switch that does not exist, and stops
/// the next maintainer "fixing" it by aliasing 1.1 onto the 1.0 implementation — which would not be
/// a widening but a correctness bug, computing digests over bytes the signer never signed.
fn unimplemented_canonicalization_reason(uri: &str) -> String {
    let supported = "inclusive and exclusive C14N 1.0, each with and without comments";
    if uri == C14N_11 {
        format!(
            "Canonical XML 1.1 is not implemented by this build (a capability gap, not a policy \
             refusal — no canonicalization is refused for being weak, and no setting enables this \
             one). 1.1 inherits `xml:base`/`xml:lang`/`xml:space` onto a signed subtree's apex \
             element differently from 1.0, so canonicalizing 1.1 content under the 1.0 rules would \
             digest bytes the signer did not sign. Supported: {supported}"
        )
    } else {
        format!(
            "not implemented by this build (a capability gap, not a policy refusal — no \
             canonicalization is refused for being weak, and no setting enables one). Supported: \
             {supported}"
        )
    }
}

/// The precise refusal for a `URI` form this verifier cannot dereference.
fn unsupported_uri_message(uri: &str) -> String {
    let lower = uri.to_ascii_lowercase();
    if lower.starts_with("http://")
        || lower.starts_with("https://")
        || lower.starts_with("ftp://")
        || lower.starts_with("file://")
    {
        format!(
            "unsupported Reference URI: external reference ({uri}) — this verifier resolves only \
             same-document references (URI=\"\" or #fragment), makes no network calls, and refuses \
             a reference it cannot fetch and digest rather than skipping it"
        )
    } else {
        format!(
            "unsupported Reference URI: {uri} — this verifier resolves only same-document \
             references (URI=\"\" or #fragment)"
        )
    }
}

#[derive(Debug)]
struct ReferencedElement {
    bytes: Vec<u8>,
    local_name: String,
    is_document_root: bool,
    /// Byte offset of the element's `<` in the source document.
    start: usize,
    /// Byte offset just past the element's closing `>` in the source document.
    end: usize,
}

fn find_unique_id_element(xml: &[u8], id: &str) -> Result<ReferencedElement, TslError> {
    use quick_xml::events::Event;

    let mut reader = quick_xml::Reader::from_reader(xml);
    reader.config_mut().trim_text(false);

    let mut buf = Vec::new();
    let mut element_depth = 0usize;
    let mut matched_count = 0usize;
    let mut first_match: Option<ReferencedElement> = None;
    let mut active_match: Option<(usize, usize, String, bool)> = None;

    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(e) => {
                let is_document_root = element_depth == 0;
                let local = local_name(e.name().as_ref());
                let event_end = reader.buffer_position() as usize;
                let event_start = find_event_start(xml, event_end)?;
                let is_match = element_has_id(&e, id);

                if let Some((depth, _, _, _)) = active_match.as_mut() {
                    *depth += 1;
                }

                if is_match {
                    matched_count += 1;
                    if active_match.is_none() && first_match.is_none() {
                        active_match = Some((1, event_start, local.clone(), is_document_root));
                    }
                }

                element_depth = element_depth.saturating_add(1);
            }
            Event::Empty(e) => {
                let is_document_root = element_depth == 0;
                if element_has_id(&e, id) {
                    matched_count += 1;
                    if first_match.is_none() {
                        let event_end = reader.buffer_position() as usize;
                        let event_start = find_event_start(xml, event_end)?;
                        first_match = Some(ReferencedElement {
                            bytes: xml[event_start..event_end].to_vec(),
                            local_name: local_name(e.name().as_ref()),
                            is_document_root,
                            start: event_start,
                            end: event_end,
                        });
                    }
                }
            }
            Event::End(_) => {
                element_depth = element_depth.saturating_sub(1);
                if let Some((depth, start, local_name, is_document_root)) = active_match.as_mut() {
                    *depth = depth.saturating_sub(1);
                    if *depth == 0 {
                        let start = *start;
                        let local_name = local_name.clone();
                        let is_document_root = *is_document_root;
                        let event_end = reader.buffer_position() as usize;
                        if first_match.is_none() {
                            first_match = Some(ReferencedElement {
                                bytes: xml[start..event_end].to_vec(),
                                local_name,
                                is_document_root,
                                start,
                                end: event_end,
                            });
                        }
                        active_match = None;
                    }
                }
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }

    match matched_count {
        0 => Err(TslError::SignatureStructure(format!(
            "Reference URI fragment (#{id}) did not match an ID-bearing element"
        ))),
        1 => first_match.ok_or_else(|| {
            TslError::SignatureStructure(format!(
                "Reference URI fragment (#{id}) did not resolve to a complete element"
            ))
        }),
        count => Err(TslError::SignatureStructure(format!(
            "Reference URI fragment (#{id}) matched multiple ID-bearing elements: {count}"
        ))),
    }
}

fn element_has_id(e: &quick_xml::events::BytesStart<'_>, expected: &str) -> bool {
    e.attributes().any(|attr| {
        let Ok(attr) = attr else {
            return false;
        };
        if !matches!(local_name(attr.key.as_ref()).as_str(), "Id" | "ID" | "id") {
            return false;
        }
        String::from_utf8_lossy(&attr.value) == expected
    })
}

fn find_event_start(xml: &[u8], event_end: usize) -> Result<usize, TslError> {
    xml[..event_end]
        .iter()
        .rposition(|b| *b == b'<')
        .ok_or_else(|| {
            TslError::SignatureStructure("could not locate XML element start".to_owned())
        })
}

/// Remove the `<ds:Signature>...</ds:Signature>` subtree from `xml` bytes, returning a new
/// Vec. This is the "enveloped signature" transform.
fn strip_signature_element(xml: &[u8]) -> Vec<u8> {
    // Find `<ds:Signature` or `<Signature` (with or without namespace prefix). We look for the
    // start tag and then find its matching close tag by counting depth.
    let needle_lower = b"<signature";
    let needle_upper = b"<ds:signature";
    let xml_str = xml; // operate on raw bytes

    let sig_start = find_case_insensitive(xml_str, needle_upper)
        .or_else(|| find_case_insensitive(xml_str, needle_lower));
    let Some(sig_start_byte) = sig_start else {
        // No Signature element — return as-is (the digest check will then fail against the
        // original document, which is the correct outcome for an unsigned document).
        return xml.to_vec();
    };

    // Find the matching close tag `</ds:Signature>` or `</Signature>`.
    let close_upper = b"</ds:signature>";
    let close_lower = b"</signature>";
    let sig_end = find_case_insensitive(xml_str, close_upper)
        .or_else(|| find_case_insensitive(xml_str, close_lower));
    let Some(sig_end_byte) = sig_end else {
        return xml.to_vec();
    };
    let end_inclusive = sig_end_byte + close_upper.len().max(close_lower.len());

    let mut out = Vec::with_capacity(xml.len());
    out.extend_from_slice(&xml[..sig_start_byte]);
    out.extend_from_slice(&xml[end_inclusive.min(xml.len())..]);
    out
}

/// Case-insensitive search for `needle` in `haystack`, returning the byte offset of the first
/// match.
fn find_case_insensitive(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w| w.eq_ignore_ascii_case(needle))
}

/// Whether the reference's `<ds:DigestValue>` matches the digest — under `algorithm`, the one this
/// reference's own `<ds:DigestMethod>` declared — of any candidate form of the resolved
/// (transform-applied) content: the raw octets (already-canonical fast path), the namespace-hoisted
/// subtree, or the real C14N output of either — under each explicit C14N transform the reference
/// declares, or under XML-DSig's inclusive-C14N default when it declares none.
///
/// Accepting any candidate is safe: all of them are bound to the one `<ds:DigestValue>`, which is
/// itself inside the signed `SignedInfo`, so an attacker cannot steer the verifier to a form they
/// control, and tampering with the referenced content perturbs *every* candidate. The *algorithm*
/// is likewise fixed by the caller from signed bytes: only one hash is ever tried per reference, so
/// nothing here can fall back to a weaker one.
fn reference_digest_matches(
    reference: &Reference,
    algorithm: DigestAlgorithm,
    resolved: &ResolvedReference,
) -> bool {
    let expected = reference.digest_value.as_slice();

    // Candidate 1/2: the raw transformed octets, and the namespace-hoisted subtree.
    if digest_matches(&resolved.content, algorithm, expected) {
        return true;
    }
    if let Some(hoisted) = &resolved.hoisted
        && digest_matches(hoisted, algorithm, expected)
    {
        return true;
    }

    // Candidate 3..: real C14N under each explicit C14N transform on the reference (the
    // enveloped-signature transform resolves to `None` and is skipped here — it was already applied
    // during resolution). A canonicalization error simply removes that candidate; the raw candidate
    // above stays the fail-closed default.
    let mut saw_explicit_c14n = false;
    for transform in &reference.transforms {
        let Some(c14n) = C14nAlgorithm::from_uri(transform) else {
            continue;
        };
        saw_explicit_c14n = true;
        if c14n_digest_matches(&resolved.content, c14n, algorithm, expected) {
            return true;
        }
        if let Some(hoisted) = &resolved.hoisted
            && c14n_digest_matches(hoisted, c14n, algorithm, expected)
        {
            return true;
        }
    }

    // Candidate N: with no explicit C14N transform, XML-DSig's default for a same-document
    // reference is inclusive C14N 1.0 of the resolved node-set — the form a conforming signer used
    // for, e.g., a `SignedProperties` reference that declares only a `DigestMethod`.
    if !saw_explicit_c14n {
        if c14n_digest_matches(
            &resolved.content,
            C14nAlgorithm::Inclusive,
            algorithm,
            expected,
        ) {
            return true;
        }
        if let Some(hoisted) = &resolved.hoisted
            && c14n_digest_matches(hoisted, C14nAlgorithm::Inclusive, algorithm, expected)
        {
            return true;
        }
    }
    false
}

/// Whether the `algorithm` digest of `bytes` equals `expected`.
fn digest_matches(bytes: &[u8], algorithm: DigestAlgorithm, expected: &[u8]) -> bool {
    algorithm.digest(bytes) == expected
}

/// Whether the `digest` of the `c14n`-canonicalized `bytes` equals `expected`. A canonicalization
/// failure removes the candidate rather than accepting it.
fn c14n_digest_matches(
    bytes: &[u8],
    c14n: C14nAlgorithm,
    digest: DigestAlgorithm,
    expected: &[u8],
) -> bool {
    match crate::c14n::canonicalize(bytes, c14n) {
        Ok(canon) => digest_matches(&canon, digest, expected),
        Err(_) => false,
    }
}

/// Build the ordered candidate byte streams for the `<ds:SignedInfo>` signature check.
///
/// The primary candidate is the real C14N of the namespace-hoisted subtree, canonicalized under the
/// declared `CanonicalizationMethod`; the fallback is the raw element bytes (leading whitespace
/// trimmed) for lists signed over already-serialized-canonical SignedInfo octets. The signature must
/// verify over at least one candidate.
fn signed_info_candidates(
    xml: &[u8],
    start: usize,
    end: usize,
    canonicalization_method: &str,
) -> Vec<Vec<u8>> {
    let mut candidates: Vec<Vec<u8>> = Vec::with_capacity(2);

    // Primary: real C14N over the hoisted subtree (best-effort; skipped on any failure).
    if let Some(alg) = C14nAlgorithm::from_uri(canonicalization_method)
        && let Ok(hoisted) = hoist_signed_info_namespaces(xml, start, end)
        && let Ok(canon) = crate::c14n::canonicalize(&hoisted, alg)
    {
        candidates.push(canon);
    }

    // Fallback: the raw SignedInfo bytes with leading whitespace trimmed.
    let raw: Vec<u8> = xml[start..end]
        .iter()
        .skip_while(|b| b.is_ascii_whitespace())
        .copied()
        .collect();
    if !candidates.contains(&raw) {
        candidates.push(raw);
    }
    candidates
}

/// Hoist the ancestor in-scope namespace declarations onto the `<ds:SignedInfo>` start tag.
///
/// A thin alias for [`hoist_element_namespaces`] over the SignedInfo byte range, kept for the
/// signature-value path that has always used it.
fn hoist_signed_info_namespaces(xml: &[u8], start: usize, end: usize) -> Result<Vec<u8>, TslError> {
    hoist_element_namespaces(xml, start, end)
}

/// Hoist the ancestor in-scope namespace declarations onto the start tag of the element occupying
/// `xml[start..end]`.
///
/// A signed subtree — `<ds:SignedInfo>`, or the element a same-document `<ds:Reference>` points at —
/// inherits `xmlns`/`xmlns:ds` (and any other in-scope prefixes) from its ancestors, but the sliced
/// subtree bytes do not carry them. C14N requires in-scope ancestor namespaces to be present on the
/// apex element, so this walks the document to the element starting at `start`, collects every
/// ancestor declaration (nearer declarations overriding farther ones), and injects each one not
/// already declared on the element itself into its start tag. Inclusive C14N then renders them all;
/// exclusive C14N drops the unused ones — both correct. The built-in `xml` prefix is never hoisted
/// (C14N pre-binds it).
fn hoist_element_namespaces(xml: &[u8], start: usize, end: usize) -> Result<Vec<u8>, TslError> {
    use quick_xml::events::Event;

    if end > xml.len() || start >= end {
        return Err(TslError::SignatureStructure(
            "invalid signed-element byte range".to_owned(),
        ));
    }

    // 1. Collect ancestor in-scope namespaces by walking to the element that starts at `start`,
    //    maintaining a stack of per-element declarations. Matching on the byte offset (rather than
    //    an element name) keeps this correct for any signed subtree, including two same-named
    //    elements in different places.
    let mut reader = quick_xml::Reader::from_reader(xml);
    reader.config_mut().trim_text(false);
    let mut buf = Vec::new();
    let mut stack: Vec<Vec<(String, String)>> = Vec::new();
    let mut found = false;
    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(e) => {
                let event_end = reader.buffer_position() as usize;
                if find_event_start(xml, event_end)? == start {
                    found = true;
                    break;
                }
                stack.push(namespace_decls(&e));
            }
            Event::End(_) => {
                stack.pop();
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    if !found {
        return Err(TslError::SignatureStructure(
            "could not locate the signed element for namespace hoisting".to_owned(),
        ));
    }
    // Flatten to an in-scope map, nearer ancestors overriding farther ones.
    let mut in_scope: Vec<(String, String)> = Vec::new();
    for decls in &stack {
        for (prefix, uri) in decls {
            if let Some(slot) = in_scope.iter_mut().find(|(p, _)| p == prefix) {
                slot.1 = uri.clone();
            } else {
                in_scope.push((prefix.clone(), uri.clone()));
            }
        }
    }

    // 2. Determine the element's own declarations (its own decls win, so never re-inject those).
    let slice = &xml[start..end];
    let own = first_element_namespace_decls(slice)?;
    let own_prefixes: std::collections::HashSet<&str> =
        own.iter().map(|(p, _)| p.as_str()).collect();

    // 3. Inject the missing ancestor declarations right after the element qualified name.
    let mut injected = String::new();
    for (prefix, uri) in &in_scope {
        if prefix == "xml" || own_prefixes.contains(prefix.as_str()) {
            continue;
        }
        if prefix.is_empty() {
            injected.push_str(" xmlns=\"");
        } else {
            injected.push_str(" xmlns:");
            injected.push_str(prefix);
            injected.push_str("=\"");
        }
        push_escaped_attr_value(&mut injected, uri);
        injected.push('"');
    }

    if injected.is_empty() {
        return Ok(slice.to_vec());
    }

    let tag_end = start_tag_end(slice)?;
    let mut out = Vec::with_capacity(slice.len() + injected.len());
    out.extend_from_slice(&slice[..tag_end]);
    out.extend_from_slice(injected.as_bytes());
    out.extend_from_slice(&slice[tag_end..]);
    Ok(out)
}

/// The `xmlns`/`xmlns:*` declarations literally present on a start/empty tag as `(prefix, uri)`
/// (empty prefix = the default namespace).
fn namespace_decls(e: &quick_xml::events::BytesStart<'_>) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for attr in e.attributes() {
        let Ok(attr) = attr else { continue };
        let key = String::from_utf8_lossy(attr.key.as_ref()).into_owned();
        let value = String::from_utf8_lossy(&attr.value).into_owned();
        if key == "xmlns" {
            out.push((String::new(), value));
        } else if let Some(prefix) = key.strip_prefix("xmlns:") {
            out.push((prefix.to_owned(), value));
        }
    }
    out
}

/// The namespace declarations on the first element of `element_bytes` (the apex element start tag).
fn first_element_namespace_decls(element_bytes: &[u8]) -> Result<Vec<(String, String)>, TslError> {
    use quick_xml::events::Event;

    let mut reader = quick_xml::Reader::from_reader(element_bytes);
    reader.config_mut().trim_text(false);
    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(e) | Event::Empty(e) => return Ok(namespace_decls(&e)),
            Event::Eof => {
                return Err(TslError::SignatureStructure(
                    "signed subtree has no element".to_owned(),
                ));
            }
            _ => {}
        }
        buf.clear();
    }
}

/// The byte index of the `>` that closes the start tag at the front of `slice`, honouring quoted
/// attribute values so a `>` inside an attribute is not mistaken for the tag end.
fn start_tag_end(slice: &[u8]) -> Result<usize, TslError> {
    let mut quote: Option<u8> = None;
    for (i, &b) in slice.iter().enumerate() {
        match quote {
            Some(q) => {
                if b == q {
                    quote = None;
                }
            }
            None => match b {
                b'"' | b'\'' => quote = Some(b),
                b'>' => return Ok(i),
                _ => {}
            },
        }
    }
    Err(TslError::SignatureStructure(
        "malformed start tag on the signed element (no closing '>')".to_owned(),
    ))
}

/// Minimal XML attribute-value escaping so a hoisted namespace URI stays well-formed when re-parsed
/// by the canonicalizer (which performs the authoritative C14N escaping).
fn push_escaped_attr_value(out: &mut String, value: &str) {
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(ch),
        }
    }
}

/// Extract the DER of the signer certificate from `<ds:KeyInfo>/<ds:X509Data>/<ds:X509Certificate>`,
/// for downstream certificate-path building (wp26 E5 `certpath`, E4 `lotl`). Returns `Ok(None)` when
/// the document carries no `<ds:Signature>` or the signature carries no embedded certificate.
// Exposed ahead of its in-crate consumers (E4 `lotl.rs`, E5 `certpath.rs`), which land in parallel.
#[allow(dead_code)]
pub(crate) fn extract_signer_cert(xml: &[u8]) -> Result<Option<Vec<u8>>, TslError> {
    match parse_signature(xml) {
        Ok(parsed) => Ok(parsed.signer_cert_der),
        // No signature element at all is not an error for extraction — there is simply no cert.
        Err(TslError::SignatureStructure(_)) => Ok(None),
        Err(err) => Err(err),
    }
}

/// Verify the signature value against the signer certificate's public key over any candidate
/// SignedInfo form; success on the first candidate that verifies.
fn verify_signature_value(
    cert_der: &[u8],
    algorithm: SignatureAlgorithm,
    signature: &[u8],
    signed_info_candidates: &[Vec<u8>],
) -> Result<(), TslError> {
    let cert = x509_cert::Certificate::from_der(cert_der)
        .map_err(|_| TslError::SignatureStructure("invalid signer certificate DER".to_owned()))?;

    match algorithm {
        SignatureAlgorithm::RsaPkcs1(hash) => {
            verify_rsa_pkcs1(&cert, hash, signature, signed_info_candidates)
        }
        SignatureAlgorithm::RsaPss(hash) => {
            verify_rsa_pss(&cert, hash, signature, signed_info_candidates)
        }
        SignatureAlgorithm::Ecdsa(hash) => {
            verify_ecdsa(&cert, hash, signature, signed_info_candidates)
        }
    }
}

/// Verify an RSASSA-PKCS1-v1_5 signature over any candidate SignedInfo form, reducing each
/// candidate with `hash` — the hash the declared `SignatureMethod` named, and only that one.
///
/// # Why the typed `Pkcs1v15Sign::new::<D>()`
/// PKCS#1 v1.5 signs a DER `DigestInfo` that embeds the hash's OID (RFC 8017 §9.2). This used to be
/// a hand-written 19-byte SHA-256 prefix fed to `Pkcs1v15Sign::new_unprefixed()`, which was fine
/// while SHA-256 was the only option — the sibling `chancela-xades` verifier still does it that way
/// to avoid depending on `sha2/oid`. With several hashes in play a hand-built prefix table becomes a
/// hazard: pairing the wrong prefix with a hash does not error, it just never verifies, and it
/// would be indistinguishable from a genuinely bad signature. The typed constructor derives the
/// prefix from the hash type's own `AssociatedOid` (hence the `oid` features in `Cargo.toml`), so
/// hash and prefix cannot drift apart.
fn verify_rsa_pkcs1(
    cert: &x509_cert::Certificate,
    hash: DigestAlgorithm,
    signature: &[u8],
    signed_info_candidates: &[Vec<u8>],
) -> Result<(), TslError> {
    use rsa::Pkcs1v15Sign;
    use sha2::{Sha256, Sha384, Sha512};

    let public_key = rsa_public_key(cert)?;
    for signed_info in signed_info_candidates {
        let scheme = match hash {
            DigestAlgorithm::Sha256 => Pkcs1v15Sign::new::<Sha256>(),
            DigestAlgorithm::Sha384 => Pkcs1v15Sign::new::<Sha384>(),
            DigestAlgorithm::Sha512 => Pkcs1v15Sign::new::<Sha512>(),
            DigestAlgorithm::Sha3_256 => Pkcs1v15Sign::new::<sha3::Sha3_256>(),
            DigestAlgorithm::Sha3_384 => Pkcs1v15Sign::new::<sha3::Sha3_384>(),
            DigestAlgorithm::Sha3_512 => Pkcs1v15Sign::new::<sha3::Sha3_512>(),
            DigestAlgorithm::Sha1 => Pkcs1v15Sign::new::<sha1::Sha1>(),
        };
        if public_key
            .verify(scheme, &hash.digest(signed_info), signature)
            .is_ok()
        {
            return Ok(());
        }
    }
    Err(TslError::SignatureVerificationFailed)
}

/// Verify an RSASSA-PSS signature over any candidate SignedInfo form.
///
/// RFC 9231 §2.3.9 fixes every parameter for the per-hash `#<hash>-rsa-MGF1` URIs this verifier
/// accepts: the mask generation function is MGF1 over the *same* hash, and the salt length is the
/// hash's output length. `Pss::new::<D>()` is exactly that pairing, which is why only these fully
/// specified URIs are on the allowlist — the generic `#rsa-pss` URI carries its parameters in an
/// `RSAPSSParams` element this verifier does not parse, and defaults its digest to SHA-1.
fn verify_rsa_pss(
    cert: &x509_cert::Certificate,
    hash: DigestAlgorithm,
    signature: &[u8],
    signed_info_candidates: &[Vec<u8>],
) -> Result<(), TslError> {
    use rsa::pss::Pss;
    use sha2::{Sha256, Sha384, Sha512};

    let public_key = rsa_public_key(cert)?;
    for signed_info in signed_info_candidates {
        let scheme = match hash {
            DigestAlgorithm::Sha256 => Pss::new::<Sha256>(),
            DigestAlgorithm::Sha384 => Pss::new::<Sha384>(),
            DigestAlgorithm::Sha512 => Pss::new::<Sha512>(),
            DigestAlgorithm::Sha3_256 => Pss::new::<sha3::Sha3_256>(),
            DigestAlgorithm::Sha3_384 => Pss::new::<sha3::Sha3_384>(),
            DigestAlgorithm::Sha3_512 => Pss::new::<sha3::Sha3_512>(),
            DigestAlgorithm::Sha1 => Pss::new::<sha1::Sha1>(),
        };
        if public_key
            .verify(scheme, &hash.digest(signed_info), signature)
            .is_ok()
        {
            return Ok(());
        }
    }
    Err(TslError::SignatureVerificationFailed)
}

/// The certificate's RSA public key.
fn rsa_public_key(cert: &x509_cert::Certificate) -> Result<rsa::RsaPublicKey, TslError> {
    use der::referenced::OwnedToRef;

    let spki = cert.tbs_certificate.subject_public_key_info.owned_to_ref();
    rsa::RsaPublicKey::try_from(spki).map_err(|_| TslError::SignatureVerificationFailed)
}

/// The certificate's `SubjectPublicKeyInfo` re-encoded as DER, the form the RustCrypto
/// `from_public_key_der` constructors take.
fn spki_der(cert: &x509_cert::Certificate) -> Result<Vec<u8>, TslError> {
    cert.tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| TslError::SignatureVerificationFailed)
}

/// The NIST curve an EC signer certificate's key sits on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EcCurve {
    P256,
    P384,
    P521,
}

impl EcCurve {
    /// The fixed width of an XML-DSig `r || s` signature value on this curve.
    fn signature_len(self) -> usize {
        match self {
            Self::P256 => 64,
            Self::P384 => 96,
            Self::P521 => 132,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::P256 => "P-256",
            Self::P384 => "P-384",
            Self::P521 => "P-521",
        }
    }
}

/// `id-ecPublicKey` — the SPKI algorithm OID for an EC key, whose parameters name the curve.
const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
/// `secp256r1` / NIST P-256.
const OID_P256: &str = "1.2.840.10045.3.1.7";
/// `secp384r1` / NIST P-384.
const OID_P384: &str = "1.3.132.0.34";
/// `secp521r1` / NIST P-521.
const OID_P521: &str = "1.3.132.0.35";

/// The named curve of an EC signer certificate, read from its `SubjectPublicKeyInfo`.
///
/// RFC 9231 is explicit that an `ecdsa-sha*` URI names the **hash only**; the curve is a property of
/// the key. So the curve is read from the certificate here and the hash from the `SignatureMethod`
/// separately — an `ecdsa-sha512` signature over a P-384 key is legal and must verify.
fn ec_named_curve(cert: &x509_cert::Certificate) -> Result<EcCurve, TslError> {
    use der::asn1::ObjectIdentifier;

    let spki = &cert.tbs_certificate.subject_public_key_info;
    let algorithm_oid = spki.algorithm.oid.to_string();
    if algorithm_oid != OID_EC_PUBLIC_KEY {
        return Err(TslError::SignatureStructure(format!(
            "signer certificate carries a {algorithm_oid} key, but the <ds:SignatureMethod> \
             declares ECDSA — the key and the signature method disagree"
        )));
    }
    let curve_oid = spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|p| p.decode_as::<ObjectIdentifier>().ok())
        .ok_or_else(|| {
            TslError::SignatureStructure(
                "signer certificate's EC key does not name a curve in its SPKI parameters (an \
                 implicit or explicit-parameters curve is not supported)"
                    .to_owned(),
            )
        })?;
    match curve_oid.to_string().as_str() {
        OID_P256 => Ok(EcCurve::P256),
        OID_P384 => Ok(EcCurve::P384),
        OID_P521 => Ok(EcCurve::P521),
        other => Err(TslError::SignatureUnsupportedAlgorithm(format!(
            "EC curve: {other} (signer key) — supported curves are P-256, P-384 and P-521"
        ))),
    }
}

/// Verify an ECDSA XML-DSig signature over any candidate SignedInfo form.
///
/// The curve comes from the signer certificate ([`ec_named_curve`]) and the hash from the declared
/// `SignatureMethod`, independently, as RFC 9231 requires. Each candidate is reduced with that hash
/// and checked through `verify_prehash`, which applies the ECDSA `bits2field` conversion (truncating
/// a hash wider than the curve's base-point order). Using the plain `Verifier` impl instead would
/// silently re-impose the curve's *own* paired digest and quietly ignore the declared hash.
///
/// XML-DSig carries ECDSA signatures as the fixed-width raw `r || s` value whose width is set by the
/// curve; DER `ECDSA-Sig-Value` encodings are refused.
fn verify_ecdsa(
    cert: &x509_cert::Certificate,
    hash: DigestAlgorithm,
    signature: &[u8],
    signed_info_candidates: &[Vec<u8>],
) -> Result<(), TslError> {
    let curve = ec_named_curve(cert)?;
    if signature.len() != curve.signature_len() {
        return Err(TslError::SignatureStructure(format!(
            "ECDSA XML-DSig signature value must be raw r||s ({} bytes on {}), got {} bytes",
            curve.signature_len(),
            curve.name(),
            signature.len()
        )));
    }

    match curve {
        EcCurve::P256 => {
            use p256::ecdsa::signature::hazmat::PrehashVerifier;
            use p256::ecdsa::{Signature, VerifyingKey};
            use p256::pkcs8::DecodePublicKey;

            let key = VerifyingKey::from_public_key_der(&spki_der(cert)?)
                .map_err(|_| TslError::SignatureVerificationFailed)?;
            let sig = Signature::from_slice(signature)
                .map_err(|_| TslError::SignatureVerificationFailed)?;
            for signed_info in signed_info_candidates {
                if key.verify_prehash(&hash.digest(signed_info), &sig).is_ok() {
                    return Ok(());
                }
            }
        }
        EcCurve::P384 => {
            use p384::ecdsa::signature::hazmat::PrehashVerifier;
            use p384::ecdsa::{Signature, VerifyingKey};
            use p384::pkcs8::DecodePublicKey;

            let key = VerifyingKey::from_public_key_der(&spki_der(cert)?)
                .map_err(|_| TslError::SignatureVerificationFailed)?;
            let sig = Signature::from_slice(signature)
                .map_err(|_| TslError::SignatureVerificationFailed)?;
            for signed_info in signed_info_candidates {
                if key.verify_prehash(&hash.digest(signed_info), &sig).is_ok() {
                    return Ok(());
                }
            }
        }
        EcCurve::P521 => {
            use p521::ecdsa::signature::hazmat::PrehashVerifier;
            use p521::ecdsa::{Signature, VerifyingKey};

            // `p521` 0.13 has no SPKI `DecodePublicKey`; take the SEC1 point (uncompressed
            // `04 || X || Y`) straight from the SPKI BIT STRING, as `chancela-xades` does.
            let point = cert
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .as_bytes()
                .ok_or(TslError::SignatureVerificationFailed)?;
            let key = VerifyingKey::from_sec1_bytes(point)
                .map_err(|_| TslError::SignatureVerificationFailed)?;
            let sig = Signature::from_slice(signature)
                .map_err(|_| TslError::SignatureVerificationFailed)?;
            for signed_info in signed_info_candidates {
                if key.verify_prehash(&hash.digest(signed_info), &sig).is_ok() {
                    return Ok(());
                }
            }
        }
    }
    Err(TslError::SignatureVerificationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Inclusive XML Canonicalization 1.0 (RFC 3076). Production code resolves canonicalization
    /// URIs through `C14nAlgorithm::from_uri`; the fixtures below need the literal to render.
    const C14N_10: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
    /// Exclusive XML Canonicalization 1.0 (RFC 3741) — what the fixtures declare.
    const EXC_C14N_10: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";

    const SIMPLE_SIGNED: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList>
  <SchemeInformation><SchemeTerritory>PT</SchemeTerritory></SchemeInformation>
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference URI="">
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==</ds:SignatureValue>
    <ds:KeyInfo><ds:X509Data><ds:X509Certificate>AAAA</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
  </ds:Signature>
</TrustServiceStatusList>"#;

    #[test]
    fn parses_signature_structure() {
        let parsed = parse_signature(SIMPLE_SIGNED.as_bytes()).expect("parse");
        assert_eq!(parsed.canonicalization_method, EXC_C14N_10);
        assert_eq!(parsed.signature_method, RSA_SHA256);
        assert!(!parsed.signature_value.is_empty());
        assert_eq!(parsed.references.len(), 1);
        let reference = parsed.references.into_iter().next().expect("reference");
        assert_eq!(reference.uri, "");
        assert_eq!(reference.digest_method, SHA256_DIGEST);
        assert!(reference.transforms.is_empty());
        assert_eq!(reference.digest_value, vec![0u8; 32]);
        assert!(parsed.signer_cert_der.is_some());
    }

    #[test]
    fn missing_signature_is_an_error() {
        let xml = b"<TrustServiceStatusList><SchemeInformation/></TrustServiceStatusList>";
        let err = parse_signature(xml).unwrap_err();
        assert!(matches!(err, TslError::SignatureStructure(_)));
    }

    #[test]
    fn strip_signature_removes_subtree() {
        let stripped = strip_signature_element(SIMPLE_SIGNED.as_bytes());
        let s = String::from_utf8_lossy(&stripped);
        assert!(!s.contains("ds:Signature"));
        assert!(s.contains("SchemeTerritory"));
    }

    const NS_DS: &str = "http://www.w3.org/2000/09/xmldsig#";

    /// A document whose `<ds:SignedInfo>` inherits `xmlns:ds` from the root and uses self-closing
    /// empty children — i.e. genuinely NOT in canonical form.
    fn non_canonical_signed_info_doc(digest_b64: &str, sig_b64: &str, cert_b64: &str) -> String {
        format!(
            "<TrustServiceStatusList xmlns:ds=\"{NS_DS}\">\
             <SchemeInformation><SchemeTerritory>PT</SchemeTerritory></SchemeInformation>\
             <ds:Signature>\
             <ds:SignedInfo>\n  <ds:CanonicalizationMethod Algorithm=\"{EXC_C14N_10}\"/>\n  \
             <ds:SignatureMethod Algorithm=\"{ECDSA_SHA256}\"/>\n  \
             <ds:Reference URI=\"\">\n    <ds:DigestMethod Algorithm=\"{SHA256_DIGEST}\"/>\n    \
             <ds:DigestValue>{digest_b64}</ds:DigestValue>\n  </ds:Reference>\n</ds:SignedInfo>\
             <ds:SignatureValue>{sig_b64}</ds:SignatureValue>\
             <ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert_b64}</ds:X509Certificate>\
             </ds:X509Data></ds:KeyInfo>\
             </ds:Signature>\
             </TrustServiceStatusList>"
        )
    }

    fn signed_info_offsets(doc: &str) -> (usize, usize) {
        let start = doc.find("<ds:SignedInfo>").expect("SignedInfo start");
        let end = doc.find("</ds:SignedInfo>").expect("SignedInfo end") + "</ds:SignedInfo>".len();
        (start, end)
    }

    #[test]
    fn hoist_injects_inherited_ds_namespace() {
        // `<ds:SignedInfo>` declares no namespaces itself; `xmlns:ds` is on the root. The hoist must
        // carry that inherited declaration onto the SignedInfo start tag.
        let doc = non_canonical_signed_info_doc("AAAA", "AAAA", "AAAA");
        let (start, end) = signed_info_offsets(&doc);
        let hoisted = hoist_signed_info_namespaces(doc.as_bytes(), start, end).expect("hoist");
        let hs = String::from_utf8(hoisted).expect("utf8");
        assert!(
            hs.starts_with(&format!("<ds:SignedInfo xmlns:ds=\"{NS_DS}\">")),
            "hoisted SignedInfo must carry the inherited xmlns:ds, got: {hs}"
        );
        // The hoisted subtree must canonicalize cleanly.
        assert!(crate::c14n::canonicalize(hs.as_bytes(), C14nAlgorithm::Exclusive).is_ok());
    }

    #[test]
    fn signed_info_primary_candidate_is_the_real_c14n_output() {
        // The first (primary) candidate handed to hashing MUST equal the real C14N of the
        // namespace-hoisted subtree, and MUST differ from the raw fallback (empty children expanded,
        // xmlns:ds hoisted) — proving canonicalization is genuinely routed through `c14n`.
        let doc = non_canonical_signed_info_doc("AAAA", "AAAA", "AAAA");
        let (start, end) = signed_info_offsets(&doc);
        let candidates = signed_info_candidates(doc.as_bytes(), start, end, EXC_C14N_10);

        let hoisted = hoist_signed_info_namespaces(doc.as_bytes(), start, end).expect("hoist");
        let expected = crate::c14n::canonicalize(&hoisted, C14nAlgorithm::Exclusive).expect("c14n");
        assert_eq!(
            candidates.first().map(Vec::as_slice),
            Some(expected.as_slice()),
            "primary SignedInfo candidate must be the real C14N output"
        );
        assert!(
            candidates.len() >= 2,
            "raw fallback candidate must also be present"
        );
        assert_ne!(
            candidates[0], candidates[1],
            "for a non-canonical SignedInfo the C14N form must differ from the raw bytes"
        );
    }

    #[test]
    fn non_canonical_signed_info_verifies_over_its_c14n_form() {
        use std::str::FromStr;

        use der::asn1::{BitString, ObjectIdentifier};
        use p256::ecdsa::SigningKey;
        use p256::ecdsa::signature::Signer;
        use rsa::rand_core::OsRng;
        use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
        use x509_cert::name::Name;
        use x509_cert::serial_number::SerialNumber;
        use x509_cert::time::Validity;
        use x509_cert::{Certificate, TbsCertificate, Version};

        fn base64_standard(bytes: &[u8]) -> String {
            const TABLE: &[u8; 64] =
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
            for chunk in bytes.chunks(3) {
                let b0 = chunk[0];
                let b1 = *chunk.get(1).unwrap_or(&0);
                let b2 = *chunk.get(2).unwrap_or(&0);
                out.push(TABLE[(b0 >> 2) as usize] as char);
                out.push(TABLE[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
                out.push(if chunk.len() > 1 {
                    TABLE[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char
                } else {
                    '='
                });
                out.push(if chunk.len() > 2 {
                    TABLE[(b2 & 0x3f) as usize] as char
                } else {
                    '='
                });
            }
            out
        }

        // A P-256 self-signed cert carrying the signing key.
        let key = SigningKey::random(&mut OsRng);
        let spki = SubjectPublicKeyInfoOwned::from_key(*key.verifying_key()).expect("spki");
        let sig_alg = AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2"),
            parameters: None,
        };
        let name = Name::from_str("CN=E3 c14n routing test signer").expect("name");
        let validity =
            Validity::from_now(std::time::Duration::from_secs(365 * 24 * 3600)).expect("validity");
        let cert = Certificate {
            tbs_certificate: TbsCertificate {
                version: Version::V3,
                serial_number: SerialNumber::new(&[7u8]).expect("serial"),
                signature: sig_alg.clone(),
                issuer: name.clone(),
                validity,
                subject: name,
                subject_public_key_info: spki,
                issuer_unique_id: None,
                subject_unique_id: None,
                extensions: None,
            },
            signature_algorithm: sig_alg,
            signature: BitString::from_bytes(&[0u8; 64]).expect("bitstring"),
        };
        let cert_der = cert.to_der().expect("cert der");
        let cert_b64 = base64_standard(&cert_der);

        // The reference (URI="", no C14N transform) digests the raw document minus the Signature.
        // strip_signature yields exactly the surrounding bytes, so precompute the digest over them.
        let placeholder = base64_standard(&[0x11u8; 64]);
        let doc0 = non_canonical_signed_info_doc(
            &base64_standard(&sha2::Sha256::digest(b"placeholder")),
            &placeholder,
            &cert_b64,
        );
        let stripped = strip_signature_element(doc0.as_bytes());
        let digest_b64 = base64_standard(&sha2::Sha256::digest(&stripped));

        // Rebuild the document with the correct reference digest, then locate SignedInfo and sign
        // over the PRIMARY (real C14N) candidate — the form a conforming XML-DSig signer signs.
        let doc0 = non_canonical_signed_info_doc(&digest_b64, &placeholder, &cert_b64);
        let (start, end) = signed_info_offsets(&doc0);
        let candidates = signed_info_candidates(doc0.as_bytes(), start, end, EXC_C14N_10);
        let canonical = candidates[0].clone();
        let raw_fallback = candidates[1].clone();
        assert_ne!(
            canonical, raw_fallback,
            "test must exercise a non-canonical SignedInfo"
        );

        let signature: p256::ecdsa::Signature = key.sign(&canonical);
        let sig_b64 = base64_standard(&signature.to_bytes());
        let doc = doc0.replace(&placeholder, &sig_b64);

        // The full verifier accepts it, anchored to the embedded cert — the signature verifies via
        // the C14N candidate, since it was signed over the canonical (not raw) SignedInfo.
        let anchors = TslTrustAnchors::new().with_cert_der(&cert_der);
        let parsed = parse_signature(doc.as_bytes()).expect("parse");
        parsed
            .verify(doc.as_bytes(), &anchors)
            .expect("non-canonical SignedInfo must verify over its C14N form");

        // And the raw fallback ALONE would NOT verify — proving the C14N candidate did the work.
        let sig_raw = signature.to_bytes().to_vec();
        assert!(
            verify_ecdsa(&cert, DigestAlgorithm::Sha256, &sig_raw, &[raw_fallback]).is_err(),
            "raw bytes alone must not verify a signature made over the canonical form"
        );
    }

    #[test]
    fn extract_signer_cert_returns_embedded_der_or_none() {
        // The placeholder fixture carries a 3-byte "cert" (base64 "AAAA" = 0x00 0x00 0x00).
        let doc = non_canonical_signed_info_doc("AAAA", "AAAA", "AAAA");
        let extracted = extract_signer_cert(doc.as_bytes()).expect("extract");
        assert_eq!(extracted, Some(vec![0u8, 0u8, 0u8]));

        // No <ds:Signature> at all -> Ok(None), not an error.
        let none = extract_signer_cert(b"<TrustServiceStatusList/>").expect("extract none");
        assert_eq!(none, None);
    }

    // ---- Multi-reference signatures -----------------------------------------------------------
    //
    // Every fixture below is synthesized in-process: an ephemeral P-256 key is generated per test,
    // wrapped in a self-signed certificate, and used to sign a Trusted List assembled here. No real
    // certificate, trust anchor, key or endpoint is involved, and nothing touches the network.

    const NS_XADES: &str = "http://uri.etsi.org/01903/v1.3.2#";
    /// An XPath transform — a construct this verifier cannot evaluate and must refuse by name.
    const XPATH_TRANSFORM: &str = "http://www.w3.org/TR/1999/REC-xpath-19991116";

    /// Standard-alphabet base64 with padding (the module's tests avoid a base64 dependency).
    fn base64_standard(bytes: &[u8]) -> String {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
        for chunk in bytes.chunks(3) {
            let b0 = chunk[0];
            let b1 = *chunk.get(1).unwrap_or(&0);
            let b2 = *chunk.get(2).unwrap_or(&0);
            out.push(TABLE[(b0 >> 2) as usize] as char);
            out.push(TABLE[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
            out.push(if chunk.len() > 1 {
                TABLE[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                TABLE[(b2 & 0x3f) as usize] as char
            } else {
                '='
            });
        }
        out
    }

    /// Mint an ephemeral P-256 signing key and a self-signed certificate carrying its public key.
    fn ephemeral_signer() -> (p256::ecdsa::SigningKey, Vec<u8>) {
        use std::str::FromStr;

        use der::asn1::{BitString, ObjectIdentifier};
        use p256::ecdsa::SigningKey;
        use rsa::rand_core::OsRng;
        use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
        use x509_cert::name::Name;
        use x509_cert::serial_number::SerialNumber;
        use x509_cert::time::Validity;
        use x509_cert::{Certificate, TbsCertificate, Version};

        let key = SigningKey::random(&mut OsRng);
        let spki = SubjectPublicKeyInfoOwned::from_key(*key.verifying_key()).expect("spki");
        let sig_alg = AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2"),
            parameters: None,
        };
        let name = Name::from_str("CN=multi-reference TSL test signer").expect("name");
        let validity =
            Validity::from_now(std::time::Duration::from_secs(365 * 24 * 3600)).expect("validity");
        let cert = Certificate {
            tbs_certificate: TbsCertificate {
                version: Version::V3,
                serial_number: SerialNumber::new(&[11u8]).expect("serial"),
                signature: sig_alg.clone(),
                issuer: name.clone(),
                validity,
                subject: name,
                subject_public_key_info: spki,
                issuer_unique_id: None,
                subject_unique_id: None,
                extensions: None,
            },
            signature_algorithm: sig_alg,
            signature: BitString::from_bytes(&[0u8; 64]).expect("bitstring"),
        };
        (key, cert.to_der().expect("cert der"))
    }

    /// One `<ds:Reference>` to render into a synthesized `<ds:SignedInfo>`.
    struct RefSpec {
        uri: String,
        transforms: Vec<String>,
        /// The `<ds:DigestMethod Algorithm>` URI this reference declares. Deliberately independent
        /// of `digest_b64`: the two are set separately so a test can declare one algorithm while
        /// supplying a digest computed under another.
        digest_uri: String,
        digest_b64: String,
    }

    impl RefSpec {
        fn new(uri: &str, digest_b64: String) -> Self {
            Self {
                uri: uri.to_owned(),
                transforms: Vec::new(),
                digest_uri: SHA256_DIGEST.to_owned(),
                digest_b64,
            }
        }

        fn with_transform(mut self, uri: &str) -> Self {
            self.transforms.push(uri.to_owned());
            self
        }

        fn with_digest_uri(mut self, uri: &str) -> Self {
            self.digest_uri = uri.to_owned();
            self
        }
    }

    fn render_reference(spec: &RefSpec) -> String {
        let mut s = format!("<ds:Reference URI=\"{}\">", spec.uri);
        if !spec.transforms.is_empty() {
            s.push_str("<ds:Transforms>");
            for t in &spec.transforms {
                s.push_str(&format!("<ds:Transform Algorithm=\"{t}\"/>"));
            }
            s.push_str("</ds:Transforms>");
        }
        s.push_str(&format!(
            "<ds:DigestMethod Algorithm=\"{}\"/>",
            spec.digest_uri
        ));
        s.push_str(&format!(
            "<ds:DigestValue>{}</ds:DigestValue>",
            spec.digest_b64
        ));
        s.push_str("</ds:Reference>");
        s
    }

    /// A Trusted List carrying a XAdES-shaped `<ds:Signature>`: the SignedInfo holds `refs`, and a
    /// `<ds:Object>` holds the `SignedProperties` (and a second auxiliary element) that a real list's
    /// extra references point at. Both auxiliary elements inherit `xmlns:ds`/`xmlns:xades` from the
    /// root, so their sliced bytes are genuinely NOT in canonical form.
    fn multiref_doc(
        refs: &[RefSpec],
        sig_method: &str,
        c14n: &str,
        sig_b64: &str,
        cert_b64: &str,
    ) -> String {
        let references: String = refs.iter().map(render_reference).collect();
        format!(
            "<TrustServiceStatusList xmlns:ds=\"{NS_DS}\" xmlns:xades=\"{NS_XADES}\">\
             <SchemeInformation><SchemeTerritory>PT</SchemeTerritory></SchemeInformation>\
             <ds:Signature Id=\"sig-1\">\
             <ds:SignedInfo>\n  <ds:CanonicalizationMethod Algorithm=\"{c14n}\"/>\n  \
             <ds:SignatureMethod Algorithm=\"{sig_method}\"/>\n  {references}\n</ds:SignedInfo>\
             <ds:SignatureValue>{sig_b64}</ds:SignatureValue>\
             <ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert_b64}</ds:X509Certificate>\
             </ds:X509Data></ds:KeyInfo>\
             <ds:Object><xades:QualifyingProperties Target=\"#sig-1\">\
             <xades:SignedProperties Id=\"signed-props-1\"><xades:SignedSignatureProperties>\
             <xades:SigningTime>2026-01-15T09:00:00Z</xades:SigningTime>\
             </xades:SignedSignatureProperties></xades:SignedProperties>\
             <xades:UnsignedProperties Id=\"aux-props-2\"><xades:CounterSignature/>\
             </xades:UnsignedProperties>\
             </xades:QualifyingProperties></ds:Object>\
             </ds:Signature>\
             </TrustServiceStatusList>"
        )
    }

    /// The literal source bytes of the element running from `open` to the end of `close`.
    ///
    /// Deliberately a plain string search rather than the verifier's own resolver, so the expected
    /// digests below are computed independently of the code under test.
    fn raw_element(doc: &str, open: &str, close: &str) -> Vec<u8> {
        let start = doc.find(open).expect("element start");
        let end = doc[start..].find(close).expect("element end") + start + close.len();
        doc.as_bytes()[start..end].to_vec()
    }

    fn signed_properties_bytes(doc: &str) -> Vec<u8> {
        raw_element(doc, "<xades:SignedProperties ", "</xades:SignedProperties>")
    }

    fn aux_properties_bytes(doc: &str) -> Vec<u8> {
        raw_element(
            doc,
            "<xades:UnsignedProperties ",
            "</xades:UnsignedProperties>",
        )
    }

    /// Assemble a synthesized multi-reference TSL and sign its `<ds:SignedInfo>` over the real C14N
    /// form, exactly as a conforming XML-DSig signer would.
    ///
    /// `make_refs` is handed a placeholder document to derive its digests from. That is sound
    /// because nothing a reference digests depends on the SignedInfo contents: the enveloped
    /// `URI=""` content is the document with the whole `<ds:Signature>` removed, and the auxiliary
    /// elements live in `<ds:Object>` outside `<ds:SignedInfo>`. The digest and signature
    /// placeholders are the same width as the real values, so no byte offset moves.
    fn signed_multiref_doc(
        key: &p256::ecdsa::SigningKey,
        cert_der: &[u8],
        make_refs: impl Fn(&str) -> Vec<RefSpec>,
    ) -> String {
        use p256::ecdsa::signature::Signer;

        let cert_b64 = base64_standard(cert_der);
        let sig_placeholder = base64_standard(&[0x11u8; 64]);

        let probe = multiref_doc(&[], ECDSA_SHA256, EXC_C14N_10, &sig_placeholder, &cert_b64);
        let refs = make_refs(&probe);
        let doc = multiref_doc(
            &refs,
            ECDSA_SHA256,
            EXC_C14N_10,
            &sig_placeholder,
            &cert_b64,
        );

        let (start, end) = signed_info_offsets(&doc);
        let candidates = signed_info_candidates(doc.as_bytes(), start, end, EXC_C14N_10);
        let signature: p256::ecdsa::Signature = key.sign(&candidates[0]);
        let sig_b64 = base64_standard(&signature.to_bytes());
        assert_eq!(
            sig_b64.len(),
            sig_placeholder.len(),
            "signature substitution must preserve byte offsets"
        );
        doc.replace(&sig_placeholder, &sig_b64)
    }

    /// The reference over the whole document: `URI=""` with the enveloped-signature transform, whose
    /// digest is taken over the document minus the `<ds:Signature>` subtree.
    fn document_reference(probe: &str) -> RefSpec {
        let stripped = strip_signature_element(probe.as_bytes());
        RefSpec::new("", base64_standard(&sha2::Sha256::digest(&stripped)))
            .with_transform(ENVELOPED_SIGNATURE_TRANSFORM)
    }

    /// Requirement 1 + the reported bug: a signature with two references — the document plus a
    /// XAdES `SignedProperties` — verifies end to end, where the old verifier refused outright with
    /// "multiple <ds:Reference> elements are not supported".
    #[test]
    fn two_reference_signature_verifies_end_to_end() {
        let (key, cert_der) = ephemeral_signer();
        let doc = signed_multiref_doc(&key, &cert_der, |probe| {
            vec![
                document_reference(probe),
                RefSpec::new(
                    "#signed-props-1",
                    base64_standard(&sha2::Sha256::digest(signed_properties_bytes(probe))),
                ),
            ]
        });

        let parsed = parse_signature(doc.as_bytes()).expect("parse");
        assert_eq!(parsed.references.len(), 2, "both references must be parsed");

        let anchors = TslTrustAnchors::new().with_cert_der(&cert_der);
        parse_signature(doc.as_bytes())
            .expect("parse")
            .verify(doc.as_bytes(), &anchors)
            .expect("a document + SignedProperties signature must verify");
    }

    /// Requirement 1: EVERY reference is digested, not just the first (or the one that resolves).
    /// Corrupting either reference's digest — while leaving the SignedInfo signature itself valid,
    /// since the corruption is baked in before signing — must fail the whole signature.
    #[test]
    fn a_wrong_digest_on_any_reference_refuses_the_signature() {
        for corrupt_index in [0usize, 1usize] {
            let (key, cert_der) = ephemeral_signer();
            let doc = signed_multiref_doc(&key, &cert_der, |probe| {
                let mut doc_digest =
                    sha2::Sha256::digest(strip_signature_element(probe.as_bytes()));
                let mut props_digest = sha2::Sha256::digest(signed_properties_bytes(probe));
                if corrupt_index == 0 {
                    doc_digest[0] ^= 0x01;
                } else {
                    props_digest[0] ^= 0x01;
                }
                vec![
                    RefSpec::new("", base64_standard(&doc_digest))
                        .with_transform(ENVELOPED_SIGNATURE_TRANSFORM),
                    RefSpec::new("#signed-props-1", base64_standard(&props_digest)),
                ]
            });

            // The SignedInfo signature is intact: the ONLY defect is the corrupted digest, so a
            // verifier that skipped this reference would wrongly report success.
            let anchors = TslTrustAnchors::new().with_cert_der(&cert_der);
            let err = parse_signature(doc.as_bytes())
                .expect("parse")
                .verify(doc.as_bytes(), &anchors)
                .expect_err("a wrong reference digest must refuse the signature");
            assert!(
                matches!(err, TslError::SignatureDigestMismatch),
                "reference {corrupt_index}: got {err:?}"
            );
        }
    }

    /// Requirement 2: the "valid signature over nothing" attack. Both references digest correctly
    /// and the SignedInfo signature verifies against an anchored certificate — but neither
    /// reference covers the Trusted List, so nothing about the list's content is authenticated and
    /// it MUST be refused.
    #[test]
    fn references_covering_no_list_content_are_refused() {
        let (key, cert_der) = ephemeral_signer();
        let doc = signed_multiref_doc(&key, &cert_der, |probe| {
            vec![
                RefSpec::new(
                    "#signed-props-1",
                    base64_standard(&sha2::Sha256::digest(signed_properties_bytes(probe))),
                ),
                RefSpec::new(
                    "#aux-props-2",
                    base64_standard(&sha2::Sha256::digest(aux_properties_bytes(probe))),
                ),
            ]
        });

        let anchors = TslTrustAnchors::new().with_cert_der(&cert_der);
        let err = parse_signature(doc.as_bytes())
            .expect("parse")
            .verify(doc.as_bytes(), &anchors)
            .expect_err("a signature covering no list content must be refused");
        assert!(
            matches!(err, TslError::SignatureStructure(ref msg)
                if msg.contains("no <ds:Reference> covers")
                    && msg.contains("TrustServiceStatusList root")),
            "got {err:?}"
        );

        // Tampering with the list's actual content does not change the verdict — proof that none of
        // these references was ever authenticating it.
        let tampered = doc.replace(
            "<SchemeTerritory>PT</SchemeTerritory>",
            "<SchemeTerritory>ES</SchemeTerritory>",
        );
        assert!(
            parse_signature(tampered.as_bytes())
                .expect("parse")
                .verify(tampered.as_bytes(), &anchors)
                .is_err()
        );
    }

    /// Requirement 3: an unsupported transform on a LATER reference is a hard failure naming the
    /// construct. Skipping it would leave signed-scope content unverified while reporting success.
    #[test]
    fn unsupported_transform_on_a_later_reference_is_refused_by_name() {
        let (key, cert_der) = ephemeral_signer();
        let doc = signed_multiref_doc(&key, &cert_der, |probe| {
            vec![
                document_reference(probe),
                RefSpec::new(
                    "#signed-props-1",
                    base64_standard(&sha2::Sha256::digest(signed_properties_bytes(probe))),
                )
                .with_transform(XPATH_TRANSFORM),
            ]
        });

        let anchors = TslTrustAnchors::new().with_cert_der(&cert_der);
        let err = parse_signature(doc.as_bytes())
            .expect("parse")
            .verify(doc.as_bytes(), &anchors)
            .expect_err("an unsupported transform must refuse the signature");
        assert!(
            matches!(err, TslError::SignatureUnsupportedAlgorithm(ref msg)
                if msg.contains("transform")
                    && msg.contains(XPATH_TRANSFORM)
                    && msg.contains("2/2")),
            "the refusal must name the transform and the reference carrying it, got {err:?}"
        );
    }

    /// Requirement 3: URI forms the verifier cannot dereference — an external `https://` reference
    /// and an xpointer expression — are refused with a message naming the construct. Neither is
    /// skipped, and neither is allowed to ride along on a sibling reference that does verify.
    #[test]
    fn unresolvable_reference_uris_are_refused_by_name() {
        for (uri, expected_fragment) in [
            ("https://example.invalid/props.xml", "external reference"),
            ("#xpointer(id('signed-props-1'))", "xpointer expression"),
        ] {
            let (key, cert_der) = ephemeral_signer();
            let doc = signed_multiref_doc(&key, &cert_der, |probe| {
                vec![
                    document_reference(probe),
                    RefSpec::new(uri, base64_standard(&[0u8; 32])),
                ]
            });

            let anchors = TslTrustAnchors::new().with_cert_der(&cert_der);
            let err = parse_signature(doc.as_bytes())
                .expect("parse")
                .verify(doc.as_bytes(), &anchors)
                .expect_err("an unresolvable Reference URI must refuse the signature");
            assert!(
                matches!(err, TslError::SignatureStructure(ref msg)
                    if msg.contains("unsupported Reference URI")
                        && msg.contains(expected_fragment)),
                "{uri}: got {err:?}"
            );
        }
    }

    /// A `SignedProperties` reference digested over its real exclusive-C14N form — the shape a
    /// conforming XAdES signer produces, where the sliced source bytes are NOT what was digested
    /// because the element inherits `xmlns:xades` from the document root.
    #[test]
    fn fragment_reference_verifies_over_its_canonical_form() {
        // Built by hand rather than through the verifier's hoist: this is the independent statement
        // of what a conforming signer digests.
        let hoisted = format!(
            "<xades:SignedProperties xmlns:ds=\"{NS_DS}\" xmlns:xades=\"{NS_XADES}\" \
             Id=\"signed-props-1\"><xades:SignedSignatureProperties>\
             <xades:SigningTime>2026-01-15T09:00:00Z</xades:SigningTime>\
             </xades:SignedSignatureProperties></xades:SignedProperties>"
        );
        let canonical =
            crate::c14n::canonicalize(hoisted.as_bytes(), C14nAlgorithm::Exclusive).expect("c14n");
        let canonical_digest = sha2::Sha256::digest(&canonical);

        let (key, cert_der) = ephemeral_signer();
        let doc = signed_multiref_doc(&key, &cert_der, |probe| {
            assert_ne!(
                sha2::Sha256::digest(signed_properties_bytes(probe)).as_slice(),
                canonical_digest.as_slice(),
                "the test must exercise a fragment whose canonical form differs from its source bytes"
            );
            vec![
                document_reference(probe),
                RefSpec::new("#signed-props-1", base64_standard(&canonical_digest))
                    .with_transform(EXC_C14N_10),
            ]
        });

        let anchors = TslTrustAnchors::new().with_cert_der(&cert_der);
        parse_signature(doc.as_bytes())
            .expect("parse")
            .verify(doc.as_bytes(), &anchors)
            .expect("a fragment reference digested over its canonical form must verify");
    }

    /// Requirement 4: only `<ds:Reference>` elements inside the signed `<ds:SignedInfo>` are in
    /// scope. A `<ds:Manifest>` reference in a `<ds:Object>` is outside what `<ds:SignatureValue>`
    /// commits to, so an attacker can add one freely; it must be neither parsed into the verified
    /// set nor able to satisfy document coverage.
    #[test]
    fn references_outside_signed_info_are_not_in_the_verified_set() {
        let (key, cert_der) = ephemeral_signer();
        let doc = signed_multiref_doc(&key, &cert_der, document_reference_only);

        // Splice an unsigned Manifest reference into the <ds:Object>, after signing.
        let injected = format!(
            "<ds:Manifest><ds:Reference URI=\"#aux-props-2\">\
             <ds:DigestMethod Algorithm=\"{SHA256_DIGEST}\"/>\
             <ds:DigestValue>{}</ds:DigestValue></ds:Reference></ds:Manifest>",
            base64_standard(&[0u8; 32])
        );
        let attacked = doc.replace("<ds:Object>", &format!("<ds:Object>{injected}"));
        assert_ne!(attacked, doc, "the injection must have applied");

        let parsed = parse_signature(attacked.as_bytes()).expect("parse");
        assert_eq!(
            parsed.references.len(),
            1,
            "only the SignedInfo reference is in the signature's scope"
        );

        // The list still validates on its one in-scope reference (the injected Manifest lives
        // inside <ds:Signature>, which the enveloped transform strips), and the bogus digest the
        // attacker supplied never enters the verdict.
        let anchors = TslTrustAnchors::new().with_cert_der(&cert_der);
        parsed
            .verify(attacked.as_bytes(), &anchors)
            .expect("an out-of-scope reference must not change the verdict");
    }

    fn document_reference_only(probe: &str) -> Vec<RefSpec> {
        vec![document_reference(probe)]
    }

    // ---- The widened strong algorithm set ------------------------------------------------------
    //
    // Every fixture below is synthesized in-process from an ephemeral key. The rule these tests
    // exist to hold is that an algorithm is on the allowlist only if this build computes it
    // *correctly* — so each accepted algorithm gets a fixture that round-trips through a real
    // signature, and each refused one gets a named refusal.

    /// Inclusive C14N 1.0 **with comments** — a genuinely different canonicalization that
    /// `c14n.rs` implements.
    const C14N_10_WITH_COMMENTS: &str =
        "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";
    /// Exclusive C14N 1.0 **with comments**.
    const EXC_C14N_10_WITH_COMMENTS: &str = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";
    /// The generic parameterized RSA-PSS URI — refused (unparsed params, SHA-1 default digest).
    const RSA_PSS_GENERIC: &str = "http://www.w3.org/2007/05/xmldsig-more#rsa-pss";
    /// EdDSA over Ed25519 — no implementation in the dependency tree, so refused by name.
    const EDDSA_ED25519: &str = "http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519";
    /// SHA3-224 — below the strength floor this verifier widens to; refused.
    const SHA3_224_DIGEST: &str = "http://www.w3.org/2007/05/xmldsig-more#sha3-224";
    /// RIPEMD-160 — broken *and* not computable here; permanently refused.
    const RIPEMD160_DIGEST: &str = "http://www.w3.org/2001/04/xmlenc#ripemd160";

    /// Wrap a prepared SPKI in a self-signed certificate.
    ///
    /// The certificate's own `signature` field is filler: this verifier authenticates the Trusted
    /// List signature and matches the certificate against a trust anchor, and never checks the
    /// certificate's self-signature. Keeping it filler avoids implying otherwise.
    fn self_signed_with_spki(
        cn: &str,
        serial: u8,
        spki: spki::SubjectPublicKeyInfoOwned,
    ) -> Vec<u8> {
        use std::str::FromStr;

        use der::asn1::{BitString, ObjectIdentifier};
        use spki::AlgorithmIdentifierOwned;
        use x509_cert::name::Name;
        use x509_cert::serial_number::SerialNumber;
        use x509_cert::time::Validity;
        use x509_cert::{Certificate, TbsCertificate, Version};

        let sig_alg = AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2"),
            parameters: None,
        };
        let name = Name::from_str(&format!("CN={cn}")).expect("name");
        let cert = Certificate {
            tbs_certificate: TbsCertificate {
                version: Version::V3,
                serial_number: SerialNumber::new(&[serial]).expect("serial"),
                signature: sig_alg.clone(),
                issuer: name.clone(),
                validity: Validity::from_now(std::time::Duration::from_secs(365 * 24 * 3600))
                    .expect("validity"),
                subject: name,
                subject_public_key_info: spki,
                issuer_unique_id: None,
                subject_unique_id: None,
                extensions: None,
            },
            signature_algorithm: sig_alg,
            signature: BitString::from_bytes(&[0u8; 64]).expect("bitstring"),
        };
        cert.to_der().expect("cert der")
    }

    fn p384_signer() -> (p384::ecdsa::SigningKey, Vec<u8>) {
        use rsa::rand_core::OsRng;
        use spki::SubjectPublicKeyInfoOwned;

        let key = p384::ecdsa::SigningKey::random(&mut OsRng);
        let spki = SubjectPublicKeyInfoOwned::from_key(*key.verifying_key()).expect("p384 spki");
        let cert_der = self_signed_with_spki("TSL P-384 test signer", 31, spki);
        (key, cert_der)
    }

    fn p521_signer() -> (p521::ecdsa::SigningKey, Vec<u8>) {
        use der::asn1::{Any, BitString, ObjectIdentifier};
        use rsa::rand_core::OsRng;
        use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

        let key = p521::ecdsa::SigningKey::random(&mut OsRng);
        // `p521` 0.13 has no SPKI `EncodePublicKey`, so assemble the SubjectPublicKeyInfo by hand
        // from the uncompressed SEC1 point — the mirror image of how `verify_ecdsa` reads it back.
        let point = p521::ecdsa::VerifyingKey::from(&key).to_encoded_point(false);
        let spki = SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid: ObjectIdentifier::new_unwrap(OID_EC_PUBLIC_KEY),
                parameters: Some(
                    Any::encode_from(&ObjectIdentifier::new_unwrap(OID_P521)).expect("secp521r1"),
                ),
            },
            subject_public_key: BitString::from_bytes(point.as_bytes()).expect("p521 point"),
        };
        let cert_der = self_signed_with_spki("TSL P-521 test signer", 32, spki);
        (key, cert_der)
    }

    /// Assemble a synthesized two-reference TSL — the document plus a XAdES `SignedProperties`,
    /// both digested with `digest` under `digest_uri` — declaring `sig_method` and `c14n`, and sign
    /// its canonical `<ds:SignedInfo>` with `sign`.
    ///
    /// One helper for every scheme: `sign` receives exactly the bytes a conforming XML-DSig signer
    /// signs (the primary C14N candidate) and returns the raw `<ds:SignatureValue>` octets, so RSA,
    /// PSS and every ECDSA curve go through the identical document-assembly path.
    fn signed_doc_with(
        sig_method: &str,
        c14n: &str,
        digest: DigestAlgorithm,
        digest_uri: &str,
        cert_der: &[u8],
        sig_len: usize,
        sign: impl Fn(&[u8]) -> Vec<u8>,
    ) -> String {
        let cert_b64 = base64_standard(cert_der);
        let sig_placeholder = base64_standard(&vec![0x11u8; sig_len]);

        let probe = multiref_doc(&[], sig_method, c14n, &sig_placeholder, &cert_b64);
        let refs = vec![
            document_reference_under(&probe, digest, digest_uri),
            props_reference_under(&probe, digest, digest_uri),
        ];
        let doc = multiref_doc(&refs, sig_method, c14n, &sig_placeholder, &cert_b64);

        let (start, end) = signed_info_offsets(&doc);
        let candidates = signed_info_candidates(doc.as_bytes(), start, end, c14n);
        let sig_b64 = base64_standard(&sign(&candidates[0]));
        assert_eq!(
            sig_b64.len(),
            sig_placeholder.len(),
            "signature substitution must preserve byte offsets"
        );
        doc.replace(&sig_placeholder, &sig_b64)
    }

    /// SHA3-256/384/512 reference digests verify. The signature method is held at `rsa-sha512`
    /// throughout so this exercises the *digest* table alone, and the asserted digest widths
    /// (32/48/64) prove a real SHA-3 was computed rather than a SHA-2 quietly substituted.
    #[test]
    fn sha3_reference_digests_verify() {
        for (digest_uri, algorithm, width) in [
            (SHA3_256_DIGEST, DigestAlgorithm::Sha3_256, 32),
            (SHA3_384_DIGEST, DigestAlgorithm::Sha3_384, 48),
            (SHA3_512_DIGEST, DigestAlgorithm::Sha3_512, 64),
        ] {
            let (key, cert_der) = rsa_signer();
            let doc = signed_doc_with(
                RSA_SHA512,
                EXC_C14N_10,
                algorithm,
                digest_uri,
                cert_der,
                256,
                |si| sign_rsa(key, DigestAlgorithm::Sha512, si),
            );

            let parsed = parse_signature(doc.as_bytes()).expect("parse");
            assert!(
                parsed
                    .references
                    .iter()
                    .all(|r| r.digest_value.len() == width),
                "{digest_uri}: expected {width}-byte digests"
            );
            // A SHA-3 digest must differ from the same-width SHA-2 digest of the same bytes —
            // otherwise the "SHA-3" arm would be indistinguishable from a SHA-2 fallback.
            assert_ne!(
                algorithm.digest(b"chancela"),
                match width {
                    32 => DigestAlgorithm::Sha256.digest(b"chancela"),
                    48 => DigestAlgorithm::Sha384.digest(b"chancela"),
                    _ => DigestAlgorithm::Sha512.digest(b"chancela"),
                },
                "{digest_uri}: SHA-3 must not be computing SHA-2"
            );

            let anchors = TslTrustAnchors::new().with_cert_der(cert_der);
            parsed
                .verify(doc.as_bytes(), &anchors)
                .unwrap_or_else(|e| panic!("{digest_uri} must verify, got {e:?}"));
        }
    }

    /// RSASSA-PSS verifies for every per-hash `#<hash>-rsa-MGF1` URI on the allowlist. PSS is
    /// randomized, so a passing fixture here is a genuine sign/verify round-trip with MGF1 and the
    /// salt length RFC 9231 fixes — not a replayed vector.
    #[test]
    fn rsa_pss_signatures_verify() {
        for (sig_method, hash) in [
            (RSA_PSS_SHA256, DigestAlgorithm::Sha256),
            (RSA_PSS_SHA384, DigestAlgorithm::Sha384),
            (RSA_PSS_SHA512, DigestAlgorithm::Sha512),
            (RSA_PSS_SHA3_256, DigestAlgorithm::Sha3_256),
            (RSA_PSS_SHA3_384, DigestAlgorithm::Sha3_384),
            (RSA_PSS_SHA3_512, DigestAlgorithm::Sha3_512),
        ] {
            let (key, cert_der) = rsa_signer();
            let doc = signed_doc_with(
                sig_method,
                EXC_C14N_10,
                DigestAlgorithm::Sha512,
                SHA512_DIGEST,
                cert_der,
                256,
                |si| sign_rsa_pss(key, hash, si),
            );

            let anchors = TslTrustAnchors::new().with_cert_der(cert_der);
            parse_signature(doc.as_bytes())
                .expect("parse")
                .verify(doc.as_bytes(), &anchors)
                .unwrap_or_else(|e| panic!("{sig_method} must verify, got {e:?}"));
        }
    }

    /// A PSS signature must not verify under the PKCS#1 v1.5 URI (or vice versa): the two schemes
    /// are different padding, and accepting either for the other would mean the declared method is
    /// not actually deciding how the signature is checked.
    #[test]
    fn pss_and_pkcs1_padding_are_not_interchangeable() {
        let (key, cert_der) = rsa_signer();
        let anchors = TslTrustAnchors::new().with_cert_der(cert_der);

        // Declares PKCS#1 v1.5, signed with PSS.
        let doc = signed_doc_with(
            RSA_SHA512,
            EXC_C14N_10,
            DigestAlgorithm::Sha512,
            SHA512_DIGEST,
            cert_der,
            256,
            |si| sign_rsa_pss(key, DigestAlgorithm::Sha512, si),
        );
        assert!(matches!(
            parse_signature(doc.as_bytes())
                .expect("parse")
                .verify(doc.as_bytes(), &anchors),
            Err(TslError::SignatureVerificationFailed)
        ));

        // Declares PSS, signed with PKCS#1 v1.5.
        let doc = signed_doc_with(
            RSA_PSS_SHA512,
            EXC_C14N_10,
            DigestAlgorithm::Sha512,
            SHA512_DIGEST,
            cert_der,
            256,
            |si| sign_rsa(key, DigestAlgorithm::Sha512, si),
        );
        assert!(matches!(
            parse_signature(doc.as_bytes())
                .expect("parse")
                .verify(doc.as_bytes(), &anchors),
            Err(TslError::SignatureVerificationFailed)
        ));
    }

    /// ECDSA verifies on each supported curve, in each curve's conventional hash pairing.
    #[test]
    fn ecdsa_verifies_on_every_supported_curve() {
        // One trait, re-exported by each curve crate: importing it once covers all three.
        use p256::ecdsa::signature::hazmat::PrehashSigner;

        // P-256 / ecdsa-sha256
        let (key, cert_der) = ephemeral_signer();
        let doc = signed_doc_with(
            ECDSA_SHA256,
            EXC_C14N_10,
            DigestAlgorithm::Sha512,
            SHA512_DIGEST,
            &cert_der,
            64,
            |si| {
                let sig: p256::ecdsa::Signature = key
                    .sign_prehash(&DigestAlgorithm::Sha256.digest(si))
                    .expect("p256 sign");
                sig.to_bytes().to_vec()
            },
        );
        let anchors = TslTrustAnchors::new().with_cert_der(&cert_der);
        parse_signature(doc.as_bytes())
            .expect("parse")
            .verify(doc.as_bytes(), &anchors)
            .expect("P-256 ecdsa-sha256 must verify");

        // P-384 / ecdsa-sha384
        let (key, cert_der) = p384_signer();
        let doc = signed_doc_with(
            ECDSA_SHA384,
            EXC_C14N_10,
            DigestAlgorithm::Sha512,
            SHA512_DIGEST,
            &cert_der,
            96,
            |si| {
                let sig: p384::ecdsa::Signature = key
                    .sign_prehash(&DigestAlgorithm::Sha384.digest(si))
                    .expect("p384 sign");
                sig.to_bytes().to_vec()
            },
        );
        let anchors = TslTrustAnchors::new().with_cert_der(&cert_der);
        parse_signature(doc.as_bytes())
            .expect("parse")
            .verify(doc.as_bytes(), &anchors)
            .expect("P-384 ecdsa-sha384 must verify");

        // P-521 / ecdsa-sha512
        let (key, cert_der) = p521_signer();
        let doc = signed_doc_with(
            ECDSA_SHA512,
            EXC_C14N_10,
            DigestAlgorithm::Sha512,
            SHA512_DIGEST,
            &cert_der,
            132,
            |si| {
                let sig: p521::ecdsa::Signature = key
                    .sign_prehash(&DigestAlgorithm::Sha512.digest(si))
                    .expect("p521 sign");
                sig.to_bytes().to_vec()
            },
        );
        let anchors = TslTrustAnchors::new().with_cert_der(&cert_der);
        parse_signature(doc.as_bytes())
            .expect("parse")
            .verify(doc.as_bytes(), &anchors)
            .expect("P-521 ecdsa-sha512 must verify");
    }

    /// RFC 9231: an `ecdsa-sha*` URI names the **hash only**; the curve is a property of the key.
    /// So `ecdsa-sha512` over a **P-384** key is legal and must verify — the case a verifier that
    /// binds curve-to-hash-name (as this one used to) gets wrong. The control below signs the same
    /// document with a different hash than the URI declares and must fail, proving the URI is still
    /// deciding the hash rather than being ignored.
    #[test]
    fn ecdsa_curve_comes_from_the_key_and_hash_from_the_uri() {
        use p384::ecdsa::signature::hazmat::PrehashSigner;

        let (key, cert_der) = p384_signer();
        let anchors = TslTrustAnchors::new().with_cert_der(&cert_der);
        assert_eq!(
            ec_named_curve(&x509_cert::Certificate::from_der(&cert_der).expect("cert"))
                .expect("curve"),
            EcCurve::P384,
            "the fixture must really be a P-384 key"
        );

        // Mismatched-but-legal pairing: SHA-512 declared, P-384 key.
        let doc = signed_doc_with(
            ECDSA_SHA512,
            EXC_C14N_10,
            DigestAlgorithm::Sha256,
            SHA256_DIGEST,
            &cert_der,
            96,
            |si| {
                let sig: p384::ecdsa::Signature = key
                    .sign_prehash(&DigestAlgorithm::Sha512.digest(si))
                    .expect("p384 sign");
                sig.to_bytes().to_vec()
            },
        );
        parse_signature(doc.as_bytes())
            .expect("parse")
            .verify(doc.as_bytes(), &anchors)
            .expect("ecdsa-sha512 over a P-384 key is legal and must verify");

        // Control: declares ecdsa-sha512 but signs the SHA-256 reduction — must not verify.
        let doc = signed_doc_with(
            ECDSA_SHA512,
            EXC_C14N_10,
            DigestAlgorithm::Sha256,
            SHA256_DIGEST,
            &cert_der,
            96,
            |si| {
                let sig: p384::ecdsa::Signature = key
                    .sign_prehash(&DigestAlgorithm::Sha256.digest(si))
                    .expect("p384 sign");
                sig.to_bytes().to_vec()
            },
        );
        assert!(
            matches!(
                parse_signature(doc.as_bytes())
                    .expect("parse")
                    .verify(doc.as_bytes(), &anchors),
                Err(TslError::SignatureVerificationFailed)
            ),
            "the declared hash must still decide how SignedInfo is reduced"
        );
    }

    /// An ECDSA `<ds:SignatureValue>` must be the raw `r||s` width of the **key's** curve. The
    /// refusal names the curve, so an operator can see that the value was sized for a different one.
    #[test]
    fn an_ecdsa_signature_sized_for_the_wrong_curve_is_refused() {
        use p384::ecdsa::signature::hazmat::PrehashSigner;

        let (key, cert_der) = p384_signer();
        // 64 bytes is the P-256 width; this key is P-384, which needs 96.
        let doc = signed_doc_with(
            ECDSA_SHA384,
            EXC_C14N_10,
            DigestAlgorithm::Sha512,
            SHA512_DIGEST,
            &cert_der,
            64,
            |si| {
                let sig: p384::ecdsa::Signature = key
                    .sign_prehash(&DigestAlgorithm::Sha384.digest(si))
                    .expect("p384 sign");
                sig.to_bytes()[..64].to_vec()
            },
        );

        let anchors = TslTrustAnchors::new().with_cert_der(&cert_der);
        let err = parse_signature(doc.as_bytes())
            .expect("parse")
            .verify(doc.as_bytes(), &anchors)
            .expect_err("a wrongly-sized ECDSA value must be refused");
        assert!(
            matches!(err, TslError::SignatureStructure(ref m)
                if m.contains("96 bytes on P-384") && m.contains("got 64")),
            "got {err:?}"
        );
    }

    /// Canonicalization is widened to exactly what `c14n.rs` implements. The `#WithComments`
    /// variants are accepted and genuinely used; C14N 1.1 is refused by name because this build
    /// does not implement its `xml:`-attribute inheritance rules, and accepting a canonicalization
    /// it computes differently would silently change what bytes the signature covers.
    #[test]
    fn with_comments_canonicalization_is_accepted_and_c14n_11_is_refused() {
        for c14n in [C14N_10_WITH_COMMENTS, EXC_C14N_10_WITH_COMMENTS, C14N_10] {
            let (key, cert_der) = rsa_signer();
            let doc = signed_doc_with(
                RSA_SHA512,
                c14n,
                DigestAlgorithm::Sha512,
                SHA512_DIGEST,
                cert_der,
                256,
                |si| sign_rsa(key, DigestAlgorithm::Sha512, si),
            );
            let anchors = TslTrustAnchors::new().with_cert_der(cert_der);
            parse_signature(doc.as_bytes())
                .expect("parse")
                .verify(doc.as_bytes(), &anchors)
                .unwrap_or_else(|e| panic!("{c14n} must verify, got {e:?}"));
        }

        // C14N 1.1: refused at step 2, naming the URI.
        let (key, cert_der) = rsa_signer();
        let doc = signed_doc_with(
            RSA_SHA512,
            C14N_11,
            DigestAlgorithm::Sha512,
            SHA512_DIGEST,
            cert_der,
            256,
            |si| sign_rsa(key, DigestAlgorithm::Sha512, si),
        );
        let anchors = TslTrustAnchors::new().with_cert_der(cert_der);
        let err = parse_signature(doc.as_bytes())
            .expect("parse")
            .verify(doc.as_bytes(), &anchors)
            .expect_err("C14N 1.1 must be refused");
        // The refusal must name the URI *and* explain that this is a capability gap rather than a
        // policy refusal — an operator who reads "unsupported algorithm" and goes looking for the
        // setting that enables it has been sent on a hunt for something that does not exist.
        let TslError::SignatureUnsupportedAlgorithm(ref message) = err else {
            panic!("got {err:?}");
        };
        assert!(message.contains("canonicalization:"), "{message}");
        assert!(message.contains(C14N_11), "{message}");
        assert!(message.contains("not implemented"), "{message}");
        assert!(message.contains("capability gap"), "{message}");
        assert!(
            message.contains("xml:base"),
            "the refusal must say what actually differs in 1.1: {message}"
        );
        assert!(
            message.contains("not a policy refusal"),
            "the refusal must rule out the policy reading explicitly: {message}"
        );
        // And it must not send the reader after the legacy-algorithm setting, which cannot help:
        // that setting names broken algorithms, and this is a missing implementation.
        assert!(
            !message.contains("tsl_legacy_algorithms") && !message.contains("TslAlgorithmPolicy"),
            "a capability gap must not point at the legacy-algorithm opt-in: {message}"
        );

        // The same explanation appears when C14N 1.1 arrives as a `<ds:Transform>` rather than as
        // the `<ds:CanonicalizationMethod>`, so the diagnosis does not depend on which slot of the
        // signature it occupied.
        let (key, cert_der) = rsa_signer();
        let doc = signed_multiref_doc_rsa(RSA_SHA512, DigestAlgorithm::Sha512, |probe| {
            vec![
                document_reference_under(probe, DigestAlgorithm::Sha512, SHA512_DIGEST),
                props_reference_under(probe, DigestAlgorithm::Sha512, SHA512_DIGEST)
                    .with_transform(C14N_11),
            ]
        })
        .0;
        let _ = key;
        let anchors = TslTrustAnchors::new().with_cert_der(cert_der);
        let err = parse_signature(doc.as_bytes())
            .expect("parse")
            .verify(doc.as_bytes(), &anchors)
            .expect_err("a C14N 1.1 transform must be refused");
        assert!(
            matches!(err, TslError::SignatureUnsupportedAlgorithm(ref m)
                if m.contains("transform:")
                    && m.contains(C14N_11)
                    && m.contains("capability gap")
                    && m.contains("2/2")),
            "got {err:?}"
        );
    }

    /// Algorithms this build deliberately does not implement are refused by name rather than
    /// guessed at. Each of these is a URI a real signer could emit, and a precise refusal is the
    /// correct outcome — accepting one and mis-computing it would be strictly worse.
    #[test]
    fn unimplemented_algorithms_are_refused_by_name() {
        for uri in [RSA_PSS_GENERIC, EDDSA_ED25519] {
            assert_eq!(
                SignatureAlgorithm::from_uri(uri),
                None,
                "{uri} must not resolve to a signature algorithm"
            );
        }
        for uri in [SHA3_224_DIGEST, RIPEMD160_DIGEST] {
            assert_eq!(
                DigestAlgorithm::from_uri(uri),
                None,
                "{uri} must not resolve to a digest algorithm"
            );
        }
        assert_eq!(
            C14nAlgorithm::from_uri(C14N_11),
            None,
            "C14N 1.1 must not resolve while c14n.rs implements only the 1.0 semantics"
        );
    }

    // ---- Operator-enabled legacy algorithms ----------------------------------------------------

    /// The two-stage rule, stated directly: knowing how to compute an algorithm is not permission
    /// to rely on it. SHA-1 *resolves* (this build can compute it, and must be able to, to honour
    /// an opt-in) but is weak; MD5 and RIPEMD-160 do not resolve at all and can never be enabled.
    #[test]
    fn computability_and_permission_are_separate_questions() {
        assert_eq!(
            DigestAlgorithm::from_uri(LEGACY_SHA1_DIGEST),
            Some(DigestAlgorithm::Sha1)
        );
        assert!(DigestAlgorithm::Sha1.is_weak());
        assert!(!DigestAlgorithm::Sha256.is_weak());
        assert!(
            SignatureAlgorithm::from_uri(LEGACY_RSA_SHA1)
                .expect("rsa-sha1")
                .is_weak()
        );
        assert!(
            !SignatureAlgorithm::from_uri(RSA_SHA512)
                .expect("rsa-sha512")
                .is_weak()
        );

        // MD5 is not on the legacy list because nothing here computes it — so it can never be
        // enabled, only refused.
        assert_eq!(DigestAlgorithm::from_uri(MD5_DIGEST), None);
        assert!(!KNOWN_LEGACY_ALGORITHMS.contains(&MD5_DIGEST));
        assert!(!KNOWN_LEGACY_ALGORITHMS.contains(&RIPEMD160_DIGEST));
    }

    /// The default policy is empty, and an empty policy is today's behaviour exactly.
    #[test]
    fn the_default_policy_permits_no_legacy_algorithm() {
        let policy = TslAlgorithmPolicy::new();
        assert!(!policy.permits_any_legacy());
        for uri in KNOWN_LEGACY_ALGORITHMS {
            assert!(
                !policy.allows_legacy(uri),
                "{uri} must not be allowed by default"
            );
        }
        assert_eq!(policy, TslAlgorithmPolicy::default());
    }

    /// The setting is a closed vocabulary, not an arbitrary-URI escape hatch: an unknown URI is
    /// refused at construction, so it can never reach the verifier's exact-match allowlist.
    #[test]
    fn the_policy_refuses_an_unknown_legacy_uri() {
        for uri in [
            MD5_DIGEST,
            RIPEMD160_DIGEST,
            SHA512_DIGEST,
            "http://example.invalid/whatever",
            "",
        ] {
            let err = TslAlgorithmPolicy::new()
                .with_legacy_algorithm(uri)
                .expect_err("an unknown legacy URI must be refused");
            assert!(
                matches!(err, TslError::TrustAnchorConfig(ref m) if m.contains("unknown legacy")),
                "{uri}: got {err:?}"
            );
        }
        // And every advertised URI is accepted, so the settings layer and the verifier agree.
        for uri in KNOWN_LEGACY_ALGORITHMS {
            TslAlgorithmPolicy::new()
                .with_legacy_algorithm(uri)
                .unwrap_or_else(|e| panic!("{uri} must be enableable, got {e:?}"));
        }
    }

    /// An explicitly-enabled SHA-1 reference digest verifies, AND the success carries a structured
    /// marker naming the algorithm and the exact reference that relied on it. A bare `Ok` here
    /// would be the failure this whole mechanism exists to prevent.
    #[test]
    fn an_enabled_sha1_digest_verifies_and_is_reported() {
        let (key, cert_der) = rsa_signer();
        let doc = signed_doc_with(
            RSA_SHA512,
            EXC_C14N_10,
            DigestAlgorithm::Sha1,
            LEGACY_SHA1_DIGEST,
            cert_der,
            256,
            |si| sign_rsa(key, DigestAlgorithm::Sha512, si),
        );
        let anchors = TslTrustAnchors::new().with_cert_der(cert_der);

        // Default policy: refused by name, exactly as before this feature existed.
        let err = parse_signature(doc.as_bytes())
            .expect("parse")
            .verify(doc.as_bytes(), &anchors)
            .expect_err("SHA-1 must be refused without an explicit opt-in");
        assert!(
            matches!(err, TslError::SignatureUnsupportedAlgorithm(ref m)
                if m.contains("digest:") && m.contains(LEGACY_SHA1_DIGEST)),
            "got {err:?}"
        );

        // Enabled: verifies, and says so.
        let policy = TslAlgorithmPolicy::new()
            .with_legacy_algorithm(LEGACY_SHA1_DIGEST)
            .expect("enable sha1");
        let report = parse_signature(doc.as_bytes())
            .expect("parse")
            .verify_with_policy(doc.as_bytes(), &anchors, &policy)
            .expect("an enabled SHA-1 digest must verify");

        assert!(report.relied_on_weak_algorithm());
        assert_eq!(
            report.weak_algorithms.len(),
            2,
            "both references used SHA-1"
        );
        assert_eq!(report.weak_algorithms[0].code, CODE_WEAK_DIGEST_PERMITTED);
        assert_eq!(report.weak_algorithms[0].algorithm, LEGACY_SHA1_DIGEST);
        assert_eq!(
            report.weak_algorithms[0].site,
            WeakAlgorithmSite::Reference {
                index: 1,
                total: 2,
                uri: String::new(),
            }
        );
        assert_eq!(
            report.weak_algorithms[1].site,
            WeakAlgorithmSite::Reference {
                index: 2,
                total: 2,
                uri: "#signed-props-1".to_owned(),
            }
        );
    }

    /// The same, for an enabled `rsa-sha1` `<ds:SignatureMethod>`: it verifies and the reliance is
    /// reported against the signature method rather than a reference.
    #[test]
    fn an_enabled_rsa_sha1_signature_verifies_and_is_reported() {
        let (key, cert_der) = rsa_signer();
        let doc = signed_doc_with(
            LEGACY_RSA_SHA1,
            EXC_C14N_10,
            DigestAlgorithm::Sha512,
            SHA512_DIGEST,
            cert_der,
            256,
            |si| sign_rsa(key, DigestAlgorithm::Sha1, si),
        );
        let anchors = TslTrustAnchors::new().with_cert_der(cert_der);

        assert!(
            parse_signature(doc.as_bytes())
                .expect("parse")
                .verify(doc.as_bytes(), &anchors)
                .is_err(),
            "rsa-sha1 must be refused without an explicit opt-in"
        );

        let policy = TslAlgorithmPolicy::new()
            .with_legacy_algorithm(LEGACY_RSA_SHA1)
            .expect("enable rsa-sha1");
        let report = parse_signature(doc.as_bytes())
            .expect("parse")
            .verify_with_policy(doc.as_bytes(), &anchors, &policy)
            .expect("an enabled rsa-sha1 signature must verify");

        assert_eq!(report.weak_algorithms.len(), 1);
        assert_eq!(
            report.weak_algorithms[0].code,
            CODE_WEAK_SIGNATURE_METHOD_PERMITTED
        );
        assert_eq!(report.weak_algorithms[0].algorithm, LEGACY_RSA_SHA1);
        assert_eq!(
            report.weak_algorithms[0].site,
            WeakAlgorithmSite::SignatureMethod
        );
    }

    /// Enabling one broken algorithm permits that algorithm and nothing else. Enabling the SHA-1
    /// *digest* does not enable `rsa-sha1`, and does not make any never-computable primitive pass.
    #[test]
    fn enabling_one_legacy_algorithm_does_not_enable_another() {
        let policy = TslAlgorithmPolicy::new()
            .with_legacy_algorithm(LEGACY_SHA1_DIGEST)
            .expect("enable sha1 digest");
        assert!(policy.allows_legacy(LEGACY_SHA1_DIGEST));
        assert!(!policy.allows_legacy(LEGACY_RSA_SHA1));
        assert!(!policy.allows_legacy(LEGACY_ECDSA_SHA1));
        assert!(!policy.allows_legacy(MD5_DIGEST));

        // An rsa-sha1 signature stays refused under a SHA-1-*digest*-only policy.
        let (key, cert_der) = rsa_signer();
        let doc = signed_doc_with(
            LEGACY_RSA_SHA1,
            EXC_C14N_10,
            DigestAlgorithm::Sha1,
            LEGACY_SHA1_DIGEST,
            cert_der,
            256,
            |si| sign_rsa(key, DigestAlgorithm::Sha1, si),
        );
        let anchors = TslTrustAnchors::new().with_cert_der(cert_der);
        let err = parse_signature(doc.as_bytes())
            .expect("parse")
            .verify_with_policy(doc.as_bytes(), &anchors, &policy)
            .expect_err("rsa-sha1 must stay refused when only the SHA-1 digest was enabled");
        assert!(
            matches!(err, TslError::SignatureUnsupportedAlgorithm(ref m)
                if m.contains("signature method:") && m.contains(LEGACY_RSA_SHA1)),
            "got {err:?}"
        );

        // An MD5 digest stays refused even with every enableable legacy algorithm turned on.
        let everything = KNOWN_LEGACY_ALGORITHMS
            .iter()
            .fold(TslAlgorithmPolicy::new(), |p, uri| {
                p.with_legacy_algorithm(uri).expect("enable")
            });
        let doc = signed_doc_with(
            RSA_SHA512,
            EXC_C14N_10,
            DigestAlgorithm::Sha512,
            SHA512_DIGEST,
            cert_der,
            256,
            |si| sign_rsa(key, DigestAlgorithm::Sha512, si),
        )
        .replace(SHA512_DIGEST, MD5_DIGEST);
        let err = parse_signature(doc.as_bytes())
            .expect("parse")
            .verify_with_policy(doc.as_bytes(), &anchors, &everything)
            .expect_err("MD5 must be refused under any policy");
        assert!(
            matches!(err, TslError::SignatureUnsupportedAlgorithm(ref m)
                if m.contains("digest:") && m.contains(MD5_DIGEST)),
            "got {err:?}"
        );
    }

    /// The marker is a real signal, not an always-on decoration: a strong-only verification carries
    /// none, even when a legacy algorithm happens to be enabled in the policy.
    #[test]
    fn a_strong_only_verification_carries_no_weak_marker() {
        let (key, cert_der) = rsa_signer();
        let doc = signed_doc_with(
            RSA_SHA512,
            EXC_C14N_10,
            DigestAlgorithm::Sha512,
            SHA512_DIGEST,
            cert_der,
            256,
            |si| sign_rsa(key, DigestAlgorithm::Sha512, si),
        );
        let anchors = TslTrustAnchors::new().with_cert_der(cert_der);

        for policy in [
            TslAlgorithmPolicy::new(),
            TslAlgorithmPolicy::new()
                .with_legacy_algorithm(LEGACY_SHA1_DIGEST)
                .expect("enable sha1"),
        ] {
            let report = parse_signature(doc.as_bytes())
                .expect("parse")
                .verify_with_policy(doc.as_bytes(), &anchors, &policy)
                .expect("a strong signature must verify");
            assert!(
                !report.relied_on_weak_algorithm(),
                "a SHA-512 signature must carry no weak marker even when SHA-1 is enabled"
            );
            assert!(report.weak_algorithms.is_empty());
        }
    }

    /// Enabling a legacy algorithm relaxes the algorithm rule and nothing else — every other
    /// property still holds. Proven here on the one that would be most tempting to lose: the
    /// digests are still actually compared, so a tampered body is still refused.
    #[test]
    fn enabling_sha1_does_not_relax_any_other_check() {
        let (key, cert_der) = rsa_signer();
        let doc = signed_doc_with(
            RSA_SHA512,
            EXC_C14N_10,
            DigestAlgorithm::Sha1,
            LEGACY_SHA1_DIGEST,
            cert_der,
            256,
            |si| sign_rsa(key, DigestAlgorithm::Sha512, si),
        );
        let policy = TslAlgorithmPolicy::new()
            .with_legacy_algorithm(LEGACY_SHA1_DIGEST)
            .expect("enable sha1");

        // Tampered content is still caught by the (weak, but genuinely computed) digest.
        let tampered = doc.replace(
            "<SchemeTerritory>PT</SchemeTerritory>",
            "<SchemeTerritory>ES</SchemeTerritory>",
        );
        assert_ne!(tampered, doc);
        let anchors = TslTrustAnchors::new().with_cert_der(cert_der);
        assert!(matches!(
            parse_signature(tampered.as_bytes())
                .expect("parse")
                .verify_with_policy(tampered.as_bytes(), &anchors, &policy),
            Err(TslError::SignatureDigestMismatch)
        ));

        // The trust-anchor gate is still fail-closed.
        let err = parse_signature(doc.as_bytes())
            .expect("parse")
            .verify_with_policy(doc.as_bytes(), &TslTrustAnchors::new(), &policy)
            .expect_err("an unanchored list must still be untrusted");
        assert!(
            matches!(err, TslError::SignatureUntrusted(_)),
            "got {err:?}"
        );
    }

    /// The report is a wire payload: the stable codes and the structured site must serialize in the
    /// shape the web layer will translate, with no user-facing prose crossing the boundary.
    #[test]
    fn the_weak_algorithm_report_serializes_to_stable_codes() {
        let report = TslSignatureReport {
            weak_algorithms: vec![
                WeakAlgorithmUse {
                    code: CODE_WEAK_SIGNATURE_METHOD_PERMITTED.to_owned(),
                    algorithm: LEGACY_RSA_SHA1.to_owned(),
                    site: WeakAlgorithmSite::SignatureMethod,
                },
                WeakAlgorithmUse {
                    code: CODE_WEAK_DIGEST_PERMITTED.to_owned(),
                    algorithm: LEGACY_SHA1_DIGEST.to_owned(),
                    site: WeakAlgorithmSite::Reference {
                        index: 2,
                        total: 2,
                        uri: "#signed-props-1".to_owned(),
                    },
                },
            ],
        };
        let json = serde_json::to_value(&report).expect("serialize");
        let entries = json["weak_algorithms"].as_array().expect("array");
        assert_eq!(entries[0]["code"], "tsl_weak_signature_method_permitted");
        assert_eq!(entries[0]["site"], "signature_method");
        assert_eq!(entries[1]["code"], "tsl_weak_digest_permitted");
        assert_eq!(entries[1]["site"], "reference");
        assert_eq!(entries[1]["index"], 2);
        assert_eq!(entries[1]["total"], 2);
        assert_eq!(entries[1]["uri"], "#signed-props-1");

        // Round-trips, and an empty report omits the field entirely.
        let back: TslSignatureReport = serde_json::from_value(json).expect("deserialize");
        assert_eq!(back, report);
        let empty = serde_json::to_value(TslSignatureReport::default()).expect("serialize");
        assert_eq!(empty, serde_json::json!({}));
    }

    // ---- Digest / signature algorithm agility --------------------------------------------------
    //
    // The live GNS Portuguese Trusted List is signed `rsa-sha512` with SHA-512 reference digests,
    // which the SHA-256-only verifier refused outright. The fixtures below are all synthesized
    // in-process from an ephemeral RSA key — no real Trusted List, certificate or key is committed
    // or read here; the real list is only ever used as a local, uncommitted oracle.

    /// MD5 — broken *and* not computable by this build, so it is permanently refused and can never
    /// appear in [`KNOWN_LEGACY_ALGORITHMS`]. (SHA-1 and its signature methods have production
    /// constants — `LEGACY_SHA1_DIGEST` and friends — because an operator can enable those.)
    const MD5_DIGEST: &str = "http://www.w3.org/2001/04/xmldsig-more#md5";

    /// An ephemeral RSA-2048 key and its self-signed certificate, minted **once** for the whole
    /// module: 2048-bit keygen in a debug build is by far the slowest thing in these tests, and
    /// every RSA fixture below can share one key without weakening anything it proves.
    fn rsa_signer() -> &'static (rsa::RsaPrivateKey, Vec<u8>) {
        use std::str::FromStr;
        use std::sync::OnceLock;

        use der::asn1::{BitString, ObjectIdentifier};
        use rsa::rand_core::OsRng;
        use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
        use x509_cert::name::Name;
        use x509_cert::serial_number::SerialNumber;
        use x509_cert::time::Validity;
        use x509_cert::{Certificate, TbsCertificate, Version};

        static SIGNER: OnceLock<(rsa::RsaPrivateKey, Vec<u8>)> = OnceLock::new();
        SIGNER.get_or_init(|| {
            let key = rsa::RsaPrivateKey::new(&mut OsRng, 2048).expect("rsa keygen");
            // sha256WithRSAEncryption — the certificate's own signature algorithm, which is
            // unrelated to the XML-DSig SignatureMethod under test (this verifier never checks it).
            let sig_alg = AlgorithmIdentifierOwned {
                oid: ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11"),
                parameters: None,
            };
            let name = Name::from_str("CN=TSL digest-agility test signer").expect("name");
            let cert = Certificate {
                tbs_certificate: TbsCertificate {
                    version: Version::V3,
                    serial_number: SerialNumber::new(&[13u8]).expect("serial"),
                    signature: sig_alg.clone(),
                    issuer: name.clone(),
                    validity: Validity::from_now(std::time::Duration::from_secs(365 * 24 * 3600))
                        .expect("validity"),
                    subject: name,
                    subject_public_key_info: SubjectPublicKeyInfoOwned::from_key(
                        rsa::RsaPublicKey::from(&key),
                    )
                    .expect("spki"),
                    issuer_unique_id: None,
                    subject_unique_id: None,
                    extensions: None,
                },
                signature_algorithm: sig_alg,
                signature: BitString::from_bytes(&[0u8; 256]).expect("bitstring"),
            };
            (key, cert.to_der().expect("cert der"))
        })
    }

    /// Produce an RSASSA-PKCS1-v1_5 signature over `message` reduced with `hash`.
    ///
    /// Built with the same typed `Pkcs1v15Sign::new::<D>()` the verifier uses, so the DigestInfo
    /// prefix comes from the hash's own OID on both sides rather than from a table this test could
    /// copy an error out of.
    fn sign_rsa(key: &rsa::RsaPrivateKey, hash: DigestAlgorithm, message: &[u8]) -> Vec<u8> {
        use rsa::Pkcs1v15Sign;
        use sha2::{Sha256, Sha384, Sha512};

        let scheme = match hash {
            DigestAlgorithm::Sha256 => Pkcs1v15Sign::new::<Sha256>(),
            DigestAlgorithm::Sha384 => Pkcs1v15Sign::new::<Sha384>(),
            DigestAlgorithm::Sha512 => Pkcs1v15Sign::new::<Sha512>(),
            DigestAlgorithm::Sha3_256 => Pkcs1v15Sign::new::<sha3::Sha3_256>(),
            DigestAlgorithm::Sha3_384 => Pkcs1v15Sign::new::<sha3::Sha3_384>(),
            DigestAlgorithm::Sha3_512 => Pkcs1v15Sign::new::<sha3::Sha3_512>(),
            DigestAlgorithm::Sha1 => Pkcs1v15Sign::new::<sha1::Sha1>(),
        };
        key.sign(scheme, &hash.digest(message)).expect("rsa sign")
    }

    /// Produce an RSASSA-PSS signature over `message` reduced with `hash`, with MGF1 over the same
    /// hash and a salt the length of that hash — the parameters RFC 9231 fixes for the per-hash
    /// `#<hash>-rsa-MGF1` URIs. PSS is randomized, so this cannot be a fixed vector.
    fn sign_rsa_pss(key: &rsa::RsaPrivateKey, hash: DigestAlgorithm, message: &[u8]) -> Vec<u8> {
        use rsa::pss::Pss;
        use rsa::rand_core::OsRng;
        use sha2::{Sha256, Sha384, Sha512};

        let scheme = match hash {
            DigestAlgorithm::Sha256 => Pss::new::<Sha256>(),
            DigestAlgorithm::Sha384 => Pss::new::<Sha384>(),
            DigestAlgorithm::Sha512 => Pss::new::<Sha512>(),
            DigestAlgorithm::Sha3_256 => Pss::new::<sha3::Sha3_256>(),
            DigestAlgorithm::Sha3_384 => Pss::new::<sha3::Sha3_384>(),
            DigestAlgorithm::Sha3_512 => Pss::new::<sha3::Sha3_512>(),
            DigestAlgorithm::Sha1 => Pss::new::<sha1::Sha1>(),
        };
        key.sign_with_rng(&mut OsRng, scheme, &hash.digest(message))
            .expect("rsa-pss sign")
    }

    /// Assemble a synthesized multi-reference TSL, declare `sig_method` on it, and sign its
    /// `<ds:SignedInfo>` (real C14N form) with RSA-PKCS1 reduced by `signing_hash`.
    ///
    /// `sig_method` and `signing_hash` are separate parameters on purpose: passing a mismatched
    /// pair produces exactly the "declared one algorithm, signed with another" document that
    /// [`declared_signature_hash_must_match_the_hash_used`] requires. Returns the signed document
    /// and the signer certificate DER (the anchor).
    fn signed_multiref_doc_rsa(
        sig_method: &str,
        signing_hash: DigestAlgorithm,
        make_refs: impl Fn(&str) -> Vec<RefSpec>,
    ) -> (String, Vec<u8>) {
        let (key, cert_der) = rsa_signer();
        let cert_b64 = base64_standard(cert_der);
        // RSA-2048 signatures are always 256 bytes, so the placeholder is the same width as the
        // real value and no byte offset moves when it is substituted in.
        let sig_placeholder = base64_standard(&[0x11u8; 256]);

        let probe = multiref_doc(&[], sig_method, EXC_C14N_10, &sig_placeholder, &cert_b64);
        let refs = make_refs(&probe);
        let doc = multiref_doc(&refs, sig_method, EXC_C14N_10, &sig_placeholder, &cert_b64);

        let (start, end) = signed_info_offsets(&doc);
        let candidates = signed_info_candidates(doc.as_bytes(), start, end, EXC_C14N_10);
        let sig_b64 = base64_standard(&sign_rsa(key, signing_hash, &candidates[0]));
        assert_eq!(
            sig_b64.len(),
            sig_placeholder.len(),
            "signature substitution must preserve byte offsets"
        );
        (doc.replace(&sig_placeholder, &sig_b64), cert_der.clone())
    }

    /// The whole-document reference (`URI=""` + enveloped transform) digested under `algorithm`,
    /// declaring `digest_uri` as its `<ds:DigestMethod>`.
    fn document_reference_under(
        probe: &str,
        algorithm: DigestAlgorithm,
        digest_uri: &str,
    ) -> RefSpec {
        let stripped = strip_signature_element(probe.as_bytes());
        RefSpec::new("", base64_standard(&algorithm.digest(&stripped)))
            .with_transform(ENVELOPED_SIGNATURE_TRANSFORM)
            .with_digest_uri(digest_uri)
    }

    /// The XAdES `SignedProperties` reference digested under `algorithm`.
    fn props_reference_under(probe: &str, algorithm: DigestAlgorithm, digest_uri: &str) -> RefSpec {
        RefSpec::new(
            "#signed-props-1",
            base64_standard(&algorithm.digest(&signed_properties_bytes(probe))),
        )
        .with_digest_uri(digest_uri)
    }

    /// The reported bug, end to end: the two-reference shape of the live PT list — SHA-512 digests
    /// throughout, `rsa-sha512` over `<ds:SignedInfo>` — verifies, where the SHA-256-only verifier
    /// refused with "unsupported TSL XML-DSig algorithm: digest: …#sha512".
    #[test]
    fn sha512_digests_and_rsa_sha512_verify_end_to_end() {
        let (doc, cert_der) =
            signed_multiref_doc_rsa(RSA_SHA512, DigestAlgorithm::Sha512, |probe| {
                vec![
                    document_reference_under(probe, DigestAlgorithm::Sha512, SHA512_DIGEST),
                    props_reference_under(probe, DigestAlgorithm::Sha512, SHA512_DIGEST),
                ]
            });

        let parsed = parse_signature(doc.as_bytes()).expect("parse");
        assert_eq!(parsed.references.len(), 2);
        assert_eq!(parsed.signature_method, RSA_SHA512);
        assert!(
            parsed.references.iter().all(|r| r.digest_value.len() == 64),
            "the fixture must really carry SHA-512-width digests"
        );

        let anchors = TslTrustAnchors::new().with_cert_der(&cert_der);
        parsed
            .verify(doc.as_bytes(), &anchors)
            .expect("a SHA-512 / rsa-sha512 Trusted List must verify");
    }

    /// SHA-384 verifies too — proving the digest is dispatched from the declared URI rather than
    /// swapped for a second hardcode. Both standard SHA-384 URIs (RFC 4051's `xmldsig-more#sha384`
    /// and XML Encryption 1.1's `xmlenc#sha384`) are exercised.
    #[test]
    fn sha384_digests_and_rsa_sha384_verify_end_to_end() {
        for digest_uri in [SHA384_DIGEST, SHA384_DIGEST_XMLENC] {
            let (doc, cert_der) =
                signed_multiref_doc_rsa(RSA_SHA384, DigestAlgorithm::Sha384, |probe| {
                    vec![
                        document_reference_under(probe, DigestAlgorithm::Sha384, digest_uri),
                        props_reference_under(probe, DigestAlgorithm::Sha384, digest_uri),
                    ]
                });

            let parsed = parse_signature(doc.as_bytes()).expect("parse");
            assert!(
                parsed.references.iter().all(|r| r.digest_value.len() == 48),
                "{digest_uri}: the fixture must really carry SHA-384-width digests"
            );

            let anchors = TslTrustAnchors::new().with_cert_der(&cert_der);
            parsed
                .verify(doc.as_bytes(), &anchors)
                .unwrap_or_else(|e| panic!("{digest_uri} must verify, got {e:?}"));
        }
    }

    /// The unchanged baseline: SHA-256 digests with `rsa-sha256` still verify. This is also the
    /// only in-crate coverage of the RSA path itself, which moved from a hand-encoded SHA-256
    /// `DigestInfo` prefix to the typed `Pkcs1v15Sign::new::<D>()`.
    #[test]
    fn sha256_digests_and_rsa_sha256_still_verify() {
        let (doc, cert_der) =
            signed_multiref_doc_rsa(RSA_SHA256, DigestAlgorithm::Sha256, |probe| {
                vec![
                    document_reference_under(probe, DigestAlgorithm::Sha256, SHA256_DIGEST),
                    props_reference_under(probe, DigestAlgorithm::Sha256, SHA256_DIGEST),
                ]
            });

        let anchors = TslTrustAnchors::new().with_cert_der(&cert_der);
        parse_signature(doc.as_bytes())
            .expect("parse")
            .verify(doc.as_bytes(), &anchors)
            .expect("the SHA-256 / rsa-sha256 path must be unchanged");
    }

    /// Per-reference dispatch, stated as sharply as it can be: one reference declares SHA-256 and
    /// the other SHA-512, in the SAME signature. A verifier holding one algorithm for the whole
    /// signature — whichever one it picked — fails one of the two digests. The widths (32 vs 64
    /// bytes) are asserted so the fixture cannot silently degenerate into a single algorithm.
    #[test]
    fn mixed_digest_algorithms_across_references_verify() {
        let (doc, cert_der) =
            signed_multiref_doc_rsa(RSA_SHA512, DigestAlgorithm::Sha512, |probe| {
                vec![
                    document_reference_under(probe, DigestAlgorithm::Sha256, SHA256_DIGEST),
                    props_reference_under(probe, DigestAlgorithm::Sha512, SHA512_DIGEST),
                ]
            });

        let parsed = parse_signature(doc.as_bytes()).expect("parse");
        assert_eq!(parsed.references[0].digest_method, SHA256_DIGEST);
        assert_eq!(parsed.references[0].digest_value.len(), 32);
        assert_eq!(parsed.references[1].digest_method, SHA512_DIGEST);
        assert_eq!(parsed.references[1].digest_value.len(), 64);

        let anchors = TslTrustAnchors::new().with_cert_der(&cert_der);
        parsed
            .verify(doc.as_bytes(), &anchors)
            .expect("references with different DigestMethods must each use their own");
    }

    /// The new digest is genuinely being *checked*, not merely accepted: tampering with the list's
    /// content after signing, under SHA-512, is refused. Without this a verifier that "supported"
    /// SHA-512 by skipping the comparison would pass every test above.
    #[test]
    fn a_tampered_body_under_sha512_is_refused() {
        let (doc, cert_der) =
            signed_multiref_doc_rsa(RSA_SHA512, DigestAlgorithm::Sha512, |probe| {
                vec![
                    document_reference_under(probe, DigestAlgorithm::Sha512, SHA512_DIGEST),
                    props_reference_under(probe, DigestAlgorithm::Sha512, SHA512_DIGEST),
                ]
            });
        let anchors = TslTrustAnchors::new().with_cert_der(&cert_der);
        parse_signature(doc.as_bytes())
            .expect("parse")
            .verify(doc.as_bytes(), &anchors)
            .expect("the untampered fixture must verify");

        let tampered = doc.replace(
            "<SchemeTerritory>PT</SchemeTerritory>",
            "<SchemeTerritory>ES</SchemeTerritory>",
        );
        assert_ne!(tampered, doc, "the tamper must have applied");
        let err = parse_signature(tampered.as_bytes())
            .expect("parse")
            .verify(tampered.as_bytes(), &anchors)
            .expect_err("a tampered SHA-512-digested list must be refused");
        assert!(
            matches!(err, TslError::SignatureDigestMismatch),
            "got {err:?}"
        );
    }

    /// Nothing resolves by resemblance. The allowlists are exact matches over complete URIs, so a
    /// URI that merely *contains* a supported one — the shape a prefix match or a `contains("sha")`
    /// test would wrongly accept — resolves to nothing.
    #[test]
    fn algorithm_resolution_is_exact_never_by_resemblance() {
        for uri in [
            &format!("{SHA512_DIGEST}-evil"),
            &format!("evil{SHA512_DIGEST}"),
            "http://example.invalid/sha512",
            "http://www.w3.org/2001/04/xmlenc#sha256 ",
            "sha256",
        ] {
            assert_eq!(
                DigestAlgorithm::from_uri(uri),
                None,
                "{uri} must not resolve to a digest algorithm"
            );
        }
        for uri in [
            &format!("{RSA_SHA512}-evil"),
            "http://example.invalid/rsa-sha512",
        ] {
            assert_eq!(
                SignatureAlgorithm::from_uri(uri),
                None,
                "{uri} must not resolve to a signature algorithm"
            );
        }
    }

    /// A SHA-1 `<ds:DigestMethod>` is refused by name, identifying the URI and which reference
    /// carried it — the same precise refusal an unknown algorithm gets, never a silent skip.
    #[test]
    fn a_sha1_reference_digest_is_refused_by_name() {
        let (doc, cert_der) =
            signed_multiref_doc_rsa(RSA_SHA512, DigestAlgorithm::Sha512, |probe| {
                vec![
                    document_reference_under(probe, DigestAlgorithm::Sha512, SHA512_DIGEST),
                    // A 20-byte "SHA-1" digest value declared with the SHA-1 URI. It is refused before
                    // anything is hashed — the verifier will not compute SHA-1 even to reject it.
                    RefSpec::new("#signed-props-1", base64_standard(&[0u8; 20]))
                        .with_digest_uri(LEGACY_SHA1_DIGEST),
                ]
            });

        let anchors = TslTrustAnchors::new().with_cert_der(&cert_der);
        let err = parse_signature(doc.as_bytes())
            .expect("parse")
            .verify(doc.as_bytes(), &anchors)
            .expect_err("a SHA-1 reference digest must be refused");
        assert!(
            matches!(err, TslError::SignatureUnsupportedAlgorithm(ref msg)
                if msg.contains("digest:") && msg.contains(LEGACY_SHA1_DIGEST) && msg.contains("2/2")),
            "the refusal must name the algorithm and the reference carrying it, got {err:?}"
        );
    }

    /// An `rsa-sha1` `<ds:SignatureMethod>` is refused by name, even when every reference digest
    /// is a supported algorithm and verifies.
    #[test]
    fn an_rsa_sha1_signature_method_is_refused_by_name() {
        // Signed with SHA-512 so the ONLY defect is the declared method: a verifier that quietly
        // accepted rsa-sha1 by falling back to some other hash would still have to fail here.
        let (doc, cert_der) =
            signed_multiref_doc_rsa(LEGACY_RSA_SHA1, DigestAlgorithm::Sha512, |probe| {
                vec![
                    document_reference_under(probe, DigestAlgorithm::Sha512, SHA512_DIGEST),
                    props_reference_under(probe, DigestAlgorithm::Sha512, SHA512_DIGEST),
                ]
            });

        let anchors = TslTrustAnchors::new().with_cert_der(&cert_der);
        let err = parse_signature(doc.as_bytes())
            .expect("parse")
            .verify(doc.as_bytes(), &anchors)
            .expect_err("an rsa-sha1 SignatureMethod must be refused");
        assert!(
            matches!(err, TslError::SignatureUnsupportedAlgorithm(ref msg)
                if msg.contains("signature method:") && msg.contains(LEGACY_RSA_SHA1)),
            "the refusal must name the signature method, got {err:?}"
        );
    }

    /// The `<ds:SignedInfo>` hash is taken from the declared `<ds:SignatureMethod>` and nowhere
    /// else. A signature declaring `rsa-sha512` whose value was actually produced over a SHA-256
    /// reduction does not verify — the verifier never tries a second hash looking for one that
    /// works, which would let an attacker pick the weakest supported hash for free.
    #[test]
    fn declared_signature_hash_must_match_the_hash_used() {
        let refs = |probe: &str| {
            vec![
                document_reference_under(probe, DigestAlgorithm::Sha512, SHA512_DIGEST),
                props_reference_under(probe, DigestAlgorithm::Sha512, SHA512_DIGEST),
            ]
        };

        // Control: declared and actual agree (both SHA-256 over SignedInfo) -> verifies. This is
        // what makes the failure below attributable to the mismatch and nothing else.
        let (doc, cert_der) = signed_multiref_doc_rsa(RSA_SHA256, DigestAlgorithm::Sha256, refs);
        let anchors = TslTrustAnchors::new().with_cert_der(&cert_der);
        parse_signature(doc.as_bytes())
            .expect("parse")
            .verify(doc.as_bytes(), &anchors)
            .expect("the matched control must verify");

        // Mismatch: declares rsa-sha512, signed over a SHA-256 reduction.
        let (doc, cert_der) = signed_multiref_doc_rsa(RSA_SHA512, DigestAlgorithm::Sha256, refs);
        let anchors = TslTrustAnchors::new().with_cert_der(&cert_der);
        let err = parse_signature(doc.as_bytes())
            .expect("parse")
            .verify(doc.as_bytes(), &anchors)
            .expect_err("a SignatureMethod/hash mismatch must not verify");
        assert!(
            matches!(err, TslError::SignatureVerificationFailed),
            "got {err:?}"
        );
    }
}
