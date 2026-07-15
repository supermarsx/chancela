//! XML Canonicalization (C14N) for Trusted List XML-DSig — **Phase-A frozen seam (wp26 E2)**.
//!
//! XML-DSig signs the *canonical* form of `<ds:SignedInfo>` and of each referenced element, not the
//! raw source bytes. Real-world EU LOTL / member-state TSLs are signed over a genuine
//! canonicalization (inclusive RFC 3076 or exclusive RFC 3741), so verifying them requires
//! reconstructing those canonical bytes rather than hashing the source subtree verbatim (the
//! current `xmldsig.rs` fast-path, correct only for already-canonical lists).
//!
//! This module is the single owner of that canonicalization. Phase A freezes the public signature
//! below; **E2 replaces the stub body with a real implementation** (namespace/attribute ordering,
//! comment stripping, whitespace and empty-element normalization) over `quick-xml` / `roxmltree`.
//! `xmldsig.rs` (E3) consumes only [`C14nAlgorithm`] + [`canonicalize`].

use crate::error::TslError;

/// The XML canonicalization algorithm a `<ds:CanonicalizationMethod>` / `<ds:Transform>` selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum C14nAlgorithm {
    /// Inclusive XML Canonicalization 1.0 — `http://www.w3.org/TR/2001/REC-xml-c14n-20010315`
    /// (RFC 3076). All in-scope namespaces are emitted on the apex element.
    Inclusive,
    /// Inclusive XML Canonicalization 1.0 **with comments**
    /// (`http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments`).
    InclusiveWithComments,
    /// Exclusive XML Canonicalization 1.0 — `http://www.w3.org/2001/10/xml-exc-c14n#` (RFC 3741).
    /// Only visibly-utilized namespaces are emitted (plus any `InclusiveNamespaces` PrefixList).
    Exclusive,
    /// Exclusive XML Canonicalization 1.0 **with comments**
    /// (`http://www.w3.org/2001/10/xml-exc-c14n#WithComments`).
    ExclusiveWithComments,
}

impl C14nAlgorithm {
    /// Resolve a canonicalization/transform algorithm URI to a [`C14nAlgorithm`], or `None` when the
    /// URI is not a canonicalization we support.
    pub fn from_uri(uri: &str) -> Option<Self> {
        match uri {
            "http://www.w3.org/TR/2001/REC-xml-c14n-20010315" => Some(Self::Inclusive),
            "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments" => {
                Some(Self::InclusiveWithComments)
            }
            "http://www.w3.org/2001/10/xml-exc-c14n#" => Some(Self::Exclusive),
            "http://www.w3.org/2001/10/xml-exc-c14n#WithComments" => {
                Some(Self::ExclusiveWithComments)
            }
            _ => None,
        }
    }

    /// Whether this algorithm preserves comments in the canonical output.
    pub fn with_comments(self) -> bool {
        matches!(
            self,
            Self::InclusiveWithComments | Self::ExclusiveWithComments
        )
    }

    /// Whether this algorithm is exclusive canonicalization (RFC 3741).
    pub fn is_exclusive(self) -> bool {
        matches!(self, Self::Exclusive | Self::ExclusiveWithComments)
    }
}

/// Canonicalize a single XML element subtree per `algorithm`.
///
/// `element_bytes` is the serialized bytes of exactly one element (its start tag through its
/// matching end tag) **as it appears in the source document**, with the caller responsible for
/// having selected the correct subtree (for a whole-document `URI=""` reference with an
/// enveloped-signature transform, the `<ds:Signature>` element is removed first). Ancestor
/// namespace context that a real canonicalization must fold in is resolved by this function from the
/// declarations carried on the subtree; callers pass element bytes that still carry the ancestor
/// `xmlns` declarations in scope, exactly as XML-DSig requires.
///
/// Returns the canonical octet stream to be hashed. Returns [`TslError::Canonicalization`] when the
/// input is not well-formed or uses a construct this canonicalizer does not implement.
///
/// **Phase-A stub (wp26 E2 owns the implementation).**
pub fn canonicalize(element_bytes: &[u8], algorithm: C14nAlgorithm) -> Result<Vec<u8>, TslError> {
    let _ = (element_bytes, algorithm);
    Err(TslError::Unimplemented("c14n::canonicalize"))
}
