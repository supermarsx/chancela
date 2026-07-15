//! Generic X.509 certificate-path builder — **Phase-A frozen seam (wp26 E5)**.
//!
//! Builds a path from an end-entity signer certificate, through any intermediate CA certificates
//! carried alongside it (e.g. from a CMS `SignedData` certificate set), up to a trust anchor
//! extracted from an authenticated Trusted List ([`crate::trust_store::TslTrustStore`]). This is the
//! missing piece over today's fingerprint pin: real chaining with validity, basic-constraints,
//! path-length, key-usage, and child-signature checks.
//!
//! The algorithm mirrors the conservative offline builder in `chancela-tsa/src/path.rs` (RSA-SHA256
//! and P-256 ECDSA-SHA256 only; reject unknown algorithms rather than guess). The cross-crate
//! duplication is deliberate and acceptable for now — a shared helper is a documented future
//! cleanup (wp26 §5 risk 3), not part of this work package.
//!
//! Phase A freezes the public API; **E5 replaces the stub body** with the real path build.

use time::OffsetDateTime;

use crate::error::TslError;

/// Options controlling a path build.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct PathBuildOptions {
    /// The instant at which certificate validity (`notBefore`/`notAfter`) is evaluated — typically
    /// the signing time or a trusted timestamp, not wall-clock now.
    pub validation_time: OffsetDateTime,
}

impl PathBuildOptions {
    /// Build options that evaluate validity at `validation_time`.
    pub fn at(validation_time: OffsetDateTime) -> Self {
        Self { validation_time }
    }
}

/// A successfully built certificate path: the DER certificates from the end-entity leaf up to and
/// including the matched trust anchor, in chain order (`certs_der[0]` is the signer).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CertPath {
    /// The chain, leaf-first, anchor-last. Each certificate is DER-encoded.
    pub certs_der: Vec<Vec<u8>>,
}

impl CertPath {
    /// The end-entity (leaf) certificate DER — the signer whose path was built.
    pub fn leaf(&self) -> &[u8] {
        // The leaf is always present in a built path; an empty path is never constructed.
        self.certs_der.first().map(Vec::as_slice).unwrap_or(&[])
    }

    /// The matched trust-anchor certificate DER (the last element of the chain).
    pub fn anchor(&self) -> &[u8] {
        self.certs_der.last().map(Vec::as_slice).unwrap_or(&[])
    }

    /// The number of certificates in the path (leaf + intermediates + anchor).
    pub fn len(&self) -> usize {
        self.certs_der.len()
    }

    /// Whether the path carries no certificates (never true for a built path).
    pub fn is_empty(&self) -> bool {
        self.certs_der.is_empty()
    }

    /// Issuer of the signer within the built path — the certificate that signed the leaf. For a
    /// directly anchor-issued leaf this is the anchor. Returns the leaf itself only for a
    /// degenerate single-element self-issued path.
    pub fn signer_issuer(&self) -> &[u8] {
        self.certs_der
            .get(1)
            .or_else(|| self.certs_der.first())
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }
}

/// Build a certificate path from `signer_der` to one of `anchors`, using `intermediates` to bridge
/// the gap.
///
/// - `signer_der`: the end-entity signer certificate (DER).
/// - `intermediates`: candidate intermediate CA certificates (DER), order-independent — typically
///   the certificate set embedded in the CMS/PAdES signature.
/// - `anchors`: DER trust-anchor certificates (a `TslTrustStore`'s `qc_anchors` or `qtst_anchors`).
/// - `opts`: validity evaluation instant.
///
/// Verifies at each link: the child's issuer matches the parent's subject, the parent is a CA
/// (basic constraints) with a sufficient path length and a `keyCertSign` key usage, every
/// certificate is temporally valid at `opts.validation_time`, and the child's signature verifies
/// against the parent's public key (RSA-SHA256 / P-256 ECDSA-SHA256 only).
///
/// Returns the built [`CertPath`] (leaf-first, anchor-last) or [`TslError::CertPath`] when no path
/// to a configured anchor exists. **Fail-closed:** an empty `anchors` set yields an error.
///
/// **Phase-A stub (wp26 E5 owns the implementation).**
pub fn build_path(
    signer_der: &[u8],
    intermediates: &[Vec<u8>],
    anchors: &[Vec<u8>],
    opts: &PathBuildOptions,
) -> Result<CertPath, TslError> {
    let _ = (signer_der, intermediates, anchors, opts);
    Err(TslError::Unimplemented("certpath::build_path"))
}
