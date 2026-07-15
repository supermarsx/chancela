//! Trust-anchor store aggregated from an authenticated Trusted List — **Phase-A frozen seam
//! (wp26 E5)**.
//!
//! Once a member-state TSL has been authenticated (its XML-DSig verified against a certificate
//! carried by a pointer inside a verified LOTL, wp26 §2.1), the CA/QC and TSA/QTST services it
//! lists that are *granted and effective* are the trust anchors an end-entity signer must chain to.
//! This module extracts those anchors into a [`TslTrustStore`] that the cert-path builder
//! ([`crate::certpath`]) and the signing crate consume.
//!
//! Phase A freezes the public API; **E5 replaces the stub bodies** with real aggregation over
//! [`crate::parse::TrustedList`].

use time::OffsetDateTime;

use crate::parse::TrustedList;

/// Trust anchors aggregated from an authenticated Trusted List.
///
/// `authenticated`/`stale` carry the provenance of the list the anchors came from so downstream
/// trust decisions never silently upgrade an unverified or stale list (fail-closed, wp26 §2.1).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct TslTrustStore {
    /// DER-encoded certificates of granted+effective CA/QC (qualified-certificate issuer) services —
    /// the anchors an end-entity **signing** certificate is path-built to.
    pub qc_anchors: Vec<Vec<u8>>,
    /// DER-encoded certificates of granted+effective TSA/QTST (qualified timestamp) services — the
    /// anchors a **timestamp** signer is path-built to.
    pub qtst_anchors: Vec<Vec<u8>>,
    /// Whether the list these anchors came from was cryptographically authenticated (LOTL-derived
    /// signer verification). Anchors from an unauthenticated list MUST NOT ground a trust decision.
    pub authenticated: bool,
    /// Whether the list these anchors came from was served from a stale cache (fetch failed, fell
    /// back to a previously-cached copy). Stale anchors may be reported but flagged.
    pub stale: bool,
}

impl TslTrustStore {
    /// Aggregate the granted+effective CA/QC and TSA/QTST anchors from `list` as of `now`.
    ///
    /// `authenticated` records whether `list` itself was authenticated (its own signature verified
    /// via the LOTL-derived path); `stale` records whether it came from a fallback cache. Both are
    /// carried through onto the returned store unchanged.
    ///
    /// **Phase-A stub (wp26 E5 owns the implementation).**
    pub fn from_list(
        list: &TrustedList,
        authenticated: bool,
        stale: bool,
        now: OffsetDateTime,
    ) -> Self {
        let _ = (list, now);
        Self {
            qc_anchors: Vec::new(),
            qtst_anchors: Vec::new(),
            authenticated,
            stale,
        }
    }

    /// Whether the store carries no anchors at all (nothing to chain to — fail-closed).
    pub fn is_empty(&self) -> bool {
        self.qc_anchors.is_empty() && self.qtst_anchors.is_empty()
    }
}
