//! Live EU LOTL (List of Trusted Lists) ingestion + member-state traversal — **Phase-A frozen
//! seam (wp26 E4)**.
//!
//! The EU List of Trusted Lists is the root directory: a single signed XML list whose
//! `PointersToOtherTSL` entries point at each member-state TSL and carry the certificate that
//! member-state list's own signature is expected to verify against. Trust bootstraps as
//! (wp26 §2.1):
//!
//! 1. Fetch the LOTL and verify its XML-DSig against the **pinned OJEU LOTL signing anchors**
//!    ([`crate::source::TslTrustAnchors`]) — fail-closed, exactly as the national list is anchored
//!    today.
//! 2. Parse `PointersToOtherTSL` into [`crate::parse::OtherTslPointer`]s.
//! 3. Select the member-state pointer for the target territory (e.g. `PT`).
//! 4. Fetch that member-state TSL and verify its XML-DSig against the signer certificate the
//!    **authenticated LOTL pointer** carries — deriving member-state trust from the verified LOTL
//!    rather than from a separate per-list pin.
//!
//! Graceful offline fallback: when a fetch fails, the caller may fall back to an on-disk cached copy
//! and the result is flagged `stale`; an unverifiable list is never reported authenticated.
//!
//! Phase A freezes the public API; **E4 replaces the stub bodies** with the real implementation,
//! and adds the `#[ignore]` live LOTL→PT test in `tests/network.rs`.

use crate::error::TslError;
use crate::parse::{OtherTslPointer, TrustedList};
use crate::source::{TslSource, TslTrustAnchors};

/// The pinned EU LOTL location (Official Journal of the EU). Overridable via
/// [`ENV_LOTL_URL`] for testing / mirror use. The LOTL signing certificate(s) are pinned separately
/// via [`crate::source::ENV_TSL_TRUST_ANCHOR`] (re-used as the LOTL anchor), fail-closed.
pub const DEFAULT_LOTL_URL: &str = "https://ec.europa.eu/tools/lotl/eu-lotl.xml";

/// Environment variable overriding [`DEFAULT_LOTL_URL`].
pub const ENV_LOTL_URL: &str = "CHANCELA_LOTL_URL";

/// An authenticated Trusted List (LOTL or member-state), plus provenance flags.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AuthenticatedList {
    /// The parsed list.
    pub list: TrustedList,
    /// Whether the list's own XML-DSig verified against the expected anchor/pointer certificate.
    pub authenticated: bool,
    /// Whether the bytes came from a fallback cache after a live fetch failed.
    pub stale: bool,
}

/// Ingest and authenticate a LOTL from raw XML: verify its XML-DSig against the pinned LOTL
/// `anchors`, then parse it (including its `PointersToOtherTSL`). Fail-closed: an empty anchor set
/// or a signature that does not verify yields [`TslError::Lotl`] / a signature error.
///
/// **Phase-A stub (wp26 E4 owns the implementation).**
pub fn ingest_lotl(
    lotl_xml: &[u8],
    anchors: &TslTrustAnchors,
) -> Result<AuthenticatedList, TslError> {
    let _ = (lotl_xml, anchors);
    Err(TslError::Unimplemented("lotl::ingest_lotl"))
}

/// Select the member-state pointer for `territory` (e.g. `PT`) from an authenticated LOTL. Prefers a
/// pointer whose `MimeType` denotes an XML TSL. Returns `None` when no pointer matches.
///
/// **Phase-A stub (wp26 E4 owns the implementation).**
pub fn member_pointer<'a>(
    lotl: &'a AuthenticatedList,
    territory: &str,
) -> Option<&'a OtherTslPointer> {
    let _ = (lotl, territory);
    None
}

/// Ingest and authenticate a member-state TSL from raw XML: verify its XML-DSig against the signer
/// certificate(s) the authenticated LOTL `pointer` carries, then parse it. Fail-closed: a pointer
/// with no signer certificate, or a signature that does not verify, yields an error.
///
/// **Phase-A stub (wp26 E4 owns the implementation).**
pub fn ingest_member_tsl(
    tsl_xml: &[u8],
    pointer: &OtherTslPointer,
) -> Result<AuthenticatedList, TslError> {
    let _ = (tsl_xml, pointer);
    Err(TslError::Unimplemented("lotl::ingest_member_tsl"))
}

/// End-to-end live bootstrap: fetch the LOTL via `lotl_source`, authenticate it against `anchors`,
/// select the `territory` pointer, fetch that member-state TSL via `member_source`, and authenticate
/// it against the pointer. Returns the authenticated member-state list.
///
/// **Phase-A stub (wp26 E4 owns the implementation).**
pub fn bootstrap_member_tsl<L: TslSource, M: TslSource>(
    lotl_source: &L,
    member_source: &M,
    anchors: &TslTrustAnchors,
    territory: &str,
) -> Result<AuthenticatedList, TslError> {
    let _ = (lotl_source, member_source, anchors, territory);
    Err(TslError::Unimplemented("lotl::bootstrap_member_tsl"))
}
