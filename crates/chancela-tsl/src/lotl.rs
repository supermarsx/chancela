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
use crate::parse::{OtherTslPointer, TrustedList, parse_tsl};
use crate::source::{TslSource, TslTrustAnchors, validate_tsl_signature_with_anchors};

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
pub fn ingest_lotl(
    lotl_xml: &[u8],
    anchors: &TslTrustAnchors,
) -> Result<AuthenticatedList, TslError> {
    // Fail-closed at the root of trust: with no pinned LOTL signing anchor, the LOTL is
    // self-attested and MUST NOT be trusted. `validate_tsl_signature_with_anchors` already fails
    // closed on an empty set, but we reject early with a clearer message so the caller knows the
    // configuration — not the bytes — is at fault.
    if anchors.is_empty() {
        return Err(TslError::Lotl(
            "no LOTL trust anchor configured; the EU LOTL is the system root of trust and cannot \
             be authenticated without a pinned OJEU signing certificate (fail-closed)"
                .to_owned(),
        ));
    }
    // Verify the LOTL's own XML-DSig against the pinned OJEU anchors. On any failure the error is
    // propagated verbatim (SignatureUntrusted / SignatureVerificationFailed / …); we never fall
    // through to return an authenticated list for a list whose signature did not verify.
    validate_tsl_signature_with_anchors(lotl_xml, anchors)?;
    let list = parse_tsl(lotl_xml)?;
    Ok(AuthenticatedList {
        list,
        authenticated: true,
        stale: false,
    })
}

/// Select the member-state pointer for `territory` (e.g. `PT`) from an authenticated LOTL. Prefers a
/// pointer whose `MimeType` denotes an XML TSL. Returns `None` when no pointer matches.
pub fn member_pointer<'a>(
    lotl: &'a AuthenticatedList,
    territory: &str,
) -> Option<&'a OtherTslPointer> {
    let want = territory.trim();

    let territory_matches = |pointer: &OtherTslPointer| {
        pointer
            .scheme_territory
            .as_deref()
            .is_some_and(|t| t.trim().eq_ignore_ascii_case(want))
    };
    // An XML TSL pointer (the machine-readable list) is preferred over a PDF human-readable one.
    let is_xml_tsl = |pointer: &OtherTslPointer| {
        pointer.mime_type.as_deref().is_some_and(|mime| {
            let mime = mime.to_ascii_lowercase();
            mime.contains("tsl+xml") || mime.contains("xml")
        })
    };

    // One pass: return the first XML pointer for the territory, remembering the first territory
    // match of any mime type as a fallback (a pointer that omits MimeType is still usable).
    let mut fallback: Option<&OtherTslPointer> = None;
    for pointer in &lotl.list.other_tsl_pointers {
        if !territory_matches(pointer) {
            continue;
        }
        if is_xml_tsl(pointer) {
            return Some(pointer);
        }
        if fallback.is_none() {
            fallback = Some(pointer);
        }
    }
    fallback
}

/// Ingest and authenticate a member-state TSL from raw XML: verify its XML-DSig against the signer
/// certificate(s) the authenticated LOTL `pointer` carries, then parse it. Fail-closed: a pointer
/// with no signer certificate, or a signature that does not verify, yields an error.
pub fn ingest_member_tsl(
    tsl_xml: &[u8],
    pointer: &OtherTslPointer,
) -> Result<AuthenticatedList, TslError> {
    // Fail-closed: a pointer with no signer certificate carries no basis for trust. Rather than
    // fall back to the environment anchor (which anchors the *national* list, not this pointer),
    // we refuse — the whole point of LOTL traversal is that member-state trust is derived from the
    // verified LOTL pointer.
    if pointer.signer_certs.is_empty() {
        return Err(TslError::Lotl(
            "member-state pointer carries no signer certificate".to_owned(),
        ));
    }

    // The member-state TSL's expected signer is whatever the authenticated LOTL pointer names.
    // A pointer may carry several certificates to cover key rotation; take their union.
    let anchors = pointer
        .signer_certs
        .iter()
        .fold(TslTrustAnchors::new(), |anchors, cert| {
            anchors.with_cert_der(cert)
        });

    validate_tsl_signature_with_anchors(tsl_xml, &anchors)?;
    let list = parse_tsl(tsl_xml)?;
    Ok(AuthenticatedList {
        list,
        authenticated: true,
        stale: false,
    })
}

/// End-to-end live bootstrap: fetch the LOTL via `lotl_source`, authenticate it against `anchors`,
/// select the `territory` pointer, fetch that member-state TSL via `member_source`, and authenticate
/// it against the pointer. Returns the authenticated member-state list.
pub fn bootstrap_member_tsl<L: TslSource, M: TslSource>(
    lotl_source: &L,
    member_source: &M,
    anchors: &TslTrustAnchors,
    territory: &str,
) -> Result<AuthenticatedList, TslError> {
    // 1. Fetch + authenticate the LOTL against the pinned OJEU anchors (fail-closed).
    let lotl_bytes = lotl_source.fetch()?;
    let lotl = ingest_lotl(&lotl_bytes, anchors)?;

    // 2. Select the member-state pointer for `territory` from the *authenticated* LOTL. Its signer
    //    certificate is the derived trust anchor for the member-state list.
    let pointer = member_pointer(&lotl, territory).ok_or_else(|| {
        TslError::Lotl(format!(
            "the authenticated LOTL carries no member-state pointer for territory {territory:?}"
        ))
    })?;

    // 3. Fetch + authenticate the member-state TSL against that LOTL-derived signer.
    let member_bytes = member_source.fetch()?;
    ingest_member_tsl(&member_bytes, pointer)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Wrap a set of pointers in an (otherwise empty) authenticated LOTL for selection tests.
    fn lotl_with(pointers: Vec<OtherTslPointer>) -> AuthenticatedList {
        AuthenticatedList {
            list: TrustedList {
                scheme_operator_name: String::new(),
                scheme_operator_names: Vec::new(),
                scheme_name: String::new(),
                scheme_names: Vec::new(),
                scheme_territory: "EU".to_owned(),
                sequence_number: None,
                issue_date_time: None,
                next_update: None,
                other_tsl_pointers: pointers,
                providers: Vec::new(),
            },
            authenticated: true,
            stale: false,
        }
    }

    fn pointer(location: &str, territory: &str, mime: Option<&str>) -> OtherTslPointer {
        OtherTslPointer {
            tsl_location: location.to_owned(),
            scheme_territory: Some(territory.to_owned()),
            mime_type: mime.map(str::to_owned),
            signer_certs: vec![b"member signer cert der".to_vec()],
        }
    }

    #[test]
    fn member_pointer_prefers_xml_over_pdf_and_is_case_insensitive() {
        // Order deliberately puts the PDF pointer first: selection must prefer the XML TSL
        // regardless of document order, and match the territory case-insensitively.
        let lotl = lotl_with(vec![
            pointer("https://example.test/PT.pdf", "PT", Some("application/pdf")),
            pointer(
                "https://example.test/PT.xml",
                "PT",
                Some("application/vnd.etsi.tsl+xml"),
            ),
            pointer(
                "https://example.test/ES.xml",
                "ES",
                Some("application/vnd.etsi.tsl+xml"),
            ),
        ]);

        let chosen = member_pointer(&lotl, "pt").expect("a PT pointer is present");
        assert_eq!(chosen.tsl_location, "https://example.test/PT.xml");
        assert!(
            chosen
                .mime_type
                .as_deref()
                .is_some_and(|m| m.contains("xml"))
        );
    }

    #[test]
    fn member_pointer_falls_back_to_any_matching_pointer_without_xml_mime() {
        // A pointer that omits MimeType is still usable when it is the only territory match.
        let lotl = lotl_with(vec![pointer("https://example.test/PT", "PT", None)]);
        let chosen = member_pointer(&lotl, "PT").expect("the sole PT pointer is selected");
        assert_eq!(chosen.tsl_location, "https://example.test/PT");
    }

    #[test]
    fn member_pointer_returns_none_for_absent_territory() {
        let lotl = lotl_with(vec![pointer(
            "https://example.test/PT.xml",
            "PT",
            Some("application/vnd.etsi.tsl+xml"),
        )]);
        assert!(member_pointer(&lotl, "DE").is_none());
    }

    #[test]
    fn ingest_member_tsl_fails_closed_without_signer_cert() {
        // Fail-closed cardinal rule: a pointer carrying no signer certificate can never authenticate
        // a member-state list — it must error before any signature/parse work.
        let pointer = OtherTslPointer {
            tsl_location: "https://example.test/PT.xml".to_owned(),
            scheme_territory: Some("PT".to_owned()),
            mime_type: Some("application/vnd.etsi.tsl+xml".to_owned()),
            signer_certs: Vec::new(),
        };
        let err = ingest_member_tsl(b"<TrustServiceStatusList/>", &pointer).unwrap_err();
        assert!(
            matches!(err, TslError::Lotl(ref msg) if msg.contains("no signer certificate")),
            "got {err:?}"
        );
    }

    #[test]
    fn ingest_lotl_fails_closed_with_empty_anchor_set() {
        // The LOTL is the system root of trust: with no pinned anchor it can never be authenticated,
        // and crucially never yields an `authenticated: true` list.
        let result = ingest_lotl(b"<TrustServiceStatusList/>", &TslTrustAnchors::new());
        let err = result.expect_err("empty anchors must fail closed");
        assert!(matches!(err, TslError::Lotl(_)), "got {err:?}");
    }

    #[test]
    fn ingest_lotl_with_anchor_but_no_valid_signature_is_not_authenticated() {
        // Even with an anchor configured, unsigned/garbage XML must not produce an authenticated
        // list — the signature has to verify first (never a silent upgrade).
        let anchors = TslTrustAnchors::new().with_cert_der(b"some pinned OJEU cert der");
        let result = ingest_lotl(b"<TrustServiceStatusList/>", &anchors);
        assert!(
            result.is_err(),
            "a list with no verifiable signature must never authenticate: {result:?}"
        );
    }
}
