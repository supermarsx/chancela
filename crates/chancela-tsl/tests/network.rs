//! Live-network test for `chancela-tsl`. Double-gated: it is compiled only under the
//! `network-tests` feature AND is `#[ignore]`d, so it never runs in CI and, even locally, needs
//! an explicit `--features network-tests -- --ignored`. See `crates/chancela-tsl/TESTING.md`.
#![cfg(feature = "network-tests")]

use chancela_tsl::{
    DEFAULT_LOTL_URL, ENV_LOTL_URL, HttpTslSource, TslSource, TslTrustAnchors,
    bootstrap_member_tsl, parse_tsl,
};

#[test]
#[ignore = "hits the live Portuguese Trusted List over the network"]
fn fetches_and_parses_live_pt_tsl() {
    // Uses CHANCELA_TSL_URL if set, else the pinned GNS default.
    let source = HttpTslSource::from_env();
    let bytes = source.fetch().expect("fetch live TSL");
    let list = parse_tsl(&bytes).expect("parse live TSL");
    assert_eq!(list.scheme_territory, "PT");
    assert!(
        !list.providers.is_empty(),
        "the live PT TSL should list trust-service providers"
    );
}

/// Live LOTL → PT member-state bootstrap (wp26 §2.1 / E4).
///
/// Fetches the real EU List of Trusted Lists ([`DEFAULT_LOTL_URL`], overridable via
/// [`ENV_LOTL_URL`] for a mirror), authenticates it against the **pinned OJEU LOTL signing
/// certificate**, selects the `PT` pointer, fetches the PT TSL, and verifies it against the signer
/// certificate the authenticated LOTL pointer carries — proving member-state trust is derived from
/// the verified LOTL rather than a separate per-list pin.
///
/// The LOTL anchor is configured exactly like the national-list anchor, reusing
/// [`TslTrustAnchors::from_env`]: set `CHANCELA_TSL_TRUST_ANCHOR` to a file holding the OJEU LOTL
/// signing certificate (PEM/DER), and/or `CHANCELA_TSL_TRUST_ANCHOR_SHA256` to its DER SHA-256
/// fingerprint. The PT member source uses `CHANCELA_TSL_URL` (else the pinned GNS default).
///
/// **Fail-closed when unconfigured:** with no anchor set, this asserts the bootstrap *errors*
/// rather than trusting the LOTL — it never yields an authenticated list. Double-gated
/// (`network-tests` + `#[ignore]`), so it never runs in CI.
#[test]
#[ignore = "hits the live EU LOTL + PT TSL over the network; needs CHANCELA_TSL_TRUST_ANCHOR[_SHA256] pinned to the OJEU LOTL signing cert"]
fn bootstraps_live_pt_tsl_from_eu_lotl() {
    let lotl_url = std::env::var(ENV_LOTL_URL).unwrap_or_else(|_| DEFAULT_LOTL_URL.to_owned());
    let lotl_source = HttpTslSource::new(lotl_url);
    // The PT member-state TSL is fetched from CHANCELA_TSL_URL / the pinned GNS default; the
    // bootstrap authenticates it against the LOTL-derived PT pointer signer.
    let member_source = HttpTslSource::from_env();

    let anchors = TslTrustAnchors::from_env().expect("load LOTL trust anchors from env");

    if anchors.is_empty() {
        // Fail-closed: without the pinned OJEU LOTL signing certificate the LOTL is self-attested
        // and MUST NOT be trusted. Assert the bootstrap errors rather than returning a list.
        let err = bootstrap_member_tsl(&lotl_source, &member_source, &anchors, "PT")
            .expect_err("an unanchored LOTL must fail closed, never authenticate");
        eprintln!(
            "LOTL bootstrap fell closed (no CHANCELA_TSL_TRUST_ANCHOR[_SHA256] configured): {err}"
        );
        return;
    }

    let member = bootstrap_member_tsl(&lotl_source, &member_source, &anchors, "PT")
        .expect("bootstrap + authenticate the live PT TSL from the EU LOTL");
    assert!(
        member.authenticated,
        "a member list returned by bootstrap is authenticated by construction"
    );
    assert_eq!(member.list.scheme_territory, "PT");
    assert!(
        !member.list.providers.is_empty(),
        "the live PT TSL should list trust-service providers"
    );
}
