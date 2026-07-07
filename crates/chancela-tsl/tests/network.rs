//! Live-network test for `chancela-tsl`. Double-gated: it is compiled only under the
//! `network-tests` feature AND is `#[ignore]`d, so it never runs in CI and, even locally, needs
//! an explicit `--features network-tests -- --ignored`. See `crates/chancela-tsl/TESTING.md`.
#![cfg(feature = "network-tests")]

use chancela_tsl::{HttpTslSource, TslSource, parse_tsl};

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
