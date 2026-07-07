//! Real-endpoint SCMD tests. **Never run in CI.**
//!
//! Double-gated: compiled only with `--features network-tests` AND marked `#[ignore]`, so
//! they run only when explicitly requested with real AMA preprod credentials. See `TESTING.md`.
#![cfg(feature = "network-tests")]

use chancela_cmd::{CmdConfig, HttpScmdTransport, ScmdClient};

/// Fetch a citizen certificate from AMA preprod.
///
/// Requires: `CHANCELA_CMD_ENV=preprod`, a valid `CHANCELA_CMD_APPLICATION_ID` issued by AMA,
/// and `CHANCELA_CMD_TEST_PHONE` set to a phone registered for CMD in preprod.
#[test]
#[ignore = "hits AMA preprod; needs a registered ApplicationId + test phone"]
fn preprod_get_certificate() {
    let cfg = CmdConfig::from_env().expect("CMD env config (see TESTING.md)");
    let phone = std::env::var("CHANCELA_CMD_TEST_PHONE").expect("CHANCELA_CMD_TEST_PHONE");
    let transport = HttpScmdTransport::from_config(&cfg).expect("build transport");
    let client = ScmdClient::from_config(transport, &cfg).expect("build client");
    let chain = client
        .get_certificate(&phone)
        .expect("GetCertificate against preprod");
    assert!(!chain.leaf_der.is_empty());
}
