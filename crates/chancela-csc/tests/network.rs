//! Live-QTSP CSC v2 tests, gated behind the `network-tests` feature **and** `#[ignore]`.
//!
//! These NEVER run in CI. They require a real per-provider CSC sandbox account + credentials (the
//! CSC analogue of CMD's AMA onboarding), supplied via `CHANCELA_CSC_<PROVIDER>_*` env vars and a
//! `CHANCELA_CSC_TEST_BASE_URL`. Run manually, e.g.:
//!
//! ```text
//! CHANCELA_CSC_TEST_BASE_URL=https://sandbox.qtsp.example/csc/v2 \
//! CHANCELA_CSC_MYQTSP_CLIENT_ID=... CHANCELA_CSC_MYQTSP_CLIENT_SECRET=... \
//!   cargo test -p chancela-csc --features network-tests -- --ignored
//! ```

#![cfg(feature = "network-tests")]

use chancela_csc::{CscClient, CscConfig, CscSecrets, HttpCscTransport};

/// Smoke test: authenticate + list credentials against a live sandbox.
#[test]
#[ignore = "requires a live QTSP CSC sandbox + per-provider credentials"]
fn live_authenticate_and_list() {
    let provider_id =
        std::env::var("CHANCELA_CSC_TEST_PROVIDER").unwrap_or_else(|_| "myqtsp".to_string());
    let base_url = std::env::var("CHANCELA_CSC_TEST_BASE_URL")
        .expect("set CHANCELA_CSC_TEST_BASE_URL to the sandbox base");
    let config = CscConfig::sandbox(&provider_id, &provider_id, base_url);
    config.validate().expect("config valid");
    let secrets = CscSecrets::from_env(&provider_id).expect("per-provider secrets in env");
    let transport = HttpCscTransport::new(config.base_url.clone()).expect("transport");
    let client = CscClient::new(transport, config, secrets);

    let token = client.authenticate().expect("oauth2/token");
    let creds = client.list_credentials(&token).expect("credentials/list");
    assert!(
        !creds.is_empty(),
        "sandbox account should expose a credential"
    );
}
