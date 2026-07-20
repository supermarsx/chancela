//! Live TSA integration test (spec 04, SIG-22).
//!
//! Double-gated: compiled only under `--features network-tests` AND marked `#[ignore]`, so it
//! never runs in CI and must be invoked explicitly against a reachable RFC 3161 TSA. Set
//! `CHANCELA_TSA_URL` to the endpoint. See `TESTING.md`.

#![cfg(feature = "network-tests")]

use sha2::{Digest, Sha256};

use chancela_tsa::{HttpTsaTransport, TsaClient};

#[test]
#[ignore = "hits a live RFC 3161 TSA; requires CHANCELA_TSA_URL and network access"]
fn live_tsa_stamps_a_digest() {
    let transport = HttpTsaTransport::from_env().expect("CHANCELA_TSA_URL must be set");
    let client = TsaClient::new(transport);

    let digest: [u8; 32] = Sha256::digest(b"chancela live TSA smoke test").into();
    let ts = client.timestamp(digest).expect("live TSA timestamp");

    assert!(!ts.token_der.is_empty());
    println!(
        "live TSA granted: genTime={} policy={} serial={:02x?}",
        ts.gen_time, ts.policy, ts.serial_number
    );
}
