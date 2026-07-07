//! Live registry consultation — the honest live-validation seam (plan t11 §4).
//!
//! DOUBLE-GATED: this file compiles only under `--features network-tests`, and the test inside is
//! additionally `#[ignore]`d, so it never runs in CI. It hits the real certidão permanente
//! endpoint with a **real, user-supplied access code**. See `TESTING.md` for the workflow.
//!
//! Run it with:
//! ```text
//! CHANCELA_REGISTRY_TEST_CODE=XXXX-XXXX-XXXX \
//!   cargo test -p chancela-registry --features network-tests -- --ignored --nocapture
//! ```

#![cfg(feature = "network-tests")]

use chancela_registry::{
    AccessCode, ENV_REGISTRY_EMAIL, ENV_REGISTRY_TEST_CODE, HttpRegistryTransport, RegistryClient,
};

#[test]
#[ignore = "hits the live registry; requires CHANCELA_REGISTRY_TEST_CODE (a real access code)"]
fn live_consultation_parses_a_real_certidao() {
    let raw_code = std::env::var(ENV_REGISTRY_TEST_CODE).unwrap_or_else(|_| {
        panic!("set {ENV_REGISTRY_TEST_CODE} to a real 12-digit access code to run this test")
    });
    let code = AccessCode::parse(&raw_code).expect("CHANCELA_REGISTRY_TEST_CODE must be 12 digits");
    let email = std::env::var(ENV_REGISTRY_EMAIL).ok();

    let transport = HttpRegistryTransport::from_env().expect("build http transport");
    let extract = RegistryClient::new(transport)
        .lookup(&code, email.as_deref())
        .expect("live lookup should parse a certidão");

    // Print the parsed shape so a human can eyeball the live parse against the real certidão.
    // Note: the access code is never printed — only its masked provenance.
    eprintln!("masked code : {}", extract.provenance.access_code_masked);
    eprintln!("retrieved_at: {}", extract.provenance.retrieved_at);
    eprintln!("source_url  : {}", extract.provenance.source_url);
    eprintln!("raw_digest  : {}", extract.provenance.raw_digest);
    eprintln!("nipc        : {:?}", extract.nipc);
    eprintln!("firma       : {:?}", extract.firma);
    eprintln!(
        "forma       : {:?} -> {:?}",
        extract.forma_juridica, extract.legal_form
    );
    eprintln!("sede        : {:?}", extract.sede);
    eprintln!("cae         : {:?}", extract.cae);
    eprintln!("inscrições  : {} entries", extract.inscricoes.len());
    eprintln!("órgãos      : {} officers", extract.orgaos.len());

    // The live document must at least yield an identity anchor if it parsed at all.
    assert!(
        extract.nipc.is_some() || extract.firma.is_some(),
        "a real certidão should carry a NIPC or firma"
    );
}
