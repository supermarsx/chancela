//! Real-endpoint SCMD tests. **Never run in CI.**
//!
//! Double-gated: compiled only with `--features network-tests` AND marked `#[ignore]`, so
//! they run only when explicitly requested with real AMA preprod credentials. See `TESTING.md`.
#![cfg(feature = "network-tests")]

use chancela_cmd::{CmdConfig, HttpScmdTransport, ScmdClient, SignRequest};

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
    // A real CSPRNG: an encrypting preprod config RSA-encrypts the mobile for GetCertificate.
    let mut rng = rand_core::OsRng;
    let chain = client
        .get_certificate(&mut rng, &phone)
        .expect("GetCertificate against preprod");
    assert!(!chain.leaf_der.is_empty());
}

/// THE live-call runbook: the ONE preprod round trip that confirms AMA accepts what Chancela
/// constructs — GetCertificate -> SCMDSign -> ValidateOtp -> a real 256-byte RSA signature.
///
/// ## ⚠️ THIS PERFORMS A REAL QUALIFIED SIGNATURE
///
/// Confirming the OTP makes AMA produce a genuine qualified electronic signature under the
/// citizen's Chave Móvel Digital key over the digest this test submits. It is a real cryptographic
/// act, not a dry run. Only run it with a preprod **test** citizen and a throwaway digest, knowing
/// exactly what you are authorizing.
///
/// ## Why it cannot run by accident
///
/// Double-gated: it compiles only under `--features network-tests` (off in CI) **and** is
/// `#[ignore]`d, so a plain `cargo test` neither builds nor runs it. It additionally blocks on an
/// interactive OTP read from stdin, so even when compiled it cannot complete unattended.
///
/// ## Runbook
///
/// 1. Obtain preprod credentials from AMA integration/certification (`eid@ama.pt`).
/// 2. Export:
///    - `CHANCELA_CMD_ENV=preprod`
///    - `CHANCELA_CMD_APPLICATION_ID=<AMA-issued ApplicationId>`
///    - `CHANCELA_CMD_HTTP_BASIC_USERNAME` / `CHANCELA_CMD_HTTP_BASIC_PASSWORD` (if AMA requires them)
///    - `CHANCELA_CMD_AMA_CERT_PEM=<path to AMA field-encryption key PEM>` (field encryption is
///      mandatory on the real transport in every environment)
///    - `CHANCELA_CMD_TEST_PHONE=+351 XXXXXXXXX` — a phone registered for CMD in preprod
///    - `CHANCELA_CMD_TEST_PIN=<the citizen's CMD signature PIN>`
/// 3. Run (a TTY is required for the OTP prompt):
///    ```
///    cargo test -p chancela-cmd --features network-tests -- --ignored --nocapture \
///        preprod_full_sign_round_trip
///    ```
/// 4. The test calls GetCertificate, then SCMDSign (AMA dispatches an OTP to the phone), then
///    prompts `OTP: ` on stdout. Type the OTP received on the device and press Enter.
/// 5. **Success** = a 256-byte RSA-2048 signature returned and a non-empty leaf certificate; the
///    test asserts both. Any AMA rejection surfaces as a redacted `CmdError` and fails the test.
#[test]
#[ignore = "PERFORMS A REAL QUALIFIED SIGNATURE against AMA preprod; needs credentials + an interactive OTP (see TESTING.md)"]
fn preprod_full_sign_round_trip() {
    use std::io::Write;

    let cfg = CmdConfig::from_env().expect("CMD env config (see TESTING.md)");
    let phone = std::env::var("CHANCELA_CMD_TEST_PHONE").expect("CHANCELA_CMD_TEST_PHONE");
    let pin = std::env::var("CHANCELA_CMD_TEST_PIN").expect("CHANCELA_CMD_TEST_PIN");
    let transport = HttpScmdTransport::from_config(&cfg).expect("build transport");
    let client = ScmdClient::from_config(transport, &cfg).expect("build client");
    let mut rng = rand_core::OsRng;

    // A throwaway 32-byte digest to sign. NOT a real document digest — this is a live-path probe.
    let digest = *b"chancela preprod live probe 0001";
    assert_eq!(digest.len(), 32);

    let handle = client
        .request_signature(
            &mut rng,
            &SignRequest {
                user_id: phone,
                pin,
                doc_name: "chancela preprod live-call probe (NOT A DOCUMENT)".to_string(),
                hash: digest.to_vec(),
            },
        )
        .expect("SCMDSign against preprod dispatched the OTP");
    assert_eq!(handle.code, "200");

    print!("An OTP was dispatched to the registered device. OTP: ");
    std::io::stdout().flush().ok();
    let mut otp = String::new();
    std::io::stdin()
        .read_line(&mut otp)
        .expect("read OTP from stdin");
    let otp = otp.trim();

    let raw = client
        .confirm_otp(&mut rng, &handle, otp)
        .expect("ValidateOtp against preprod returned the qualified signature");
    assert_eq!(raw.signature.len(), 256, "RSA-2048 signature is 256 bytes");
    assert!(
        !raw.signing_cert_der.is_empty(),
        "leaf certificate attached"
    );
}
