//! Offline RFC 3161 round-trip tests: build a request, replay a real OpenSSL `TimeStampResp`
//! through the mock transport, and verify the token structurally (spec 04, SIG-22).
//!
//! No network runs here; the response is the bundled real-world fixture. See `TESTING.md`.

use der::oid::ObjectIdentifier;
use sha2::{Digest, Sha256};

use chancela_tsa::mock::{
    FIXTURE_DIGEST, FIXTURE_NONCE, FIXTURE_REQUEST_DER, FIXTURE_RESPONSE_DER, MockTsaTransport,
};
use chancela_tsa::verify::QualifiedTimestampPolicy;
use chancela_tsa::{TimestampRequest, TsaClient, TsaError, verify_response};

/// The policy OID carried by the bundled OpenSSL fixture token (`tsa.cnf` `default_policy`).
const FIXTURE_POLICY: &str = "1.2.3.4.1";

fn fixture_request() -> TimestampRequest {
    // Match the bundled request exactly: certReq unset, explicit fixture nonce.
    TimestampRequest::new(FIXTURE_DIGEST)
        .without_certificate()
        .with_nonce(FIXTURE_NONCE)
}

#[test]
fn fixture_digest_is_sha256_of_abc() {
    assert_eq!(Sha256::digest(b"abc").as_slice(), &FIXTURE_DIGEST);
}

#[test]
fn built_request_matches_real_openssl_query_byte_for_byte() {
    // Proves our TimeStampReq encoder produces exactly what `openssl ts -query` emits.
    let der = fixture_request().to_der().expect("encode request");
    assert_eq!(der, FIXTURE_REQUEST_DER);
}

#[test]
fn verify_real_fixture_response() {
    let request = fixture_request();
    let ts = verify_response(
        FIXTURE_RESPONSE_DER,
        &request,
        &QualifiedTimestampPolicy::Any,
    )
    .expect("verify fixture response");

    assert_eq!(ts.policy, FIXTURE_POLICY);
    assert_eq!(ts.serial_number, vec![0x04]);
    // genTime from the fixture: 2023-06-07T11:26:26Z.
    assert_eq!(ts.gen_time.unix_timestamp(), 1_686_137_186);
    // certReq was unset in the request, so OpenSSL does not embed the signing cert.
    assert!(ts.tsa_certificate_der.is_none(), "fixture omits TSA cert");
    assert!(!ts.token_der.is_empty());
}

#[test]
fn client_round_trip_via_mock_transport() {
    let client = TsaClient::new(MockTsaTransport::from_fixture());
    let request = fixture_request();
    let ts = client.stamp(&request).expect("mock round-trip");
    assert_eq!(ts.policy, FIXTURE_POLICY);

    // The transport saw exactly the DER our encoder produced.
    let seen = client.transport().last_request().expect("recorded request");
    assert_eq!(seen, FIXTURE_REQUEST_DER);
}

#[test]
fn imprint_mismatch_is_rejected() {
    // Ask to timestamp a different digest than the fixture covers.
    let request = TimestampRequest::new([0x11; 32])
        .without_certificate()
        .with_nonce(FIXTURE_NONCE);
    let err = verify_response(
        FIXTURE_RESPONSE_DER,
        &request,
        &QualifiedTimestampPolicy::Any,
    )
    .unwrap_err();
    assert!(matches!(err, TsaError::ImprintMismatch), "got {err:?}");
}

#[test]
fn nonce_mismatch_is_rejected() {
    let request = TimestampRequest::new(FIXTURE_DIGEST)
        .without_certificate()
        .with_nonce(FIXTURE_NONCE ^ 0xFF);
    let err = verify_response(
        FIXTURE_RESPONSE_DER,
        &request,
        &QualifiedTimestampPolicy::Any,
    )
    .unwrap_err();
    assert!(matches!(err, TsaError::NonceMismatch), "got {err:?}");
}

#[test]
fn missing_nonce_in_request_skips_nonce_check() {
    // A request without a nonce accepts a token that happens to carry one.
    let request = TimestampRequest::new(FIXTURE_DIGEST).without_certificate();
    let ts = verify_response(
        FIXTURE_RESPONSE_DER,
        &request,
        &QualifiedTimestampPolicy::Any,
    )
    .expect("no-nonce request verifies");
    assert_eq!(ts.policy, FIXTURE_POLICY);
}

#[test]
fn qualified_policy_hook_accepts_matching_policy() {
    let request = fixture_request();
    let policy =
        QualifiedTimestampPolicy::RequireOneOf(vec![ObjectIdentifier::new_unwrap(FIXTURE_POLICY)]);
    assert!(verify_response(FIXTURE_RESPONSE_DER, &request, &policy).is_ok());
}

#[test]
fn qualified_policy_hook_rejects_other_policy() {
    let request = fixture_request();
    let policy = QualifiedTimestampPolicy::RequireOneOf(vec![ObjectIdentifier::new_unwrap(
        "1.3.6.1.4.1.99999.1",
    )]);
    let err = verify_response(FIXTURE_RESPONSE_DER, &request, &policy).unwrap_err();
    assert!(
        matches!(err, TsaError::PolicyRejected { ref got } if got == FIXTURE_POLICY),
        "got {err:?}"
    );
}

#[test]
fn cert_req_without_embedded_cert_is_rejected() {
    // The fixture token embeds no certificate; a request that set certReq=true must be rejected
    // because the returned token is not self-contained.
    let with_cert = TimestampRequest::new(FIXTURE_DIGEST).with_nonce(FIXTURE_NONCE);
    assert!(with_cert.cert_req());
    let err = verify_response(
        FIXTURE_RESPONSE_DER,
        &with_cert,
        &QualifiedTimestampPolicy::Any,
    )
    .unwrap_err();
    assert!(matches!(err, TsaError::NoTsaCertificate), "got {err:?}");
}

#[test]
fn truncated_response_is_a_decode_error() {
    let request = fixture_request();
    let err = verify_response(
        &FIXTURE_RESPONSE_DER[..FIXTURE_RESPONSE_DER.len() / 2],
        &request,
        &QualifiedTimestampPolicy::Any,
    )
    .unwrap_err();
    assert!(matches!(err, TsaError::DecodeResponse(_)), "got {err:?}");
}

#[test]
fn timestamp_serde_round_trips() {
    let request = fixture_request();
    let ts = verify_response(
        FIXTURE_RESPONSE_DER,
        &request,
        &QualifiedTimestampPolicy::Any,
    )
    .expect("verify");
    let json = serde_json::to_string(&ts).expect("serialize");
    let back: chancela_tsa::Timestamp = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back.policy, ts.policy);
    assert_eq!(back.serial_number, ts.serial_number);
    assert_eq!(back.gen_time, ts.gen_time);
    assert_eq!(back.token_der, ts.token_der);
}

#[test]
fn tampered_tstinfo_fails_message_digest_binding() {
    // Flip one digit inside the TSTInfo genTime (`...2626Z` -> `...2627Z`). This keeps every DER
    // length valid and leaves the message imprint untouched, so verification reaches the signed-
    // attribute binding check — where SHA-256 of the mutated TstInfo no longer equals the token's
    // message-digest attribute.
    let needle = b"20230607112626Z";
    let pos = FIXTURE_RESPONSE_DER
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("genTime present in fixture");
    let mut bytes = FIXTURE_RESPONSE_DER.to_vec();
    bytes[pos + needle.len() - 2] ^= 0x01; // final '6' (0x36) -> '7' (0x37), still a valid digit

    let request = fixture_request();
    let err = verify_response(&bytes, &request, &QualifiedTimestampPolicy::Any).unwrap_err();
    assert!(
        matches!(err, TsaError::MessageDigestMismatch),
        "got {err:?}"
    );
}
