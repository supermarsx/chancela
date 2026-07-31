//! Golden conformance vectors: Chancela's CMD request construction and response parsing, pinned
//! byte-for-byte to the exact bytes the working reference `recov-pt` produces/consumes for the
//! same synthetic inputs.
//!
//! # What these prove — and what they do NOT
//!
//! The CMD JSON integration (`AppSCMDService.svc`) was rebuilt field-by-field from `recov-pt`
//! (`F:\Projects\recov-pt`, `src/cli/cmd_challenge.rs` + `src/cli/cmd_verify.rs`), the tool that
//! completes the real AMA CMD flow against the live service. Each vector below encodes the exact
//! serialization/parse that recov-pt performs, cites the recov-pt source line it pins, and asserts
//! Chancela produces/consumes the identical bytes.
//!
//! **These prove Chancela constructs requests and parses responses exactly as recov-pt does.**
//! They do **NOT** prove AMA accepts the bodies end to end: no live call is made here, and none
//! can be here (there is no live-test path in this environment). Golden vectors against a working
//! reference are strong evidence of construction parity, not proof of the round trip. The single
//! live preprod call that *would* confirm the round trip is the double-gated
//! (`--features network-tests` + `#[ignore]`) `preprod_full_sign_round_trip` in `tests/network.rs`;
//! see `TESTING.md`. A green run of this suite must not be read as an end-to-end guarantee.
//!
//! # Every value here is synthetic
//!
//! No real credential, key, endpoint token, phone, ApplicationId, PIN, OTP, or fingerprint from
//! recov-pt or any operator appears in this file. The ApplicationId is the all-zero GUID, the phone
//! is `+351000000000`, the PIN/OTP are `000000`, the ProcessId is the all-zero GUID, and the signed
//! digest is the well-known SHA-256 of the empty string (a public test vector, RFC 6234). Pinning
//! the *shape and transformation logic* needs no secret.
//!
//! # How the exact bytes are captured
//!
//! `wire.rs`'s serializers are `pub(crate)`, so these integration tests drive them through the
//! public [`ScmdClient`] over a recording [`MockScmdTransport`], with the [`FieldEncryptor::Cleartext`]
//! encryptor (`ScmdClient::new`) so the sensitive fields pass through verbatim and the emitted body
//! is fully deterministic. The mock stores the exact JSON string the wire layer built, which is what
//! we compare against the golden.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use chancela_cmd::rand_core::{CryptoRng, Error, RngCore, impls};
use chancela_cmd::wire::{OP_GET_CERTIFICATE, OP_SCMD_SIGN, OP_VALIDATE_OTP};
use chancela_cmd::{CmdError, MockScmdTransport, ScmdClient, SignRequest, SignatureAlgorithm};

// --- synthetic inputs (see module doc: every value is synthetic) --------------------------------

/// Fake ApplicationId — the all-zero GUID, sent as the RAW string (never base64).
const APP_ID: &str = "00000000-0000-0000-0000-000000000000";
/// Fake citizen mobile, already in space-free wire form.
const PHONE: &str = "+351000000000";
/// Operator-entered grouping-space form; the flow strips the spaces before it reaches the wire.
const PHONE_SPACED: &str = "+351 000000000";
/// Fake signing PIN.
const PIN: &str = "000000";
/// Fake OTP.
const OTP: &str = "000000";
/// Fake ProcessId — the all-zero GUID.
const PROCESS_ID: &str = "00000000-0000-0000-0000-000000000000";
/// Synthetic document label. ASCII-only so the golden byte string is unambiguous.
const DOC_NAME: &str = "Chancela conformance vector NOT A DOCUMENT";

/// The bare 32-byte digest fed to `SCMDSign`: SHA-256 of the empty string.
///
/// This is a public test vector (RFC 6234 / FIPS 180-4). recov-pt pins the same 32 bytes as the
/// tail of its `DigestInfo` in `src/cli/cmd_challenge.rs:351-354`, so reusing it makes the Hash
/// golden a direct cross-reference to recov-pt's own asserted value.
const EMPTY_SHA256_DIGEST: [u8; 32] = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
];

/// Golden base64 of the 51-byte RFC 8017 §9.2 SHA-256 `DigestInfo` over [`EMPTY_SHA256_DIGEST`]
/// (19-byte prefix + the 32 digest bytes). Computed independently of the crate constant; the flow
/// must reproduce it exactly. recov-pt builds the same 51 bytes (`src/cli/cmd_challenge.rs:20-83`).
const EMPTY_SHA256_HASH_B64: &str =
    "MDEwDQYJYIZIAWUDBAIBBQAEIOOwxEKY/BwUmvv0yJlvuSQnrkHkZJuTTKSVmRt4UrhV";

// --- golden request bodies (byte-exact, compact serde_json — no spaces, `/` unescaped) ----------

/// `GetCertificate` — recov-pt `src/cli/cmd_verify.rs:1096-1099`
/// (`{"ApplicationId": <raw>, "UserId": <encrypted mobile>}`; raw ApplicationId at line 1097).
const GOLDEN_GET_CERTIFICATE: &str =
    r#"{"ApplicationId":"00000000-0000-0000-0000-000000000000","UserId":"+351000000000"}"#;

/// `SCMDSign` — recov-pt `src/cli/cmd_challenge.rs:85-112` (PascalCase struct, field order
/// ApplicationId, UserId, Pin, Hash, DocName; five members).
const GOLDEN_SCMD_SIGN: &str = concat!(
    r#"{"ApplicationId":"00000000-0000-0000-0000-000000000000","#,
    r#""UserId":"+351000000000","Pin":"000000","#,
    r#""Hash":"MDEwDQYJYIZIAWUDBAIBBQAEIOOwxEKY/BwUmvv0yJlvuSQnrkHkZJuTTKSVmRt4UrhV","#,
    r#""DocName":"Chancela conformance vector NOT A DOCUMENT"}"#,
);

/// `ValidateOtp` — recov-pt `src/cli/cmd_challenge.rs:139-164` (field order ApplicationId, Code,
/// ProcessId, then the camelCase `isBiometricValidation` always `false`; four members).
const GOLDEN_VALIDATE_OTP: &str = concat!(
    r#"{"ApplicationId":"00000000-0000-0000-0000-000000000000","#,
    r#""Code":"000000","ProcessId":"00000000-0000-0000-0000-000000000000","#,
    r#""isBiometricValidation":false}"#,
);

// --- test RNG (unused by the Cleartext encryptor but required by the method signatures) ---------

/// Deterministic xorshift RNG for offline tests (never used in production).
struct TestRng(u64);
impl TestRng {
    fn new() -> Self {
        TestRng(0x9e37_79b9_7f4a_7c15)
    }
}
impl RngCore for TestRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        impls::fill_bytes_via_next(self, dest)
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
impl CryptoRng for TestRng {}

/// A `SCMDSign` success whose `ProcessId` is the synthetic all-zero GUID, so the `ValidateOtp`
/// envelope built downstream carries a deterministic ProcessId for the byte-exact golden.
fn scmd_sign_ok_with_synthetic_process_id() -> String {
    format!(r#"{{"Code":"200","Message":"ok","ProcessId":"{PROCESS_ID}"}}"#)
}

fn sign_request() -> SignRequest {
    SignRequest {
        user_id: PHONE.to_string(),
        pin: PIN.to_string(),
        doc_name: DOC_NAME.to_string(),
        hash: EMPTY_SHA256_DIGEST.to_vec(),
    }
}

// --- request construction vectors ---------------------------------------------------------------

#[test]
fn get_certificate_body_is_byte_identical_to_recov_pt() {
    // recov-pt `src/cli/cmd_verify.rs:1096-1099`.
    let mut rng = TestRng::new();
    let client = ScmdClient::new(MockScmdTransport::preprod_success(), APP_ID);
    client
        .get_certificate(&mut rng, PHONE)
        .expect("GetCertificate parses the canned chain");

    let envelope = client
        .transport()
        .last_envelope_for(OP_GET_CERTIFICATE)
        .expect("GetCertificate was called");
    assert_eq!(
        envelope, GOLDEN_GET_CERTIFICATE,
        "GetCertificate body drifted from the recov-pt reference"
    );
    // The ApplicationId is the RAW GUID, never base64 — a distinct claim from mere field equality.
    assert!(
        !envelope.contains(&STANDARD.encode(APP_ID.as_bytes())),
        "the base64 of the ApplicationId must not appear on the wire"
    );
}

#[test]
fn scmd_sign_body_is_byte_identical_to_recov_pt() {
    // recov-pt `src/cli/cmd_challenge.rs:85-112`.
    let mut rng = TestRng::new();
    let client = ScmdClient::new(MockScmdTransport::preprod_success(), APP_ID);
    client
        .request_signature(&mut rng, &sign_request())
        .expect("SCMDSign round trip");

    let envelope = client
        .transport()
        .last_envelope_for(OP_SCMD_SIGN)
        .expect("SCMDSign was called");
    assert_eq!(
        envelope, GOLDEN_SCMD_SIGN,
        "SCMDSign body drifted from the recov-pt reference"
    );
    // The Hash carries the 51-byte DER DigestInfo (68 base64 chars), never the bare 32-byte digest.
    assert!(
        envelope.contains(EMPTY_SHA256_HASH_B64),
        "Hash must be the base64 of the RFC 8017 §9.2 DigestInfo"
    );
    assert!(
        !envelope.contains(&STANDARD.encode(EMPTY_SHA256_DIGEST)),
        "the bare digest must never appear on the wire"
    );
}

#[test]
fn validate_otp_body_is_byte_identical_to_recov_pt() {
    // recov-pt `src/cli/cmd_challenge.rs:139-164`.
    let mut rng = TestRng::new();
    let mock = MockScmdTransport::preprod_success()
        .with_response(OP_SCMD_SIGN, scmd_sign_ok_with_synthetic_process_id());
    let client = ScmdClient::new(mock, APP_ID);
    let handle = client
        .request_signature(&mut rng, &sign_request())
        .expect("SCMDSign round trip");
    assert_eq!(handle.process_id, PROCESS_ID);
    client
        .confirm_otp(&mut rng, &handle, OTP)
        .expect("ValidateOtp round trip");

    let envelope = client
        .transport()
        .last_envelope_for(OP_VALIDATE_OTP)
        .expect("ValidateOtp was called");
    assert_eq!(
        envelope, GOLDEN_VALIDATE_OTP,
        "ValidateOtp body drifted from the recov-pt reference"
    );
}

#[test]
fn grouping_spaces_are_stripped_before_the_wire() {
    // recov-pt strips grouping spaces before encrypting (`src/cli/private_input.rs:78`), so the
    // service is given `+351000000000`, never `+351 000000000`. The operator-entered spaced form
    // must serialize to the identical golden body.
    let mut rng = TestRng::new();
    let client = ScmdClient::new(MockScmdTransport::preprod_success(), APP_ID);
    client
        .get_certificate(&mut rng, PHONE_SPACED)
        .expect("GetCertificate parses");

    let envelope = client
        .transport()
        .last_envelope_for(OP_GET_CERTIFICATE)
        .expect("GetCertificate was called");
    assert_eq!(
        envelope, GOLDEN_GET_CERTIFICATE,
        "grouping spaces must not change the wire body"
    );
}

// --- response parsing vectors (the exact JSON shapes recov-pt receives) -------------------------

/// Build a client whose `GetCertificate`/`SCMDSign` succeed and whose `ValidateOtp` returns
/// `otp_response`, then run the flow to a handle and confirm the OTP.
fn confirm_with_validate_otp_response(
    otp_response: &str,
) -> Result<chancela_cmd::RawSignature, CmdError> {
    let mut rng = TestRng::new();
    let mock = MockScmdTransport::preprod_success().with_response(OP_VALIDATE_OTP, otp_response);
    let client = ScmdClient::new(mock, APP_ID);
    let handle = client
        .request_signature(&mut rng, &sign_request())
        .expect("SCMDSign round trip");
    client.confirm_otp(&mut rng, &handle, OTP)
}

#[test]
fn validate_otp_signature_is_decoded_from_the_integer_array() {
    // recov-pt returns the signature as a JSON **integer array**, not base64
    // (`src/cli/cmd_challenge.rs:190-206`). The bytes must decode verbatim, full 0..=255 range.
    let response = r#"{"Status":{"Code":"200","Message":"ok"},"Signature":[0,1,127,128,254,255]}"#;
    let raw =
        confirm_with_validate_otp_response(response).expect("integer-array signature decodes");
    assert!(matches!(raw.algorithm, SignatureAlgorithm::RsaPkcs1Sha256));
    assert_eq!(raw.signature, [0, 1, 127, 128, 254, 255]);
}

#[test]
fn validate_otp_rejects_a_base64_signature() {
    // NEGATIVE: a base64 string is NOT how the service returns the signature — it is an integer
    // array. recov-pt rejects a non-array Signature (`src/cli/cmd_challenge.rs:190-193`);
    // Chancela's `wire::parse_validate_otp` mirrors it (`src/wire.rs:194-202`).
    let response = r#"{"Status":{"Code":"200"},"Signature":"AQID"}"#;
    let err = confirm_with_validate_otp_response(response)
        .expect_err("base64 signature must be rejected");
    assert!(matches!(err, CmdError::ResponseParse(_)), "{err:?}");
}

#[test]
fn validate_otp_rejects_out_of_range_signature_items() {
    // NEGATIVE: only 0..=255 integers are valid signature bytes
    // (recov-pt `src/cli/cmd_challenge.rs:198-206`).
    for item in ["256", "-1", "1.5", r#""1""#, "null", "true"] {
        let response = format!(r#"{{"Status":{{"Code":"200"}},"Signature":[{item}]}}"#);
        match confirm_with_validate_otp_response(&response) {
            Err(CmdError::ResponseParse(_)) => {}
            other => panic!("item {item}: expected ResponseParse, got {other:?}"),
        }
    }
}

#[test]
fn validate_otp_surfaces_a_non_success_status_code() {
    // NEGATIVE: a non-"200" `Status.Code` is surfaced as a rejection, never treated as success
    // (recov-pt `src/cli/cmd_challenge.rs:225-237`; `Code:"200"` is the only success).
    let response = r#"{"Status":{"Code":"402","Message":"OTP invalido"},"Signature":null}"#;
    let err = confirm_with_validate_otp_response(response).expect_err("402 must surface");
    match err {
        CmdError::OtpRejected { code, .. } => assert_eq!(code, "402"),
        other => panic!("expected OtpRejected(402), got {other:?}"),
    }
}

/// Run `GetCertificate`/`ValidateOtp` success but override `SCMDSign` with `sign_response`.
fn request_signature_with_scmd_sign_response(
    sign_response: &str,
) -> Result<chancela_cmd::ProcessHandle, CmdError> {
    let mut rng = TestRng::new();
    let mock = MockScmdTransport::preprod_success().with_response(OP_SCMD_SIGN, sign_response);
    let client = ScmdClient::new(mock, APP_ID);
    client.request_signature(&mut rng, &sign_request())
}

#[test]
fn scmd_sign_parses_the_d_string_wrapper() {
    // recov-pt unwraps the ASP.NET-AJAX `{"d": "<json>"}` envelope, re-parsing the string payload
    // (`src/cli/cmd_challenge.rs:209-223`; Chancela `src/wire.rs:234-245`).
    let response =
        r#"{"d":"{\"Code\":\"200\",\"ProcessId\":\"00000000-0000-0000-0000-000000000000\"}"}"#;
    let handle = request_signature_with_scmd_sign_response(response).expect("string-wrapped d");
    assert_eq!(handle.process_id, PROCESS_ID);
}

#[test]
fn scmd_sign_parses_the_d_object_wrapper() {
    // The object form of the `{"d": ...}` envelope (recov-pt `src/cli/cmd_challenge.rs:216-221`).
    let response = r#"{"d":{"Code":"200","ProcessId":"00000000-0000-0000-0000-000000000000"}}"#;
    let handle = request_signature_with_scmd_sign_response(response).expect("object-wrapped d");
    assert_eq!(handle.process_id, PROCESS_ID);
}

#[test]
fn scmd_sign_surfaces_a_non_success_status_code() {
    // NEGATIVE: a non-"200" `Code` is surfaced, never treated as success
    // (recov-pt `src/cli/cmd_challenge.rs:225-237`).
    let response = r#"{"Code":"401","Message":"PIN invalido"}"#;
    let err = request_signature_with_scmd_sign_response(response).expect_err("401 must surface");
    match err {
        CmdError::ServiceStatus { code, .. } => assert_eq!(code, "401"),
        other => panic!("expected ServiceStatus(401), got {other:?}"),
    }
}

#[test]
fn scmd_sign_requires_a_string_status_code() {
    // NEGATIVE: recov-pt requires the `Code` to be a JSON **string**, rejecting a numeric `200`
    // (`src/cli/cmd_challenge.rs:226`). A numeric code must be a parse error, not silent success.
    let response = r#"{"Code":200,"ProcessId":"00000000-0000-0000-0000-000000000000"}"#;
    let err = request_signature_with_scmd_sign_response(response)
        .expect_err("numeric Code must be rejected");
    assert!(matches!(err, CmdError::ResponseParse(_)), "{err:?}");
}
