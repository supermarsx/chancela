//! Offline round-trip tests for the SCMD SIG-02 flow using [`MockScmdTransport`].
//!
//! These run with no network. Real preprod/prod calls live behind the `network-tests`
//! feature + `#[ignore]` (see `TESTING.md`).

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::Value;

use chancela_cmd::rand_core::{CryptoRng, Error, RngCore, impls};
use chancela_cmd::wire::{OP_SCMD_SIGN, OP_VALIDATE_OTP};
use chancela_cmd::{
    CmdConfig, CmdError, MockScmdTransport, ScmdClient, SignRequest, SignatureAlgorithm,
};

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

const APP_ID: &str = "CHANCELA-APP-0001";
/// Operator-entered form, with grouping spaces. The flow must strip them before encrypting.
const PHONE: &str = "+351 912345678";
/// The wire plaintext the field encryptor must see: the phone with spaces removed.
const PHONE_NORMALIZED: &str = "+351912345678";
const PROCESS_ID: &str = "b3f1c2a4-5d6e-4f80-9a1b-2c3d4e5f6a7b";

/// The 19-byte PKCS#1 v1.5 `DigestInfo` prefix for SHA-256, transcribed independently from
/// RFC 8017 §9.2 — deliberately **not** imported from the crate, so this test pins the bytes
/// rather than agreeing with whatever the production constant happens to say.
const EXPECTED_SHA256_DIGEST_INFO_PREFIX: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

/// Parse a recorded JSON request body.
fn body(json: &str) -> Value {
    serde_json::from_str(json).expect("recorded request body is JSON")
}

#[test]
fn full_request_otp_retrieve_round_trip() {
    let mut rng = TestRng::new();
    let client = ScmdClient::new(MockScmdTransport::preprod_success(), APP_ID);

    // 1. GetCertificate returns leaf + one issuer.
    let chain = client.get_certificate(&mut rng, PHONE).unwrap();
    assert!(!chain.leaf_der.is_empty());
    assert_eq!(chain.chain_der.len(), 1, "expected exactly one issuer cert");

    // 2. SCMDSign dispatches the OTP and returns a ProcessId.
    let req = SignRequest {
        user_id: PHONE.to_string(),
        pin: "1234".to_string(),
        doc_name: "livro-de-atas.pdf".to_string(),
        hash: vec![0xAB; 32],
    };
    let handle = client.request_signature(&mut rng, &req).unwrap();
    assert_eq!(handle.process_id, PROCESS_ID);
    assert_eq!(handle.code, "200");

    // 3. ValidateOtp returns the raw RSA signature; the cert is attached from GetCertificate.
    let raw = client.confirm_otp(&mut rng, &handle, "654321").unwrap();
    assert!(matches!(raw.algorithm, SignatureAlgorithm::RsaPkcs1Sha256));
    assert_eq!(raw.signature.len(), 256, "RSA-2048 signature is 256 bytes");
    assert!(!raw.signing_cert_der.is_empty());
    assert_eq!(raw.chain_der.len(), 1);

    // Wire assertions on the SCMDSign JSON body.
    let mock = client.transport();
    let sign = body(&mock.last_envelope_for(OP_SCMD_SIGN).unwrap());

    // ApplicationId is the RAW string, never base64-encoded.
    assert_eq!(sign["ApplicationId"], Value::String(APP_ID.to_string()));
    let raw_body = mock.last_envelope_for(OP_SCMD_SIGN).unwrap();
    assert!(
        !raw_body.contains(&STANDARD.encode(APP_ID.as_bytes())),
        "the base64 of the ApplicationId must not appear on the wire"
    );

    // The `Hash` member carries the DER `DigestInfo`, not the bare digest (RFC 8017 §9.2 step 2).
    let hash_b64 = sign["Hash"].as_str().expect("Hash is a JSON string");
    let mut expected_digest_info = EXPECTED_SHA256_DIGEST_INFO_PREFIX.to_vec();
    expected_digest_info.extend_from_slice(&[0xAB; 32]);
    assert_eq!(hash_b64, STANDARD.encode(&expected_digest_info));
    assert_ne!(
        hash_b64,
        STANDARD.encode([0xAB; 32]),
        "the bare 32-byte digest must not appear on the wire"
    );

    // Preprod PIN is cleartext; the mobile is normalized (grouping spaces stripped) before it goes
    // into the encryptor, so the UserId member carries `+351912345678`, never `+351 912345678`.
    assert_eq!(sign["Pin"], Value::String("1234".to_string()));
    assert_eq!(sign["UserId"], Value::String(PHONE_NORMALIZED.to_string()));

    // ValidateOtp carries the ProcessId and `isBiometricValidation:false`.
    let otp = body(&mock.last_envelope_for(OP_VALIDATE_OTP).unwrap());
    assert_eq!(otp["ProcessId"], Value::String(PROCESS_ID.to_string()));
    assert_eq!(otp["isBiometricValidation"], Value::Bool(false));

    // GetCertificate was called twice: once by us, once inside confirm_otp.
    let get_cert_calls = mock
        .calls()
        .iter()
        .filter(|c| c.action == "GetCertificate")
        .count();
    assert_eq!(get_cert_calls, 2);
    // The GetCertificate UserId is encrypted/normalized too (cleartext passthrough here).
    let get_cert = body(
        &mock
            .last_envelope_for("GetCertificate")
            .expect("GetCertificate was called"),
    );
    assert_eq!(
        get_cert["UserId"],
        Value::String(PHONE_NORMALIZED.to_string())
    );
    assert_eq!(get_cert["ApplicationId"], Value::String(APP_ID.to_string()));
}

/// The value submitted to `SCMDSign` is the RFC 8017 §9.2 `DigestInfo`: 51 raw bytes / 68 base64
/// characters, opening with the SHA-256 prefix and closing with the digest verbatim.
///
/// This is the assertion that constrains the wire format. It decodes what the flow actually sent
/// rather than re-deriving it, so it fails if the prefix is dropped, doubled, or misencoded.
#[test]
fn scmd_sign_submits_the_der_digest_info_not_the_bare_digest() {
    let mut rng = TestRng::new();
    let client = ScmdClient::new(MockScmdTransport::preprod_success(), APP_ID);
    let digest = [0x5Au8; 32];
    client
        .request_signature(
            &mut rng,
            &SignRequest {
                user_id: PHONE.to_string(),
                pin: "1234".to_string(),
                doc_name: "livro-de-atas.pdf".to_string(),
                hash: digest.to_vec(),
            },
        )
        .unwrap();

    let sign = body(
        &client
            .transport()
            .last_envelope_for(OP_SCMD_SIGN)
            .expect("SCMDSign was called"),
    );
    let hash_b64 = sign["Hash"].as_str().expect("Hash is a JSON string");

    assert_eq!(
        hash_b64.len(),
        68,
        "51 raw bytes base64-encode to 68 characters; got {hash_b64:?}"
    );
    let submitted = STANDARD.decode(hash_b64).expect("Hash is base64");
    assert_eq!(
        submitted.len(),
        51,
        "19-byte DigestInfo prefix + 32-byte digest"
    );
    assert_eq!(
        &submitted[..19],
        &EXPECTED_SHA256_DIGEST_INFO_PREFIX,
        "submitted value must open with the RFC 8017 §9.2 SHA-256 DigestInfo prefix"
    );
    assert_eq!(
        &submitted[19..],
        &digest,
        "the digest must be carried through unaltered after the prefix"
    );
}

/// A digest that is not 32 bytes is rejected outright rather than padded, truncated, or sent as
/// is — the wire value that gets signed must never be silently reshaped.
#[test]
fn scmd_sign_rejects_a_wrong_length_digest() {
    let mut rng = TestRng::new();
    let client = ScmdClient::new(MockScmdTransport::preprod_success(), APP_ID);
    for bad in [vec![0u8; 31], vec![0u8; 33], Vec::new(), vec![0u8; 51]] {
        let len = bad.len();
        let err = client
            .request_signature(
                &mut rng,
                &SignRequest {
                    user_id: PHONE.to_string(),
                    pin: "1234".to_string(),
                    doc_name: "d.pdf".to_string(),
                    hash: bad,
                },
            )
            .unwrap_err();
        match err {
            CmdError::RequestBuild(msg) => {
                assert!(msg.contains("32-byte"), "unexpected message: {msg}");
                assert!(
                    msg.contains(&len.to_string()),
                    "message names the length: {msg}"
                );
            }
            other => panic!("expected RequestBuild for a {len}-byte digest, got {other:?}"),
        }
    }
}

#[test]
fn otp_bytes_are_never_the_signature_artifact() {
    // SIG-02: the OTP is a possession-factor confirmation, not the signature. The artifact
    // is a 256-byte qualified RSA signature, unrelated to the 6-digit OTP.
    let mut rng = TestRng::new();
    let client = ScmdClient::new(MockScmdTransport::preprod_success(), APP_ID);
    let handle = client
        .request_signature(
            &mut rng,
            &SignRequest {
                user_id: PHONE.to_string(),
                pin: "1234".to_string(),
                doc_name: "d.pdf".to_string(),
                hash: vec![1; 32],
            },
        )
        .unwrap();
    let otp = "123456";
    let raw = client.confirm_otp(&mut rng, &handle, otp).unwrap();
    assert_ne!(raw.signature.as_slice(), otp.as_bytes());
    assert!(raw.signature.len() > otp.len());
}

#[test]
fn scmd_sign_error_maps_to_service_status() {
    let mut rng = TestRng::new();
    let client = ScmdClient::new(MockScmdTransport::scmd_sign_error(), APP_ID);
    let err = client
        .request_signature(
            &mut rng,
            &SignRequest {
                user_id: PHONE.to_string(),
                pin: "0000".to_string(),
                doc_name: "d.pdf".to_string(),
                hash: vec![2; 32],
            },
        )
        .unwrap_err();
    match err {
        CmdError::ServiceStatus { code, message } => {
            assert_eq!(code, "401");
            assert!(message.contains("PIN"));
        }
        other => panic!("expected ServiceStatus, got {other:?}"),
    }
}

#[test]
fn otp_rejection_maps_to_error() {
    let mut rng = TestRng::new();
    let client = ScmdClient::new(MockScmdTransport::otp_rejected(), APP_ID);
    let handle = client
        .request_signature(
            &mut rng,
            &SignRequest {
                user_id: PHONE.to_string(),
                pin: "1234".to_string(),
                doc_name: "d.pdf".to_string(),
                hash: vec![3; 32],
            },
        )
        .unwrap();
    let err = client.confirm_otp(&mut rng, &handle, "000000").unwrap_err();
    match err {
        CmdError::OtpRejected { code, .. } => assert_eq!(code, "402"),
        other => panic!("expected OtpRejected, got {other:?}"),
    }
}

#[test]
fn get_certificate_without_a_pem_payload_is_a_parse_error() {
    // The JSON `AppSCMDService` returns no SOAP `Fault`; a request that yields no certificate PEM
    // (here `{"d":null}`) surfaces as a response-parse error, not a silent empty chain.
    let mut rng = TestRng::new();
    let client = ScmdClient::new(
        MockScmdTransport::empty().with_response("GetCertificate", r#"{"d":null}"#),
        APP_ID,
    );
    let err = client.get_certificate(&mut rng, PHONE).unwrap_err();
    assert!(matches!(err, CmdError::ResponseParse(_)), "{err:?}");
}

#[test]
fn missing_action_response_is_transport_error() {
    let mut rng = TestRng::new();
    let client = ScmdClient::new(MockScmdTransport::empty(), APP_ID);
    let err = client.get_certificate(&mut rng, PHONE).unwrap_err();
    assert!(matches!(err, CmdError::Transport(_)));
}

#[test]
fn preprod_config_is_cleartext_prod_requires_cert() {
    let preprod = CmdConfig::preprod("APPID");
    assert!(!preprod.field_encryptor().unwrap().is_encrypting());

    let prod = CmdConfig {
        env: chancela_cmd::CmdEnv::Prod,
        application_id: "APPID".to_string(),
        basic_auth: None,
        ama_cert_pem: None,
    };
    assert!(matches!(prod.field_encryptor(), Err(CmdError::Config(_))));
}
