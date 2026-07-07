//! Offline round-trip tests for the SCMD SIG-02 flow using [`MockScmdTransport`].
//!
//! These run with no network. Real preprod/prod calls live behind the `network-tests`
//! feature + `#[ignore]` (see `TESTING.md`).

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use chancela_cmd::rand_core::{CryptoRng, Error, RngCore, impls};
use chancela_cmd::soap::{ACTION_CCMOVEL_SIGN, ACTION_GET_CERTIFICATE, ACTION_VALIDATE_OTP};
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
const PHONE: &str = "+351 912345678";
const PROCESS_ID: &str = "b3f1c2a4-5d6e-4f80-9a1b-2c3d4e5f6a7b";

#[test]
fn full_request_otp_retrieve_round_trip() {
    let mut rng = TestRng::new();
    let client = ScmdClient::new(MockScmdTransport::preprod_success(), APP_ID);

    // 1. GetCertificate returns leaf + one issuer.
    let chain = client.get_certificate(PHONE).unwrap();
    assert!(!chain.leaf_der.is_empty());
    assert_eq!(chain.chain_der.len(), 1, "expected exactly one issuer cert");

    // 2. CCMovelSign dispatches the OTP and returns a ProcessId.
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

    // Wire assertions: the flow base64s the ApplicationId and threads the ProcessId + hash.
    let mock = client.transport();
    let sign_env = mock.last_envelope_for(ACTION_CCMOVEL_SIGN).unwrap();
    assert!(sign_env.contains(&STANDARD.encode(APP_ID.as_bytes())));
    assert!(sign_env.contains(&STANDARD.encode([0xAB; 32])));
    assert!(
        sign_env.contains("<d:Pin>1234</d:Pin>"),
        "preprod PIN is cleartext"
    );
    let otp_env = mock.last_envelope_for(ACTION_VALIDATE_OTP).unwrap();
    assert!(
        otp_env.contains(PROCESS_ID),
        "ProcessId must be wired into ValidateOtp"
    );
    // GetCertificate was called twice: once by us, once inside confirm_otp.
    let get_cert_calls = mock
        .calls()
        .iter()
        .filter(|c| c.action == ACTION_GET_CERTIFICATE)
        .count();
    assert_eq!(get_cert_calls, 2);
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
fn ccmovel_sign_error_maps_to_service_status() {
    let mut rng = TestRng::new();
    let client = ScmdClient::new(MockScmdTransport::ccmovel_sign_error(), APP_ID);
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
fn soap_fault_surfaces_as_error() {
    let client = ScmdClient::new(
        MockScmdTransport::empty()
            .with_response(ACTION_GET_CERTIFICATE, chancela_cmd::mock::SOAP_FAULT),
        APP_ID,
    );
    let err = client.get_certificate(PHONE).unwrap_err();
    match err {
        CmdError::SoapFault(msg) => assert!(msg.contains("ApplicationId")),
        other => panic!("expected SoapFault, got {other:?}"),
    }
}

#[test]
fn missing_action_response_is_transport_error() {
    let client = ScmdClient::new(MockScmdTransport::empty(), APP_ID);
    let err = client.get_certificate(PHONE).unwrap_err();
    assert!(matches!(err, CmdError::Transport(_)));
}

#[test]
fn preprod_config_is_cleartext_prod_requires_cert() {
    let preprod = CmdConfig::preprod("APPID");
    assert!(!preprod.field_encryptor().unwrap().is_encrypting());

    let prod = CmdConfig {
        env: chancela_cmd::CmdEnv::Prod,
        application_id: "APPID".to_string(),
        ama_cert_pem: None,
    };
    assert!(matches!(prod.field_encryptor(), Err(CmdError::Config(_))));
}
