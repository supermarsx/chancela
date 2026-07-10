//! Offline envelope-orchestration tests: serial/parallel completion, the trusted-list policy gate,
//! the SIG-02 OTP-labelling invariant, family/slot enforcement, and manual recording.
//!
//! These use the shape-only [`MockProvider`] and a [`StaticTrustPolicy`], so they need no real
//! crypto keys (`assemble_cades_b` only *parses* the signer certificate). The cryptographic
//! round-trip lives in `tests/roundtrip.rs`.

use time::OffsetDateTime;

use chancela_cmd::{MockScmdTransport, ScmdClient};
use chancela_signing::provider::OTP_STEP_LEVEL;
use chancela_signing::{
    BaselineProfile, CmdProvider, DocumentInput, EvidentiaryLevel, MockProvider, SignOptions,
    SignatureArtifact, SignatureEnvelope, SignatureFormat, SignatureRequest, SignerCapacity,
    SignerProvider, SigningError, SigningFamily, SigningJob, SigningOrder, StaticTrustPolicy,
    TrustedListStatus, is_complete, pending_slots, record_manual_signature, sign_slot,
    validate_signature,
};

fn fixed_time() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_750_000_000).unwrap()
}

fn request(
    family: SigningFamily,
    format: SignatureFormat,
    profile: BaselineProfile,
) -> SignatureRequest {
    SignatureRequest {
        family,
        format,
        profile,
        capacity: SignerCapacity::Manager,
        document_digest: [7u8; 32],
    }
}

fn cades_job<'a>(
    provider: &'a dyn SignerProvider,
    policy: Option<&'a mut dyn chancela_signing::TrustPolicy>,
    digest: &'a [u8; 32],
) -> SigningJob<'a> {
    SigningJob {
        provider,
        policy,
        tsa: None,
        input: DocumentInput::Digest(digest),
        signing_time: fixed_time(),
        pdf_options: SignOptions::default(),
    }
}

#[test]
fn parallel_envelope_completes_in_any_order() {
    let provider = MockProvider::deterministic_rsa(SigningFamily::CartaoDeCidadao);
    let digest = [1u8; 32];
    let mut env = SignatureEnvelope::new(
        SigningOrder::Parallel,
        vec![
            request(
                SigningFamily::CartaoDeCidadao,
                SignatureFormat::CAdES,
                BaselineProfile::B_B,
            ),
            request(
                SigningFamily::CartaoDeCidadao,
                SignatureFormat::CAdES,
                BaselineProfile::B_B,
            ),
        ],
    );

    // Parallel: both slots are pending, and they may be signed in any order.
    assert_eq!(pending_slots(&env), vec![0, 1]);
    sign_slot(&mut env, 1, cades_job(&provider, None, &digest)).unwrap();
    assert_eq!(pending_slots(&env), vec![0]);
    assert!(!is_complete(&env));
    sign_slot(&mut env, 0, cades_job(&provider, None, &digest)).unwrap();

    assert!(is_complete(&env));
    assert_eq!(env.artifacts.len(), 2);
    // Each artifact records the slot it filled (completion order was 1 then 0).
    assert_eq!(env.artifact_for(0).unwrap().slot, 0);
    assert_eq!(env.artifact_for(1).unwrap().slot, 1);
    assert!(
        !env.artifacts[0].signature.is_empty(),
        "CMS bytes were recorded"
    );
}

#[test]
fn serial_envelope_enforces_order() {
    let provider = MockProvider::deterministic_rsa(SigningFamily::CartaoDeCidadao);
    let digest = [2u8; 32];
    let mut env = SignatureEnvelope::new(
        SigningOrder::Serial,
        vec![
            request(
                SigningFamily::CartaoDeCidadao,
                SignatureFormat::CAdES,
                BaselineProfile::B_B,
            ),
            request(
                SigningFamily::CartaoDeCidadao,
                SignatureFormat::CAdES,
                BaselineProfile::B_B,
            ),
        ],
    );

    // Serial: only slot 0 is pending; signing slot 1 first is rejected.
    assert_eq!(pending_slots(&env), vec![0]);
    let err = sign_slot(&mut env, 1, cades_job(&provider, None, &digest)).unwrap_err();
    assert_eq!(
        err,
        SigningError::SlotOrder {
            expected: 0,
            got: 1
        }
    );

    sign_slot(&mut env, 0, cades_job(&provider, None, &digest)).unwrap();
    assert_eq!(pending_slots(&env), vec![1]);
    sign_slot(&mut env, 1, cades_job(&provider, None, &digest)).unwrap();
    assert!(is_complete(&env));
}

#[test]
fn already_signed_and_out_of_range_slots_are_rejected() {
    let provider = MockProvider::deterministic_rsa(SigningFamily::CartaoDeCidadao);
    let digest = [3u8; 32];
    let mut env = SignatureEnvelope::new(
        SigningOrder::Parallel,
        vec![request(
            SigningFamily::CartaoDeCidadao,
            SignatureFormat::CAdES,
            BaselineProfile::B_B,
        )],
    );
    sign_slot(&mut env, 0, cades_job(&provider, None, &digest)).unwrap();
    assert_eq!(
        sign_slot(&mut env, 0, cades_job(&provider, None, &digest)).unwrap_err(),
        SigningError::SlotAlreadySigned(0)
    );
    assert_eq!(
        sign_slot(&mut env, 5, cades_job(&provider, None, &digest)).unwrap_err(),
        SigningError::SlotOutOfRange { slot: 5, len: 1 }
    );
}

#[test]
fn withdrawn_trusted_list_status_is_refused() {
    let provider = MockProvider::deterministic_rsa(SigningFamily::QualifiedCertificate);
    let digest = [4u8; 32];
    let mut env = SignatureEnvelope::new(
        SigningOrder::Parallel,
        vec![request(
            SigningFamily::QualifiedCertificate,
            SignatureFormat::CAdES,
            BaselineProfile::B_B,
        )],
    );

    // A withdrawn issuer is rejected before any artifact is produced (SIG-11/23).
    let mut withdrawn = StaticTrustPolicy::withdrawn();
    let err = sign_slot(
        &mut env,
        0,
        cades_job(&provider, Some(&mut withdrawn), &digest),
    )
    .unwrap_err();
    assert_eq!(
        err,
        SigningError::UntrustedService {
            status: TrustedListStatus::Withdrawn
        }
    );
    assert!(env.artifacts.is_empty(), "no artifact on refusal");

    // A granted issuer signs and the status is recorded on the artifact.
    let mut granted = StaticTrustPolicy::granted();
    sign_slot(
        &mut env,
        0,
        cades_job(&provider, Some(&mut granted), &digest),
    )
    .unwrap();
    assert_eq!(
        env.artifacts[0].trusted_list_status,
        Some(TrustedListStatus::Granted)
    );
    assert!(env.artifacts[0].is_qualified());
}

#[test]
fn unknown_trusted_list_status_is_refused() {
    let provider = MockProvider::deterministic_rsa(SigningFamily::CartaoDeCidadao);
    let digest = [5u8; 32];
    let mut env = SignatureEnvelope::new(
        SigningOrder::Parallel,
        vec![request(
            SigningFamily::CartaoDeCidadao,
            SignatureFormat::CAdES,
            BaselineProfile::B_B,
        )],
    );
    let mut unknown = StaticTrustPolicy::new(TrustedListStatus::Unknown);
    let err = sign_slot(
        &mut env,
        0,
        cades_job(&provider, Some(&mut unknown), &digest),
    )
    .unwrap_err();
    assert_eq!(
        err,
        SigningError::UntrustedService {
            status: TrustedListStatus::Unknown
        }
    );
}

#[test]
fn policy_without_issuer_certificate_errors() {
    // A qualified provider that presents no issuer (like a smartcard) cannot pass a trust gate.
    let provider =
        MockProvider::deterministic_rsa(SigningFamily::CartaoDeCidadao).with_issuer(None);
    let digest = [6u8; 32];
    let mut env = SignatureEnvelope::new(
        SigningOrder::Parallel,
        vec![request(
            SigningFamily::CartaoDeCidadao,
            SignatureFormat::CAdES,
            BaselineProfile::B_B,
        )],
    );
    let mut granted = StaticTrustPolicy::granted();
    assert_eq!(
        sign_slot(
            &mut env,
            0,
            cades_job(&provider, Some(&mut granted), &digest)
        )
        .unwrap_err(),
        SigningError::MissingIssuerCertificate
    );
    // With no policy configured, the same provider signs fine (trust resolved out-of-band).
    sign_slot(&mut env, 0, cades_job(&provider, None, &digest)).unwrap();
    assert!(is_complete(&env));
}

#[test]
fn provider_family_must_match_the_request() {
    let provider = MockProvider::deterministic_rsa(SigningFamily::CartaoDeCidadao);
    let digest = [8u8; 32];
    let mut env = SignatureEnvelope::new(
        SigningOrder::Parallel,
        vec![request(
            SigningFamily::ChaveMovelDigital,
            SignatureFormat::CAdES,
            BaselineProfile::B_B,
        )],
    );
    assert_eq!(
        sign_slot(&mut env, 0, cades_job(&provider, None, &digest)).unwrap_err(),
        SigningError::FamilyMismatch {
            requested: SigningFamily::ChaveMovelDigital,
            provided: SigningFamily::CartaoDeCidadao,
        }
    );
}

#[test]
fn provider_failure_surfaces() {
    let provider =
        MockProvider::deterministic_rsa(SigningFamily::CartaoDeCidadao).failing("card removed");
    let digest = [9u8; 32];
    let mut env = SignatureEnvelope::new(
        SigningOrder::Parallel,
        vec![request(
            SigningFamily::CartaoDeCidadao,
            SignatureFormat::CAdES,
            BaselineProfile::B_B,
        )],
    );
    let err = sign_slot(&mut env, 0, cades_job(&provider, None, &digest)).unwrap_err();
    assert!(matches!(err, SigningError::Provider(msg) if msg.contains("card removed")));
}

#[test]
fn manual_slot_records_a_scan_and_is_labelled_handwritten() {
    let mut env = SignatureEnvelope::new(
        SigningOrder::Parallel,
        vec![request(
            SigningFamily::Manual,
            SignatureFormat::PAdES,
            BaselineProfile::B_B,
        )],
    );
    // A Manual slot must not go through the cryptographic signing path.
    let provider = MockProvider::deterministic_rsa(SigningFamily::CartaoDeCidadao);
    let digest = [10u8; 32];
    assert_eq!(
        sign_slot(&mut env, 0, cades_job(&provider, None, &digest)).unwrap_err(),
        SigningError::WrongSigningPath {
            family: SigningFamily::Manual
        }
    );

    // Recording the scan yields a HandwrittenScanned artifact (SIG-03), not a qualified one.
    record_manual_signature(
        &mut env,
        0,
        b"scanned-signature-page".to_vec(),
        fixed_time(),
    )
    .unwrap();
    let art = &env.artifacts[0];
    assert_eq!(art.evidentiary_level, EvidentiaryLevel::HandwrittenScanned);
    assert!(!art.is_qualified());
    assert_eq!(art.signature, b"scanned-signature-page");
    assert!(is_complete(&env));
}

#[test]
fn manual_recording_rejects_a_qualified_slot() {
    let mut env = SignatureEnvelope::new(
        SigningOrder::Parallel,
        vec![request(
            SigningFamily::CartaoDeCidadao,
            SignatureFormat::PAdES,
            BaselineProfile::B_B,
        )],
    );
    assert_eq!(
        record_manual_signature(&mut env, 0, b"scan".to_vec(), fixed_time()).unwrap_err(),
        SigningError::WrongSigningPath {
            family: SigningFamily::CartaoDeCidadao
        }
    );
}

#[test]
fn cmd_otp_is_a_confirmation_step_never_the_signature() {
    // SIG-02: the OTP is the possession-factor confirmation inside the qualified flow; the produced
    // artifact is the qualified signature, and no provider ever reports OtpConfirmation.
    assert_eq!(OTP_STEP_LEVEL, EvidentiaryLevel::OtpConfirmation);
    assert!(!OTP_STEP_LEVEL.is_qualified_signature());

    let client = ScmdClient::new(MockScmdTransport::preprod_success(), "chancela-app-id");
    let otp_calls = std::cell::Cell::new(0);
    let provider = CmdProvider::new(client, "+351 912345678", "1234", "Ata 1/2026", |_handle| {
        otp_calls.set(otp_calls.get() + 1);
        Ok("123456".to_string())
    });
    // The provider itself is labelled Qualified, never OtpConfirmation.
    assert_eq!(provider.evidentiary_level(), EvidentiaryLevel::Qualified);

    let digest = [11u8; 32];
    let mut env = SignatureEnvelope::new(
        SigningOrder::Parallel,
        vec![request(
            SigningFamily::ChaveMovelDigital,
            SignatureFormat::CAdES,
            BaselineProfile::B_B,
        )],
    );
    sign_slot(&mut env, 0, cades_job(&provider, None, &digest)).unwrap();

    assert_eq!(otp_calls.get(), 1, "the OTP was confirmed exactly once");
    let art = &env.artifacts[0];
    assert_eq!(art.evidentiary_level, EvidentiaryLevel::Qualified);
    assert_ne!(art.evidentiary_level, EvidentiaryLevel::OtpConfirmation);
    assert!(art.is_qualified());
    assert!(!art.signature.is_empty());
}

#[test]
fn xades_signing_remains_explicitly_unsupported() {
    let provider = MockProvider::deterministic_rsa(SigningFamily::CartaoDeCidadao);
    let digest = [12u8; 32];

    let mut env = SignatureEnvelope::new(
        SigningOrder::Parallel,
        vec![request(
            SigningFamily::CartaoDeCidadao,
            SignatureFormat::XAdES,
            BaselineProfile::B_B,
        )],
    );
    assert_eq!(
        sign_slot(&mut env, 0, cades_job(&provider, None, &digest)).unwrap_err(),
        SigningError::UnsupportedFormat(SignatureFormat::XAdES)
    );
    assert!(
        env.artifacts.is_empty(),
        "XAdES must not produce an artifact"
    );
}

#[test]
fn asic_signing_requires_payload_bytes() {
    let provider = MockProvider::deterministic_rsa(SigningFamily::CartaoDeCidadao);
    let digest = [12u8; 32];
    let mut env = SignatureEnvelope::new(
        SigningOrder::Parallel,
        vec![request(
            SigningFamily::CartaoDeCidadao,
            SignatureFormat::ASiC,
            BaselineProfile::B_B,
        )],
    );

    assert_eq!(
        sign_slot(&mut env, 0, cades_job(&provider, None, &digest)).unwrap_err(),
        SigningError::FormatInputMismatch {
            format: SignatureFormat::ASiC
        }
    );
    assert!(
        env.artifacts.is_empty(),
        "ASiC must not package only a bare digest"
    );
}

#[test]
fn xades_validation_remains_explicitly_unsupported() {
    let artifact = SignatureArtifact {
        id: uuid::Uuid::nil(),
        slot: 0,
        family: SigningFamily::CartaoDeCidadao,
        format: SignatureFormat::XAdES,
        profile: BaselineProfile::B_B,
        evidentiary_level: EvidentiaryLevel::Qualified,
        signed_at: Some(fixed_time()),
        signature: b"recognized-but-unavailable".to_vec(),
        trusted_list_status: None,
        timestamp_token_der: None,
    };

    assert_eq!(
        validate_signature(&artifact, Some(&[0u8; 32])).unwrap_err(),
        SigningError::UnsupportedFormat(SignatureFormat::XAdES)
    );
}

#[test]
fn asic_validation_reports_container_errors() {
    let artifact = SignatureArtifact {
        id: uuid::Uuid::nil(),
        slot: 0,
        family: SigningFamily::CartaoDeCidadao,
        format: SignatureFormat::ASiC,
        profile: BaselineProfile::B_B,
        evidentiary_level: EvidentiaryLevel::Qualified,
        signed_at: Some(fixed_time()),
        signature: b"not a zip".to_vec(),
        trusted_list_status: None,
        timestamp_token_der: None,
    };

    let err = validate_signature(&artifact, None).unwrap_err();
    assert!(matches!(err, SigningError::Asic(msg) if msg.contains("ZIP")));
}

#[test]
fn input_mismatch_is_reported_for_supported_formats() {
    let provider = MockProvider::deterministic_rsa(SigningFamily::CartaoDeCidadao);
    let digest = [12u8; 32];

    // A PAdES request fed a bare digest (instead of PDF bytes) is an input mismatch.
    let mut pades = SignatureEnvelope::new(
        SigningOrder::Parallel,
        vec![request(
            SigningFamily::CartaoDeCidadao,
            SignatureFormat::PAdES,
            BaselineProfile::B_B,
        )],
    );
    assert_eq!(
        sign_slot(&mut pades, 0, cades_job(&provider, None, &digest)).unwrap_err(),
        SigningError::FormatInputMismatch {
            format: SignatureFormat::PAdES
        }
    );
}
