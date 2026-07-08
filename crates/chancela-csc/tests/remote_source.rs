//! t59 Slice 2 — [`CscRemoteSource`] satisfies the frozen
//! [`chancela_signing::RemoteSigningSource`] contract, proven end to end, offline.
//!
//! The proofs mirror `chancela-signing/tests/remote_source.rs`, but drive a **CSC** provider over
//! [`MockCscTransport`]:
//!
//! 1. A full round-trip through the trait object — `prepare_signature` → `initiate` → (persist the
//!    secret-free session) → `confirm` → `embed_signature` → `validate_pdf_signature` — with a
//!    **cryptographically real** RSA signature produced over the exact digest the client sends, so
//!    the embedded PDF validates.
//! 2. The trusted-list gate fails closed for a withdrawn issuer (no artifact, no OTP dispatched).
//! 3. The session carries no secret (no PIN/OTP/SAD/token in JSON or Debug).
//! 4. The OTP two-phase: `credentials/sendOTP` fires at initiate; a rejected OTP at confirm yields
//!    no artifact.
//!
//! No network, no private keys checked in. Fictional "Encosto Estratégico Lda" / "Amélia Marques".

mod common;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use zeroize::Zeroizing;

use chancela_cades::signed_attributes_digest;
use chancela_csc::mock::{
    ERROR_INVALID_OTP, MockCscTransport, credentials_info_response, sign_hash_response,
};
use chancela_csc::rest::{OID_RSA_ENCRYPTION, PATH_CREDENTIALS_SEND_OTP};
use chancela_csc::{CscClient, CscRemoteSource};
use chancela_pades::{prepare_signature, validate_pdf_signature};
use chancela_signing::{
    EvidentiaryLevel, RemoteInitiate, RemoteSignSession, RemoteSigningSource, SigningError,
    SigningFamily, StaticTrustPolicy, TrustedListStatus, embed_signature,
};

use common::{CREDENTIAL_ID, OTP, PIN, RsaSigner, USER_REF};

fn sign_opts() -> chancela_pades::SignOptions {
    chancela_pades::SignOptions {
        field_name: Some("Assinatura".into()),
        signing_time: Some("D:20250615142640Z".into()),
        reason: Some("Ata aprovada em assembleia".into()),
        location: Some("Lisboa".into()),
        contact_info: None,
    }
}

/// Build a happy-path CSC source whose signHash returns a REAL signature over the digest that this
/// exact `prepared` + signer + signing time imply — so the produced CMS validates cryptographically.
fn happy_source(
    signer: &RsaSigner,
    issuer: &RsaSigner,
    prepared: &chancela_pades::PreparedSignature,
) -> CscRemoteSource<MockCscTransport> {
    // The confirm path signs the CAdES signed-attributes digest over the prepared ByteRange digest.
    let signed_attrs = signed_attributes_digest(
        prepared.byterange_digest(),
        &signer.cert_der(),
        common::fixed_time(),
    )
    .expect("signed attrs");
    let sig = signer.sign_digest(&signed_attrs);

    let info = credentials_info_response(
        &[signer.cert_der_b64(), issuer.cert_der_b64()],
        &[OID_RSA_ENCRYPTION],
    );
    let transport = MockCscTransport::happy_path(info, sign_hash_response(&STANDARD.encode(&sig)));
    let client = CscClient::new(transport, common::test_config(), common::test_secrets());
    CscRemoteSource::new(client)
}

/// PROOF 1 — the CSC source round-trips the whole two-phase pipeline through the trait object,
/// producing a PDF that validates; and the persisted session is secret-free.
#[test]
fn csc_remote_source_round_trips_prepare_initiate_confirm_embed_validate() {
    let signer = RsaSigner::new("Amélia Marques (QTSP teste)", 1);
    let issuer = RsaSigner::new("Encosto Estratégico Lda — EC Teste", 2);
    let pdf = common::base_pdf();
    let prepared = prepare_signature(&pdf, &sign_opts()).expect("prepare");

    let source = happy_source(&signer, &issuer, &prepared);
    // Drive it purely through the object-safe trait, as the api will (`dyn RemoteSigningSource`).
    let source: &dyn RemoteSigningSource = &source;

    assert_eq!(source.family(), SigningFamily::QualifiedCertificate);
    assert!(source.evidentiary_level().is_qualified_signature());
    assert_eq!(source.evidentiary_level(), EvidentiaryLevel::Qualified);

    // Phase 1: initiate (with the trusted-list gate).
    let mut policy = StaticTrustPolicy::granted();
    let pin = Zeroizing::new(PIN.to_string());
    let session = source
        .initiate(
            &RemoteInitiate {
                user_ref: USER_REF,
                credential: &pin,
                doc_name: "livro-de-atas.pdf",
                signing_time: common::fixed_time(),
            },
            &prepared,
            Some(&mut policy),
        )
        .expect("initiate");

    assert_eq!(session.provider_id, common::PROVIDER_ID);
    assert_eq!(session.provider_ref, CREDENTIAL_ID);
    assert_eq!(session.user_ref, USER_REF);
    assert_eq!(
        session.trusted_list_status,
        Some(TrustedListStatus::Granted)
    );
    assert_eq!(&session.byterange_digest, prepared.byterange_digest());
    assert_eq!(session.signing_cert_der, signer.cert_der());

    // The persisted session is secret-free: no PIN, OTP, SAD, or access token.
    let persisted = serde_json::to_string(&session).expect("session serializes");
    for secret in [
        PIN,
        OTP,
        "SAD-encosto-preprod",
        "csc-preprod-access-token-0001",
    ] {
        assert!(
            !persisted.contains(secret),
            "secret '{secret}' must never be in the session JSON"
        );
    }
    assert!(
        !format!("{session:?}").contains(PIN),
        "PIN must not leak via Debug"
    );
    let session: RemoteSignSession =
        serde_json::from_str(&persisted).expect("session deserializes");

    // Phase 2: confirm with the OTP activation → CMS → embed → validate.
    let activation = Zeroizing::new(OTP.to_string());
    let cms = source.confirm(&session, &activation).expect("confirm");
    let signed_pdf = embed_signature(&prepared, &cms).expect("embed");

    let report = validate_pdf_signature(&signed_pdf).expect("signature must validate");
    assert!(report.covers_whole_file_except_contents);
    assert_eq!(report.cades.signer_cert_der, session.signing_cert_der);
    assert!(report.cades.signing_certificate_v2_present);
    assert_eq!(
        report.cades.signing_time.map(|t| t.unix_timestamp()),
        Some(1_750_000_000)
    );
}

/// PROOF 2 — the trusted-list gate fails closed for a withdrawn issuer: no artifact, and the OTP
/// was never dispatched (the gate runs before `credentials/sendOTP`).
#[test]
fn csc_remote_source_rejects_untrusted_issuer_before_dispatching_otp() {
    let signer = RsaSigner::new("Amélia Marques (QTSP teste)", 1);
    let issuer = RsaSigner::new("Encosto Estratégico Lda — EC Teste", 2);
    let pdf = common::base_pdf();
    let prepared = prepare_signature(&pdf, &sign_opts()).expect("prepare");
    let source = happy_source(&signer, &issuer, &prepared);

    let mut policy = StaticTrustPolicy::withdrawn();
    let pin = Zeroizing::new(PIN.to_string());
    let err = source
        .initiate(
            &RemoteInitiate {
                user_ref: USER_REF,
                credential: &pin,
                doc_name: "d.pdf",
                signing_time: common::fixed_time(),
            },
            &prepared,
            Some(&mut policy),
        )
        .expect_err("withdrawn issuer must be rejected");
    assert!(matches!(
        err,
        SigningError::UntrustedService {
            status: TrustedListStatus::Withdrawn
        }
    ));
    // No OTP was dispatched — the gate is fail-closed and runs before any activation.
    let dispatched = source
        .client()
        .transport()
        .calls()
        .iter()
        .any(|c| c.path == PATH_CREDENTIALS_SEND_OTP);
    assert!(
        !dispatched,
        "OTP must not be dispatched for an untrusted issuer"
    );
}

/// PROOF 3 — the OTP two-phase: initiate dispatches the OTP; a rejected OTP at confirm yields no
/// artifact (the SIG-02 confirmation failed).
#[test]
fn csc_remote_source_otp_two_phase_dispatch_then_reject() {
    let signer = RsaSigner::new("Amélia Marques (QTSP teste)", 1);
    let issuer = RsaSigner::new("Encosto Estratégico Lda — EC Teste", 2);
    let pdf = common::base_pdf();
    let prepared = prepare_signature(&pdf, &sign_opts()).expect("prepare");

    // A source whose authorize call rejects the OTP.
    let info = credentials_info_response(
        &[signer.cert_der_b64(), issuer.cert_der_b64()],
        &[OID_RSA_ENCRYPTION],
    );
    let transport = MockCscTransport::happy_path(info, sign_hash_response("AA==")).with_response(
        chancela_csc::rest::PATH_CREDENTIALS_AUTHORIZE,
        ERROR_INVALID_OTP,
    );
    let source = CscRemoteSource::new(CscClient::new(
        transport,
        common::test_config(),
        common::test_secrets(),
    ));

    let mut policy = StaticTrustPolicy::granted();
    let pin = Zeroizing::new(PIN.to_string());
    let session = source
        .initiate(
            &RemoteInitiate {
                user_ref: USER_REF,
                credential: &pin,
                doc_name: "d.pdf",
                signing_time: common::fixed_time(),
            },
            &prepared,
            Some(&mut policy),
        )
        .expect("initiate");

    // Phase 1 dispatched the OTP.
    let dispatched = source
        .client()
        .transport()
        .calls()
        .iter()
        .any(|c| c.path == PATH_CREDENTIALS_SEND_OTP);
    assert!(
        dispatched,
        "initiate must dispatch the OTP (credentials/sendOTP)"
    );

    // Phase 2 with a bad OTP → provider error, no CMS.
    let err = source
        .confirm(&session, &Zeroizing::new("000000".to_string()))
        .expect_err("a rejected OTP must not produce a signature");
    assert!(matches!(err, SigningError::Provider(_)));
}
