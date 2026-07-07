//! Offline behaviour of the smartcard layer, driven entirely by `MockToken`
//! and the fake-free reader path. No card reader or middleware is required —
//! these run in CI on all three OS (plan §3 / §6).

use chancela_cades::SignatureAlgorithm;
use chancela_smartcard::{
    CertUsage, CryptoToken, MockToken, SmartcardError, TokenCertificate, detect,
    select_authentication_certificate, select_signature_certificate,
    token::{LABEL_AUTH_CERT, LABEL_SIGNATURE_CERT},
};

const DIGEST: [u8; 32] = [0x5A; 32];

#[test]
fn v1_card_lists_signature_and_auth_certs() {
    let token = MockToken::cartao_de_cidadao_v1();
    let certs = token.list_certificates().unwrap();
    assert_eq!(certs.len(), 2);
    assert!(
        certs
            .iter()
            .all(|c| c.algorithm == SignatureAlgorithm::RsaPkcs1Sha256)
    );
}

#[test]
fn selects_signature_cert_by_label_not_index() {
    // Auth cert first, signature cert second: selection must be label-driven.
    let token = MockToken::cartao_de_cidadao_v2();
    let certs = token.list_certificates().unwrap();

    let sig = select_signature_certificate(&certs).expect("signature cert present");
    assert_eq!(sig.label, LABEL_SIGNATURE_CERT);
    assert_eq!(sig.usage(), CertUsage::QualifiedSignature);

    let auth = select_authentication_certificate(&certs).expect("auth cert present");
    assert_eq!(auth.label, LABEL_AUTH_CERT);
    assert_eq!(auth.usage(), CertUsage::Authentication);
}

#[test]
fn v1_signs_with_rsa_pkcs1() {
    let token = MockToken::cartao_de_cidadao_v1();
    let certs = token.list_certificates().unwrap();
    let cert = select_signature_certificate(&certs).unwrap();

    let sig = token.sign_digest(cert, &DIGEST).unwrap();
    assert_eq!(sig.algorithm, SignatureAlgorithm::RsaPkcs1Sha256);
    assert_eq!(sig.signature.len(), 256, "RSA-2048 signature width");
    assert_eq!(sig.signing_cert_der, cert.cert_der);
    assert!(sig.chain_der.is_empty());
}

#[test]
fn v2_signs_with_ecdsa_der() {
    let token = MockToken::cartao_de_cidadao_v2();
    let certs = token.list_certificates().unwrap();
    let cert = select_signature_certificate(&certs).unwrap();

    let sig = token.sign_digest(cert, &DIGEST).unwrap();
    assert_eq!(sig.algorithm, SignatureAlgorithm::EcdsaP256Sha256);
    // The ECDSA value must be DER SEQUENCE { INTEGER, INTEGER }, not raw r‖s.
    assert_eq!(sig.signature.first(), Some(&0x30));
    assert_ne!(
        sig.signature.len(),
        64,
        "must be DER-wrapped, not raw P1363"
    );
}

#[test]
fn signing_is_deterministic_per_digest() {
    let token = MockToken::cartao_de_cidadao_v1();
    let certs = token.list_certificates().unwrap();
    let cert = select_signature_certificate(&certs).unwrap();
    let a = token.sign_digest(cert, &DIGEST).unwrap();
    let b = token.sign_digest(cert, &DIGEST).unwrap();
    assert_eq!(a.signature, b.signature);

    let other = token.sign_digest(cert, &[0x01; 32]).unwrap();
    assert_ne!(a.signature, other.signature, "different digests differ");
}

#[test]
fn unactivated_signature_key_fails_but_auth_works() {
    let token = MockToken::cartao_de_cidadao_v2().without_signature_activation();
    let certs = token.list_certificates().unwrap();

    let sig_cert = select_signature_certificate(&certs).unwrap();
    let err = token.sign_digest(sig_cert, &DIGEST).unwrap_err();
    assert!(matches!(err, SmartcardError::Pkcs11(_)));

    // Authentication cert still signs (it is not the qualified-signature key).
    let auth_cert = select_authentication_certificate(&certs).unwrap();
    assert!(token.sign_digest(auth_cert, &DIGEST).is_ok());
}

#[test]
fn signing_unknown_cert_is_not_found() {
    let token = MockToken::cartao_de_cidadao_v1();
    let ghost = TokenCertificate {
        label: "NOT ON CARD".to_owned(),
        cert_der: vec![0x30, 0x00],
        algorithm: SignatureAlgorithm::RsaPkcs1Sha256,
    };
    let err = token.sign_digest(&ghost, &DIGEST).unwrap_err();
    assert!(matches!(err, SmartcardError::CertificateNotFound(_)));
}

#[test]
fn empty_card_has_no_signature_cert() {
    let token = MockToken::with_certificates(Vec::new());
    let certs = token.list_certificates().unwrap();
    assert!(select_signature_certificate(&certs).is_none());
}

#[test]
fn reader_detect_never_panics() {
    // Acceptance (plan §3, e9 smoke): whether the box has zero readers, a real
    // reader, or no PC/SC service, detect() returns a Result and never panics.
    match detect() {
        Ok(readers) => {
            // Any list (including empty) is acceptable.
            for r in &readers {
                assert!(!r.name.is_empty());
            }
        }
        Err(SmartcardError::PcscUnavailable(_) | SmartcardError::Pcsc(_)) => {}
        Err(other) => panic!("unexpected error kind from detect(): {other}"),
    }
}
