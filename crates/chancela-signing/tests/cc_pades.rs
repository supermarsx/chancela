//! t58 Slice 1 — the **Cartão de Cidadão → PAdES** binding, end to end, offline.
//!
//! Proves the frozen CC seam [`chancela_signing::sign_pdf_cc`]: trusted-list gate (SIG-11/23) →
//! `prepare_signature` (compute the `/ByteRange` digest) → the card's `sign_digest` (PKCS#11) →
//! assemble CAdES-B → `embed_signature` → `validate_pdf_signature`. Both card generations are
//! exercised: CC v1 (RSA-2048, `CKM_RSA_PKCS`) and CC v2 (P-256, `CKM_ECDSA` re-encoded to DER).
//!
//! CC is synchronous (no OTP, no session) so — unlike the CMD two-phase test — a single call does
//! everything. To make the signature *cryptographically* valid, the in-test card
//! ([`CcTestCard`]) is backed by a **real ephemeral key** (RSA-2048 / P-256) whose self-signed
//! certificate it exposes as the citizen SIGNATURE certificate; the produced signature therefore
//! verifies. No private keys are checked in (plan §6). This is a test stand-in for card hardware,
//! not a fabricated "valid" real-card signature: the checked-in `MockToken` remains shape-only and
//! is used here only for the cert-selection and un-activated-signature *negative* paths.
//!
//! Fixtures use the fictional "Encosto Estratégico Lda" / "Amélia Marques" — never a real entity.
//! No live PKCS#11, PC/SC, or reader hardware is touched (all offline, t58 gate).

use std::str::FromStr;
use std::time::Duration as StdDuration;

use der::Encode;
use der::asn1::{Any, BitString, ObjectIdentifier};
use sha2::{Digest, Sha256};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use time::OffsetDateTime;
use x509_cert::certificate::{Certificate, TbsCertificate, Version};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;

use chancela_cades::{
    RawSignature, SignatureAlgorithm, assemble_cades_b, signed_attributes_digest,
};
use chancela_pades::{SignOptions, embed_signature, prepare_signature, validate_pdf_signature};
use chancela_signing::{
    SignerProvider, SigningError, SmartcardProvider, StaticTrustPolicy, TrustedListStatus,
    sign_pdf_cc,
};
use chancela_smartcard::token::{LABEL_AUTH_CERT, LABEL_SIGNATURE_CERT};
use chancela_smartcard::{
    CertUsage, CryptoToken, MockToken, SmartcardError, TokenCertificate,
    select_authentication_certificate, select_signature_certificate,
};

const OID_SHA256_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const OID_ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

/// DER `DigestInfo` prefix for SHA-256 (RFC 8017 §9.2).
const SHA256_DIGEST_INFO_PREFIX: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

/// 2025-06-15T14:26:40Z — whole seconds, inside the CAdES UTCTime window.
fn fixed_time() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_750_000_000).unwrap()
}

// --- An in-test, key-backed CryptoToken standing in for a Cartão de Cidadão -----------------------

/// A hardware-free [`CryptoToken`] backed by real ephemeral keys, standing in for a citizen card.
///
/// It exposes two certificates under the real card CKA_LABELs — a qualified **signature**
/// certificate and an **authentication** certificate, on *distinct* keys — so the provider's
/// label-based selection (never the auth cert, SIG-02) is provable by certificate identity, and the
/// produced signature is cryptographically valid against the signature certificate.
struct CcTestCard {
    /// The qualified-signature private key — RSA-2048 (CC v1) or P-256 (CC v2).
    signature_key: SignerKey,
    signature_cert_der: Vec<u8>,
    auth_cert_der: Vec<u8>,
    /// A separate issuing-CA certificate supplied out-of-band for the TSL gate (the card exposes
    /// only the leaf, so `SmartcardProvider::with_issuer_certificate` carries this).
    issuer_cert_der: Vec<u8>,
    /// The PIN presented to the most recent `sign_digest_with_pin` call, recorded so the seam test
    /// can prove the in-app PIN reaches the card (t67). Interior-mutable because `CryptoToken` signs
    /// through `&self`.
    recorded_pin: std::sync::Mutex<Option<String>>,
}

enum SignerKey {
    Rsa(Box<rsa::RsaPrivateKey>),
    Ecdsa(Box<p256::ecdsa::SigningKey>),
}

impl CcTestCard {
    /// A CC **v1** card: RSA-2048 signature key + distinct RSA authentication cert.
    fn cc_v1() -> Self {
        let signature = EphemeralSigner::new_rsa("Amélia Marques (assinatura)", 1);
        let auth = EphemeralSigner::new_rsa("Amélia Marques (autenticação)", 2);
        let issuer = EphemeralSigner::new_rsa("Encosto Estratégico Lda — EC Teste", 3);
        Self {
            signature_cert_der: signature.cert_der.clone(),
            auth_cert_der: auth.cert_der,
            issuer_cert_der: issuer.cert_der,
            signature_key: signature.key,
            recorded_pin: std::sync::Mutex::new(None),
        }
    }

    /// A CC **v2** card (June 2024+): P-256 signature key + distinct P-256 authentication cert.
    fn cc_v2() -> Self {
        let signature = EphemeralSigner::new_ecdsa("Amélia Marques (assinatura)", 1);
        let auth = EphemeralSigner::new_ecdsa("Amélia Marques (autenticação)", 2);
        let issuer = EphemeralSigner::new_ecdsa("Encosto Estratégico Lda — EC Teste", 3);
        Self {
            signature_cert_der: signature.cert_der.clone(),
            auth_cert_der: auth.cert_der,
            issuer_cert_der: issuer.cert_der,
            signature_key: signature.key,
            recorded_pin: std::sync::Mutex::new(None),
        }
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        match self.signature_key {
            SignerKey::Rsa(_) => SignatureAlgorithm::RsaPkcs1Sha256,
            SignerKey::Ecdsa(_) => SignatureAlgorithm::EcdsaP256Sha256,
        }
    }

    /// The PIN the card last received (test helper).
    fn last_pin(&self) -> Option<String> {
        self.recorded_pin.lock().unwrap().clone()
    }
}

impl CryptoToken for CcTestCard {
    fn list_certificates(&self) -> Result<Vec<TokenCertificate>, SmartcardError> {
        Ok(vec![
            // The card may reorder objects; selection is by label, so list the auth cert FIRST to
            // prove the signature cert is chosen by usage, not position.
            TokenCertificate {
                label: LABEL_AUTH_CERT.to_owned(),
                cert_der: self.auth_cert_der.clone(),
                algorithm: self.algorithm(),
            },
            TokenCertificate {
                label: LABEL_SIGNATURE_CERT.to_owned(),
                cert_der: self.signature_cert_der.clone(),
                algorithm: self.algorithm(),
            },
        ])
    }

    fn sign_digest(
        &self,
        cert: &TokenCertificate,
        digest: &[u8; 32],
    ) -> Result<RawSignature, SmartcardError> {
        // The qualified signature key must only ever sign under the SIGNATURE certificate (SIG-02).
        assert_eq!(
            cert.usage(),
            CertUsage::QualifiedSignature,
            "the card must only be asked to sign with the qualified-signature certificate"
        );
        let signature = match &self.signature_key {
            SignerKey::Rsa(key) => sign_rsa_digest_info(key, digest),
            SignerKey::Ecdsa(key) => {
                use p256::ecdsa::signature::hazmat::PrehashSigner;
                let sig: p256::ecdsa::Signature =
                    key.sign_prehash(digest).expect("ecdsa prehash sign");
                sig.to_der().as_bytes().to_vec()
            }
        };
        Ok(RawSignature::new(
            self.algorithm(),
            signature,
            cert.cert_der.clone(),
            Vec::new(),
        ))
    }

    fn sign_digest_with_pin(
        &self,
        cert: &TokenCertificate,
        digest: &[u8; 32],
        pin: Option<&str>,
    ) -> Result<RawSignature, SmartcardError> {
        // Record the presented PIN so the seam test can prove the in-app PIN reached the card,
        // then sign exactly as the protected-auth path would (the key-backed signature is
        // independent of how login was authenticated).
        *self.recorded_pin.lock().unwrap() = pin.map(str::to_owned);
        self.sign_digest(cert, digest)
    }
}

/// A freshly-minted ephemeral key + self-signed certificate.
struct EphemeralSigner {
    key: SignerKey,
    cert_der: Vec<u8>,
}

impl EphemeralSigner {
    fn new_rsa(cn: &str, serial: u8) -> Self {
        use rsa::rand_core::OsRng;
        let key = rsa::RsaPrivateKey::new(&mut OsRng, 2048).expect("rsa keygen");
        let spki =
            SubjectPublicKeyInfoOwned::from_key(rsa::RsaPublicKey::from(&key)).expect("rsa spki");
        let sig_alg = AlgorithmIdentifierOwned {
            oid: OID_SHA256_WITH_RSA,
            parameters: Some(Any::null()),
        };
        let signer = key.clone();
        let cert_der = build_self_signed(cn, serial, spki, sig_alg, |tbs| {
            sign_rsa_digest_info(&signer, &Sha256::digest(tbs).into())
        });
        Self {
            key: SignerKey::Rsa(Box::new(key)),
            cert_der,
        }
    }

    fn new_ecdsa(cn: &str, serial: u8) -> Self {
        use p256::ecdsa::SigningKey;
        use p256::ecdsa::signature::Signer;
        use rsa::rand_core::OsRng;
        let key = SigningKey::random(&mut OsRng);
        let spki = SubjectPublicKeyInfoOwned::from_key(*key.verifying_key()).expect("ec spki");
        let sig_alg = AlgorithmIdentifierOwned {
            oid: OID_ECDSA_WITH_SHA256,
            parameters: None,
        };
        let signer = key.clone();
        let cert_der = build_self_signed(cn, serial, spki, sig_alg, |tbs| {
            let sig: p256::ecdsa::Signature = signer.sign(tbs);
            sig.to_der().as_bytes().to_vec()
        });
        Self {
            key: SignerKey::Ecdsa(Box::new(key)),
            cert_der,
        }
    }
}

fn sign_rsa_digest_info(key: &rsa::RsaPrivateKey, digest: &[u8; 32]) -> Vec<u8> {
    let mut digest_info = SHA256_DIGEST_INFO_PREFIX.to_vec();
    digest_info.extend_from_slice(digest);
    key.sign(rsa::Pkcs1v15Sign::new_unprefixed(), &digest_info)
        .expect("rsa sign")
}

fn build_self_signed(
    cn: &str,
    serial: u8,
    spki: SubjectPublicKeyInfoOwned,
    sig_alg: AlgorithmIdentifierOwned,
    sign: impl Fn(&[u8]) -> Vec<u8>,
) -> Vec<u8> {
    let name = Name::from_str(&format!("CN={cn}")).expect("name");
    let validity = Validity::from_now(StdDuration::from_secs(365 * 24 * 3600)).expect("validity");
    let tbs = TbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::new(&[serial]).expect("serial"),
        signature: sig_alg.clone(),
        issuer: name.clone(),
        validity,
        subject: name,
        subject_public_key_info: spki,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: None,
    };
    let tbs_der = tbs.to_der().expect("tbs der");
    let signature = sign(&tbs_der);
    let cert = Certificate {
        tbs_certificate: tbs,
        signature_algorithm: sig_alg,
        signature: BitString::from_bytes(&signature).expect("bitstring"),
    };
    cert.to_der().expect("cert der")
}

// --- Minimal base PDF (classic cross-reference table, mirrors chancela-pades tests) ---------------

fn assemble_pdf(objects: &[(u32, &str)], root: u32) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"%PDF-1.7\n%\xE2\xE3\xCF\xD3\n");
    let mut offsets = Vec::new();
    for (id, body) in objects {
        offsets.push((*id, buf.len()));
        buf.extend_from_slice(format!("{id} 0 obj\n{body}\nendobj\n").as_bytes());
    }
    let xref_off = buf.len();
    let max_id = objects.iter().map(|(id, _)| *id).max().unwrap();
    buf.extend_from_slice(format!("xref\n0 {}\n", max_id + 1).as_bytes());
    buf.extend_from_slice(b"0000000000 65535 f\r\n");
    for id in 1..=max_id {
        let off = offsets
            .iter()
            .find(|(i, _)| *i == id)
            .map(|(_, o)| *o)
            .unwrap();
        buf.extend_from_slice(format!("{off:010} 00000 n\r\n").as_bytes());
    }
    buf.extend_from_slice(
        format!("trailer\n<< /Size {} /Root {root} 0 R >>\n", max_id + 1).as_bytes(),
    );
    buf.extend_from_slice(format!("startxref\n{xref_off}\n%%EOF\n").as_bytes());
    buf
}

fn base_pdf() -> Vec<u8> {
    assemble_pdf(
        &[
            (1, "<< /Type /Catalog /Pages 2 0 R >>"),
            (2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"),
            (
                3,
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << >> >>",
            ),
        ],
        1,
    )
}

fn sign_opts() -> SignOptions {
    SignOptions {
        field_name: Some("Assinatura".into()),
        signing_time: Some("D:20250615142640Z".into()),
        reason: Some("Ata aprovada em assembleia".into()),
        location: Some("Lisboa".into()),
        contact_info: None,
    }
}

// --- The proofs -----------------------------------------------------------------------------------

/// The whole-seam round trip, per card generation: `sign_pdf_cc` gates the issuer, drives the card,
/// and returns a signed PDF that validates cryptographically.
fn cc_seam_round_trip(card: CcTestCard) {
    let signature_cert_der = card.signature_cert_der.clone();
    let auth_cert_der = card.auth_cert_der.clone();
    let issuer_cert_der = card.issuer_cert_der.clone();
    let pdf = base_pdf();

    let provider =
        SmartcardProvider::new(card).with_issuer_certificate(Some(issuer_cert_der.clone()));
    let mut policy = StaticTrustPolicy::granted();

    let outcome = sign_pdf_cc(
        &provider,
        &pdf,
        fixed_time(),
        &sign_opts(),
        Some(&mut policy),
    )
    .expect("CC signature");

    // Trusted-list gate resolved and passed (SIG-11/23).
    assert_eq!(
        outcome.trusted_list_status,
        Some(TrustedListStatus::Granted)
    );
    // The qualified-SIGNATURE certificate was the signer — never the authentication certificate.
    assert_eq!(
        outcome.signing_cert_der, signature_cert_der,
        "the signer is the qualified-signature certificate"
    );
    assert_ne!(
        outcome.signing_cert_der, auth_cert_der,
        "the authentication certificate is never used to sign (SIG-02)"
    );

    // The original PDF is an untouched prefix (incremental update).
    assert_eq!(
        &outcome.signed_pdf[..pdf.len()],
        &pdf[..],
        "incremental update leaves the original bytes intact"
    );

    // The signature validates cryptographically over the ByteRange (SIG-24), and the embedded
    // signer certificate is the card's signature leaf.
    let report = validate_pdf_signature(&outcome.signed_pdf).expect("signature must validate");
    assert!(
        report.covers_whole_file_except_contents,
        "ByteRange covers the whole file except /Contents"
    );
    assert_eq!(
        report.total_len,
        outcome.signed_pdf.len(),
        "validation ran over the whole signed file"
    );
    assert_eq!(
        report.cades.signer_cert_der, signature_cert_der,
        "validated signer cert is the card's signature leaf"
    );
    assert!(
        report.cades.signing_certificate_v2_present,
        "CAdES-B signing-certificate-v2 present"
    );
    assert_eq!(
        report.cades.signing_time.map(|t| t.unix_timestamp()),
        Some(1_750_000_000),
        "authoritative signing time carried in the signed attributes"
    );
    assert!(
        !report.has_signature_timestamp,
        "B-B — no signature timestamp"
    );
}

#[test]
fn cc_v1_rsa_seam_round_trip() {
    cc_seam_round_trip(CcTestCard::cc_v1());
}

#[test]
fn cc_v2_p256_seam_round_trip() {
    cc_seam_round_trip(CcTestCard::cc_v2());
}

/// The explicit F5 path `prepare_signature → card sign_digest → assemble CAdES-B → embed_signature
/// → validate_pdf_signature`, driving a smartcard provider through the reusable prepare/embed seam
/// (t57-S2). This is the same composition `sign_pdf_cc` performs internally, spelled out.
#[test]
fn cc_prepare_sign_embed_validate_explicit() {
    let card = CcTestCard::cc_v1();
    let signature_cert_der = card.signature_cert_der.clone();
    let provider = SmartcardProvider::new(card);
    let pdf = base_pdf();
    let signing_time = fixed_time();

    // Phase 1: prepare — compute the ByteRange digest to sign, reserving the placeholder.
    let prepared = prepare_signature(&pdf, &sign_opts()).expect("prepare");

    // The card signs the CAdES signed-attributes digest over the prepared ByteRange digest.
    let cert_der = provider.signing_certificate_der().expect("signature cert");
    let signed_attrs =
        signed_attributes_digest(prepared.byterange_digest(), &cert_der, signing_time)
            .expect("signed-attrs digest");
    let raw = provider
        .sign_signed_attributes(&signed_attrs)
        .expect("card sign_digest");
    let cms = assemble_cades_b(&raw, prepared.byterange_digest(), signing_time).expect("cades-b");

    // Phase 2: embed the CMS into the reserved placeholder, then validate.
    let signed_pdf = embed_signature(&prepared, &cms).expect("embed");
    let report = validate_pdf_signature(&signed_pdf).expect("validate");
    assert!(report.covers_whole_file_except_contents);
    assert_eq!(report.cades.signer_cert_der, signature_cert_der);
}

/// The TSL gate rejects a non-granted issuer before the card is ever asked to sign (no PIN prompt).
#[test]
fn tsl_gate_rejects_untrusted_issuer() {
    let card = CcTestCard::cc_v1();
    let issuer_cert_der = card.issuer_cert_der.clone();
    let provider = SmartcardProvider::new(card).with_issuer_certificate(Some(issuer_cert_der));
    let mut policy = StaticTrustPolicy::withdrawn();

    let err = sign_pdf_cc(
        &provider,
        &base_pdf(),
        fixed_time(),
        &sign_opts(),
        Some(&mut policy),
    )
    .expect_err("a withdrawn issuer must be rejected");

    match err {
        SigningError::UntrustedService { status } => {
            assert_eq!(status, TrustedListStatus::Withdrawn);
        }
        other => panic!("expected UntrustedService, got {other:?}"),
    }
}

/// With a policy configured, a card that presents no out-of-band issuer certificate fails closed —
/// the qualified trust check must never be silently skipped (SIG-11/23).
#[test]
fn tsl_gate_fails_closed_without_issuer() {
    // No `.with_issuer_certificate(...)` — the card exposes only the leaf.
    let provider = SmartcardProvider::new(CcTestCard::cc_v1());
    let mut policy = StaticTrustPolicy::granted();

    let err = sign_pdf_cc(
        &provider,
        &base_pdf(),
        fixed_time(),
        &sign_opts(),
        Some(&mut policy),
    )
    .expect_err("a configured policy with no issuer must fail closed");

    assert!(
        matches!(err, SigningError::MissingIssuerCertificate),
        "got {err:?}"
    );
}

/// The provider selects the qualified-signature certificate by label, and never the authentication
/// certificate — proven on the checked-in shape-only `MockToken` (no key needed for selection).
#[test]
fn signature_certificate_is_selected_never_authentication() {
    let certs = MockToken::cartao_de_cidadao_v1()
        .list_certificates()
        .unwrap();
    let selected = select_signature_certificate(&certs).expect("a signature cert is present");
    assert_eq!(selected.usage(), CertUsage::QualifiedSignature);

    let provider = SmartcardProvider::new(MockToken::cartao_de_cidadao_v1());
    assert_eq!(
        provider.signing_certificate_der().unwrap(),
        selected.cert_der,
        "the provider signs with the qualified-signature certificate"
    );

    // A card exposing ONLY the authentication certificate has no signable certificate — the auth
    // cert is never a fallback (SIG-02).
    let auth = select_authentication_certificate(&certs)
        .expect("an auth cert is present")
        .clone();
    let auth_only = SmartcardProvider::new(MockToken::with_certificates(vec![auth]));
    assert!(
        matches!(
            auth_only.signing_certificate_der(),
            Err(SigningError::Provider(_))
        ),
        "no qualified-signature certificate ⇒ Provider error, never the auth cert"
    );
}

/// A card whose qualified signature was never activated fails cleanly at sign time, producing no
/// artifact (the middleware/card refuses; `chancela-smartcard`'s shape-only `MockToken` mirrors it).
#[test]
fn unactivated_signature_fails_cleanly() {
    let token = MockToken::cartao_de_cidadao_v1().without_signature_activation();
    // A dummy issuer + granted policy so the gate passes and the failure is isolated to signing.
    let provider = SmartcardProvider::new(token).with_issuer_certificate(Some(vec![0u8; 4]));
    let mut policy = StaticTrustPolicy::granted();

    let err = sign_pdf_cc(
        &provider,
        &base_pdf(),
        fixed_time(),
        &sign_opts(),
        Some(&mut policy),
    )
    .expect_err("an un-activated qualified signature must fail");

    match err {
        SigningError::Provider(msg) => {
            assert!(msg.contains("not activated"), "got {msg}");
        }
        other => panic!("expected Provider error, got {other:?}"),
    }
}

// --- t67: in-app CC PIN threading ----------------------------------------------------------------

/// The in-app PIN is threaded end-to-end through `sign_pdf_cc_with_pin`: it reaches the card, and
/// the produced signature still validates cryptographically over the ByteRange (SIG-24).
#[test]
fn cc_in_app_pin_is_threaded_to_the_card_and_validates() {
    use chancela_signing::cc::sign_pdf_cc_with_pin;
    use zeroize::Zeroizing;

    let card = CcTestCard::cc_v1();
    let signature_cert_der = card.signature_cert_der.clone();
    let issuer_cert_der = card.issuer_cert_der.clone();
    let provider = SmartcardProvider::new(card).with_issuer_certificate(Some(issuer_cert_der));
    let mut policy = StaticTrustPolicy::granted();
    let pin = Zeroizing::new("1234".to_owned());

    let outcome = sign_pdf_cc_with_pin(
        &provider,
        &base_pdf(),
        fixed_time(),
        &sign_opts(),
        Some(&mut policy),
        Some(&pin),
    )
    .expect("CC signature with in-app PIN");

    assert_eq!(
        provider.token().last_pin().as_deref(),
        Some("1234"),
        "the in-app PIN reached the card's login"
    );
    let report = validate_pdf_signature(&outcome.signed_pdf).expect("signature must validate");
    assert_eq!(report.cades.signer_cert_der, signature_cert_der);
}

/// A `None` PIN (the default `sign_pdf_cc` seam) preserves the protected-authentication path — no
/// PIN is presented to the card.
#[test]
fn cc_none_pin_preserves_protected_auth_path() {
    let card = CcTestCard::cc_v1();
    let issuer_cert_der = card.issuer_cert_der.clone();
    let provider = SmartcardProvider::new(card).with_issuer_certificate(Some(issuer_cert_der));
    let mut policy = StaticTrustPolicy::granted();

    let outcome = sign_pdf_cc(
        &provider,
        &base_pdf(),
        fixed_time(),
        &sign_opts(),
        Some(&mut policy),
    )
    .expect("CC signature, protected-auth path");

    assert_eq!(
        provider.token().last_pin(),
        None,
        "no PIN is presented on the protected-authentication path"
    );
    validate_pdf_signature(&outcome.signed_pdf).expect("signature must validate");
}

/// `SmartcardProvider` forwards the PIN to the token unchanged (proven on the shape-only
/// `MockToken`, which records the exact value), and `None` presents no PIN.
#[test]
fn provider_forwards_pin_to_token() {
    use zeroize::Zeroizing;

    let provider = SmartcardProvider::new(MockToken::cartao_de_cidadao_v1());
    let digest = [0x11u8; 32];

    let pin = Zeroizing::new("4321".to_owned());
    provider
        .sign_signed_attributes_with_pin(&digest, Some(&pin))
        .expect("sign with pin");
    assert!(provider.token().last_login_used_pin());
    assert!(provider.token().last_login_pin_was("4321"));

    // The no-PIN entry point presents no PIN (protected-auth path).
    provider
        .sign_signed_attributes(&digest)
        .expect("sign without pin");
    assert!(!provider.token().last_login_used_pin());
}

/// A wrong PIN surfaces through the provider as `SigningError::Provider` whose message names the PIN
/// failure but **never echoes any PIN value** (plan §6).
#[test]
fn wrong_pin_surfaces_through_provider_without_leaking_the_pin() {
    use zeroize::Zeroizing;

    let token = MockToken::cartao_de_cidadao_v1()
        .requiring_pin("1234", chancela_smartcard::PinTriesLeft::FinalTry);
    let provider = SmartcardProvider::new(token);
    let entered = Zeroizing::new("0000".to_owned());

    let err = provider
        .sign_signed_attributes_with_pin(&[0x22u8; 32], Some(&entered))
        .expect_err("a wrong PIN must fail");

    match err {
        SigningError::Provider(msg) => {
            assert!(
                !msg.contains("0000") && !msg.contains("1234"),
                "no PIN value may appear in the error: {msg}"
            );
            assert!(
                msg.to_ascii_lowercase().contains("pin"),
                "the message names the PIN failure: {msg}"
            );
        }
        other => panic!("expected Provider error, got {other:?}"),
    }
}

/// The transient PIN wrapper wipes its buffer on drop — the `Zeroizing` custody the whole in-app-PIN
/// path relies on (drop-flag pattern; the production PIN is held in exactly this `Zeroizing`).
#[test]
fn zeroizing_pin_is_wiped_on_drop() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use zeroize::{Zeroize, Zeroizing};

    static WIPED: AtomicBool = AtomicBool::new(false);
    struct PinLike;
    impl Zeroize for PinLike {
        fn zeroize(&mut self) {
            WIPED.store(true, Ordering::SeqCst);
        }
    }

    {
        let _guard = Zeroizing::new(PinLike);
        assert!(!WIPED.load(Ordering::SeqCst), "not wiped while still alive");
    }
    assert!(
        WIPED.load(Ordering::SeqCst),
        "Zeroizing wipes the PIN when it goes out of scope"
    );
}
