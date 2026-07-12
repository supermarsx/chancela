//! t67-e6 — batch document signing under a single authentication, end to end, offline.
//!
//! Proves [`chancela_signing::sign_pdf_batch`] / [`chancela_signing::sign_detached_cades_batch`]:
//!
//! - **One session, one PIN.** A batch reuses ONE [`SignerProvider`] (asserted via a
//!   [`CountingProvider`] that counts signing invocations) and, with an in-app PIN, replays that one
//!   PIN to every document's context-specific login → honest [`AuthMode::SingleAuth`].
//! - **Honest per-document auth.** With no in-app PIN the Cartão de Cidadão protected-authentication
//!   path (its signature key is `CKA_ALWAYS_AUTHENTICATE`, prompting per operation) is reported as
//!   [`AuthMode::PerDocumentAuth`] — never falsely single-PIN (plan decision 3, §6).
//! - **No abort on failure.** One deliberately malformed document fails on its own; the rest sign.
//! - **PIN custody.** The transient in-app PIN is owned by the batch as a [`Zeroizing`] and never
//!   appears in the report (plan §6).
//! - **Per-document seals.** Each document carries its own [`SealAppearance`] (t67-e3), applied
//!   independently within one batch.
//!
//! The batch cannot emit a *cryptographically valid* signature from the checked-in shape-only mock,
//! so — like `tests/cc_pades.rs` — the in-test card ([`KeyCard`]) is backed by a **real ephemeral
//! RSA key** whose self-signed certificate it exposes as the citizen SIGNATURE certificate; the
//! produced signatures therefore verify through the batch's own `validate_pdf_signature` gate. No
//! private keys are checked in (plan §6). Fixtures use the fictional "Amélia Marques" — never a real
//! person. No live PKCS#11/PC-SC/reader hardware is touched.

use std::str::FromStr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration as StdDuration;

use chancela_cades::{assemble_cades_b, signed_attributes_digest};
use der::Encode;
use der::asn1::{Any, BitString, ObjectIdentifier};
use sha2::{Digest, Sha256};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use time::OffsetDateTime;
use x509_cert::certificate::{Certificate, TbsCertificate, Version};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;
use zeroize::Zeroizing;

use chancela_pades::validate_pdf_signature;
use chancela_signing::{
    AuthMode, BatchCadesDocument, BatchPdfDocument, EvidentiaryLevel, MockProvider, RawSignature,
    RemoteBatchAuthMode, RemoteBatchConfirmDocument, RemoteBatchPdfDocument, RemoteInitiate,
    RemoteSignSession, RemoteSigningSource, SealAppearance, SealContent, SealPlacement,
    SignOptions, SignatureAlgorithm, SignerProvider, SigningError, SigningFamily,
    SmartcardProvider, StaticTrustPolicy, TextSeal, TrustPolicy, TrustedListStatus,
    confirm_remote_pdf_batch_repeated_sessions, initiate_remote_pdf_batch_repeated_sessions,
    sign_detached_cades_batch, sign_pdf_batch,
};
use chancela_smartcard::token::LABEL_SIGNATURE_CERT;
use chancela_smartcard::{CryptoToken, SmartcardError, TokenCertificate};

const OID_SHA256_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");

/// DER `DigestInfo` prefix for SHA-256 (RFC 8017 §9.2).
const SHA256_DIGEST_INFO_PREFIX: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

const PHONE: &str = "+351 912345678";
const PIN: &str = "2468";
const OTP: &str = "135790";

/// 2026-07-11T00:00:00Z — a fixed, whole-second batch signing time.
fn fixed_time() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_752_192_000).unwrap()
}

// --- An in-test, RSA-key-backed CryptoToken standing in for a Cartão de Cidadão -------------------

/// A hardware-free [`CryptoToken`] backed by a real ephemeral RSA-2048 key, exposing it under the
/// citizen SIGNATURE label so the produced signatures are cryptographically valid, and recording the
/// PIN presented to the most recent login so the batch's PIN replay is provable.
struct KeyCard {
    signature_key: Box<rsa::RsaPrivateKey>,
    signature_cert_der: Vec<u8>,
    /// The PIN presented to the most recent `sign_digest_with_pin` (interior-mutable — `CryptoToken`
    /// signs through `&self`).
    recorded_pin: Mutex<Option<String>>,
}

impl KeyCard {
    fn new() -> Self {
        let signer = EphemeralRsaSigner::new("Amélia Marques (assinatura)", 1);
        Self {
            signature_key: Box::new(signer.key),
            signature_cert_der: signer.cert_der,
            recorded_pin: Mutex::new(None),
        }
    }

    fn last_pin(&self) -> Option<String> {
        self.recorded_pin.lock().unwrap().clone()
    }
}

impl CryptoToken for KeyCard {
    fn list_certificates(&self) -> Result<Vec<TokenCertificate>, SmartcardError> {
        Ok(vec![TokenCertificate {
            label: LABEL_SIGNATURE_CERT.to_owned(),
            cert_der: self.signature_cert_der.clone(),
            algorithm: SignatureAlgorithm::RsaPkcs1Sha256,
        }])
    }

    fn sign_digest(
        &self,
        cert: &TokenCertificate,
        digest: &[u8; 32],
    ) -> Result<RawSignature, SmartcardError> {
        let signature = sign_rsa_digest_info(&self.signature_key, digest);
        Ok(RawSignature::new(
            SignatureAlgorithm::RsaPkcs1Sha256,
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
        *self.recorded_pin.lock().unwrap() = pin.map(str::to_owned);
        self.sign_digest(cert, digest)
    }
}

/// A [`SignerProvider`] decorator that counts signing invocations (proving one session is reused)
/// and records how many of them presented an in-app PIN (proving the single PIN was replayed).
struct CountingProvider<'a> {
    inner: &'a dyn SignerProvider,
    calls: AtomicUsize,
    calls_with_pin: AtomicUsize,
}

/// A [`RemoteSigningSource`] test double that can only open one-digest sessions. It records every
/// initiate digest and confirm reference so the repeated-session helper cannot hide a multi-hash
/// provider batch behind one call.
struct CountingRemoteSource {
    provider_id: String,
    signer: EphemeralRsaSigner,
    issuer: EphemeralRsaSigner,
    expected_activation: String,
    fail_initiate_doc_names: Vec<String>,
    initiate_digests: Mutex<Vec<[u8; 32]>>,
    confirm_refs: Mutex<Vec<String>>,
}

impl CountingRemoteSource {
    fn new() -> Self {
        Self {
            provider_id: "encosto-remote-test".to_owned(),
            signer: EphemeralRsaSigner::new("Amélia Marques (remote batch)", 11),
            issuer: EphemeralRsaSigner::new("Encosto Estratégico Lda EC", 12),
            expected_activation: OTP.to_owned(),
            fail_initiate_doc_names: Vec::new(),
            initiate_digests: Mutex::new(Vec::new()),
            confirm_refs: Mutex::new(Vec::new()),
        }
    }

    fn failing_initiate_for(doc_names: &[&str]) -> Self {
        let mut source = Self::new();
        source.fail_initiate_doc_names = doc_names.iter().map(|name| (*name).to_owned()).collect();
        source
    }

    fn initiate_digests(&self) -> Vec<[u8; 32]> {
        self.initiate_digests.lock().unwrap().clone()
    }

    fn confirm_refs(&self) -> Vec<String> {
        self.confirm_refs.lock().unwrap().clone()
    }
}

impl RemoteSigningSource for CountingRemoteSource {
    fn family(&self) -> SigningFamily {
        SigningFamily::QualifiedCertificate
    }

    fn evidentiary_level(&self) -> EvidentiaryLevel {
        EvidentiaryLevel::Qualified
    }

    fn initiate(
        &self,
        req: &RemoteInitiate<'_>,
        prepared: &chancela_signing::PreparedSignature,
        policy: Option<&mut dyn TrustPolicy>,
    ) -> Result<RemoteSignSession, SigningError> {
        let issuer_der = self.issuer.cert_der.clone();
        let trusted_list_status = match policy {
            Some(policy) => {
                let status = policy.issuer_status(&issuer_der, req.signing_time)?;
                if status != TrustedListStatus::Granted {
                    return Err(SigningError::UntrustedService { status });
                }
                Some(status)
            }
            None => None,
        };
        if self
            .fail_initiate_doc_names
            .iter()
            .any(|name| name == req.doc_name)
        {
            return Err(SigningError::Provider(format!(
                "initiate rejected {}",
                req.doc_name
            )));
        }
        let mut digests = self.initiate_digests.lock().unwrap();
        digests.push(*prepared.byterange_digest());
        let ordinal = digests.len();
        Ok(RemoteSignSession {
            provider_id: self.provider_id.clone(),
            provider_ref: format!("remote-session-{ordinal}-{}", req.doc_name),
            user_ref: req.user_ref.to_owned(),
            signing_cert_der: self.signer.cert_der.clone(),
            chain_der: vec![issuer_der],
            trusted_list_status,
            byterange_digest: *prepared.byterange_digest(),
            signing_time: req.signing_time,
        })
    }

    fn confirm(
        &self,
        session: &RemoteSignSession,
        activation: &Zeroizing<String>,
    ) -> Result<Vec<u8>, SigningError> {
        self.confirm_refs
            .lock()
            .unwrap()
            .push(session.provider_ref.clone());
        if activation.as_str() != self.expected_activation {
            return Err(SigningError::Provider("activation rejected".to_owned()));
        }
        let signed_attrs_digest = signed_attributes_digest(
            &session.byterange_digest,
            &session.signing_cert_der,
            session.signing_time,
        )
        .map_err(|e| SigningError::Cades(e.to_string()))?;
        let raw = RawSignature::new(
            SignatureAlgorithm::RsaPkcs1Sha256,
            self.signer.sign_digest(&signed_attrs_digest),
            session.signing_cert_der.clone(),
            session.chain_der.clone(),
        );
        assemble_cades_b(&raw, &session.byterange_digest, session.signing_time)
            .map_err(|e| SigningError::Cades(e.to_string()))
    }
}

impl<'a> CountingProvider<'a> {
    fn new(inner: &'a dyn SignerProvider) -> Self {
        Self {
            inner,
            calls: AtomicUsize::new(0),
            calls_with_pin: AtomicUsize::new(0),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::Relaxed)
    }

    fn calls_with_pin(&self) -> usize {
        self.calls_with_pin.load(Ordering::Relaxed)
    }
}

impl SignerProvider for CountingProvider<'_> {
    fn family(&self) -> SigningFamily {
        self.inner.family()
    }

    fn evidentiary_level(&self) -> EvidentiaryLevel {
        self.inner.evidentiary_level()
    }

    fn signing_certificate_der(&self) -> Result<Vec<u8>, SigningError> {
        self.inner.signing_certificate_der()
    }

    fn issuer_certificate_der(&self) -> Result<Option<Vec<u8>>, SigningError> {
        self.inner.issuer_certificate_der()
    }

    fn sign_signed_attributes(
        &self,
        signed_attrs_digest: &[u8; 32],
    ) -> Result<RawSignature, SigningError> {
        self.sign_signed_attributes_with_pin(signed_attrs_digest, None)
    }

    fn sign_signed_attributes_with_pin(
        &self,
        signed_attrs_digest: &[u8; 32],
        pin: Option<&Zeroizing<String>>,
    ) -> Result<RawSignature, SigningError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        if pin.is_some() {
            self.calls_with_pin.fetch_add(1, Ordering::Relaxed);
        }
        self.inner
            .sign_signed_attributes_with_pin(signed_attrs_digest, pin)
    }
}

/// A freshly-minted ephemeral RSA key + self-signed certificate.
struct EphemeralRsaSigner {
    key: rsa::RsaPrivateKey,
    cert_der: Vec<u8>,
}

impl EphemeralRsaSigner {
    fn new(cn: &str, serial: u8) -> Self {
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
        Self { key, cert_der }
    }

    fn sign_digest(&self, digest: &[u8; 32]) -> Vec<u8> {
        sign_rsa_digest_info(&self.key, digest)
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

fn marked_pdf(marker: &str) -> Vec<u8> {
    let marker_object = format!("<< /ChancelaTestMarker ({marker}) >>");
    assemble_pdf(
        &[
            (1, "<< /Type /Catalog /Pages 2 0 R >>"),
            (2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"),
            (
                3,
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << >> >>",
            ),
            (4, &marker_object),
        ],
        1,
    )
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn comma_joined_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// A visible text seal at a given page/position (fixed size), for the per-document seal proofs.
fn text_seal(page: usize, x: f32, y: f32) -> SealAppearance {
    SealAppearance {
        placement: SealPlacement {
            page,
            x,
            y,
            w: 180.0,
            h: 54.0,
        },
        content: SealContent::Text(TextSeal::name_date("Amélia Marques", "2026-07-11")),
    }
}

fn pdf_doc<'a>(
    id: &str,
    pdf: &'a [u8],
    appearance: Option<SealAppearance>,
) -> BatchPdfDocument<'a> {
    BatchPdfDocument {
        id: id.to_owned(),
        pdf,
        options: SignOptions::default(),
        appearance,
    }
}

fn remote_pdf_doc<'a>(id: &str, pdf: &'a [u8]) -> RemoteBatchPdfDocument<'a> {
    RemoteBatchPdfDocument {
        id: id.to_owned(),
        pdf,
        options: SignOptions::default(),
        appearance: None,
        doc_name: format!("{id}.pdf"),
    }
}

/// A key-backed CC provider with a dummy out-of-band issuer so the granted TSL gate passes.
fn cc_provider(card: KeyCard) -> SmartcardProvider<KeyCard> {
    SmartcardProvider::new(card).with_issuer_certificate(Some(vec![0u8; 4]))
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

// --- The proofs -----------------------------------------------------------------------------------

/// One session, one in-app PIN: the batch reuses a single provider and replays the one PIN to every
/// document's login, so a batch of N is honestly `SingleAuth` and every signature validates.
#[test]
fn batch_single_session_replays_one_in_app_pin_as_single_auth() {
    let pdf = base_pdf();
    let provider = cc_provider(KeyCard::new());
    let counting = CountingProvider::new(&provider);
    let docs = [
        pdf_doc("act-1", &pdf, None),
        pdf_doc("act-2", &pdf, None),
        pdf_doc("act-3", &pdf, None),
    ];
    let mut policy = StaticTrustPolicy::granted();

    let report = sign_pdf_batch(
        &counting,
        &docs,
        fixed_time(),
        Some(&mut policy),
        Some(Zeroizing::new("1234".to_owned())),
    );

    assert!(report.all_ok(), "every document signs");
    assert_eq!(report.ok_count(), 3);
    assert_eq!(
        report.auth_mode,
        AuthMode::SingleAuth,
        "one in-app PIN covered the batch"
    );
    assert_eq!(report.auth_events, 3, "three signing invocations");
    assert_eq!(report.trusted_list_status, Some(TrustedListStatus::Granted));

    // ONE provider/session was reused for all three documents, and the single in-app PIN was
    // replayed to each context-specific login.
    assert_eq!(
        counting.calls(),
        3,
        "one session, one signing call per document"
    );
    assert_eq!(
        counting.calls_with_pin(),
        3,
        "the in-app PIN was replayed to every login"
    );
    assert_eq!(
        provider.token().last_pin().as_deref(),
        Some("1234"),
        "the in-app PIN reached the card"
    );

    // Each produced PDF validates cryptographically (SIG-24), independently of the batch's own gate.
    for outcome in &report.results {
        let signed = outcome.result.as_ref().expect("signed pdf");
        validate_pdf_signature(signed).expect("signature validates");
    }
}

/// No in-app PIN: the Cartão de Cidadão protected-authentication path prompts per operation
/// (`CKA_ALWAYS_AUTHENTICATE`), so the batch is honestly `PerDocumentAuth` and presents no PIN.
#[test]
fn batch_without_in_app_pin_is_honestly_per_document_auth() {
    let pdf = base_pdf();
    let provider = cc_provider(KeyCard::new());
    let counting = CountingProvider::new(&provider);
    let docs = [pdf_doc("act-1", &pdf, None), pdf_doc("act-2", &pdf, None)];
    let mut policy = StaticTrustPolicy::granted();

    let report = sign_pdf_batch(&counting, &docs, fixed_time(), Some(&mut policy), None);

    assert!(report.all_ok());
    assert_eq!(
        report.auth_mode,
        AuthMode::PerDocumentAuth,
        "protected-auth with CKA_ALWAYS_AUTHENTICATE is per-document — never falsely single-PIN"
    );
    assert_eq!(report.auth_events, 2);
    assert_eq!(counting.calls(), 2, "one session, two signing calls");
    assert_eq!(counting.calls_with_pin(), 0, "no in-app PIN was presented");
    assert_eq!(
        provider.token().last_pin(),
        None,
        "the protected-authentication path presents no PIN to the card"
    );
}

/// One malformed document fails on its own; the rest of the batch still signs (no abort). The
/// malformed document fails before the card is contacted, so it is not an authentication event.
#[test]
fn one_failing_document_does_not_abort_the_batch() {
    let good = base_pdf();
    let broken = b"%PDF-1.7 this is not a real pdf".to_vec();
    let provider = cc_provider(KeyCard::new());
    let docs = [
        pdf_doc("ok-first", &good, None),
        pdf_doc("broken", &broken, None),
        pdf_doc("ok-last", &good, None),
    ];
    let mut policy = StaticTrustPolicy::granted();

    let report = sign_pdf_batch(
        &provider,
        &docs,
        fixed_time(),
        Some(&mut policy),
        Some(Zeroizing::new("1234".to_owned())),
    );

    assert!(!report.all_ok());
    assert_eq!(report.ok_count(), 2, "the two valid documents still sign");
    assert_eq!(report.failed_count(), 1);
    assert_eq!(
        report.auth_events, 2,
        "only the two documents that reached the card"
    );

    assert!(
        report.results[0].result.is_ok(),
        "first good document signed"
    );
    assert_eq!(report.results[1].id, "broken");
    assert!(
        matches!(report.results[1].result, Err(SigningError::Pades(_))),
        "the malformed document reports its own PAdES error: {:?}",
        report.results[1].result
    );
    assert!(
        report.results[2].result.is_ok(),
        "later document still signed after the failure"
    );
}

/// Each document carries its own seal: within one batch, a document with a visible seal gets a real
/// `/Rect` + `/AP`, a document with a different placement produces different bytes, and a document
/// with no appearance keeps the invisible, locked default.
#[test]
fn per_document_seal_placement_is_applied_independently() {
    let pdf = base_pdf();
    let provider = cc_provider(KeyCard::new());
    let docs = [
        pdf_doc("seal-a", &pdf, Some(text_seal(0, 72.0, 600.0))),
        pdf_doc("seal-b", &pdf, Some(text_seal(0, 300.0, 120.0))),
        pdf_doc("no-seal", &pdf, None),
    ];
    let mut policy = StaticTrustPolicy::granted();

    let report = sign_pdf_batch(
        &provider,
        &docs,
        fixed_time(),
        Some(&mut policy),
        Some(Zeroizing::new("1234".to_owned())),
    );
    assert!(report.all_ok());

    let seal_a = report.results[0].result.as_ref().unwrap();
    let seal_b = report.results[1].result.as_ref().unwrap();
    let no_seal = report.results[2].result.as_ref().unwrap();

    // The two visible-seal documents each carry a real appearance (`/AP`) and dropped the invisible
    // zero-`/Rect` placeholder.
    for signed in [seal_a, seal_b] {
        assert!(
            contains(signed, b"/AP"),
            "visible seal has an /AP appearance"
        );
        assert!(
            !contains(signed, b"/Rect [0 0 0 0]"),
            "visible seal replaced the invisible zero /Rect"
        );
    }
    // Different per-document placements produce different signed bytes (placement is threaded
    // per document, not shared).
    assert_ne!(
        seal_a, seal_b,
        "different placements yield different output"
    );

    // The no-appearance document in the same batch kept the invisible, locked default.
    assert!(
        contains(no_seal, b"/Rect [0 0 0 0]"),
        "no-seal document keeps the invisible zero /Rect"
    );
    assert!(
        !contains(no_seal, b"/AP"),
        "no-seal document has no appearance stream"
    );
}

/// The transient in-app PIN is owned by the batch as a `Zeroizing` (dropped/zeroized when the batch
/// returns) and never appears in the report or any per-document outcome (plan §6).
#[test]
fn in_app_pin_is_never_present_in_the_report() {
    let pdf = base_pdf();
    let provider = cc_provider(KeyCard::new());
    let docs = [pdf_doc("act-1", &pdf, None)];
    let mut policy = StaticTrustPolicy::granted();

    // The batch takes ownership of the PIN; after this call the only copy has been dropped+zeroized.
    let report = sign_pdf_batch(
        &provider,
        &docs,
        fixed_time(),
        Some(&mut policy),
        Some(Zeroizing::new("1234".to_owned())),
    );

    assert_eq!(
        provider.token().last_pin().as_deref(),
        Some("1234"),
        "the PIN was used"
    );
    let dump = format!("{report:?}");
    assert!(
        !dump.contains("1234"),
        "the PIN never appears in the batch report"
    );
    for outcome in &report.results {
        assert!(
            !format!("{outcome:?}").contains("1234"),
            "the PIN never appears in a per-document outcome"
        );
    }
}

/// The `Zeroizing` the batch holds the PIN in wipes its buffer on drop — the custody guarantee the
/// batch relies on to zeroize the in-app PIN after signing.
#[test]
fn zeroizing_pin_custody_wipes_on_drop() {
    use std::sync::atomic::AtomicBool;
    use zeroize::Zeroize;

    static WIPED: AtomicBool = AtomicBool::new(false);
    struct PinLike;
    impl Zeroize for PinLike {
        fn zeroize(&mut self) {
            WIPED.store(true, Ordering::SeqCst);
        }
    }

    {
        let _guard = Zeroizing::new(PinLike);
        assert!(!WIPED.load(Ordering::SeqCst), "not wiped while alive");
    }
    assert!(
        WIPED.load(Ordering::SeqCst),
        "Zeroizing wipes the PIN when it drops"
    );
}

/// A withdrawn issuer fails the whole batch closed: no document is signed, nothing reaches the card.
#[test]
fn untrusted_issuer_fails_the_whole_batch_closed() {
    let pdf = base_pdf();
    let provider = cc_provider(KeyCard::new());
    let counting = CountingProvider::new(&provider);
    let docs = [pdf_doc("act-1", &pdf, None), pdf_doc("act-2", &pdf, None)];
    let mut policy = StaticTrustPolicy::withdrawn();

    let report = sign_pdf_batch(
        &counting,
        &docs,
        fixed_time(),
        Some(&mut policy),
        Some(Zeroizing::new("1234".to_owned())),
    );

    assert!(!report.all_ok());
    assert_eq!(report.failed_count(), 2, "every document is refused");
    assert_eq!(report.auth_events, 0, "nothing reached the card");
    assert!(report.signing_cert_der.is_none());
    assert_eq!(
        report.trusted_list_status,
        Some(TrustedListStatus::Withdrawn)
    );
    assert_eq!(counting.calls(), 0, "the card was never asked to sign");
    for outcome in &report.results {
        assert!(matches!(
            outcome.result,
            Err(SigningError::UntrustedService {
                status: TrustedListStatus::Withdrawn
            })
        ));
    }
}

/// The detached-CAdES batch lane signs each payload under one authentication and aggregates results.
#[test]
fn detached_cades_batch_signs_each_payload() {
    let provider = cc_provider(KeyCard::new());
    let docs = [
        BatchCadesDocument {
            id: "digest-1".to_owned(),
            content_digest: [0x11u8; 32],
        },
        BatchCadesDocument {
            id: "digest-2".to_owned(),
            content_digest: [0x22u8; 32],
        },
    ];
    let mut policy = StaticTrustPolicy::granted();

    let report = sign_detached_cades_batch(
        &provider,
        &docs,
        fixed_time(),
        Some(&mut policy),
        Some(Zeroizing::new("1234".to_owned())),
    );

    assert!(report.all_ok(), "both payloads sign");
    assert_eq!(report.auth_mode, AuthMode::SingleAuth);
    assert_eq!(report.auth_events, 2);
    for outcome in &report.results {
        assert!(
            !outcome.result.as_ref().unwrap().is_empty(),
            "produced a CAdES CMS"
        );
    }
}

/// The honest `AuthMode` mapping per family: a locally-unlocked software key is `SingleAuth`, a CMD
/// provider (a fresh OTP per signature) is `PerDocumentAuth`. Exercised over the CAdES lane, which
/// does not require a cryptographically valid signature.
#[test]
fn auth_mode_reflects_the_signer_family() {
    let payload = [BatchCadesDocument {
        id: "d".to_owned(),
        content_digest: [0x33u8; 32],
    }];

    let soft = MockProvider::deterministic_rsa(SigningFamily::QualifiedCertificate);
    let soft_report = sign_detached_cades_batch(&soft, &payload, fixed_time(), None, None);
    assert_eq!(
        soft_report.auth_mode,
        AuthMode::SingleAuth,
        "a software key unlocked once is single-auth"
    );

    let cmd = MockProvider::deterministic_rsa(SigningFamily::ChaveMovelDigital);
    let cmd_report = sign_detached_cades_batch(&cmd, &payload, fixed_time(), None, None);
    assert_eq!(
        cmd_report.auth_mode,
        AuthMode::PerDocumentAuth,
        "CMD dispatches a fresh OTP per signature"
    );
}

/// Remote repeated-session batch is deliberately N independent one-digest sessions and N confirms,
/// never one provider-certified multi-hash batch or a `SingleAuth` claim.
#[test]
fn remote_repeated_batch_opens_and_confirms_one_session_per_pdf() {
    let pdf = base_pdf();
    let source = CountingRemoteSource::new();
    let mut doc_2 = remote_pdf_doc("act-2", &pdf);
    doc_2.options.field_name = Some("Assinatura2".to_owned());
    let docs = [remote_pdf_doc("act-1", &pdf), doc_2];
    let pin = Zeroizing::new(PIN.to_owned());
    let mut policy = StaticTrustPolicy::granted();

    let initiate = initiate_remote_pdf_batch_repeated_sessions(
        &source,
        &docs,
        PHONE,
        &pin,
        fixed_time(),
        Some(&mut policy),
    );

    assert!(initiate.all_ok());
    assert_eq!(
        initiate.auth_mode,
        RemoteBatchAuthMode::PerDocumentActivation
    );
    assert_eq!(initiate.initiate_events, 2);
    let digests = source.initiate_digests();
    assert_eq!(digests.len(), 2, "two one-digest initiate calls");
    assert_ne!(
        digests[0], digests[1],
        "each prepared PDF/session carries its own ByteRange digest"
    );

    let pending: Vec<_> = initiate
        .results
        .iter()
        .map(|r| r.result.as_ref().expect("pending"))
        .collect();
    assert_ne!(
        pending[0].session.provider_ref, pending[1].session.provider_ref,
        "provider sessions are distinct"
    );
    assert_eq!(
        pending[0].session.byterange_digest,
        *pending[0].prepared.byterange_digest()
    );
    assert_eq!(
        pending[1].session.byterange_digest,
        *pending[1].prepared.byterange_digest()
    );

    let activation_1 = Zeroizing::new(OTP.to_owned());
    let activation_2 = Zeroizing::new(OTP.to_owned());
    let confirm_docs = [
        RemoteBatchConfirmDocument {
            pending: pending[0],
            activation: &activation_1,
        },
        RemoteBatchConfirmDocument {
            pending: pending[1],
            activation: &activation_2,
        },
    ];

    let confirm = confirm_remote_pdf_batch_repeated_sessions(&source, &confirm_docs);

    assert!(confirm.all_ok());
    assert_eq!(
        confirm.auth_mode,
        RemoteBatchAuthMode::PerDocumentActivation
    );
    assert_eq!(confirm.confirm_events, 2);
    assert_eq!(source.confirm_refs().len(), 2, "two confirm calls");
    for outcome in &confirm.results {
        let signed = outcome.result.as_ref().expect("signed pdf");
        validate_pdf_signature(signed).expect("signature validates");
    }
}

/// A malformed PDF fails before remote initiate and does not prevent later valid PDFs from opening
/// their own sessions.
#[test]
fn remote_repeated_batch_prepare_failure_is_per_document() {
    let good = base_pdf();
    let broken = b"%PDF-1.7 this is not a real pdf".to_vec();
    let source = CountingRemoteSource::new();
    let docs = [
        remote_pdf_doc("ok-first", &good),
        remote_pdf_doc("broken", &broken),
        remote_pdf_doc("ok-last", &good),
    ];
    let pin = Zeroizing::new(PIN.to_owned());
    let mut policy = StaticTrustPolicy::granted();

    let report = initiate_remote_pdf_batch_repeated_sessions(
        &source,
        &docs,
        PHONE,
        &pin,
        fixed_time(),
        Some(&mut policy),
    );

    assert!(!report.all_ok());
    assert_eq!(report.ok_count(), 2);
    assert_eq!(report.failed_count(), 1);
    assert_eq!(
        report.initiate_events, 2,
        "only valid PDFs reached the remote source"
    );
    assert_eq!(source.initiate_digests().len(), 2);
    assert!(report.results[0].result.is_ok());
    assert_eq!(report.results[1].id, "broken");
    assert!(matches!(
        report.results[1].result,
        Err(SigningError::Pades(_))
    ));
    assert!(report.results[2].result.is_ok());
}

/// A provider-side initiate rejection is isolated to that document and preserves input order while
/// later valid documents still open their own sessions.
#[test]
fn remote_repeated_batch_initiate_failure_is_per_document() {
    let pdf = base_pdf();
    let source = CountingRemoteSource::failing_initiate_for(&["fail-middle.pdf"]);
    let docs = [
        remote_pdf_doc("ok-first", &pdf),
        remote_pdf_doc("fail-middle", &pdf),
        remote_pdf_doc("ok-last", &pdf),
    ];
    let pin = Zeroizing::new(PIN.to_owned());
    let mut policy = StaticTrustPolicy::granted();

    let report = initiate_remote_pdf_batch_repeated_sessions(
        &source,
        &docs,
        PHONE,
        &pin,
        fixed_time(),
        Some(&mut policy),
    );

    assert!(!report.all_ok());
    assert_eq!(report.ok_count(), 2);
    assert_eq!(report.failed_count(), 1);
    assert_eq!(
        report.initiate_events, 3,
        "all prepared PDFs reached provider initiate"
    );
    assert_eq!(
        source.initiate_digests().len(),
        2,
        "only accepted sessions record provider digests"
    );
    assert_eq!(report.results[0].id, "ok-first");
    assert!(report.results[0].result.is_ok());
    assert_eq!(report.results[1].id, "fail-middle");
    assert!(matches!(
        report.results[1].result,
        Err(SigningError::Provider(_))
    ));
    assert_eq!(report.results[2].id, "ok-last");
    assert!(report.results[2].result.is_ok());
}

/// One rejected activation fails only that pending document; other pending records still confirm
/// under their own per-document activation semantics.
#[test]
fn remote_repeated_batch_confirm_failure_is_per_document() {
    let pdf = base_pdf();
    let source = CountingRemoteSource::new();
    let docs = [
        remote_pdf_doc("act-1", &pdf),
        remote_pdf_doc("act-2", &pdf),
        remote_pdf_doc("act-3", &pdf),
    ];
    let pin = Zeroizing::new(PIN.to_owned());
    let mut policy = StaticTrustPolicy::granted();
    let initiate = initiate_remote_pdf_batch_repeated_sessions(
        &source,
        &docs,
        PHONE,
        &pin,
        fixed_time(),
        Some(&mut policy),
    );
    let pending: Vec<_> = initiate
        .results
        .iter()
        .map(|r| r.result.as_ref().expect("pending"))
        .collect();

    let good_activation = Zeroizing::new(OTP.to_owned());
    let bad_activation = Zeroizing::new("wrong-activation".to_owned());
    let good_activation_after = Zeroizing::new(OTP.to_owned());
    let confirm_docs = [
        RemoteBatchConfirmDocument {
            pending: pending[0],
            activation: &good_activation,
        },
        RemoteBatchConfirmDocument {
            pending: pending[1],
            activation: &bad_activation,
        },
        RemoteBatchConfirmDocument {
            pending: pending[2],
            activation: &good_activation_after,
        },
    ];

    let report = confirm_remote_pdf_batch_repeated_sessions(&source, &confirm_docs);

    assert!(!report.all_ok());
    assert_eq!(report.ok_count(), 2);
    assert_eq!(report.failed_count(), 1);
    assert_eq!(report.confirm_events, 3);
    assert_eq!(
        source.confirm_refs().len(),
        3,
        "bad activation did not abort later confirm accounting"
    );
    assert!(report.results[0].result.is_ok());
    assert!(matches!(
        report.results[1].result,
        Err(SigningError::Provider(_))
    ));
    assert!(report.results[2].result.is_ok());
}

/// Pending records are the reusable remote state and must remain secret-free: no initiate PIN and
/// no activation value may appear in serialization or `Debug`.
#[test]
fn remote_repeated_batch_pending_records_do_not_store_activation_secrets() {
    let marker = "CONFIDENTIAL_ACT_BODY_924190";
    let pdf = marked_pdf(marker);
    let source = CountingRemoteSource::new();
    let docs = [remote_pdf_doc("act-1", &pdf)];
    let pin = Zeroizing::new(PIN.to_owned());
    let mut policy = StaticTrustPolicy::granted();
    let report = initiate_remote_pdf_batch_repeated_sessions(
        &source,
        &docs,
        PHONE,
        &pin,
        fixed_time(),
        Some(&mut policy),
    );
    let pending = report.results[0].result.as_ref().expect("pending");
    assert!(
        contains_bytes(pending.prepared.prepared_pdf(), marker.as_bytes()),
        "test marker must be present in the prepared PDF before redaction checks"
    );

    let serialized = serde_json::to_string(pending).expect("pending serializes");
    let debug = format!("{pending:?}");
    let marker_json_fragment = comma_joined_bytes(marker.as_bytes());
    let marker_debug_fragment = marker_json_fragment.replace(',', ", ");
    assert!(
        !serialized.contains(marker),
        "document text must not leak through serialization"
    );
    assert!(
        !serialized.contains(&marker_json_fragment),
        "document bytes must not leak through serialization"
    );
    assert!(
        !debug.contains(marker),
        "document text must not leak through Debug"
    );
    assert!(
        !debug.contains(&marker_debug_fragment),
        "document bytes must not leak through Debug"
    );
    assert!(!serialized.contains(PIN), "PIN must not be persisted");
    assert!(
        !serialized.contains(OTP),
        "activation must not be persisted before confirm"
    );
    assert!(!debug.contains(PIN), "PIN must not leak through Debug");
    assert!(
        !debug.contains(OTP),
        "activation must not leak through Debug"
    );
}
