//! t67-e8 — the in-app Cartão de Cidadão **batch** signing API, end to end, over a key-backed card.
//!
//! Drives `POST /v1/signature/cc/batch-sign` through the axum router with an injected, key-backed
//! [`chancela_smartcard::CryptoToken`] standing in for a citizen card, so the produced PDFs genuinely
//! validate with no reader / PKCS#11 / hardware. Covers:
//!
//! - a batch of N with one deliberately unsignable act → **per-document results** (N-1 signed, 1
//!   error) without aborting the batch; each signed act is persisted and validates;
//! - the **honest auth accounting**: an in-app PIN → `auth_mode: "single_auth"` (the PIN is replayed
//!   to each card login); no PIN → `"per_document_auth"`;
//! - **PIN redaction**: the in-app PIN appears in no result, ledger event, or error body;
//! - a **wrong** in-app PIN fails every document with a PIN-free message and leaves no artifact;
//! - the **RBAC gate** (`signing.perform`) and the **co-location gate** (CC-B).
//!
//! Fictional example data only: "Encosto Estratégico, S.A." / "Amélia Marques" — never real names.

mod common;

use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration as StdDuration;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use der::Encode;
use der::asn1::{Any, BitString, ObjectIdentifier};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use tower::ServiceExt;
use x509_cert::certificate::{Certificate, TbsCertificate, Version};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;

use chancela_api::{AppState, router};
use chancela_cades::{RawSignature, SignatureAlgorithm};
use chancela_pades::validate_pdf_signature;
use chancela_signing::{
    SignerProvider, SigningError, SmartcardProvider, StaticTrustPolicy, TrustPolicy,
    TrustedListStatus,
};
use chancela_smartcard::error::PinTriesLeft;
use chancela_smartcard::token::{LABEL_AUTH_CERT, LABEL_SIGNATURE_CERT};
use chancela_smartcard::{CertUsage, CryptoToken, SmartcardError, TokenCertificate};
use common::TEST_PASSWORD;

const OID_SHA256_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const SHA256_DIGEST_INFO_PREFIX: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

// --- An in-test, key-backed CryptoToken standing in for a Cartão de Cidadão (RSA / CC v1) ---------

/// A hardware-free RSA [`CryptoToken`] standing in for a citizen card: a qualified **signature** leaf
/// on a distinct key from the **authentication** leaf, a distinct issuing-CA certificate for the TSL
/// gate, an optional required in-app PIN, and a shared log of the PINs threaded to it. `Clone` so the
/// DI factory can mint a provider per batch (the log Arc is shared across clones).
#[derive(Clone)]
struct KeyCard {
    signature_key: Arc<rsa::RsaPrivateKey>,
    signature_cert_der: Vec<u8>,
    auth_cert_der: Vec<u8>,
    issuer_cert_der: Vec<u8>,
    expected_pin: Option<String>,
    pin_log: Arc<Mutex<Vec<Option<String>>>>,
}

impl KeyCard {
    fn cc_v1() -> Self {
        let signature = EphemeralRsaSigner::new("Amélia Marques (assinatura)", 1);
        let auth = EphemeralRsaSigner::new("Amélia Marques (autenticação)", 2);
        let issuer = EphemeralRsaSigner::new("Encosto Estratégico Lda — EC Teste", 3);
        Self {
            signature_key: Arc::new(signature.key),
            signature_cert_der: signature.cert_der,
            auth_cert_der: auth.cert_der,
            issuer_cert_der: issuer.cert_der,
            expected_pin: None,
            pin_log: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn requiring_pin(mut self, pin: &str) -> Self {
        self.expected_pin = Some(pin.to_owned());
        self
    }

    fn threaded_pins(&self) -> Vec<Option<String>> {
        self.pin_log.lock().expect("pin log poisoned").clone()
    }
}

impl CryptoToken for KeyCard {
    fn list_certificates(&self) -> Result<Vec<TokenCertificate>, SmartcardError> {
        Ok(vec![
            TokenCertificate {
                label: LABEL_AUTH_CERT.to_owned(),
                cert_der: self.auth_cert_der.clone(),
                algorithm: SignatureAlgorithm::RsaPkcs1Sha256,
            },
            TokenCertificate {
                label: LABEL_SIGNATURE_CERT.to_owned(),
                cert_der: self.signature_cert_der.clone(),
                algorithm: SignatureAlgorithm::RsaPkcs1Sha256,
            },
        ])
    }

    fn sign_digest(
        &self,
        cert: &TokenCertificate,
        digest: &[u8; 32],
    ) -> Result<RawSignature, SmartcardError> {
        assert_eq!(
            cert.usage(),
            CertUsage::QualifiedSignature,
            "the card must only be asked to sign with the qualified-signature certificate"
        );
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
        self.pin_log
            .lock()
            .expect("pin log poisoned")
            .push(pin.map(str::to_owned));
        if let Some(expected) = &self.expected_pin
            && pin != Some(expected.as_str())
        {
            return Err(SmartcardError::WrongPin {
                tries_left: PinTriesLeft::Low,
            });
        }
        self.sign_digest(cert, digest)
    }
}

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

// --- test harness ---------------------------------------------------------------------------------

/// A temp data dir removed on drop.
struct TempDir(std::path::PathBuf);
impl TempDir {
    fn new() -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!("chancela-cc-batch-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

type CcProviderFactory =
    Arc<dyn Fn() -> Result<Box<dyn SignerProvider>, SigningError> + Send + Sync>;

fn provider_factory(card: KeyCard, issuer_cert_der: Option<Vec<u8>>) -> CcProviderFactory {
    Arc::new(move || {
        Ok(Box::new(
            SmartcardProvider::new(card.clone()).with_issuer_certificate(issuer_cert_der.clone()),
        ))
    })
}

fn state_at(dir: &std::path::Path, factory: Option<CcProviderFactory>, local: bool) -> AppState {
    let mut state = AppState::with_data_dir(dir);
    state.local_signing = local;
    state.cc_provider = factory;
    {
        let mut settings = state.settings.try_write().unwrap();
        settings.signing.tsa_url = None;
        settings.signing.tsa_providers.clear();
    }
    let policy: Arc<dyn Fn() -> Box<dyn TrustPolicy + Send> + Send + Sync> =
        Arc::new(move || Box::new(StaticTrustPolicy::new(TrustedListStatus::Granted)));
    state.cmd_trust_policy = Some(policy);
    state
}

async fn send(state: &AppState, req: Request<Body>) -> (StatusCode, Value) {
    let resp = router(state.clone())
        .oneshot(req)
        .await
        .expect("router responds");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.expect("body");
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, value)
}

async fn send_bytes(state: &AppState, req: Request<Body>) -> (StatusCode, Vec<u8>) {
    let resp = router(state.clone())
        .oneshot(req)
        .await
        .expect("router responds");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.expect("body");
    (status, bytes.to_vec())
}

fn json_req(method: &str, uri: &str, token: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-chancela-session", token)
        .body(Body::from(body.to_string()))
        .expect("request builds")
}

fn get_req(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("x-chancela-session", token)
        .body(Body::empty())
        .expect("request builds")
}

async fn bootstrap(state: &AppState) -> (String, String) {
    let (status, user) = send(
        state,
        Request::builder()
            .method("POST")
            .uri("/v1/users")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "username": "amelia.marques",
                    "display_name": "Amélia Marques",
                    "password": TEST_PASSWORD,
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create first user: {user}");
    let uid = user["id"].as_str().expect("user id").to_owned();
    let token = open_session(state, &uid).await;
    (token, uid)
}

async fn open_session(state: &AppState, user_id: &str) -> String {
    let (status, session) = send(
        state,
        Request::builder()
            .method("POST")
            .uri("/v1/session")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({ "user_id": user_id, "password": TEST_PASSWORD }).to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "open session: {session}");
    session["token"].as_str().expect("token").to_owned()
}

/// Create the entity + book once and return their ids (a batch signs several acts in one book).
async fn entity_and_book(state: &AppState, token: &str) -> (String, String) {
    let (status, entity) = send(
        state,
        json_req(
            "POST",
            "/v1/entities",
            token,
            json!({ "name": "Encosto Estratégico, S.A.", "nipc": "503004642", "seat": "Lisboa", "kind": "SociedadeAnonima" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "entity: {entity}");
    let entity_id = entity["id"].as_str().unwrap().to_owned();

    let (status, book) = send(
        state,
        json_req(
            "POST",
            "/v1/books",
            token,
            json!({ "entity_id": entity_id, "kind": "AssembleiaGeral", "purpose": "livro de atas", "opening_date": "2026-01-15", "required_signatories": ["Administrador"] }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "book: {book}");
    let book_id = book["id"].as_str().unwrap().to_owned();
    (entity_id, book_id)
}

/// Draft an act in `book_id`; when `ready_to_sign` is true, advance it to `Signing`, otherwise
/// leave it at `TextApproved` to exercise the per-document lifecycle guard.
async fn make_act(state: &AppState, token: &str, book_id: &str, ready_to_sign: bool) -> String {
    let (status, act) = send(
        state,
        json_req(
            "POST",
            "/v1/acts",
            token,
            json!({ "book_id": book_id, "title": "Ata da AG anual", "channel": "Physical" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "act: {act}");
    let act_id = act["id"].as_str().unwrap().to_owned();

    let (status, _) = send(
        state,
        json_req(
            "PATCH",
            &format!("/v1/acts/{act_id}"),
            token,
            json!({
                "meeting_date": "2026-03-30", "meeting_time": "10:00", "place": "Sede social",
                "mesa": { "presidente": "Ana Presidente", "secretarios": ["Rui Secretário"] },
                "agenda": [{ "number": 1, "text": "Aprovação das contas" }],
                "attendance_reference": "Lista de presenças",
                "deliberations": "Aprovadas as contas do exercício.",
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let states = if ready_to_sign {
        &[
            "Review",
            "Convened",
            "Deliberated",
            "TextApproved",
            "Signing",
        ][..]
    } else {
        &["Review", "Convened", "Deliberated", "TextApproved"][..]
    };
    for to in states {
        let (status, _) = send(
            state,
            json_req(
                "POST",
                &format!("/v1/acts/{act_id}/advance"),
                token,
                json!({ "to": *to }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "advance to {to}");
    }

    act_id
}

async fn signature_status(state: &AppState, token: &str, act_id: &str) -> Value {
    let (_, view) = send(
        state,
        get_req(&format!("/v1/acts/{act_id}/signature"), token),
    )
    .await;
    view
}

async fn ledger_events(state: &AppState, token: &str, act_id: &str) -> Value {
    let (status, events) = send(
        state,
        get_req(&format!("/v1/ledger/events?scope=act:{act_id}"), token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "ledger events: {events}");
    events
}

// --- tests ----------------------------------------------------------------------------------------

/// A batch of three acts where one has not entered `Signing`: the two ready acts sign and validate,
/// the premature act is an isolated per-document error, and the batch reports honest counts.
#[tokio::test]
async fn batch_signs_ready_acts_and_isolates_one_unsignable_doc() {
    const PIN: &str = "824193";
    let dir = TempDir::new();
    let card = KeyCard::cc_v1().requiring_pin(PIN);
    let observer = card.clone();
    let signature_cert_der = card.signature_cert_der.clone();
    let issuer = card.issuer_cert_der.clone();
    let factory = provider_factory(card, Some(issuer));
    let state = state_at(&dir.0, Some(factory), true);
    let (token, _uid) = bootstrap(&state).await;
    let (_entity, book) = entity_and_book(&state, &token).await;

    let act_a = make_act(&state, &token, &book, true).await;
    let act_not_ready = make_act(&state, &token, &book, false).await;
    let act_b = make_act(&state, &token, &book, true).await;

    let (status, done) = send(
        &state,
        json_req(
            "POST",
            "/v1/signature/cc/batch-sign",
            &token,
            json!({
                "act_ids": [act_a, act_not_ready, act_b],
                "capacity": "Administrador",
                "pin": PIN,
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "batch sign: {done}");
    assert_eq!(done["family"], "CartaoDeCidadao");
    assert_eq!(
        done["auth_mode"], "single_auth",
        "one in-app PIN for the batch"
    );
    assert_eq!(done["auth_events"], 2, "two docs reached the card");
    assert_eq!(done["requested"], 3);
    assert_eq!(done["signed"], 2);
    assert_eq!(done["failed"], 1);
    assert_eq!(done["trusted_list_status"], "Granted");

    // Results are in the requested order and correlate by act id.
    let results = done["results"].as_array().expect("results array");
    assert_eq!(results.len(), 3);
    assert_eq!(results[0]["act_id"], act_a);
    assert_eq!(results[0]["status"], "signed");
    assert!(results[0]["signed_pdf_digest"].is_string());
    assert_eq!(results[1]["act_id"], act_not_ready);
    assert_eq!(results[1]["status"], "error");
    assert!(
        results[1]["error"]
            .as_str()
            .is_some_and(|m| m.contains("Signing")),
        "act outside Signing reports an honest precondition error: {}",
        results[1]
    );
    assert_eq!(results[2]["act_id"], act_b);
    assert_eq!(results[2]["status"], "signed");

    // The two ready acts persist a validating PDF and flip to signed; the premature one did not.
    for act_id in [&act_a, &act_b] {
        let (status, signed_pdf) = send_bytes(
            &state,
            get_req(&format!("/v1/acts/{act_id}/document/signed"), &token),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let report = validate_pdf_signature(&signed_pdf).expect("signed PDF must validate");
        assert!(report.covers_whole_file_except_contents);
        assert_eq!(report.cades.signer_cert_der, signature_cert_der);
        assert_eq!(
            signature_status(&state, &token, act_id).await["status"],
            "signed"
        );
    }
    assert_ne!(
        signature_status(&state, &token, &act_not_ready).await["status"],
        "signed"
    );

    // The PIN was replayed to each of the two card logins (single human authentication).
    assert_eq!(
        observer.threaded_pins(),
        vec![Some(PIN.to_owned()), Some(PIN.to_owned())]
    );

    // REDACTION: the PIN appears in no result body nor any ledger event of the signed acts.
    assert!(
        !done.to_string().contains(PIN),
        "PIN must not appear in the batch response: {done}"
    );
    for act_id in [&act_a, &act_b] {
        let events = ledger_events(&state, &token, act_id).await;
        assert!(
            !events.to_string().contains(PIN),
            "PIN must not appear in any ledger event for {act_id}: {events}"
        );
    }
}

/// Without an in-app PIN the batch runs the protected-authentication path and reports honest
/// per-document authentication (never a false single-PIN claim).
#[tokio::test]
async fn batch_without_pin_reports_per_document_auth() {
    let dir = TempDir::new();
    let card = KeyCard::cc_v1(); // no required PIN → protected-auth path
    let issuer = card.issuer_cert_der.clone();
    let factory = provider_factory(card, Some(issuer));
    let state = state_at(&dir.0, Some(factory), true);
    let (token, _uid) = bootstrap(&state).await;
    let (_entity, book) = entity_and_book(&state, &token).await;
    let act_a = make_act(&state, &token, &book, true).await;
    let act_b = make_act(&state, &token, &book, true).await;

    let (status, done) = send(
        &state,
        json_req(
            "POST",
            "/v1/signature/cc/batch-sign",
            &token,
            json!({ "act_ids": [act_a, act_b] }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "batch sign: {done}");
    assert_eq!(
        done["auth_mode"], "per_document_auth",
        "no in-app PIN → a reader prompt per document"
    );
    assert_eq!(done["signed"], 2);
    assert_eq!(done["failed"], 0);
}

/// A wrong in-app PIN fails every document in the batch, with a PIN-free per-document message and no
/// artifact left behind.
#[tokio::test]
async fn batch_wrong_pin_fails_all_docs_without_leaking_pin() {
    const CARD_PIN: &str = "824193";
    const WRONG_PIN: &str = "000111";
    let dir = TempDir::new();
    let card = KeyCard::cc_v1().requiring_pin(CARD_PIN);
    let issuer = card.issuer_cert_der.clone();
    let factory = provider_factory(card, Some(issuer));
    let state = state_at(&dir.0, Some(factory), true);
    let (token, _uid) = bootstrap(&state).await;
    let (_entity, book) = entity_and_book(&state, &token).await;
    let act_a = make_act(&state, &token, &book, true).await;
    let act_b = make_act(&state, &token, &book, true).await;

    let (status, done) = send(
        &state,
        json_req(
            "POST",
            "/v1/signature/cc/batch-sign",
            &token,
            json!({ "act_ids": [act_a, act_b], "pin": WRONG_PIN }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "batch responds 200 with per-doc results: {done}"
    );
    assert_eq!(done["signed"], 0);
    assert_eq!(done["failed"], 2);
    for result in done["results"].as_array().expect("results") {
        assert_eq!(result["status"], "error");
        assert!(
            result["error"].as_str().unwrap_or_default().contains("PIN"),
            "each failure names the PIN issue: {result}"
        );
    }
    // No PIN anywhere in the response, and neither act was signed.
    let body = done.to_string();
    assert!(
        !body.contains(WRONG_PIN) && !body.contains(CARD_PIN),
        "batch body must not leak any PIN: {done}"
    );
    for act_id in [&act_a, &act_b] {
        let (status, _) = send_bytes(
            &state,
            get_req(&format!("/v1/acts/{act_id}/document/signed"), &token),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "no signed artifact for {act_id}"
        );
    }
}

/// The RBAC gate: a session lacking `signing.perform` is refused with 403 for the whole batch, before
/// the card is touched — nothing is signed.
#[tokio::test]
async fn batch_403_for_role_without_signing_perm() {
    let dir = TempDir::new();
    let card = KeyCard::cc_v1();
    let issuer = card.issuer_cert_der.clone();
    let factory = provider_factory(card, Some(issuer));
    let state = state_at(&dir.0, Some(factory), true);

    let (owner, _uid) = bootstrap(&state).await;
    let (_entity, book) = entity_and_book(&state, &owner).await;
    let act_a = make_act(&state, &owner, &book, true).await;
    let act_b = make_act(&state, &owner, &book, true).await;

    let (status, limited) = send(
        &state,
        json_req(
            "POST",
            "/v1/users",
            &owner,
            json!({
                "username": "leitor.user",
                "display_name": "Leitor",
                "password": TEST_PASSWORD,
            }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "create limited user: {limited}"
    );
    let limited_id = limited["id"].as_str().unwrap().to_owned();

    let (_, roles) = send(&state, get_req("/v1/roles", &owner)).await;
    let gestor_id = roles
        .as_array()
        .expect("roles")
        .iter()
        .find(|r| r["name"] == "Gestor")
        .and_then(|r| r["id"].as_str())
        .expect("seeded Gestor")
        .to_owned();
    let (status, _) = send(
        &state,
        json_req(
            "DELETE",
            &format!("/v1/users/{limited_id}/roles"),
            &owner,
            json!({ "role_id": gestor_id, "scope": { "kind": "global" } }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "remove default Gestor@Global");

    let limited_tok = open_session(&state, &limited_id).await;
    let (status, err) = send(
        &state,
        json_req(
            "POST",
            "/v1/signature/cc/batch-sign",
            &limited_tok,
            json!({ "act_ids": [act_a, act_b] }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "no signing.perform → 403: {err}"
    );
    for act_id in [&act_a, &act_b] {
        let (status, _) = send_bytes(
            &state,
            get_req(&format!("/v1/acts/{act_id}/document/signed"), &owner),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "nothing signed for {act_id}");
    }
}

/// The co-location gate (CC-B): a non-co-located server refuses the batch (409) before any PIN is
/// read, and signs nothing.
#[tokio::test]
async fn batch_409_when_not_co_located() {
    let dir = TempDir::new();
    let card = KeyCard::cc_v1();
    let issuer = card.issuer_cert_der.clone();
    let factory = provider_factory(card, Some(issuer));
    let state = state_at(&dir.0, Some(factory), false); // NOT co-located
    let (token, _uid) = bootstrap(&state).await;
    let (_entity, book) = entity_and_book(&state, &token).await;
    let act_a = make_act(&state, &token, &book, true).await;

    let (status, err) = send(
        &state,
        json_req(
            "POST",
            "/v1/signature/cc/batch-sign",
            &token,
            json!({ "act_ids": [act_a], "pin": "824193" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "not co-located → 409: {err}");
    assert!(
        err["error"]
            .as_str()
            .unwrap_or_default()
            .contains("aplicação de secretária"),
        "honest co-location message: {err}"
    );
    assert!(
        !err.to_string().contains("824193"),
        "the refused PIN must not appear in the body: {err}"
    );
    let (status, _) = send_bytes(
        &state,
        get_req(&format!("/v1/acts/{act_a}/document/signed"), &token),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "nothing signed");
}

/// An empty or duplicate act list is a clean 422 before any signing.
#[tokio::test]
async fn batch_rejects_empty_and_duplicate_act_lists() {
    let dir = TempDir::new();
    let card = KeyCard::cc_v1();
    let issuer = card.issuer_cert_der.clone();
    let factory = provider_factory(card, Some(issuer));
    let state = state_at(&dir.0, Some(factory), true);
    let (token, _uid) = bootstrap(&state).await;
    let (_entity, book) = entity_and_book(&state, &token).await;
    let act = make_act(&state, &token, &book, true).await;

    let (status, err) = send(
        &state,
        json_req(
            "POST",
            "/v1/signature/cc/batch-sign",
            &token,
            json!({ "act_ids": [] }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "empty list → 422: {err}"
    );

    let (status, err) = send(
        &state,
        json_req(
            "POST",
            "/v1/signature/cc/batch-sign",
            &token,
            json!({ "act_ids": [act, act] }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "duplicate acts → 422: {err}"
    );
}
