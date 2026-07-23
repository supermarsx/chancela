//! t58-e2 — the synchronous Cartão de Cidadão qualified-signing API, end to end, over a MOCK card.
//!
//! Drives `POST /v1/acts/{id}/signature/cc/sign` through the axum router with an injected,
//! key-backed [`chancela_smartcard::CryptoToken`] standing in for a citizen card — so the produced
//! PDF genuinely validates (SIG-24) with no reader / PKCS#11 / hardware (t58 gate). Covers:
//!
//! - the signed round-trip for BOTH card generations (CC v1 RSA-2048, CC v2 P-256): the signed
//!   variant is persisted, a `document.signed` event is chained, and the chain still verifies; the
//!   status remains `em_assinatura` until the explicit seal reports `finalizado_qualificado`;
//! - the **co-location gate** (CC-B): `409` when `CHANCELA_LOCAL_SIGNING` is absent (a remote server);
//! - the **RBAC gate**: `403` for a session lacking `signing.perform` at the act's book;
//! - the **provider-error mapping**: an un-activated card signature → an honest CC `422`, distinct
//!   from a PAdES/CAdES failure, and no artifact left behind.
//!
//! The PIN is entered at the reader and never enters this process — there is no PIN field anywhere in
//! the CC flow (verify the request body carries no secret). Fictional example data only: "Encosto
//! Estratégico, S.A." / "Amélia Marques" — never real names.

use crate::common;

use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration as StdDuration;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
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
use chancela_core::ActId;
use chancela_pades::{add_doc_timestamp_revision, inspect_doc_timestamps, validate_pdf_signature};
use chancela_signing::{
    SignerProvider, SigningError, SmartcardProvider, StaticTrustPolicy, TrustPolicy,
    TrustedListStatus,
};
use chancela_smartcard::error::PinTriesLeft;
use chancela_smartcard::token::{LABEL_AUTH_CERT, LABEL_SIGNATURE_CERT};
use chancela_smartcard::{CertUsage, CryptoToken, MockToken, SmartcardError, TokenCertificate};
use chancela_tsl::{DigitalIdentity, parse_tsl};
use common::TEST_PASSWORD;
use common::tsa_http::MockTsaServer;
use uuid::Uuid;

const OID_SHA256_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const OID_ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const SHA256_DIGEST_INFO_PREFIX: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];
const OCSP_DER_FIXTURE: &[u8] = &[0x30, 0x03, 0x02, 0x01, 0x05];
const CRL_DER_FIXTURE: &[u8] = &[0x30, 0x05, 0x06, 0x03, 0x2a, 0x03, 0x04];
const PT_TSL_SAMPLE: &[u8] = include_bytes!("../../chancela-tsl/fixtures/pt-tsl-sample.xml");

// --- An in-test, key-backed CryptoToken standing in for a Cartão de Cidadão -----------------------

/// A hardware-free [`CryptoToken`] backed by real ephemeral keys, standing in for a citizen card.
/// Exposes a qualified **signature** certificate and an **authentication** certificate on distinct
/// keys (so label-based selection is provable) and carries a distinct issuing-CA certificate for the
/// TSL gate (the real card exposes only the leaf). `Clone` so the DI factory can mint a fresh
/// provider per request.
#[derive(Clone)]
struct CcTestCard {
    signature_key: SignerKey,
    signature_cert_der: Vec<u8>,
    auth_cert_der: Vec<u8>,
    issuer_cert_der: Vec<u8>,
    /// t67-e8: when `Some`, the card requires exactly this in-app PIN — any other (or `None`) yields
    /// [`SmartcardError::WrongPin`], so the API PIN-threading + wrong-PIN mapping is exercised while
    /// a *correct* PIN still produces a real, validating signature.
    expected_pin: Option<String>,
    /// t67-e8: the PIN threaded to every `sign_digest_with_pin` call (shared across the cloned
    /// per-request providers), so a test can assert the in-app PIN reached the card seam. The
    /// recorded value never leaves the test — production code never surfaces it.
    pin_log: Arc<Mutex<Vec<Option<String>>>>,
}

#[derive(Clone)]
enum SignerKey {
    Rsa(Box<rsa::RsaPrivateKey>),
    Ecdsa(Box<p256::ecdsa::SigningKey>),
}

impl CcTestCard {
    fn cc_v1() -> Self {
        let signature = EphemeralSigner::new_rsa("Amélia Marques (assinatura)", 1);
        let auth = EphemeralSigner::new_rsa("Amélia Marques (autenticação)", 2);
        let issuer = EphemeralSigner::new_rsa("Encosto Estratégico Lda — EC Teste", 3);
        Self {
            signature_cert_der: signature.cert_der.clone(),
            auth_cert_der: auth.cert_der,
            issuer_cert_der: issuer.cert_der,
            signature_key: signature.key,
            expected_pin: None,
            pin_log: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn cc_v2() -> Self {
        let signature = EphemeralSigner::new_ecdsa("Amélia Marques (assinatura)", 1);
        let auth = EphemeralSigner::new_ecdsa("Amélia Marques (autenticação)", 2);
        let issuer = EphemeralSigner::new_ecdsa("Encosto Estratégico Lda — EC Teste", 3);
        Self {
            signature_cert_der: signature.cert_der.clone(),
            auth_cert_der: auth.cert_der,
            issuer_cert_der: issuer.cert_der,
            signature_key: signature.key,
            expected_pin: None,
            pin_log: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Require exactly `pin` as the in-app PIN (t67-e8): a correct PIN signs for real, any other
    /// yields [`SmartcardError::WrongPin`]. The shared PIN log is unaffected.
    fn requiring_pin(mut self, pin: &str) -> Self {
        self.expected_pin = Some(pin.to_owned());
        self
    }

    /// The PINs threaded to the card so far (shared across the cloned per-request providers).
    fn threaded_pins(&self) -> Vec<Option<String>> {
        self.pin_log.lock().expect("pin log poisoned").clone()
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        match self.signature_key {
            SignerKey::Rsa(_) => SignatureAlgorithm::RsaPkcs1Sha256,
            SignerKey::Ecdsa(_) => SignatureAlgorithm::EcdsaP256Sha256,
        }
    }
}

impl CryptoToken for CcTestCard {
    fn list_certificates(&self) -> Result<Vec<TokenCertificate>, SmartcardError> {
        Ok(vec![
            // Auth cert FIRST — selection is by label, not position (SIG-02).
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
        // Record the threaded PIN (test-only observation) before any early return.
        self.pin_log
            .lock()
            .expect("pin log poisoned")
            .push(pin.map(str::to_owned));
        // A required-PIN card rejects a wrong/absent PIN with the typed WrongPin the api classifies.
        if let Some(expected) = &self.expected_pin
            && pin != Some(expected.as_str())
        {
            return Err(SmartcardError::WrongPin {
                tries_left: PinTriesLeft::Low,
            });
        }
        // A correct (or unconstrained) PIN produces the same real signature as the NULL-PIN path.
        self.sign_digest(cert, digest)
    }
}

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

// --- test harness ---------------------------------------------------------------------------------

/// A temp data dir that is removed on drop.
struct TempDir(std::path::PathBuf);
impl TempDir {
    fn new() -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!("chancela-cc-signing-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn fixture_granted_issuer_cert() -> Vec<u8> {
    let list = parse_tsl(PT_TSL_SAMPLE).expect("fixture parses");
    let provider = list
        .providers
        .iter()
        .find(|provider| provider.name.contains("MULTICERT"))
        .expect("fixture has a granted e-signature provider");
    provider.services[0]
        .digital_identities
        .iter()
        .find_map(|identity| match identity {
            DigitalIdentity::Certificate(der) => Some(der.clone()),
            _ => None,
        })
        .expect("fixture provider carries a certificate identity")
}

/// The CC signer-provider factory shape `AppState::cc_provider` holds (mirrors the field type).
type CcProviderFactory =
    Arc<dyn Fn() -> Result<Box<dyn SignerProvider>, SigningError> + Send + Sync>;

/// A CC-signing provider factory over a cloneable [`CryptoToken`] + out-of-band issuer certificate.
/// Mints a fresh [`SmartcardProvider`] per call (as the real handler builds one per request).
fn provider_factory<T>(token: T, issuer_cert_der: Option<Vec<u8>>) -> CcProviderFactory
where
    T: CryptoToken + Clone + Send + Sync + 'static,
{
    Arc::new(move || {
        Ok(Box::new(
            SmartcardProvider::new(token.clone()).with_issuer_certificate(issuer_cert_der.clone()),
        ))
    })
}

/// Build a durable state at `dir`: co-located (`local_signing`), a granted/withdrawn TSL policy, and
/// the injected CC provider factory. `local` gates the co-location signal.
fn state_at(
    dir: &std::path::Path,
    factory: Option<CcProviderFactory>,
    granted: bool,
    local: bool,
) -> AppState {
    let trust_status = if granted {
        TrustedListStatus::Granted
    } else {
        TrustedListStatus::Withdrawn
    };
    state_at_with_trust_status(dir, factory, trust_status, local)
}

fn state_at_with_trust_status(
    dir: &std::path::Path,
    factory: Option<CcProviderFactory>,
    trust_status: TrustedListStatus,
    local: bool,
) -> AppState {
    let mut state = AppState::with_data_dir(dir);
    state.local_signing = local;
    state.cc_provider = factory;
    {
        let mut settings = state.settings.try_write().unwrap();
        settings.signing.tsa_url = None;
        settings.signing.tsa_providers.clear();
    }
    let policy: Arc<dyn Fn() -> Box<dyn TrustPolicy + Send> + Send + Sync> =
        Arc::new(move || Box::new(StaticTrustPolicy::new(trust_status)));
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

/// Bootstrap a first-run user + session; return (token, user_id).
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

/// Create an act in `Signing` with its immutable canonical PDF/A snapshot and return its id.
async fn seal_an_act(state: &AppState, token: &str) -> String {
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

    for to in [
        "Review",
        "Convened",
        "Deliberated",
        "TextApproved",
        "Signing",
    ] {
        let (status, _) = send(
            state,
            json_req(
                "POST",
                &format!("/v1/acts/{act_id}/advance"),
                token,
                json!({ "to": to }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "advance to {to}");
    }

    act_id
}

async fn seal_signed_act(state: &AppState, token: &str, act_id: &str) {
    let (status, sealed) = send(
        state,
        json_req("POST", &format!("/v1/acts/{act_id}/seal"), token, json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "seal signed act: {sealed}");
}

async fn signed_event_count(state: &AppState, token: &str, act_id: &str) -> usize {
    event_kind_count(state, token, act_id, "document.signed").await
}

async fn event_kind_count(state: &AppState, token: &str, act_id: &str, kind: &str) -> usize {
    let (status, events) = send(
        state,
        get_req(&format!("/v1/ledger/events?scope=act:{act_id}"), token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "ledger events: {events}");
    events
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["kind"] == kind)
        .count()
}

async fn assert_no_signed_artifact_or_event(state: &AppState, token: &str, act_id: &str) {
    let (status, _) = send_bytes(
        state,
        get_req(&format!("/v1/acts/{act_id}/document/signed"), token),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(signed_event_count(state, token, act_id).await, 0);
    let (_, view) = send(
        state,
        get_req(&format!("/v1/acts/{act_id}/signature"), token),
    )
    .await;
    assert_ne!(view["status"], "signed");
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn fixture_timestamp_token() -> Vec<u8> {
    let tsa = chancela_tsa::TsaClient::new(chancela_tsa::MockTsaTransport::from_fixture());
    let req = chancela_tsa::TimestampRequest::new(chancela_tsa::mock::FIXTURE_DIGEST)
        .with_nonce(chancela_tsa::mock::FIXTURE_NONCE)
        .without_certificate();
    tsa.stamp(&req).expect("fixture timestamp token").token_der
}

fn token_with_replaced_fixture_imprint(imprint: &[u8; 32]) -> Vec<u8> {
    let mut token = fixture_timestamp_token();
    let pos = token
        .windows(chancela_tsa::mock::FIXTURE_DIGEST.len())
        .position(|w| w == chancela_tsa::mock::FIXTURE_DIGEST)
        .expect("fixture imprint present");
    token[pos..pos + imprint.len()].copy_from_slice(imprint);
    token
}

fn doc_timestamp_token_for_revision(pdf: &[u8]) -> Vec<u8> {
    let placeholder =
        add_doc_timestamp_revision(pdf, &fixture_timestamp_token()).expect("placeholder DTS");
    let report = inspect_doc_timestamps(&placeholder).expect("inspect placeholder DTS");
    let digest = report
        .validations
        .last()
        .and_then(|validation| validation.document_digest)
        .expect("DocTimeStamp ByteRange digest");
    token_with_replaced_fixture_imprint(&digest)
}

fn assert_signature_evidence_status(
    view: &Value,
    current_level: &str,
    timestamp_present: bool,
    expected_long_term_status: &str,
) {
    let evidence = &view["evidence"];
    assert_eq!(evidence["current_level"], current_level);
    assert_eq!(evidence["timestamp_evidence_present"], timestamp_present);
    assert_eq!(evidence["dss_revocation_evidence_present"], false);
    let expected_dss_status = if current_level == "Unsigned" {
        "not_applicable"
    } else {
        "not_present"
    };
    assert_eq!(
        evidence["dss_revocation_evidence_status"],
        expected_dss_status
    );
    assert_eq!(evidence["dss"]["present"], false);
    assert_eq!(evidence["dss"]["vri_count"], 0);
    assert_eq!(evidence["dss"]["ocsp_count"], 0);
    assert_eq!(evidence["dss"]["crl_count"], 0);
    assert_eq!(
        evidence["dss"]["inspection_status"],
        if current_level == "Unsigned" {
            "not_applicable"
        } else {
            "inspected_from_signed_pdf"
        }
    );
    assert_eq!(evidence["local_b_lt_style_evidence_present"], false);
    assert_eq!(evidence["production_b_lt_status"], "not_claimed");
    assert_eq!(evidence["live_revocation_fetching"], false);
    assert_eq!(evidence["legal_b_lt_claimed"], false);
    assert_eq!(evidence["status_scope"], "technical_evidence_only");
    assert!(
        evidence.get("legal_qualification").is_none(),
        "evidence status must not claim legal qualification: {evidence}"
    );
    let statuses = evidence["long_term_status"]
        .as_array()
        .expect("long_term_status array");
    for expected in [
        expected_long_term_status,
        "lt_not_implemented",
        "lt_production_not_claimed",
        "lta_not_implemented",
    ] {
        assert!(
            statuses
                .iter()
                .any(|status| status.as_str() == Some(expected)),
            "missing {expected} in long_term_status: {evidence}"
        );
    }
}

async fn sign_with_cc_timestamp_and_attach_dss(
    state: &AppState,
    token: &str,
    act_id: &str,
    signature_cert_der: &[u8],
) -> Value {
    sign_with_cc_timestamp_and_attach_dss_with_validation_time(
        state,
        token,
        act_id,
        signature_cert_der,
        None,
    )
    .await
}

async fn sign_with_cc_timestamp_and_attach_dss_with_validation_time(
    state: &AppState,
    token: &str,
    act_id: &str,
    signature_cert_der: &[u8],
    validation_time: Option<&str>,
) -> Value {
    let (status, done) = send(
        state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/cc/sign"),
            token,
            json!({ "capacity": "Administrador" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "cc sign: {done}");
    assert_eq!(done["timestamp_token"], true);

    let mut attach_body = json!({
        "certificates": [B64.encode(signature_cert_der)],
        "ocsp_responses": [B64.encode(OCSP_DER_FIXTURE)],
        "crls": [B64.encode(CRL_DER_FIXTURE)],
    });
    if let Some(validation_time) = validation_time {
        attach_body["validation_time"] = json!(validation_time);
    }

    let (status, attached) = send(
        state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/dss/attach"),
            token,
            attach_body,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "DSS attach: {attached}");
    assert_eq!(attached["evidentiary_level"], "B-LT-local");
    attached
}

// --- tests ----------------------------------------------------------------------------------------

/// The whole CC round trip for a card generation: sign → validating signed PDF, `document.signed`
/// event, chain still verifies, then the validated artifact is sealed and reported as
/// `finalizado_qualificado` — reusing t57-S3's shape.
async fn cc_round_trip(card: CcTestCard) {
    let dir = TempDir::new();
    let signature_cert_der = card.signature_cert_der.clone();
    let issuer = card.issuer_cert_der.clone();
    let factory = provider_factory(card, Some(issuer));
    let state = state_at(&dir.0, Some(factory), true, true);
    let (token, _uid) = bootstrap(&state).await;
    let act_id = seal_an_act(&state, &token).await;

    // Pre-sign: status unsigned, no signed PDF yet.
    let (_, view) = send(
        &state,
        get_req(&format!("/v1/acts/{act_id}/signature"), &token),
    )
    .await;
    assert_eq!(view["status"], "unsigned");
    assert_signature_evidence_status(&view, "Unsigned", false, "not_configured");

    // Sign with the card — no secret in the body (the PIN is at the reader).
    let (status, done) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/cc/sign"),
            &token,
            json!({ "capacity": "Administrador" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "cc sign: {done}");
    assert_eq!(done["family"], "CartaoDeCidadao");
    assert_eq!(done["evidentiary_level"], "Qualified");
    assert_eq!(done["trusted_list_status"], "Granted");
    assert_eq!(done["finalization"], "em_assinatura");
    assert_eq!(done["timestamp_token"], false);
    assert_eq!(
        done["signer_capacity_evidence"]["requested_provider_capacity"],
        "Administrador"
    );
    assert_eq!(
        done["signer_capacity_evidence"]["verification_status"],
        "not_checked_by_scap"
    );

    // The signed PDF downloads and VALIDATES (SIG-24): ByteRange covers the whole file, the signer
    // is the card's SIGNATURE leaf.
    let (status, signed_pdf) = send_bytes(
        &state,
        get_req(&format!("/v1/acts/{act_id}/document/signed"), &token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let report = validate_pdf_signature(&signed_pdf).expect("signed PDF must validate");
    assert!(report.covers_whole_file_except_contents);
    assert!(report.cades.signing_certificate_v2_present);
    assert_eq!(report.cades.signer_cert_der, signature_cert_der);

    // A `document.signed` event was appended (chained), with the CC family.
    let (_, events) = send(
        &state,
        get_req(&format!("/v1/ledger/events?scope=act:{act_id}"), &token),
    )
    .await;
    let signed_event = events
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["kind"] == "document.signed")
        .expect("document.signed event present");
    let payload_family = signed_event["payload"]["family"]
        .as_str()
        .or_else(|| signed_event["data"]["family"].as_str());
    if let Some(fam) = payload_family {
        assert_eq!(fam, "CartaoDeCidadao");
    }

    // The chain still verifies.
    let (_, verify) = send(&state, get_req("/v1/ledger/verify", &token)).await;
    assert_eq!(verify["valid"], true);

    // The signature is complete, but finalization is never claimed before the explicit seal.
    let (_, view) = send(
        &state,
        get_req(&format!("/v1/acts/{act_id}/signature"), &token),
    )
    .await;
    assert_eq!(view["status"], "signed");
    assert_eq!(view["finalization"], "em_assinatura");
    assert_eq!(view["signed"]["family"], "CartaoDeCidadao");
    assert_eq!(view["signed"]["evidentiary_level"], "Qualified");
    assert_eq!(
        view["signed"]["signer_capacity_evidence"]["requested_provider_capacity"],
        "Administrador"
    );
    assert_eq!(
        view["signed"]["signer_capacity_evidence"]["authority_reference"],
        Value::Null
    );
    assert_signature_evidence_status(&view, "B-B", false, "not_configured");

    // A second signature over the already-signed act is refused (409).
    let (status, _) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/cc/sign"),
            &token,
            json!({}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    seal_signed_act(&state, &token, &act_id).await;
    let (_, sealed_view) = send(
        &state,
        get_req(&format!("/v1/acts/{act_id}/signature"), &token),
    )
    .await;
    assert_eq!(sealed_view["status"], "signed");
    assert_eq!(sealed_view["finalization"], "finalizado_qualificado");
}

#[tokio::test]
async fn cc_v1_rsa_sign_round_trip_produces_a_validating_signed_pdf() {
    cc_round_trip(CcTestCard::cc_v1()).await;
}

#[tokio::test]
async fn cc_v2_p256_sign_round_trip_produces_a_validating_signed_pdf() {
    cc_round_trip(CcTestCard::cc_v2()).await;
}

#[tokio::test]
async fn cc_sign_timestamps_when_tsa_configured() {
    let dir = TempDir::new();
    let card = CcTestCard::cc_v1();
    let signature_cert_der = card.signature_cert_der.clone();
    let issuer = card.issuer_cert_der.clone();
    let factory = provider_factory(card, Some(issuer));
    let state = state_at(&dir.0, Some(factory), true, true);
    let tsa = MockTsaServer::granted();
    {
        let mut settings = state.settings.write().await;
        settings.signing.tsa_url = Some(tsa.url().to_owned());
        settings.signing.tsl_url = None;
    }
    let (token, _uid) = bootstrap(&state).await;
    let act_id = seal_an_act(&state, &token).await;

    let (status, done) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/cc/sign"),
            &token,
            json!({ "capacity": "Administrador" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "cc sign: {done}");
    assert_eq!(done["timestamp_token"], true);

    let (status, signed_pdf) = send_bytes(
        &state,
        get_req(&format!("/v1/acts/{act_id}/document/signed"), &token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let report = validate_pdf_signature(&signed_pdf).expect("timestamped PDF validates");
    assert!(report.covers_whole_file_except_contents);
    assert!(report.has_signature_timestamp);
    assert_eq!(report.cades.signer_cert_der, signature_cert_der);

    let stored = state
        .signed_documents
        .read()
        .await
        .get(&ActId(Uuid::parse_str(&act_id).unwrap()))
        .cloned()
        .expect("signed artifact stored");
    assert!(
        stored
            .timestamp_token_der
            .as_ref()
            .map(|token| !token.is_empty())
            .unwrap_or(false),
        "timestamp token DER stored"
    );

    let (_, view) = send(
        &state,
        get_req(&format!("/v1/acts/{act_id}/signature"), &token),
    )
    .await;
    assert_eq!(view["signed"]["timestamp_token"], true);
    assert_signature_evidence_status(&view, "B-T", true, "timestamped");
}

#[tokio::test]
async fn cc_dss_attach_api_persists_caller_supplied_local_technical_evidence() {
    let dir = TempDir::new();
    let card = CcTestCard::cc_v1();
    let signature_cert_der = card.signature_cert_der.clone();
    let issuer = card.issuer_cert_der.clone();
    let factory = provider_factory(card, Some(issuer));
    let state = state_at(&dir.0, Some(factory), true, true);
    let tsa = MockTsaServer::granted();
    {
        let mut settings = state.settings.write().await;
        settings.signing.tsa_url = Some(tsa.url().to_owned());
        settings.signing.tsl_url = None;
    }
    let (token, _uid) = bootstrap(&state).await;
    let act_id = seal_an_act(&state, &token).await;

    let (status, done) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/cc/sign"),
            &token,
            json!({ "capacity": "Administrador" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "cc sign: {done}");
    assert_eq!(done["timestamp_token"], true);

    let (status, before_pdf) = send_bytes(
        &state,
        get_req(&format!("/v1/acts/{act_id}/document/signed"), &token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let before_digest = sha256_hex(&before_pdf);

    let (status, attached) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/dss/attach"),
            &token,
            json!({
                "certificates": [B64.encode(&signature_cert_der)],
                "ocsp_responses": [B64.encode(OCSP_DER_FIXTURE)],
                "crls": [B64.encode(CRL_DER_FIXTURE)],
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "DSS attach: {attached}");
    assert_eq!(attached["act_id"], act_id);
    assert_eq!(attached["timestamp_token"], true);
    assert_eq!(attached["evidentiary_level"], "B-LT-local");
    assert_eq!(attached["production_b_lt_status"], "not_claimed");
    assert_eq!(attached["legal_b_lt_claimed"], false);
    assert_eq!(attached["status_scope"], "technical_evidence_only");
    let after_digest = attached["signed_pdf_digest"].as_str().expect("digest");
    assert_ne!(
        after_digest, before_digest,
        "DSS append updates signed PDF bytes"
    );

    let (_, view) = send(
        &state,
        get_req(&format!("/v1/acts/{act_id}/signature"), &token),
    )
    .await;
    let evidence = &view["evidence"];
    assert_eq!(evidence["current_level"], "B-LT-local");
    assert_eq!(evidence["timestamp_evidence_present"], true);
    assert_eq!(evidence["dss_revocation_evidence_present"], true);
    assert_eq!(
        evidence["dss_revocation_evidence_status"],
        "present_local_technical_only"
    );
    assert_eq!(evidence["local_b_lt_style_evidence_present"], true);
    assert_eq!(evidence["production_b_lt_status"], "not_claimed");
    assert_eq!(evidence["live_revocation_fetching"], false);
    assert_eq!(evidence["legal_b_lt_claimed"], false);
    assert_eq!(evidence["status_scope"], "technical_evidence_only");
    assert!(evidence.get("legal_qualification").is_none());
    assert_eq!(evidence["dss"]["present"], true);
    assert_eq!(evidence["dss"]["vri_count"], 1);
    assert_eq!(evidence["dss"]["vri_tu_count"], 0);
    assert_eq!(evidence["dss"]["vri_tu_keys"], json!([]));
    assert_eq!(evidence["dss"]["certificate_count"], 1);
    assert_eq!(evidence["dss"]["ocsp_count"], 1);
    assert_eq!(evidence["dss"]["crl_count"], 1);
    assert_eq!(
        evidence["dss"]["inspection_status"],
        "inspected_from_signed_pdf"
    );
    assert_eq!(evidence["dss"]["revocation_evidence_present"], true);
    assert_eq!(
        evidence["dss"]["certificate_sha256"],
        json!([sha256_hex(&signature_cert_der)])
    );
    assert_eq!(
        evidence["dss"]["ocsp_sha256"],
        json!([sha256_hex(OCSP_DER_FIXTURE)])
    );
    assert_eq!(
        evidence["dss"]["crl_sha256"],
        json!([sha256_hex(CRL_DER_FIXTURE)])
    );
    let plan = &evidence["local_technical_renewal_plan"];
    assert_eq!(plan["dss_validation_time_present"], false);
    assert_eq!(
        plan["missing_inputs"],
        json!(["dss_validation_time", "document_timestamp"])
    );
    assert_eq!(plan["next_action"], "record_dss_validation_time");
    assert_eq!(plan["production_long_term_profile_claimed"], false);
    assert_eq!(plan["legal_ltv_claimed"], false);
    let statuses = evidence["long_term_status"]
        .as_array()
        .expect("long_term_status array");
    for expected in [
        "timestamped",
        "lt_local_technical_evidence",
        "lt_production_not_claimed",
        "lta_not_implemented",
    ] {
        assert!(
            statuses
                .iter()
                .any(|status| status.as_str() == Some(expected)),
            "missing {expected} in long_term_status: {evidence}"
        );
    }

    let (status, after_pdf) = send_bytes(
        &state,
        get_req(&format!("/v1/acts/{act_id}/document/signed"), &token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(sha256_hex(&after_pdf), after_digest);
    let report = validate_pdf_signature(&after_pdf).expect("DSS-updated PDF validates");
    assert!(report.covers_signed_revision_except_contents);
    assert!(!report.covers_whole_file_except_contents);
    assert!(report.has_later_incremental_updates);
    assert!(report.has_signature_timestamp);
    assert_eq!(report.cades.signer_cert_der, signature_cert_der);

    let stored = state
        .signed_documents
        .read()
        .await
        .get(&ActId(Uuid::parse_str(&act_id).unwrap()))
        .cloned()
        .expect("signed artifact stored");
    assert_eq!(stored.signed_pdf_digest, after_digest);

    let (_, events) = send(
        &state,
        get_req(&format!("/v1/ledger/events?scope=act:{act_id}"), &token),
    )
    .await;
    assert_eq!(
        events
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| e["kind"] == "document.signed")
            .count(),
        1,
        "DSS attach must not mint a second document.signed event"
    );
    let dss_event = events
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["kind"] == "document.signature.dss_attached")
        .expect("DSS audit event present");
    assert!(
        dss_event["payload_digest"]
            .as_str()
            .is_some_and(|digest| digest.len() == 64),
        "DSS audit event carries a payload digest"
    );
}

#[tokio::test]
async fn cc_dss_attach_api_accepts_validation_time_and_reports_tu_renewal_plan() {
    let dir = TempDir::new();
    let card = CcTestCard::cc_v1();
    let signature_cert_der = card.signature_cert_der.clone();
    let issuer = card.issuer_cert_der.clone();
    let factory = provider_factory(card, Some(issuer));
    let state = state_at(&dir.0, Some(factory), true, true);
    let tsa = MockTsaServer::granted();
    {
        let mut settings = state.settings.write().await;
        settings.signing.tsa_url = Some(tsa.url().to_owned());
        settings.signing.tsl_url = None;
    }
    let (token, _uid) = bootstrap(&state).await;
    let act_id = seal_an_act(&state, &token).await;

    let attached = sign_with_cc_timestamp_and_attach_dss_with_validation_time(
        &state,
        &token,
        &act_id,
        &signature_cert_der,
        Some("2026-07-09T12:00:00Z"),
    )
    .await;

    assert_eq!(attached["act_id"], act_id);
    assert_eq!(attached["timestamp_token"], true);
    assert_eq!(attached["evidentiary_level"], "B-LT-local");
    assert_eq!(attached["production_b_lt_status"], "not_claimed");
    assert_eq!(attached["legal_b_lt_claimed"], false);
    assert_eq!(attached["status_scope"], "technical_evidence_only");

    let evidence = &attached["evidence"];
    assert_eq!(evidence["current_level"], "B-LT-local");
    assert_eq!(evidence["dss_revocation_evidence_present"], true);
    assert_eq!(evidence["local_b_lt_style_evidence_present"], true);
    assert_eq!(evidence["production_b_lt_status"], "not_claimed");
    assert_eq!(evidence["live_revocation_fetching"], false);
    assert_eq!(evidence["legal_b_lt_claimed"], false);
    assert_eq!(evidence["legal_b_lta_claimed"], false);
    assert_eq!(evidence["status_scope"], "technical_evidence_only");
    assert!(evidence.get("legal_qualification").is_none());
    assert_eq!(evidence["dss"]["present"], true);
    assert_eq!(evidence["dss"]["vri_count"], 1);
    assert_eq!(evidence["dss"]["vri_tu_count"], 1);
    assert_eq!(
        evidence["dss"]["vri_tu_keys"]
            .as_array()
            .expect("VRI /TU keys")
            .len(),
        1
    );
    assert_eq!(evidence["dss"]["revocation_evidence_present"], true);

    let plan = &evidence["local_technical_renewal_plan"];
    assert_eq!(plan["dss_validation_time_present"], true);
    assert_eq!(plan["doc_timestamp_present"], false);
    assert_eq!(plan["missing_inputs"], json!(["document_timestamp"]));
    assert_eq!(plan["next_action"], "add_document_timestamp");
    assert_eq!(plan["all_local_planning_inputs_present"], false);
    assert_eq!(plan["production_long_term_profile_claimed"], false);
    assert_eq!(plan["legal_ltv_claimed"], false);

    let (status, after_pdf) = send_bytes(
        &state,
        get_req(&format!("/v1/acts/{act_id}/document/signed"), &token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let report = validate_pdf_signature(&after_pdf).expect("DSS /TU PDF validates");
    assert_eq!(report.dss.vri_tu_count, 1);
    assert!(report.dss.has_vri_tu());
}

#[tokio::test]
async fn dss_attach_rejects_malformed_validation_time_without_digest_change_or_event() {
    let dir = TempDir::new();
    let card = CcTestCard::cc_v1();
    let signature_cert_der = card.signature_cert_der.clone();
    let issuer = card.issuer_cert_der.clone();
    let factory = provider_factory(card, Some(issuer));
    let state = state_at(&dir.0, Some(factory), true, true);
    let tsa = MockTsaServer::granted();
    {
        let mut settings = state.settings.write().await;
        settings.signing.tsa_url = Some(tsa.url().to_owned());
        settings.signing.tsl_url = None;
    }
    let (token, _uid) = bootstrap(&state).await;
    let act_id = seal_an_act(&state, &token).await;

    let (status, done) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/cc/sign"),
            &token,
            json!({ "capacity": "Administrador" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "cc sign: {done}");
    let before_digest = done["signed_pdf_digest"]
        .as_str()
        .expect("signed digest")
        .to_owned();

    let (status, err) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/dss/attach"),
            &token,
            json!({
                "certificates": [B64.encode(&signature_cert_der)],
                "ocsp_responses": [B64.encode(OCSP_DER_FIXTURE)],
                "crls": [B64.encode(CRL_DER_FIXTURE)],
                "validation_time": "not-a-time",
            }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "malformed DSS validation_time must be rejected: {err}"
    );
    assert!(
        err["error"]
            .as_str()
            .is_some_and(|msg| msg.contains("validation_time must be an RFC 3339 timestamp")),
        "unexpected error: {err}"
    );

    let (status, after_pdf) = send_bytes(
        &state,
        get_req(&format!("/v1/acts/{act_id}/document/signed"), &token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(sha256_hex(&after_pdf), before_digest);
    let stored_after = state
        .signed_documents
        .read()
        .await
        .get(&ActId(Uuid::parse_str(&act_id).unwrap()))
        .cloned()
        .expect("signed artifact still stored");
    assert_eq!(stored_after.signed_pdf_digest, before_digest);
    assert_eq!(
        event_kind_count(&state, &token, &act_id, "document.signature.dss_attached").await,
        0,
        "rejected DSS attach must not append an event"
    );
}

#[tokio::test]
async fn dss_attach_requires_an_existing_signed_pdf() {
    let dir = TempDir::new();
    let state = state_at(&dir.0, None, true, true);
    let (token, _uid) = bootstrap(&state).await;
    let act_id = seal_an_act(&state, &token).await;

    let (status, err) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/dss/attach"),
            &token,
            json!({ "ocsp_responses": [B64.encode(OCSP_DER_FIXTURE)] }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "DSS attach needs an existing signed PDF: {err}"
    );
    assert_no_signed_artifact_or_event(&state, &token, &act_id).await;
}

#[tokio::test]
async fn archive_timestamp_append_api_persists_caller_supplied_local_technical_evidence() {
    let dir = TempDir::new();
    let card = CcTestCard::cc_v1();
    let signature_cert_der = card.signature_cert_der.clone();
    let issuer = card.issuer_cert_der.clone();
    let factory = provider_factory(card, Some(issuer));
    let state = state_at(&dir.0, Some(factory), true, true);
    let tsa = MockTsaServer::granted();
    {
        let mut settings = state.settings.write().await;
        settings.signing.tsa_url = Some(tsa.url().to_owned());
        settings.signing.tsl_url = None;
    }
    let (token, _uid) = bootstrap(&state).await;
    let act_id = seal_an_act(&state, &token).await;
    sign_with_cc_timestamp_and_attach_dss_with_validation_time(
        &state,
        &token,
        &act_id,
        &signature_cert_der,
        Some("2026-07-09T12:00:00Z"),
    )
    .await;

    let (status, before_pdf) = send_bytes(
        &state,
        get_req(&format!("/v1/acts/{act_id}/document/signed"), &token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let before_digest = sha256_hex(&before_pdf);
    let stored_before = state
        .signed_documents
        .read()
        .await
        .get(&ActId(Uuid::parse_str(&act_id).unwrap()))
        .cloned()
        .expect("signed artifact stored before archive timestamp");
    let doc_timestamp_token = doc_timestamp_token_for_revision(&before_pdf);

    let (status, appended) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/archive-timestamp/append"),
            &token,
            json!({ "timestamp_token": B64.encode(&doc_timestamp_token) }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "archive timestamp append: {appended}"
    );
    assert_eq!(appended["act_id"], act_id);
    assert_eq!(appended["evidentiary_level"], "B-LTA-local");
    assert_eq!(appended["status_scope"], "technical_evidence_only");
    assert_eq!(appended["production_b_lta_status"], "not_claimed");
    assert_eq!(appended["legal_b_lta_claimed"], false);
    assert_eq!(appended["archive_timestamp_token"], true);
    let after_digest = appended["signed_pdf_digest"].as_str().expect("digest");
    assert_ne!(
        after_digest, before_digest,
        "DocTimeStamp append updates signed PDF bytes"
    );

    let evidence = &appended["evidence"];
    assert_eq!(evidence["current_level"], "B-LTA-local");
    assert_eq!(evidence["status_scope"], "technical_evidence_only");
    assert_eq!(evidence["legal_b_lta_claimed"], false);
    assert_eq!(evidence["doc_timestamp"]["present"], true);
    assert_eq!(evidence["doc_timestamp"]["count"], 1);
    assert_eq!(evidence["doc_timestamp"]["all_imprints_valid"], true);
    assert_eq!(
        evidence["doc_timestamp"]["validations"][0]["status"],
        "valid"
    );
    let plan = &evidence["local_technical_renewal_plan"];
    assert_eq!(plan["dss_validation_time_present"], true);
    assert_eq!(plan["doc_timestamp_present"], true);
    assert_eq!(plan["doc_timestamp_imprints_valid"], true);
    assert_eq!(plan["missing_inputs"], json!([]));
    assert_eq!(plan["next_action"], "monitor_timestamp_renewal");
    assert_eq!(plan["has_local_evidence_gap"], false);
    assert_eq!(plan["all_local_planning_inputs_present"], true);
    assert_eq!(plan["production_long_term_profile_claimed"], false);
    assert_eq!(plan["legal_ltv_claimed"], false);
    assert_eq!(
        appended["doc_timestamp"]["token_sha256"],
        json!([sha256_hex(&doc_timestamp_token)])
    );
    let statuses = evidence["long_term_status"]
        .as_array()
        .expect("long_term_status array");
    assert!(
        statuses
            .iter()
            .any(|status| status.as_str() == Some("lta_local_technical_evidence")),
        "missing local B-LTA technical marker: {evidence}"
    );

    let (status, after_pdf) = send_bytes(
        &state,
        get_req(&format!("/v1/acts/{act_id}/document/signed"), &token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(sha256_hex(&after_pdf), after_digest);
    let report = validate_pdf_signature(&after_pdf).expect("archive-timestamped PDF validates");
    assert!(report.covers_signed_revision_except_contents);
    assert!(report.has_later_incremental_updates);
    assert!(report.doc_timestamps.all_imprints_valid());
    assert_eq!(report.doc_timestamps.count, 1);

    let stored_after = state
        .signed_documents
        .read()
        .await
        .get(&ActId(Uuid::parse_str(&act_id).unwrap()))
        .cloned()
        .expect("signed artifact stored after archive timestamp");
    assert_eq!(stored_after.signed_pdf_digest, after_digest);
    assert_eq!(
        stored_after.signature_family,
        stored_before.signature_family
    );
    assert_eq!(
        stored_after.evidentiary_level,
        stored_before.evidentiary_level
    );
    assert_eq!(
        stored_after.timestamp_token_der,
        stored_before.timestamp_token_der
    );
    assert_ne!(
        stored_after.signed_pdf_bytes,
        stored_before.signed_pdf_bytes
    );

    assert_eq!(
        event_kind_count(&state, &token, &act_id, "document.signed").await,
        1,
        "archive timestamp append must not mint document.signed"
    );
    assert_eq!(
        event_kind_count(
            &state,
            &token,
            &act_id,
            "document.signature.archive_timestamp_appended"
        )
        .await,
        1,
        "archive timestamp audit event present"
    );
}

#[tokio::test]
async fn archive_timestamp_append_rejects_stale_token_without_digest_change_or_event() {
    let dir = TempDir::new();
    let card = CcTestCard::cc_v1();
    let signature_cert_der = card.signature_cert_der.clone();
    let issuer = card.issuer_cert_der.clone();
    let factory = provider_factory(card, Some(issuer));
    let state = state_at(&dir.0, Some(factory), true, true);
    let tsa = MockTsaServer::granted();
    {
        let mut settings = state.settings.write().await;
        settings.signing.tsa_url = Some(tsa.url().to_owned());
        settings.signing.tsl_url = None;
    }
    let (token, _uid) = bootstrap(&state).await;
    let act_id = seal_an_act(&state, &token).await;
    sign_with_cc_timestamp_and_attach_dss(&state, &token, &act_id, &signature_cert_der).await;

    let (status, before_pdf) = send_bytes(
        &state,
        get_req(&format!("/v1/acts/{act_id}/document/signed"), &token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let before_digest = sha256_hex(&before_pdf);
    let stale_token = fixture_timestamp_token();

    let (status, err) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/archive-timestamp/append"),
            &token,
            json!({ "timestamp_token": B64.encode(&stale_token) }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "stale archive timestamp token must be rejected: {err}"
    );

    let (status, after_pdf) = send_bytes(
        &state,
        get_req(&format!("/v1/acts/{act_id}/document/signed"), &token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(sha256_hex(&after_pdf), before_digest);
    let stored_after = state
        .signed_documents
        .read()
        .await
        .get(&ActId(Uuid::parse_str(&act_id).unwrap()))
        .cloned()
        .expect("signed artifact still stored");
    assert_eq!(stored_after.signed_pdf_digest, before_digest);
    assert_eq!(
        event_kind_count(
            &state,
            &token,
            &act_id,
            "document.signature.archive_timestamp_appended"
        )
        .await,
        0,
        "rejected stale token must not append an event"
    );
}

#[tokio::test]
async fn archive_timestamp_append_requires_existing_signed_pdf_in_signing() {
    let dir = TempDir::new();
    let state = state_at(&dir.0, None, true, true);
    let (token, _uid) = bootstrap(&state).await;
    let act_id = seal_an_act(&state, &token).await;

    let (status, err) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/archive-timestamp/append"),
            &token,
            json!({ "timestamp_token": B64.encode(fixture_timestamp_token()) }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "unsigned act in Signing has no signed PDF to timestamp: {err}"
    );
    assert_no_signed_artifact_or_event(&state, &token, &act_id).await;
    assert_eq!(
        event_kind_count(
            &state,
            &token,
            &act_id,
            "document.signature.archive_timestamp_appended"
        )
        .await,
        0
    );
}

#[tokio::test]
async fn cc_revocation_collection_endpoint_fails_closed_without_signer_revocation_uris() {
    let dir = TempDir::new();
    let card = CcTestCard::cc_v1();
    let issuer = card.issuer_cert_der.clone();
    let factory = provider_factory(card, Some(issuer.clone()));
    let state = state_at(&dir.0, Some(factory), true, true);
    state.settings.write().await.signing.tsa_url = None;
    let (token, _uid) = bootstrap(&state).await;
    let act_id = seal_an_act(&state, &token).await;

    let (status, done) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/cc/sign"),
            &token,
            json!({ "capacity": "Administrador" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "cc sign: {done}");
    let before_digest = done["signed_pdf_digest"]
        .as_str()
        .expect("digest")
        .to_owned();

    let (status, err) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/dss/collect-revocation"),
            &token,
            json!({
                "issuer_certificate": B64.encode(&issuer),
                "validation_time": "2026-07-09T12:00:00Z",
            }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "revocation collection should fail closed: {err}"
    );
    assert!(
        err["error"]
            .as_str()
            .is_some_and(|msg| msg.contains("sem HTTP(S)") || msg.contains("no HTTP(S)")),
        "unexpected error: {err}"
    );

    let (_, view) = send(
        &state,
        get_req(&format!("/v1/acts/{act_id}/signature"), &token),
    )
    .await;
    assert_eq!(view["signed"]["signed_pdf_digest"], before_digest);
    assert_eq!(view["evidence"]["current_level"], "B-B");
    assert_eq!(view["evidence"]["dss_revocation_evidence_present"], false);
    assert_eq!(view["evidence"]["live_revocation_fetching"], false);
    assert_eq!(view["evidence"]["legal_b_lt_claimed"], false);
}

#[tokio::test]
async fn cc_sign_rejects_withdrawn_and_unknown_trust_policy() {
    for trust_status in [TrustedListStatus::Withdrawn, TrustedListStatus::Unknown] {
        let dir = TempDir::new();
        let card = CcTestCard::cc_v1();
        let issuer = card.issuer_cert_der.clone();
        let factory = provider_factory(card, Some(issuer));
        let state = state_at_with_trust_status(&dir.0, Some(factory), trust_status, true);
        let (token, _uid) = bootstrap(&state).await;
        let act_id = seal_an_act(&state, &token).await;

        let (status, err) = send(
            &state,
            json_req(
                "POST",
                &format!("/v1/acts/{act_id}/signature/cc/sign"),
                &token,
                json!({ "capacity": "Administrador" }),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{trust_status:?} issuer must fail closed: {err}"
        );
        assert!(
            err.to_string().contains(&format!("{trust_status:?}")),
            "error reports trust outcome: {err}"
        );
        assert_no_signed_artifact_or_event(&state, &token, &act_id).await;
    }
}

#[tokio::test]
async fn cc_sign_rejects_real_tsl_source_with_invalid_signature() {
    let dir = TempDir::new();
    let card = CcTestCard::cc_v1();
    let issuer = fixture_granted_issuer_cert();
    let factory = provider_factory(card, Some(issuer));
    let mut state = state_at(&dir.0, Some(factory), true, true);
    state.cmd_trust_policy = None;
    let tsl_path = dir.0.join("invalid-signature-tsl.xml");
    std::fs::write(&tsl_path, PT_TSL_SAMPLE).expect("invalid signature TSL fixture");
    {
        let mut settings = state.settings.write().await;
        settings.signing.tsl_sources.truncate(1);
        settings.signing.tsl_sources[0].url = None;
        settings.signing.tsl_sources[0].path = Some(tsl_path.display().to_string());
        settings.signing.tsl_url = None;
        settings.signing.tsa_url = None;
        settings.signing.tsa_providers.clear();
    }
    let (token, _uid) = bootstrap(&state).await;
    let act_id = seal_an_act(&state, &token).await;

    let (status, err) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/cc/sign"),
            &token,
            json!({ "capacity": "Administrador" }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "unauthenticated TSL must fail closed: {err}"
    );
    let msg = err["error"].as_str().unwrap_or_default();
    assert!(
        msg.contains("Lista de Confiança") && msg.contains("Unknown"),
        "invalid TSL signature is reported as an unknown trust decision: {err}"
    );
    assert_no_signed_artifact_or_event(&state, &token, &act_id).await;
}

#[tokio::test]
async fn trust_refresh_rejects_unsafe_tsl_source_without_replacing_cache() {
    let dir = TempDir::new();
    let state = state_at(&dir.0, None, true, true);
    let (token, _uid) = bootstrap(&state).await;

    let (status, body) = send(
        &state,
        json_req(
            "POST",
            "/v1/trust/refresh",
            &token,
            json!({ "url": "http://127.0.0.1:9/tsl.xml" }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "unsafe TSL refresh reports status: {body}"
    );
    assert_eq!(body["outcome"], "Failed");
    assert_eq!(body["source_kind"], "Url");
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|error| error.contains("unsafe outbound URL")),
        "refresh response carries an actionable unsafe-url error: {body}"
    );
    assert!(
        !dir.0.join("tsl.xml").exists(),
        "failed TSL refresh must not install a cache"
    );
}

/// The co-location gate (CC-B): with `CHANCELA_LOCAL_SIGNING` absent (`local_signing == false`, a
/// remote server), the CC endpoint 409s and produces no signed variant.
#[tokio::test]
async fn cc_sign_409_when_not_co_located() {
    let dir = TempDir::new();
    let card = CcTestCard::cc_v1();
    let issuer = card.issuer_cert_der.clone();
    let factory = provider_factory(card, Some(issuer));
    // Injected provider present, but NOT co-located → the gate must still refuse.
    let state = state_at(&dir.0, Some(factory), true, false);
    let (token, _uid) = bootstrap(&state).await;
    let act_id = seal_an_act(&state, &token).await;

    let (status, err) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/cc/sign"),
            &token,
            json!({}),
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

    assert_no_signed_artifact_or_event(&state, &token, &act_id).await;
}

/// The RBAC gate: a session lacking `signing.perform` at the act's book is refused with 403 — even
/// when co-located and with a working card. (The RBAC check precedes the co-location check.)
#[tokio::test]
async fn cc_sign_403_for_role_without_signing_perm() {
    let dir = TempDir::new();
    let card = CcTestCard::cc_v1();
    let issuer = card.issuer_cert_der.clone();
    let factory = provider_factory(card, Some(issuer));
    let state = state_at(&dir.0, Some(factory), true, true);

    // Owner bootstraps, seals the act, and creates a second, read-only user.
    let (owner, _uid) = bootstrap(&state).await;
    let act_id = seal_an_act(&state, &owner).await;

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

    // Resolve the seeded Gestor role id (a newly-created user defaults to Gestor@Global, which HAS
    // signing.perform) and remove that default so the limited user holds no signing authority.
    let (_, roles) = send(&state, get_req("/v1/roles", &owner)).await;
    // t87: key on the stable role **id**, never the display name — seeded names are English
    // and are translated client-side, so a rename must not break this fixture. The catalog is
    // still fetched and checked, because the point here is that the role really is seeded.
    let default_role_id = chancela_authz::COMPANY_OWNER_ROLE_ID.0.to_string();
    assert!(
        roles
            .as_array()
            .expect("roles")
            .iter()
            .any(|r| r["id"] == serde_json::Value::from(default_role_id.as_str())),
        "the seeded default operator role is offered by the catalog"
    );
    let (status, _) = send(
        &state,
        json_req(
            "DELETE",
            &format!("/v1/users/{limited_id}/roles"),
            &owner,
            json!({ "role_id": default_role_id, "scope": { "kind": "global" } }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "remove default Gestor@Global");

    // The limited user (now without signing.perform) is refused.
    let limited_tok = open_session(&state, &limited_id).await;
    let (status, err) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/cc/sign"),
            &limited_tok,
            json!({}),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "no signing.perform → 403: {err}"
    );

    assert_no_signed_artifact_or_event(&state, &owner, &act_id).await;
}

/// The provider-error mapping: an un-activated qualified signature (a real card failure mode) is
/// surfaced as an honest CC 422 — distinct from a PAdES/CAdES failure — and leaves no artifact.
#[tokio::test]
async fn cc_sign_local_provider_unavailable_maps_to_honest_error() {
    let dir = TempDir::new();
    let factory: CcProviderFactory = Arc::new(|| {
        Err(SigningError::Provider(
            "simulated local provider unavailable".to_owned(),
        ))
    });
    let state = state_at(&dir.0, Some(factory), true, true);
    let (token, _uid) = bootstrap(&state).await;
    let act_id = seal_an_act(&state, &token).await;

    let (status, err) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/cc/sign"),
            &token,
            json!({}),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "local provider unavailable -> 422: {err}"
    );
    let msg = err["error"].as_str().unwrap_or_default();
    assert!(
        msg.contains("Cartão de Cidadão") && msg.contains("simulated local provider unavailable"),
        "provider outage is actionable and provider-specific: {err}"
    );
    assert_no_signed_artifact_or_event(&state, &token, &act_id).await;
}

#[tokio::test]
async fn cc_sign_provider_error_maps_to_honest_error() {
    let dir = TempDir::new();
    // The shape-only MockToken with the signature deactivated fails at sign time (like a card whose
    // qualified signature was never activated). A dummy issuer + granted policy isolate the failure
    // to signing so the TSL gate passes first.
    let token = MockToken::cartao_de_cidadao_v1().without_signature_activation();
    let factory = provider_factory(token, Some(vec![0u8; 4]));
    let state = state_at(&dir.0, Some(factory), true, true);
    let (token_s, _uid) = bootstrap(&state).await;
    let act_id = seal_an_act(&state, &token_s).await;

    let (status, err) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/cc/sign"),
            &token_s,
            json!({}),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "card failure → 422: {err}"
    );
    let msg = err["error"].as_str().unwrap_or_default();
    assert!(
        msg.contains("Cartão de Cidadão"),
        "honest CC message, distinct from a PAdES/CAdES error: {msg}"
    );
    assert!(
        !msg.contains("montar a assinatura"),
        "a card failure is NOT reported as a CMS/PDF-assembly error: {msg}"
    );

    assert_no_signed_artifact_or_event(&state, &token_s, &act_id).await;
}

// --- t67-e8: in-app CC PIN ------------------------------------------------------------------------

/// The in-app PIN happy path: a co-located CC signature with a correct in-app PIN threads the PIN to
/// the card, produces a validating qualified signature, and leaves the PIN in **no** server artifact
/// (redaction — plan §6).
#[tokio::test]
async fn cc_sign_with_in_app_pin_signs_and_redacts_pin() {
    // A distinctive PIN that would be trivial to spot if it leaked into any artifact.
    const PIN: &str = "824193";
    let dir = TempDir::new();
    let card = CcTestCard::cc_v1().requiring_pin(PIN);
    let observer = card.clone(); // shares the PIN log Arc with the per-request providers
    let signature_cert_der = card.signature_cert_der.clone();
    let issuer = card.issuer_cert_der.clone();
    let factory = provider_factory(card, Some(issuer));
    let state = state_at(&dir.0, Some(factory), true, true);
    let (token, _uid) = bootstrap(&state).await;
    let act_id = seal_an_act(&state, &token).await;

    let (status, done) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/cc/sign"),
            &token,
            json!({ "capacity": "Administrador", "pin": PIN }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "cc sign with in-app PIN: {done}");
    assert_eq!(done["family"], "CartaoDeCidadao");
    assert_eq!(done["finalization"], "em_assinatura");

    // The in-app PIN was threaded through the signing seam to the card (and only that PIN).
    assert_eq!(observer.threaded_pins(), vec![Some(PIN.to_owned())]);

    // The produced PDF validates (SIG-24), signed by the card's SIGNATURE leaf.
    let (status, signed_pdf) = send_bytes(
        &state,
        get_req(&format!("/v1/acts/{act_id}/document/signed"), &token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let report = validate_pdf_signature(&signed_pdf).expect("signed PDF must validate");
    assert!(report.covers_whole_file_except_contents);
    assert_eq!(report.cades.signer_cert_der, signature_cert_der);

    // REDACTION (plan §6): the PIN appears in NO server-visible artifact — not the sign response,
    // not any ledger event, not the signature status view.
    assert!(
        !done.to_string().contains(PIN),
        "PIN must not appear in the sign response: {done}"
    );
    let (_, events) = send(
        &state,
        get_req(&format!("/v1/ledger/events?scope=act:{act_id}"), &token),
    )
    .await;
    assert!(
        !events.to_string().contains(PIN),
        "PIN must not appear in any ledger event: {events}"
    );
    let (_, view) = send(
        &state,
        get_req(&format!("/v1/acts/{act_id}/signature"), &token),
    )
    .await;
    assert!(
        !view.to_string().contains(PIN),
        "PIN must not appear in the signature status view: {view}"
    );
}

/// A wrong in-app PIN is mapped to a structured `422` carrying `pin_status` + `tries_left`, with the
/// PIN absent from every field of the error body, and leaves no artifact behind.
#[tokio::test]
async fn cc_sign_wrong_in_app_pin_maps_to_structured_422_without_leaking_pin() {
    const CARD_PIN: &str = "824193";
    const WRONG_PIN: &str = "000111";
    let dir = TempDir::new();
    let card = CcTestCard::cc_v1().requiring_pin(CARD_PIN);
    let issuer = card.issuer_cert_der.clone();
    let factory = provider_factory(card, Some(issuer));
    let state = state_at(&dir.0, Some(factory), true, true);
    let (token, _uid) = bootstrap(&state).await;
    let act_id = seal_an_act(&state, &token).await;

    let (status, err) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/cc/sign"),
            &token,
            json!({ "pin": WRONG_PIN }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "wrong in-app PIN → structured 422: {err}"
    );
    assert_eq!(err["pin_status"], "wrong_pin");
    assert_eq!(err["tries_left"], "low");
    assert!(
        err["error"].as_str().unwrap_or_default().contains("PIN"),
        "honest PIN-incorrect message: {err}"
    );
    // Neither the presented wrong PIN nor the card's PIN may appear anywhere in the body.
    let body = err.to_string();
    assert!(
        !body.contains(WRONG_PIN) && !body.contains(CARD_PIN),
        "error body must not leak any PIN: {err}"
    );
    assert_no_signed_artifact_or_event(&state, &token, &act_id).await;
}

/// A blocked card PIN is mapped to a structured `422` with `pin_status: "blocked"`, without leaking
/// the presented PIN, and leaves no artifact behind.
#[tokio::test]
async fn cc_sign_blocked_in_app_pin_maps_to_structured_422() {
    const PIN: &str = "000111";
    let dir = TempDir::new();
    // The shape-only MockToken with a blocked user PIN rejects the login before signing. A dummy
    // issuer + granted policy isolate the failure to the PIN so the TSL gate passes first.
    let mock = MockToken::cartao_de_cidadao_v1().with_blocked_pin();
    let factory = provider_factory(mock, Some(vec![0u8; 4]));
    let state = state_at(&dir.0, Some(factory), true, true);
    let (token, _uid) = bootstrap(&state).await;
    let act_id = seal_an_act(&state, &token).await;

    let (status, err) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/cc/sign"),
            &token,
            json!({ "pin": PIN }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "blocked PIN → structured 422: {err}"
    );
    assert_eq!(err["pin_status"], "blocked");
    assert!(
        !err.to_string().contains(PIN),
        "error body must not leak the presented PIN: {err}"
    );
    assert_no_signed_artifact_or_event(&state, &token, &act_id).await;
}

/// A PIN supplied to a **non-co-located** server is refused by the co-location gate (409) before any
/// PIN is read — the honest "requires the desktop app" message, no artifact.
#[tokio::test]
async fn cc_sign_with_pin_still_409_when_not_co_located() {
    let dir = TempDir::new();
    let card = CcTestCard::cc_v1().requiring_pin("824193");
    let issuer = card.issuer_cert_der.clone();
    let factory = provider_factory(card, Some(issuer));
    let state = state_at(&dir.0, Some(factory), true, false);
    let (token, _uid) = bootstrap(&state).await;
    let act_id = seal_an_act(&state, &token).await;

    let (status, err) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/cc/sign"),
            &token,
            json!({ "pin": "824193" }),
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
    assert_no_signed_artifact_or_event(&state, &token, &act_id).await;
}

// --- visible-seal options (t67-e9) ----------------------------------------------------------------

/// A malformed *visible* seal spec (non-positive width/height) is rejected with a precise `422` — the
/// geometry validation runs before any card interaction, so nothing is signed. This exercises the
/// shared `seal_appearance_from_request` validator that every sign DTO now carries.
#[tokio::test]
async fn cc_sign_rejects_malformed_visible_seal_geometry() {
    let dir = TempDir::new();
    let card = CcTestCard::cc_v1();
    let issuer = card.issuer_cert_der.clone();
    let factory = provider_factory(card, Some(issuer));
    let state = state_at(&dir.0, Some(factory), true, true);
    let (token, _uid) = bootstrap(&state).await;
    let act_id = seal_an_act(&state, &token).await;

    let (status, err) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/cc/sign"),
            &token,
            json!({
                "seal": {
                    "invisible": false,
                    "page": 0,
                    "x": 72.0,
                    "y": 72.0,
                    "w": 0.0,
                    "h": 40.0,
                    "template": { "kind": "name_date", "name": "Amélia Marques", "date": "2026-07-12" }
                }
            }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "non-positive seal geometry → 422: {err}"
    );
    assert!(
        err["error"]
            .as_str()
            .unwrap_or_default()
            .contains("largura e a altura"),
        "the geometry error is reported: {err}"
    );
    assert_no_signed_artifact_or_event(&state, &token, &act_id).await;
}

/// The seal-options round-trip: a well-formed *visible* seal reaches the Cartão de Cidadão signing
/// path (`sign_pdf_cc_with_appearance`) and lands on the requested page. The produced PDF still
/// validates (SIG-24) and carries a real widget `/Rect` (`[x, y, x+w, y+h]`) plus an `/AP` appearance
/// stream — not the invisible `[0 0 0 0]` default. Whole-number coordinates serialize without a
/// decimal point, so the `/Rect` numbers appear verbatim in the signed bytes.
#[tokio::test]
async fn cc_sign_places_visible_seal_on_requested_page() {
    let dir = TempDir::new();
    let card = CcTestCard::cc_v1();
    let issuer = card.issuer_cert_der.clone();
    let factory = provider_factory(card, Some(issuer));
    let state = state_at(&dir.0, Some(factory), true, true);
    let (token, _uid) = bootstrap(&state).await;
    let act_id = seal_an_act(&state, &token).await;

    let (status, done) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/cc/sign"),
            &token,
            json!({
                "capacity": "Administrador",
                "seal": {
                    "invisible": false,
                    "page": 0,
                    "x": 72.0,
                    "y": 700.0,
                    "w": 180.0,
                    "h": 48.0,
                    "template": { "kind": "signed_by", "heading": "Assinado por", "name": "Amélia Marques", "date": "2026-07-12" }
                }
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "cc sign with visible seal: {done}");

    // The signed artifact validates and carries the requested visible seal.
    let (status, signed_pdf) = send_bytes(
        &state,
        get_req(&format!("/v1/acts/{act_id}/document/signed"), &token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let report = validate_pdf_signature(&signed_pdf).expect("sealed signed PDF must validate");
    assert!(report.covers_whole_file_except_contents);

    let pdf_text = String::from_utf8_lossy(&signed_pdf);
    // Real /Rect [72 700 252 748] on the requested page (72+180, 700+48) — not the invisible default.
    assert!(
        pdf_text.contains("72 700 252 748"),
        "the signed PDF carries the requested seal /Rect"
    );
    // An /AP appearance stream is present (the invisible default emits none).
    assert!(
        pdf_text.contains("/AP"),
        "the signed PDF carries an /AP appearance stream"
    );

    let (_, view) = send(
        &state,
        get_req(&format!("/v1/acts/{act_id}/signature"), &token),
    )
    .await;
    assert_eq!(view["status"], "signed");
}

/// An out-of-range seal page is refused with a clear `422` from the PAdES layer (never a panic), and
/// nothing is signed.
#[tokio::test]
async fn cc_sign_rejects_out_of_range_seal_page() {
    let dir = TempDir::new();
    let card = CcTestCard::cc_v1();
    let issuer = card.issuer_cert_der.clone();
    let factory = provider_factory(card, Some(issuer));
    let state = state_at(&dir.0, Some(factory), true, true);
    let (token, _uid) = bootstrap(&state).await;
    let act_id = seal_an_act(&state, &token).await;

    let (status, err) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/cc/sign"),
            &token,
            json!({
                "seal": {
                    "invisible": false,
                    "page": 999,
                    "x": 10.0,
                    "y": 10.0,
                    "w": 100.0,
                    "h": 40.0,
                    "template": { "kind": "name_date", "name": "Amélia Marques", "date": "2026-07-12" }
                }
            }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "out-of-range seal page → 422 (no panic): {err}"
    );
    assert_no_signed_artifact_or_event(&state, &token, &act_id).await;
}

/// An explicitly *invisible* seal (the backward-compatible default shape) is ignored: the CC signature
/// proceeds exactly as with no `seal` field at all, producing a validating signed artifact.
#[tokio::test]
async fn cc_sign_ignores_explicit_invisible_seal() {
    let dir = TempDir::new();
    let card = CcTestCard::cc_v1();
    let issuer = card.issuer_cert_der.clone();
    let factory = provider_factory(card, Some(issuer));
    let state = state_at(&dir.0, Some(factory), true, true);
    let (token, _uid) = bootstrap(&state).await;
    let act_id = seal_an_act(&state, &token).await;

    let (status, done) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/cc/sign"),
            &token,
            json!({
                "capacity": "Administrador",
                "seal": { "invisible": true, "w": 0.0, "h": 0.0 }
            }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "invisible seal is ignored, signing proceeds: {done}"
    );
    let (_, view) = send(
        &state,
        get_req(&format!("/v1/acts/{act_id}/signature"), &token),
    )
    .await;
    assert_eq!(view["status"], "signed");
}
