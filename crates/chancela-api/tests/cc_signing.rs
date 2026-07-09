//! t58-e2 — the synchronous Cartão de Cidadão qualified-signing API, end to end, over a MOCK card.
//!
//! Drives `POST /v1/acts/{id}/signature/cc/sign` through the axum router with an injected,
//! key-backed [`chancela_smartcard::CryptoToken`] standing in for a citizen card — so the produced
//! PDF genuinely validates (SIG-24) with no reader / PKCS#11 / hardware (t58 gate). Covers:
//!
//! - the signed round-trip for BOTH card generations (CC v1 RSA-2048, CC v2 P-256): the signed
//!   variant is persisted, a `document.signed` event is chained, the chain still verifies, and the
//!   status flips to `signed` / `finalizado_qualificado` — reusing t57-S3's store row + event shape;
//! - the **co-location gate** (CC-B): `409` when `CHANCELA_LOCAL_SIGNING` is absent (a remote server);
//! - the **RBAC gate**: `403` for a session lacking `signing.perform` at the act's book;
//! - the **provider-error mapping**: an un-activated card signature → an honest CC `422`, distinct
//!   from a PAdES/CAdES failure, and no artifact left behind.
//!
//! The PIN is entered at the reader and never enters this process — there is no PIN field anywhere in
//! the CC flow (verify the request body carries no secret). Fictional example data only: "Encosto
//! Estratégico, S.A." / "Amélia Marques" — never real names.

mod common;

use std::str::FromStr;
use std::sync::Arc;
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
use chancela_pades::validate_pdf_signature;
use chancela_signing::{
    SignerProvider, SigningError, SmartcardProvider, StaticTrustPolicy, TrustPolicy,
    TrustedListStatus,
};
use chancela_smartcard::token::{LABEL_AUTH_CERT, LABEL_SIGNATURE_CERT};
use chancela_smartcard::{CertUsage, CryptoToken, MockToken, SmartcardError, TokenCertificate};
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
        }
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
    state.settings.try_write().unwrap().signing.tsa_url = None;
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
                json!({ "username": "amelia.marques", "display_name": "Amélia Marques" })
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
            .body(Body::from(json!({ "user_id": user_id }).to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "open session: {session}");
    session["token"].as_str().expect("token").to_owned()
}

/// Seal an act (real PDF/A) as the Owner and return its id.
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

    let (status, sealed) = send(
        state,
        json_req("POST", &format!("/v1/acts/{act_id}/seal"), token, json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "seal: {sealed}");
    act_id
}

async fn signed_event_count(state: &AppState, token: &str, act_id: &str) -> usize {
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
        .filter(|e| e["kind"] == "document.signed")
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

// --- tests ----------------------------------------------------------------------------------------

/// The whole CC round trip for a card generation: sign → validating signed PDF, `document.signed`
/// event, chain still verifies, status flips to `finalizado_qualificado` — reusing t57-S3's shape.
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
    assert_eq!(done["finalization"], "finalizado_qualificado");
    assert_eq!(done["timestamp_token"], false);

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

    // Status flipped to signed / finalizado-qualificado, reported through the SAME status shape.
    let (_, view) = send(
        &state,
        get_req(&format!("/v1/acts/{act_id}/signature"), &token),
    )
    .await;
    assert_eq!(view["status"], "signed");
    assert_eq!(view["finalization"], "finalizado_qualificado");
    assert_eq!(view["signed"]["family"], "CartaoDeCidadao");
    assert_eq!(view["signed"]["evidentiary_level"], "Qualified");
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
    state.settings.write().await.signing.tsa_url = Some(tsa.url().to_owned());
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
    state.settings.write().await.signing.tsa_url = Some(tsa.url().to_owned());
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
            json!({ "username": "leitor.user", "display_name": "Leitor" }),
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
