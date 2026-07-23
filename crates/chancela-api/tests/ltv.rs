//! t67-e9 — the long-term-validation (LTV) *execution* endpoints, end to end over the axum router.
//!
//! `POST /v1/acts/{id}/signature/ltv/execute` drives the real PAdES-B-LT/LTA pipeline (t67-e5's
//! `execute_pdf_lta`) over an act's signed PDF: fetch validated revocation evidence → embed `/DSS`+
//! `/VRI` → append a `/DocTimeStamp`. `.../ltv/renew` drives `renew_pdf_ltv`. These tests prove the
//! **endpoint wiring** and **honest failure modes** without live network:
//!
//! - RBAC: `403` for a session lacking `signing.perform` (before any I/O);
//! - `409` when the act has no signed PDF yet;
//! - `422` on a malformed issuer certificate;
//! - `422` when no TSA provider is configured (no archive timestamp is possible);
//! - **fail-closed** `422` when the signer certificate carries no HTTP(S) revocation URI, so no
//!   revocation evidence can be collected (the pipeline never fabricates evidence).
//!
//! The deep evidence mechanics (a real `/DSS`+`/DocTimeStamp` round and a renewal appending a second
//! revision) are proven against mock OCSP/CRL + TSA transports at the signing layer in
//! `chancela-signing/tests/ltv_execution.rs`; the API surface hardcodes the real HTTP revocation
//! provider (no boundary injection point), so these tests assert the wiring + honest fail-closed.
//!
//! A hardware-free, key-backed [`CryptoToken`] stands in for a citizen card (as in `cc_signing.rs`),
//! so the underlying signed PDF genuinely validates. Fictional example data only.

use crate::common;

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
use chancela_signing::{
    SignerProvider, SigningError, SmartcardProvider, StaticTrustPolicy, TrustPolicy,
    TrustedListStatus,
};
use chancela_smartcard::token::{LABEL_AUTH_CERT, LABEL_SIGNATURE_CERT};
use chancela_smartcard::{CertUsage, CryptoToken, SmartcardError, TokenCertificate};
use common::TEST_PASSWORD;
use common::tsa_http::MockTsaServer;

const OID_SHA256_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const SHA256_DIGEST_INFO_PREFIX: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

// --- A hardware-free, key-backed CryptoToken standing in for a Cartão de Cidadão ------------------

#[derive(Clone)]
struct CcTestCard {
    signature_key: Arc<rsa::RsaPrivateKey>,
    signature_cert_der: Vec<u8>,
    auth_cert_der: Vec<u8>,
    issuer_cert_der: Vec<u8>,
}

impl CcTestCard {
    fn rsa() -> Self {
        let signature = EphemeralSigner::new_rsa("Amélia Marques (assinatura)", 1);
        let auth = EphemeralSigner::new_rsa("Amélia Marques (autenticação)", 2);
        let issuer = EphemeralSigner::new_rsa("Encosto Estratégico Lda — EC Teste", 3);
        Self {
            signature_cert_der: signature.cert_der,
            auth_cert_der: auth.cert_der,
            issuer_cert_der: issuer.cert_der,
            signature_key: Arc::new(signature.key),
        }
    }
}

impl CryptoToken for CcTestCard {
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
        assert_eq!(cert.usage(), CertUsage::QualifiedSignature);
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
        _pin: Option<&str>,
    ) -> Result<RawSignature, SmartcardError> {
        self.sign_digest(cert, digest)
    }
}

struct EphemeralSigner {
    key: rsa::RsaPrivateKey,
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

struct TempDir(std::path::PathBuf);
impl TempDir {
    fn new() -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!("chancela-ltv-{}", uuid::Uuid::new_v4()));
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

fn provider_factory(token: CcTestCard, issuer_cert_der: Option<Vec<u8>>) -> CcProviderFactory {
    Arc::new(move || {
        Ok(Box::new(
            SmartcardProvider::new(token.clone()).with_issuer_certificate(issuer_cert_der.clone()),
        ))
    })
}

/// Build a co-located durable state with a granted TSL policy, the injected CC provider factory, and
/// an optional configured TSA URL.
fn state_at(dir: &std::path::Path, factory: CcProviderFactory, tsa_url: Option<&str>) -> AppState {
    let mut state = AppState::with_data_dir(dir);
    state.local_signing = true;
    state.cc_provider = Some(factory);
    {
        let mut settings = state.settings.try_write().unwrap();
        settings.signing.tsa_url = tsa_url.map(str::to_owned);
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

/// Produce a qualified CC signature over the canonical signing snapshot so an LTV round has a
/// signed PDF to upgrade before the final seal freezes the evidence tuple.
async fn cc_sign(state: &AppState, token: &str, act_id: &str) {
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
}

// --- tests ----------------------------------------------------------------------------------------

/// RBAC: a session without `signing.perform` is refused with `403` before any signed-PDF I/O.
#[tokio::test]
async fn ltv_execute_403_for_role_without_signing_perm() {
    let dir = TempDir::new();
    let card = CcTestCard::rsa();
    let issuer = card.issuer_cert_der.clone();
    let factory = provider_factory(card, Some(issuer.clone()));
    let state = state_at(&dir.0, factory, None);

    let (owner, _uid) = bootstrap(&state).await;
    let act_id = seal_an_act(&state, &owner).await;
    cc_sign(&state, &owner, &act_id).await;

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

    let limited_tok = open_session(&state, &limited_id).await;
    let (status, err) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/ltv/execute"),
            &limited_tok,
            json!({ "issuer_certificate": B64.encode(&issuer) }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "no signing.perform → 403: {err}"
    );
}

/// `409` when the act has not been signed yet — there is no PDF to upgrade.
#[tokio::test]
async fn ltv_execute_409_when_act_not_signed() {
    let dir = TempDir::new();
    let card = CcTestCard::rsa();
    let issuer = card.issuer_cert_der.clone();
    let factory = provider_factory(card, Some(issuer.clone()));
    let state = state_at(&dir.0, factory, None);
    let (token, _uid) = bootstrap(&state).await;
    let act_id = seal_an_act(&state, &token).await;

    let (status, err) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/ltv/execute"),
            &token,
            json!({ "issuer_certificate": B64.encode(&issuer) }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "unsigned act → 409: {err}");
    assert!(
        err["error"]
            .as_str()
            .unwrap_or_default()
            .contains("ainda não tem PDF assinado"),
        "honest not-signed message: {err}"
    );
}

/// `422` on a malformed issuer certificate (bad base64/DER).
#[tokio::test]
async fn ltv_execute_422_on_malformed_issuer_certificate() {
    let dir = TempDir::new();
    let card = CcTestCard::rsa();
    let issuer = card.issuer_cert_der.clone();
    let factory = provider_factory(card, Some(issuer));
    let state = state_at(&dir.0, factory, None);
    let (token, _uid) = bootstrap(&state).await;
    let act_id = seal_an_act(&state, &token).await;
    cc_sign(&state, &token, &act_id).await;

    let (status, err) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/ltv/execute"),
            &token,
            json!({ "issuer_certificate": "@@ not base64 @@" }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "malformed issuer → 422: {err}"
    );
}

/// `422` when no TSA provider is configured: without a live RFC 3161 TSA there is no archive
/// timestamp to add, so the endpoint refuses before touching revocation I/O.
#[tokio::test]
async fn ltv_execute_422_when_no_tsa_configured() {
    let dir = TempDir::new();
    let card = CcTestCard::rsa();
    let issuer = card.issuer_cert_der.clone();
    let factory = provider_factory(card, Some(issuer.clone()));
    let state = state_at(&dir.0, factory, None);
    let (token, _uid) = bootstrap(&state).await;
    let act_id = seal_an_act(&state, &token).await;
    cc_sign(&state, &token, &act_id).await;

    let (status, err) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/ltv/execute"),
            &token,
            json!({ "issuer_certificate": B64.encode(&issuer) }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "no TSA configured → 422: {err}"
    );
    assert!(
        err["error"]
            .as_str()
            .unwrap_or_default()
            .contains("carimbos temporais (TSA)"),
        "honest TSA-required message: {err}"
    );
}

/// Fail-closed `422`: with a TSA configured, LTV execution still refuses when the signer certificate
/// carries no HTTP(S) revocation URI — no revocation evidence can be collected, and the pipeline
/// never fabricates it. Nothing about the signed artifact changes.
#[tokio::test]
async fn ltv_execute_fails_closed_without_signer_revocation_uris() {
    let dir = TempDir::new();
    let card = CcTestCard::rsa();
    let issuer = card.issuer_cert_der.clone();
    let factory = provider_factory(card, Some(issuer.clone()));
    let tsa = MockTsaServer::granted();
    let state = state_at(&dir.0, factory, Some(tsa.url()));
    let (token, _uid) = bootstrap(&state).await;
    let act_id = seal_an_act(&state, &token).await;
    cc_sign(&state, &token, &act_id).await;

    let (_, before) = send(
        &state,
        get_req(&format!("/v1/acts/{act_id}/signature"), &token),
    )
    .await;
    let before_digest = before["signed"]["signed_pdf_digest"].clone();

    let (status, err) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/ltv/execute"),
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
        "no revocation URI → fail closed 422: {err}"
    );
    assert!(
        err["error"]
            .as_str()
            .unwrap_or_default()
            .contains("execução LTV"),
        "honest LTV-failure message: {err}"
    );

    // The signed artifact is unchanged (no partial revision was persisted).
    let (_, after) = send(
        &state,
        get_req(&format!("/v1/acts/{act_id}/signature"), &token),
    )
    .await;
    assert_eq!(after["signed"]["signed_pdf_digest"], before_digest);
    // A TSA is configured, so the underlying CC signature carries a signature timestamp (B-T); the
    // failed LTV round adds no DSS/DocTimeStamp, so the level is unchanged and no legal claim is made.
    assert_eq!(after["evidence"]["current_level"], "B-T");
    assert_eq!(after["evidence"]["dss_revocation_evidence_present"], false);
    assert_eq!(after["evidence"]["legal_b_lta_claimed"], false);
}

/// The renewal endpoint shares the same wiring and fails closed identically when there is no
/// revocation material to collect.
#[tokio::test]
async fn ltv_renew_fails_closed_without_signer_revocation_uris() {
    let dir = TempDir::new();
    let card = CcTestCard::rsa();
    let issuer = card.issuer_cert_der.clone();
    let factory = provider_factory(card, Some(issuer.clone()));
    let tsa = MockTsaServer::granted();
    let state = state_at(&dir.0, factory, Some(tsa.url()));
    let (token, _uid) = bootstrap(&state).await;
    let act_id = seal_an_act(&state, &token).await;
    cc_sign(&state, &token, &act_id).await;

    let (status, err) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/ltv/renew"),
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
        "renew fail closed → 422: {err}"
    );
}
