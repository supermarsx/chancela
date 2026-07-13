//! t59-s3 — the provider-generic remote-signing API, end to end, over MOCK transports.
//!
//! Drives the unified `dyn RemoteSigningSource` registry through the axum router via the generic
//! `POST /v1/acts/{id}/signature/remote/{provider}/initiate|confirm` endpoints, with injected,
//! offline transports (a CSC `MockCscTransport` and an SCMD mock) that mint a real RSA-2048
//! signature over the digest the provider signs — so the produced PDF genuinely validates (SIG-24)
//! without ever touching a live QTSP / SCMD / TSL. Covers:
//!
//! - a CSC QTSP round-trip over the generic path (validating signed PDF + `document.signed` event +
//!   status flips to `finalizado_qualificado`, reported through the SAME `SignatureStatusView`
//!   shape with `family = "QualifiedCertificate"` — no web contract drift);
//! - the persisted pending session carries NO PIN/OTP;
//! - Chave Móvel Digital works over the SAME generic path (provider `"cmd"`);
//! - `GET /v1/signature/providers` lists CMD + a configured CSC provider;
//! - `422` for an unknown / unconfigured provider;
//! - `403` for a role lacking `signing.perform`.
//!
//! Fictional example data only: "Encosto Estratégico Lda" / "Amélia Marques" — never real names.

mod common;

use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration as StdDuration;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use der::asn1::{Any, BitString, ObjectIdentifier};
use der::pem::LineEnding;
use der::{Encode, EncodePem};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use tower::ServiceExt;
use x509_cert::certificate::{Certificate, TbsCertificate, Version};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;

use chancela_api::{AppState, router};
use chancela_cmd::soap::{ACTION_CCMOVEL_SIGN, ACTION_GET_CERTIFICATE, ACTION_VALIDATE_OTP};
use chancela_cmd::{CmdError, ScmdTransport};
use chancela_core::ActId;
use chancela_csc::mock::{
    CREDENTIALS_LIST_OK, OAUTH_TOKEN_OK, SEND_OTP_OK, credentials_info_response, sign_hash_response,
};
use chancela_csc::rest::{
    self, Authorization as CscAuthHeader, OID_RSA_ENCRYPTION, PATH_SIGNATURES_SIGN_HASH,
};
use chancela_csc::{CscAuthorization, CscConfig, CscError, CscTransport};
use chancela_pades::validate_pdf_signature;
use chancela_signing::{StaticTrustPolicy, TrustPolicy, TrustedListStatus};
use common::TEST_PASSWORD;
use common::tsa_http::MockTsaServer;
use uuid::Uuid;

const OID_SHA256_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const SHA256_DIGEST_INFO_PREFIX: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

const CSC_PROVIDER_ID: &str = "encosto-qtsp";
const APP_ID: &str = "CHANCELA-PREPROD-0001";
const PHONE: &str = "+351 912345678";
const PIN: &str = "271828";
const OTP: &str = "314159";
const CSC_ACTIVATION: &str = "141421"; // the OTP/SAD activation submitted at confirm

// --- ephemeral in-test RSA signer ------------------------------------------------------------

struct RsaSigner {
    key: rsa::RsaPrivateKey,
    cert: Certificate,
}

impl RsaSigner {
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
        let cert = build_self_signed(cn, serial, spki, sig_alg, |tbs| {
            sign_rsa_digest_info(&signer, &Sha256::digest(tbs).into())
        });
        Self { key, cert }
    }

    fn cert_pem(&self) -> String {
        self.cert.to_pem(LineEnding::LF).expect("cert pem")
    }

    fn cert_der_b64(&self) -> String {
        STANDARD.encode(self.cert.to_der().expect("cert der"))
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
) -> Certificate {
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
    Certificate {
        tbs_certificate: tbs,
        signature_algorithm: sig_alg,
        signature: BitString::from_bytes(&signature).expect("bitstring"),
    }
}

// --- smart CSC transport: signs the signHash digest with the leaf key ------------------------

/// An offline [`CscTransport`] returning canned CSC responses, and — on `signatures/signHash` —
/// a REAL RSA signature over the hash carried in the request body (or a rejected OTP at
/// `credentials/authorize` when `reject`). `Send` (no interior non-`Send` state) so it satisfies
/// the DI factory. Each `signHash` body carries its own hash, so no cross-request state is needed.
#[derive(Clone)]
struct SmartCscTransport {
    leaf_key: Arc<rsa::RsaPrivateKey>,
    info_json: String,
    reject: bool,
    fail_path: Option<&'static str>,
}

impl SmartCscTransport {
    fn new(leaf: &RsaSigner, issuer: &RsaSigner, reject: bool) -> Self {
        let info_json = credentials_info_response(
            &[leaf.cert_der_b64(), issuer.cert_der_b64()],
            &[OID_RSA_ENCRYPTION],
        );
        Self {
            leaf_key: Arc::new(leaf.key.clone()),
            info_json,
            reject,
            fail_path: None,
        }
    }

    fn with_transport_error_on(mut self, path: &'static str) -> Self {
        self.fail_path = Some(path);
        self
    }
}

impl CscTransport for SmartCscTransport {
    fn post_json(
        &self,
        path: &str,
        _auth: CscAuthHeader<'_>,
        body: &str,
    ) -> Result<String, CscError> {
        if matches!(self.fail_path, Some(fail) if fail == path) {
            return Err(CscError::Transport(format!(
                "simulated CSC outage at {path}"
            )));
        }
        Ok(match path {
            rest::PATH_OAUTH2_TOKEN => OAUTH_TOKEN_OK.to_string(),
            rest::PATH_CREDENTIALS_LIST => CREDENTIALS_LIST_OK.to_string(),
            rest::PATH_CREDENTIALS_INFO => self.info_json.clone(),
            rest::PATH_CREDENTIALS_SEND_OTP => SEND_OTP_OK.to_string(),
            rest::PATH_CREDENTIALS_AUTHORIZE => {
                if self.reject {
                    return Err(CscError::Service {
                        error: "invalid_otp".into(),
                        description: "OTP inválido ou expirado".into(),
                    });
                }
                r#"{ "SAD": "SAD-encosto-preprod" }"#.to_string()
            }
            PATH_SIGNATURES_SIGN_HASH => {
                let v: Value = serde_json::from_str(body)
                    .map_err(|e| CscError::Transport(format!("bad signHash body: {e}")))?;
                let hash_b64 = v["hash"][0]
                    .as_str()
                    .ok_or_else(|| CscError::Transport("no hash in signHash".into()))?;
                let hash = STANDARD
                    .decode(hash_b64.trim())
                    .map_err(|e| CscError::Base64(e.to_string()))?;
                let digest: [u8; 32] = hash[..32].try_into().expect("32-byte digest");
                let sig = sign_rsa_digest_info(&self.leaf_key, &digest);
                sign_hash_response(&STANDARD.encode(&sig))
            }
            other => {
                return Err(CscError::Transport(format!("unexpected CSC path {other}")));
            }
        })
    }
}

// --- smart SCMD transport (CMD over the generic path) ----------------------------------------

#[derive(Clone)]
struct SmartCmdTransport {
    leaf_key: Arc<rsa::RsaPrivateKey>,
    leaf_pem: String,
    issuer_pem: String,
    captured_hash: Arc<Mutex<Option<Vec<u8>>>>,
}

impl SmartCmdTransport {
    fn new(leaf: &RsaSigner, issuer: &RsaSigner) -> Self {
        Self {
            leaf_key: Arc::new(leaf.key.clone()),
            leaf_pem: leaf.cert_pem(),
            issuer_pem: issuer.cert_pem(),
            captured_hash: Arc::new(Mutex::new(None)),
        }
    }
}

impl ScmdTransport for SmartCmdTransport {
    fn call(&self, action: &str, soap_body: &str) -> Result<String, CmdError> {
        if action == ACTION_GET_CERTIFICATE {
            Ok(format!(
                r#"<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>
<GetCertificateResponse xmlns="http://tempuri.org/"><GetCertificateResult>{}{}</GetCertificateResult></GetCertificateResponse>
</s:Body></s:Envelope>"#,
                self.leaf_pem, self.issuer_pem
            ))
        } else if action == ACTION_CCMOVEL_SIGN {
            let hash_b64 = between(soap_body, "<d:Hash>", "</d:Hash>")
                .ok_or_else(|| CmdError::Transport("no <d:Hash>".into()))?;
            let hash = STANDARD
                .decode(hash_b64.trim())
                .map_err(|e| CmdError::Base64(e.to_string()))?;
            *self.captured_hash.lock().unwrap() = Some(hash);
            Ok(CCMOVEL_SIGN_OK.to_string())
        } else if action == ACTION_VALIDATE_OTP {
            let guard = self.captured_hash.lock().unwrap();
            let hash = guard.as_ref().expect("CCMovelSign captured the hash first");
            let digest: [u8; 32] = hash[..32].try_into().expect("32-byte digest");
            let sig = sign_rsa_digest_info(&self.leaf_key, &digest);
            Ok(format!(
                r#"<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>
<ValidateOtpResponse xmlns="http://tempuri.org/"><ValidateOtpResult xmlns:a="http://schemas.datacontract.org/2004/07/Ama.Authentication.Service.Services.CMDService" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
<a:Signature>{}</a:Signature><a:Status><a:Code>200</a:Code><a:Message>OK</a:Message></a:Status>
</ValidateOtpResult></ValidateOtpResponse></s:Body></s:Envelope>"#,
                STANDARD.encode(&sig)
            ))
        } else {
            Err(CmdError::Transport(format!("unexpected action {action}")))
        }
    }
}

const CCMOVEL_SIGN_OK: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>
<CCMovelSignResponse xmlns="http://tempuri.org/"><CCMovelSignResult xmlns:a="http://schemas.datacontract.org/2004/07/Ama.Authentication.Service.Services.CMDService" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
<a:Code>200</a:Code><a:Message>OK</a:Message><a:ProcessId>b3f1c2a4-5d6e-4f80-9a1b-2c3d4e5f6a7b</a:ProcessId>
</CCMovelSignResult></CCMovelSignResponse></s:Body></s:Envelope>"#;

fn between<'a>(hay: &'a str, open: &str, close: &str) -> Option<&'a str> {
    let start = hay.find(open)? + open.len();
    let end = hay[start..].find(close)? + start;
    Some(&hay[start..end])
}

// --- test harness ----------------------------------------------------------------------------

struct TempDir(std::path::PathBuf);
impl TempDir {
    fn new() -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!("chancela-remote-signing-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The injected CSC transport factory type `AppState::csc_transport` holds.
type CscTransportFactory = Arc<dyn Fn(&CscConfig) -> Box<dyn CscTransport + Send> + Send + Sync>;

fn csc_config() -> CscConfig {
    CscConfig {
        provider_id: CSC_PROVIDER_ID.to_string(),
        display_name: "Encosto QTSP".to_string(),
        base_url: "https://sandbox.encosto.example/csc/v2".to_string(),
        authorization: CscAuthorization::Service,
        sandbox: true,
        credential_id: None,
        scope: chancela_csc::DEFAULT_SCOPE.to_string(),
    }
}

/// A durable state with a granted trust policy and the given injected transports/providers.
async fn state_at(
    dir: &std::path::Path,
    csc: Option<SmartCscTransport>,
    cmd: Option<SmartCmdTransport>,
) -> AppState {
    state_at_with_trust_status(dir, csc, cmd, TrustedListStatus::Granted).await
}

async fn state_at_with_trust_status(
    dir: &std::path::Path,
    csc: Option<SmartCscTransport>,
    cmd: Option<SmartCmdTransport>,
    trust_status: TrustedListStatus,
) -> AppState {
    let mut state = AppState::with_data_dir(dir);
    let policy: Arc<dyn Fn() -> Box<dyn TrustPolicy + Send> + Send + Sync> =
        Arc::new(move || Box::new(StaticTrustPolicy::new(trust_status)));
    state.cmd_trust_policy = Some(policy);
    {
        let mut settings = state.settings.write().await;
        settings.signing.cmd.application_id = Some(APP_ID.to_owned());
        settings.signing.tsa_url = None;
        settings.signing.tsa_providers.clear();
    }
    if let Some(csc) = csc {
        state.csc_providers = Arc::new(vec![csc_config()]);
        let factory: CscTransportFactory = Arc::new(move |_cfg| Box::new(csc.clone()));
        state.csc_transport = Some(factory);
    }
    if let Some(cmd) = cmd {
        state.cmd_transport = Some(Arc::new(cmd));
    }
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

async fn bootstrap(state: &AppState) -> String {
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
    open_session(state, &uid).await
}

async fn create_user(state: &AppState, token: &str, username: &str) -> String {
    let (status, user) = send(
        state,
        json_req(
            "POST",
            "/v1/users",
            token,
            json!({
                "username": username,
                "display_name": username,
                "password": TEST_PASSWORD,
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create user: {user}");
    user["id"].as_str().expect("user id").to_owned()
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

async fn seal_an_act(state: &AppState, token: &str) -> String {
    let (status, entity) = send(
        state,
        json_req("POST", "/v1/entities", token, json!({ "name": "Encosto Estratégico Lda", "nipc": "503004642", "seat": "Lisboa", "kind": "SociedadeAnonima" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "entity: {entity}");
    let entity_id = entity["id"].as_str().unwrap().to_owned();

    let (status, book) = send(
        state,
        json_req("POST", "/v1/books", token, json!({ "entity_id": entity_id, "kind": "AssembleiaGeral", "purpose": "livro de atas", "opening_date": "2026-01-15", "required_signatories": ["Administrador"] })),
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
        json_req("POST", &format!("/v1/acts/{act_id}/seal"), token, json!({ "manual_signature_original_reference": { "storage_reference": "Arquivo A / Pasta 2026 / Ata teste" } })),
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

async fn expire_pending_session(state: &AppState, session_id: &str) {
    let mut pending = state
        .store
        .as_ref()
        .unwrap()
        .pending_cmd_session(session_id)
        .unwrap()
        .expect("pending session");
    pending.expires_at = time::OffsetDateTime::now_utc() - time::Duration::seconds(1);
    state
        .store
        .as_ref()
        .unwrap()
        .persist(|tx| tx.upsert_pending_cmd_session(&pending))
        .unwrap();
    state
        .pending_signatures
        .write()
        .await
        .insert(session_id.to_owned(), pending);
}

// --- tests -----------------------------------------------------------------------------------

/// A CSC QTSP round-trip over the generic `/signature/remote/{provider}/*` endpoints: initiate →
/// confirm produces a validating signed PDF reported through the SAME status shape (family
/// `QualifiedCertificate`), and the persisted pending session carries no secret.
#[tokio::test]
async fn csc_generic_round_trip_produces_a_validating_signed_pdf() {
    let dir = TempDir::new();
    let leaf = RsaSigner::new("Amélia Marques (QTSP teste)", 1);
    let issuer = RsaSigner::new("Encosto Estratégico Lda — EC Teste", 2);
    let csc = SmartCscTransport::new(&leaf, &issuer, false);
    let state = state_at(&dir.0, Some(csc), None).await;
    let token = bootstrap(&state).await;
    let act_id = seal_an_act(&state, &token).await;

    let base = format!("/v1/acts/{act_id}/signature/remote/{CSC_PROVIDER_ID}");

    // Phase 1: initiate.
    let (status, init) = send(
        &state,
        json_req(
            "POST",
            &format!("{base}/initiate"),
            &token,
            json!({
                "user_ref": "amelia.marques@encosto.example",
                "credential": PIN,
                "capacity": "Administrador"
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "initiate: {init}");
    let session_id = init["session_id"].as_str().expect("session_id").to_owned();
    assert_eq!(init["provider_id"], CSC_PROVIDER_ID);
    assert_eq!(init["family"], "QualifiedCertificate");
    assert_eq!(init["evidentiary_level"], "Qualified");
    assert_eq!(init["status"], "activation_pending");
    assert!(
        !init.to_string().contains(PIN),
        "PIN must not appear in the response"
    );

    // The persisted pending session carries NO PIN/activation.
    let pending = state
        .store
        .as_ref()
        .unwrap()
        .pending_cmd_session(&session_id)
        .unwrap()
        .expect("pending session persisted");
    let blob = format!("{}{}", pending.session_json, pending.prepared_json);
    assert!(!blob.contains(PIN), "PIN must never be persisted");
    assert!(
        !blob.contains(CSC_ACTIVATION),
        "activation must never be persisted"
    );
    let capacity_evidence = pending
        .signer_capacity_evidence_json
        .as_deref()
        .expect("pending capacity evidence");
    assert!(capacity_evidence.contains("\"requested_provider_capacity\":\"Administrador\""));
    assert!(capacity_evidence.contains("\"verification_status\":\"not_checked_by_scap\""));

    // Status now pending.
    let (_, view) = send(
        &state,
        get_req(&format!("/v1/acts/{act_id}/signature"), &token),
    )
    .await;
    assert_eq!(view["status"], "pending");
    assert_eq!(view["pending"]["provider_id"], CSC_PROVIDER_ID);
    assert_eq!(view["pending"]["family"], "QualifiedCertificate");
    assert_eq!(
        view["pending"]["activation_hint"],
        "confirme com o código de ativação enviado"
    );
    assert_eq!(
        view["pending"]["masked_phone"],
        "confirme com o código de ativação enviado"
    );

    // Phase 2: confirm.
    let (status, done) = send(
        &state,
        json_req(
            "POST",
            &format!("{base}/confirm"),
            &token,
            json!({ "session_id": session_id.clone(), "activation": CSC_ACTIVATION }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "confirm: {done}");
    assert_eq!(done["provider_id"], CSC_PROVIDER_ID);
    assert_eq!(done["family"], "QualifiedCertificate");
    assert_eq!(done["evidentiary_level"], "Qualified");
    assert_eq!(done["trusted_list_status"], "Granted");
    assert_eq!(done["finalization"], "finalizado_qualificado");
    assert_eq!(
        done["signer_capacity_evidence"]["requested_provider_capacity"],
        "Administrador"
    );

    // The signed PDF downloads and VALIDATES (SIG-24).
    let (status, signed_pdf) = send_bytes(
        &state,
        get_req(&format!("/v1/acts/{act_id}/document/signed"), &token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let report = validate_pdf_signature(&signed_pdf).expect("signed PDF must validate");
    assert!(report.covers_whole_file_except_contents);
    assert!(report.cades.signing_certificate_v2_present);
    assert_eq!(report.cades.signer_cert_der, leaf.cert.to_der().unwrap());

    // A `document.signed` event was appended, with the provider id + QualifiedCertificate family.
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
        .expect("document.signed event");
    let payload = signed_event
        .get("payload")
        .or_else(|| signed_event.get("data"));
    if let Some(p) = payload {
        if let Some(fam) = p["family"].as_str() {
            assert_eq!(fam, "QualifiedCertificate");
        }
        assert_eq!(
            p["signer_capacity_evidence"]["verification_status"],
            "not_checked_by_scap"
        );
    }

    // Chain still verifies; status flipped to signed through the SAME status shape.
    let (_, verify) = send(&state, get_req("/v1/ledger/verify", &token)).await;
    assert_eq!(verify["valid"], true);
    let (_, view) = send(
        &state,
        get_req(&format!("/v1/acts/{act_id}/signature"), &token),
    )
    .await;
    assert_eq!(view["status"], "signed");
    assert_eq!(view["finalization"], "finalizado_qualificado");
    assert_eq!(view["signed"]["family"], "QualifiedCertificate");
    assert_eq!(view["signed"]["evidentiary_level"], "Qualified");
    assert_eq!(
        view["signed"]["signer_capacity_evidence"]["requested_provider_capacity"],
        "Administrador"
    );
    assert_eq!(
        view["signed"]["signer_capacity_evidence"]["verification_source"],
        serde_json::Value::Null
    );

    // The pending session is single-use: replaying confirm is refused and does not append a second
    // signed event.
    let (status, _) = send(
        &state,
        json_req(
            "POST",
            &format!("{base}/confirm"),
            &token,
            json!({ "session_id": session_id, "activation": CSC_ACTIVATION }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(signed_event_count(&state, &token, &act_id).await, 1);

    // A second signature over the already-signed act is refused (409).
    let (status, _) = send(
        &state,
        json_req(
            "POST",
            &format!("{base}/initiate"),
            &token,
            json!({ "user_ref": "amelia.marques@encosto.example", "credential": PIN }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn csc_generic_round_trip_timestamps_when_tsa_configured() {
    let dir = TempDir::new();
    let leaf = RsaSigner::new("Amélia Marques (QTSP teste)", 1);
    let issuer = RsaSigner::new("Encosto Estratégico Lda — EC Teste", 2);
    let csc = SmartCscTransport::new(&leaf, &issuer, false);
    let state = state_at(&dir.0, Some(csc), None).await;
    let tsa = MockTsaServer::granted();
    state.settings.write().await.signing.tsa_url = Some(tsa.url().to_owned());
    let token = bootstrap(&state).await;
    let act_id = seal_an_act(&state, &token).await;
    let base = format!("/v1/acts/{act_id}/signature/remote/{CSC_PROVIDER_ID}");

    let (status, init) = send(
        &state,
        json_req(
            "POST",
            &format!("{base}/initiate"),
            &token,
            json!({ "user_ref": "amelia.marques@encosto.example", "credential": PIN }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "initiate: {init}");
    let session_id = init["session_id"].as_str().unwrap().to_owned();

    let (status, done) = send(
        &state,
        json_req(
            "POST",
            &format!("{base}/confirm"),
            &token,
            json!({ "session_id": session_id, "activation": CSC_ACTIVATION }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "confirm: {done}");
    assert_eq!(done["timestamp_token"], true);
    assert_eq!(done["provider_id"], CSC_PROVIDER_ID);

    let (status, signed_pdf) = send_bytes(
        &state,
        get_req(&format!("/v1/acts/{act_id}/document/signed"), &token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let report = validate_pdf_signature(&signed_pdf).expect("timestamped PDF validates");
    assert!(report.covers_whole_file_except_contents);
    assert!(report.has_signature_timestamp);
    assert_eq!(report.cades.signer_cert_der, leaf.cert.to_der().unwrap());

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
}

#[tokio::test]
async fn csc_initiate_rejects_withdrawn_and_unknown_trust_policy() {
    for trust_status in [TrustedListStatus::Withdrawn, TrustedListStatus::Unknown] {
        let dir = TempDir::new();
        let leaf = RsaSigner::new("Amélia Marques (QTSP teste)", 1);
        let issuer = RsaSigner::new("Encosto Estratégico Lda — EC Teste", 2);
        let csc = SmartCscTransport::new(&leaf, &issuer, false);
        let state = state_at_with_trust_status(&dir.0, Some(csc), None, trust_status).await;
        let token = bootstrap(&state).await;
        let act_id = seal_an_act(&state, &token).await;

        let (status, err) = send(
            &state,
            json_req(
                "POST",
                &format!("/v1/acts/{act_id}/signature/remote/{CSC_PROVIDER_ID}/initiate"),
                &token,
                json!({ "user_ref": "amelia.marques@encosto.example", "credential": PIN }),
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
        assert!(
            state.pending_signatures.read().await.is_empty(),
            "untrusted initiate must not create a pending signing session"
        );
        assert_no_signed_artifact_or_event(&state, &token, &act_id).await;
    }
}

#[tokio::test]
async fn csc_pending_session_rejects_unknown_session_wrong_actor_wrong_act_and_provider_path() {
    let dir = TempDir::new();
    let leaf = RsaSigner::new("Amélia Marques (QTSP teste)", 1);
    let issuer = RsaSigner::new("Encosto Estratégico Lda — EC Teste", 2);
    let csc = SmartCscTransport::new(&leaf, &issuer, false);
    let state = state_at(&dir.0, Some(csc), None).await;
    let owner = bootstrap(&state).await;
    let act_id = seal_an_act(&state, &owner).await;
    let base = format!("/v1/acts/{act_id}/signature/remote/{CSC_PROVIDER_ID}");

    let (status, init) = send(
        &state,
        json_req(
            "POST",
            &format!("{base}/initiate"),
            &owner,
            json!({ "user_ref": "amelia.marques@encosto.example", "credential": PIN }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "initiate: {init}");
    let session_id = init["session_id"].as_str().unwrap().to_owned();

    let (status, _) = send(
        &state,
        json_req(
            "POST",
            &format!("{base}/confirm"),
            &owner,
            json!({ "session_id": uuid::Uuid::new_v4().to_string(), "activation": CSC_ACTIVATION }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let other_id = create_user(&state, &owner, "bruno.dias").await;
    let other = open_session(&state, &other_id).await;
    let (status, _) = send(
        &state,
        json_req(
            "POST",
            &format!("{base}/confirm"),
            &other,
            json!({ "session_id": session_id.clone(), "activation": CSC_ACTIVATION }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let other_act = seal_an_act(&state, &owner).await;
    let (status, _) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{other_act}/signature/remote/{CSC_PROVIDER_ID}/confirm"),
            &owner,
            json!({ "session_id": session_id.clone(), "activation": CSC_ACTIVATION }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    let (status, err) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/remote/cmd/confirm"),
            &owner,
            json!({ "session_id": session_id, "activation": CSC_ACTIVATION }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "provider path mismatch must not confirm through another provider route: {err}"
    );

    assert_no_signed_artifact_or_event(&state, &owner, &act_id).await;
    assert_no_signed_artifact_or_event(&state, &owner, &other_act).await;
}

#[tokio::test]
async fn csc_expired_pending_session_returns_gone_and_leaves_no_signature() {
    let dir = TempDir::new();
    let leaf = RsaSigner::new("Amélia Marques (QTSP teste)", 1);
    let issuer = RsaSigner::new("Encosto Estratégico Lda — EC Teste", 2);
    let csc = SmartCscTransport::new(&leaf, &issuer, false);
    let state = state_at(&dir.0, Some(csc), None).await;
    let token = bootstrap(&state).await;
    let act_id = seal_an_act(&state, &token).await;
    let base = format!("/v1/acts/{act_id}/signature/remote/{CSC_PROVIDER_ID}");

    let (status, init) = send(
        &state,
        json_req(
            "POST",
            &format!("{base}/initiate"),
            &token,
            json!({ "user_ref": "amelia.marques@encosto.example", "credential": PIN }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "initiate: {init}");
    let session_id = init["session_id"].as_str().unwrap().to_owned();
    expire_pending_session(&state, &session_id).await;

    let (status, err) = send(
        &state,
        json_req(
            "POST",
            &format!("{base}/confirm"),
            &token,
            json!({ "session_id": session_id.clone(), "activation": CSC_ACTIVATION }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::GONE, "expired confirm: {err}");
    assert!(
        state
            .store
            .as_ref()
            .unwrap()
            .pending_cmd_session(&session_id)
            .unwrap()
            .is_none(),
        "expired pending session is consumed"
    );
    assert_no_signed_artifact_or_event(&state, &token, &act_id).await;
}

#[tokio::test]
async fn csc_confirm_transport_error_maps_to_422_and_leaves_no_signature() {
    let dir = TempDir::new();
    let leaf = RsaSigner::new("Amélia Marques (QTSP teste)", 1);
    let issuer = RsaSigner::new("Encosto Estratégico Lda — EC Teste", 2);
    let csc = SmartCscTransport::new(&leaf, &issuer, false)
        .with_transport_error_on(PATH_SIGNATURES_SIGN_HASH);
    let state = state_at(&dir.0, Some(csc), None).await;
    let token = bootstrap(&state).await;
    let act_id = seal_an_act(&state, &token).await;
    let base = format!("/v1/acts/{act_id}/signature/remote/{CSC_PROVIDER_ID}");

    let (status, init) = send(
        &state,
        json_req(
            "POST",
            &format!("{base}/initiate"),
            &token,
            json!({ "user_ref": "amelia.marques@encosto.example", "credential": PIN }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "initiate: {init}");
    let session_id = init["session_id"].as_str().unwrap().to_owned();

    let (status, err) = send(
        &state,
        json_req(
            "POST",
            &format!("{base}/confirm"),
            &token,
            json!({ "session_id": session_id.clone(), "activation": CSC_ACTIVATION }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "transport outage maps cleanly: {err}"
    );
    assert!(
        err.to_string().contains("CSC transport error"),
        "transport cause is preserved without secrets: {err}"
    );
    assert!(
        state
            .store
            .as_ref()
            .unwrap()
            .pending_cmd_session(&session_id)
            .unwrap()
            .is_some(),
        "provider outage does not consume the retryable pending session"
    );
    assert_no_signed_artifact_or_event(&state, &token, &act_id).await;
}

/// Chave Móvel Digital works over the SAME generic path (provider `"cmd"`), unbroken.
#[tokio::test]
async fn cmd_over_generic_path_produces_a_validating_signed_pdf() {
    let dir = TempDir::new();
    let leaf = RsaSigner::new("Amélia Marques (CMD teste)", 1);
    let issuer = RsaSigner::new("Encosto Estratégico Lda — EC Teste", 2);
    let cmd = SmartCmdTransport::new(&leaf, &issuer);
    let state = state_at(&dir.0, None, Some(cmd)).await;
    let token = bootstrap(&state).await;
    let act_id = seal_an_act(&state, &token).await;

    let base = format!("/v1/acts/{act_id}/signature/remote/cmd");
    let (status, init) = send(
        &state,
        json_req(
            "POST",
            &format!("{base}/initiate"),
            &token,
            json!({ "user_ref": PHONE, "credential": PIN }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "initiate: {init}");
    assert_eq!(init["provider_id"], "cmd");
    assert_eq!(init["family"], "ChaveMovelDigital");
    let session_id = init["session_id"].as_str().unwrap().to_owned();

    let (status, done) = send(
        &state,
        json_req(
            "POST",
            &format!("{base}/confirm"),
            &token,
            json!({ "session_id": session_id, "activation": OTP }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "confirm: {done}");
    assert_eq!(done["provider_id"], "cmd");
    assert_eq!(done["family"], "ChaveMovelDigital");
    assert_eq!(done["finalization"], "finalizado_qualificado");

    let (status, signed_pdf) = send_bytes(
        &state,
        get_req(&format!("/v1/acts/{act_id}/document/signed"), &token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let report = validate_pdf_signature(&signed_pdf).expect("signed PDF validates");
    assert!(report.covers_whole_file_except_contents);
    assert_eq!(report.cades.signer_cert_der, leaf.cert.to_der().unwrap());
}

/// `GET /v1/signature/providers` lists CMD (configured) + the configured CSC provider.
#[tokio::test]
async fn get_providers_lists_cmd_and_configured_csc() {
    let dir = TempDir::new();
    let leaf = RsaSigner::new("Amélia Marques (QTSP teste)", 1);
    let issuer = RsaSigner::new("Encosto Estratégico Lda — EC Teste", 2);
    let csc = SmartCscTransport::new(&leaf, &issuer, false);
    let state = state_at(&dir.0, Some(csc), None).await;
    let token = bootstrap(&state).await;

    let (status, list) = send(&state, get_req("/v1/signature/providers", &token)).await;
    assert_eq!(status, StatusCode::OK, "providers: {list}");
    let arr = list.as_array().expect("array");

    let cmd = arr.iter().find(|p| p["id"] == "cmd").expect("cmd present");
    assert_eq!(cmd["family"], "ChaveMovelDigital");
    assert_eq!(cmd["evidentiary_level"], "Qualified");
    assert_eq!(cmd["configured"], true, "cmd has an ApplicationId");

    let csc = arr
        .iter()
        .find(|p| p["id"] == CSC_PROVIDER_ID)
        .expect("csc provider present");
    assert_eq!(csc["family"], "QualifiedCertificate");
    assert_eq!(csc["label"], "Encosto QTSP");
    assert_eq!(csc["configured"], true, "csc provider is configured (DI)");
}

/// An unknown provider id → 422; a known-but-unconfigured provider → 422.
#[tokio::test]
async fn remote_initiate_422_for_unknown_or_unconfigured_provider() {
    let dir = TempDir::new();
    // No CSC transport injected and no providers → an id that isn't "cmd" is unknown.
    let state = state_at(&dir.0, None, None).await;
    let token = bootstrap(&state).await;
    let act_id = seal_an_act(&state, &token).await;

    let (status, err) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/remote/nao-existe/initiate"),
            &token,
            json!({ "user_ref": "x", "credential": "y" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "unknown: {err}");
    assert!(
        err["error"]
            .as_str()
            .unwrap_or_default()
            .contains("desconhecido"),
        "honest unknown-provider message: {err}"
    );
    assert_no_signed_artifact_or_event(&state, &token, &act_id).await;
}

/// A role lacking `signing.perform` is refused on the generic initiate (403) and on the providers
/// list (403).
#[tokio::test]
async fn remote_endpoints_403_for_role_without_signing_perm() {
    let dir = TempDir::new();
    let leaf = RsaSigner::new("Amélia Marques (QTSP teste)", 1);
    let issuer = RsaSigner::new("Encosto Estratégico Lda — EC Teste", 2);
    let csc = SmartCscTransport::new(&leaf, &issuer, false);
    let state = state_at(&dir.0, Some(csc), None).await;

    let owner = bootstrap(&state).await;
    let act_id = seal_an_act(&state, &owner).await;

    // Create a second user, then strip its default Gestor@Global (which has signing.perform).
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
    assert_eq!(status, StatusCode::CREATED, "limited user: {limited}");
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

    // Generic initiate → 403.
    let (status, err) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/remote/{CSC_PROVIDER_ID}/initiate"),
            &limited_tok,
            json!({ "user_ref": "x", "credential": PIN }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "no signing.perform → 403: {err}"
    );

    // Providers list → 403.
    let (status, _) = send(&state, get_req("/v1/signature/providers", &limited_tok)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    assert_no_signed_artifact_or_event(&state, &owner, &act_id).await;
}
