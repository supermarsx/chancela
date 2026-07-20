//! t57-S3 — the qualified Chave Móvel Digital signing API, end to end, over a MOCK SCMD transport.
//!
//! Drives the real two-phase state machine through the axum router (`initiate` → `confirm`) with an
//! injected, offline SCMD transport that mints a real RSA-2048 signature over the signed-attributes
//! digest CMD would sign — so the produced PDF genuinely validates (SIG-24) while never touching the
//! live SCMD/TSL network (t57 gate). Covers: the signed round-trip (validates + `document.signed`
//! event + status flips), session survival across a restart, PIN/OTP never persisted, a wrong OTP,
//! and that `require_qualified_for_seal` gates the STATUS, not the seal.
//!
//! Fictional example data only: "Encosto Estratégico, S.A." / "Amélia Marques" — never real names.

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
use tokio::sync::RwLock as AsyncRwLock;
use tower::ServiceExt;
use x509_cert::certificate::{Certificate, TbsCertificate, Version};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;

use chancela_api::{
    AppState, CmdCredentialFields, CmdEnvSetting, CredentialFieldSet, CredentialMode, router,
};
use chancela_cmd::soap::{ACTION_CCMOVEL_SIGN, ACTION_GET_CERTIFICATE, ACTION_VALIDATE_OTP};
use chancela_cmd::{CmdError, ScmdTransport};
use chancela_core::ActId;
use chancela_pades::validate_pdf_signature;
use chancela_signing::{StaticTrustPolicy, TrustPolicy, TrustedListStatus};
use common::TEST_PASSWORD;
use common::tsa_http::MockTsaServer;
use uuid::Uuid;
use zeroize::Zeroizing;

const OID_SHA256_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const SHA256_DIGEST_INFO_PREFIX: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

const APP_ID: &str = "CHANCELA-PREPROD-0001";
const PHONE: &str = "+351 912345678";
const PIN: &str = "271828";
const OTP: &str = "314159";
const CMD_ENV_KEYS: [&str; 5] = [
    "CHANCELA_CMD_ENV",
    "CHANCELA_CMD_APPLICATION_ID",
    "CHANCELA_CMD_HTTP_BASIC_USERNAME",
    "CHANCELA_CMD_HTTP_BASIC_PASSWORD",
    "CHANCELA_CMD_AMA_CERT_PEM",
];
const PROVIDER_CREDENTIAL_ENV_KEYS: [&str; 3] = [
    "CHANCELA_CREDENTIAL_KEY",
    "CHANCELA_CREDENTIAL_KEY_FILE",
    "CHANCELA_CREDENTIAL_STRICT",
];
/// Serializes access to the process-global `CHANCELA_CMD_*` / `CHANCELA_CREDENTIAL_*` env vars.
///
/// Every test drives `resolve_cmd_config`, which falls back to `CmdConfig::from_env()` whenever a
/// test has no stored provider credentials — so ALL tests *read* these env vars during `initiate`.
/// The env-*mutating* tests take the write lock (exclusive); the env-*reading* happy-path tests take
/// the read lock (shared, so they still run in parallel with each other) but never overlap a mutator.
/// Without this, a mutator's transient malformed-env fixture could leak into a concurrent happy-path
/// test's `initiate` and spuriously flip it to 422 — the long-standing parallel-test race.
static ENV_LOCK: AsyncRwLock<()> = AsyncRwLock::const_new(());

// --- ephemeral in-test RSA signer (mirrors chancela-pades/signing tests) ----------------------

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

// --- the smart mock transport: signs the captured signed-attrs digest at ValidateOtp ----------

/// An offline `ScmdTransport` that returns the ephemeral certificate on `GetCertificate`, captures
/// the CAdES signed-attributes digest sent in `CCMovelSign`, and — on `ValidateOtp` — returns a real
/// RSA signature over that captured digest (or a rejection when `reject_otp`). `Send + Sync` so it
/// satisfies the shared `AppState`; the captured digest is shared so an initiate/confirm pair split
/// across a restart (two `AppState`s cloning this transport) still lines up.
#[derive(Clone)]
struct SmartCmdTransport {
    leaf_key: Arc<rsa::RsaPrivateKey>,
    leaf_pem: String,
    issuer_pem: String,
    captured_hash: Arc<Mutex<Option<Vec<u8>>>>,
    reject_otp: bool,
    fail_action: Option<&'static str>,
    expected_application_id_b64: Option<String>,
}

impl SmartCmdTransport {
    fn new(leaf: &RsaSigner, issuer: &RsaSigner, reject_otp: bool) -> Self {
        Self {
            leaf_key: Arc::new(leaf.key.clone()),
            leaf_pem: leaf.cert_pem(),
            issuer_pem: issuer.cert_pem(),
            captured_hash: Arc::new(Mutex::new(None)),
            reject_otp,
            fail_action: None,
            expected_application_id_b64: None,
        }
    }

    fn with_transport_error_on(mut self, action: &'static str) -> Self {
        self.fail_action = Some(action);
        self
    }

    fn expect_application_id(mut self, application_id: &str) -> Self {
        self.expected_application_id_b64 = Some(STANDARD.encode(application_id.as_bytes()));
        self
    }

    fn assert_expected_application_id(&self, soap_body: &str) -> Result<(), CmdError> {
        if let Some(expected) = &self.expected_application_id_b64
            && !soap_body.contains(expected)
        {
            return Err(CmdError::Transport(
                "unexpected CMD application id source".to_owned(),
            ));
        }
        Ok(())
    }
}

impl ScmdTransport for SmartCmdTransport {
    fn call(&self, action: &str, soap_body: &str) -> Result<String, CmdError> {
        if matches!(self.fail_action, Some(fail) if fail == action) {
            return Err(CmdError::Transport(format!(
                "simulated SCMD outage at {action}"
            )));
        }
        self.assert_expected_application_id(soap_body)?;
        if action == ACTION_GET_CERTIFICATE {
            Ok(get_certificate_response(&self.leaf_pem, &self.issuer_pem))
        } else if action == ACTION_CCMOVEL_SIGN {
            let hash_b64 = between(soap_body, "<d:Hash>", "</d:Hash>")
                .ok_or_else(|| CmdError::Transport("no <d:Hash> in CCMovelSign".into()))?;
            let hash = STANDARD
                .decode(hash_b64.trim())
                .map_err(|e| CmdError::Base64(e.to_string()))?;
            *self.captured_hash.lock().unwrap() = Some(hash);
            Ok(CCMOVEL_SIGN_OK.to_string())
        } else if action == ACTION_VALIDATE_OTP {
            if self.reject_otp {
                return Ok(VALIDATE_OTP_REJECTED.to_string());
            }
            let guard = self.captured_hash.lock().unwrap();
            let hash = guard.as_ref().expect("CCMovelSign captured the hash first");
            let digest: [u8; 32] = hash[..32].try_into().expect("32-byte digest");
            let sig = sign_rsa_digest_info(&self.leaf_key, &digest);
            Ok(validate_otp_response(&STANDARD.encode(&sig)))
        } else {
            Err(CmdError::Transport(format!("unexpected action {action}")))
        }
    }
}

/// The shallowest substring between `open` and `close` (good enough for the well-formed envelopes).
fn between<'a>(hay: &'a str, open: &str, close: &str) -> Option<&'a str> {
    let start = hay.find(open)? + open.len();
    let end = hay[start..].find(close)? + start;
    Some(&hay[start..end])
}

const CCMOVEL_SIGN_OK: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <CCMovelSignResponse xmlns="http://tempuri.org/">
      <CCMovelSignResult xmlns:a="http://schemas.datacontract.org/2004/07/Ama.Authentication.Service.Services.CMDService" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
        <a:Code>200</a:Code>
        <a:Message>Confirme com o OTP enviado.</a:Message>
        <a:ProcessId>b3f1c2a4-5d6e-4f80-9a1b-2c3d4e5f6a7b</a:ProcessId>
      </CCMovelSignResult>
    </CCMovelSignResponse>
  </s:Body>
</s:Envelope>"#;

const VALIDATE_OTP_REJECTED: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <ValidateOtpResponse xmlns="http://tempuri.org/">
      <ValidateOtpResult xmlns:a="http://schemas.datacontract.org/2004/07/Ama.Authentication.Service.Services.CMDService" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
        <a:Signature i:nil="true"/>
        <a:Status><a:Code>402</a:Code><a:Message>OTP inválido ou expirado.</a:Message></a:Status>
      </ValidateOtpResult>
    </ValidateOtpResponse>
  </s:Body>
</s:Envelope>"#;

fn get_certificate_response(leaf_pem: &str, issuer_pem: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <GetCertificateResponse xmlns="http://tempuri.org/">
      <GetCertificateResult>{leaf_pem}{issuer_pem}</GetCertificateResult>
    </GetCertificateResponse>
  </s:Body>
</s:Envelope>"#
    )
}

fn validate_otp_response(signature_b64: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <ValidateOtpResponse xmlns="http://tempuri.org/">
      <ValidateOtpResult xmlns:a="http://schemas.datacontract.org/2004/07/Ama.Authentication.Service.Services.CMDService" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
        <a:Signature>{signature_b64}</a:Signature>
        <a:Status><a:Code>200</a:Code><a:Message>Assinatura concluída.</a:Message></a:Status>
      </ValidateOtpResult>
    </ValidateOtpResponse>
  </s:Body>
</s:Envelope>"#
    )
}

// --- test harness -----------------------------------------------------------------------------

/// A temp data dir that is removed on drop.
struct TempDir(std::path::PathBuf);
impl TempDir {
    fn new() -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!("chancela-cmd-signing-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct EnvRestore(Vec<(&'static str, Option<String>)>);

impl EnvRestore {
    fn capture(keys: &[&'static str]) -> Self {
        Self(
            keys.iter()
                .copied()
                .map(|key| (key, std::env::var(key).ok()))
                .collect(),
        )
    }

    fn capture_and_remove(keys: &[&'static str]) -> Self {
        let saved = keys
            .iter()
            .copied()
            .map(|key| {
                let value = std::env::var(key).ok();
                unsafe {
                    std::env::remove_var(key);
                }
                (key, value)
            })
            .collect();
        Self(saved)
    }
}

fn without_cmd_env() -> EnvRestore {
    EnvRestore::capture_and_remove(&CMD_ENV_KEYS)
}

fn zeroizing(value: &str) -> Zeroizing<String> {
    Zeroizing::new(value.to_owned())
}

fn set_provider_credential_test_key() {
    unsafe {
        std::env::set_var(
            "CHANCELA_CREDENTIAL_KEY",
            "cmd-signing-provider-credential-test-key",
        );
        std::env::remove_var("CHANCELA_CREDENTIAL_KEY_FILE");
        std::env::remove_var("CHANCELA_CREDENTIAL_STRICT");
    }
}

fn clear_cmd_env() {
    for key in CMD_ENV_KEYS {
        unsafe {
            std::env::remove_var(key);
        }
    }
}

fn seed_stored_cmd_application_id(state: &AppState, application_id: &str) {
    state
        .provider_credentials
        .put(
            CredentialMode::Cmd,
            "",
            CmdCredentialFields {
                application_id: Some(zeroizing(application_id)),
                ..Default::default()
            }
            .into_set_pairs(),
            &[],
        )
        .expect("seed stored CMD credentials");
}

fn seed_partial_stored_cmd_record(state: &AppState) {
    state
        .provider_credentials
        .put(
            CredentialMode::Cmd,
            "",
            CmdCredentialFields {
                http_basic_username: Some(zeroizing("stored-user-fixture")),
                ..Default::default()
            }
            .into_set_pairs(),
            &[],
        )
        .expect("seed partial stored CMD credentials");
}

fn restore_keys() -> Vec<&'static str> {
    CMD_ENV_KEYS
        .into_iter()
        .chain(PROVIDER_CREDENTIAL_ENV_KEYS)
        .collect()
}

impl Drop for EnvRestore {
    fn drop(&mut self) {
        for (key, value) in self.0.drain(..) {
            unsafe {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
    }
}

/// Build a durable state at `dir` with the injected transport + a granted trust policy + the CMD
/// ApplicationId set (from "env"/settings). `reject` picks the OTP behaviour.
async fn state_at_with_trust_status(
    dir: &std::path::Path,
    transport: SmartCmdTransport,
    trust_status: TrustedListStatus,
) -> AppState {
    let mut state = AppState::with_data_dir(dir);
    state.cmd_transport = Some(Arc::new(transport));
    let policy: Arc<dyn Fn() -> Box<dyn TrustPolicy + Send> + Send + Sync> =
        Arc::new(move || Box::new(StaticTrustPolicy::new(trust_status)));
    state.cmd_trust_policy = Some(policy);
    {
        let mut settings = state.settings.write().await;
        settings.signing.cmd.application_id = Some(APP_ID.to_owned());
        settings.signing.tsa_url = None;
        settings.signing.tsa_providers.clear();
    }
    state
}

async fn state_at(dir: &std::path::Path, transport: SmartCmdTransport, granted: bool) -> AppState {
    let trust_status = if granted {
        TrustedListStatus::Granted
    } else {
        TrustedListStatus::Withdrawn
    };
    state_at_with_trust_status(dir, transport, trust_status).await
}

/// Send one request through a fresh router; return (status, JSON body).
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

/// Send one request; return (status, raw bytes) — for the signed PDF download.
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
    // First-run POST /v1/users is auth-exempt (no users yet).
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

/// Open a session for an existing user id (session create is auth-exempt); return the token.
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

// --- tests ------------------------------------------------------------------------------------

#[tokio::test]
async fn cmd_initiate_uses_stored_application_id_with_env_cleared() {
    let _guard = ENV_LOCK.write().await;
    let keys = restore_keys();
    let _env = EnvRestore::capture_and_remove(&keys);
    set_provider_credential_test_key();

    let dir = TempDir::new();
    let leaf = RsaSigner::new("Amélia Marques (CMD teste)", 1);
    let issuer = RsaSigner::new("Encosto Estratégico — EC Teste", 2);
    let transport = SmartCmdTransport::new(&leaf, &issuer, false).expect_application_id(APP_ID);
    let state = state_at(&dir.0, transport, true).await;
    state.settings.write().await.signing.cmd.application_id = None;
    seed_stored_cmd_application_id(&state, APP_ID);
    let (token, _uid) = bootstrap(&state).await;
    let act_id = seal_an_act(&state, &token).await;

    let (status, init) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/cmd/initiate"),
            &token,
            json!({ "phone": PHONE, "pin": PIN }),
        ),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "stored CMD config initiates: {init}"
    );
    assert_eq!(init["status"], "otp_pending");
}

#[tokio::test]
async fn cmd_stored_application_id_beats_env_application_id() {
    let _guard = ENV_LOCK.write().await;
    let keys = restore_keys();
    let _env = EnvRestore::capture(&keys);
    clear_cmd_env();
    set_provider_credential_test_key();
    unsafe {
        std::env::set_var("CHANCELA_CMD_APPLICATION_ID", "ENV-CMD-APP-FIXTURE");
    }

    let dir = TempDir::new();
    let leaf = RsaSigner::new("Amélia Marques (CMD teste)", 1);
    let issuer = RsaSigner::new("Encosto Estratégico — EC Teste", 2);
    let transport = SmartCmdTransport::new(&leaf, &issuer, false).expect_application_id(APP_ID);
    let state = state_at(&dir.0, transport, true).await;
    state.settings.write().await.signing.cmd.application_id = None;
    seed_stored_cmd_application_id(&state, APP_ID);
    let (token, _uid) = bootstrap(&state).await;
    let act_id = seal_an_act(&state, &token).await;

    let (status, init) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/cmd/initiate"),
            &token,
            json!({ "phone": PHONE, "pin": PIN }),
        ),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "stored CMD config beats env: {init}"
    );
}

#[tokio::test]
async fn cmd_partial_stored_record_fails_without_env_mixing() {
    let _guard = ENV_LOCK.write().await;
    let keys = restore_keys();
    let _env = EnvRestore::capture(&keys);
    clear_cmd_env();
    set_provider_credential_test_key();
    unsafe {
        std::env::set_var("CHANCELA_CMD_APPLICATION_ID", "ENV-CMD-APP-FIXTURE");
    }

    let dir = TempDir::new();
    let leaf = RsaSigner::new("Amélia Marques (CMD teste)", 1);
    let issuer = RsaSigner::new("Encosto Estratégico — EC Teste", 2);
    let transport = SmartCmdTransport::new(&leaf, &issuer, false)
        .with_transport_error_on(ACTION_GET_CERTIFICATE);
    let state = state_at(&dir.0, transport, true).await;
    state.settings.write().await.signing.cmd.application_id = None;
    seed_partial_stored_cmd_record(&state);
    let (token, _uid) = bootstrap(&state).await;
    let act_id = seal_an_act(&state, &token).await;

    let (status, err) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/cmd/initiate"),
            &token,
            json!({ "phone": PHONE, "pin": PIN }),
        ),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "partial stored: {err}"
    );
    let msg = err["error"].as_str().unwrap_or_default();
    assert!(msg.contains("mode 'cmd'"), "mode is named: {err}");
    assert!(
        msg.contains("application_id"),
        "missing field is named: {err}"
    );
    assert!(
        msg.contains("http_basic_password"),
        "partial BasicAuth pair is named: {err}"
    );
    assert!(
        !msg.contains("ENV-CMD-APP-FIXTURE") && !msg.contains("stored-user-fixture"),
        "error must not contain stored or env values: {err}"
    );
    assert!(state.pending_signatures.read().await.is_empty());
    assert_no_signed_artifact_or_event(&state, &token, &act_id).await;
}

#[tokio::test]
async fn cmd_env_application_id_still_works_without_stored_record() {
    let _guard = ENV_LOCK.write().await;
    let keys = restore_keys();
    let _env = EnvRestore::capture(&keys);
    clear_cmd_env();
    unsafe {
        std::env::remove_var("CHANCELA_CREDENTIAL_KEY");
        std::env::remove_var("CHANCELA_CREDENTIAL_KEY_FILE");
        std::env::remove_var("CHANCELA_CREDENTIAL_STRICT");
        std::env::set_var("CHANCELA_CMD_APPLICATION_ID", APP_ID);
    }

    let dir = TempDir::new();
    let leaf = RsaSigner::new("Amélia Marques (CMD teste)", 1);
    let issuer = RsaSigner::new("Encosto Estratégico — EC Teste", 2);
    let transport = SmartCmdTransport::new(&leaf, &issuer, false).expect_application_id(APP_ID);
    let state = state_at(&dir.0, transport, true).await;
    state.settings.write().await.signing.cmd.application_id = None;
    let (token, _uid) = bootstrap(&state).await;
    let act_id = seal_an_act(&state, &token).await;

    let (status, init) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/cmd/initiate"),
            &token,
            json!({ "phone": PHONE, "pin": PIN }),
        ),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "env CMD config still initiates: {init}"
    );
}

#[tokio::test]
async fn cmd_malformed_env_fails_closed_without_settings_fallback() {
    let _guard = ENV_LOCK.write().await;
    let keys = restore_keys();
    let _env = EnvRestore::capture(&keys);
    clear_cmd_env();
    unsafe {
        std::env::remove_var("CHANCELA_CREDENTIAL_KEY");
        std::env::remove_var("CHANCELA_CREDENTIAL_KEY_FILE");
        std::env::remove_var("CHANCELA_CREDENTIAL_STRICT");
        std::env::set_var("CHANCELA_CMD_APPLICATION_ID", "ENV-CMD-APP-FIXTURE");
        std::env::set_var("CHANCELA_CMD_HTTP_BASIC_USERNAME", "env-user-fixture");
    }

    let dir = TempDir::new();
    let leaf = RsaSigner::new("Amélia Marques (CMD teste)", 1);
    let issuer = RsaSigner::new("Encosto Estratégico — EC Teste", 2);
    let transport = SmartCmdTransport::new(&leaf, &issuer, false)
        .with_transport_error_on(ACTION_GET_CERTIFICATE);
    let state = state_at(&dir.0, transport, true).await;
    let (token, _uid) = bootstrap(&state).await;
    let act_id = seal_an_act(&state, &token).await;

    let (status, err) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/cmd/initiate"),
            &token,
            json!({ "phone": PHONE, "pin": PIN }),
        ),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "malformed CMD env must fail before settings fallback/transport: {err}"
    );
    let msg = err["error"].as_str().unwrap_or_default();
    assert!(msg.contains("configuração CMD inválida"), "{err}");
    assert!(
        !msg.contains("ENV-CMD-APP-FIXTURE")
            && !msg.contains("env-user-fixture")
            && !msg.contains("simulated SCMD outage"),
        "error must not contain env values or transport output: {err}"
    );
    assert!(state.pending_signatures.read().await.is_empty());
    assert_no_signed_artifact_or_event(&state, &token, &act_id).await;
}

#[tokio::test]
async fn cmd_signing_round_trip_produces_a_validating_signed_pdf() {
    // Read env under a shared lock so a concurrent env-mutating test can't leak its fixture.
    let _env_guard = ENV_LOCK.read().await;
    let dir = TempDir::new();
    let leaf = RsaSigner::new("Amélia Marques (CMD teste)", 1);
    let issuer = RsaSigner::new("Encosto Estratégico — EC Teste", 2);
    let transport = SmartCmdTransport::new(&leaf, &issuer, false);
    let state = state_at(&dir.0, transport, true).await;
    let (token, _uid) = bootstrap(&state).await;
    let act_id = seal_an_act(&state, &token).await;

    // Pre-sign: status unsigned, no signed PDF yet.
    let (status, view) = send(
        &state,
        get_req(&format!("/v1/acts/{act_id}/signature"), &token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(view["status"], "unsigned");
    let (status, _) = send_bytes(
        &state,
        get_req(&format!("/v1/acts/{act_id}/document/signed"), &token),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Phase 1: initiate.
    let (status, init) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/cmd/initiate"),
            &token,
            json!({ "phone": PHONE, "pin": PIN, "capacity": "Administrador" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "initiate: {init}");
    let session_id = init["session_id"].as_str().expect("session_id").to_owned();
    assert_eq!(init["status"], "otp_pending");
    assert_eq!(init["evidentiary_level"], "Qualified");
    // The response carries no secret.
    let init_str = init.to_string();
    assert!(
        !init_str.contains(PIN),
        "PIN must not appear in the initiate response"
    );

    // The persisted pending session carries NO PIN/OTP (durable + serialized blobs).
    let pending = state
        .store
        .as_ref()
        .unwrap()
        .pending_cmd_session(&session_id)
        .unwrap()
        .expect("pending session persisted");
    let blob = format!("{}{}", pending.session_json, pending.prepared_json);
    assert!(!blob.contains(PIN), "PIN must never be persisted");
    assert!(!blob.contains(OTP), "OTP must never be persisted");
    assert!(
        !format!("{pending:?}").contains(PIN),
        "PIN must not leak via Debug"
    );
    let capacity_evidence = pending
        .signer_capacity_evidence_json
        .as_deref()
        .expect("pending capacity evidence");
    assert!(capacity_evidence.contains("\"requested_provider_capacity\":\"Administrador\""));
    assert!(capacity_evidence.contains("\"verification_status\":\"not_checked_by_scap\""));
    assert!(capacity_evidence.contains("\"status_scope\":\"declared_capacity_evidence_only\""));
    assert!(!capacity_evidence.contains("verified_by_scap"));

    // Status now pending.
    let (_, view) = send(
        &state,
        get_req(&format!("/v1/acts/{act_id}/signature"), &token),
    )
    .await;
    assert_eq!(view["status"], "pending");

    // Phase 2: confirm with the OTP.
    let (status, done) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/cmd/confirm"),
            &token,
            json!({ "session_id": session_id.clone(), "otp": OTP }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "confirm: {done}");
    assert_eq!(done["family"], "ChaveMovelDigital");
    assert_eq!(done["evidentiary_level"], "Qualified");
    assert_eq!(done["trusted_list_status"], "Granted");
    assert_eq!(done["finalization"], "em_assinatura");
    assert_eq!(
        done["signer_capacity_evidence"]["requested_provider_capacity"],
        "Administrador"
    );
    assert_eq!(
        done["signer_capacity_evidence"]["verification_status"],
        "not_checked_by_scap"
    );

    // The signed PDF downloads and VALIDATES (SIG-24): ByteRange covers the whole file, signer is
    // the session leaf, and there is a signing time.
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

    // A `document.signed` event was appended (chained).
    let (_, events) = send(
        &state,
        get_req(&format!("/v1/ledger/events?scope=act:{act_id}"), &token),
    )
    .await;
    let kinds: Vec<&str> = events
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["kind"].as_str())
        .collect();
    assert!(
        kinds.contains(&"document.signed"),
        "document.signed event present: {kinds:?}"
    );
    let signed_event = events
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["kind"] == "document.signed")
        .expect("document.signed event present");
    if let Some(event_payload) = signed_event
        .get("payload")
        .or_else(|| signed_event.get("data"))
    {
        assert_eq!(
            event_payload["signer_capacity_evidence"]["requested_provider_capacity"],
            "Administrador"
        );
        assert_eq!(
            event_payload["signer_capacity_evidence"]["verification_status"],
            "not_checked_by_scap"
        );
    }

    // The chain still verifies.
    let (_, verify) = send(&state, get_req("/v1/ledger/verify", &token)).await;
    assert_eq!(verify["valid"], true);

    // Status flipped to signed.
    let (_, view) = send(
        &state,
        get_req(&format!("/v1/acts/{act_id}/signature"), &token),
    )
    .await;
    assert_eq!(view["status"], "signed");
    assert_eq!(view["finalization"], "em_assinatura");
    assert_eq!(view["signed"]["evidentiary_level"], "Qualified");
    assert_eq!(
        view["signed"]["signer_capacity_evidence"]["requested_provider_capacity"],
        "Administrador"
    );
    assert_eq!(
        view["signed"]["signer_capacity_evidence"]["status_scope"],
        "declared_capacity_evidence_only"
    );

    // The pending session is single-use: replaying the same confirm is refused and does not append a
    // second `document.signed` event.
    let (status, _) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/cmd/confirm"),
            &token,
            json!({ "session_id": session_id, "otp": OTP }),
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
            &format!("/v1/acts/{act_id}/signature/cmd/initiate"),
            &token,
            json!({ "phone": PHONE, "pin": PIN }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn cmd_signing_timestamps_when_tsa_configured() {
    // Read env under a shared lock so a concurrent env-mutating test can't leak its fixture.
    let _env_guard = ENV_LOCK.read().await;
    let dir = TempDir::new();
    let leaf = RsaSigner::new("Amélia Marques (CMD teste)", 1);
    let issuer = RsaSigner::new("Encosto Estratégico — EC Teste", 2);
    let transport = SmartCmdTransport::new(&leaf, &issuer, false);
    let state = state_at(&dir.0, transport, true).await;
    let tsa = MockTsaServer::granted();
    state.settings.write().await.signing.tsa_url = Some(tsa.url().to_owned());
    let (token, _uid) = bootstrap(&state).await;
    let act_id = seal_an_act(&state, &token).await;

    let (status, init) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/cmd/initiate"),
            &token,
            json!({ "phone": PHONE, "pin": PIN }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "initiate: {init}");
    let session_id = init["session_id"].as_str().unwrap().to_owned();

    let (status, done) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/cmd/confirm"),
            &token,
            json!({ "session_id": session_id, "otp": OTP }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "confirm: {done}");
    assert_eq!(done["timestamp_token"], true);

    let (status, signed_pdf) = send_bytes(
        &state,
        get_req(&format!("/v1/acts/{act_id}/document/signed"), &token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let report = validate_pdf_signature(&signed_pdf).expect("timestamped PDF validates");
    assert!(report.covers_whole_file_except_contents);
    assert!(report.has_signature_timestamp, "PAdES-B-T timestamp");
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
    assert_eq!(
        stored.signed_pdf_digest,
        done["signed_pdf_digest"].as_str().unwrap()
    );

    let (_, view) = send(
        &state,
        get_req(&format!("/v1/acts/{act_id}/signature"), &token),
    )
    .await;
    assert_eq!(view["signed"]["timestamp_token"], true);

    assert_eq!(signed_event_count(&state, &token, &act_id).await, 1);
}

#[tokio::test]
async fn cmd_tsa_failure_leaves_no_signed_artifact() {
    // Read env under a shared lock so a concurrent env-mutating test can't leak its fixture.
    let _env_guard = ENV_LOCK.read().await;
    let dir = TempDir::new();
    let leaf = RsaSigner::new("Amélia Marques (CMD teste)", 1);
    let issuer = RsaSigner::new("Encosto Estratégico — EC Teste", 2);
    let transport = SmartCmdTransport::new(&leaf, &issuer, false);
    let state = state_at(&dir.0, transport, true).await;
    let tsa = MockTsaServer::outage();
    state.settings.write().await.signing.tsa_url = Some(tsa.url().to_owned());
    let (token, _uid) = bootstrap(&state).await;
    let act_id = seal_an_act(&state, &token).await;

    let (status, init) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/cmd/initiate"),
            &token,
            json!({ "phone": PHONE, "pin": PIN }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "initiate: {init}");
    let session_id = init["session_id"].as_str().unwrap().to_owned();

    let (status, err) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/cmd/confirm"),
            &token,
            json!({ "session_id": session_id, "otp": OTP }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "TSA failure maps cleanly: {err}"
    );
    assert!(
        err["error"]
            .as_str()
            .unwrap_or_default()
            .contains("carimbo temporal"),
        "timestamp failure is explicit: {err}"
    );
    assert_no_signed_artifact_or_event(&state, &token, &act_id).await;
}

#[tokio::test]
async fn cmd_malformed_tsa_token_leaves_no_signed_artifact() {
    // Read env under a shared lock so a concurrent env-mutating test can't leak its fixture.
    let _env_guard = ENV_LOCK.read().await;
    let dir = TempDir::new();
    let leaf = RsaSigner::new("Amélia Marques (CMD teste)", 1);
    let issuer = RsaSigner::new("Encosto Estratégico — EC Teste", 2);
    let transport = SmartCmdTransport::new(&leaf, &issuer, false);
    let state = state_at(&dir.0, transport, true).await;
    let tsa = MockTsaServer::malformed_token();
    state.settings.write().await.signing.tsa_url = Some(tsa.url().to_owned());
    let (token, _uid) = bootstrap(&state).await;
    let act_id = seal_an_act(&state, &token).await;

    let (status, init) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/cmd/initiate"),
            &token,
            json!({ "phone": PHONE, "pin": PIN }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "initiate: {init}");
    let session_id = init["session_id"].as_str().unwrap().to_owned();

    let (status, err) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/cmd/confirm"),
            &token,
            json!({ "session_id": session_id, "otp": OTP }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "malformed TSA token maps cleanly: {err}"
    );
    assert!(
        err["error"]
            .as_str()
            .unwrap_or_default()
            .contains("carimbo temporal"),
        "timestamp failure is explicit: {err}"
    );
    assert_no_signed_artifact_or_event(&state, &token, &act_id).await;
}

#[tokio::test]
async fn cmd_initiate_requires_application_id_and_leaves_no_signature() {
    let _guard = ENV_LOCK.write().await;
    let _env = without_cmd_env();
    let dir = TempDir::new();
    let leaf = RsaSigner::new("Amélia Marques (CMD teste)", 1);
    let issuer = RsaSigner::new("Encosto Estratégico — EC Teste", 2);
    let transport = SmartCmdTransport::new(&leaf, &issuer, false);
    let state = state_at(&dir.0, transport, true).await;
    state.settings.write().await.signing.cmd.application_id = None;
    let (token, _uid) = bootstrap(&state).await;
    let act_id = seal_an_act(&state, &token).await;

    let (status, err) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/cmd/initiate"),
            &token,
            json!({ "phone": PHONE, "pin": PIN }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "missing ApplicationId is client-actionable: {err}"
    );
    assert!(
        err["error"]
            .as_str()
            .unwrap_or_default()
            .contains("ApplicationId"),
        "error points at the missing ApplicationId: {err}"
    );
    assert!(
        state.pending_signatures.read().await.is_empty(),
        "missing config must not create a pending signing session"
    );
    assert_no_signed_artifact_or_event(&state, &token, &act_id).await;
}

#[tokio::test]
async fn cmd_prod_without_ama_certificate_fails_before_scmd_and_leaves_no_signature() {
    let _guard = ENV_LOCK.write().await;
    let _env = without_cmd_env();
    let dir = TempDir::new();
    let leaf = RsaSigner::new("Amélia Marques (CMD teste)", 1);
    let issuer = RsaSigner::new("Encosto Estratégico — EC Teste", 2);
    let transport = SmartCmdTransport::new(&leaf, &issuer, false)
        .with_transport_error_on(ACTION_GET_CERTIFICATE);
    let state = state_at(&dir.0, transport, true).await;
    state.settings.write().await.signing.cmd.env = CmdEnvSetting::Prod;
    let (token, _uid) = bootstrap(&state).await;
    let act_id = seal_an_act(&state, &token).await;

    let (status, err) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/cmd/initiate"),
            &token,
            json!({ "phone": PHONE, "pin": PIN }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "PROD without AMA cert is client-actionable: {err}"
    );
    let msg = err["error"].as_str().unwrap_or_default();
    assert!(
        msg.contains("CHANCELA_CMD_AMA_CERT_PEM") || msg.contains("field encryption"),
        "error points at the missing production certificate: {err}"
    );
    assert!(
        state.pending_signatures.read().await.is_empty(),
        "invalid production config must not create a pending signing session"
    );
    assert_no_signed_artifact_or_event(&state, &token, &act_id).await;
}

#[tokio::test]
async fn cmd_initiate_rejects_withdrawn_and_unknown_trust_policy() {
    let _guard = ENV_LOCK.write().await;
    let _env = without_cmd_env();
    for trust_status in [TrustedListStatus::Withdrawn, TrustedListStatus::Unknown] {
        let dir = TempDir::new();
        let leaf = RsaSigner::new("Amélia Marques (CMD teste)", 1);
        let issuer = RsaSigner::new("Encosto Estratégico — EC Teste", 2);
        let transport = SmartCmdTransport::new(&leaf, &issuer, false);
        let state = state_at_with_trust_status(&dir.0, transport, trust_status).await;
        let (token, _uid) = bootstrap(&state).await;
        let act_id = seal_an_act(&state, &token).await;

        let (status, err) = send(
            &state,
            json_req(
                "POST",
                &format!("/v1/acts/{act_id}/signature/cmd/initiate"),
                &token,
                json!({ "phone": PHONE, "pin": PIN }),
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
async fn pending_session_survives_a_restart_and_confirms() {
    // Read env under a shared lock so a concurrent env-mutating test can't leak its fixture.
    let _env_guard = ENV_LOCK.read().await;
    let dir = TempDir::new();
    let leaf = RsaSigner::new("Amélia Marques (CMD teste)", 1);
    let issuer = RsaSigner::new("Encosto Estratégico — EC Teste", 2);
    // One transport shared across both "boots" (so the captured digest lines up after the restart).
    let transport = SmartCmdTransport::new(&leaf, &issuer, false);

    let session_id;
    let act_id;
    let uid;
    {
        let state = state_at(&dir.0, transport.clone(), true).await;
        let (token, user_id) = bootstrap(&state).await;
        uid = user_id;
        act_id = seal_an_act(&state, &token).await;
        let (status, init) = send(
            &state,
            json_req(
                "POST",
                &format!("/v1/acts/{act_id}/signature/cmd/initiate"),
                &token,
                json!({ "phone": PHONE, "pin": PIN }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "initiate: {init}");
        session_id = init["session_id"].as_str().unwrap().to_owned();
        // `state` drops here — the in-memory pending map is gone; only the durable row remains.
    }

    // Reboot from the same data dir: the pending session is rehydrated from the store.
    let state2 = state_at(&dir.0, transport, true).await;
    assert!(
        state2
            .pending_signatures
            .read()
            .await
            .contains_key(&session_id),
        "pending session rehydrated on boot"
    );
    // The user persists in users.json across the reboot, so re-open a session for that same user
    // (first-run POST /v1/users is no longer auth-exempt once a user exists).
    let token = open_session(&state2, &uid).await;
    let (status, done) = send(
        &state2,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/cmd/confirm"),
            &token,
            json!({ "session_id": session_id, "otp": OTP }),
        ),
    )
    .await;
    // Note: the pending session records the ORIGINAL initiating actor; the reboot's fresh session is
    // the SAME first user (amelia.marques), so the actor-gating passes and confirm succeeds.
    assert_eq!(status, StatusCode::OK, "confirm after restart: {done}");
    assert_eq!(done["finalization"], "em_assinatura");
    let (status, signed_pdf) = send_bytes(
        &state2,
        get_req(&format!("/v1/acts/{act_id}/document/signed"), &token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        validate_pdf_signature(&signed_pdf)
            .expect("validates")
            .covers_whole_file_except_contents
    );
}

#[tokio::test]
async fn pending_session_rejects_unknown_session_wrong_actor_and_wrong_act() {
    // Read env under a shared lock so a concurrent env-mutating test can't leak its fixture.
    let _env_guard = ENV_LOCK.read().await;
    let dir = TempDir::new();
    let leaf = RsaSigner::new("Amélia Marques (CMD teste)", 1);
    let issuer = RsaSigner::new("Encosto Estratégico — EC Teste", 2);
    let transport = SmartCmdTransport::new(&leaf, &issuer, false);
    let state = state_at(&dir.0, transport, true).await;
    let (owner, _uid) = bootstrap(&state).await;
    let act_id = seal_an_act(&state, &owner).await;

    let (status, init) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/cmd/initiate"),
            &owner,
            json!({ "phone": PHONE, "pin": PIN }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "initiate: {init}");
    let session_id = init["session_id"].as_str().unwrap().to_owned();

    let (status, _) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/cmd/confirm"),
            &owner,
            json!({ "session_id": uuid::Uuid::new_v4().to_string(), "otp": OTP }),
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
            &format!("/v1/acts/{act_id}/signature/cmd/confirm"),
            &other,
            json!({ "session_id": session_id.clone(), "otp": OTP }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let other_act = seal_an_act(&state, &owner).await;
    let (status, _) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{other_act}/signature/cmd/confirm"),
            &owner,
            json!({ "session_id": session_id, "otp": OTP }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    assert_no_signed_artifact_or_event(&state, &owner, &act_id).await;
    assert_no_signed_artifact_or_event(&state, &owner, &other_act).await;
}

#[tokio::test]
async fn expired_pending_session_returns_gone_and_leaves_no_signature() {
    // Read env under a shared lock so a concurrent env-mutating test can't leak its fixture.
    let _env_guard = ENV_LOCK.read().await;
    let dir = TempDir::new();
    let leaf = RsaSigner::new("Amélia Marques (CMD teste)", 1);
    let issuer = RsaSigner::new("Encosto Estratégico — EC Teste", 2);
    let transport = SmartCmdTransport::new(&leaf, &issuer, false);
    let state = state_at(&dir.0, transport, true).await;
    let (token, _uid) = bootstrap(&state).await;
    let act_id = seal_an_act(&state, &token).await;

    let (status, init) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/cmd/initiate"),
            &token,
            json!({ "phone": PHONE, "pin": PIN }),
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
            &format!("/v1/acts/{act_id}/signature/cmd/confirm"),
            &token,
            json!({ "session_id": session_id.clone(), "otp": OTP }),
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
    assert!(
        !state
            .pending_signatures
            .read()
            .await
            .contains_key(&session_id),
        "expired pending session is removed from the live map"
    );
    assert_no_signed_artifact_or_event(&state, &token, &act_id).await;
}

#[tokio::test]
async fn cmd_confirm_transport_error_maps_to_422_and_leaves_no_signature() {
    // Read env under a shared lock so a concurrent env-mutating test can't leak its fixture.
    let _env_guard = ENV_LOCK.read().await;
    let dir = TempDir::new();
    let leaf = RsaSigner::new("Amélia Marques (CMD teste)", 1);
    let issuer = RsaSigner::new("Encosto Estratégico — EC Teste", 2);
    let transport =
        SmartCmdTransport::new(&leaf, &issuer, false).with_transport_error_on(ACTION_VALIDATE_OTP);
    let state = state_at(&dir.0, transport, true).await;
    let (token, _uid) = bootstrap(&state).await;
    let act_id = seal_an_act(&state, &token).await;

    let (status, init) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/cmd/initiate"),
            &token,
            json!({ "phone": PHONE, "pin": PIN }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "initiate: {init}");
    let session_id = init["session_id"].as_str().unwrap().to_owned();

    let (status, err) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/cmd/confirm"),
            &token,
            json!({ "session_id": session_id.clone(), "otp": OTP }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "transport outage maps cleanly: {err}"
    );
    assert!(
        err.to_string().contains("SCMD transport error"),
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

#[tokio::test]
async fn wrong_otp_is_a_clean_error_and_leaves_no_signature() {
    // Read env under a shared lock so a concurrent env-mutating test can't leak its fixture.
    let _env_guard = ENV_LOCK.read().await;
    let dir = TempDir::new();
    let leaf = RsaSigner::new("Amélia Marques (CMD teste)", 1);
    let issuer = RsaSigner::new("Encosto Estratégico — EC Teste", 2);
    let transport = SmartCmdTransport::new(&leaf, &issuer, true); // ValidateOtp rejects
    let state = state_at(&dir.0, transport, true).await;
    let (token, _uid) = bootstrap(&state).await;
    let act_id = seal_an_act(&state, &token).await;

    let (status, init) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/cmd/initiate"),
            &token,
            json!({ "phone": PHONE, "pin": PIN }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "initiate: {init}");
    let session_id = init["session_id"].as_str().unwrap().to_owned();

    let (status, err) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/cmd/confirm"),
            &token,
            json!({ "session_id": session_id, "otp": "000000" }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "wrong OTP → 422: {err}"
    );
    assert!(
        !err.to_string().contains("000000"),
        "the OTP must not be echoed"
    );

    assert_no_signed_artifact_or_event(&state, &token, &act_id).await;
}

#[tokio::test]
async fn finalization_is_reported_only_after_the_explicit_seal() {
    // Read env under a shared lock so a concurrent env-mutating test can't leak its fixture.
    let _env_guard = ENV_LOCK.read().await;
    let dir = TempDir::new();
    let leaf = RsaSigner::new("Amélia Marques (CMD teste)", 1);
    let issuer = RsaSigner::new("Encosto Estratégico — EC Teste", 2);
    let transport = SmartCmdTransport::new(&leaf, &issuer, false);
    let state = state_at(&dir.0, transport, true).await;
    let (token, _uid) = bootstrap(&state).await;

    // Before the explicit final seal, even a policy requesting qualified evidence reports the
    // lifecycle honestly as still collecting signatures.
    state
        .settings
        .write()
        .await
        .signing
        .require_qualified_for_seal = true;
    let act_id = seal_an_act(&state, &token).await;

    let (_, view) = send(
        &state,
        get_req(&format!("/v1/acts/{act_id}/signature"), &token),
    )
    .await;
    assert_eq!(view["status"], "unsigned");
    assert_eq!(view["require_qualified_for_seal"], true);
    assert_eq!(view["finalization"], "em_assinatura");

    // A qualified signature completes the signed artifact, but does not itself finalize the act.
    let (status, init) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/cmd/initiate"),
            &token,
            json!({ "phone": PHONE, "pin": PIN }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "initiate: {init}");
    let session_id = init["session_id"].as_str().unwrap().to_owned();
    let (status, _) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/cmd/confirm"),
            &token,
            json!({ "session_id": session_id, "otp": OTP }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, view) = send(
        &state,
        get_req(&format!("/v1/acts/{act_id}/signature"), &token),
    )
    .await;
    assert_eq!(view["status"], "signed");
    assert_eq!(view["finalization"], "em_assinatura");

    // The validated digital-evidence seal is the only transition that claims finalization.
    seal_signed_act(&state, &token, &act_id).await;
    let (_, view) = send(
        &state,
        get_req(&format!("/v1/acts/{act_id}/signature"), &token),
    )
    .await;
    assert_eq!(view["finalization"], "finalizado_qualificado");

    // The explicit manual-original path may also seal, but never claims a qualified signature.
    state
        .settings
        .write()
        .await
        .signing
        .require_qualified_for_seal = false;
    let act2 = seal_an_act(&state, &token).await;
    let (_, view2) = send(
        &state,
        get_req(&format!("/v1/acts/{act2}/signature"), &token),
    )
    .await;
    assert_eq!(view2["finalization"], "em_assinatura");
    let (status, sealed) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act2}/seal"),
            &token,
            json!({
                "manual_signature_original_reference": {
                    "storage_reference": "Arquivo A / Pasta 2026 / Ata manual"
                }
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "manual seal: {sealed}");
    let (_, view2) = send(
        &state,
        get_req(&format!("/v1/acts/{act2}/signature"), &token),
    )
    .await;
    assert_eq!(view2["finalization"], "finalizado");
}

#[tokio::test]
async fn initiate_before_signing_is_conflict() {
    // Read env under a shared lock so a concurrent env-mutating test can't leak its fixture.
    let _env_guard = ENV_LOCK.read().await;
    let dir = TempDir::new();
    let leaf = RsaSigner::new("Amélia Marques (CMD teste)", 1);
    let issuer = RsaSigner::new("Encosto Estratégico — EC Teste", 2);
    let transport = SmartCmdTransport::new(&leaf, &issuer, false);
    let state = state_at(&dir.0, transport, true).await;
    let (token, _uid) = bootstrap(&state).await;

    // Create an entity/book/act but do not advance it to the canonical `Signing` snapshot.
    let (_, entity) = send(
        &state,
        json_req("POST", "/v1/entities", &token, json!({ "name": "Encosto Estratégico, S.A.", "nipc": "503004642", "seat": "Lisboa", "kind": "SociedadeAnonima" })),
    )
    .await;
    let entity_id = entity["id"].as_str().unwrap().to_owned();
    let (_, book) = send(
        &state,
        json_req("POST", "/v1/books", &token, json!({ "entity_id": entity_id, "kind": "AssembleiaGeral", "purpose": "livro", "opening_date": "2026-01-15", "required_signatories": ["Administrador"] })),
    )
    .await;
    let book_id = book["id"].as_str().unwrap().to_owned();
    let (_, act) = send(
        &state,
        json_req(
            "POST",
            "/v1/acts",
            &token,
            json!({ "book_id": book_id, "title": "Ata", "channel": "Physical" }),
        ),
    )
    .await;
    let act_id = act["id"].as_str().unwrap().to_owned();

    let (status, _) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/cmd/initiate"),
            &token,
            json!({ "phone": PHONE, "pin": PIN }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "cannot sign an act outside Signing"
    );
}
