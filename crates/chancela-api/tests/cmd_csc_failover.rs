//! wp27-e7 — multi-entry CMD/CSC signing failover, end to end over MOCK transports.
//!
//! The failover ENGINE (priority-ordered candidate resolution + the retryable/terminal walk) is
//! unit-tested in `credential_resolve`; these tests prove it is now WIRED into the two-phase remote
//! signing INITIATE and that CONFIRM pins the exact entry the walk chose. Every provider call goes
//! through an offline mock transport keyed per stored entry (by ApplicationId for CMD, by client_id
//! for CSC), so a specific entry can be made to fail retryably or terminally and the walk's behaviour
//! observed. No live QTSP identity is touched.
//!
//! Coverage (the four required cases + the CSC twins):
//! - **failover-on-retryable** — a transport outage on the top entry advances to the next.
//! - **stop-on-terminal (PIN/OTP-burn guard)** — a provider "no" on the top entry STOPS: the next
//!   entry is NEVER contacted, so its PIN/OTP attempts are never burned.
//! - **confirm-resolves-the-same-entry** — after a fail-over the session pins the chosen entry and
//!   confirm resolves THAT credential, not `default_entry`.
//! - **priority / disabled ordering** — the highest-priority ENABLED entry is used; a disabled one is
//!   skipped.
//!
//! Fictional example data only: "Encosto Estratégico Lda" / "Amélia Marques" — never real names.

mod common;

use std::str::FromStr;
use std::sync::{Arc, Mutex, Once};
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

use chancela_api::{
    AppState, CmdCredentialFields, CredentialFieldSet, CredentialMode, CscCredentialFields,
    EntryMetadata, EntrySelectors, router,
};
use chancela_cmd::soap::{ACTION_CCMOVEL_SIGN, ACTION_GET_CERTIFICATE, ACTION_VALIDATE_OTP};
use chancela_cmd::{CmdError, ScmdTransport};
use chancela_csc::mock::{
    CREDENTIALS_LIST_OK, OAUTH_TOKEN_OK, SEND_OTP_OK, credentials_info_response, sign_hash_response,
};
use chancela_csc::rest::{
    self, Authorization as CscAuthHeader, OID_RSA_ENCRYPTION, PATH_SIGNATURES_SIGN_HASH,
};
use chancela_csc::{CscAuthorization, CscConfig, CscError, CscTransport};
use chancela_signing::{StaticTrustPolicy, TrustPolicy, TrustedListStatus};
use common::TEST_PASSWORD;
use zeroize::Zeroizing;

const OID_SHA256_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const SHA256_DIGEST_INFO_PREFIX: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

const CSC_PROVIDER_ID: &str = "encosto-qtsp";
const PHONE: &str = "+351 912345678";
const PIN: &str = "271828";
const OTP: &str = "314159";
const CSC_ACTIVATION: &str = "141421";

// Distinct per-entry ApplicationIds (CMD) so the mock can tell which stored entry is calling.
const APP_PRIMARY: &str = "CHANCELA-PREPROD-PRIMARY";
const APP_SECONDARY: &str = "CHANCELA-PREPROD-SECONDARY";
// Distinct per-entry CSC service client ids.
const CSC_CLIENT_PRIMARY: &str = "csc-client-primary";
const CSC_CLIENT_SECONDARY: &str = "csc-client-secondary";

/// Set the process-global credential encryption key ONCE for this test binary (never unset, so a
/// concurrent test's `AppState::with_data_dir` store can always decrypt). All tests use the same key.
fn ensure_credential_key() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| unsafe {
        std::env::set_var("CHANCELA_CREDENTIAL_KEY", "wp27-e7-failover-test-key-0001");
        std::env::remove_var("CHANCELA_CREDENTIAL_KEY_FILE");
        std::env::remove_var("CHANCELA_CREDENTIAL_STRICT");
    });
}

fn zeroizing(value: &str) -> Zeroizing<String> {
    Zeroizing::new(value.to_owned())
}

// --- ephemeral in-test RSA signer (mirrors the sibling signing suites) ------------------------

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

fn between<'a>(hay: &'a str, open: &str, close: &str) -> Option<&'a str> {
    let start = hay.find(open)? + open.len();
    let end = hay[start..].find(close)? + start;
    Some(&hay[start..end])
}

// --- failover-aware CMD mock ------------------------------------------------------------------

/// How one stored CMD entry (identified by its ApplicationId) behaves.
#[derive(Clone, Copy, PartialEq, Eq)]
enum CmdBehavior {
    /// Sign successfully.
    Ok,
    /// Fail with a RETRYABLE transport outage at `action` (the walk should advance).
    RetryableAt(&'static str),
    /// Fail with a TERMINAL provider rejection at `action` (the walk MUST stop; no fail-over).
    TerminalAt(&'static str),
}

#[derive(Clone)]
struct CmdMockEntry {
    application_id: String,
    behavior: CmdBehavior,
}

/// An offline SCMD transport keyed by ApplicationId: each stored entry can be made to fail retryably
/// or terminally at a given SOAP action, and every call `(action, application_id)` is recorded so a
/// test can assert exactly which entry the walk reached in each phase.
#[derive(Clone)]
struct FailoverCmdTransport {
    leaf_key: Arc<rsa::RsaPrivateKey>,
    leaf_pem: String,
    issuer_pem: String,
    captured_hash: Arc<Mutex<Option<Vec<u8>>>>,
    entries: Vec<CmdMockEntry>,
    calls: Arc<Mutex<Vec<(String, String)>>>,
}

impl FailoverCmdTransport {
    fn new(leaf: &RsaSigner, issuer: &RsaSigner, entries: Vec<CmdMockEntry>) -> Self {
        Self {
            leaf_key: Arc::new(leaf.key.clone()),
            leaf_pem: leaf.cert_pem(),
            issuer_pem: issuer.cert_pem(),
            captured_hash: Arc::new(Mutex::new(None)),
            entries,
            calls: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// The ApplicationId whose base64 appears in this SOAP body (the entry making the call).
    fn acting_application_id(&self, soap_body: &str) -> Option<String> {
        self.entries
            .iter()
            .find(|e| soap_body.contains(&STANDARD.encode(e.application_id.as_bytes())))
            .map(|e| e.application_id.clone())
    }

    fn calls(&self) -> Vec<(String, String)> {
        self.calls.lock().expect("cmd calls poisoned").clone()
    }

    fn saw_application_id(&self, application_id: &str) -> bool {
        self.calls().iter().any(|(_, app)| app == application_id)
    }

    fn application_id_at(&self, action: &str) -> Option<String> {
        self.calls()
            .into_iter()
            .find(|(a, _)| a == action)
            .map(|(_, app)| app)
    }
}

impl ScmdTransport for FailoverCmdTransport {
    fn call(&self, action: &str, soap_body: &str) -> Result<String, CmdError> {
        let application_id = self
            .acting_application_id(soap_body)
            .unwrap_or_else(|| "<unknown>".to_owned());
        self.calls
            .lock()
            .expect("cmd calls poisoned")
            .push((action.to_owned(), application_id.clone()));

        if let Some(entry) = self
            .entries
            .iter()
            .find(|e| e.application_id == application_id)
        {
            match entry.behavior {
                CmdBehavior::RetryableAt(fail) if fail == action => {
                    return Err(CmdError::Transport(format!(
                        "simulated SCMD outage at {action}"
                    )));
                }
                CmdBehavior::TerminalAt(fail) if fail == action => {
                    return Err(CmdError::OtpRejected {
                        code: "402".to_owned(),
                        message: "PIN/OTP rejeitado".to_owned(),
                    });
                }
                _ => {}
            }
        }

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

// --- failover-aware CSC mock ------------------------------------------------------------------

/// An offline CSC transport keyed by service `client_id`: any client id in `retryable_clients` fails
/// retryably at the OAuth token step (so the walk advances to the next entry); every token call's
/// `client_id` is recorded so a test can assert which entry authenticated in each phase.
#[derive(Clone)]
struct FailoverCscTransport {
    leaf_key: Arc<rsa::RsaPrivateKey>,
    info_json: String,
    retryable_clients: Arc<Vec<String>>,
    token_client_ids: Arc<Mutex<Vec<String>>>,
}

impl FailoverCscTransport {
    fn new(leaf: &RsaSigner, issuer: &RsaSigner, retryable_clients: Vec<String>) -> Self {
        let info_json = credentials_info_response(
            &[leaf.cert_der_b64(), issuer.cert_der_b64()],
            &[OID_RSA_ENCRYPTION],
        );
        Self {
            leaf_key: Arc::new(leaf.key.clone()),
            info_json,
            retryable_clients: Arc::new(retryable_clients),
            token_client_ids: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn token_client_ids(&self) -> Vec<String> {
        self.token_client_ids
            .lock()
            .expect("csc token clients poisoned")
            .clone()
    }
}

impl CscTransport for FailoverCscTransport {
    fn post_json(
        &self,
        path: &str,
        auth: CscAuthHeader<'_>,
        body: &str,
    ) -> Result<String, CscError> {
        if path == rest::PATH_OAUTH2_TOKEN {
            let client_id = match auth {
                CscAuthHeader::Basic { client_id, .. } => client_id.to_owned(),
                _ => "<none>".to_owned(),
            };
            self.token_client_ids
                .lock()
                .expect("csc token clients poisoned")
                .push(client_id.clone());
            if self.retryable_clients.contains(&client_id) {
                return Err(CscError::Transport(format!(
                    "simulated CSC outage for {client_id}"
                )));
            }
            return Ok(OAUTH_TOKEN_OK.to_string());
        }
        Ok(match path {
            rest::PATH_CREDENTIALS_LIST => CREDENTIALS_LIST_OK.to_string(),
            rest::PATH_CREDENTIALS_INFO => self.info_json.clone(),
            rest::PATH_CREDENTIALS_SEND_OTP => SEND_OTP_OK.to_string(),
            rest::PATH_CREDENTIALS_AUTHORIZE => r#"{ "SAD": "SAD-encosto-preprod" }"#.to_string(),
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
            other => return Err(CscError::Transport(format!("unexpected CSC path {other}"))),
        })
    }
}

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

type CscTransportFactory = Arc<dyn Fn(&CscConfig) -> Box<dyn CscTransport + Send> + Send + Sync>;

// --- test harness -----------------------------------------------------------------------------

struct TempDir(std::path::PathBuf);
impl TempDir {
    fn new() -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!("chancela-failover-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A durable state with a granted trust policy and NO env/settings-supplied credentials — every
/// signing credential comes from the multi-entry store, so the failover walk is exercised in full.
async fn state_with_trust(dir: &std::path::Path, granted: bool) -> AppState {
    ensure_credential_key();
    let trust_status = if granted {
        TrustedListStatus::Granted
    } else {
        TrustedListStatus::Withdrawn
    };
    let mut state = AppState::with_data_dir(dir);
    let policy: Arc<dyn Fn() -> Box<dyn TrustPolicy + Send> + Send + Sync> =
        Arc::new(move || Box::new(StaticTrustPolicy::new(trust_status)));
    state.cmd_trust_policy = Some(policy);
    {
        let mut settings = state.settings.write().await;
        // No settings ApplicationId: the stored multi-entry list is the only CMD credential source.
        settings.signing.cmd.application_id = None;
        settings.signing.tsa_url = None;
        settings.signing.tsa_providers.clear();
    }
    state
}

fn attach_cmd(state: &mut AppState, transport: FailoverCmdTransport) {
    state.cmd_transport = Some(Arc::new(transport));
}

fn attach_csc(state: &mut AppState, transport: FailoverCscTransport) {
    state.csc_providers = Arc::new(vec![csc_config()]);
    let factory: CscTransportFactory = Arc::new(move |_cfg| Box::new(transport.clone()));
    state.csc_transport = Some(factory);
}

/// Store one CMD entry (a distinct ApplicationId) at a priority + enabled flag.
fn put_cmd_entry(
    state: &AppState,
    entry_id: &str,
    application_id: &str,
    priority: i32,
    enabled: bool,
) {
    state
        .provider_credentials
        .put_entry(
            CredentialMode::Cmd,
            "",
            entry_id,
            Some(EntryMetadata {
                label: format!("cmd-{entry_id}"),
                priority,
                enabled,
                endpoint: None,
                selectors: EntrySelectors::new(),
            }),
            CmdCredentialFields {
                application_id: Some(zeroizing(application_id)),
                ..Default::default()
            }
            .into_set_pairs(),
            &[],
        )
        .expect("put cmd entry");
}

/// Store one CSC service entry (a distinct client id/secret) at a priority + enabled flag.
fn put_csc_entry(state: &AppState, entry_id: &str, client_id: &str, priority: i32, enabled: bool) {
    state
        .provider_credentials
        .put_entry(
            CredentialMode::CscQtsp,
            CSC_PROVIDER_ID,
            entry_id,
            Some(EntryMetadata {
                label: format!("csc-{entry_id}"),
                priority,
                enabled,
                endpoint: None,
                selectors: EntrySelectors::new(),
            }),
            CscCredentialFields {
                client_id: Some(zeroizing(client_id)),
                client_secret: Some(zeroizing(&format!("{client_id}-secret"))),
                ..Default::default()
            }
            .into_set_pairs(),
            &[],
        )
        .expect("put csc entry");
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
    let (status, session) = send(
        state,
        Request::builder()
            .method("POST")
            .uri("/v1/session")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({ "user_id": uid, "password": TEST_PASSWORD }).to_string(),
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
            json!({ "name": "Encosto Estratégico Lda", "nipc": "503004642", "seat": "Lisboa", "kind": "SociedadeAnonima" }),
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

// =============================================================================================
// CMD failover
// =============================================================================================

#[tokio::test]
async fn cmd_initiate_fails_over_on_a_retryable_error() {
    let dir = TempDir::new();
    let leaf = RsaSigner::new("Amélia Marques (CMD)", 1);
    let issuer = RsaSigner::new("Encosto Estratégico Lda — EC", 2);
    // Primary (priority 0) is unreachable at GetCertificate → retryable; secondary (priority 1) works.
    let transport = FailoverCmdTransport::new(
        &leaf,
        &issuer,
        vec![
            CmdMockEntry {
                application_id: APP_PRIMARY.to_owned(),
                behavior: CmdBehavior::RetryableAt(ACTION_GET_CERTIFICATE),
            },
            CmdMockEntry {
                application_id: APP_SECONDARY.to_owned(),
                behavior: CmdBehavior::Ok,
            },
        ],
    );
    let mut state = state_with_trust(&dir.0, true).await;
    attach_cmd(&mut state, transport.clone());
    put_cmd_entry(&state, "primary", APP_PRIMARY, 0, true);
    put_cmd_entry(&state, "secondary", APP_SECONDARY, 1, true);
    let token = bootstrap(&state).await;
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

    assert_eq!(status, StatusCode::OK, "failover initiate: {init}");
    assert_eq!(init["status"], "otp_pending");
    // The retryable top entry was tried, then the walk advanced to the working one.
    assert!(
        transport.saw_application_id(APP_PRIMARY),
        "the primary entry must have been attempted first"
    );
    assert_eq!(
        transport.application_id_at(ACTION_CCMOVEL_SIGN).as_deref(),
        Some(APP_SECONDARY),
        "the OTP must have been dispatched against the secondary (failed-over) entry"
    );
}

#[tokio::test]
async fn cmd_initiate_stops_on_terminal_and_does_not_burn_the_next_entry() {
    let dir = TempDir::new();
    let leaf = RsaSigner::new("Amélia Marques (CMD)", 1);
    let issuer = RsaSigner::new("Encosto Estratégico Lda — EC", 2);
    // Primary rejects the PIN at CCMovelSign → TERMINAL. Secondary would work, but must NOT be reached.
    let transport = FailoverCmdTransport::new(
        &leaf,
        &issuer,
        vec![
            CmdMockEntry {
                application_id: APP_PRIMARY.to_owned(),
                behavior: CmdBehavior::TerminalAt(ACTION_CCMOVEL_SIGN),
            },
            CmdMockEntry {
                application_id: APP_SECONDARY.to_owned(),
                behavior: CmdBehavior::Ok,
            },
        ],
    );
    let mut state = state_with_trust(&dir.0, true).await;
    attach_cmd(&mut state, transport.clone());
    put_cmd_entry(&state, "primary", APP_PRIMARY, 0, true);
    put_cmd_entry(&state, "secondary", APP_SECONDARY, 1, true);
    let token = bootstrap(&state).await;
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
        "a terminal provider rejection must surface, not fail over: {err}"
    );
    assert!(
        transport.saw_application_id(APP_PRIMARY),
        "the primary entry was attempted"
    );
    assert!(
        !transport.saw_application_id(APP_SECONDARY),
        "PIN/OTP-burn guard: the secondary entry must NEVER be contacted after a terminal error"
    );
    // No pending session was persisted.
    assert!(state.pending_signatures.read().await.is_empty());
}

#[tokio::test]
async fn cmd_confirm_resolves_the_same_entry_the_walk_chose() {
    let dir = TempDir::new();
    let leaf = RsaSigner::new("Amélia Marques (CMD)", 1);
    let issuer = RsaSigner::new("Encosto Estratégico Lda — EC", 2);
    // Primary fails over at initiate; the session is opened against the secondary entry.
    let transport = FailoverCmdTransport::new(
        &leaf,
        &issuer,
        vec![
            CmdMockEntry {
                application_id: APP_PRIMARY.to_owned(),
                behavior: CmdBehavior::RetryableAt(ACTION_GET_CERTIFICATE),
            },
            CmdMockEntry {
                application_id: APP_SECONDARY.to_owned(),
                behavior: CmdBehavior::Ok,
            },
        ],
    );
    let mut state = state_with_trust(&dir.0, true).await;
    attach_cmd(&mut state, transport.clone());
    put_cmd_entry(&state, "primary", APP_PRIMARY, 0, true);
    put_cmd_entry(&state, "secondary", APP_SECONDARY, 1, true);
    let token = bootstrap(&state).await;
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
    assert_eq!(done["family"], "ChaveMovelDigital");
    // Confirm ran ValidateOtp against the SAME (secondary) entry the walk pinned — never the default.
    assert_eq!(
        transport.application_id_at(ACTION_VALIDATE_OTP).as_deref(),
        Some(APP_SECONDARY),
        "confirm must resolve the pinned entry, not re-resolve default_entry"
    );
    assert!(
        !transport
            .calls()
            .iter()
            .any(|(action, app)| action == ACTION_VALIDATE_OTP && app == APP_PRIMARY),
        "confirm must never submit the OTP against the failed-over-from primary entry"
    );
}

#[tokio::test]
async fn cmd_initiate_uses_highest_priority_enabled_entry() {
    let leaf = RsaSigner::new("Amélia Marques (CMD)", 1);
    let issuer = RsaSigner::new("Encosto Estratégico Lda — EC", 2);

    // (a) Both enabled: the highest-priority (primary) entry is used; the secondary is never reached.
    {
        let dir = TempDir::new();
        let transport = FailoverCmdTransport::new(
            &leaf,
            &issuer,
            vec![
                CmdMockEntry {
                    application_id: APP_PRIMARY.to_owned(),
                    behavior: CmdBehavior::Ok,
                },
                CmdMockEntry {
                    application_id: APP_SECONDARY.to_owned(),
                    behavior: CmdBehavior::Ok,
                },
            ],
        );
        let mut state = state_with_trust(&dir.0, true).await;
        attach_cmd(&mut state, transport.clone());
        put_cmd_entry(&state, "primary", APP_PRIMARY, 0, true);
        put_cmd_entry(&state, "secondary", APP_SECONDARY, 1, true);
        let token = bootstrap(&state).await;
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
        assert_eq!(
            transport
                .application_id_at(ACTION_GET_CERTIFICATE)
                .as_deref(),
            Some(APP_PRIMARY),
            "the highest-priority entry must be used first"
        );
        assert!(
            !transport.saw_application_id(APP_SECONDARY),
            "a lower-priority entry must not be touched once a higher one succeeds"
        );
    }

    // (b) Primary DISABLED: it is skipped during resolution; the secondary is used.
    {
        let dir = TempDir::new();
        let transport = FailoverCmdTransport::new(
            &leaf,
            &issuer,
            vec![
                CmdMockEntry {
                    application_id: APP_PRIMARY.to_owned(),
                    behavior: CmdBehavior::Ok,
                },
                CmdMockEntry {
                    application_id: APP_SECONDARY.to_owned(),
                    behavior: CmdBehavior::Ok,
                },
            ],
        );
        let mut state = state_with_trust(&dir.0, true).await;
        attach_cmd(&mut state, transport.clone());
        put_cmd_entry(&state, "primary", APP_PRIMARY, 0, false);
        put_cmd_entry(&state, "secondary", APP_SECONDARY, 1, true);
        let token = bootstrap(&state).await;
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
        assert!(
            !transport.saw_application_id(APP_PRIMARY),
            "a disabled entry must be skipped entirely"
        );
        assert_eq!(
            transport
                .application_id_at(ACTION_GET_CERTIFICATE)
                .as_deref(),
            Some(APP_SECONDARY),
            "the next enabled entry must be used"
        );
    }
}

// =============================================================================================
// CSC (generic remote) failover
// =============================================================================================

#[tokio::test]
async fn csc_initiate_fails_over_on_a_retryable_error() {
    let dir = TempDir::new();
    let leaf = RsaSigner::new("Amélia Marques (QTSP)", 1);
    let issuer = RsaSigner::new("Encosto Estratégico Lda — EC", 2);
    // The primary client's token endpoint is unreachable (retryable); the secondary authenticates.
    let transport = FailoverCscTransport::new(&leaf, &issuer, vec![CSC_CLIENT_PRIMARY.to_owned()]);
    let mut state = state_with_trust(&dir.0, true).await;
    attach_csc(&mut state, transport.clone());
    put_csc_entry(&state, "primary", CSC_CLIENT_PRIMARY, 0, true);
    put_csc_entry(&state, "secondary", CSC_CLIENT_SECONDARY, 1, true);
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

    assert_eq!(status, StatusCode::OK, "csc failover initiate: {init}");
    assert_eq!(init["status"], "activation_pending");
    assert_eq!(init["provider_id"], CSC_PROVIDER_ID);
    let seen = transport.token_client_ids();
    assert!(
        seen.contains(&CSC_CLIENT_PRIMARY.to_owned()),
        "the primary client must have been attempted first: {seen:?}"
    );
    assert!(
        seen.contains(&CSC_CLIENT_SECONDARY.to_owned()),
        "the walk must have advanced to the secondary client: {seen:?}"
    );
}

#[tokio::test]
async fn csc_confirm_resolves_the_same_entry_the_walk_chose() {
    let dir = TempDir::new();
    let leaf = RsaSigner::new("Amélia Marques (QTSP)", 1);
    let issuer = RsaSigner::new("Encosto Estratégico Lda — EC", 2);
    let transport = FailoverCscTransport::new(&leaf, &issuer, vec![CSC_CLIENT_PRIMARY.to_owned()]);
    let mut state = state_with_trust(&dir.0, true).await;
    attach_csc(&mut state, transport.clone());
    put_csc_entry(&state, "primary", CSC_CLIENT_PRIMARY, 0, true);
    put_csc_entry(&state, "secondary", CSC_CLIENT_SECONDARY, 1, true);
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
    // Confirm can only succeed by re-authenticating with the PINNED secondary client: there is no
    // default entry to fall back to, and confirm never fails over.
    assert_eq!(status, StatusCode::OK, "confirm: {done}");
    assert_eq!(done["provider_id"], CSC_PROVIDER_ID);
    assert_eq!(
        transport.token_client_ids().last().map(String::as_str),
        Some(CSC_CLIENT_SECONDARY),
        "confirm must re-authenticate with the pinned (secondary) entry, not default_entry"
    );
}
