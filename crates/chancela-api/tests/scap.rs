//! SCAP professional-attribute endpoint tests (t67-e10).
//!
//! Preprod/default coverage uses the offline mock transport. Prod credential-resolution coverage uses
//! a local loopback HTTP fixture only, never external network. The load-bearing assertions are the
//! **honesty markers**: a mock-backed attribute signature is always `declared` and never
//! `verified_by_scap`, and production requests fail closed without usable credentials.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration as StdDuration;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use der::Encode;
use der::asn1::{Any, BitString, ObjectIdentifier};
use rsa::pkcs8::EncodePrivateKey;
use serde_json::{Value, json};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use tokio::sync::Mutex as AsyncMutex;
use tower::ServiceExt;
use uuid::Uuid;
use x509_cert::certificate::{Certificate, TbsCertificate, Version};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;
use zeroize::Zeroizing;

use chancela_api::{
    AppState, CredentialFieldSet, CredentialMode, EntryMetadata, EntrySelectors,
    ScapCredentialFields, User, UserId, router,
};
use chancela_authz::{OWNER_ROLE_ID, RoleAssignment, RoleCatalog, Scope};
use time::format_description::well_known::Rfc3339;

use common::{TEST_PASSWORD, password_hash};

const PASSWORD: &str = "correct horse battery staple";
const FRIENDLY_NAME: &str = "scap signing identity";
const OID_SHA256_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
// The fictional signing citizen the mock fixtures carry (see chancela-scap mock transport).
const FIXTURE_CITIZEN_ID: &str = "199000001";
const PROVIDER_CREDENTIAL_SIDECAR_FILE: &str = "provider-credentials.enc.json";
const PROVIDER_CREDENTIAL_ENV_KEYS: [&str; 3] = [
    "CHANCELA_CREDENTIAL_KEY",
    "CHANCELA_CREDENTIAL_KEY_FILE",
    "CHANCELA_CREDENTIAL_STRICT",
];
const SCAP_ENV_KEYS: [&str; 5] = [
    "CHANCELA_SCAP_ENV",
    "CHANCELA_SCAP_BASE_URL",
    "CHANCELA_SCAP_APPLICATION_ID",
    "CHANCELA_SCAP_SECRET",
    "CHANCELA_SCAP_PROVIDER_FILTER",
];
static ENV_LOCK: AsyncMutex<()> = AsyncMutex::const_new(());

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

async fn owner_session(state: &AppState) -> String {
    *state.roles.write().await = RoleCatalog::seeded_defaults();
    let uid = UserId(Uuid::new_v4());
    let created_at = time::OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("created_at");
    state.users.write().await.insert(
        uid,
        User {
            id: uid,
            username: format!("user-{}", uid.0),
            display_name: "SCAP Signer".to_owned(),
            email: None,
            created_at,
            active: true,
            password_hash: Some(password_hash()),
            attestation_key: None,
            retired_attestation_keys: Vec::new(),
            totp: None,
            two_factor_required: false,
            force_password_change: false,
            secret_source: Default::default(),
            recovery_hash: None,
            role_assignments: vec![RoleAssignment::new(OWNER_ROLE_ID, Scope::Global)],
            language: Default::default(),
        },
    );
    let (status, session) = send(
        state,
        Request::builder()
            .method("POST")
            .uri("/v1/session")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({ "user_id": uid.0, "password": TEST_PASSWORD }).to_string(),
            ))
            .expect("request builds"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "session: {session}");
    session["token"].as_str().expect("token").to_owned()
}

fn build_self_signed(cn: &str, serial: u8, spki: SubjectPublicKeyInfoOwned) -> Vec<u8> {
    let name = Name::from_str(&format!("CN={cn}")).expect("name");
    let validity = Validity::from_now(StdDuration::from_secs(365 * 24 * 3600)).expect("validity");
    let sig_alg = AlgorithmIdentifierOwned {
        oid: OID_SHA256_WITH_RSA,
        parameters: Some(Any::null()),
    };
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
    let cert = Certificate {
        tbs_certificate: tbs,
        signature_algorithm: sig_alg,
        signature: BitString::from_bytes(&[0u8; 256]).expect("bitstring"),
    };
    cert.to_der().expect("cert der")
}

fn build_pfx() -> Vec<u8> {
    let key = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).expect("rsa keygen");
    let spki =
        SubjectPublicKeyInfoOwned::from_key(rsa::RsaPublicKey::from(&key)).expect("rsa spki");
    let cert = build_self_signed("SCAP Signer", 1, spki);
    let key_der = key.to_pkcs8_der().expect("rsa pkcs8");
    p12::PFX::new(&cert, key_der.as_bytes(), None, PASSWORD, FRIENDLY_NAME)
        .expect("pfx")
        .to_der()
}

async fn local_state() -> (AppState, String) {
    let state = AppState {
        local_signing: true,
        ..AppState::default()
    };
    let token = owner_session(&state).await;
    (state, token)
}

async fn local_state_at(dir: &Path) -> (AppState, String) {
    let mut state = AppState::with_data_dir(dir);
    state.local_signing = true;
    let token = owner_session(&state).await;
    (state, token)
}

struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new() -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!("chancela-scap-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&p).expect("create temp dir");
        Self(p)
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

fn env_keys() -> Vec<&'static str> {
    PROVIDER_CREDENTIAL_ENV_KEYS
        .into_iter()
        .chain(SCAP_ENV_KEYS)
        .collect()
}

fn clear_scap_test_env() {
    for key in env_keys() {
        unsafe {
            std::env::remove_var(key);
        }
    }
}

fn set_provider_credential_test_key() {
    unsafe {
        std::env::set_var(
            "CHANCELA_CREDENTIAL_KEY",
            "scap-provider-credential-test-key",
        );
        std::env::remove_var("CHANCELA_CREDENTIAL_KEY_FILE");
        std::env::remove_var("CHANCELA_CREDENTIAL_STRICT");
    }
}

fn zeroizing(value: &str) -> Zeroizing<String> {
    Zeroizing::new(value.to_owned())
}

fn seed_stored_scap_credentials(state: &AppState, application_id: &str, secret: &str) {
    state
        .provider_credentials
        .put(
            CredentialMode::Scap,
            "",
            ScapCredentialFields {
                application_id: Some(zeroizing(application_id)),
                secret: Some(zeroizing(secret)),
                ..Default::default()
            }
            .into_set_pairs(),
            &[],
        )
        .expect("seed stored SCAP credentials");
}

fn seed_incomplete_stored_scap_credentials(state: &AppState) {
    state
        .provider_credentials
        .put(
            CredentialMode::Scap,
            "",
            ScapCredentialFields {
                application_id: Some(zeroizing("stored-scap-app-fixture")),
                ..Default::default()
            }
            .into_set_pairs(),
            &[],
        )
        .expect("seed incomplete stored SCAP credentials");
}

fn seed_disabled_stored_scap_credentials(state: &AppState, application_id: &str, secret: &str) {
    state
        .provider_credentials
        .put_entry(
            CredentialMode::Scap,
            "",
            "disabled",
            Some(EntryMetadata {
                label: "disabled SCAP fixture".to_owned(),
                priority: 0,
                enabled: false,
                endpoint: None,
                selectors: EntrySelectors::new(),
            }),
            ScapCredentialFields {
                application_id: Some(zeroizing(application_id)),
                secret: Some(zeroizing(secret)),
                ..Default::default()
            }
            .into_set_pairs(),
            &[],
        )
        .expect("seed disabled stored SCAP credentials");
}

fn tamper_stored_scap_secret_ciphertext(dir: &Path) {
    let path = dir.join(PROVIDER_CREDENTIAL_SIDECAR_FILE);
    let bytes = std::fs::read(&path).expect("read provider credential sidecar");
    let mut sidecar: Value = serde_json::from_slice(&bytes).expect("parse credential sidecar");
    let records = sidecar
        .get_mut("records")
        .and_then(Value::as_array_mut)
        .expect("sidecar records");
    let record = records
        .iter_mut()
        .find(|record| {
            record.get("mode").and_then(Value::as_str) == Some("scap")
                && record.get("provider_id").and_then(Value::as_str) == Some("")
        })
        .expect("stored SCAP record");
    let entries = record
        .get_mut("entries")
        .and_then(Value::as_array_mut)
        .expect("SCAP record entries");
    let entry = entries
        .iter_mut()
        .find(|entry| entry.get("id").and_then(Value::as_str) == Some("default"))
        .expect("default SCAP entry");
    let ciphertext = entry
        .pointer_mut("/fields/secret/ciphertext_b64")
        .expect("stored SCAP secret ciphertext");
    let tampered = tamper_base64(ciphertext.as_str().expect("secret ciphertext is string"));
    *ciphertext = Value::String(tampered);
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&sidecar).expect("serialize tampered sidecar"),
    )
    .expect("write tampered provider credential sidecar");
}

fn tamper_base64(value: &str) -> String {
    let mut chars: Vec<char> = value.chars().collect();
    let pos = chars
        .iter()
        .rposition(|c| *c != '=')
        .expect("non-empty base64 payload");
    chars[pos] = if chars[pos] == 'A' { 'B' } else { 'A' };
    chars.into_iter().collect()
}

struct MockScapServer {
    url: String,
    request: Arc<Mutex<Option<String>>>,
}

impl MockScapServer {
    fn providers() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock SCAP");
        let url = format!("http://{}", listener.local_addr().expect("local addr"));
        let request = Arc::new(Mutex::new(None));
        let request_for_thread = request.clone();
        thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                handle_scap_connection(stream, request_for_thread);
            }
        });
        Self { url, request }
    }

    fn url(&self) -> &str {
        &self.url
    }

    fn request_text(&self) -> String {
        for _ in 0..100 {
            if let Some(req) = self.request.lock().expect("request lock").clone() {
                return req;
            }
            thread::sleep(StdDuration::from_millis(10));
        }
        panic!("mock SCAP fixture did not receive a request")
    }
}

fn handle_scap_connection(mut stream: TcpStream, request: Arc<Mutex<Option<String>>>) {
    let _ = stream.set_read_timeout(Some(StdDuration::from_secs(5)));
    let raw = read_http_request(&mut stream).expect("read SCAP request");
    let text = String::from_utf8_lossy(&raw).into_owned();
    *request.lock().expect("request lock") = Some(text);
    write_response(
        &mut stream,
        "200 OK",
        "application/json",
        br#"[{"id":"OA","name":"Ordem dos Advogados","attribute_names":["Advogado"]}]"#,
    );
}

fn read_http_request(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(header_end) = find_bytes(&buf, b"\r\n\r\n") {
            let body_start = header_end + 4;
            let content_length = content_length(&buf[..header_end]).unwrap_or(0);
            while buf.len() < body_start + content_length {
                let n = stream.read(&mut tmp)?;
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
            }
            break;
        }
    }
    Ok(buf)
}

fn content_length(headers: &[u8]) -> Option<usize> {
    let text = std::str::from_utf8(headers).ok()?;
    text.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if name.eq_ignore_ascii_case("content-length") {
            value.trim().parse().ok()
        } else {
            None
        }
    })
}

fn write_response(stream: &mut TcpStream, status: &str, content_type: &str, body: &[u8]) {
    let headers = format!(
        "HTTP/1.1 {status}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(headers.as_bytes()).expect("write headers");
    stream.write_all(body).expect("write body");
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn expected_basic_auth(application_id: &str, secret: &str) -> String {
    format!(
        "Basic {}",
        B64.encode(format!("{application_id}:{secret}").as_bytes())
    )
}

fn authorization_header(request: &str) -> Option<&str> {
    request.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if name.eq_ignore_ascii_case("authorization") {
            Some(value.trim())
        } else {
            None
        }
    })
}

fn authorization_header_state(value: Option<&str>) -> &'static str {
    match value {
        Some(value) if value.starts_with("Basic ") => "basic",
        Some(_) => "non-basic",
        None => "missing",
    }
}

fn assert_request_uses_basic_auth(request: &str, expected: &str, context: &str) {
    let actual = authorization_header(request);
    assert!(
        actual == Some(expected),
        "{context}: expected matching Basic Authorization header; actual authorization state: {}",
        authorization_header_state(actual)
    );
}

fn assert_request_does_not_use_basic_auth(request: &str, unexpected: &str, context: &str) {
    assert!(
        authorization_header(request) != Some(unexpected),
        "{context}: unexpected fixture Basic Authorization header was present"
    );
}

#[tokio::test]
async fn scap_lists_mock_providers() {
    let (state, token) = local_state().await;
    let (status, body) = send(
        &state,
        json_req("POST", "/v1/scap/providers", &token, json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "providers: {body}");
    assert_eq!(body["transport"], "mock");
    let providers = body["providers"].as_array().expect("providers");
    assert_eq!(providers.len(), 2, "{body}");
    assert!(providers.iter().any(|p| p["id"] == "OA"));
    assert!(providers.iter().any(|p| p["id"] == "OE"));
}

#[tokio::test]
async fn scap_fetches_citizen_attributes() {
    let (state, token) = local_state().await;
    let (status, body) = send(
        &state,
        json_req(
            "POST",
            "/v1/scap/attributes",
            &token,
            json!({ "citizen_id": FIXTURE_CITIZEN_ID }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "attributes: {body}");
    let attrs = body["attributes"].as_array().expect("attributes");
    assert_eq!(attrs.len(), 2, "{body}");
    assert!(attrs.iter().any(|a| a["name"] == "Advogado"));
}

#[tokio::test]
async fn scap_sign_is_declared_only_never_verified() {
    let (state, token) = local_state().await;
    let pfx = build_pfx();

    let (status, body) = send(
        &state,
        json_req(
            "POST",
            "/v1/scap/sign",
            &token,
            json!({
                "citizen_id": FIXTURE_CITIZEN_ID,
                "provider_id": "OA",
                "attribute_name": "Advogado",
                "content_base64": B64.encode(b"content bound under a professional capacity"),
                "signer": {
                    "kind": "soft_pkcs12",
                    "pkcs12_base64": B64.encode(&pfx),
                    "passphrase": PASSWORD,
                    "friendly_name": FRIENDLY_NAME,
                },
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "scap sign: {body}");
    assert_eq!(body["transport"], "mock");
    let v = &body["verification"];
    // The load-bearing honesty invariant: the mock can NEVER yield a verified capacity.
    assert_eq!(v["verified"], false, "{body}");
    assert_eq!(v["verification_status"], "declared_capacity_by_provider");
    assert_eq!(v["status_scope"], "declared_capacity_evidence_only");
    assert_ne!(v["verification_status"], "verified_by_scap");
    assert_ne!(v["status_scope"], "scap_verified_capacity");
    assert_eq!(v["attribute_name"], "Advogado");
    assert_eq!(v["provider_id"], "OA");
    // A real (technical) signature was produced.
    assert!(
        !body["signature_base64"].as_str().unwrap_or("").is_empty(),
        "{body}"
    );
}

#[tokio::test]
async fn scap_sign_rejects_unreported_attribute() {
    let (state, token) = local_state().await;
    let pfx = build_pfx();

    let (status, body) = send(
        &state,
        json_req(
            "POST",
            "/v1/scap/sign",
            &token,
            json!({
                "citizen_id": FIXTURE_CITIZEN_ID,
                "provider_id": "OA",
                "attribute_name": "Notario",
                "content_base64": B64.encode(b"x"),
                "signer": {
                    "kind": "soft_pkcs12",
                    "pkcs12_base64": B64.encode(&pfx),
                    "passphrase": PASSWORD,
                    "friendly_name": FRIENDLY_NAME,
                },
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
}

#[tokio::test]
async fn scap_prod_uses_stored_credentials_with_credential_env_cleared() {
    let _guard = ENV_LOCK.lock().await;
    let keys = env_keys();
    let _env = EnvRestore::capture(&keys);
    clear_scap_test_env();
    set_provider_credential_test_key();

    let server = MockScapServer::providers();
    unsafe {
        std::env::set_var("CHANCELA_SCAP_BASE_URL", server.url());
    }
    let dir = TempDir::new();
    let (state, token) = local_state_at(&dir.0).await;
    seed_stored_scap_credentials(&state, "stored-scap-app", "stored-scap-secret");

    let (status, body) = send(
        &state,
        json_req(
            "POST",
            "/v1/scap/providers",
            &token,
            json!({ "environment": "prod" }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "stored prod SCAP: {body}");
    assert_eq!(body["transport"], "http");
    let providers = body["providers"].as_array().expect("providers");
    assert!(providers.iter().any(|p| p["id"] == "OA"), "{body}");
    let req = server.request_text();
    assert_request_uses_basic_auth(
        &req,
        &expected_basic_auth("stored-scap-app", "stored-scap-secret"),
        "stored credentials must be sent to SCAP fixture",
    );
}

#[tokio::test]
async fn scap_prod_uses_env_credentials_when_no_stored_credentials_exist() {
    let _guard = ENV_LOCK.lock().await;
    let keys = env_keys();
    let _env = EnvRestore::capture(&keys);
    clear_scap_test_env();

    let server = MockScapServer::providers();
    unsafe {
        std::env::set_var("CHANCELA_SCAP_BASE_URL", server.url());
        std::env::set_var("CHANCELA_SCAP_APPLICATION_ID", "env-scap-app");
        std::env::set_var("CHANCELA_SCAP_SECRET", "env-scap-secret");
    }
    let (state, token) = local_state().await;

    let (status, body) = send(
        &state,
        json_req(
            "POST",
            "/v1/scap/providers",
            &token,
            json!({ "environment": "prod" }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "env fallback SCAP: {body}");
    let req = server.request_text();
    assert_request_uses_basic_auth(
        &req,
        &expected_basic_auth("env-scap-app", "env-scap-secret"),
        "env credentials must be used when no SCAP credential is stored",
    );
}

#[tokio::test]
async fn scap_stored_credentials_win_over_env() {
    let _guard = ENV_LOCK.lock().await;
    let keys = env_keys();
    let _env = EnvRestore::capture(&keys);
    clear_scap_test_env();
    set_provider_credential_test_key();

    let server = MockScapServer::providers();
    unsafe {
        std::env::set_var("CHANCELA_SCAP_BASE_URL", server.url());
        std::env::set_var("CHANCELA_SCAP_APPLICATION_ID", "env-scap-app");
        std::env::set_var("CHANCELA_SCAP_SECRET", "env-scap-secret");
    }
    let dir = TempDir::new();
    let (state, token) = local_state_at(&dir.0).await;
    seed_stored_scap_credentials(&state, "stored-scap-app", "stored-scap-secret");

    let (status, body) = send(
        &state,
        json_req(
            "POST",
            "/v1/scap/providers",
            &token,
            json!({ "environment": "prod" }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "stored beats env: {body}");
    let req = server.request_text();
    assert_request_uses_basic_auth(
        &req,
        &expected_basic_auth("stored-scap-app", "stored-scap-secret"),
        "stored credentials must win over env",
    );
    assert_request_does_not_use_basic_auth(
        &req,
        &expected_basic_auth("env-scap-app", "env-scap-secret"),
        "env credentials must not be mixed when stored credentials exist",
    );
}

#[tokio::test]
async fn scap_incomplete_stored_credentials_fail_closed_without_env_fallback() {
    let _guard = ENV_LOCK.lock().await;
    let keys = env_keys();
    let _env = EnvRestore::capture(&keys);
    clear_scap_test_env();
    set_provider_credential_test_key();
    unsafe {
        std::env::set_var("CHANCELA_SCAP_BASE_URL", "http://127.0.0.1:9/scap");
        std::env::set_var("CHANCELA_SCAP_APPLICATION_ID", "env-scap-app");
        std::env::set_var("CHANCELA_SCAP_SECRET", "env-scap-secret");
    }
    let dir = TempDir::new();
    let (state, token) = local_state_at(&dir.0).await;
    seed_incomplete_stored_scap_credentials(&state);

    let (status, err) = send(
        &state,
        json_req(
            "POST",
            "/v1/scap/providers",
            &token,
            json!({ "environment": "prod" }),
        ),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "incomplete stored credentials must fail closed: {err}"
    );
    let msg = err["error"].as_str().unwrap_or_default();
    assert!(msg.contains("mode 'scap'"), "mode is named: {err}");
    assert!(msg.contains("secret"), "missing field is named: {err}");
}

#[tokio::test]
async fn scap_disabled_stored_credentials_fail_closed_without_env_fallback() {
    let _guard = ENV_LOCK.lock().await;
    let keys = env_keys();
    let _env = EnvRestore::capture(&keys);
    clear_scap_test_env();
    set_provider_credential_test_key();
    unsafe {
        std::env::set_var("CHANCELA_SCAP_BASE_URL", "http://127.0.0.1:9/scap");
        std::env::set_var("CHANCELA_SCAP_APPLICATION_ID", "env-scap-app");
        std::env::set_var("CHANCELA_SCAP_SECRET", "env-scap-secret");
    }
    let dir = TempDir::new();
    let (state, token) = local_state_at(&dir.0).await;
    seed_disabled_stored_scap_credentials(&state, "stored-scap-app", "stored-scap-secret");

    let (status, err) = send(
        &state,
        json_req(
            "POST",
            "/v1/scap/providers",
            &token,
            json!({ "environment": "prod" }),
        ),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "disabled stored credentials must fail closed: {err}"
    );
    let msg = err["error"].as_str().unwrap_or_default();
    assert!(msg.contains("mode 'scap'"), "mode is named: {err}");
    assert!(msg.contains("disabled"), "disabled state is named: {err}");
}

#[tokio::test]
async fn scap_preprod_mock_ignores_stored_credentials_and_never_verifies() {
    let _guard = ENV_LOCK.lock().await;
    let keys = env_keys();
    let _env = EnvRestore::capture(&keys);
    clear_scap_test_env();
    set_provider_credential_test_key();

    let dir = TempDir::new();
    {
        let (seed_state, _) = local_state_at(&dir.0).await;
        seed_stored_scap_credentials(&seed_state, "stored-scap-app", "stored-scap-secret");
    }
    tamper_stored_scap_secret_ciphertext(&dir.0);
    let (state, token) = local_state_at(&dir.0).await;
    let pfx = build_pfx();

    let (status, body) = send(
        &state,
        json_req(
            "POST",
            "/v1/scap/sign",
            &token,
            json!({
                "citizen_id": FIXTURE_CITIZEN_ID,
                "provider_id": "OA",
                "attribute_name": "Advogado",
                "content_base64": B64.encode(b"mock preprod ignores stored SCAP credentials"),
                "signer": {
                    "kind": "soft_pkcs12",
                    "pkcs12_base64": B64.encode(&pfx),
                    "passphrase": PASSWORD,
                    "friendly_name": FRIENDLY_NAME,
                },
            }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "preprod mock sign: {body}");
    assert_eq!(body["transport"], "mock");
    let v = &body["verification"];
    assert_eq!(v["verified"], false, "{body}");
    assert_ne!(v["verification_status"], "verified_by_scap");
}

#[tokio::test]
async fn scap_prod_without_credentials_fails_closed() {
    let _guard = ENV_LOCK.lock().await;
    let keys = env_keys();
    let _env = EnvRestore::capture_and_remove(&keys);
    // A production request without deployment-supplied AMA credentials must be rejected before any
    // provider listing / signature is produced. Deterministic: the test process sets no SCAP creds.
    let (state, token) = local_state().await;
    let (status, body) = send(
        &state,
        json_req(
            "POST",
            "/v1/scap/providers",
            &token,
            json!({ "environment": "prod" }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "prod must fail closed: {body}"
    );
}
