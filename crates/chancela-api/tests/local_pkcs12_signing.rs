//! Local PKCS#12 software-certificate signing API regression tests.
//!
//! The PFX is generated in-process: no checked-in private keys, no OS certificate store, and no
//! network. The API must persist only the signed PDF plus public evidence labels.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
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
use p12::PFX;
use rsa::pkcs8::EncodePrivateKey;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use tokio::sync::Mutex as AsyncMutex;
use tower::ServiceExt;
use uuid::Uuid;
use x509_cert::certificate::{Certificate, TbsCertificate, Version};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;

use chancela_api::{AppState, User, UserId, router};
use chancela_authz::{OWNER_ROLE_ID, RoleAssignment, RoleCatalog, Scope};
use chancela_core::ActId;
use chancela_pades::validate_pdf_signature;
use time::format_description::well_known::Rfc3339;

use common::{TEST_PASSWORD, password_hash};

const PASSWORD: &str = "correct horse battery staple";
const FRIENDLY_NAME: &str = "local advanced signing identity";
const OID_SHA256_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const FIXTURE_CITIZEN_ID: &str = "199000001";
const SCAP_ENV_KEYS: [&str; 4] = [
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

fn clear_scap_test_env() {
    for key in SCAP_ENV_KEYS {
        unsafe {
            std::env::remove_var(key);
        }
    }
}

struct MockScapServer {
    url: String,
    requests: Arc<Mutex<Vec<String>>>,
}

impl MockScapServer {
    fn granted_attribute() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock SCAP");
        let url = format!("http://{}", listener.local_addr().expect("local addr"));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let requests_for_thread = requests.clone();
        thread::spawn(move || {
            for _ in 0..2 {
                if let Ok((stream, _)) = listener.accept() {
                    handle_scap_connection(stream, requests_for_thread.clone());
                }
            }
        });
        Self { url, requests }
    }

    fn url(&self) -> &str {
        &self.url
    }

    fn request_texts(&self) -> Vec<String> {
        for _ in 0..100 {
            let requests = self.requests.lock().expect("request lock").clone();
            if requests.len() >= 2 {
                return requests;
            }
            thread::sleep(StdDuration::from_millis(10));
        }
        panic!("mock SCAP fixture did not receive both requests")
    }
}

fn handle_scap_connection(mut stream: TcpStream, requests: Arc<Mutex<Vec<String>>>) {
    let _ = stream.set_read_timeout(Some(StdDuration::from_secs(5)));
    let raw = read_http_request(&mut stream).expect("read SCAP request");
    let text = String::from_utf8_lossy(&raw).into_owned();
    requests.lock().expect("request lock").push(text.clone());
    let first_line = text.lines().next().unwrap_or_default();
    if first_line.starts_with("POST /attributes ") {
        write_response(
            &mut stream,
            "200 OK",
            "application/json",
            br#"[{"provider_id":"OA","provider_name":"Ordem dos Advogados","name":"Advogado","sub_attributes":[{"name":"cedula","value":"12345"}]}]"#,
        );
    } else if first_line.starts_with("POST /verify ") {
        write_response(
            &mut stream,
            "200 OK",
            "application/json",
            br#"{"decision":"Granted","authority_reference":"OA-grant-2026-fixture"}"#,
        );
    } else {
        write_response(
            &mut stream,
            "404 Not Found",
            "application/json",
            br#"{"error":"unexpected SCAP route"}"#,
        );
    }
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

async fn bootstrap(state: &AppState) -> (String, String) {
    *state.roles.write().await = RoleCatalog::seeded_defaults();
    let uid = UserId(Uuid::new_v4());
    let created_at = time::OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("created_at");
    let user = User {
        id: uid,
        username: "amelia.marques".to_owned(),
        display_name: "Amelia Marques".to_owned(),
        email: None,
        created_at,
        active: true,
        password_hash: Some(password_hash()),
        attestation_key: None,
        secret_source: Default::default(),
        recovery_hash: None,
        role_assignments: vec![RoleAssignment::new(OWNER_ROLE_ID, Scope::Global)],
    };
    state.users.write().await.insert(uid, user);
    let uid = uid.to_string();
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

async fn seed_book(state: &AppState, token: &str) -> String {
    let (status, entity) = send(
        state,
        json_req(
            "POST",
            "/v1/entities",
            token,
            json!({ "name": "Encosto Estrategico, S.A.", "nipc": "503004642", "seat": "Lisboa", "kind": "SociedadeAnonima" }),
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
    book["id"].as_str().unwrap().to_owned()
}

async fn create_signing_act(state: &AppState, token: &str, book_id: &str) -> String {
    let (status, act) = send(
        state,
        json_req(
            "POST",
            "/v1/acts",
            token,
            json!({ "book_id": book_id, "title": "Ata assinatura local", "channel": "Physical" }),
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
                "mesa": { "presidente": "Ana Presidente", "secretarios": ["Rui Secretario"] },
                "agenda": [{ "number": 1, "text": "Aprovacao das contas" }],
                "attendance_reference": "Lista de presencas",
                "deliberations": "Deliberacao aprovada."
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

async fn seal_act(state: &AppState, token: &str, act_id: &str) {
    let (status, sealed) = send(
        state,
        json_req("POST", &format!("/v1/acts/{act_id}/seal"), token, json!({ "manual_signature_original_reference": { "storage_reference": "Arquivo A / Pasta 2026 / Ata teste" } })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "seal: {sealed}");
}

async fn disable_timestamping(state: &AppState) {
    let mut settings = state.settings.write().await;
    settings.signing.tsa_url = None;
    settings.signing.tsa_providers.clear();
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

fn local_pfx() -> Vec<u8> {
    let key = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).expect("rsa keygen");
    let spki =
        SubjectPublicKeyInfoOwned::from_key(rsa::RsaPublicKey::from(&key)).expect("rsa spki");
    let cert = build_self_signed("Local PKCS12 Signer", 1, spki);
    let issuer_key = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).expect("issuer key");
    let issuer_spki = SubjectPublicKeyInfoOwned::from_key(rsa::RsaPublicKey::from(&issuer_key))
        .expect("issuer spki");
    let issuer = build_self_signed("Local PKCS12 Test Issuer", 2, issuer_spki);
    let key_der = key.to_pkcs8_der().expect("rsa pkcs8");
    PFX::new_with_cas(
        &cert,
        key_der.as_bytes(),
        &[&issuer],
        PASSWORD,
        FRIENDLY_NAME,
    )
    .expect("pfx")
    .to_der()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
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
}

fn local_sign_req(act_id: &str, token: &str, pfx: &[u8], passphrase: &str) -> Request<Body> {
    local_sign_req_with_body(
        act_id,
        token,
        json!({
            "pkcs12_base64": B64.encode(pfx),
            "passphrase": passphrase,
            "friendly_name": FRIENDLY_NAME,
            "capacity": "Administrador"
        }),
    )
}

fn local_sign_req_with_body(act_id: &str, token: &str, body: Value) -> Request<Body> {
    json_req(
        "POST",
        &format!("/v1/acts/{act_id}/signature/local/pkcs12/sign"),
        token,
        body,
    )
}

#[tokio::test]
async fn local_pkcs12_signs_as_advanced_technical_evidence_only() {
    let state = AppState {
        local_signing: true,
        ..AppState::default()
    };
    let (token, _) = bootstrap(&state).await;
    state
        .settings
        .write()
        .await
        .signing
        .require_qualified_for_seal = true;
    {
        let mut settings = state.settings.write().await;
        settings.signing.tsa_url = None;
        settings.signing.tsa_providers.clear();
    }
    let book_id = seed_book(&state, &token).await;
    let act_id = create_signing_act(&state, &token, &book_id).await;
    seal_act(&state, &token, &act_id).await;

    let pfx = local_pfx();
    let (status, signed) = send(&state, local_sign_req(&act_id, &token, &pfx, PASSWORD)).await;
    assert_eq!(status, StatusCode::OK, "local pkcs12 sign: {signed}");
    assert_eq!(signed["family"], "LocalPkcs12SoftwareCertificate");
    assert_eq!(
        signed["evidentiary_level"],
        "AdvancedLocalTechnicalEvidence"
    );
    assert_eq!(signed["trusted_list_status"], Value::Null);
    assert_eq!(signed["qualification_claimed"], false);
    assert_eq!(signed["legal_status_claimed"], false);
    assert_eq!(signed["status_scope"], "local_technical_evidence_only");
    assert_eq!(signed["finalization"], "aguarda_assinatura_qualificada");
    assert_eq!(
        signed["signer_capacity_evidence"]["requested_provider_capacity"],
        "Administrador"
    );
    assert_eq!(
        signed["signer_capacity_evidence"]["verification_status"],
        "not_checked_by_scap"
    );
    assert!(
        signed["notice"]
            .as_str()
            .expect("notice")
            .contains("no qualified remote/CMD signature")
    );

    let (status, downloaded) = send_bytes(
        &state,
        get_req(&format!("/v1/acts/{act_id}/document/signed"), &token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    validate_pdf_signature(&downloaded).expect("signed PDF validates");
    assert_eq!(
        signed["signed_pdf_digest"].as_str().expect("digest"),
        sha256_hex(&downloaded)
    );

    let (status, view) = send(
        &state,
        get_req(&format!("/v1/acts/{act_id}/signature"), &token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(view["status"], "signed");
    assert_eq!(view["finalization"], "aguarda_assinatura_qualificada");
    assert_eq!(view["signed"]["family"], "LocalPkcs12SoftwareCertificate");
    assert_eq!(
        view["signed"]["evidentiary_level"],
        "AdvancedLocalTechnicalEvidence"
    );
    assert_ne!(view["signed"]["evidentiary_level"], "Qualified");
    assert_eq!(view["evidence"]["current_level"], "B-B");
    assert_eq!(view["evidence"]["status_scope"], "technical_evidence_only");
    assert_eq!(
        view["signed"]["signer_capacity_evidence"]["requested_provider_capacity"],
        "Administrador"
    );
    assert_eq!(
        view["signed"]["signer_capacity_evidence"]["status_scope"],
        "declared_capacity_evidence_only"
    );
    assert_eq!(signed_event_count(&state, &token, &act_id).await, 1);

    let stored = state
        .signed_documents
        .read()
        .await
        .get(&ActId(Uuid::parse_str(&act_id).expect("act uuid")))
        .expect("stored signed doc")
        .clone();
    assert_eq!(stored.signature_family, "LocalPkcs12SoftwareCertificate");
    assert_eq!(stored.evidentiary_level, "AdvancedLocalTechnicalEvidence");
    assert_eq!(stored.trusted_list_status, None);
    let capacity_evidence = stored
        .signer_capacity_evidence_json
        .as_deref()
        .expect("stored capacity evidence");
    assert!(capacity_evidence.contains("\"verification_status\":\"not_checked_by_scap\""));
    assert!(!capacity_evidence.contains("qualified_capacity"));
    assert!(!String::from_utf8_lossy(&stored.signed_pdf_bytes).contains(PASSWORD));
    assert!(!String::from_utf8_lossy(&stored.signer_cert_der).contains(PASSWORD));
}

#[tokio::test]
async fn local_pkcs12_scap_capacity_preprod_is_provider_declared_only() {
    let state = AppState {
        local_signing: true,
        ..AppState::default()
    };
    let (token, _) = bootstrap(&state).await;
    disable_timestamping(&state).await;
    let book_id = seed_book(&state, &token).await;
    let act_id = create_signing_act(&state, &token, &book_id).await;
    seal_act(&state, &token, &act_id).await;

    let pfx = local_pfx();
    let (status, signed) = send(
        &state,
        local_sign_req_with_body(
            &act_id,
            &token,
            json!({
                "pkcs12_base64": B64.encode(&pfx),
                "passphrase": PASSWORD,
                "friendly_name": FRIENDLY_NAME,
                "capacity": "Advogado",
                "scap_capacity_evidence": {
                    "citizen_id": FIXTURE_CITIZEN_ID,
                    "provider_id": "OA",
                    "attribute_name": "Advogado"
                }
            }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "preprod SCAP capacity sign: {signed}"
    );
    let evidence = &signed["signer_capacity_evidence"];
    assert_eq!(evidence["requested_provider_capacity"], "Advogado");
    assert_eq!(evidence["source"], "scap_attribute_provider");
    assert_eq!(
        evidence["verification_status"],
        "declared_capacity_by_provider"
    );
    assert_eq!(evidence["status_scope"], "declared_capacity_evidence_only");
    assert_eq!(evidence["verification_source"], Value::Null);
    assert_eq!(evidence["authority_reference"], Value::Null);
    assert_ne!(evidence["verification_status"], "verified_by_scap");

    let stored = state
        .signed_documents
        .read()
        .await
        .get(&ActId(Uuid::parse_str(&act_id).expect("act uuid")))
        .expect("stored signed doc")
        .clone();
    let capacity_evidence = stored
        .signer_capacity_evidence_json
        .as_deref()
        .expect("stored SCAP capacity evidence");
    assert!(capacity_evidence.contains("\"declared_capacity_by_provider\""));
    assert!(!capacity_evidence.contains("verified_by_scap"));
}

#[tokio::test]
async fn local_pkcs12_persists_verified_scap_capacity_evidence_from_prod_fixture() {
    let _guard = ENV_LOCK.lock().await;
    let _env = EnvRestore::capture(&SCAP_ENV_KEYS);
    clear_scap_test_env();
    let server = MockScapServer::granted_attribute();
    unsafe {
        std::env::set_var("CHANCELA_SCAP_BASE_URL", server.url());
        std::env::set_var("CHANCELA_SCAP_APPLICATION_ID", "local-pkcs12-scap-app");
        std::env::set_var("CHANCELA_SCAP_SECRET", "local-pkcs12-scap-secret");
    }

    let state = AppState {
        local_signing: true,
        ..AppState::default()
    };
    let (token, _) = bootstrap(&state).await;
    disable_timestamping(&state).await;
    let book_id = seed_book(&state, &token).await;
    let act_id = create_signing_act(&state, &token, &book_id).await;
    seal_act(&state, &token, &act_id).await;

    let pfx = local_pfx();
    let (status, signed) = send(
        &state,
        local_sign_req_with_body(
            &act_id,
            &token,
            json!({
                "pkcs12_base64": B64.encode(&pfx),
                "passphrase": PASSWORD,
                "friendly_name": FRIENDLY_NAME,
                "capacity": "Advogado",
                "scap_capacity_evidence": {
                    "citizen_id": FIXTURE_CITIZEN_ID,
                    "provider_id": "OA",
                    "attribute_name": "Advogado",
                    "environment": "prod"
                }
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "prod SCAP capacity sign: {signed}");
    let evidence = &signed["signer_capacity_evidence"];
    assert_eq!(evidence["requested_provider_capacity"], "Advogado");
    assert_eq!(evidence["source"], "scap_attribute_provider");
    assert_eq!(evidence["verification_status"], "verified_by_scap");
    assert_eq!(evidence["verification_source"], "scap-prod");
    assert_eq!(evidence["authority_reference"], "OA-grant-2026-fixture");
    assert_eq!(evidence["status_scope"], "scap_verified_capacity");
    assert!(
        evidence["verified_at"]
            .as_str()
            .is_some_and(|value| value.contains('T')),
        "verified_at should be an RFC3339 timestamp: {evidence}"
    );

    let (status, view) = send(
        &state,
        get_req(&format!("/v1/acts/{act_id}/signature"), &token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "signature status: {view}");
    assert_eq!(
        view["signed"]["signer_capacity_evidence"]["verification_status"],
        "verified_by_scap"
    );
    assert_eq!(
        view["signed"]["signer_capacity_evidence"]["status_scope"],
        "scap_verified_capacity"
    );

    let stored = state
        .signed_documents
        .read()
        .await
        .get(&ActId(Uuid::parse_str(&act_id).expect("act uuid")))
        .expect("stored signed doc")
        .clone();
    let capacity_evidence = stored
        .signer_capacity_evidence_json
        .as_deref()
        .expect("stored verified SCAP capacity evidence");
    let stored_evidence: Value =
        serde_json::from_str(capacity_evidence).expect("stored capacity JSON");
    assert_eq!(stored_evidence["verification_status"], "verified_by_scap");
    assert_eq!(stored_evidence["verification_source"], "scap-prod");
    assert_eq!(
        stored_evidence["authority_reference"],
        "OA-grant-2026-fixture"
    );
    assert_eq!(stored_evidence["status_scope"], "scap_verified_capacity");

    let expected_auth = expected_basic_auth("local-pkcs12-scap-app", "local-pkcs12-scap-secret");
    let requests = server.request_texts();
    assert!(
        requests
            .iter()
            .any(|request| request.starts_with("POST /attributes ")),
        "SCAP attributes endpoint was not called: {requests:#?}"
    );
    assert!(
        requests
            .iter()
            .any(|request| request.starts_with("POST /verify ")),
        "SCAP verify endpoint was not called: {requests:#?}"
    );
    assert!(
        requests
            .iter()
            .all(|request| request.contains(&expected_auth)),
        "all SCAP fixture requests must use configured Basic auth: {requests:#?}"
    );
}

#[tokio::test]
async fn local_pkcs12_rejects_mismatched_capacity_and_scap_attribute() {
    let state = AppState {
        local_signing: true,
        ..AppState::default()
    };
    let (token, _) = bootstrap(&state).await;
    let book_id = seed_book(&state, &token).await;
    let act_id = create_signing_act(&state, &token, &book_id).await;
    seal_act(&state, &token, &act_id).await;

    let pfx = local_pfx();
    let (status, err) = send(
        &state,
        local_sign_req_with_body(
            &act_id,
            &token,
            json!({
                "pkcs12_base64": B64.encode(&pfx),
                "passphrase": PASSWORD,
                "friendly_name": FRIENDLY_NAME,
                "capacity": "Administrador",
                "scap_capacity_evidence": {
                    "citizen_id": FIXTURE_CITIZEN_ID,
                    "provider_id": "OA",
                    "attribute_name": "Advogado"
                }
            }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "mismatched capacity must fail: {err}"
    );
    let msg = err["error"].as_str().unwrap_or_default();
    assert!(
        msg.contains("capacity") && msg.contains("SCAP attribute"),
        "clear mismatch error: {err}"
    );
    assert_no_signed_artifact_or_event(&state, &token, &act_id).await;
}

#[tokio::test]
async fn local_pkcs12_wrong_passphrase_leaves_no_artifact() {
    let state = AppState {
        local_signing: true,
        ..AppState::default()
    };
    let (token, _) = bootstrap(&state).await;
    let book_id = seed_book(&state, &token).await;
    let act_id = create_signing_act(&state, &token, &book_id).await;
    seal_act(&state, &token, &act_id).await;

    let pfx = local_pfx();
    let (status, err) = send(
        &state,
        local_sign_req(&act_id, &token, &pfx, "not the password"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "wrong passphrase: {err}"
    );
    assert!(
        err["error"]
            .as_str()
            .unwrap_or_default()
            .contains("password")
    );
    assert!(!err.to_string().contains("not the password"));
    assert_no_signed_artifact_or_event(&state, &token, &act_id).await;
}

#[tokio::test]
async fn local_pkcs12_requires_local_signing_capability() {
    let state = AppState::default();
    let (token, _) = bootstrap(&state).await;
    let book_id = seed_book(&state, &token).await;
    let act_id = create_signing_act(&state, &token, &book_id).await;
    seal_act(&state, &token, &act_id).await;

    let pfx = local_pfx();
    let (status, err) = send(&state, local_sign_req(&act_id, &token, &pfx, PASSWORD)).await;
    assert_eq!(status, StatusCode::CONFLICT, "local gate: {err}");
    assert_no_signed_artifact_or_event(&state, &token, &act_id).await;
}
