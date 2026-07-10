//! Local PKCS#12 software-certificate signing API regression tests.
//!
//! The PFX is generated in-process: no checked-in private keys, no OS certificate store, and no
//! network. The API must persist only the signed PDF plus public evidence labels.

use std::str::FromStr;
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

const PASSWORD: &str = "correct horse battery staple";
const FRIENDLY_NAME: &str = "local advanced signing identity";
const OID_SHA256_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");

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
        password_hash: None,
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
            .body(Body::from(json!({ "user_id": user_id }).to_string()))
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
        json_req("POST", &format!("/v1/acts/{act_id}/seal"), token, json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "seal: {sealed}");
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
    json_req(
        "POST",
        &format!("/v1/acts/{act_id}/signature/local/pkcs12/sign"),
        token,
        json!({
            "pkcs12_base64": B64.encode(pfx),
            "passphrase": passphrase,
            "friendly_name": FRIENDLY_NAME,
            "capacity": "Administrador"
        }),
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
    assert!(!String::from_utf8_lossy(&stored.signed_pdf_bytes).contains(PASSWORD));
    assert!(!String::from_utf8_lossy(&stored.signer_cert_der).contains(PASSWORD));
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
