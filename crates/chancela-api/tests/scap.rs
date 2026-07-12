//! SCAP professional-attribute endpoint tests (t67-e10).
//!
//! Everything runs against the offline mock transport (the default). The load-bearing assertions are
//! the **honesty markers**: a mock-backed attribute signature is always `declared` and never
//! `verified_by_scap`, and a production request without deployment credentials fails closed.

use std::str::FromStr;
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
use tower::ServiceExt;
use uuid::Uuid;
use x509_cert::certificate::{Certificate, TbsCertificate, Version};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;

use chancela_api::{AppState, User, UserId, router};
use chancela_authz::{OWNER_ROLE_ID, RoleAssignment, RoleCatalog, Scope};
use time::format_description::well_known::Rfc3339;

const PASSWORD: &str = "correct horse battery staple";
const FRIENDLY_NAME: &str = "scap signing identity";
const OID_SHA256_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
// The fictional signing citizen the mock fixtures carry (see chancela-scap mock transport).
const FIXTURE_CITIZEN_ID: &str = "199000001";

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
            password_hash: None,
            attestation_key: None,
            secret_source: Default::default(),
            recovery_hash: None,
            role_assignments: vec![RoleAssignment::new(OWNER_ROLE_ID, Scope::Global)],
        },
    );
    let (status, session) = send(
        state,
        Request::builder()
            .method("POST")
            .uri("/v1/session")
            .header("content-type", "application/json")
            .body(Body::from(json!({ "user_id": uid.0 }).to_string()))
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
async fn scap_prod_without_credentials_fails_closed() {
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
